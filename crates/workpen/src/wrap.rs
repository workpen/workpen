//! Process-jail wrap via pinned nono. Feature `nono`.
//!
//! Never grant filesystem root (`/` or a Windows drive root). Inspect
//! [`KernelPolicy::grants`]; do not parse nono internals. Do not call
//! [`KernelPolicy::apply`] from unit tests (`Sandbox::apply_auto` is
//! irreversible). [`KernelPolicy::apply_pre_exec`] is safe in tests: it
//! only installs a child hook.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Access granted for one path. Hosts branch on this; do not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelAccess {
    Read,
    ReadWrite,
}

/// One grant we will hand to nono.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelGrant {
    pub path: PathBuf,
    pub access: KernelAccess,
}

/// Process-jail policy. Workspace RW, extra roots RW, existing system dirs Read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelPolicy {
    grants: Vec<KernelGrant>,
    network_blocked: bool,
}

/// Result of applying the jail. Hosts branch on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelApply {
    /// Kernel jail is active in this process, or hooked for the child.
    Applied,
    /// Platform has no kernel backend (Windows). Userspace dest-deny + PathGuard only.
    UserspaceOnly,
}

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("kernel wrap root is not usable: {0}")]
    Root(String),
    #[error("kernel wrap refused filesystem root")]
    FsRoot,
    #[error("kernel wrap apply failed: {0}")]
    Apply(String),
}

/// Whether this OS can apply a kernel jail.
#[must_use]
pub fn kernel_supported() -> bool {
    #[cfg(unix)]
    {
        nono::Sandbox::is_supported()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Build a process-jail policy. Does not apply it.
pub fn process_jail(
    workspace: impl AsRef<Path>,
    extra: impl IntoIterator<Item = impl AsRef<Path>>,
) -> Result<KernelPolicy, KernelError> {
    let mut grants = Vec::new();
    add_rw(&mut grants, workspace.as_ref())?;
    for extra in extra {
        add_rw(&mut grants, extra.as_ref())?;
    }
    for dir in system_read_dirs() {
        add_read_if_dir(&mut grants, dir);
    }
    Ok(KernelPolicy {
        grants,
        network_blocked: true,
    })
}

impl KernelPolicy {
    pub fn grants(&self) -> &[KernelGrant] {
        &self.grants
    }

    pub fn network_blocked(&self) -> bool {
        self.network_blocked
    }

    /// Apply Landlock/Seatbelt for this process. Irreversible. Not for tests.
    ///
    /// Uses `SignalMode::AllowAll` so a jailed parent can still signal children.
    pub fn apply(&self) -> Result<KernelApply, KernelError> {
        if !kernel_supported() {
            return Ok(KernelApply::UserspaceOnly);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let caps = self.to_capability_set(nono::SignalMode::AllowAll)?;
            nono::Sandbox::apply_auto(&caps).map_err(|e| KernelError::Apply(e.to_string()))?;
            Ok(KernelApply::Applied)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Ok(KernelApply::UserspaceOnly)
        }
    }

    /// Install Landlock/Seatbelt in the child `pre_exec` hook.
    ///
    /// Builds the capability set in the parent (allocation is not safe after
    /// fork). Uses `SignalMode::Isolated` so the child cannot signal the parent.
    /// Does not jail this process.
    pub fn apply_pre_exec(&self, cmd: &mut Command) -> Result<KernelApply, KernelError> {
        if !kernel_supported() {
            let _ = cmd;
            return Ok(KernelApply::UserspaceOnly);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let caps = self.to_capability_set(nono::SignalMode::Isolated)?;
            // Safety: the set is built in the parent; the hook only applies
            // it and maps failure to io::Error. apply_auto may allocate.
            unsafe {
                use std::os::unix::process::CommandExt;
                cmd.pre_exec(move || {
                    nono::Sandbox::apply_auto(&caps)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    Ok(())
                });
            }
            Ok(KernelApply::Applied)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = cmd;
            Ok(KernelApply::UserspaceOnly)
        }
    }

    #[cfg(unix)]
    fn to_capability_set(
        &self,
        signal: nono::SignalMode,
    ) -> Result<nono::CapabilitySet, KernelError> {
        let mut caps = nono::CapabilitySet::new();
        for grant in &self.grants {
            let mode = match grant.access {
                KernelAccess::Read => nono::AccessMode::Read,
                KernelAccess::ReadWrite => nono::AccessMode::ReadWrite,
            };
            caps = caps
                .allow_path(&grant.path, mode)
                .map_err(|e| KernelError::Apply(e.to_string()))?;
        }
        Ok(caps.block_network().set_signal_mode(signal))
    }
}

fn system_read_dirs() -> Vec<&'static Path> {
    vec![
        Path::new("/usr"),
        Path::new("/bin"),
        Path::new("/lib"),
        Path::new("/lib64"),
        Path::new("/sbin"),
        Path::new("/System"),
        Path::new("/Library"),
        Path::new("/dev"),
        Path::new("/etc"),
        Path::new("/opt/homebrew"),
        Path::new("/usr/local"),
    ]
}

fn add_rw(grants: &mut Vec<KernelGrant>, path: &Path) -> Result<(), KernelError> {
    let resolved = canonicalize_dir(path)?;
    push_grant(grants, resolved, KernelAccess::ReadWrite);
    Ok(())
}

fn add_read_if_dir(grants: &mut Vec<KernelGrant>, path: &Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let resolved = std::fs::canonicalize(path).ok();
    if resolved.as_ref().is_some_and(|p| is_fs_root(p)) {
        return;
    }
    // Grant the path as given so symlink lookups (`/etc` -> `/private/etc`) work.
    if !is_fs_root(path) {
        push_grant(grants, path.to_path_buf(), KernelAccess::Read);
    }
    if let Some(resolved) = resolved {
        push_grant(grants, resolved, KernelAccess::Read);
    }
}

fn push_grant(grants: &mut Vec<KernelGrant>, path: PathBuf, access: KernelAccess) {
    if let Some(existing) = grants.iter_mut().find(|g| g.path == path) {
        if access == KernelAccess::ReadWrite {
            existing.access = KernelAccess::ReadWrite;
        }
        return;
    }
    grants.push(KernelGrant { path, access });
}

fn canonicalize_dir(path: &Path) -> Result<PathBuf, KernelError> {
    let resolved = std::fs::canonicalize(path)
        .map_err(|e| KernelError::Root(format!("{}: {e}", path.display())))?;
    if !resolved.is_dir() {
        return Err(KernelError::Root(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    if is_fs_root(&resolved) {
        return Err(KernelError::FsRoot);
    }
    Ok(resolved)
}

fn is_fs_root(path: &Path) -> bool {
    match path.parent() {
        None => true,
        Some(parent) => parent.as_os_str().is_empty(),
    }
}
