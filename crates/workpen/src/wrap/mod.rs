//! Process-jail wrap. Feature `nono`.
//!
//! Unix uses pinned nono (Landlock / Seatbelt). Windows uses a
//! write-restricted token. Never grant filesystem root (`/` or a
//! Windows drive root). Inspect [`KernelPolicy::grants`]; do not parse
//! nono internals. Do not call [`KernelPolicy::apply`] from unit tests
//! (`Sandbox::apply_auto` is irreversible). [`KernelPolicy::apply_pre_exec`]
//! only installs a Unix child hook. Hosts that need a jail on every OS
//! call [`KernelPolicy::run_child`].

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

#[cfg(windows)]
mod windows;

/// Access granted for one path. Hosts branch on this; do not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelAccess {
    Read,
    ReadWrite,
}

/// One grant we will hand to the kernel backend.
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
    /// Kernel jail is active in this process, or hooked/spawned for the child.
    Applied,
    /// Platform has no kernel backend. Userspace dest-deny + PathGuard only.
    UserspaceOnly,
}

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("kernel wrap root is not usable: {0}")]
    Root(String),
    #[error("kernel wrap refused filesystem root {0}; use a subdirectory, not `/`")]
    FsRoot(PathBuf),
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
    #[cfg(windows)]
    {
        windows::write_restricted_supported()
    }
    #[cfg(not(any(unix, windows)))]
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
        add_read_if_dir(&mut grants, &dir);
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
    /// Windows cannot retoken the current process; this stays
    /// [`KernelApply::UserspaceOnly`].
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
    /// Does not jail this process. Windows has no `pre_exec`; this stays
    /// [`KernelApply::UserspaceOnly`]. Use [`Self::run_child`] to jail a child.
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

    /// Spawn `cmd` under the kernel jail and wait for it.
    ///
    /// Unix installs `pre_exec` then `status`. Windows creates a
    /// write-restricted token and `CreateProcessAsUserW`. A Windows
    /// token or job failure is [`KernelError::Apply`]; the child is
    /// not started unsandboxed.
    pub fn run_child(&self, cmd: Command) -> Result<(KernelApply, ExitStatus), KernelError> {
        #[cfg(unix)]
        {
            let mut cmd = cmd;
            scrub_child_command(&mut cmd);
            let applied = self.apply_pre_exec(&mut cmd)?;
            let status = cmd
                .status()
                .map_err(|e| KernelError::Apply(e.to_string()))?;
            Ok((applied, status))
        }
        #[cfg(windows)]
        {
            if !kernel_supported() {
                return Err(KernelError::Apply(
                    "write-restricted token is not available".into(),
                ));
            }
            windows::spawn_write_restricted(self, &cmd)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = cmd;
            Err(KernelError::Apply(
                "no kernel backend on this platform".into(),
            ))
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

/// Names `run_child` strips from the child environment.
#[must_use]
pub fn child_env_deny_names() -> &'static [&'static str] {
    &[
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PERL5OPT",
        "XAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
    ]
}

/// True when `name` is on the child-env denylist (ASCII case-insensitive).
#[must_use]
pub fn is_denied_child_env(name: impl AsRef<OsStr>) -> bool {
    let raw = name.as_ref().to_string_lossy();
    child_env_deny_names()
        .iter()
        .any(|n| raw.eq_ignore_ascii_case(n))
}

/// Remove denylist keys from `cmd` so Unix `status` does not inherit them.
pub fn scrub_child_command(cmd: &mut Command) {
    for name in child_env_deny_names() {
        cmd.env_remove(name);
    }
}

/// Insert `--noprofile` and `--norc` after argv0 when the program is bash.
///
/// When argv0 is `env`/`env.exe`, drop `NAME=value` assignments whose name
/// is on the child-env denylist, including leftover tokens inside a `-S` /
/// `--split-string` operand, then insert after the first non-flag operand
/// that is bash. Walks clustered shorts (`-iC /tmp`) and value flags
/// (`-u NAME`, `-f FILE`, `--file FILE`). Attached forms stay one token.
#[must_use]
pub fn with_bash_noprofile(
    program: impl AsRef<OsStr>,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> (OsString, Vec<OsString>) {
    let program = program.as_ref().to_os_string();
    let mut args: Vec<OsString> = args
        .into_iter()
        .map(|a| a.as_ref().to_os_string())
        .collect();
    if is_env_argv0(&program) {
        drop_denied_env_assignments(&mut args);
    }
    if is_bash_argv0(&program) {
        insert_bash_noprofile(&mut args, 0);
    } else if is_env_argv0(&program)
        && let Some(idx) = first_env_bash_operand(&args)
    {
        insert_bash_noprofile(&mut args, idx + 1);
    }
    (program, args)
}

fn drop_denied_env_assignments(args: &mut Vec<OsString>) {
    let mut i = 0;
    let mut options_done = false;
    while i < args.len() {
        let raw = args[i].to_string_lossy().into_owned();
        if !options_done {
            if raw == "--" {
                options_done = true;
                i += 1;
                continue;
            }
            if let Some(skip) = env_flag_skip(&raw) {
                rewrite_denied_in_env_s(args, i);
                i = i.saturating_add(skip);
                continue;
            }
        }
        if let Some(eq) = raw.find('=') {
            let name = &raw[..eq];
            if !name.is_empty() && is_denied_child_env(name) {
                args.remove(i);
                continue;
            }
            i += 1;
            continue;
        }
        break;
    }
}

fn rewrite_denied_in_env_s(args: &mut [OsString], i: usize) {
    let raw = args[i].to_string_lossy().into_owned();
    if let Some(value) = raw.strip_prefix("--split-string=") {
        let dropped = drop_denied_from_split_string(value);
        args[i] = OsString::from(format!("--split-string={dropped}"));
        return;
    }
    if raw == "--split-string" {
        rewrite_next_s_operand(args, i);
        return;
    }
    if let Some((prefix, attached)) = env_s_cluster(&raw) {
        if attached.is_empty() {
            rewrite_next_s_operand(args, i);
        } else {
            let dropped = drop_denied_from_split_string(attached);
            args[i] = OsString::from(format!("{prefix}{dropped}"));
        }
    }
}

fn rewrite_next_s_operand(args: &mut [OsString], i: usize) {
    if let Some(op) = args.get_mut(i + 1) {
        let dropped = drop_denied_from_split_string(&op.to_string_lossy());
        *op = OsString::from(dropped);
    }
}

/// Clustered `-*S` / `-S` (not `--`). Prefix includes `S`; rest is attached.
fn env_s_cluster(arg: &str) -> Option<(&str, &str)> {
    if !arg.starts_with('-') || arg.starts_with("--") || arg == "-" {
        return None;
    }
    let rest = &arg[1..];
    let mut idx = 0;
    for c in rest.chars() {
        if c == 'S' {
            let prefix_end = 1 + idx + c.len_utf8();
            return Some((&arg[..prefix_end], &arg[prefix_end..]));
        }
        if crate::deny::env_takes_value(c) {
            return None;
        }
        idx += c.len_utf8();
    }
    None
}

fn drop_denied_from_split_string(s: &str) -> String {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let raw = tokens[i];
        if raw == "--" || raw == "-" {
            out.extend_from_slice(&tokens[i..]);
            break;
        }
        if let Some(skip) = env_flag_skip(raw) {
            let end = (i + skip).min(tokens.len());
            out.extend_from_slice(&tokens[i..end]);
            i = end;
            continue;
        }
        if let Some(eq) = raw.find('=') {
            let name = &raw[..eq];
            if !name.is_empty() && is_denied_child_env(name) {
                i += 1;
                continue;
            }
            out.push(raw);
            i += 1;
            continue;
        }
        out.extend_from_slice(&tokens[i..]);
        break;
    }
    out.join(" ")
}

fn insert_bash_noprofile(args: &mut Vec<OsString>, at: usize) {
    let has_noprofile = args[at..].iter().any(|a| a == "--noprofile");
    let has_norc = args[at..].iter().any(|a| a == "--norc");
    if !has_noprofile {
        args.insert(at, OsString::from("--noprofile"));
    }
    if !has_norc {
        let idx = args[at..]
            .iter()
            .position(|a| a == "--noprofile")
            .map(|i| at + i + 1)
            .unwrap_or(at);
        args.insert(idx, OsString::from("--norc"));
    }
}

fn is_bash_argv0(program: &OsStr) -> bool {
    let raw = program.to_string_lossy();
    let name = raw.rsplit(['/', '\\']).next().unwrap_or(raw.as_ref());
    name.eq_ignore_ascii_case("bash") || name.eq_ignore_ascii_case("bash.exe")
}

fn is_env_argv0(program: &OsStr) -> bool {
    crate::deny::is_env_program(program)
}

fn first_env_bash_operand(args: &[OsString]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let raw = args[i].to_string_lossy();
        if raw == "--" {
            return args
                .get(i + 1)
                .filter(|a| is_bash_argv0(a.as_os_str()))
                .map(|_| i + 1);
        }
        if let Some(skip) = env_flag_skip(&raw) {
            i = i.saturating_add(skip);
            continue;
        }
        if raw.contains('=') {
            i += 1;
            continue;
        }
        if is_bash_argv0(args[i].as_os_str()) {
            return Some(i);
        }
        return None;
    }
    None
}

fn env_flag_skip(arg: &str) -> Option<usize> {
    crate::deny::env_flag_skip(arg)
}

/// Call `spawn` only when token or job setup succeeded.
pub fn spawn_after_setup<T>(
    setup: Result<T, KernelError>,
    spawn: impl FnOnce(T) -> Result<(KernelApply, ExitStatus), KernelError>,
) -> Result<(KernelApply, ExitStatus), KernelError> {
    spawn(setup?)
}

fn system_read_dirs() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        [
            "/usr",
            "/bin",
            "/lib",
            "/lib64",
            "/sbin",
            "/System",
            "/Library",
            "/dev",
            "/etc",
            "/opt/homebrew",
            "/usr/local",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect()
    }
    #[cfg(windows)]
    {
        let mut dirs = Vec::new();
        if let Some(root) = std::env::var_os("SystemRoot") {
            let root = PathBuf::from(root);
            dirs.push(root.join("System32"));
            dirs.push(root);
        }
        if let Some(pf) = std::env::var_os("ProgramFiles") {
            dirs.push(PathBuf::from(pf));
        }
        dirs
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

fn add_rw(grants: &mut Vec<KernelGrant>, path: &Path) -> Result<(), KernelError> {
    let resolved = canonicalize_dir(path)?;
    // Grant the path as given so symlink lookups (`/tmp` -> `/private/tmp`) work.
    if !is_fs_root(path) && path != resolved.as_path() {
        push_grant(grants, path.to_path_buf(), KernelAccess::ReadWrite);
    }
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
        return Err(KernelError::FsRoot(resolved));
    }
    Ok(resolved)
}

fn is_fs_root(path: &Path) -> bool {
    match path.parent() {
        None => true,
        Some(parent) => parent.as_os_str().is_empty(),
    }
}
