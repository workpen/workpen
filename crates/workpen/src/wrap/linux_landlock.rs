//! Linux Landlock for a one-file grant.
//!
//! nono `AccessMode` is read, write, or both. Read on a directory is
//! list plus read of every child. A second Landlock layer cannot add
//! traverse after that ruleset already handles execute and denies it.
//! This path builds one ruleset: the same file and directory rights
//! nono would install, plus execute on ancestor directories that are
//! not already covered by a directory grant.
//!
//! Landlock has no access right that walks a directory without that
//! execute. A path-beneath rule with that right also allows executing
//! other files beneath the directory. The ancestor rule stays execute.

use std::os::fd::{AsFd, OwnedFd};

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

use super::KernelError;

pub(super) fn apply_landlock_with_ancestors(
    caps: &nono::CapabilitySet,
    ancestors: &[std::path::PathBuf],
) -> Result<(), KernelError> {
    let detected = nono::detect_abi().map_err(|err| KernelError::Apply(err.to_string()))?;
    let abi = detected.enforced_abi();
    let mut built = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|err| KernelError::Apply(format!("filesystem rights: {err}")))?;
    match caps.network_mode() {
        nono::NetworkMode::AllowAll => {}
        nono::NetworkMode::Blocked => {
            let net = AccessNet::from_all(abi);
            if net.is_empty() {
                return Err(KernelError::Apply(
                    "file grant needs Landlock TCP filtering so the blocked network stays blocked"
                        .into(),
                ));
            }
            built = built
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(net)
                .map_err(|err| KernelError::Apply(format!("network rights: {err}")))?;
        }
        nono::NetworkMode::ProxyOnly { .. } => {
            return Err(KernelError::Apply(
                "file grant does not combine with a proxy-only network".into(),
            ));
        }
    }
    let scopes = landlock_scopes(caps, abi)?;
    if !scopes.is_empty() {
        built = built
            .set_compatibility(CompatLevel::HardRequirement)
            .scope(scopes)
            .map_err(|err| KernelError::Apply(format!("landlock scope: {err}")))?;
    }
    let mut ruleset = built
        .create()
        .map_err(|err| KernelError::Apply(format!("create ruleset: {err}")))?;
    for cap in caps.fs_capabilities() {
        let fd = PathFd::new(&cap.resolved)
            .map_err(|err| KernelError::Apply(format!("{}: {err}", cap.resolved.display())))?;
        let meta = fstat_path_fd(&fd, &cap.resolved)?;
        if meta.is_dir() == cap.is_file {
            return Err(KernelError::Apply(format!(
                "{}: grant type does not match the inode",
                cap.resolved.display()
            )));
        }
        let access = path_access(cap, abi, &meta)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|err| KernelError::Apply(format!("{}: {err}", cap.resolved.display())))?;
    }
    let traverse = ancestor_walk_access();
    for dir in ancestors {
        let fd = PathFd::new(dir)
            .map_err(|err| KernelError::Apply(format!("{}: {err}", dir.display())))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, traverse))
            .map_err(|err| KernelError::Apply(format!("{}: {err}", dir.display())))?;
    }
    let status = ruleset
        .restrict_self()
        .map_err(|err| KernelError::Apply(format!("landlock restrict: {err}")))?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(KernelError::Apply(
            "Landlock ruleset was not enforced".into(),
        ));
    }
    Ok(())
}

/// Walk right for an ancestor of a one-file grant.
///
/// Landlock has no access right that walks a directory without that
/// execute.
fn ancestor_walk_access() -> BitFlags<AccessFs> {
    AccessFs::Execute.into()
}

fn landlock_scopes(
    caps: &nono::CapabilitySet,
    abi: landlock::ABI,
) -> Result<BitFlags<Scope>, KernelError> {
    let available = Scope::from_all(abi);
    let mut scopes = BitFlags::empty();
    match caps.signal_mode() {
        nono::SignalMode::AllowAll => {}
        nono::SignalMode::AllowSameSandbox if available.is_empty() => {
            return Err(KernelError::Apply(
                "signal scope needs Landlock ABI V6, which this kernel does not provide".into(),
            ));
        }
        nono::SignalMode::Isolated | nono::SignalMode::AllowSameSandbox => {
            if !available.is_empty() {
                scopes |= Scope::Signal;
            }
        }
    }
    if caps.ipc_mode() == nono::IpcMode::SharedMemoryOnly && !available.is_empty() {
        scopes |= Scope::AbstractUnixSocket;
    }
    Ok(scopes)
}

/// `stat` the inode `PathFd` will install. `O_PATH` still allows `fstat`.
fn fstat_path_fd(fd: &PathFd, path: &std::path::Path) -> Result<std::fs::Metadata, KernelError> {
    let owned: OwnedFd = fd
        .as_fd()
        .try_clone_to_owned()
        .map_err(|err| KernelError::Apply(format!("{}: {err}", path.display())))?;
    std::fs::File::from(owned)
        .metadata()
        .map_err(|err| KernelError::Apply(format!("{}: {err}", path.display())))
}

fn path_access(
    cap: &nono::FsCapability,
    abi: landlock::ABI,
    meta: &std::fs::Metadata,
) -> Result<BitFlags<AccessFs>, KernelError> {
    let available = AccessFs::from_all(abi);
    let read = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
    let write = AccessFs::WriteFile
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym
        | AccessFs::Refer
        | AccessFs::Truncate;
    let mut access = match cap.access {
        nono::AccessMode::Read => read,
        nono::AccessMode::Write => write,
        nono::AccessMode::ReadWrite => read | write,
    };
    access &= available;
    let is_dir = meta.is_dir();
    if !is_dir {
        access &= AccessFs::from_file(abi);
    }
    {
        use std::os::unix::fs::FileTypeExt;
        let kind = meta.file_type();
        let device = kind.is_char_device() || kind.is_block_device();
        let dev_dir = is_dir && cap.resolved.starts_with("/dev");
        let write = matches!(
            cap.access,
            nono::AccessMode::Write | nono::AccessMode::ReadWrite
        );
        if (device || dev_dir) && write && available.contains(AccessFs::IoctlDev) {
            access |= AccessFs::IoctlDev;
        }
    }
    if access.is_empty() {
        return Err(KernelError::Apply(format!(
            "no Landlock rights for {}",
            cap.resolved.display()
        )));
    }
    Ok(access)
}

#[cfg(test)]
mod tests {
    use landlock::AccessFs;

    use super::ancestor_walk_access;

    #[test]
    fn ancestor_walk_is_execute_only() {
        assert_eq!(ancestor_walk_access(), AccessFs::Execute.into());
    }
}
