//! Process-jail corpus. Feature `nono`. Never grant filesystem root.
//! Does not call `KernelPolicy::apply` (irreversible).

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use workpen::{KernelAccess, KernelApply, KernelError, kernel_supported, process_jail};

fn workspace() -> TempDir {
    TempDir::new().expect("temp workspace")
}

#[test]
fn kernel_access_is_read_or_readwrite_only() {
    let kinds = [KernelAccess::Read, KernelAccess::ReadWrite];
    assert_eq!(kinds.len(), 2);
}

#[test]
fn kernel_apply_is_applied_or_userspace_only() {
    let kinds = [KernelApply::Applied, KernelApply::UserspaceOnly];
    assert_eq!(kinds.len(), 2);
}

#[test]
fn workspace_is_readwrite() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let root = fs::canonicalize(dir.path()).expect("canon");
    let grant = policy
        .grants()
        .iter()
        .find(|g| g.path == root)
        .expect("workspace grant");
    assert_eq!(grant.access, KernelAccess::ReadWrite);
    assert!(policy.network_blocked());
}

#[test]
fn extra_root_is_readwrite() {
    let dir = workspace();
    let extra = TempDir::new().expect("extra");
    let policy = process_jail(dir.path(), [extra.path()]).expect("policy");
    let extra_root = fs::canonicalize(extra.path()).expect("canon");
    let grant = policy
        .grants()
        .iter()
        .find(|g| g.path == extra_root)
        .expect("extra grant");
    assert_eq!(grant.access, KernelAccess::ReadWrite);
}

#[test]
fn never_grants_filesystem_root() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    for grant in policy.grants() {
        assert!(
            grant.path.parent().is_some() && !grant.path.parent().unwrap().as_os_str().is_empty(),
            "grant must not be filesystem root: {}",
            grant.path.display()
        );
    }
}

#[test]
fn filesystem_root_as_workspace_is_refused() {
    #[cfg(unix)]
    {
        let err = process_jail("/", std::iter::empty::<&Path>()).expect_err("root");
        assert!(matches!(err, KernelError::FsRoot));
    }
    #[cfg(windows)]
    {
        let root = Path::new(r"C:\");
        if root.exists() {
            let err = process_jail(root, std::iter::empty::<&Path>()).expect_err("root");
            assert!(matches!(err, KernelError::FsRoot));
        }
    }
}

#[test]
fn extra_root_filesystem_root_is_refused() {
    let dir = workspace();
    #[cfg(unix)]
    {
        let err = process_jail(dir.path(), ["/"]).expect_err("extra root");
        assert!(matches!(err, KernelError::FsRoot));
    }
    #[cfg(windows)]
    {
        let root = Path::new(r"C:\");
        if root.exists() {
            let err = process_jail(dir.path(), [root]).expect_err("extra root");
            assert!(matches!(err, KernelError::FsRoot));
        }
    }
}

#[test]
fn missing_workspace_is_root_error() {
    let missing = PathBuf::from("/no-such-workpen-workspace-dir");
    let err = process_jail(&missing, std::iter::empty::<&Path>()).expect_err("missing");
    assert!(matches!(err, KernelError::Root(_)));
}

#[test]
fn existing_system_dirs_are_read() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let workspace = fs::canonicalize(dir.path()).expect("canon");
    for grant in policy.grants() {
        if grant.path == workspace {
            continue;
        }
        assert_eq!(
            grant.access,
            KernelAccess::Read,
            "system grant must be Read: {}",
            grant.path.display()
        );
    }
    #[cfg(unix)]
    {
        if Path::new("/usr").is_dir() {
            let usr = fs::canonicalize("/usr").expect("usr");
            let grant = policy
                .grants()
                .iter()
                .find(|g| g.path == usr)
                .expect("/usr");
            assert_eq!(grant.access, KernelAccess::Read);
        }
    }
}

#[cfg(unix)]
#[test]
fn extra_root_overlapping_system_dir_stays_readwrite() {
    if !Path::new("/usr").is_dir() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), ["/usr"]).expect("policy");
    let usr = fs::canonicalize("/usr").expect("usr");
    let grant = policy
        .grants()
        .iter()
        .find(|g| g.path == usr)
        .expect("/usr");
    assert_eq!(grant.access, KernelAccess::ReadWrite);
}

#[test]
fn kernel_supported_matches_unix_backends() {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(kernel_supported());
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert!(!kernel_supported());
}
