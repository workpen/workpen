//! Process-jail corpus. Feature `nono`. Never grant filesystem root.
//! Does not call `KernelPolicy::apply` (irreversible). `apply_pre_exec`
//! is allowed: it only installs a child hook.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

#[cfg(unix)]
#[test]
fn extra_system_read_dirs_are_granted_when_present() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    for candidate in ["/dev", "/etc", "/opt/homebrew", "/usr/local"] {
        let path = Path::new(candidate);
        if !path.is_dir() {
            continue;
        }
        if path.parent().is_some() && !path.parent().unwrap().as_os_str().is_empty() {
            let grant = policy
                .grants()
                .iter()
                .find(|g| g.path == path)
                .unwrap_or_else(|| panic!("missing presented system Read grant: {candidate}"));
            assert_eq!(
                grant.access,
                KernelAccess::Read,
                "presented system grant must be Read: {candidate}"
            );
        }
        let Ok(resolved) = fs::canonicalize(path) else {
            continue;
        };
        if resolved.parent().is_none()
            || resolved.parent().is_some_and(|p| p.as_os_str().is_empty())
        {
            continue;
        }
        let grant = policy
            .grants()
            .iter()
            .find(|g| g.path == resolved)
            .unwrap_or_else(|| panic!("missing canonical system Read grant: {candidate}"));
        assert_eq!(
            grant.access,
            KernelAccess::Read,
            "canonical system grant must be Read: {candidate}"
        );
    }
}

#[test]
fn apply_pre_exec_does_not_jail_the_parent() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    let marker = outside.path().join("parent-still-free");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new("true");
    let applied = policy.apply_pre_exec(&mut cmd).expect("pre_exec");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert_eq!(applied, KernelApply::Applied);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert_eq!(applied, KernelApply::UserspaceOnly);
    fs::write(&marker, "free").expect("parent must still write outside the workspace");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn apply_pre_exec_child_can_echo() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new("/bin/echo");
    cmd.arg("ok");
    assert_eq!(
        policy.apply_pre_exec(&mut cmd).expect("pre_exec"),
        KernelApply::Applied
    );
    let out = cmd.output().expect("spawn child");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
}
