//! PathGuard corpus. Out-of-tree, symlink vaults, extra roots.
//! Dest-deny stays a separate type.

use std::fs;
use std::path::Path;

use tempfile::TempDir;
use workpen::{DenyPolicy, PathGuard, PathGuardError, PathGuardKind, check_dests, classify_dest};

fn workspace() -> TempDir {
    let dir = TempDir::new().expect("temp workspace");
    fs::write(dir.path().join("ok.txt"), b"ok").expect("seed file");
    dir
}

#[test]
fn path_guard_kind_is_escape_or_symlink_vault_only() {
    let kinds = [PathGuardKind::Escape, PathGuardKind::SymlinkVault];
    assert_eq!(kinds.len(), 2);
}

#[test]
fn in_tree_path_is_allowed() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path()).expect("guard");
    let got = guard.check(Path::new("ok.txt")).expect("in-tree");
    assert!(got.ends_with("ok.txt"));
    assert_eq!(guard.classify(Path::new("ok.txt")), None);
}

#[test]
fn parent_escape_is_path_guard_not_dest_deny() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path()).expect("guard");
    let policy = DenyPolicy::default();
    let escaped = Path::new("../outside.txt");
    assert_eq!(
        classify_dest(escaped, &policy),
        None,
        "out-of-tree is PathGuard, not dest-deny"
    );
    match guard.check(escaped) {
        Err(PathGuardError::Denied(deny)) => {
            assert_eq!(deny.kind, PathGuardKind::Escape);
            assert!(deny.message().contains("escapes workspace"));
            assert!(!deny.message().contains("deny glob"));
        }
        other => panic!("expected Escape, got {other:?}"),
    }
}

#[test]
fn absolute_outside_is_escape() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path()).expect("guard");
    let outside = std::env::temp_dir();
    assert_ne!(outside, dir.path());
    match guard.check(&outside) {
        Err(PathGuardError::Denied(deny)) => assert_eq!(deny.kind, PathGuardKind::Escape),
        other => panic!("expected Escape, got {other:?}"),
    }
}

#[test]
fn missing_in_tree_dest_is_allowed() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path()).expect("guard");
    guard
        .check(Path::new("new-file.txt"))
        .expect("missing dest inside workspace is allowed");
}

#[test]
fn missing_parent_escape_is_denied() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path()).expect("guard");
    match guard.check(Path::new("../no-such-secret")) {
        Err(PathGuardError::Denied(deny)) => assert_eq!(deny.kind, PathGuardKind::Escape),
        other => panic!("expected Escape, got {other:?}"),
    }
}

#[test]
fn extra_root_is_allowed() {
    let dir = workspace();
    let extra = TempDir::new().expect("extra root");
    fs::write(extra.path().join("tool.txt"), b"t").expect("extra file");
    let guard = PathGuard::with_extra_roots(dir.path(), [extra.path()]).expect("guard");
    guard
        .check(&extra.path().join("tool.txt"))
        .expect("extra root dest is allowed");
}

#[cfg(unix)]
#[test]
fn symlink_out_of_tree_is_symlink_vault() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    fs::write(outside.path().join("vault.txt"), b"secret").expect("vault");
    let link = dir.path().join("vault");
    std::os::unix::fs::symlink(outside.path().join("vault.txt"), &link).expect("symlink");
    let guard = PathGuard::new(dir.path()).expect("guard");
    match guard.check(Path::new("vault")) {
        Err(PathGuardError::Denied(deny)) => {
            assert_eq!(deny.kind, PathGuardKind::SymlinkVault);
            assert!(deny.message().contains("symlink"));
            assert!(!deny.message().contains("deny glob"));
        }
        other => panic!("expected SymlinkVault, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn symlink_inside_workspace_is_allowed() {
    let dir = workspace();
    std::os::unix::fs::symlink(dir.path().join("ok.txt"), dir.path().join("alias"))
        .expect("in-tree symlink");
    let guard = PathGuard::new(dir.path()).expect("guard");
    guard
        .check(Path::new("alias"))
        .expect("in-tree symlink is not a vault");
}

#[test]
fn check_dests_secret_name_inside_is_ok_for_path_guard() {
    let dir = workspace();
    fs::write(dir.path().join(".env"), b"x=1").expect(".env");
    let guard = PathGuard::new(dir.path()).expect("guard");
    check_dests(&guard, &[Path::new(".env")]).expect("PathGuard does not dest-deny .env");
}

#[test]
fn check_dests_escape_is_denied() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path()).expect("guard");
    let err = check_dests(&guard, &[Path::new("ok.txt"), Path::new("../x")])
        .expect_err("escape dest denied");
    match err {
        PathGuardError::Denied(deny) => assert_eq!(deny.kind, PathGuardKind::Escape),
        other => panic!("expected Denied, got {other}"),
    }
}
