//! PathGuard corpus. Out-of-tree, symlink vaults, extra roots.
//! Dest-deny stays a separate type.

use std::fs;
use std::path::Path;

use tempfile::TempDir;
use workpen::{
    AbsolutePathPolicy, DenyPolicy, ExtraRootError, PathGuard, PathGuardError, PathGuardKind,
    check_dests, classify_dest, resolve_extra_root,
};

fn workspace() -> TempDir {
    let dir = TempDir::new().expect("temp workspace");
    fs::write(dir.path().join("ok.txt"), b"ok").expect("seed file");
    dir
}

#[test]
fn path_guard_kind_is_escape_or_symlink_vault_only() {
    match PathGuardKind::Escape {
        PathGuardKind::Escape | PathGuardKind::SymlinkVault => {}
    }
}

#[test]
fn in_tree_path_is_allowed() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    let got = guard.check(Path::new("ok.txt")).expect("in-tree");
    assert!(got.ends_with("ok.txt"));
    assert_eq!(guard.classify(Path::new("ok.txt")), None);
}

#[test]
fn parent_escape_is_path_guard_not_dest_deny() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
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
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
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
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    guard
        .check(Path::new("new-file.txt"))
        .expect("missing dest inside workspace is allowed");
}

#[test]
fn missing_parent_escape_is_denied() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
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
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
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
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    guard
        .check(Path::new("alias"))
        .expect("in-tree symlink is not a vault");
}

#[test]
fn check_dests_secret_name_inside_is_ok_for_path_guard() {
    let dir = workspace();
    fs::write(dir.path().join(".env"), b"x=1").expect(".env");
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    check_dests(&guard, &[Path::new(".env")]).expect("PathGuard does not dest-deny .env");
}

#[test]
fn check_dests_escape_is_denied() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    let err = check_dests(&guard, &[Path::new("ok.txt"), Path::new("../x")])
        .expect_err("escape dest denied");
    match err {
        PathGuardError::Denied(deny) => assert_eq!(deny.kind, PathGuardKind::Escape),
        other => panic!("expected Denied, got {other}"),
    }
}

#[test]
fn builder_default_rejects_absolute_even_inside_workspace() {
    let dir = workspace();
    let guard = PathGuard::builder(dir.path()).build().expect("builder");
    let abs = dir.path().join("ok.txt");
    match guard.check_path(&abs.to_string_lossy()) {
        Err(PathGuardError::AbsolutePath(_)) => {}
        other => panic!("builder default is Reject, got {other:?}"),
    }
}

#[test]
fn allow_if_contained_accepts_absolute_inside() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    guard
        .check_path(&dir.path().join("ok.txt").to_string_lossy())
        .expect("absolute inside workspace");
}

#[test]
fn blank_and_format_chars_are_empty_path() {
    let dir = workspace();
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    for raw in [
        "", "   ", "\t\n", "\u{200B}", "\u{200C}", "\u{200D}", "\u{FEFF}",
    ] {
        match guard.check_path(raw) {
            Err(PathGuardError::EmptyPath) => {}
            other => panic!("expected EmptyPath for {raw:?}, got {other:?}"),
        }
    }
}

#[test]
fn extra_roots_do_not_apply_to_relative_inputs() {
    let parent = TempDir::new().expect("parent");
    let ws = parent.path().join("ws");
    let extra = parent.path().join("extra");
    fs::create_dir_all(&ws).expect("ws");
    fs::create_dir_all(&extra).expect("extra");
    fs::write(ws.join("ok.txt"), b"ok").expect("seed");
    fs::write(extra.join("tool.txt"), b"t").expect("extra file");
    let guard = PathGuard::new(
        ws.clone(),
        AbsolutePathPolicy::AllowAdditionalRoots(vec![extra.clone()]),
    )
    .expect("guard");
    match guard.check_path("../extra/tool.txt") {
        Err(PathGuardError::Denied(deny)) => assert_eq!(deny.kind, PathGuardKind::Escape),
        other => panic!("relative must not use extra roots, got {other:?}"),
    }
    guard
        .check_path(&extra.join("tool.txt").to_string_lossy())
        .expect("absolute extra root still allowed");
}

#[cfg(unix)]
#[test]
fn check_path_entry_allows_symlink_to_outside() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    fs::write(outside.path().join("vault.txt"), b"secret").expect("vault");
    let link = dir.path().join("vault");
    std::os::unix::fs::symlink(outside.path().join("vault.txt"), &link).expect("symlink");
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    match guard.check_path("vault") {
        Err(PathGuardError::Denied(deny)) => assert_eq!(deny.kind, PathGuardKind::SymlinkVault),
        other => panic!("check_path must follow the leaf, got {other:?}"),
    }
    let got = guard
        .check_path_entry("vault")
        .expect("entry check does not follow the leaf");
    assert_eq!(
        got.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .as_deref(),
        Some("vault")
    );
}

#[cfg(unix)]
#[test]
fn check_path_entry_rejects_parent_symlink_escape() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    fs::write(outside.path().join("leaf.txt"), b"x").expect("leaf");
    let parent_link = dir.path().join("out");
    std::os::unix::fs::symlink(outside.path(), &parent_link).expect("parent symlink");
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    match guard.check_path_entry("out/leaf.txt") {
        Err(PathGuardError::Denied(_)) => {}
        other => panic!("intermediate parent symlink-out must be denied, got {other:?}"),
    }
}

#[cfg(windows)]
#[test]
fn check_path_entry_rejects_parent_junction_escape() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    fs::write(outside.path().join("leaf.txt"), b"x").expect("leaf");
    let junction = dir.path().join("out");
    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &junction.to_string_lossy(),
            &outside.path().to_string_lossy(),
        ])
        .status();
    let Ok(status) = status else {
        return;
    };
    if !status.success() {
        return;
    }
    let guard = PathGuard::new(dir.path(), AbsolutePathPolicy::AllowIfContained).expect("guard");
    match guard.check_path_entry("out/leaf.txt") {
        Err(PathGuardError::Denied(deny)) => {
            assert!(
                matches!(
                    deny.kind,
                    PathGuardKind::Escape | PathGuardKind::SymlinkVault
                ),
                "junction parent must be Denied, got {:?}",
                deny.kind
            );
        }
        other => panic!("junction parent escape must be denied, got {other:?}"),
    }
    assert!(
        !dir.path().join("leaf.txt").exists(),
        "must not write a leaf into the workspace"
    );
}

#[test]
fn resolve_extra_root_rejects_empty_missing_and_file() {
    let dir = workspace();
    match resolve_extra_root(dir.path(), "   ") {
        Err(ExtraRootError::Empty) => {}
        other => panic!("expected Empty, got {other:?}"),
    }
    match resolve_extra_root(dir.path(), "no-such-extra-root") {
        Err(ExtraRootError::Missing { .. }) => {}
        other => panic!("expected Missing, got {other:?}"),
    }
    match resolve_extra_root(dir.path(), "ok.txt") {
        Err(ExtraRootError::NotDirectory { .. }) => {}
        other => panic!("expected NotDirectory, got {other:?}"),
    }
}

#[test]
fn resolve_extra_root_rejects_implicit_filesystem_root() {
    let dir = workspace();
    let via_dotdot = dir.path().join("..").join("..").join("..").join("..");
    match resolve_extra_root(dir.path(), &via_dotdot.to_string_lossy()) {
        Err(ExtraRootError::EscapedToRoot { .. }) => {}
        Ok(p) if p.parent().is_some_and(|x| !x.as_os_str().is_empty()) => {
            // sandbox may not walk to fs root; still must not grant implicit /
        }
        other => panic!("implicit root must not be granted, got {other:?}"),
    }
}

#[test]
fn resolve_extra_root_allows_explicit_dir() {
    let dir = workspace();
    let extra = TempDir::new().expect("extra");
    let got = resolve_extra_root(dir.path(), extra.path().to_str().expect("utf8")).expect("ok");
    let want = dunce::canonicalize(extra.path()).expect("canon");
    assert_eq!(got, want);
}

#[test]
fn resolve_extra_root_rejects_implicit_host_temp() {
    let dir = workspace();
    let marker = TempDir::new().expect("implicit-temp marker");
    let via = marker.path().join("..");
    match resolve_extra_root(dir.path(), &via.to_string_lossy()) {
        Err(ExtraRootError::EscapedToRoot { .. }) => {}
        other => panic!("implicit host temp must be refused, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn resolve_extra_root_rejects_symlink_to_filesystem_root() {
    let dir = workspace();
    let link = dir.path().join("to-root");
    std::os::unix::fs::symlink("/", &link).expect("symlink to /");
    match resolve_extra_root(dir.path(), "to-root") {
        Err(ExtraRootError::EscapedToRoot { requested, .. }) => {
            assert!(requested.contains("to-root"), "{requested}");
        }
        other => panic!("symlink to / must be EscapedToRoot, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn resolve_extra_root_rejects_symlink_to_tmp() {
    let dir = workspace();
    let link = dir.path().join("to-tmp");
    std::os::unix::fs::symlink("/tmp", &link).expect("symlink to /tmp");
    match resolve_extra_root(dir.path(), "to-tmp") {
        Err(ExtraRootError::EscapedToRoot { .. }) => {}
        other => panic!("symlink to /tmp must be EscapedToRoot, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn resolve_extra_root_allows_explicit_tmp() {
    let dir = workspace();
    let got = resolve_extra_root(dir.path(), "/tmp").expect("explicit /tmp");
    assert!(
        got == Path::new("/tmp") || got == Path::new("/private/tmp"),
        "explicit /tmp resolved to {}",
        got.display()
    );
}
