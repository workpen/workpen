//! dest-deny for `why`/`run` must use --root, not process cwd.

use std::fs;
use std::process::Command;

use tempfile::TempDir;

fn workpen() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workpen"))
}

/// Workspace with `.env` hardlinked as `notes.txt`, plus a plain `readme.md`.
/// Second temp dir is a cwd that is not the workspace.
fn workspace_with_env_hardlink() -> (TempDir, TempDir) {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    std::fs::write(ws.path().join(".env"), "SECRET=1\n").expect("write .env");
    std::fs::hard_link(ws.path().join(".env"), ws.path().join("notes.txt")).expect("hardlink");
    std::fs::write(ws.path().join("readme.md"), "ok\n").expect("write readme");
    (ws, cwd)
}

fn combined(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn why_dest_denies_hardlink_sibling_under_root_not_cwd() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["why", "--root"])
        .arg(ws.path())
        .arg("notes.txt")
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "why notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink") || lower.contains("deny"),
        "why dest-deny must mention hardlink or deny: {text}"
    );
    assert!(
        !stdout.trim().eq_ignore_ascii_case("allowed"),
        "why dest-deny must not be only allowed: {stdout}"
    );
}

#[test]
fn run_dest_denies_hardlink_sibling_under_root_before_spawn() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/cat", "notes.txt"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run cat notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink") || lower.contains("deny"),
        "run dest-deny must mention hardlink or deny: {text}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "run must dest-deny before spawn, stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_dest_denies_spaced_hardlink_argv_under_root_before_spawn() {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    std::fs::write(ws.path().join(".env"), "SECRET=1\n").expect("write .env");
    std::fs::hard_link(ws.path().join(".env"), ws.path().join("my notes.txt")).expect("hardlink");
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/cat"])
        .arg("my notes.txt")
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run cat my notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink") || lower.contains("deny"),
        "run dest-deny must mention hardlink or deny: {text}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "run must dest-deny before spawn, stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_dest_denies_hardlink_inside_sh_c_under_root_before_spawn() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/sh", "-c", "cat notes.txt"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run sh -c cat notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink") || lower.contains("deny"),
        "run dest-deny must mention hardlink or deny: {text}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "run must dest-deny before spawn, stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_refuses_dev_null_special_file_before_spawn() {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    if !std::path::Path::new("/dev/null").exists() {
        return;
    }
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/cat", "/dev/null"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run cat /dev/null must fail closed, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("special") || lower.contains("device") || lower.contains("refuse"),
        "run must name the special-file dest deny: {text}"
    );
}

#[test]
fn why_plain_file_under_root_is_allowed() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["why", "--root"])
        .arg(ws.path())
        .arg("readme.md")
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "why readme.md must be allowed, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
    assert!(
        stdout.contains("allowed"),
        "why readme.md must report allowed: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_relative_parent_root_dest_denies_hardlink_not_escape() {
    let parent = TempDir::new().expect("parent");
    let ws = parent.path().join("ws");
    let cwd = parent.path().join("here");
    fs::create_dir(&ws).expect("ws");
    fs::create_dir(&cwd).expect("cwd");
    fs::write(ws.join(".env"), "SECRET=1\n").expect("write .env");
    fs::hard_link(ws.join(".env"), ws.join("notes.txt")).expect("hardlink");
    for root in ["../ws", "./../ws"] {
        let out = workpen()
            .args(["run", "--root", root, "--", "/bin/cat", "notes.txt"])
            .current_dir(&cwd)
            .output()
            .expect("spawn workpen");
        assert!(
            !out.status.success(),
            "run --root {root} cat notes.txt must fail, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let text = combined(&out);
        let lower = text.to_ascii_lowercase();
        assert!(
            !lower.contains("escapes workspace"),
            "run --root {root} must not treat the workspace as an escape: {text}"
        );
        assert!(
            lower.contains("hardlink") || lower.contains("deny"),
            "run --root {root} dest-deny must mention hardlink or deny: {text}"
        );
        assert!(
            !stdout.contains("SECRET"),
            "run --root {root} must dest-deny before spawn, stdout={stdout}"
        );
    }
}

#[test]
fn run_missing_root_is_clear_error_not_escape() {
    let cwd = TempDir::new().expect("cwd");
    let out = workpen()
        .args([
            "run",
            "--root",
            "../no-such-workpen-ws",
            "--",
            "/bin/cat",
            "notes.txt",
        ])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "missing --root must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        !lower.contains("escapes workspace"),
        "missing --root must not claim an escape: {text}"
    );
    assert!(
        lower.contains("does not exist")
            || lower.contains("no such")
            || lower.contains("not a directory")
            || lower.contains("root"),
        "missing --root must be a clear root error: {text}"
    );
}
