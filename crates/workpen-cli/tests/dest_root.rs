//! dest-deny for `why`/`run` must use --root, not process cwd.

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
