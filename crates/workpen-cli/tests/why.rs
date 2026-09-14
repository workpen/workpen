//! `workpen why` must fail when PathGuard cannot use --root.

use std::process::Command;

#[test]
fn why_errors_when_root_is_missing() {
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args([
            "why",
            "--root",
            "/no-such-workpen-root-xyz",
            "../etc/passwd",
        ])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "missing --root must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.stderr.is_empty(), "missing --root must print an error");
    let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
    assert!(
        !stdout.contains("allowed"),
        "missing --root must not report allowed: {stdout}"
    );
}

#[test]
fn why_errors_when_root_is_home() {
    let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) else {
        return;
    };
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["why", "--root"])
        .arg(&home)
        .arg("notes.txt")
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "home --root must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("home") || lower.contains("subdirectory"),
        "home --root must name home or say use a subdirectory: {text}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout)
            .trim()
            .eq_ignore_ascii_case("allowed"),
        "home --root must not report allowed"
    );
}

#[test]
fn why_honors_workspace_agent_lock_extra_glob() {
    let ws = tempfile::TempDir::new().expect("workspace");
    std::fs::write(ws.path().join("agent.lock"), "**/*.secret\n").expect("lock");
    std::fs::write(ws.path().join("team.secret"), "x\n").expect("secret");
    std::fs::write(ws.path().join("readme.md"), "ok\n").expect("readme");
    let deny = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["why", "--root"])
        .arg(ws.path())
        .arg("team.secret")
        .output()
        .expect("spawn workpen");
    assert!(
        !deny.status.success(),
        "why team.secret must dest-deny, stdout={} stderr={}",
        String::from_utf8_lossy(&deny.stdout),
        String::from_utf8_lossy(&deny.stderr)
    );
    let stdout = String::from_utf8_lossy(&deny.stdout);
    let text = format!("{}{}", stdout, String::from_utf8_lossy(&deny.stderr));
    let lower = text.to_ascii_lowercase();
    assert!(
        !stdout.to_ascii_lowercase().contains("allowed"),
        "why team.secret must not print allowed: {stdout}"
    );
    assert!(
        lower.contains("denied") || lower.contains("deny"),
        "why team.secret must dest-deny: {text}"
    );
    let allow = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["why", "--root"])
        .arg(ws.path())
        .arg("readme.md")
        .output()
        .expect("spawn workpen");
    assert!(
        allow.status.success(),
        "why readme.md must be allowed, stdout={} stderr={}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    let allowed = String::from_utf8_lossy(&allow.stdout);
    assert!(
        allowed.to_ascii_lowercase().contains("allowed"),
        "why readme.md must print allowed: {allowed}"
    );
}
