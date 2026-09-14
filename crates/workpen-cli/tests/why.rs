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
