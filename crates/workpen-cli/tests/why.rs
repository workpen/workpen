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
