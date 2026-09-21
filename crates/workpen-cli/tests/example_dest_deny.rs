//! examples/dest-deny.sh must stay a live dest-deny demo.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

#[test]
fn dest_deny_example_blocks_secret_and_hardlink() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = root.join("examples/dest-deny.sh");
    let out = Command::new("bash")
        .arg(&script)
        .env("WORKPEN", env!("CARGO_BIN_EXE_workpen"))
        .output()
        .expect("spawn dest-deny.sh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "dest-deny.sh must succeed, stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("deny glob") && stdout.contains(".env"),
        "must dest-deny .env: {stdout}"
    );
    assert!(
        stdout.contains("hardlink") && stdout.contains("notes.txt"),
        "must dest-deny hardlink notes.txt: {stdout}"
    );
    assert!(
        stdout.contains("hello notes"),
        "must print ordinary notes.md: {stdout}"
    );
    let blocked = stdout.matches("blocked").count();
    assert_eq!(blocked, 2, "must print blocked twice: {stdout}");
    assert!(stdout.contains("allowed"), "must print allowed: {stdout}");
    assert!(
        !stdout.contains("SECRET=1"),
        "must not leak SECRET: {stdout}"
    );
}
