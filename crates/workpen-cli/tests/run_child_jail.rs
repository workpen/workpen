//! Live `workpen run` uses child pre_exec, not parent apply.
#![cfg(unix)]

use std::process::Command;

use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn run_echo_succeeds_under_child_jail() {
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/bin/echo", "ok"])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
}

#[cfg(unix)]
#[test]
fn run_can_read_etc_when_granted() {
    if !std::path::Path::new("/etc").is_dir() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/bin/ls", "/etc"])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_cannot_write_outside_workspace() {
    let dir = TempDir::new().expect("workspace");
    let outside = TempDir::new().expect("outside");
    let marker = outside.path().join("should-not-exist");
    let script = format!("echo x > {}", marker.display());
    let _out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/bin/sh", "-c", &script])
        .output()
        .expect("spawn workpen");
    assert!(
        !marker.exists(),
        "child wrote outside workspace at {}",
        marker.display()
    );
}
