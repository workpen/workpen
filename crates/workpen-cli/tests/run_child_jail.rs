//! Live `workpen run` jails the child, not the parent.

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

#[cfg(windows)]
#[test]
fn run_echo_succeeds_under_child_jail() {
    let dir = TempDir::new().expect("workspace");
    let comspec =
        std::env::var_os("COMSPEC").unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into());
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--"])
        .arg(comspec)
        .args(["/C", "echo ok"])
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

#[cfg(windows)]
#[test]
fn run_cannot_write_outside_workspace() {
    let dir = TempDir::new().expect("workspace");
    let outside = TempDir::new().expect("outside");
    let marker = outside.path().join("should-not-exist");
    let comspec =
        std::env::var_os("COMSPEC").unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into());
    let _out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--"])
        .arg(comspec)
        .args(["/C", &format!("echo x 1>{}", marker.display())])
        .output()
        .expect("spawn workpen");
    assert!(
        !marker.exists(),
        "child wrote outside workspace at {}",
        marker.display()
    );
}

#[cfg(windows)]
#[test]
fn run_can_write_inside_workspace() {
    let dir = TempDir::new().expect("workspace");
    let inside = dir.path().join("inside.txt");
    let comspec =
        std::env::var_os("COMSPEC").unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into());
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--"])
        .arg(comspec)
        .args(["/C", "echo ok 1>inside.txt"])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = std::fs::read_to_string(&inside).expect("inside write");
    assert!(body.contains("ok"), "inside body={body:?}");
}
