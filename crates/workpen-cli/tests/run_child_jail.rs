//! Live `workpen run` jails the child, not the parent.

use std::process::Command;

use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn run_echo_succeeds_without_bash_rewrite() {
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

#[cfg(target_os = "macos")]
#[test]
fn run_sh_c_echo_does_not_warn_var_select() {
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/bin/sh", "-c", "echo ok"])
        .output()
        .expect("spawn workpen");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr={err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
    assert!(
        !err.contains("var/select"),
        "sh -c must not warn on /var/select: {err}"
    );
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

#[cfg(unix)]
#[test]
fn run_timeout_kills_sleep() {
    let dir = TempDir::new().expect("workspace");
    let start = std::time::Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--timeout", "1s", "--", "/bin/sleep", "30"])
        .output()
        .expect("spawn workpen");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "timeout must return in under 10s: {:?}",
        start.elapsed()
    );
    assert_eq!(
        out.status.code(),
        Some(124),
        "timeout must exit 124, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("deadline"),
        "timeout must name the deadline: {err}"
    );
}

#[cfg(windows)]
#[test]
fn run_timeout_kills_sleeper() {
    let dir = TempDir::new().expect("workspace");
    let src = dir.path().join("sleep.rs");
    std::fs::write(
        &src,
        "fn main() { std::thread::sleep(std::time::Duration::from_secs(30)); }\n",
    )
    .expect("sleep.rs");
    let exe = dir.path().join("sleep.exe");
    let rustc = Command::new("rustc")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .status()
        .expect("rustc");
    assert!(rustc.success(), "rustc sleep.exe");
    let start = std::time::Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--timeout", "1s", "--"])
        .arg(&exe)
        .output()
        .expect("spawn workpen");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "timeout must return in under 10s: {:?}",
        start.elapsed()
    );
    assert_eq!(
        out.status.code(),
        Some(124),
        "timeout must exit 124, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("deadline"),
        "timeout must name the deadline: {err}"
    );
}

#[cfg(unix)]
#[test]
fn run_timeout_fast_command_succeeds() {
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--timeout", "5s", "--", "/bin/echo", "ok"])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "fast command must succeed, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
}

#[cfg(unix)]
fn printenv_available() -> bool {
    std::path::Path::new("/usr/bin/printenv").is_file()
}

#[cfg(unix)]
fn combined(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[cfg(unix)]
#[test]
fn run_scrubs_inherited_xai_api_key() {
    if !printenv_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .env("XAI_API_KEY", "secret")
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/usr/bin/printenv", "XAI_API_KEY"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "inherited XAI_API_KEY must be absent: status={:?} out={}",
        out.status,
        combined(&out)
    );
    assert!(
        !combined(&out).contains("secret"),
        "inherited XAI_API_KEY must not leak: {}",
        combined(&out)
    );
}

#[cfg(unix)]
#[test]
fn run_scrubs_inherited_ld_preload() {
    if !printenv_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .env("LD_PRELOAD", "evil.so")
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/usr/bin/printenv", "LD_PRELOAD"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "inherited LD_PRELOAD must be absent: status={:?} out={}",
        out.status,
        combined(&out)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("evil.so"),
        "child stdout must not print LD_PRELOAD: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_scrubs_inherited_bash_env() {
    if !printenv_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .env("BASH_ENV", "/tmp/evil.sh")
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/usr/bin/printenv", "BASH_ENV"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "inherited BASH_ENV must be absent: status={:?} out={}",
        out.status,
        combined(&out)
    );
    assert!(
        !combined(&out).contains("/tmp/evil.sh"),
        "inherited BASH_ENV must not leak: {}",
        combined(&out)
    );
}

#[cfg(unix)]
#[test]
fn run_keeps_inherited_path() {
    if !printenv_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .env("PATH", "/usr/bin:/bin")
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/usr/bin/printenv", "PATH"])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "PATH must remain: status={:?} out={}",
        out.status,
        combined(&out)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains('/'),
        "printenv PATH must print a path: {stdout:?}"
    );
}

#[cfg(unix)]
fn login_bash_home() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = TempDir::new().expect("workspace");
    let home = dir.path().join("home");
    std::fs::create_dir(&home).expect("home");
    let home = std::fs::canonicalize(&home).expect("canon home");
    let marker = home.join("profile-ran");
    std::fs::write(
        home.join(".bash_profile"),
        "echo PROFILE_RAN\ntouch \"$HOME/profile-ran\"\n",
    )
    .expect("bash_profile");
    (dir, home, marker)
}

#[cfg(unix)]
#[test]
fn run_inserts_noprofile_so_login_bash_skips_home_profile() {
    if !std::path::Path::new("/bin/bash").is_file() {
        return;
    }
    let (dir, home, marker) = login_bash_home();
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .env("HOME", &home)
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/bin/bash", "-l", "-c", "true"])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "login bash -c true must succeed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !marker.exists(),
        "login bash must not run HOME/.bash_profile"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("PROFILE_RAN"),
        "login bash must not print profile output: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_inserts_noprofile_so_env_login_bash_skips_home_profile() {
    let env_bin = ["/usr/bin/env", "/bin/env"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file());
    let Some(env_bin) = env_bin else {
        return;
    };
    if !std::path::Path::new("/bin/bash").is_file() {
        return;
    }
    let (dir, home, marker) = login_bash_home();
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .env("HOME", &home)
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", env_bin, "bash", "-l", "-c", "true"])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "env login bash -c true must succeed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !marker.exists(),
        "env login bash must not run HOME/.bash_profile"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("PROFILE_RAN"),
        "env login bash must not print profile output: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_drops_env_argv_bash_env_assignment() {
    let env_bin = ["/usr/bin/env", "/bin/env"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file());
    let Some(env_bin) = env_bin else {
        return;
    };
    if !std::path::Path::new("/bin/bash").is_file() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join(".env"), "SECRET=1\n").expect("write .env");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args([
            "--",
            env_bin,
            "BASH_ENV=.env",
            "bash",
            "-c",
            r#"printf %s "$BASH_ENV""#,
        ])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "env without denied assignment must still run: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(".env"),
        "env BASH_ENV=.env must be dropped: {stdout:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn run_extra_root_tmp_can_write_presented_path() {
    if !std::path::Path::new("/tmp").is_dir() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let marker = std::path::PathBuf::from(format!(
        "/tmp/workpen-extra-root-{}-{stamp}",
        std::process::id()
    ));
    let script = dir.path().join("write.sh");
    std::fs::write(
        &script,
        format!(
            "printf x > {}\ncat {}\n",
            marker.display(),
            marker.display()
        ),
    )
    .expect("write.sh");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--extra-root", "/tmp", "--", "/bin/sh", "write.sh"])
        .output()
        .expect("spawn workpen");
    let wrote = std::fs::read_to_string(&marker).ok();
    let _ = std::fs::remove_file(&marker);
    assert!(
        out.status.success(),
        "run --extra-root /tmp must write presented /tmp, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(wrote.as_deref(), Some("x"), "presented /tmp marker");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains('x'), "child must cat the marker: {stdout}");
}
