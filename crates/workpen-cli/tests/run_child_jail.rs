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

/// With a workspace `.env`, Linux remount skip must not start the child.
/// When remount (or Seatbelt) applies, echo still succeeds.
#[cfg(unix)]
#[test]
fn run_with_dotenv_hides_or_refuses() {
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join(".env"), "SECRET=1\n").expect("env");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", "/bin/echo", "ok"])
        .output()
        .expect("spawn workpen");
    if out.status.success() {
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
        return;
    }
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("remount unavailable") || err.contains("not started"),
        "fail-closed remount skip, stderr={err}"
    );
}

#[cfg(unix)]
#[test]
fn run_stdout_redirect_outside_workspace_is_readable() {
    let dir = TempDir::new().expect("workspace");
    let outside = TempDir::new().expect("outside");
    let dest = outside.path().join("out.txt");
    let file = std::fs::File::create(&dest).expect("create");
    let status = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/bin/echo", "ok"])
        .stdout(file)
        .status()
        .expect("spawn workpen");
    assert!(status.success(), "run with stdout outside --root");
    let body = std::fs::read_to_string(&dest).expect("read outside");
    assert_eq!(
        body.trim(),
        "ok",
        "parent must write captured stdout outside --root: {body:?}"
    );
}

#[cfg(unix)]
#[test]
fn run_forwards_stdin_without_timeout() {
    let dir = TempDir::new().expect("workspace");
    let mut child = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--", "/bin/cat"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn workpen");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"hi\n")
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hi\n",
        "no-timeout run must forward stdin: stdout={:?}",
        String::from_utf8_lossy(&out.stdout)
    );
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
fn python3_available() -> bool {
    Command::new("python3")
        .args(["-c", "print(1)"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
#[test]
fn run_timeout_large_stdout_is_captured() {
    if !python3_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args([
            "--timeout",
            "5s",
            "--",
            "python3",
            "-c",
            r#"print("x"*10**6)"#,
        ])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "1MiB print must finish under --timeout 5s, status={:?} stdout_len={} stderr={}",
        out.status.code(),
        out.stdout.len(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.len() >= 1_000_000,
        "stdout must be at least 1MiB, got {}",
        out.stdout.len()
    );
}

/// A child that prints until the deadline must not lose the drained
/// bytes when the CLI maps timeout to exit 124.
#[cfg(unix)]
#[test]
fn run_timeout_streaming_stdout_is_captured() {
    if !python3_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args([
            "--timeout",
            "1s",
            "--",
            "python3",
            "-c",
            "import sys\nwhile True:\n    sys.stdout.write('y\\n')\n    sys.stdout.flush()\n",
        ])
        .output()
        .expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(124),
        "streaming timeout must exit 124, stdout_len={} stderr={}",
        out.stdout.len(),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("deadline"),
        "timeout must name the deadline: {err}"
    );
    assert!(
        out.stdout.len() >= 64,
        "drained stdout must be kept on timeout, got {} bytes",
        out.stdout.len()
    );
}

/// 32MiB then sleep. Streaming copy must not keep a 32MiB Vec in the parent.
/// Do not use unbounded `yes` (issue #161).
#[cfg(unix)]
#[test]
fn run_timeout_stream_rss_stays_below_payload() {
    if !python3_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let dest = dir.path().join("out.bin");
    let file = std::fs::File::create(&dest).expect("out");
    let mut child = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args([
            "--timeout",
            "3s",
            "--",
            "python3",
            "-c",
            "import sys,time; sys.stdout.buffer.write(b'x'*32*1024*1024); sys.stdout.buffer.flush(); time.sleep(30)",
        ])
        .stdout(file)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn workpen");
    let pid = child.id();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sampler = {
        let stop = stop.clone();
        let peak = peak.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(kb) = rss_kb(pid) {
                    peak.fetch_max(kb, std::sync::atomic::Ordering::Relaxed);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    };
    let status = child.wait().expect("wait workpen");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = sampler.join();
    let peak = peak.load(std::sync::atomic::Ordering::Relaxed);
    let mut err = Vec::new();
    if let Some(mut s) = child.stderr.take() {
        use std::io::Read;
        let _ = s.read_to_end(&mut err);
    }
    assert_eq!(
        status.code(),
        Some(124),
        "32MiB then sleep must hit --timeout 3s, stderr={}",
        String::from_utf8_lossy(&err)
    );
    let n = std::fs::metadata(&dest).expect("meta").len();
    assert!(
        n >= 32 * 1024 * 1024,
        "redirected file must get the 32MiB payload, got {n}"
    );
    assert!(
        peak > 0 && peak < 40_000,
        "workpen RSS must stay under 40MiB while streaming 32MiB (buffered Vec would add ~32MiB), peak_kb={peak}"
    );
}

#[cfg(unix)]
fn rss_kb(pid: u32) -> Option<u64> {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(windows)]
#[test]
fn run_timeout_streaming_stdout_is_captured() {
    let dir = TempDir::new().expect("workspace");
    let src = dir.path().join("stream.rs");
    std::fs::write(
        &src,
        "fn main() { loop { use std::io::Write; let _ = std::io::stdout().write_all(b\"y\\n\"); let _ = std::io::stdout().flush(); } }\n",
    )
    .expect("stream.rs");
    let exe = dir.path().join("stream.exe");
    let rustc = Command::new("rustc")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .status()
        .expect("rustc");
    assert!(rustc.success(), "rustc stream.exe");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--timeout", "1s", "--"])
        .arg(&exe)
        .output()
        .expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(124),
        "streaming timeout must exit 124, stdout_len={} stderr={}",
        out.stdout.len(),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("deadline"),
        "timeout must name the deadline: {err}"
    );
    assert!(
        out.stdout.len() >= 64,
        "drained stdout must be kept on timeout, got {} bytes",
        out.stdout.len()
    );
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
