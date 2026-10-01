//! Live `workpen run` jails the child, not the parent.

use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::sync::Mutex;

use tempfile::TempDir;

#[cfg(unix)]
static PTY_TEST_LOCK: Mutex<()> = Mutex::new(());

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
const TTY_PROBE: &str = "if [ -t 1 ]; then printf tty; else printf pipe; fi";

#[cfg(unix)]
#[test]
fn run_without_tty_stdio_is_not_a_terminal() {
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", "/bin/sh", "-c", TTY_PROBE])
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("pipe"),
        "piped run must not be a tty: {stdout:?}"
    );
}

#[cfg(unix)]
#[test]
fn run_tty_stdio_is_a_terminal() {
    let _g = PTY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--tty", "--", "/bin/sh", "-c", TTY_PROBE])
        .stdin(Stdio::null())
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tty"),
        "--tty child stdout must be a terminal: {stdout:?} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn run_tty_still_dest_denies_env() {
    let _g = PTY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join(".env"), "SECRET=1\n").expect("env");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--tty", "--", "/bin/cat", ".env"])
        .stdin(Stdio::null())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "--tty cat .env must dest-deny, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !text.contains("SECRET"),
        "--tty must dest-deny before spawn: {text}"
    );
}

#[cfg(unix)]
#[test]
fn run_tty_timeout_kills_sleep() {
    let _g = PTY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--tty", "--timeout", "1s", "--", "/bin/sleep", "30"])
        .stdin(Stdio::null())
        .output()
        .expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(124),
        "--tty timeout must be 124, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(windows)]
#[test]
fn run_tty_is_unavailable_on_windows() {
    let dir = TempDir::new().expect("workspace");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--tty", "--", "cmd", "/c", "echo ok"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "--tty on Windows must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("tty") && err.contains("Windows"),
        "--tty must name Windows: {err}"
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

#[cfg(unix)]
#[test]
fn run_tty_forwards_stdin() {
    let _g = PTY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().expect("workspace");
    let mut child = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .arg("run")
        .arg("--root")
        .arg(dir.path())
        .args(["--tty", "--timeout", "2s", "--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
    assert_eq!(
        out.status.code(),
        Some(0),
        "--tty cat must exit 0 after stdin EOF, not hang until --timeout, stdout={:?} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert_eq!(
        stdout, "hi\n",
        "--tty piped stdin must reach cat once: stdout={stdout:?}"
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
fn run_scrubs_startup_env_even_when_opted_in() {
    if !printenv_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    for (name, value) in [
        ("PYTHONSTARTUP", "/tmp/evil.py"),
        ("PYTHONHOME", "/tmp/pyhome"),
        ("RUBYOPT", "-rvice"),
        ("LD_LIBRARY_PATH", "/tmp/evil"),
        ("NODE_PATH", "/tmp/node"),
    ] {
        let inherited = Command::new(env!("CARGO_BIN_EXE_workpen"))
            .env(name, value)
            .args(["run", "--root"])
            .arg(dir.path())
            .args(["--", "/usr/bin/printenv", name])
            .output()
            .expect("spawn");
        let stdout = String::from_utf8_lossy(&inherited.stdout);
        assert!(
            !inherited.status.success() && !stdout.contains(value),
            "inherited {name} must be absent: status={:?} out={stdout} err={}",
            inherited.status,
            String::from_utf8_lossy(&inherited.stderr)
        );
        let opted = Command::new(env!("CARGO_BIN_EXE_workpen"))
            .args(["run", "--root"])
            .arg(dir.path())
            .args([
                "--env",
                &format!("{name}={value}"),
                "--",
                "/usr/bin/printenv",
                name,
            ])
            .output()
            .expect("spawn");
        let stdout = String::from_utf8_lossy(&opted.stdout);
        assert!(
            !opted.status.success() && !stdout.contains(value),
            "--env {name} must stay removed: status={:?} out={stdout} err={}",
            opted.status,
            String::from_utf8_lossy(&opted.stderr)
        );
    }
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
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("remount unavailable"),
            "env without denied assignment must run or refuse remount skip: status={:?} stderr={err}",
            out.status
        );
        return;
    }
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

/// `connect(2)` to a Unix socket is network-outbound. `--net` must not
/// open a socket that sits under a dest-denied directory.
#[cfg(target_os = "macos")]
#[test]
fn net_cannot_connect_to_a_socket_under_a_denied_directory() {
    let probe = Command::new("python3")
        .arg("-c")
        .arg("import socket")
        .output();
    if !probe.is_ok_and(|out| out.status.success()) {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let secrets = dir.path().join("secrets");
    std::fs::create_dir(&secrets).expect("secrets");
    let sock = secrets.join("agent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .current_dir(dir.path())
        .args(["run", "--root"])
        .arg(dir.path())
        .args([
            "--timeout",
            "5s",
            "--net",
            "--",
            "python3",
            "-c",
            r#"import socket; s=socket.socket(socket.AF_UNIX); s.connect("secr"+"ets/agent.sock"); s.send(b"hi"); print("CONNECTED")"#,
        ])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("CONNECTED"),
        "socket under secrets/ must stay denied with --net: stdout={stdout} stderr={stderr}"
    );
    match listener.accept() {
        Ok(_) => panic!("listener accepted a jailed connection"),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(err) => panic!("accept: {err}"),
    }
}

/// A grandchild started with `Popen` must not keep running after `run`
/// returns. The direct child waits until that grandchild has written
/// its pid, then exits without waiting for it.
///
/// `mode=null` closes the grandchild's stdio so it does not hold the
/// parent's pipe. `mode=inherit` keeps the pipe open; `run` must not
/// block on that pipe past the leader's exit. `mode=setsid` is the
/// null case plus `os.setsid` in the grandchild. It does not plant a
/// dest-deny name: a workspace `.env` on a host that cannot enter a
/// user namespace refuses to start the child.
#[cfg(unix)]
fn background_writer_is_gone(timeout: Option<&str>, mode: &str, max_elapsed_ms: Option<u128>) {
    if !python3_available() {
        return;
    }
    let dir = TempDir::new().expect("workspace");
    let ws = dir.path().to_string_lossy().to_string();
    let script = r#"
import os, subprocess, sys, time
ws, mode = sys.argv[1], sys.argv[2]
py = sys.executable
child = r"""
import os, sys, time
ws, mode = sys.argv[1], sys.argv[2]
if mode == "setsid":
    os.setsid()
    outside = os.path.join("/tmp", "wp-setsid-" + os.path.basename(ws))
    try:
        open(outside, "w").write("x")
        probe = "tmp=open"
    except OSError as exc:
        probe = "tmp=" + type(exc).__name__
    open(os.path.join(ws, "probed.txt"), "w").write(probe + "\n")
open(os.path.join(ws, "child.pid"), "w").write(str(os.getpid()))
time.sleep(5)
open(os.path.join(ws, "done.txt"), "w").write("done\n")
"""
kw = {}
if mode == "null" or mode == "setsid":
    kw = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.Popen([py, "-c", child, ws, mode], **kw)
for _ in range(200):
    if os.path.exists(os.path.join(ws, "child.pid")):
        print("saw")
        raise SystemExit(0)
    time.sleep(0.05)
print("start-timeout")
raise SystemExit(1)
"#;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_workpen"));
    cmd.args(["run", "--root"]).arg(&ws);
    if let Some(limit) = timeout {
        cmd.args(["--timeout", limit]);
    }
    let started = std::time::Instant::now();
    let out = cmd
        .args(["--", "python3", "-c", script, &ws, mode])
        .output()
        .expect("spawn");
    let elapsed_ms = started.elapsed().as_millis();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "run must return success, stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("saw"),
        "parent must observe the grandchild start: {stdout} stderr={stderr}"
    );
    if let Some(limit_ms) = max_elapsed_ms {
        assert!(
            elapsed_ms < limit_ms,
            "run took {elapsed_ms}ms, limit {limit_ms}ms, stdout={stdout} stderr={stderr}"
        );
    }
    let pid = std::fs::read_to_string(dir.path().join("child.pid")).expect("pid");
    let pid = pid.trim().to_string();
    let mut alive = true;
    for _ in 0..10 {
        let check = Command::new("/bin/kill")
            .args(["-0", &pid])
            .stderr(Stdio::null())
            .status();
        alive = check.is_ok_and(|status| status.success());
        if !alive {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = Command::new("/bin/kill")
        .args(["-9", &pid])
        .stderr(Stdio::null())
        .status();
    assert!(
        !dir.path().join("done.txt").exists(),
        "grandchild must not finish its sleep"
    );
    assert!(
        !alive,
        "grandchild pid {pid} still alive after run returned"
    );
    if mode == "setsid" {
        let outside = std::path::PathBuf::from(format!(
            "/tmp/wp-setsid-{}",
            dir.path().file_name().expect("name").to_string_lossy()
        ));
        let leaked = outside.exists();
        let probe = std::fs::read_to_string(dir.path().join("probed.txt")).unwrap_or_default();
        let _ = std::fs::remove_file(&outside);
        assert!(
            !probe.contains("tmp=open") && !leaked,
            "write outside the workspace must fail: probe={probe} leaked={leaked}"
        );
    }
}

#[cfg(unix)]
#[test]
fn background_writer_dies_when_run_returns() {
    background_writer_is_gone(None, "null", None);
}

#[cfg(unix)]
#[test]
fn background_setsid_writer_dies_when_run_returns() {
    background_writer_is_gone(None, "setsid", None);
}

#[cfg(unix)]
#[test]
fn background_writer_dies_when_early_exit_beats_timeout() {
    background_writer_is_gone(Some("30s"), "null", None);
}

#[cfg(unix)]
#[test]
fn background_stdout_holder_does_not_stretch_timeout() {
    background_writer_is_gone(Some("1s"), "inherit", Some(3000));
}

#[cfg(unix)]
const DESCENDANTS_STOPPED: &str = "descendants were not fully stopped";

#[cfg(unix)]
fn pid_alive(pid: &str) -> bool {
    Command::new("/bin/kill")
        .args(["-0", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn kill_pid(pid: &str) {
    let _ = Command::new("/bin/kill")
        .args(["-9", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Kills every pid in `pids.txt` when the test ends, including on panic.
#[cfg(unix)]
struct KillPidFile(std::path::PathBuf);

#[cfg(unix)]
impl Drop for KillPidFile {
    fn drop(&mut self) {
        let Ok(text) = std::fs::read_to_string(&self.0) else {
            return;
        };
        for pid in text.split_whitespace() {
            kill_pid(pid);
        }
    }
}

#[cfg(unix)]
fn run_setsid_herd(n: usize, expect_signal: bool) {
    assert!(
        python3_available(),
        "python3 is required to prove the descendant cap"
    );
    let dir = TempDir::new().expect("workspace");
    let ws = dir.path().to_string_lossy().to_string();
    let pid_file = dir.path().join("pids.txt");
    let _cleanup = KillPidFile(pid_file.clone());
    let script = r#"
import os, subprocess, sys, time
n = int(sys.argv[1])
ws = sys.argv[2]
py = sys.executable
code = r'''
import os, sys, time
os.setsid()
fd = os.open("/dev/null", os.O_RDWR)
os.dup2(fd, 0)
os.dup2(fd, 1)
os.dup2(fd, 2)
open(sys.argv[1], "w").write("ready")
time.sleep(30)
'''
pids = []
for i in range(n):
    ready = os.path.join(ws, "ready-%d" % i)
    proc = subprocess.Popen(
        [py, "-c", code, ready],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pids.append(proc.pid)
with open(os.path.join(ws, "pids.txt"), "w") as handle:
    handle.write("\n".join(str(pid) for pid in pids) + "\n")
deadline = time.time() + 20
while time.time() < deadline:
    got = 0
    for i in range(n):
        if os.path.exists(os.path.join(ws, "ready-%d" % i)):
            got += 1
    if got == n:
        time.sleep(0.3)
        raise SystemExit(0)
    time.sleep(0.02)
sys.stderr.write("started %d of %d\n" % (got, n))
raise SystemExit(2)
"#;
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(&ws)
        .args(["--timeout", "45s", "--", "python3", "-c", script])
        .arg(n.to_string())
        .arg(&ws)
        .output()
        .expect("spawn workpen");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let pids = std::fs::read_to_string(&pid_file).unwrap_or_default();
    let mut alive = Vec::new();
    for pid in pids.split_whitespace() {
        if pid_alive(pid) {
            alive.push(pid.to_string());
        }
    }
    if expect_signal {
        assert!(
            !out.status.success(),
            "n={n} must not succeed when a descendant pid cannot be stored, alive={alive:?} stdout={stdout} stderr={stderr}"
        );
        assert_eq!(
            out.status.code(),
            Some(4),
            "n={n} must exit 4, alive={alive:?} stdout={stdout} stderr={stderr}"
        );
        assert!(
            stderr.contains(DESCENDANTS_STOPPED),
            "n={n} stderr must say descendants were not fully stopped: {stderr}"
        );
        assert!(
            !stderr.contains("failed to spawn"),
            "n={n} must not look like a spawn failure: {stderr}"
        );
    } else {
        assert!(
            out.status.success(),
            "n={n} must succeed, alive={alive:?} stdout={stdout} stderr={stderr}"
        );
    }
    assert!(
        alive.is_empty(),
        "n={n} left setsid grandchildren alive: {alive:?} stdout={stdout} stderr={stderr}"
    );
}

#[cfg(unix)]
#[test]
fn run_stops_one_hundred_twenty_eight_setsid_children() {
    run_setsid_herd(128, false);
}

#[cfg(unix)]
#[test]
fn run_reports_when_descendant_cap_is_exceeded() {
    run_setsid_herd(129, true);
}

#[cfg(unix)]
const RACER_C: &str = r#"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }
    if (pid == 0) {
        if (setsid() < 0) {
            _exit(1);
        }
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2) {
                close(fd);
            }
        }
        for (;;) {
            pause();
        }
    }
    FILE *handle = fopen(argv[1], "w");
    if (handle == 0) {
        _exit(1);
    }
    fprintf(handle, "%ld\n", (long)pid);
    fclose(handle);
    _exit(0);
}
"#;

#[cfg(unix)]
fn compile_c(dir: &std::path::Path, name: &str, source: &str) -> Option<std::path::PathBuf> {
    let src = dir.join(format!("{name}.c"));
    let bin = dir.join(name);
    std::fs::write(&src, source).ok()?;
    let compiled = Command::new("cc")
        .arg("-O2")
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if compiled.success() { Some(bin) } else { None }
}

fn compile_setsid_racer(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    compile_c(dir, "racer", RACER_C)
}

/// Fork, `setsid`, and `_exit` before a 2ms poll can see the child.
/// Success means that child is dead. Any other status must say the
/// tree was not fully stopped. Skips when `cc` cannot build the helper.
#[cfg(unix)]
#[test]
fn run_stops_or_reports_a_fast_setsid_orphan() {
    let dir = TempDir::new().expect("workspace");
    let Some(bin) = compile_setsid_racer(dir.path()) else {
        return;
    };
    let ws = dir.path().to_string_lossy().to_string();
    for trial in 0..20 {
        let pid_path = dir.path().join(format!("child-{trial}.pid"));
        let _cleanup = KillPidFile(pid_path.clone());
        let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
            .args(["run", "--root"])
            .arg(&ws)
            .args(["--timeout", "5s", "--"])
            .arg(&bin)
            .arg(&pid_path)
            .output()
            .expect("spawn workpen");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let pid = std::fs::read_to_string(&pid_path).unwrap_or_default();
        let pid = pid.trim();
        assert!(
            !pid.is_empty(),
            "trial {trial} did not record a child pid, stdout={stdout} stderr={stderr}"
        );
        let alive = pid_alive(pid);
        if out.status.success() {
            assert!(
                !alive,
                "trial {trial} returned success while pid {pid} was still alive, stdout={stdout} stderr={stderr}"
            );
        } else {
            assert_eq!(
                out.status.code(),
                Some(4),
                "trial {trial} must exit 4 when the child tree is incomplete, alive={alive} stdout={stdout} stderr={stderr}"
            );
            assert!(
                stderr.contains(DESCENDANTS_STOPPED),
                "trial {trial} stderr must say descendants were not fully stopped: {stderr}"
            );
        }
    }
}

#[cfg(unix)]
const DECOY_RACER_C: &str = r#"
#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static void park(void) {
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) {
            close(fd);
        }
    }
    for (;;) {
        pause();
    }
}

int main(int argc, char **argv) {
    int status = 0;
    pid_t mid;
    pid_t decoy;
    pid_t hop;
    if (argc < 2) {
        return 2;
    }
    mid = fork();
    if (mid < 0) {
        return 1;
    }
    if (mid != 0) {
        if (waitpid(mid, &status, 0) != mid) {
            return 1;
        }
        usleep(20000);
        return 0;
    }
    decoy = fork();
    if (decoy < 0) {
        _exit(1);
    }
    if (decoy == 0) {
        if (setsid() < 0) {
            _exit(1);
        }
        park();
    }
    /* Recorded sleeper, then a fork that exits before its child can be listed. */
    usleep(50000);
    hop = fork();
    if (hop < 0) {
        _exit(1);
    }
    if (hop == 0) {
        pid_t orphan = fork();
        FILE *handle;
        if (orphan < 0) {
            _exit(1);
        }
        if (orphan == 0) {
            if (setsid() < 0) {
                _exit(1);
            }
            park();
        }
        handle = fopen(argv[1], "w");
        if (handle == 0) {
            _exit(1);
        }
        fprintf(handle, "%ld\n%ld\n", (long)decoy, (long)orphan);
        fclose(handle);
        _exit(0);
    }
    _exit(0);
}
"#;

/// A recorded sleeper must not hide a later fork that exits immediately.
#[cfg(unix)]
#[test]
fn run_stops_or_reports_a_setsid_orphan_after_a_decoy() {
    let dir = TempDir::new().expect("workspace");
    let Some(bin) = compile_c(dir.path(), "decoy", DECOY_RACER_C) else {
        return;
    };
    let ws = dir.path().to_string_lossy().to_string();
    for trial in 0..10 {
        let pid_path = dir.path().join(format!("decoy-{trial}.pid"));
        let _cleanup = KillPidFile(pid_path.clone());
        let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
            .args(["run", "--root"])
            .arg(&ws)
            .args(["--timeout", "5s", "--"])
            .arg(&bin)
            .arg(&pid_path)
            .output()
            .expect("spawn workpen");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let text = std::fs::read_to_string(&pid_path).unwrap_or_default();
        let mut pids = text.split_whitespace();
        let decoy = pids.next().unwrap_or("").to_string();
        let orphan = pids.next().unwrap_or("").to_string();
        assert!(
            !decoy.is_empty() && !orphan.is_empty(),
            "trial {trial} did not record both pids, text={text:?} stdout={stdout} stderr={stderr}"
        );
        let orphan_alive = pid_alive(&orphan);
        if out.status.success() {
            assert!(
                !orphan_alive,
                "trial {trial} returned success while orphan {orphan} was still alive, stdout={stdout} stderr={stderr}"
            );
            assert!(
                !pid_alive(&decoy),
                "trial {trial} returned success while decoy {decoy} was still alive, stdout={stdout} stderr={stderr}"
            );
            assert!(
                !stderr.contains(DESCENDANTS_STOPPED),
                "trial {trial} succeeded but still reported a miss: {stderr}"
            );
        } else {
            assert_eq!(
                out.status.code(),
                Some(4),
                "trial {trial} must exit 4 when the orphan was not tracked, orphan_alive={orphan_alive} stdout={stdout} stderr={stderr}"
            );
            assert!(
                stderr.contains(DESCENDANTS_STOPPED),
                "trial {trial} stderr must say descendants were not fully stopped: {stderr}"
            );
        }
    }
}

#[cfg(unix)]
const REAPED_FORKS_C: &str = r#"
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    for (int i = 0; i < 8; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            return 1;
        }
        if (pid == 0) {
            _exit(0);
        }
        int status = 0;
        if (waitpid(pid, &status, 0) != pid) {
            return 1;
        }
    }
    return 0;
}
"#;

/// Fork plus wait is a finished helper, not an escaped descendant.
#[cfg(unix)]
#[test]
fn run_reaped_forks_do_not_report_a_miss() {
    let dir = TempDir::new().expect("workspace");
    let Some(bin) = compile_c(dir.path(), "reaped", REAPED_FORKS_C) else {
        return;
    };
    let ws = dir.path().to_string_lossy().to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_workpen"))
        .args(["run", "--root"])
        .arg(&ws)
        .args(["--timeout", "5s", "--"])
        .arg(&bin)
        .output()
        .expect("spawn workpen");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "reaped helpers must succeed, status={:?} stderr={stderr}",
        out.status.code()
    );
    assert!(
        !stderr.contains(DESCENDANTS_STOPPED),
        "reaped helpers must not report an untracked descendant: {stderr}"
    );
}
