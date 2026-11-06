//! Windows long-lived re-exec jail.
//!
//! The child writes inside the read-write root, fails to write outside
//! it, fails to read a file outside it, and opens a socket. Loopback to
//! the parent listener is tried first. If Windows blocks AppContainer
//! loopback, TCP to 1.1.1.1 port 443 is the connect this test accepts.
//! The failure text names which connect succeeded.
//!
//! Unix `spawn_reexec` returns [`workpen::KernelError::Apply`] and does
//! not start the child.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use workpen::{KernelError, KernelPolicy, process_jail, reexec_profile_creates};

fn main() {
    if std::env::var_os("WORKPEN_REEXEC_PROBE").is_some() {
        std::process::exit(probe());
    }
    if let Err(err) = parent() {
        eprintln!("FAIL: {err}");
        std::process::exit(1);
    }
}

fn parent() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows_parent()
    }
    #[cfg(not(windows))]
    {
        unix_parent()
    }
}

#[cfg(not(windows))]
fn unix_parent() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
    let marker = dir.path().join("ran");
    let policy = jail(dir.path())?;
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "echo x > ran"]).current_dir(dir.path());
    match policy.spawn_reexec(cmd) {
        Err(KernelError::Apply(_)) => {}
        Ok(_) => return Err("unix spawn_reexec started the child".into()),
        Err(err) => return Err(format!("unix spawn_reexec: {err}")),
    }
    if marker.exists() {
        return Err("unix child wrote ran".into());
    }
    if reexec_profile_creates() != 0 {
        return Err("unix reexec profile count is not zero".into());
    }
    Ok(())
}

#[cfg(windows)]
fn windows_parent() -> Result<(), String> {
    if reexec_profile_creates() != 0 {
        return Err("reexec profile was created before the test".into());
    }
    let rw = tempfile::tempdir().map_err(|err| err.to_string())?;
    let fast = jail(rw.path())?.with_network(false);
    let mut cmd = Command::new(comspec());
    cmd.args(["/C", "echo hi"]).current_dir(rw.path());
    fast.run_child(cmd)
        .map_err(|err| format!("workspace run_child: {err}"))?;
    if reexec_profile_creates() != 0 {
        return Err("run_child created the re-exec profile".into());
    }

    let gone = tempfile::tempdir().map_err(|err| err.to_string())?;
    let gone_policy = jail(gone.path())?;
    let marker = gone.path().join("should-not-run");
    std::fs::remove_dir_all(gone.path()).map_err(|err| err.to_string())?;
    let mut cmd = Command::new(std::env::current_exe().map_err(|err| err.to_string())?);
    cmd.env("WORKPEN_REEXEC_PROBE", "1");
    match gone_policy.spawn_reexec(cmd) {
        Err(KernelError::Apply(_)) => {}
        Ok(_) => return Err("missing workspace still started a child".into()),
        Err(err) => return Err(format!("missing workspace: {err}")),
    }
    if marker.exists() {
        return Err("missing workspace child wrote a marker".into());
    }
    if reexec_profile_creates() != 0 {
        return Err("failed re-exec still created a profile".into());
    }

    let outside = tempfile::tempdir().map_err(|err| err.to_string())?;
    let hidden = outside.path().join("secret.txt");
    std::fs::write(&hidden, b"top-secret\n").map_err(|err| err.to_string())?;
    let sys = system_dll()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
    let port = listener.local_addr().map_err(|err| err.to_string())?.port();
    let policy = jail(rw.path())?;
    let first = run_probe(rw.path(), outside.path(), &hidden, &sys, port, &policy)?;
    assert_probe(&first, rw.path(), outside.path(), &hidden)?;
    let created = reexec_profile_creates();
    if created == 0 {
        return Err("first re-exec did not create a profile".into());
    }
    let second = run_probe(rw.path(), outside.path(), &hidden, &sys, port, &policy)?;
    assert_probe(&second, rw.path(), outside.path(), &hidden)?;
    if reexec_profile_creates() != created {
        return Err(format!(
            "second re-exec created another profile ({} then {})",
            created,
            reexec_profile_creates()
        ));
    }
    let connect = if has_line(&first, "LOOPBACK=ok") {
        "loopback"
    } else {
        "1.1.1.1:443"
    };
    println!("reexec connect: {connect}");
    let _ = listener;
    Ok(())
}

#[cfg(windows)]
fn run_probe(
    rw: &Path,
    outside: &Path,
    hidden: &Path,
    sys: &Path,
    port: u16,
    policy: &KernelPolicy,
) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    let mut cmd = Command::new(exe);
    cmd.current_dir(rw)
        .env("WORKPEN_REEXEC_PROBE", "1")
        .env("WORKPEN_REEXEC_RW", rw)
        .env("WORKPEN_REEXEC_OUT", outside)
        .env("WORKPEN_REEXEC_HIDDEN", hidden)
        .env("WORKPEN_REEXEC_SYS", sys)
        .env("WORKPEN_REEXEC_PORT", port.to_string());
    let (applied, output) = policy
        .spawn_reexec_output(cmd)
        .map_err(|err| format!("spawn_reexec: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(format!(
            "probe status {:?} applied {applied:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        ));
    }
    Ok(stdout)
}

#[cfg(windows)]
fn assert_probe(stdout: &str, rw: &Path, outside: &Path, hidden: &Path) -> Result<(), String> {
    if !has_line(stdout, "INSIDE=ok") {
        return Err(format!("inside write failed\n{stdout}"));
    }
    let inside = std::fs::read_to_string(rw.join("inside.txt")).map_err(|err| err.to_string())?;
    if inside.trim() != "ok" {
        return Err(format!("inside body {inside:?}"));
    }
    if !has_line(stdout, "OUTSIDE=absent") || outside.join("nope.txt").exists() {
        return Err(format!("child wrote outside the jail\n{stdout}"));
    }
    if !has_line(stdout, "SECRET=denied") {
        return Err(format!("child read the outside file\n{stdout}"));
    }
    let secret = std::fs::read_to_string(hidden).map_err(|err| err.to_string())?;
    if secret != "top-secret\n" {
        return Err("outside secret file changed".into());
    }
    if !has_line(stdout, "SYS=ok") {
        return Err(format!("child could not read System32\n{stdout}"));
    }
    if has_line(stdout, "SSH=read") {
        return Err(format!("child read the profile .ssh directory\n{stdout}"));
    }
    if !has_line(stdout, "LOOPBACK=ok") && !has_line(stdout, "OUTBOUND=ok") {
        return Err(format!(
            "no connect succeeded (loopback or 1.1.1.1:443)\n{stdout}"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn has_line(text: &str, want: &str) -> bool {
    text.lines().any(|line| line.trim() == want)
}

#[cfg(windows)]
fn system_dll() -> Result<PathBuf, String> {
    let root = std::env::var_os("SystemRoot").ok_or("SystemRoot is unset")?;
    let path = PathBuf::from(root).join("System32").join("kernel32.dll");
    if !path.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    Ok(path)
}

#[cfg(windows)]
fn comspec() -> String {
    std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into())
}

fn jail(path: &Path) -> Result<KernelPolicy, String> {
    process_jail(path, std::iter::empty::<&Path>()).map_err(|err| err.to_string())
}

fn probe() -> i32 {
    let (Some(rw), Some(outside), Some(hidden), Some(sys)) = (
        env_path("WORKPEN_REEXEC_RW"),
        env_path("WORKPEN_REEXEC_OUT"),
        env_path("WORKPEN_REEXEC_HIDDEN"),
        env_path("WORKPEN_REEXEC_SYS"),
    ) else {
        println!("PROBE=bad-env");
        return 2;
    };
    match std::fs::write(rw.join("inside.txt"), b"ok\n") {
        Ok(()) => println!("INSIDE=ok"),
        Err(err) => println!("INSIDE=fail {err}"),
    }
    match std::fs::write(outside.join("nope.txt"), b"x") {
        Ok(()) => println!("OUTSIDE=wrote"),
        Err(_) => println!("OUTSIDE=absent"),
    }
    match std::fs::read(&hidden) {
        Ok(_) => println!("SECRET=read"),
        Err(_) => println!("SECRET=denied"),
    }
    match std::fs::File::open(&sys) {
        Ok(_) => println!("SYS=ok"),
        Err(err) => println!("SYS=fail {err}"),
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        let ssh = PathBuf::from(home).join(".ssh");
        if ssh.is_dir() {
            match std::fs::read_dir(&ssh) {
                Ok(_) => println!("SSH=read"),
                Err(_) => println!("SSH=denied"),
            }
        } else {
            println!("SSH=missing");
        }
    } else {
        println!("SSH=missing");
    }
    let port = std::env::var("WORKPEN_REEXEC_PORT").unwrap_or_default();
    if tcp_ok(&format!("127.0.0.1:{port}"), 2) {
        println!("LOOPBACK=ok");
    } else {
        println!("LOOPBACK=fail");
    }
    if tcp_ok("1.1.1.1:443", 8) {
        println!("OUTBOUND=ok");
    } else {
        println!("OUTBOUND=fail");
    }
    0
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

fn tcp_ok(addr: &str, secs: u64) -> bool {
    let Ok(addr) = addr.parse() else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(secs)).is_ok()
}
