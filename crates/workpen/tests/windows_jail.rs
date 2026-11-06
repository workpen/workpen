//! Windows jail behavior. Feature `nono`. Other platforms compile an
//! empty harness. The AppContainer cache and `USERPROFILE` are
//! process-wide, so each test holds one lock.

#![cfg(all(windows, feature = "nono"))]

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use tempfile::TempDir;
use workpen::{
    process_jail, reset_windows_appcontainer_creates, shutdown_process_jail,
    windows_appcontainer_creates,
};

static LOCK: Mutex<()> = Mutex::new(());

fn with_jail_lock(body: impl FnOnce()) {
    let _guard = LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let prev = std::env::var_os("USERPROFILE");
    struct Restore(Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            shutdown_process_jail();
            reset_windows_appcontainer_creates();
            match &self.0 {
                Some(value) => unsafe { std::env::set_var("USERPROFILE", value) },
                None => unsafe { std::env::remove_var("USERPROFILE") },
            }
        }
    }
    let _restore = Restore(prev);
    shutdown_process_jail();
    reset_windows_appcontainer_creates();
    body();
}

fn cmd() -> PathBuf {
    std::env::var_os("COMSPEC")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"))
}

fn com(build: impl FnOnce(&mut Command)) -> Command {
    let mut command = Command::new(cmd());
    build(&mut command);
    command
}

fn git_cat() -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from(r"C:\Program Files\Git\usr\bin\cat.exe")];
    if let Some(root) = std::env::var_os("ProgramFiles") {
        candidates.push(PathBuf::from(root).join(r"Git\usr\bin\cat.exe"));
    }
    if let Some(root) = std::env::var_os("ProgramFiles(x86)") {
        candidates.push(PathBuf::from(root).join(r"Git\usr\bin\cat.exe"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn output_text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn windows_jail_captured_stdout_still_returns_text() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        for blocked in [false, true] {
            let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
                .expect("jail")
                .with_network(blocked);
            let (applied, output) = policy
                .run_child_output(com(|command| {
                    command.args(["/C", "echo hi"]);
                }))
                .unwrap_or_else(|err| panic!("blocked={blocked}: {err}"));
            assert!(
                output.status.success(),
                "blocked={blocked} echo failed ({applied:?}): {}",
                output_text(&output)
            );
            assert!(
                output.stdout.windows(2).any(|chunk| chunk == b"hi"),
                "blocked={blocked} stdout must contain hi: {}",
                output_text(&output)
            );
        }
    });
}

#[test]
fn windows_jail_runs_git_usr_bin_cat() {
    with_jail_lock(|| {
        let Some(cat) = git_cat() else {
            eprintln!("skip: Git for Windows is not installed");
            return;
        };
        let ws = TempDir::new().expect("workspace");
        fs::write(ws.path().join("hello.txt"), b"hello-from-git\n").expect("hello");
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("jail")
            .with_network(false);
        let (applied, output) = policy
            .run_child_output({
                let mut command = Command::new(&cat);
                command.arg(ws.path().join("hello.txt"));
                command
            })
            .unwrap_or_else(|err| panic!("{err}"));
        assert!(
            output.status.success(),
            "git cat must exit 0 ({applied:?}): {}",
            output_text(&output)
        );
        assert!(
            output
                .stdout
                .windows(b"hello-from-git".len())
                .any(|c| c == b"hello-from-git"),
            "git cat stdout: {}",
            output_text(&output)
        );
        let outside = TempDir::new().expect("outside");
        let marker = outside.path().join("nope.txt");
        let script = format!("echo x 1>{}", marker.display());
        let _ = policy.run_child(com(|command| {
            command.args(["/C", &script]);
        }));
        assert!(
            !marker.exists(),
            "git jail must not write outside the grant"
        );
    });
}

#[test]
fn windows_workspace_jail_denies_profile_secret_dirs() {
    with_jail_lock(|| {
        let profile = TempDir::new().expect("profile");
        unsafe { std::env::set_var("USERPROFILE", profile.path()) };
        let names = [".ssh", ".aws", ".gnupg", ".azure", r".config\gh", ".docker"];
        let mut secrets = Vec::new();
        for name in names {
            let dir = profile.path().join(name);
            fs::create_dir_all(&dir).expect("secret dir");
            let file = dir.join("secret.txt");
            fs::write(&file, b"secret-bytes").expect("secret");
            secrets.push(file);
        }
        // `.kube` is on the deny list and is absent. Prepare must skip it.
        assert!(!profile.path().join(".kube").exists());
        let ws = TempDir::new().expect("workspace");
        fs::write(ws.path().join("note.txt"), b"workspace-ok").expect("note");
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("jail")
            .with_network(false);
        let (_applied, output) = policy
            .run_child_output(com(|command| {
                command.current_dir(ws.path()).args(["/C", "type note.txt"]);
            }))
            .expect("read workspace");
        assert!(
            output.status.success(),
            "workspace read: {}",
            output_text(&output)
        );
        assert!(
            output
                .stdout
                .windows(b"workspace-ok".len())
                .any(|c| c == b"workspace-ok")
        );
        for secret in &secrets {
            let script = format!("type {}", secret.display());
            let (_applied, output) = policy
                .run_child_output(com(|command| {
                    command.args(["/C", &script]);
                }))
                .unwrap_or_else(|err| panic!("spawn type {}: {err}", secret.display()));
            assert!(
                !output.status.success(),
                "child must not read {}: {}",
                secret.display(),
                output_text(&output)
            );
            assert!(
                !output
                    .stdout
                    .windows(b"secret-bytes".len())
                    .any(|c| c == b"secret-bytes"),
                "secret bytes leaked from {}",
                secret.display()
            );
        }
        let outside = TempDir::new().expect("outside");
        let marker = outside.path().join("nope.txt");
        let script = format!("echo x 1>{}", marker.display());
        let _ = policy.run_child(com(|command| {
            command.args(["/C", &script]);
        }));
        assert!(!marker.exists(), "write outside the grant must fail");
        for secret in &secrets {
            let body = fs::read(secret)
                .unwrap_or_else(|err| panic!("parent read {}: {err}", secret.display()));
            assert_eq!(
                body,
                b"secret-bytes",
                "parent must still read {}",
                secret.display()
            );
        }
        let sleeper = ws.path().join("sleep.cmd");
        fs::write(&sleeper, b"@echo off\r\nping -n 30 127.0.0.1 >nul\r\n").expect("sleeper");
        let err = policy
            .run_child_timeout(
                com(|command| {
                    command.arg("/C").arg(&sleeper);
                }),
                Duration::from_secs(1),
            )
            .expect_err("timeout");
        assert!(
            matches!(err, workpen::KernelError::Timeout),
            "kill must be Timeout, got {err}"
        );
        for secret in &secrets {
            assert_eq!(
                fs::read(secret).expect("parent read after kill"),
                b"secret-bytes",
                "ACE must be restored after the child is killed"
            );
        }
    });
}

#[test]
fn windows_network_jail_reuses_one_appcontainer() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>()).expect("jail");
        for _ in 0..2 {
            policy
                .run_child_output(com(|command| {
                    command.args(["/C", "echo hi"]);
                }))
                .expect("network-blocked echo");
        }
        assert_eq!(
            windows_appcontainer_creates(),
            1,
            "two network-blocked commands must share one profile"
        );
        shutdown_process_jail();
        policy
            .run_child_output(com(|command| {
                command.args(["/C", "echo hi"]);
            }))
            .expect("echo after shutdown");
        assert_eq!(
            windows_appcontainer_creates(),
            2,
            "shutdown must allow the next command to create again"
        );
        let before = windows_appcontainer_creates();
        let open = process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("jail")
            .with_network(false);
        open.run_child_output(com(|command| {
            command.args(["/C", "echo hi"]);
        }))
        .expect("workspace echo");
        assert_eq!(
            windows_appcontainer_creates(),
            before,
            "workspace must not create an AppContainer"
        );
    });
}

#[test]
fn windows_strict_jail_reads_workspace_and_system32_only() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        fs::write(ws.path().join("note.txt"), b"strict-ok").expect("note");
        let outside = TempDir::new().expect("outside");
        fs::write(outside.path().join("secret.txt"), b"outside-bytes").expect("outside");
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>()).expect("strict");
        let (_applied, output) = policy
            .run_child_output(com(|command| {
                command.current_dir(ws.path()).args(["/C", "type note.txt"]);
            }))
            .expect("read workspace");
        assert!(output.status.success(), "{}", output_text(&output));
        let (_applied, echo) = policy
            .run_child_output(com(|command| {
                command.args(["/C", "echo cmd-ok"]);
            }))
            .expect("cmd");
        assert!(
            echo.status.success(),
            "System32 cmd must start: {}",
            output_text(&echo)
        );
        let outside_file = outside.path().join("secret.txt");
        let (_applied, denied) = policy
            .run_child_output(com(|command| {
                let script = format!("type {}", outside_file.display());
                command.args(["/C", &script]);
            }))
            .expect("type outside");
        assert!(
            !denied.status.success(),
            "strict child must not read {}: {}",
            outside_file.display(),
            output_text(&denied)
        );
        assert!(
            !denied
                .stdout
                .windows(b"outside-bytes".len())
                .any(|c| c == b"outside-bytes")
        );
    });
}

#[test]
fn windows_readonly_jail_cannot_create_in_workspace() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        fs::write(ws.path().join("note.txt"), b"read-ok").expect("note");
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("jail")
            .read_only();
        let created = ws.path().join("created.txt");
        let _ = policy.run_child(com(|command| {
            let script = format!("echo x 1>{}", created.display());
            command.args(["/C", &script]);
        }));
        assert!(
            !created.exists(),
            "read-only child must not create in the workspace"
        );
        let (_applied, output) = policy
            .run_child_output(com(|command| {
                command.current_dir(ws.path()).args(["/C", "type note.txt"]);
            }))
            .expect("read");
        assert!(
            output.status.success(),
            "read-only child must still read: {}",
            output_text(&output)
        );
    });
}

#[test]
fn windows_reexec_jail_allows_network_and_denies_secrets() {
    with_jail_lock(|| {
        let profile = TempDir::new().expect("profile");
        unsafe { std::env::set_var("USERPROFILE", profile.path()) };
        let secret_dir = profile.path().join(".ssh");
        fs::create_dir_all(&secret_dir).expect("ssh");
        let secret = secret_dir.join("secret.txt");
        fs::write(&secret, b"secret-bytes").expect("secret");
        let ws = TempDir::new().expect("workspace");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let port = listener.local_addr().expect("addr").port();
        let jail = process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("jail")
            .with_network(false)
            .prepare_reexec()
            .expect("reexec");
        let inside = ws.path().join("inside.txt");
        let (_applied, wrote) = jail
            .spawn_output(com(|command| {
                let script = format!("echo inside 1>{}", inside.display());
                command.args(["/C", &script]);
            }))
            .expect("write inside");
        assert!(wrote.status.success(), "{}", output_text(&wrote));
        assert_eq!(
            fs::read_to_string(&inside).expect("inside").trim(),
            "inside"
        );
        let outside = TempDir::new().expect("outside");
        let marker = outside.path().join("nope.txt");
        let _ = jail.spawn(com(|command| {
            let script = format!("echo x 1>{}", marker.display());
            command.args(["/C", &script]);
        }));
        assert!(!marker.exists(), "re-exec jail must not write outside");
        let (_applied, denied) = jail
            .spawn_output(com(|command| {
                let script = format!("type {}", secret.display());
                command.args(["/C", &script]);
            }))
            .expect("type secret");
        assert!(!denied.status.success(), "{}", output_text(&denied));
        assert!(
            !denied
                .stdout
                .windows(b"secret-bytes".len())
                .any(|c| c == b"secret-bytes")
        );
        let creates = windows_appcontainer_creates();
        let connector = compile_connector(ws.path(), port);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2];
                let _ = stream.read(&mut buf);
            }
        });
        let (_applied, connected) = jail.spawn_output(Command::new(connector)).expect("connect");
        assert!(
            connected.status.success(),
            "loopback 127.0.0.1:{port} must be allowed, no model key: {}",
            output_text(&connected)
        );
        assert_eq!(
            windows_appcontainer_creates(),
            creates,
            "a second re-exec spawn must reuse the container"
        );
        let before = windows_appcontainer_creates();
        process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("workspace")
            .with_network(false)
            .run_child_output(com(|command| {
                command.args(["/C", "echo hi"]);
            }))
            .expect("workspace");
        assert_eq!(
            windows_appcontainer_creates(),
            before,
            "workspace run_child must not create an AppContainer"
        );
    });
}

fn compile_connector(dir: &Path, port: u16) -> PathBuf {
    let src = dir.join("connect.rs");
    let exe = dir.join("connect.exe");
    fs::write(
        &src,
        format!(
            "fn main() {{ std::net::TcpStream::connect(\"127.0.0.1:{port}\").expect(\"connect\").write_all(b\"ok\").expect(\"write\"); }}\n"
        ),
    )
    .expect("src");
    let status = Command::new("rustc")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .status()
        .expect("rustc");
    assert!(status.success(), "rustc connect.exe");
    exe
}

#[test]
fn windows_jail_child_cannot_use_clipboard_or_parent_console() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        let probe = compile_ui_probe(ws.path());
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("jail")
            .with_network(false);
        if let Some(previous) = console_title() {
            set_console_title("workpen-parent");
            let (_applied, output) = policy
                .run_child_output({
                    let mut command = Command::new(&probe);
                    command.current_dir(ws.path()).arg("title");
                    command
                })
                .expect("title probe");
            assert!(output.status.success(), "probe: {}", output_text(&output));
            let now = console_title().unwrap_or_default();
            assert_eq!(
                now, "workpen-parent",
                "child must not retitle the parent console, got {now}"
            );
            set_console_title(&previous);
        } else {
            eprintln!("skip: no parent console");
        }
        if !set_clipboard_sentinel("workpen-sentinel") {
            eprintln!("skip: clipboard is not available");
            return;
        }
        let (_applied, output) = policy
            .run_child_output({
                let mut command = Command::new(&probe);
                command.current_dir(ws.path()).arg("clip");
                command
            })
            .expect("clip probe");
        assert!(output.status.success(), "{}", output_text(&output));
        let report = fs::read_to_string(ws.path().join("clip.txt")).unwrap_or_default();
        assert!(
            report.contains("clip-fail"),
            "child clipboard open must fail, report={report}"
        );
        assert_eq!(
            read_clipboard_text().as_deref(),
            Some("workpen-sentinel"),
            "parent clipboard must be unchanged"
        );
    });
}

fn compile_ui_probe(dir: &Path) -> PathBuf {
    let src = dir.join("ui_probe.rs");
    let exe = dir.join("ui_probe.exe");
    fs::write(&src, UI_PROBE).expect("probe src");
    let status = Command::new("rustc")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .status()
        .expect("rustc");
    assert!(status.success(), "rustc ui_probe.exe");
    exe
}

const UI_PROBE: &str = r#"
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "title" {
        let title: Vec<u16> = "workpen-child-pwned".encode_utf16().chain(std::iter::once(0)).collect();
        unsafe { SetConsoleTitleW(title.as_ptr()); }
        return;
    }
    let fail = unsafe { OpenClipboard(std::ptr::null_mut()) } == 0;
    if !fail {
        unsafe { CloseClipboard(); }
    }
    let path = std::path::Path::new("clip.txt");
    std::fs::write(path, if fail { "clip-fail" } else { "clip-ok" }).expect("report");
}
unsafe extern "system" {
    fn SetConsoleTitleW(title: *const u16) -> i32;
    fn OpenClipboard(hwnd: *mut u8) -> i32;
    fn CloseClipboard() -> i32;
}
"#;

fn console_title() -> Option<String> {
    unsafe extern "system" {
        fn GetConsoleTitleW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buf = [0u16; 256];
    let n = unsafe { GetConsoleTitleW(buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..n as usize]))
}

fn set_console_title(title: &str) {
    unsafe extern "system" {
        fn SetConsoleTitleW(title: *const u16) -> i32;
    }
    let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { SetConsoleTitleW(wide.as_ptr()) };
}

fn set_clipboard_sentinel(text: &str) -> bool {
    unsafe extern "system" {
        fn OpenClipboard(hwnd: *mut u8) -> i32;
        fn EmptyClipboard() -> i32;
        fn SetClipboardData(format: u32, mem: *mut u8) -> *mut u8;
        fn CloseClipboard() -> i32;
        fn GlobalAlloc(flags: u32, bytes: usize) -> *mut u8;
        fn GlobalLock(mem: *mut u8) -> *mut u8;
        fn GlobalUnlock(mem: *mut u8) -> i32;
    }
    if unsafe { OpenClipboard(std::ptr::null_mut()) } == 0 {
        return false;
    }
    unsafe { EmptyClipboard() };
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide.len() * 2;
    let mem = unsafe { GlobalAlloc(0x0002, bytes) };
    if mem.is_null() {
        unsafe { CloseClipboard() };
        return false;
    }
    let locked = unsafe { GlobalLock(mem) };
    if locked.is_null() {
        unsafe { CloseClipboard() };
        return false;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, locked, bytes);
        GlobalUnlock(mem);
        // CF_UNICODETEXT = 13. The clipboard owns `mem` after this call.
        SetClipboardData(13, mem);
        CloseClipboard();
    }
    true
}

fn read_clipboard_text() -> Option<String> {
    unsafe extern "system" {
        fn OpenClipboard(hwnd: *mut u8) -> i32;
        fn GetClipboardData(format: u32) -> *mut u8;
        fn CloseClipboard() -> i32;
        fn GlobalLock(mem: *mut u8) -> *mut u8;
        fn GlobalUnlock(mem: *mut u8) -> i32;
    }
    if unsafe { OpenClipboard(std::ptr::null_mut()) } == 0 {
        return None;
    }
    let mem = unsafe { GetClipboardData(13) };
    if mem.is_null() {
        unsafe { CloseClipboard() };
        return None;
    }
    let locked = unsafe { GlobalLock(mem) };
    if locked.is_null() {
        unsafe { CloseClipboard() };
        return None;
    }
    let mut units = Vec::new();
    let mut ptr = locked as *const u16;
    unsafe {
        while *ptr != 0 {
            units.push(*ptr);
            ptr = ptr.add(1);
        }
        GlobalUnlock(mem);
        CloseClipboard();
    }
    Some(String::from_utf16_lossy(&units))
}
