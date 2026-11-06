//! Windows jail behavior. Feature `nono`. Other platforms compile an
//! empty harness. The AppContainer cache and `USERPROFILE` are
//! process-wide, so each test holds one lock.

#![cfg(all(windows, feature = "nono"))]

use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// Read `path` without putting it on argv. Argv dest-deny would
/// refuse `.env` and `.ssh` before the ACL jail runs.
fn type_hidden(path: &Path) -> Command {
    com(|command| {
        command
            .env("WP_READ", path)
            .args(["/C", "type \"%WP_READ%\""]);
    })
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
            let (_applied, output) = policy
                .run_child_output(type_hidden(secret))
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
fn windows_jail_restores_dest_deny_ace() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        let env = ws.path().join(".env");
        fs::write(&env, b"dest-deny-bytes").expect("env");
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("jail")
            .with_network(false);
        let (_applied, output) = policy
            .run_child_output(type_hidden(&env))
            .expect("type .env");
        assert!(
            !output.status.success(),
            "child must not read dest-deny .env: {}",
            output_text(&output)
        );
        assert!(
            !output
                .stdout
                .windows(b"dest-deny-bytes".len())
                .any(|chunk| chunk == b"dest-deny-bytes"),
            "dest-deny bytes leaked: {}",
            output_text(&output)
        );
        assert_eq!(
            fs::read(&env).expect("parent read after child"),
            b"dest-deny-bytes",
            "dest-deny ACE must be restored after the child exits"
        );
    });
}

#[test]
fn windows_network_jail_outbound_connect_fails() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let port = listener.local_addr().expect("addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_thread = Arc::clone(&accepted);
        std::thread::spawn(move || {
            for _ in 0..8 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                accepted_thread.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 8];
                let _ = stream.read(&mut buf);
            }
        });
        TcpStream::connect(("127.0.0.1", port)).expect("parent connects");
        let start = Instant::now();
        while accepted.load(Ordering::SeqCst) < 1 && start.elapsed() < Duration::from_secs(2) {
            std::thread::yield_now();
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the listener must accept the parent before the jailed connect"
        );
        let connector = compile_blocked_connector(ws.path(), port);
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>()).expect("jail");
        for _ in 0..2 {
            let (applied, output) = policy
                .run_child_output(Command::new(&connector))
                .expect("spawn blocked connect");
            assert!(
                !output.status.success(),
                "outbound connect must fail ({applied:?}): {}",
                output_text(&output)
            );
            assert!(
                output_text(&output).contains("connect-fail"),
                "expected connect-fail, not a skip path ({applied:?}): {}",
                output_text(&output)
            );
        }
        assert_eq!(
            windows_appcontainer_creates(),
            1,
            "two blocked connects must share one profile"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "a jailed connect must not reach the listener"
        );
    });
}

fn compile_blocked_connector(dir: &Path, port: u16) -> PathBuf {
    let src = dir.join("connect_blocked.rs");
    let exe = dir.join("connect_blocked.exe");
    fs::write(
        &src,
        format!(
            r#"fn main() {{
    match std::net::TcpStream::connect_timeout(
        &"127.0.0.1:{port}".parse().unwrap(),
        std::time::Duration::from_secs(3),
    ) {{
        Ok(_) => {{}}
        Err(err) => {{
            eprintln!("connect-fail {{err}}");
            std::process::exit(1);
        }}
    }}
}}
"#
        ),
    )
    .expect("src");
    let status = Command::new("rustc")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .status()
        .expect("rustc");
    assert!(status.success(), "rustc connect_blocked.exe");
    exe
}

#[test]
fn windows_jail_job_close_kills_child() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        let sleeper = compile_sleeper(ws.path());
        for blocked in [false, true] {
            let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
                .expect("jail")
                .with_network(blocked);
            let err = policy
                .run_child_timeout(Command::new(&sleeper), Duration::from_secs(1))
                .expect_err("timeout");
            assert!(
                matches!(err, workpen::KernelError::Timeout),
                "blocked={blocked} job close must kill the child, got {err}"
            );
        }
    });
}

fn compile_sleeper(dir: &Path) -> PathBuf {
    let src = dir.join("sleep30.rs");
    let exe = dir.join("sleep30.exe");
    fs::write(
        &src,
        "fn main() { std::thread::sleep(std::time::Duration::from_secs(30)); }\n",
    )
    .expect("sleeper src");
    let status = Command::new("rustc")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .status()
        .expect("rustc");
    assert!(status.success(), "rustc sleep30.exe");
    exe
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
fn windows_jail_child_cannot_use_clipboard_or_parent_console() {
    with_jail_lock(|| {
        let ws = TempDir::new().expect("workspace");
        let probe = compile_ui_probe(ws.path());
        // GitHub-hosted Windows has no window station, so AllocConsole
        // fails. The probe still has to open CONOUT$. A parent with no
        // console must see con-fail. A parent with a console must keep
        // its title and must not show the marker.
        let have_console = ensure_parent_console();
        let previous = have_console.then(|| console_title()).flatten();
        if have_console {
            set_console_title("workpen-parent");
        }
        for blocked in [false, true] {
            let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
                .expect("jail")
                .with_network(blocked);
            let (_applied, output) = policy
                .run_child_output({
                    let mut command = Command::new(&probe);
                    command.current_dir(ws.path()).arg("con");
                    command
                })
                .unwrap_or_else(|err| panic!("blocked={blocked} con probe: {err}"));
            assert!(
                output.status.success(),
                "blocked={blocked} probe: {}",
                output_text(&output)
            );
            assert!(
                !output_text(&output).contains("WPCONMARK"),
                "blocked={blocked} marker reached the captured pipe"
            );
            let report = fs::read_to_string(ws.path().join("con.txt")).unwrap_or_default();
            if have_console {
                assert_eq!(
                    console_title().as_deref(),
                    Some("workpen-parent"),
                    "blocked={blocked} child changed the parent console title, report={report}"
                );
                assert!(
                    !parent_console_contains("WPCONMARK"),
                    "blocked={blocked} child wrote the parent console, report={report}"
                );
            } else {
                assert!(
                    report.contains("con-fail"),
                    "blocked={blocked} child opened CONOUT$ with no parent console, report={report}"
                );
            }
        }
        if let Some(title) = previous {
            set_console_title(&title);
        }
        let policy = process_jail(ws.path(), std::iter::empty::<&Path>())
            .expect("jail")
            .with_network(false);
        assert!(
            set_clipboard_sentinel("workpen-sentinel"),
            "clipboard is not available; a skip would not prove the deny"
        );
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
        .arg("-l")
        .arg("user32")
        .arg(&src)
        .status()
        .expect("rustc");
    assert!(status.success(), "rustc ui_probe.exe");
    exe
}

const UI_PROBE: &str = r#"
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "con" {
        let wrote = write_conout();
        std::fs::write("con.txt", if wrote { "con-write" } else { "con-fail" }).expect("report");
        return;
    }
    let fail = unsafe { OpenClipboard(std::ptr::null_mut()) } == 0;
    if !fail {
        unsafe { CloseClipboard(); }
    }
    std::fs::write("clip.txt", if fail { "clip-fail" } else { "clip-ok" }).expect("report");
}

fn write_conout() -> bool {
    let mut name: Vec<u16> = "CONOUT$".encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            name.as_mut_ptr(),
            0x4000_0000,
            0x1 | 0x2,
            std::ptr::null_mut(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == (-1isize as *mut u8) {
        return false;
    }
    let msg: Vec<u16> = "WPCONMARK".encode_utf16().collect();
    let mut wrote = 0u32;
    let ok = unsafe {
        WriteConsoleW(
            handle,
            msg.as_ptr(),
            msg.len() as u32,
            &mut wrote,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };
    ok != 0
}

unsafe extern "system" {
    fn CreateFileW(
        name: *mut u16,
        access: u32,
        share: u32,
        sec: *mut u8,
        disp: u32,
        flags: u32,
        template: *mut u8,
    ) -> *mut u8;
    fn WriteConsoleW(
        handle: *mut u8,
        buf: *const u16,
        len: u32,
        wrote: *mut u32,
        reserved: *mut u8,
    ) -> i32;
    fn CloseHandle(handle: *mut u8) -> i32;
    fn OpenClipboard(hwnd: *mut u8) -> i32;
    fn CloseClipboard() -> i32;
}
"#;

fn ensure_parent_console() -> bool {
    unsafe extern "system" {
        fn GetConsoleWindow() -> *mut u8;
        fn AllocConsole() -> i32;
    }
    if !unsafe { GetConsoleWindow() }.is_null() {
        return true;
    }
    unsafe { AllocConsole() != 0 }
}

fn parent_console_contains(marker: &str) -> bool {
    read_parent_console().contains(marker)
}

fn read_parent_console() -> String {
    #[repr(C)]
    struct Coord {
        x: i16,
        y: i16,
    }
    #[repr(C)]
    struct SmallRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }
    #[repr(C)]
    struct ConsoleScreenBufferInfo {
        size: Coord,
        cursor: Coord,
        attributes: u16,
        window: SmallRect,
        maximum: Coord,
    }
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sec: *mut u8,
            disp: u32,
            flags: u32,
            template: *mut u8,
        ) -> *mut u8;
        fn GetConsoleScreenBufferInfo(handle: *mut u8, info: *mut ConsoleScreenBufferInfo) -> i32;
        fn ReadConsoleOutputCharacterW(
            handle: *mut u8,
            buf: *mut u16,
            len: u32,
            coord: Coord,
            read: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut u8) -> i32;
    }
    let name: Vec<u16> = "CONOUT$".encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x8000_0000,
            0x1 | 0x2,
            std::ptr::null_mut(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(
        handle, -1isize as *mut u8,
        "parent could not open CONOUT$ after AllocConsole"
    );
    let mut info = ConsoleScreenBufferInfo {
        size: Coord { x: 0, y: 0 },
        cursor: Coord { x: 0, y: 0 },
        attributes: 0,
        window: SmallRect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        maximum: Coord { x: 0, y: 0 },
    };
    let info_ok = unsafe { GetConsoleScreenBufferInfo(handle, &mut info) };
    assert_ne!(info_ok, 0, "GetConsoleScreenBufferInfo");
    let width = i32::from(info.size.x).max(1);
    let rows = i32::from(info.cursor.y).max(0) + 1;
    let mut units = Vec::new();
    for row in 0..rows {
        let mut buf = vec![0u16; width as usize];
        let mut read = 0u32;
        let ok = unsafe {
            ReadConsoleOutputCharacterW(
                handle,
                buf.as_mut_ptr(),
                width as u32,
                Coord {
                    x: 0,
                    y: row as i16,
                },
                &mut read,
            )
        };
        if ok == 0 {
            break;
        }
        units.extend_from_slice(&buf[..read as usize]);
    }
    unsafe { CloseHandle(handle) };
    String::from_utf16_lossy(&units)
}

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
    #[link(name = "user32")]
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
    #[link(name = "user32")]
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
