//! dest-deny for `why`/`run` must use --root, not process cwd.

#[cfg(unix)]
use std::fs;
use std::process::Command;

use tempfile::TempDir;

fn workpen() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workpen"))
}

/// Workspace with `.env` hardlinked as `notes.txt`, plus a plain `readme.md`.
/// Second temp dir is a cwd that is not the workspace.
fn workspace_with_env_hardlink() -> (TempDir, TempDir) {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    std::fs::write(ws.path().join(".env"), "SECRET=1\n").expect("write .env");
    std::fs::hard_link(ws.path().join(".env"), ws.path().join("notes.txt")).expect("hardlink");
    std::fs::write(ws.path().join("readme.md"), "ok\n").expect("write readme");
    (ws, cwd)
}

fn combined(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn why_dest_denies_hardlink_sibling_under_root_not_cwd() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["why", "--root"])
        .arg(ws.path())
        .arg("notes.txt")
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "why notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink"),
        "why dest-deny must mention hardlink: {text}"
    );
    assert!(
        !stdout.trim().eq_ignore_ascii_case("allowed"),
        "why dest-deny must not be only allowed: {stdout}"
    );
    assert!(
        text.contains("denied name .env"),
        "why hardlink dest-deny must say denied name .env: {text}"
    );
}

#[test]
fn why_glob_dest_names_matching_auth_glob() {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    std::fs::write(ws.path().join("auth-work.json"), "{}\n").expect("write auth");
    let out = workpen()
        .args(["why", "--root"])
        .arg(ws.path())
        .arg("auth-work.json")
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "why auth-work.json must dest-deny, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out);
    assert!(
        text.contains("**/auth-*.json"),
        "why glob dest-deny must name **/auth-*.json: {text}"
    );
}

#[test]
fn run_dest_denies_hardlink_sibling_under_root_before_spawn() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/cat", "notes.txt"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run cat notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink"),
        "run dest-deny must mention hardlink: {text}"
    );
    assert!(
        text.contains("denied name .env"),
        "run hardlink dest-deny must say denied name .env: {text}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "run must dest-deny before spawn, stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_allowed_dest_after_hardlink_dest_deny() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let echo = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/echo", "hello"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        echo.status.success(),
        "run echo hello must succeed after dest-deny fixture, stdout={} stderr={}",
        String::from_utf8_lossy(&echo.stdout),
        String::from_utf8_lossy(&echo.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&echo.stdout).trim(), "hello");
    let cat = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/cat", "readme.md"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        cat.status.success(),
        "run cat readme.md must succeed after dest-deny fixture, stdout={} stderr={}",
        String::from_utf8_lossy(&cat.stdout),
        String::from_utf8_lossy(&cat.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&cat.stdout).trim(), "ok");
}

#[cfg(unix)]
#[test]
fn run_dest_denies_nested_env_split_string_before_spawn() {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    std::fs::write(ws.path().join(".env"), "SECRET=1\n").expect("write .env");
    std::fs::write(ws.path().join("readme.md"), "ok\n").expect("write readme");
    let deny = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "env", "env", "-S", "cat .env"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !deny.status.success(),
        "run env env -S cat .env must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&deny.stdout),
        String::from_utf8_lossy(&deny.stderr)
    );
    let stdout = String::from_utf8_lossy(&deny.stdout);
    assert!(
        !stdout.contains("SECRET"),
        "nested env must dest-deny before spawn, stdout={stdout}"
    );
    let allow = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "env", "env", "-S", "cat readme.md"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        allow.status.success(),
        "run env env -S cat readme.md must succeed, stdout={} stderr={}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&allow.stdout).trim(), "ok");
}

#[cfg(unix)]
#[test]
fn run_dest_denies_spaced_hardlink_argv_under_root_before_spawn() {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    std::fs::write(ws.path().join(".env"), "SECRET=1\n").expect("write .env");
    std::fs::hard_link(ws.path().join(".env"), ws.path().join("my notes.txt")).expect("hardlink");
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/cat"])
        .arg("my notes.txt")
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run cat my notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink"),
        "run dest-deny must mention hardlink: {text}"
    );
    assert!(
        text.contains("denied name .env"),
        "run hardlink dest-deny must say denied name .env: {text}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "run must dest-deny before spawn, stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_dest_denies_hardlink_inside_sh_c_under_root_before_spawn() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/sh", "-c", "cat notes.txt"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run sh -c cat notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink"),
        "run dest-deny must mention hardlink: {text}"
    );
    assert!(
        text.contains("denied name .env"),
        "run hardlink dest-deny must say denied name .env: {text}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "run must dest-deny before spawn, stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_dest_denies_hardlink_inside_bash_lc_under_root_before_spawn() {
    if !std::path::Path::new("/bin/bash").exists() {
        return;
    }
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/bash", "-lc", "cat notes.txt"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run bash -lc cat notes.txt hardlink sibling must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("hardlink"),
        "run dest-deny must mention hardlink: {text}"
    );
    assert!(
        text.contains("denied name .env"),
        "run hardlink dest-deny must say denied name .env: {text}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "run must dest-deny before spawn, stdout={stdout}"
    );
    let echo = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/bash", "-lc", "echo hello"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        echo.status.success(),
        "run bash -lc echo hello must succeed after dest-deny fixture, stdout={} stderr={}",
        String::from_utf8_lossy(&echo.stdout),
        String::from_utf8_lossy(&echo.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&echo.stdout).trim(), "hello");
}

#[cfg(unix)]
#[test]
fn run_dest_denies_hardlink_inside_bash_uc_and_infix_redirect() {
    if !std::path::Path::new("/bin/bash").exists() {
        return;
    }
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/bash", "-uc", "cat notes.txt"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run bash -uc cat notes.txt must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("SECRET"),
        "run bash -uc must dest-deny before spawn"
    );
    let redirect = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/sh", "-c", "cat<.env"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !redirect.status.success(),
        "run sh -c cat<.env must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&redirect.stdout),
        String::from_utf8_lossy(&redirect.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&redirect.stdout).contains("SECRET"),
        "run infix redirect must dest-deny before spawn"
    );
}

#[cfg(unix)]
#[test]
fn run_refuses_dev_null_special_file_before_spawn() {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    if !std::path::Path::new("/dev/null").exists() {
        return;
    }
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "/bin/cat", "/dev/null"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run cat /dev/null must fail closed, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("special") || lower.contains("device") || lower.contains("refuse"),
        "run must name the special-file dest deny: {text}"
    );
}

#[test]
fn why_plain_file_under_root_is_allowed() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["why", "--root"])
        .arg(ws.path())
        .arg("readme.md")
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "why readme.md must be allowed, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lower = stdout.to_ascii_lowercase();
    assert!(
        lower.contains("allowed"),
        "why readme.md must report allowed: {stdout}"
    );
    assert!(
        stdout.contains("readme.md"),
        "why readme.md must name the dest that passed: {stdout}"
    );
}

#[test]
fn why_extra_path_token_is_error_not_allowed() {
    let (ws, cwd) = workspace_with_env_hardlink();
    let out = workpen()
        .args(["why", "--root"])
        .arg(ws.path())
        .args(["readme.md", "notes.txt"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "why extra path token must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out);
    assert!(
        text.contains("notes.txt"),
        "why extra token must name notes.txt: {text}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.trim().eq_ignore_ascii_case("allowed"),
        "why extra token must not be only allowed: {stdout}"
    );
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("usage") || lower.contains("unexpected"),
        "why extra token must mention usage or unexpected: {text}"
    );
}

#[cfg(unix)]
#[test]
fn run_relative_parent_root_dest_denies_hardlink_not_escape() {
    let parent = TempDir::new().expect("parent");
    let ws = parent.path().join("ws");
    let cwd = parent.path().join("here");
    fs::create_dir(&ws).expect("ws");
    fs::create_dir(&cwd).expect("cwd");
    fs::write(ws.join(".env"), "SECRET=1\n").expect("write .env");
    fs::hard_link(ws.join(".env"), ws.join("notes.txt")).expect("hardlink");
    for root in ["../ws", "./../ws"] {
        let out = workpen()
            .args(["run", "--root", root, "--", "/bin/cat", "notes.txt"])
            .current_dir(&cwd)
            .output()
            .expect("spawn workpen");
        assert!(
            !out.status.success(),
            "run --root {root} cat notes.txt must fail, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let text = combined(&out);
        let lower = text.to_ascii_lowercase();
        assert!(
            !lower.contains("escapes workspace"),
            "run --root {root} must not treat the workspace as an escape: {text}"
        );
        assert!(
            lower.contains("hardlink"),
            "run --root {root} dest-deny must mention hardlink: {text}"
        );
        assert!(
            text.contains("denied name .env"),
            "run --root {root} dest-deny must say denied name .env: {text}"
        );
        assert!(
            !stdout.contains("SECRET"),
            "run --root {root} must dest-deny before spawn, stdout={stdout}"
        );
    }
    let allowed = workpen()
        .args(["run", "--root", "../ws", "--", "/bin/echo", "hello"])
        .current_dir(&cwd)
        .output()
        .expect("spawn workpen");
    assert!(
        allowed.status.success(),
        "run --root ../ws echo hello must succeed after dest-deny, stdout={} stderr={}",
        String::from_utf8_lossy(&allowed.stdout),
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&allowed.stdout).trim(), "hello");
}

#[cfg(unix)]
#[test]
fn why_relative_parent_root_dest_denies_hardlink_not_escape() {
    let parent = TempDir::new().expect("parent");
    let ws = parent.path().join("ws");
    let cwd = parent.path().join("here");
    fs::create_dir(&ws).expect("ws");
    fs::create_dir(&cwd).expect("cwd");
    fs::write(ws.join(".env"), "SECRET=1\n").expect("write .env");
    fs::hard_link(ws.join(".env"), ws.join("notes.txt")).expect("hardlink");
    for root in ["../ws", "./../ws"] {
        let out = workpen()
            .args(["why", "--root", root, "notes.txt"])
            .current_dir(&cwd)
            .output()
            .expect("spawn workpen");
        assert!(
            !out.status.success(),
            "why --root {root} notes.txt must fail, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let text = combined(&out);
        let lower = text.to_ascii_lowercase();
        assert!(
            !lower.contains("escapes workspace"),
            "why --root {root} must not treat the workspace as an escape: {text}"
        );
        assert!(
            lower.contains("hardlink"),
            "why --root {root} dest-deny must mention hardlink: {text}"
        );
        assert!(
            text.contains("denied name .env"),
            "why --root {root} dest-deny must say denied name .env: {text}"
        );
    }
}

#[cfg(unix)]
#[test]
fn why_relative_parent_root_plain_file_is_allowed_not_escape() {
    let parent = TempDir::new().expect("parent");
    let ws = parent.path().join("ws");
    let cwd = parent.path().join("here");
    fs::create_dir(&ws).expect("ws");
    fs::create_dir(&cwd).expect("cwd");
    fs::write(ws.join("readme.md"), "ok\n").expect("write readme");
    for root in ["../ws", "./../ws"] {
        let out = workpen()
            .args(["why", "--root", root, "readme.md"])
            .current_dir(&cwd)
            .output()
            .expect("spawn workpen");
        let text = combined(&out);
        let lower = text.to_ascii_lowercase();
        assert!(
            !lower.contains("escapes workspace"),
            "why --root {root} readme.md must not treat the workspace as an escape: {text}"
        );
        assert!(
            out.status.success(),
            "why --root {root} readme.md must be allowed, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let allowed = stdout.to_ascii_lowercase();
        assert!(
            allowed.contains("allowed"),
            "why --root {root} readme.md must report allowed: {stdout}"
        );
        assert!(
            stdout.contains("readme.md"),
            "why --root {root} readme.md must name the dest that passed: {stdout}"
        );
    }
}

#[cfg(unix)]
#[test]
fn run_extra_root_constructed_env_is_dest_denied() {
    let ws = TempDir::new().expect("workspace");
    let extra = TempDir::new().expect("extra");
    std::fs::write(ws.path().join("readme.md"), "ok\n").expect("readme");
    let extra_env = extra.path().join(".env");
    std::fs::write(&extra_env, "SECRET=1\n").expect("extra .env");
    std::fs::write(extra.path().join("ok.txt"), "ok\n").expect("ok.txt");
    // Construct `.env` at runtime so argv dest-deny does not peel the name.
    let script = format!("n=.; cat {}/${{n}}env", extra.path().display());
    let deny = workpen()
        .arg("run")
        .arg("--root")
        .arg(ws.path())
        .arg("--extra-root")
        .arg(extra.path())
        .args(["--", "/bin/sh", "-c", &script])
        .output()
        .expect("spawn workpen");
    let stdout = String::from_utf8_lossy(&deny.stdout);
    assert!(
        !stdout.contains("SECRET"),
        "constructed extra-root .env must not print SECRET, stdout={stdout} stderr={}",
        String::from_utf8_lossy(&deny.stderr)
    );
    assert!(
        extra_env.exists(),
        "extra-root .env must remain after dest-deny"
    );
    let allow = workpen()
        .arg("run")
        .arg("--root")
        .arg(ws.path())
        .arg("--extra-root")
        .arg(extra.path())
        .arg("--")
        .arg("/bin/cat")
        .arg(extra.path().join("ok.txt"))
        .output()
        .expect("spawn workpen");
    let allow_out = String::from_utf8_lossy(&allow.stdout);
    let allow_err = String::from_utf8_lossy(&allow.stderr);
    if allow.status.success() {
        assert_eq!(
            allow_out.trim(),
            "ok",
            "extra-root ok.txt must print ok when remount/Seatbelt applied, stderr={allow_err}"
        );
    } else {
        assert!(
            allow_err.contains("extra-root dest-deny remount") || allow_err.contains("unavailable"),
            "without remount, extra-root dest-deny must refuse spawn, stdout={allow_out} stderr={allow_err}"
        );
    }
}

#[test]
fn why_extra_root_resolves_against_process_cwd_not_workspace() {
    let parent = TempDir::new().expect("parent");
    let ws = parent.path().join("ws");
    let here = parent.path().join("here");
    let extra = here.join("extra");
    std::fs::create_dir(&ws).expect("ws");
    std::fs::create_dir_all(&extra).expect("extra");
    let tool = extra.join("tool.txt");
    std::fs::write(&tool, "ok\n").expect("tool");
    let out = workpen()
        .args(["why", "--root", "../ws", "--extra-root", "extra"])
        .arg(&tool)
        .current_dir(&here)
        .output()
        .expect("spawn workpen");
    assert!(
        out.status.success(),
        "why --extra-root extra from cwd must be allowed, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lower = stdout.to_ascii_lowercase();
    assert!(
        lower.contains("allowed"),
        "why extra tool.txt must report allowed: {stdout}"
    );
    assert!(
        stdout.contains("tool.txt"),
        "why extra tool.txt must name the dest: {stdout}"
    );
    let text = combined(&out);
    assert!(
        !text.contains("does not exist"),
        "extra-root extra must resolve against process cwd, not --root: {text}"
    );
}

#[test]
fn why_extra_root_home_is_refused() {
    let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) else {
        return;
    };
    let Ok(home) = std::fs::canonicalize(&home) else {
        return;
    };
    if !home.is_dir() {
        return;
    }
    let ws = TempDir::new().expect("workspace");
    std::fs::write(ws.path().join("readme.md"), "ok\n").expect("readme");
    let dest = home.join(".gitconfig");
    let out = workpen()
        .args(["why", "--root"])
        .arg(ws.path())
        .arg("--extra-root")
        .arg(&home)
        .arg(&dest)
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "why --extra-root HOME must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out).to_ascii_lowercase();
    assert!(
        text.contains("home") || text.contains("subdirectory"),
        "why --extra-root HOME must name home refuse: {}",
        combined(&out)
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout)
            .to_ascii_lowercase()
            .contains("allowed"),
        "why --extra-root HOME must not print allowed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn why_missing_root_is_clear_error_not_escape() {
    let cwd = TempDir::new().expect("cwd");
    let out = workpen()
        .args(["why", "--root", "../no-such-workpen-ws", "notes.txt"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "missing --root must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        !lower.contains("escapes workspace"),
        "missing --root must not claim an escape: {text}"
    );
    assert!(
        lower.contains("does not exist")
            || lower.contains("no such")
            || lower.contains("not a directory")
            || lower.contains("root"),
        "missing --root must be a clear root error: {text}"
    );
}

#[test]
fn run_honors_workspace_agent_lock_extra_glob_before_spawn() {
    let ws = TempDir::new().expect("workspace");
    let cwd = TempDir::new().expect("other cwd");
    std::fs::write(ws.path().join("agent.lock"), "**/*.secret\n").expect("lock");
    std::fs::write(ws.path().join("team.secret"), "SECRET=1\n").expect("secret");
    std::fs::write(ws.path().join("readme.md"), "ok\n").expect("readme");
    let out = workpen()
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "cat", "team.secret"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run cat team.secret must dest-deny, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("denied") || lower.contains("deny"),
        "run team.secret must dest-deny before spawn: {text}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "run must dest-deny team.secret before spawn, stdout={stdout}"
    );
}

#[test]
fn run_missing_root_is_clear_error_not_escape() {
    let cwd = TempDir::new().expect("cwd");
    let out = workpen()
        .args([
            "run",
            "--root",
            "../no-such-workpen-ws",
            "--",
            "/bin/cat",
            "notes.txt",
        ])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "missing --root must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        !lower.contains("escapes workspace"),
        "missing --root must not claim an escape: {text}"
    );
    assert!(
        lower.contains("does not exist")
            || lower.contains("no such")
            || lower.contains("not a directory")
            || lower.contains("root"),
        "missing --root must be a clear root error: {text}"
    );
}

#[test]
fn gc_missing_root_is_clear_error_not_registry() {
    let cwd = TempDir::new().expect("cwd");
    let out = workpen()
        .args(["gc", "--root", "../no-such-workpen-ws", "--max-age", "7d"])
        .current_dir(cwd.path())
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "missing --root must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = combined(&out);
    let lower = text.to_ascii_lowercase();
    assert!(
        !lower.contains("registry unreadable"),
        "missing --root must not be a git registry error: {text}"
    );
    assert!(
        lower.contains("does not exist"),
        "missing --root must say workspace root does not exist: {text}"
    );
}
