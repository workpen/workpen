//! CLI parse errors name the legal surface and the spawn target.

use std::fs::OpenOptions;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

use tempfile::TempDir;

fn workpen() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workpen"))
}

#[test]
fn help_names_why_run_and_gc() {
    for arg in ["help", "--help", "-h"] {
        let out = workpen().arg(arg).output().expect("spawn workpen");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{arg} must exit 0, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("why"),
            "{arg} stdout must name why: {stdout}"
        );
        assert!(
            stdout.contains("run"),
            "{arg} stdout must name run: {stdout}"
        );
        assert!(stdout.contains("gc"), "{arg} stdout must name gc: {stdout}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.is_empty(),
            "{arg} must print usage on stdout, not stderr: {err}"
        );
    }
}

#[test]
fn unknown_gc_flag_names_max_age() {
    let out = workpen()
        .args(["gc", "--max_age", "7d"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "underscore max_age must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown"), "stderr must say unknown: {err}");
    assert!(
        err.contains("--max-age"),
        "stderr must name --max-age: {err}"
    );
    assert!(
        err.contains("--dry-run"),
        "stderr must name --dry-run: {err}"
    );
    assert!(
        err.contains("--leftover"),
        "stderr must name --leftover: {err}"
    );
}

#[test]
fn empty_argv_prints_usage() {
    let out = workpen().output().expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "empty argv must exit 2, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.stdout.is_empty(),
        "empty argv must leave stdout empty: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        err.contains("usage: workpen"),
        "empty argv must print usage: {err}"
    );
    assert!(
        err.contains("network") && err.contains("read-write"),
        "empty argv must describe the default child: {err}"
    );
}

#[test]
fn why_empty_path_does_not_claim_escape() {
    let dir = TempDir::new().expect("workspace");
    for path in ["", " "] {
        let out = workpen()
            .args(["why", "--root"])
            .arg(dir.path())
            .arg(path)
            .output()
            .expect("spawn workpen");
        assert!(
            !out.status.success(),
            "empty why path must fail, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.to_ascii_lowercase().contains("empty"),
            "empty why path must mention empty: {combined}"
        );
        assert!(
            !combined.contains("escapes workspace"),
            "empty why path must not claim escape: {combined}"
        );
    }
}

#[test]
fn run_spawn_failure_names_the_command() {
    let dir = TempDir::new().expect("workspace");
    let missing = "/no-such-workpen-cmd-xyz";
    let out = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", missing])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "missing command must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(127),
        "missing command must exit 127, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("command not found") && err.contains(missing),
        "missing command must say command not found: {err}"
    );
    assert!(
        !err.contains("kernel wrap"),
        "missing command must not be a kernel wrap failure: {err}"
    );
}

#[test]
fn why_help_prints_usage_not_allowed() {
    for args in [vec!["why", "--help"], vec!["why", "-h"]] {
        let out = workpen().args(&args).output().expect("spawn workpen");
        assert_eq!(
            out.status.code(),
            Some(0),
            "why help {args:?} must exit 0, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("usage: workpen why"),
            "why help {args:?} must print why usage: {stdout}"
        );
        assert!(
            !stdout.to_ascii_lowercase().contains("allowed"),
            "why help {args:?} must not print allowed: {stdout}"
        );
    }
}

#[test]
fn why_equals_root_is_not_a_path() {
    let out = workpen()
        .args(["why", "--root=/ws"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "why --root=/ws must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.to_ascii_lowercase().contains("allowed"),
        "why --root=/ws must not print allowed: {stdout}"
    );
    assert!(
        err.contains("--root") && err.contains("DIR"),
        "why --root=/ws must name --root DIR: {err}"
    );
}

#[test]
fn run_equals_root_is_unknown_flag() {
    let out = workpen()
        .args(["run", "--root=/ws", "--", "/bin/true"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "run --root=/ws must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--root") && err.contains("DIR"),
        "run --root=/ws must name --root DIR: {err}"
    );
    assert!(
        !err.contains("failed to spawn"),
        "run --root=/ws must not spawn: {err}"
    );
}

#[test]
fn run_timeout_missing_value_names_usage() {
    let out = workpen()
        .args(["run", "--timeout"])
        .output()
        .expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing --timeout must exit 2, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--timeout"),
        "missing --timeout must name the flag: {err}"
    );
}

#[test]
fn run_tty_without_command_names_usage() {
    let out = workpen()
        .args(["run", "--tty"])
        .output()
        .expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "run --tty without CMD must exit 2, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--tty"),
        "run --tty without CMD must name --tty: {err}"
    );
}

#[test]
fn run_help_without_separator_prints_usage() {
    for args in [vec!["run", "--help"], vec!["run", "-h"]] {
        let out = workpen().args(&args).output().expect("spawn workpen");
        assert_eq!(
            out.status.code(),
            Some(0),
            "run help {args:?} must exit 0, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            stdout.contains("usage: workpen run") && stdout.contains("[--] CMD"),
            "run help {args:?} must print run usage: {stdout}"
        );
        assert!(
            !err.contains("failed to spawn"),
            "run help {args:?} must not spawn --help: {err}"
        );
    }
}

#[test]
fn run_help_after_separator_is_the_child() {
    let out = workpen()
        .args(["run", "--", "--help"])
        .output()
        .expect("spawn workpen");
    assert_ne!(
        out.status.code(),
        Some(0),
        "run -- --help must not be CLI help, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("usage: workpen run"),
        "run -- --help must not print run usage: {stdout}"
    );
    assert!(
        err.contains("failed to spawn") || err.contains("--help"),
        "run -- --help must treat --help as the child: stdout={stdout} stderr={err}"
    );
}

#[test]
fn gc_help_prints_usage() {
    for args in [vec!["gc", "--help"], vec!["gc", "-h"]] {
        let out = workpen().args(&args).output().expect("spawn workpen");
        assert_eq!(
            out.status.code(),
            Some(0),
            "gc help {args:?} must exit 0, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("usage: workpen gc") && stdout.contains("--max-age"),
            "gc help {args:?} must print gc usage: {stdout}"
        );
    }
}

#[test]
fn run_leading_dash_flag_names_separator_and_cmd() {
    for args in [
        vec!["run", "-c", "echo"],
        vec!["run", "--verbose", "--", "echo"],
    ] {
        let out = workpen().args(&args).output().expect("spawn workpen");
        assert_eq!(
            out.status.code(),
            Some(2),
            "run {args:?} must exit 2, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("unknown flag"),
            "run {args:?} must say unknown flag: {err}"
        );
        assert!(
            err.contains("[--]") && err.contains("CMD"),
            "run {args:?} must mention [--] CMD, not only --root: {err}"
        );
        assert!(
            !err.contains("failed to spawn"),
            "run {args:?} must not spawn: {err}"
        );
    }
}

#[test]
fn gc_root_after_max_age_is_not_unknown() {
    let repo = init_git_repo();
    let out = workpen()
        .args(["gc", "--max-age", "7d", "--root"])
        .arg(repo.path())
        .output()
        .expect("spawn workpen");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("unknown"),
        "gc --max-age then --root must not say unknown: {err}"
    );
    assert!(
        out.status.success(),
        "gc --max-age 7d --root tmpdir must succeed, stdout={} stderr={err}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn gc_rejects_extra_root() {
    let out = workpen()
        .args(["gc", "--extra-root", "/tmp", "--max-age", "7d"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "gc --extra-root must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("extra-root"),
        "gc --extra-root must mention extra-root: {err}"
    );
}

#[test]
fn gc_leftover_flag_as_value_is_missing() {
    let out = workpen()
        .args(["gc", "--leftover", "--max-age", "7d"])
        .output()
        .expect("spawn workpen");
    assert!(
        !out.status.success(),
        "gc --leftover --max-age must fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("unknown") || !err.contains("7d"),
        "missing --leftover value must not call 7d unknown: {err}"
    );
}

#[test]
fn gc_honors_workspace_agent_lock_cache_secret() {
    let repo = init_git_repo();
    std::fs::write(repo.path().join("agent.lock"), b"**/*.secret\n").expect("lock");

    let old = SystemTime::now() - Duration::from_secs(2 * 3600);
    let unix = old
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("unix")
        .as_secs();
    let date = unix.to_string();
    let amend = Command::new("git")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("GIT_AUTHOR_DATE", &date)
        .env("GIT_COMMITTER_DATE", &date)
        .args(["commit", "--amend", "--no-edit", "--date"])
        .arg(&date)
        .current_dir(repo.path())
        .output()
        .expect("amend");
    assert!(
        amend.status.success(),
        "amend: {}",
        String::from_utf8_lossy(&amend.stderr)
    );

    let leftover_dir = repo.path().join(".workpen-worktrees");
    std::fs::create_dir_all(&leftover_dir).expect("leftover dir");
    let leftover = leftover_dir.join("extra-secret");
    git_in(
        repo.path(),
        &[
            "worktree",
            "add",
            leftover.to_str().expect("utf8"),
            "-b",
            "extra-secret",
        ],
    );

    let target = leftover.join("target");
    std::fs::create_dir_all(&target).expect("target");
    std::fs::write(target.join("team.secret"), b"host extra\n").expect("secret");
    stamp_mtime_tree(&leftover, old);
    stamp_mtime_tree(&repo.path().join(".git/worktrees"), old);

    let out = workpen()
        .args(["gc", "--root"])
        .arg(repo.path())
        .args(["--max-age", "1s", "--leftover"])
        .arg(&leftover_dir)
        .output()
        .expect("spawn workpen");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        out.status.success(),
        "gc leftover with agent.lock extra must succeed, stdout={stdout} stderr={stderr}"
    );
    assert!(
        leftover.exists(),
        "leftover with target/team.secret must stay: {combined}"
    );
    assert!(
        combined.contains("keep") && combined.contains("unique untracked files"),
        "gc must keep UniqueUntracked leftover: {combined}"
    );
    assert!(
        !combined.to_ascii_lowercase().contains("reclaimed"),
        "gc must not reclaim leftover with agent.lock extra: {combined}"
    );
    assert!(
        stdout.contains("keep") && stdout.contains("1 worktrees"),
        "gc must keep the row and print a count: {stdout}"
    );
}

#[test]
fn top_version_flags_print_crate_version() {
    for arg in ["--version", "-V"] {
        let out = workpen().arg(arg).output().expect("spawn");
        assert_eq!(out.status.code(), Some(0), "{arg}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            env!("CARGO_PKG_VERSION")
        );
    }
}

#[test]
fn run_version_flag_with_no_child_prints_workpen_version() {
    let out = workpen()
        .args(["run", "--version"])
        .output()
        .expect("spawn workpen");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim() == env!("CARGO_PKG_VERSION"),
        "run --version must print the crate version: {stdout}"
    );
}

#[test]
fn run_version_before_child_token_is_workpen() {
    let out = workpen()
        .args(["run", "--version", "/bin/echo", "child"])
        .output()
        .expect("spawn workpen");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), env!("CARGO_PKG_VERSION"));
    assert!(!stdout.contains("child"));
}

#[cfg(unix)]
#[test]
fn run_dashdash_echo_version_and_short_v_are_child_args() {
    let dir = TempDir::new().expect("workspace");
    for arg in ["--version", "-V"] {
        let out = workpen()
            .args(["run", "--root"])
            .arg(dir.path())
            .args(["--", "/bin/echo", arg])
            .output()
            .expect("spawn");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "echo {arg} must run, stdout={stdout} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains(arg),
            "echo must print {arg}, not the workpen version: {stdout}"
        );
        assert!(!stdout.contains(env!("CARGO_PKG_VERSION")));
    }
}

#[cfg(unix)]
#[test]
fn run_short_v_after_command_without_dashdash() {
    let dir = TempDir::new().expect("workspace");
    let bare = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["/bin/echo", "-V"])
        .output()
        .expect("spawn workpen");
    let stdout = String::from_utf8_lossy(&bare.stdout);
    assert_eq!(
        bare.status.code(),
        Some(0),
        "echo -V must run, stdout={stdout} stderr={}",
        String::from_utf8_lossy(&bare.stderr)
    );
    assert!(
        stdout.contains("-V"),
        "echo must print -V, not the workpen version: {stdout}"
    );
    assert!(!stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn run_dashdash_version_is_the_child_program() {
    let dir = TempDir::new().expect("workspace");
    let out = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", "--version"])
        .output()
        .expect("spawn workpen");
    assert_eq!(out.status.code(), Some(127));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("command not found") && err.contains("--version"),
        "run -- --version must look up a program named --version: {err}"
    );
    assert!(!err.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn why_and_gc_version_stay_usage() {
    for args in [
        vec!["why", "--version"],
        vec!["gc", "--version"],
        vec!["version"],
    ] {
        let out = workpen().args(&args).output().expect("spawn workpen");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} must be usage, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains(env!("CARGO_PKG_VERSION")),
            "{args:?} must not print the version: {stdout}"
        );
    }
}

#[test]
fn run_dot_env_is_policy_exit_3() {
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join(".env"), b"SECRET=1\n").expect("env");
    let out = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", "/bin/cat", ".env"])
        .output()
        .expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(3),
        "run .env must exit 3, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("SECRET=1"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("SECRET=1"));
}

#[test]
fn unknown_command_and_gc_without_max_age_exit_2() {
    let frob = workpen().arg("frob").output().expect("spawn");
    assert_eq!(frob.status.code(), Some(2));
    let gc = workpen().arg("gc").output().expect("spawn");
    assert_eq!(gc.status.code(), Some(2));
}

#[cfg(unix)]
#[test]
fn child_exit_2_and_3_pass_through() {
    let dir = TempDir::new().expect("workspace");
    for code in [2, 3] {
        let script = format!("exit {code}");
        let out = workpen()
            .args(["run", "--root"])
            .arg(dir.path())
            .args(["--", "/bin/sh", "-c", &script])
            .output()
            .expect("spawn");
        assert_eq!(
            out.status.code(),
            Some(code),
            "child exit {code} must pass through, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains("deny") && !err.contains("command not found"),
            "child exit {code} must not look like a policy refusal: {err}"
        );
    }
}

#[cfg(unix)]
#[test]
fn run_home_and_fs_root_are_policy_exit_3() {
    let home = std::env::var("HOME").expect("HOME");
    let home_out = workpen()
        .args(["run", "--root", &home, "--", "/bin/echo", "x"])
        .output()
        .expect("spawn");
    assert_eq!(
        home_out.status.code(),
        Some(3),
        "home root must exit 3, stderr={}",
        String::from_utf8_lossy(&home_out.stderr)
    );
    let fs = workpen()
        .args(["run", "--root", "/", "--", "/bin/echo", "x"])
        .output()
        .expect("spawn");
    assert_eq!(
        fs.status.code(),
        Some(3),
        "filesystem root must exit 3, stderr={}",
        String::from_utf8_lossy(&fs.stderr)
    );
}

#[test]
fn run_missing_root_stays_exit_2() {
    let out = workpen()
        .args([
            "run",
            "--root",
            "/no/such/workpen-root-xyz",
            "--",
            "/bin/echo",
            "x",
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing root must exit 2, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn path_match_is_named_and_missing_file_is_not_a_wrap() {
    let ws = TempDir::new().expect("workspace");
    let hit = TempDir::new().expect("path hit");
    let miss = TempDir::new().expect("path miss");
    let program = hit.path().join("wp-marker-cmd");
    std::fs::copy("/bin/echo", &program).expect("copy echo");
    let path = std::env::join_paths([miss.path(), hit.path()]).expect("PATH");
    let out = workpen()
        .env("PATH", &path)
        .args(["run", "--root"])
        .arg(ws.path())
        .args(["--", "wp-marker-cmd"])
        .output()
        .expect("spawn");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "outside program must not run: {text}"
    );
    assert_ne!(out.status.code(), Some(127), "{text}");
    assert!(
        text.contains(&hit.path().display().to_string()),
        "status={:?} PATH failure must name the first existing match: {text}",
        out.status
    );
    assert!(
        text.contains("--extra-root"),
        "outside program must mention --extra-root: {text}"
    );
    assert!(!text.contains("command not found"), "{text}");
}

#[cfg(unix)]
#[test]
fn existing_file_exec_failure_stays_kernel_wrap() {
    let dir = TempDir::new().expect("workspace");
    let bin = dir.path().join("wp-not-bin");
    std::fs::write(&bin, b"\0\0\0\0not-a-mach-o").expect("write");
    let mut perms = std::fs::metadata(&bin).expect("meta").permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&bin, perms).expect("chmod");
    let out = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .arg("--")
        .arg(&bin)
        .output()
        .expect("spawn");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.starts_with("command not found:"),
        "a file that exists must not be reported missing: {err}"
    );
    if err.contains("kernel wrap") {
        assert_eq!(out.status.code(), Some(2), "{err}");
    } else {
        assert_ne!(out.status.code(), Some(127), "{err}");
    }
}

#[test]
fn run_help_names_network_and_not_always_start() {
    let out = workpen().args(["run", "--help"]).output().expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("network"),
        "run help must name network: {stdout}"
    );
    assert!(
        stdout.contains("read-write"),
        "run help must name read-write: {stdout}"
    );
    assert!(
        stdout.contains("not started"),
        "run help must say the child is not always started: {stdout}"
    );
    assert!(!stdout.contains("always means"));
}

#[test]
fn gc_empty_names_leftover_dir_and_max_age_token() {
    let repo = init_git_repo();
    for extra in [Vec::<&str>::new(), vec!["--dry-run"]] {
        let mut args = vec![
            "gc".to_string(),
            "--root".to_string(),
            repo.path().display().to_string(),
            "--max-age".to_string(),
            "1d".to_string(),
        ];
        args.extend(extra.into_iter().map(str::to_string));
        let out = workpen().args(&args).output().expect("spawn");
        assert_eq!(
            out.status.code(),
            Some(0),
            "stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("no leftover worktrees under")
                && stdout.contains(".workpen-worktrees")
                && stdout.contains("(max-age 1d)"),
            "empty gc must name the dir and token: {stdout}"
        );
        assert!(
            !stdout.contains("keep "),
            "empty gc must not invent keep rows: {stdout}"
        );
    }
}

#[test]
fn gc_dry_run_reclaim_line_stays() {
    let repo = init_git_repo();
    let old = SystemTime::now() - Duration::from_secs(2 * 3600);
    let unix = old
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("unix")
        .as_secs()
        .to_string();
    let amend = Command::new("git")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("GIT_AUTHOR_DATE", &unix)
        .env("GIT_COMMITTER_DATE", &unix)
        .args(["commit", "--amend", "--no-edit", "--date", &unix])
        .current_dir(repo.path())
        .output()
        .expect("amend");
    assert!(
        amend.status.success(),
        "{}",
        String::from_utf8_lossy(&amend.stderr)
    );
    let leftover_dir = repo.path().join(".workpen-worktrees");
    std::fs::create_dir_all(&leftover_dir).expect("leftover dir");
    let leftover = leftover_dir.join("old-clean");
    git_in(
        repo.path(),
        &[
            "worktree",
            "add",
            leftover.to_str().expect("utf8"),
            "-b",
            "old-clean",
        ],
    );
    stamp_mtime_tree(&leftover, old);
    stamp_mtime_tree(&repo.path().join(".git/worktrees"), old);
    let out = workpen()
        .args(["gc", "--root"])
        .arg(repo.path())
        .args(["--max-age", "1s", "--dry-run", "--leftover"])
        .arg(&leftover_dir)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("dry-run: would reclaim"),
        "reclaimable tree must keep the reclaim line: {stdout}"
    );
    assert!(stdout.contains("1 worktrees"), "{stdout}");
    assert!(leftover.exists(), "dry-run must not delete the worktree");
}

fn git_in(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn stamp_mtime_tree(root: &Path, when: SystemTime) {
    if let Ok(rd) = std::fs::read_dir(root) {
        for ent in rd.flatten() {
            let path = ent.path();
            if path.is_dir() {
                stamp_mtime_tree(&path, when);
            } else {
                stamp_mtime(&path, when);
            }
        }
    }
    stamp_mtime(root, when);
}

fn stamp_mtime(path: &Path, when: SystemTime) {
    if let Ok(file) = OpenOptions::new().write(true).open(path) {
        let _ = file.set_modified(when);
    }
}

fn init_git_repo() -> TempDir {
    let dir = TempDir::new().expect("repo");
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .args(args)
            .current_dir(dir.path())
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-b", "main"]);
    git(&["config", "user.email", "dev@example.com"]);
    git(&["config", "user.name", "dev"]);
    git(&["config", "commit.gpgsign", "false"]);
    std::fs::write(dir.path().join("README"), b"x").expect("readme");
    git(&["add", "README"]);
    git(&["commit", "-m", "init"]);
    dir
}
