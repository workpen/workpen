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
        assert!(
            stdout.contains("network") && stdout.contains("read-write"),
            "{arg} must describe the network default and extra-root access: {stdout}"
        );
        assert!(
            stdout.contains("does not spawn")
                && stdout.contains("jailed child")
                && stdout.contains(".workpen-worktrees"),
            "{arg} must describe why, run, and gc: {stdout}"
        );
        assert!(
            stdout.contains("1 is a why denial")
                && stdout.contains("3 is a policy refusal")
                && stdout.contains("124 is a timeout"),
            "{arg} must list exit codes: {stdout}"
        );
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
    assert!(
        err.contains("does not spawn")
            && err.contains(".workpen-worktrees")
            && err.contains("124 is a timeout"),
        "empty argv must include the long help: {err}"
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

#[cfg(unix)]
#[test]
fn why_dangling_in_tree_symlink_is_allowed() {
    let dir = TempDir::new().expect("workspace");
    std::os::unix::fs::symlink("missing-name", dir.path().join("alias")).expect("link");
    let out = workpen()
        .args(["why", "--root"])
        .arg(dir.path())
        .arg(dir.path().join("alias"))
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("allowed") && !stdout.contains("escapes"),
        "a dangling link to a name in the workspace is allowed: stdout={stdout} stderr={stderr}"
    );
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
fn run_and_policy_missing_value_names_that_flag() {
    for cmd in ["run", "policy"] {
        for flag in ["--read", "--write", "--env"] {
            let out = workpen().args([cmd, flag]).output().expect("spawn");
            let err = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                out.status.code(),
                Some(2),
                "{cmd} {flag} must exit 2: {err}"
            );
            assert!(
                err.contains(&format!("missing {flag} value")),
                "{cmd} {flag} must name the flag: {err}"
            );
            assert!(
                !err.contains("workpen gc"),
                "{cmd} {flag} must not print gc usage: {err}"
            );
        }
    }
}

#[test]
fn run_timeout_that_does_not_fit_on_the_clock_exits_2() {
    let dir = TempDir::new().expect("workspace");
    let out = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--timeout", "999999999999999d", "--", "true"])
        .output()
        .expect("spawn");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "huge --timeout must exit 2, not panic: {err}"
    );
    assert!(
        err.contains("does not fit on the clock"),
        "huge --timeout must name the clock: {err}"
    );
    assert!(!err.contains("panicked"), "{err}");
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
fn gc_outside_a_git_repo_names_that() {
    let dir = TempDir::new().expect("dir");
    let out = workpen()
        .args(["gc", "--root"])
        .arg(dir.path())
        .args(["--max-age", "1s", "--dry-run"])
        .output()
        .expect("spawn");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(
        err.contains("not a git repository"),
        "must say it is not a git repository: {err}"
    );
    assert!(
        !err.contains("fatal:"),
        "must not pass through git fatal: {err}"
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
        stdout.contains("keep") && stdout.contains("1 leftover worktrees"),
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
        assert_ne!(
            stdout.trim(),
            env!("CARGO_PKG_VERSION"),
            "workpen must not steal {arg}: {stdout}"
        );
        assert!(
            stdout.contains(arg) || stdout.contains("echo"),
            "the child must receive {arg}: {stdout}"
        );
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

#[cfg(unix)]
#[test]
fn run_root_after_the_command_is_child_argv() {
    let dir = TempDir::new().expect("workspace");
    let missing = dir.path().join("not-a-workspace");
    let out = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["/bin/echo", "--root"])
        .arg(&missing)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "echo --root must run in the first workspace: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("--root") && stdout.contains("not-a-workspace"),
        "echo must receive --root: stdout={stdout} stderr={stderr}"
    );
    assert!(
        !stderr.contains("path guard"),
        "the later --root must not replace the workspace: {stderr}"
    );

    let ordered = workpen()
        .args(["run", "--timeout", "5s", "--root"])
        .arg(dir.path())
        .args(["/bin/echo", "kept"])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&ordered.stdout);
    assert!(
        ordered.status.success() && stdout.contains("kept"),
        "a flag before --root must still run the child: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&ordered.stderr)
    );

    let extra = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["/bin/echo", "--extra-root", "/tmp/not-an-extra-root"])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&extra.stdout);
    let stderr = String::from_utf8_lossy(&extra.stderr);
    assert!(
        extra.status.success() && stdout.contains("--extra-root"),
        "echo must receive --extra-root: stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn why_extra_root_after_the_path_is_not_a_root() {
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join("notes.md"), b"ok\n").expect("notes");
    let out = workpen()
        .args(["why", "--root"])
        .arg(dir.path())
        .args(["notes.md", "--extra-root", "/tmp/not-an-extra-root"])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a flag after the path is usage: stdout={} stderr={stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains("unknown flag") && stderr.contains("--extra-root"),
        "{stderr}"
    );
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
    let mut perms = std::fs::metadata(&program).expect("meta").permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o644);
    std::fs::set_permissions(&program, perms).expect("chmod");
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
    }
}

#[cfg(unix)]
#[test]
fn run_env_scrubs_tokens_and_keeps_opt_in() {
    let dir = TempDir::new().expect("workspace");
    let inherited = workpen()
        .env("GITHUB_TOKEN", "fixture")
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", "/usr/bin/env"])
        .output()
        .expect("spawn");
    let text = String::from_utf8_lossy(&inherited.stdout);
    assert!(
        inherited.status.success(),
        "env must run, stderr={}",
        String::from_utf8_lossy(&inherited.stderr)
    );
    assert!(
        !text.contains("GITHUB_TOKEN") && !text.contains("fixture"),
        "inherited token must be absent"
    );

    let argv = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", "/usr/bin/env", "GITHUB_TOKEN=fixture", "/usr/bin/env"])
        .output()
        .expect("spawn");
    let text = String::from_utf8_lossy(&argv.stdout);
    assert!(
        !text.contains("fixture"),
        "argv env assignment must be stripped"
    );

    let opted = workpen()
        .env("GITHUB_TOKEN", "fixture")
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--env", "GITHUB_TOKEN", "--", "/usr/bin/env"])
        .output()
        .expect("spawn");
    let text = String::from_utf8_lossy(&opted.stdout);
    assert!(
        text.contains("GITHUB_TOKEN=fixture"),
        "opt-in must show the parent value"
    );

    let loader = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--env", "LD_PRELOAD=/tmp/nope.so", "--", "/usr/bin/env"])
        .output()
        .expect("spawn");
    let text = String::from_utf8_lossy(&loader.stdout);
    assert!(!text.contains("LD_PRELOAD") && !text.contains("nope.so"));

    let cleared = workpen()
        .env("GITHUB_TOKEN", "fixture")
        .args(["run", "--env", "FOO=bar", "--env-clear", "--root"])
        .arg(dir.path())
        .args(["--", "echo", "ok"])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&cleared.stdout);
    assert!(
        cleared.status.success(),
        "relative echo after --env-clear must run, stderr={}",
        String::from_utf8_lossy(&cleared.stderr)
    );
    assert!(stdout.contains("ok"), "{stdout}");

    let echo_flag = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", "/bin/echo", "--env"])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&echo_flag.stdout);
    assert!(
        stdout.contains("--env") || stdout.contains("echo"),
        "run -- /bin/echo --env is the child: {stdout}"
    );
}

#[test]
fn why_and_run_json_do_not_leak_or_wrap_success() {
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join(".env"), b"SECRET=1\n").expect("env");
    std::fs::write(dir.path().join("notes.md"), b"hello notes\n").expect("notes");
    let denied = workpen()
        .args(["why", "--json", "--root"])
        .arg(dir.path())
        .arg(".env")
        .output()
        .expect("spawn");
    assert_eq!(denied.status.code(), Some(1));
    let text = String::from_utf8_lossy(&denied.stdout);
    assert!(text.contains("\"result\":\"denied\""), "{text}");
    assert!(text.contains("\"exit\":1"), "{text}");
    assert!(text.contains("\"kind\":\"deny_glob\""), "{text}");
    assert!(!text.contains("SECRET"));
    assert_eq!(text.lines().count(), 1);
    let allowed = workpen()
        .args(["why", "--json", "--root"])
        .arg(dir.path())
        .arg("notes.md")
        .output()
        .expect("spawn");
    assert_eq!(allowed.status.code(), Some(0));
    let text = String::from_utf8_lossy(&allowed.stdout);
    assert!(text.contains("\"result\":\"allowed\""), "{text}");
    assert_eq!(text.lines().count(), 1);
    let run_deny = workpen()
        .args(["run", "--json", "--root"])
        .arg(dir.path())
        .args(["--", "/bin/cat", ".env"])
        .output()
        .expect("spawn");
    assert_eq!(run_deny.status.code(), Some(3));
    let text = String::from_utf8_lossy(&run_deny.stdout);
    assert!(text.contains("\"result\":\"denied\""), "{text}");
    assert!(text.contains("\"exit\":3"), "{text}");
    assert!(!text.contains("SECRET"));
    assert!(
        run_deny.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&run_deny.stderr)
    );
    #[cfg(unix)]
    {
        // The deny cases above plant `.env`. A clean root has no dest to
        // hide, so echo starts and `--json` must not wrap its stdout.
        let clean = TempDir::new().expect("clean");
        let run_ok = workpen()
            .args(["run", "--json", "--root"])
            .arg(clean.path())
            .args(["--", "/bin/echo", "hello-json"])
            .output()
            .expect("spawn");
        let stdout = String::from_utf8_lossy(&run_ok.stdout);
        let stderr = String::from_utf8_lossy(&run_ok.stderr);
        assert!(
            run_ok.status.success()
                && stdout.contains("hello-json")
                && !stdout.contains("\"result\""),
            "success must not wrap stdout: stdout={stdout} stderr={stderr}"
        );
        let as_child = workpen()
            .args(["run", "--root"])
            .arg(clean.path())
            .args(["--", "/bin/echo", "--json"])
            .output()
            .expect("spawn");
        let child_out = String::from_utf8_lossy(&as_child.stdout);
        assert!(
            as_child.status.success()
                && child_out.contains("--json")
                && !child_out.contains("\"result\""),
            "--json after -- is the child: stdout={child_out} stderr={}",
            String::from_utf8_lossy(&as_child.stderr)
        );
        let home = std::env::var("HOME").expect("HOME");
        let home_out = workpen()
            .args(["run", "--json", "--root", &home, "--", "/bin/echo", "x"])
            .output()
            .expect("spawn");
        assert_eq!(home_out.status.code(), Some(3));
        let home_text = String::from_utf8_lossy(&home_out.stdout);
        assert!(home_text.contains("\"result\":\"denied\""), "{home_text}");
        assert!(home_text.contains("\"kind\":\"path_guard\""), "{home_text}");
        assert!(home_text.contains("\"exit\":3"), "{home_text}");
        assert!(
            home_out.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&home_out.stderr)
        );
        let root_out = workpen()
            .args(["run", "--json", "--root", "/", "--", "/bin/echo", "x"])
            .output()
            .expect("spawn");
        assert_eq!(root_out.status.code(), Some(3));
        let root_text = String::from_utf8_lossy(&root_out.stdout);
        assert!(root_text.contains("\"kind\":\"path_guard\""), "{root_text}");
        assert!(
            root_out.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&root_out.stderr)
        );
        let why_home = workpen()
            .args(["why", "--json", "--root", &home, "notes.md"])
            .output()
            .expect("spawn");
        assert_eq!(why_home.status.code(), Some(1));
        let why_text = String::from_utf8_lossy(&why_home.stdout);
        assert!(why_text.contains("\"kind\":\"path_guard\""), "{why_text}");
        assert!(why_text.contains("\"exit\":1"), "{why_text}");
        assert!(
            why_home.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&why_home.stderr)
        );
    }
}

#[test]
fn init_writes_comments_and_does_not_replace_an_existing_file() {
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join(".env"), b"SECRET=1\n").expect("env");
    let created = workpen()
        .args(["init", "--root"])
        .arg(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(
        created.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let path = dir.path().join("agent.lock");
    let body = std::fs::read_to_string(&path).expect("read lock");
    for line in body.lines() {
        let trimmed = line.trim();
        assert!(
            trimmed.is_empty() || trimmed.starts_with('#'),
            "init line must be a comment or blank: {line}"
        );
    }
    assert!(body.contains("# secrets/**"), "{body}");
    assert!(!body.lines().any(|line| line.trim() == "secrets/**"));
    let why = workpen()
        .args(["why", "--root"])
        .arg(dir.path())
        .arg(".env")
        .output()
        .expect("spawn");
    assert_eq!(why.status.code(), Some(1));
    let text = String::from_utf8_lossy(&why.stdout);
    assert!(text.to_ascii_lowercase().contains("deny"), "{text}");
    assert!(!text.contains("SECRET"));
    let again = workpen()
        .args(["init", "--root"])
        .arg(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(again.status.code(), Some(2));
    assert_eq!(std::fs::read_to_string(&path).expect("unchanged"), body);
    let nested = TempDir::new().expect("dir lock");
    std::fs::create_dir(nested.path().join("agent.lock")).expect("dir");
    let blocked = workpen()
        .args(["init", "--root"])
        .arg(nested.path())
        .output()
        .expect("spawn");
    assert_eq!(blocked.status.code(), Some(2));
    assert!(nested.path().join("agent.lock").is_dir());
}

#[cfg(unix)]
#[test]
fn init_does_not_follow_an_agent_lock_symlink() {
    let dir = TempDir::new().expect("workspace");
    let outside = TempDir::new().expect("outside");
    let target = outside.path().join("pwned");
    std::os::unix::fs::symlink(&target, dir.path().join("agent.lock")).expect("link");
    let out = workpen()
        .args(["init", "--root"])
        .arg(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("symlink"), "{err}");
    assert!(!target.exists(), "init wrote through the symlink");
    let meta = std::fs::symlink_metadata(dir.path().join("agent.lock")).expect("link remains");
    assert!(meta.file_type().is_symlink());
}

#[cfg(unix)]
#[test]
fn init_refuses_home_and_filesystem_root() {
    let home = std::env::var("HOME").expect("HOME");
    let home_out = workpen()
        .args(["init", "--root", &home])
        .output()
        .expect("spawn");
    assert_eq!(home_out.status.code(), Some(3));
    let root_out = workpen()
        .args(["init", "--root", "/"])
        .output()
        .expect("spawn");
    assert_eq!(root_out.status.code(), Some(3));
}

#[test]
fn policy_prints_jail_without_secret_bytes() {
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join(".env"), b"SECRET=1\n").expect("env");
    let out = workpen()
        .args(["policy", "--root"])
        .arg(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("network: blocked"), "{stdout}");
    assert!(stdout.contains("read-write:"), "{stdout}");
    assert!(stdout.contains("read:"), "{stdout}");
    assert!(stdout.contains("deny: **/.env"), "{stdout}");
    assert!(!stdout.contains("SECRET"));
    let would = workpen()
        .args(["policy", "--root"])
        .arg(dir.path())
        .args(["--", ".env"])
        .output()
        .expect("spawn");
    assert_eq!(would.status.code(), Some(0));
    let text = String::from_utf8_lossy(&would.stdout);
    assert!(text.contains("would-deny"), "{text}");
    assert!(!text.contains("SECRET"));
}

#[test]
fn policy_net_is_allowed_and_dashdash_net_is_the_child() {
    let dir = TempDir::new().expect("workspace");
    let allowed = workpen()
        .args(["policy", "--net", "--root"])
        .arg(dir.path())
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&allowed.stdout);
    assert!(stdout.contains("network: allowed"), "{stdout}");
    #[cfg(unix)]
    {
        let child = workpen()
            .args(["run", "--root"])
            .arg(dir.path())
            .args(["--", "/bin/echo", "--net"])
            .output()
            .expect("spawn");
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(
            stdout.contains("--net") || stdout.contains("echo"),
            "run -- /bin/echo --net must not enable network by stealing the arg: stdout={stdout} stderr={}",
            String::from_utf8_lossy(&child.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn policy_home_and_fs_root_match_run_exit() {
    let home = std::env::var("HOME").expect("HOME");
    let policy_home = workpen()
        .args(["policy", "--root", &home])
        .output()
        .expect("spawn");
    let run_home = workpen()
        .args(["run", "--root", &home, "--", "/bin/echo", "x"])
        .output()
        .expect("spawn");
    assert_eq!(policy_home.status.code(), Some(3));
    assert_eq!(policy_home.status.code(), run_home.status.code());
    let policy_root = workpen()
        .args(["policy", "--root", "/"])
        .output()
        .expect("spawn");
    let run_root = workpen()
        .args(["run", "--root", "/", "--", "/bin/echo", "x"])
        .output()
        .expect("spawn");
    assert_eq!(policy_root.status.code(), Some(3));
    assert_eq!(policy_root.status.code(), run_root.status.code());
}

#[test]
fn policy_invalid_lock_exits_like_run() {
    let dir = TempDir::new().expect("workspace");
    std::fs::write(dir.path().join("agent.lock"), b"[\n").expect("lock");
    let policy = workpen()
        .args(["policy", "--root"])
        .arg(dir.path())
        .output()
        .expect("spawn");
    let run = workpen()
        .args(["run", "--root"])
        .arg(dir.path())
        .args(["--", "/bin/echo", "x"])
        .output()
        .expect("spawn");
    assert_eq!(policy.status.code(), Some(2));
    assert!(
        policy.stdout.is_empty(),
        "invalid lock must not print a partial jail"
    );
    assert_eq!(policy.status.code(), run.status.code());
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
        stdout.contains("--timeout") && stdout.contains("--tty"),
        "run help must name --timeout and --tty: {stdout}"
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
    let target = repo.path().join("target");
    std::fs::create_dir_all(target.join("stale")).expect("target");
    std::fs::write(target.join("stale").join("old"), b"x").expect("target file");
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
        assert!(
            !stdout.contains("target/"),
            "gc must not report target/ as a leftover root: {stdout}"
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
    assert!(stdout.contains("1 leftover worktrees"), "{stdout}");
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

/// Windows rejects `"` in a file name. The helper test covers escaping
/// on every platform. This checks that `why --json` uses that helper.
#[cfg(unix)]
#[test]
fn why_json_escapes_a_quote_in_the_path() {
    let dir = TempDir::new().expect("dir");
    let file = dir.path().join("say\"hi.txt");
    std::fs::write(&file, b"ok").expect("write");
    let out = workpen()
        .args(["why", "--json", "--root"])
        .arg(dir.path())
        .arg(&file)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "why --json should allow the file: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("say\\\"hi.txt"),
        "quote in the path must be escaped: {stdout}"
    );
    assert!(stdout.lines().count() == 1, "one JSON object: {stdout}");
}

#[test]
fn doctor_help_names_the_command() {
    let out = workpen()
        .args(["doctor", "--help"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("workpen doctor"), "{stdout}");
    assert!(stdout.contains("Does not start a command"), "{stdout}");
}

#[test]
fn doctor_rejects_arguments() {
    let out = workpen()
        .args(["doctor", "--root"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn doctor_live_reports_this_machine() {
    let cwd = TempDir::new().expect("cwd");
    let env_path = cwd.path().join(".env");
    let out = workpen()
        .arg("doctor")
        .current_dir(cwd.path())
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("os:"), "{stdout} {stderr}");
    assert!(stdout.contains("version:"), "{stdout}");
    assert!(!stdout.contains("SECRET"));
    assert!(!env_path.exists(), "doctor must not plant .env");
    assert!(
        !stdout.contains("network: open") && !stdout.contains("network: allowed"),
        "{stdout}"
    );
    #[cfg(target_os = "linux")]
    {
        if stdout.contains("remount: unavailable") {
            assert_eq!(out.status.code(), Some(1), "{stdout} {stderr}");
            assert!(stdout.contains("kernel: supported"), "{stdout}");
            assert!(stdout.contains("unshare"), "{stdout}");
            assert!(stdout.contains("user-namespace id map"), "{stdout}");
            assert!(stdout.contains("private remount of /"), "{stdout}");
        } else {
            assert!(out.status.success(), "{stdout} {stderr}");
            assert!(stdout.contains("remount: available"), "{stdout}");
        }
    }
    #[cfg(target_os = "macos")]
    {
        assert!(out.status.success(), "{stdout} {stderr}");
        assert!(stdout.contains("kernel: supported"), "{stdout}");
        assert!(!stdout.contains("remount:"), "{stdout}");
    }
    #[cfg(windows)]
    {
        if stdout.contains("kernel: unsupported") {
            assert_eq!(out.status.code(), Some(1), "{stdout} {stderr}");
        } else {
            assert!(out.status.success(), "{stdout} {stderr}");
            assert!(
                stdout.contains("wfp: skipped") || stdout.contains("wfp: applied"),
                "{stdout}"
            );
        }
    }
}

/// A command killed by SIGKILL exits 137 from a shell (`128+9`).
/// Workpen was reporting 1 because the reaper dies by that signal
/// and `ExitStatus::code` is `None`.
#[cfg(unix)]
#[test]
fn run_killed_child_exits_137() {
    let dir = TempDir::new().expect("workspace");
    let out = workpen()
        .args(["run", "--timeout", "5s", "--root"])
        .arg(dir.path())
        .args(["--", "/bin/sh", "-c", "kill -9 $$"])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(137),
        "SIGKILL must be 128+9, stderr={stderr}"
    );
    assert!(
        !stderr.contains("failed to spawn"),
        "a signal is not a spawn failure: {stderr}"
    );
}
