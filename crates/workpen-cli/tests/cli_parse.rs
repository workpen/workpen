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
        err.contains("usage: workpen"),
        "empty argv must print usage: {err}"
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
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(missing),
        "spawn failure must name {missing}: {err}"
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
