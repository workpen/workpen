//! CLI parse errors name the legal surface and the spawn target.

use std::process::Command;

use tempfile::TempDir;

fn workpen() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workpen"))
}

#[test]
fn help_names_why_run_and_gc() {
    for arg in ["help", "--help"] {
        let out = workpen().arg(arg).output().expect("spawn workpen");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{arg} must exit 2, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("why"), "{arg} stderr must name why: {err}");
        assert!(err.contains("run"), "{arg} stderr must name run: {err}");
        assert!(err.contains("gc"), "{arg} stderr must name gc: {err}");
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
    assert!(
        !err.contains("--help"),
        "unknown gc flag must not advertise --help: {err}"
    );
}

#[test]
fn empty_argv_stays_not_ready() {
    let out = workpen().output().expect("spawn workpen");
    assert!(
        out.status.success(),
        "empty argv must exit 0, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Not ready."),
        "empty argv must stay stealth: {err}"
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
fn why_help_is_unknown_flag_not_allowed() {
    let out = workpen()
        .args(["why", "--help"])
        .output()
        .expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "why --help must exit 2, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.to_ascii_lowercase().contains("allowed"),
        "why --help must not print allowed: {stdout}"
    );
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
fn run_help_without_separator_is_unknown_flag() {
    let out = workpen()
        .args(["run", "--help"])
        .output()
        .expect("spawn workpen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "run --help must exit 2, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("failed to spawn"),
        "run --help must not spawn --help: {err}"
    );
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
