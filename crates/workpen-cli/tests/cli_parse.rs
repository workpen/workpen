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
