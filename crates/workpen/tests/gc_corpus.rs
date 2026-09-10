//! Leftover worktree GC corpus. Fail-closed. Feature `gc`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use tempfile::TempDir;
use workpen::{GcDecision, GcKeepReason, GcPolicy, Worktree, decide, gc_leftovers, list_worktrees};

fn git(cwd: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("repo");
    git(dir.path(), &["init", "-b", "main"]);
    git(dir.path(), &["config", "user.email", "dev@example.com"]);
    git(dir.path(), &["config", "user.name", "dev"]);
    fs::write(dir.path().join("README"), b"x").expect("readme");
    git(dir.path(), &["add", "README"]);
    git(dir.path(), &["commit", "-m", "init"]);
    let top = dir.path().to_path_buf();
    (dir, top)
}

fn add_worktree(repo: &Path, name: &str) -> PathBuf {
    let dest = repo.join(name);
    git(
        repo,
        &["worktree", "add", dest.to_str().expect("utf8"), "-b", name],
    );
    dest
}

#[test]
fn refuse_home_as_workspace() {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    let Some(home) = home else {
        return;
    };
    let home = PathBuf::from(home);
    if !home.join(".git").exists() && !home.join(".git").is_file() {
        return;
    }
    let err = list_worktrees(&home).expect_err("home is not a gc workspace");
    assert!(err.to_string().contains("home"));
}

#[test]
fn primary_is_kept() {
    let (_dir, repo) = init_repo();
    let trees = list_worktrees(&repo).expect("list");
    let primary = trees.iter().find(|t| t.primary).expect("primary");
    let policy = GcPolicy::new(Duration::from_secs(0));
    match decide(primary, &policy, SystemTime::now(), Path::new("/")).expect("decide") {
        GcDecision::Keep(GcKeepReason::Primary) => {}
        other => panic!("expected Primary, got {other:?}"),
    }
}

#[test]
fn dirty_worktree_is_kept() {
    let (_dir, repo) = init_repo();
    let wt = add_worktree(&repo, "dirty");
    fs::write(wt.join("README"), b"changed").expect("dirty");
    let tree = Worktree {
        path: wt,
        locked: false,
        primary: false,
    };
    let policy = GcPolicy::new(Duration::from_secs(0));
    match decide(&tree, &policy, SystemTime::now(), Path::new("/")).expect("decide") {
        GcDecision::Keep(GcKeepReason::Dirty) => {}
        other => panic!("expected Dirty, got {other:?}"),
    }
}

#[test]
fn unique_untracked_is_kept() {
    let (_dir, repo) = init_repo();
    let wt = add_worktree(&repo, "unique");
    fs::write(wt.join("only-here.txt"), b"unique").expect("untracked");
    let tree = Worktree {
        path: wt,
        locked: false,
        primary: false,
    };
    let policy = GcPolicy::new(Duration::from_secs(0));
    match decide(&tree, &policy, SystemTime::now(), Path::new("/")).expect("decide") {
        GcDecision::Keep(GcKeepReason::Unique) => {}
        other => panic!("expected Unique, got {other:?}"),
    }
}

#[test]
fn live_cwd_is_kept() {
    let (_dir, repo) = init_repo();
    let wt = add_worktree(&repo, "live");
    let tree = Worktree {
        path: wt.clone(),
        locked: false,
        primary: false,
    };
    let policy = GcPolicy::new(Duration::from_secs(0));
    match decide(&tree, &policy, SystemTime::now(), &wt).expect("decide") {
        GcDecision::Keep(GcKeepReason::LiveCwd) => {}
        other => panic!("expected LiveCwd, got {other:?}"),
    }
}

#[test]
fn locked_worktree_is_kept() {
    let tree = Worktree {
        path: PathBuf::from("/tmp/locked-wt"),
        locked: true,
        primary: false,
    };
    let policy = GcPolicy::new(Duration::from_secs(0));
    match decide(&tree, &policy, SystemTime::now(), Path::new("/")).expect("decide") {
        GcDecision::Keep(GcKeepReason::Locked) => {}
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn young_clean_worktree_is_kept() {
    let (_dir, repo) = init_repo();
    let wt = add_worktree(&repo, "young");
    let tree = Worktree {
        path: wt,
        locked: false,
        primary: false,
    };
    let policy = GcPolicy::new(Duration::from_secs(60 * 60));
    match decide(&tree, &policy, SystemTime::now(), Path::new("/")).expect("decide") {
        GcDecision::Keep(GcKeepReason::Young) => {}
        other => panic!("expected Young, got {other:?}"),
    }
}

#[test]
fn old_clean_worktree_is_removed() {
    let (_dir, repo) = init_repo();
    let wt = add_worktree(&repo, "oldclean");
    let tree = Worktree {
        path: wt.clone(),
        locked: false,
        primary: false,
    };
    let policy = GcPolicy::new(Duration::from_secs(0));
    let now = SystemTime::now() + Duration::from_secs(10);
    match decide(&tree, &policy, now, Path::new("/")).expect("decide") {
        GcDecision::Remove => {}
        other => panic!("expected Remove, got {other:?}"),
    }
    let report = gc_leftovers(&repo, &policy, now, Path::new("/")).expect("gc");
    let want = std::fs::canonicalize(&wt).unwrap_or(wt.clone());
    assert!(
        report
            .removed
            .iter()
            .any(|p| p == &wt || p == &want || p.file_name() == wt.file_name()),
        "old clean worktree should be removed: {report:?}"
    );
    assert!(!wt.exists(), "worktree directory should be gone");
}
