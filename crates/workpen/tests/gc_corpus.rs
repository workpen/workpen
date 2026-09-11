//! Leftover worktree GC corpus. Fail-closed. Feature `gc`.
//!
//! Host contract for first Bline dest-deny + argv + GC dogfood.
//! Do not dest-parent-copy Bline sources.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

static CWD_LOCK: Mutex<()> = Mutex::new(());

use tempfile::TempDir;
use workpen::{
    GcConfig, GcDecision, GcError, KeepReason, classify_for_age_gc, classify_worktree,
    parse_max_age, remove_explicit, run_gc, worktree_last_used,
};

const CACHEDIR_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n# cache\n";

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

fn git_out(cwd: &Path, args: &[&str]) -> String {
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
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn init_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("repo");
    git(dir.path(), &["init", "-b", "main"]);
    git(dir.path(), &["config", "user.email", "dev@example.com"]);
    git(dir.path(), &["config", "user.name", "dev"]);
    git(dir.path(), &["config", "commit.gpgsign", "false"]);
    fs::write(dir.path().join("README"), b"x").expect("readme");
    git(dir.path(), &["add", "README"]);
    git(dir.path(), &["commit", "-m", "init"]);
    let top = dir.path().to_path_buf();
    (dir, top)
}

fn add_leftover_worktree(repo: &Path, leftover_dir: &Path, name: &str) -> PathBuf {
    fs::create_dir_all(leftover_dir).expect("leftover dir");
    let dest = leftover_dir.join(name);
    git(
        repo,
        &["worktree", "add", dest.to_str().expect("utf8"), "-b", name],
    );
    dest
}

fn cfg(repo: &Path, max_age: Duration, now: SystemTime) -> GcConfig {
    let mut cfg = GcConfig::new(repo, max_age);
    cfg.now = now;
    cfg
}

fn keep_reason(decision: &GcDecision) -> KeepReason {
    match decision {
        GcDecision::Keep { reason } => *reason,
        other => panic!("expected Keep, got {other:?}"),
    }
}

#[test]
fn parse_max_age_tokens() {
    assert_eq!(
        parse_max_age("7d").expect("7d"),
        Duration::from_secs(7 * 86400)
    );
    assert_eq!(
        parse_max_age("24h").expect("24h"),
        Duration::from_secs(24 * 3600)
    );
    assert_eq!(
        parse_max_age("60m").expect("60m"),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(parse_max_age("30s").expect("30s"), Duration::from_secs(30));
}

#[test]
fn parse_max_age_rejects_zero_and_bad_unit() {
    match parse_max_age("0d") {
        Err(GcError::InvalidDuration(_)) => {}
        other => panic!("expected InvalidDuration, got {other:?}"),
    }
    match parse_max_age("5w") {
        Err(GcError::InvalidDuration(_)) => {}
        other => panic!("expected InvalidDuration, got {other:?}"),
    }
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
    let err = run_gc(&home, &GcConfig::new(&home, Duration::from_secs(1)))
        .expect_err("home is not a gc workspace");
    assert!(err.to_string().contains("home"));
}

#[test]
fn primary_is_never_a_candidate() {
    let (_dir, repo) = init_repo();
    let rows = run_gc(
        &repo,
        &cfg(&repo, Duration::from_secs(0), SystemTime::now()),
    )
    .expect("gc");
    assert!(
        rows.iter()
            .all(|(p, _)| p.canonicalize().ok() != repo.canonicalize().ok()),
        "primary checkout must not appear: {rows:?}"
    );
}

#[test]
fn dirty_worktree_is_kept() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "dirty");
    fs::write(wt.join("README"), b"changed").expect("dirty");
    match classify_worktree(&wt, false) {
        GcDecision::Keep {
            reason: KeepReason::DirtyWork,
        } => {}
        other => panic!("expected DirtyWork, got {other:?}"),
    }
}

#[test]
fn unique_untracked_is_kept() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "unique");
    fs::write(wt.join("only-here.txt"), b"unique").expect("untracked");
    match classify_worktree(&wt, false) {
        GcDecision::Keep {
            reason: KeepReason::UniqueUntracked,
        } => {}
        other => panic!("expected UniqueUntracked, got {other:?}"),
    }
}

#[test]
fn live_cwd_is_kept() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "live");
    let _guard = CWD_LOCK.lock().expect("cwd lock");
    let prev = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&wt).expect("chdir");
    let rows = run_gc(
        &repo,
        &cfg(
            &repo,
            Duration::from_secs(0),
            SystemTime::now() + Duration::from_secs(10),
        ),
    );
    let _ = std::env::set_current_dir(&prev);
    let rows = rows.expect("gc");
    let row = rows
        .iter()
        .find(|(p, _)| p.file_name() == wt.file_name())
        .expect("live row");
    assert_eq!(keep_reason(&row.1), KeepReason::LiveCwd);
    assert!(wt.exists(), "live cwd must not be removed");
}

#[test]
fn locked_worktree_is_kept() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "locked");
    git(&repo, &["worktree", "lock", wt.to_str().expect("utf8")]);
    let rows = run_gc(
        &repo,
        &cfg(
            &repo,
            Duration::from_secs(0),
            SystemTime::now() + Duration::from_secs(10),
        ),
    )
    .expect("gc");
    let row = rows
        .iter()
        .find(|(p, _)| p.file_name() == wt.file_name())
        .expect("locked row");
    assert_eq!(keep_reason(&row.1), KeepReason::Locked);
    assert!(wt.exists(), "locked worktree must not be removed");
}

#[test]
fn young_clean_worktree_is_kept() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "young");
    match classify_for_age_gc(&wt, false, Duration::from_secs(60 * 60), SystemTime::now()) {
        GcDecision::Keep {
            reason: KeepReason::TooNew,
        } => {}
        other => panic!("expected TooNew, got {other:?}"),
    }
}

#[test]
fn old_clean_worktree_is_reclaimed() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "oldclean");
    let now = SystemTime::now() + Duration::from_secs(10);
    match classify_for_age_gc(&wt, false, Duration::from_secs(0), now) {
        GcDecision::Reclaim { .. } => {}
        other => panic!("expected Reclaim, got {other:?}"),
    }
    let rows = run_gc(&repo, &cfg(&repo, Duration::from_secs(0), now)).expect("gc");
    assert!(
        rows.iter().any(|(p, d)| {
            p.file_name() == wt.file_name() && matches!(d, GcDecision::Reclaim { .. })
        }),
        "old clean worktree should be reclaimed: {rows:?}"
    );
    assert!(!wt.exists(), "worktree directory should be gone");
}

#[test]
fn untracked_leftover_is_kept_and_not_removed() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let copy = leftover.join("copy");
    fs::create_dir_all(&copy).expect("copy");
    fs::write(copy.join("README"), b"x").expect("readme");
    match classify_for_age_gc(&copy, true, Duration::from_secs(0), SystemTime::now()) {
        GcDecision::Keep {
            reason: KeepReason::UntrackedWorktree,
        } => {}
        other => panic!("expected UntrackedWorktree, got {other:?}"),
    }
    let rows = run_gc(
        &repo,
        &cfg(
            &repo,
            Duration::from_secs(0),
            SystemTime::now() + Duration::from_secs(10),
        ),
    )
    .expect("gc");
    assert!(
        rows.iter().any(|(p, d)| {
            p.file_name() == copy.file_name()
                && matches!(
                    d,
                    GcDecision::Keep {
                        reason: KeepReason::UntrackedWorktree
                    }
                )
        }),
        "untracked leftover should be reported: {rows:?}"
    );
    assert!(copy.exists(), "untracked leftover must not be age-removed");
}

#[test]
fn leftover_dir_is_host_configurable() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".bline-worktrees");
    let copy = leftover.join("copy");
    fs::create_dir_all(&copy).expect("copy");
    let mut gc = GcConfig::new(&repo, Duration::from_secs(0));
    gc.leftover_dir = leftover;
    gc.now = SystemTime::now() + Duration::from_secs(10);
    let rows = run_gc(&repo, &gc).expect("gc");
    assert!(
        rows.iter().any(|(p, d)| {
            p.file_name() == copy.file_name()
                && matches!(
                    d,
                    GcDecision::Keep {
                        reason: KeepReason::UntrackedWorktree
                    }
                )
        }),
        "host leftover_dir must be scanned: {rows:?}"
    );
    assert!(copy.exists());
}

#[test]
fn cache_only_target_is_reclaimable() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "cache-wt");
    let target = wt.join("target");
    fs::create_dir_all(&target).expect("target");
    fs::write(target.join("CACHEDIR.TAG"), CACHEDIR_TAG).expect("tag");
    fs::write(target.join("lib.rlib"), b"obj").expect("obj");
    match classify_worktree(&wt, false) {
        GcDecision::Reclaim { .. } => {}
        other => panic!("expected reclaim cache-only, got {other:?}"),
    }
}

#[test]
fn unique_dangling_commit_is_saved_under_prefix() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "saved");
    fs::write(wt.join("README"), b"unique commit").expect("edit");
    git(&wt, &["add", "README"]);
    git(&wt, &["commit", "-m", "unique"]);
    let sha = git_out(&wt, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&wt, &["reset", "--hard", "HEAD~1"]);
    let mut gc = cfg(
        &repo,
        Duration::from_secs(0),
        SystemTime::now() + Duration::from_secs(10),
    );
    gc.saved_ref_prefix = "refs/bline/reclaimed".into();
    let rows = run_gc(&repo, &gc).expect("gc");
    let saved = rows
        .iter()
        .find_map(|(p, d)| {
            if p.file_name() == wt.file_name() {
                match d {
                    GcDecision::Reclaim { saved_refs } => Some(saved_refs.clone()),
                    _ => None,
                }
            } else {
                None
            }
        })
        .expect("reclaim row");
    assert!(
        saved
            .iter()
            .any(|r| r.contains("refs/bline/reclaimed") && r.contains(&sha)),
        "expected saved ref under host prefix: {saved:?}"
    );
    let listed = git_out(&repo, &["show-ref"]);
    assert!(
        listed.contains("refs/bline/reclaimed"),
        "saved ref must exist on the repo: {listed}"
    );
    assert!(!wt.exists(), "tree is removed; branch/ref kept");
}

#[test]
fn dry_run_does_not_remove() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "dry");
    let mut gc = cfg(
        &repo,
        Duration::from_secs(0),
        SystemTime::now() + Duration::from_secs(10),
    );
    gc.dry_run = true;
    let rows = run_gc(&repo, &gc).expect("gc");
    assert!(
        rows.iter().any(
            |(p, d)| p.file_name() == wt.file_name() && matches!(d, GcDecision::Reclaim { .. })
        ),
        "dry-run still classifies reclaim: {rows:?}"
    );
    assert!(wt.exists(), "dry-run must leave the tree");
}

#[test]
fn registry_unreadable_is_error() {
    let dir = TempDir::new().expect("tmp");
    match run_gc(
        dir.path(),
        &GcConfig::new(dir.path(), Duration::from_secs(1)),
    ) {
        Err(GcError::RegistryUnreadable(_)) | Err(GcError::Git { .. }) => {}
        other => panic!("expected registry error, got {other:?}"),
    }
}

#[test]
fn keep_reason_as_str_is_stable() {
    assert_eq!(KeepReason::DirtyWork.as_str(), "unique uncommitted work");
    assert_eq!(
        KeepReason::UniqueUntracked.as_str(),
        "unique untracked files"
    );
    assert_eq!(KeepReason::TooNew.as_str(), "newer than --max-age");
    assert_eq!(
        KeepReason::UntrackedWorktree.as_str(),
        "untracked (use worktree rm)"
    );
    assert_eq!(KeepReason::NotAGitDir.as_str(), "not a git worktree");
    assert_eq!(
        KeepReason::StatusUnreadable.as_str(),
        "git status unreadable"
    );
    assert_eq!(KeepReason::LiveCwd.as_str(), "live process cwd");
    assert_eq!(KeepReason::Locked.as_str(), "locked");
}

#[cfg(unix)]
#[test]
fn age_uses_tree_mtime_not_root_only() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "mtime");
    let amend = Command::new("git")
        .args([
            "commit",
            "--amend",
            "--no-edit",
            "--date=2000-01-01T00:00:00",
        ])
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00")
        .current_dir(&wt)
        .status()
        .expect("amend");
    if !amend.success() {
        return;
    }
    let index = git_out(&wt, &["rev-parse", "--git-path", "index"]);
    let index = PathBuf::from(index.trim());
    let index = if index.is_absolute() {
        index
    } else {
        wt.join(index)
    };
    let stamp = |p: &Path| {
        Command::new("touch")
            .args(["-t", "200001010000", p.to_str().expect("utf8")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !stamp(&wt) || !stamp(&index) {
        return;
    }
    fs::write(wt.join("nested.txt"), b"new").expect("nested");
    match classify_for_age_gc(&wt, false, Duration::from_secs(60 * 60), SystemTime::now()) {
        GcDecision::Keep {
            reason: KeepReason::TooNew,
        } => {}
        other => panic!("nested file mtime must keep the tree young, got {other:?}"),
    }
}

fn git_path(wt: &Path, name: &str) -> PathBuf {
    let raw = git_out(wt, &["rev-parse", "--git-path", name]);
    let p = PathBuf::from(raw.trim());
    if p.is_absolute() { p } else { wt.join(p) }
}

#[test]
fn unreadable_git_status_is_kept() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "status-fail");
    fs::write(git_path(&wt, "index"), [0u8, 0, 0]).expect("corrupt index");
    match classify_worktree(&wt, false) {
        GcDecision::Keep {
            reason: KeepReason::StatusUnreadable,
        } => {}
        other => panic!("expected StatusUnreadable, got {other:?}"),
    }
    let now = SystemTime::now() + Duration::from_secs(10);
    let _ = run_gc(&repo, &cfg(&repo, Duration::from_secs(0), now));
    assert!(wt.exists(), "unreadable status must not be reclaimed");
}

#[test]
fn missing_git_pointer_is_kept() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "missing-git");
    let git_ptr = wt.join(".git");
    if git_ptr.is_file() {
        fs::remove_file(&git_ptr).expect("remove .git file");
    } else {
        fs::remove_dir_all(&git_ptr).expect("remove .git dir");
    }
    match classify_worktree(&wt, false) {
        GcDecision::Keep {
            reason: KeepReason::NotAGitDir,
        } => {}
        other => panic!("expected NotAGitDir, got {other:?}"),
    }
    let now = SystemTime::now() + Duration::from_secs(10);
    let _ = run_gc(&repo, &cfg(&repo, Duration::from_secs(0), now));
    assert!(wt.exists(), "missing git dir must not be reclaimed");
}

#[cfg(unix)]
#[test]
fn recent_index_keeps_tree_when_head_and_files_are_old() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "index-age");
    let amend = Command::new("git")
        .args([
            "commit",
            "--amend",
            "--no-edit",
            "--date=2000-01-01T00:00:00",
        ])
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00")
        .current_dir(&wt)
        .status()
        .expect("amend");
    if !amend.success() {
        return;
    }
    let index = git_path(&wt, "index");
    let stamp = |p: &Path| {
        Command::new("touch")
            .args(["-t", "200001010000", p.to_str().expect("utf8")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !stamp(&wt) || !stamp(&wt.join("README")) {
        return;
    }
    let now = SystemTime::now();
    if let Ok(f) = fs::File::open(&index) {
        let _ = f.set_modified(now);
    } else if !Command::new("touch")
        .arg(index.to_str().expect("utf8"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return;
    }
    match classify_for_age_gc(&wt, false, Duration::from_secs(60 * 60), now) {
        GcDecision::Keep {
            reason: KeepReason::TooNew,
        } => {}
        other => panic!("fresh index must keep the tree, got {other:?}"),
    }
}

#[test]
fn remove_explicit_refuses_dirty() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "rm-dirty");
    fs::write(wt.join("README"), b"changed").expect("dirty");
    match remove_explicit(&wt, "refs/workpen/reclaimed", true) {
        Ok(GcDecision::Keep {
            reason: KeepReason::DirtyWork,
        }) => {}
        other => panic!("force must not skip unique work, got {other:?}"),
    }
    assert!(wt.exists(), "dirty tree must stay");
}

#[test]
fn remove_explicit_reclaims_clean() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "rm-clean");
    match remove_explicit(&wt, "refs/workpen/reclaimed", false) {
        Ok(GcDecision::Reclaim { .. }) => {}
        other => panic!("expected reclaim, got {other:?}"),
    }
    assert!(!wt.exists(), "clean tree should be removed");
}

#[test]
fn worktree_last_used_is_public() {
    let (_dir, repo) = init_repo();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "last-used");
    let used = worktree_last_used(&wt).expect("last used");
    assert!(used <= SystemTime::now() + Duration::from_secs(2));
}
