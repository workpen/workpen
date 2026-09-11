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
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
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
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
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

struct Repo {
    _lock: std::sync::MutexGuard<'static, ()>,
    _dir: TempDir,
    repo: PathBuf,
}

fn init_repo() -> Repo {
    let _lock = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().expect("repo");
    let repo = dir.path().join("origin");
    fs::create_dir(&repo).expect("origin");
    git(&repo, &["init", "-b", "main"]);
    git(&repo, &["config", "user.email", "dev@example.com"]);
    git(&repo, &["config", "user.name", "dev"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    git(&repo, &["config", "core.autocrlf", "false"]);
    git(&repo, &["config", "core.eol", "lf"]);
    fs::write(repo.join("README"), b"x").expect("readme");
    git(&repo, &["add", "README"]);
    git(&repo, &["commit", "-m", "init"]);
    Repo {
        _lock,
        _dir: dir,
        repo,
    }
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
fn parse_max_age_does_not_peel_quotes() {
    match parse_max_age("'7d'") {
        Err(GcError::InvalidDuration(msg)) => {
            assert!(
                msg.contains("use s, m, h, d"),
                "quoted 7d must hint units, got {msg}"
            );
        }
        other => panic!("quoted 7d must stay InvalidDuration, got {other:?}"),
    }
    match parse_max_age("\"7d\"") {
        Err(GcError::InvalidDuration(msg)) => {
            assert!(
                msg.contains("use s, m, h, d"),
                "double-quoted 7d must hint units, got {msg}"
            );
        }
        other => panic!("double-quoted 7d must stay InvalidDuration, got {other:?}"),
    }
    match parse_max_age("7days") {
        Err(GcError::InvalidDuration(msg)) => {
            assert!(
                msg.contains("use s, m, h, d"),
                "7days must hint units, got {msg}"
            );
        }
        other => panic!("7days must stay InvalidDuration, got {other:?}"),
    }
    assert_eq!(
        parse_max_age("7d").expect("bare 7d"),
        Duration::from_secs(7 * 86400)
    );
}

struct RestoreHomeEnv {
    home: Option<std::ffi::OsString>,
    profile: Option<std::ffi::OsString>,
}

impl RestoreHomeEnv {
    fn set_to(path: &Path) -> Self {
        let home = std::env::var_os("HOME");
        let profile = std::env::var_os("USERPROFILE");
        // Safety: serialized by CWD_LOCK (Repo holds it); restored on drop.
        unsafe {
            std::env::set_var("HOME", path);
            std::env::set_var("USERPROFILE", path);
        }
        Self { home, profile }
    }
}

impl Drop for RestoreHomeEnv {
    fn drop(&mut self) {
        unsafe {
            match &self.home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match &self.profile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }
}

#[test]
fn refuse_home_as_workspace() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let _restore = RestoreHomeEnv::set_to(&repo);
    match run_gc(&repo, &GcConfig::new(&repo, Duration::from_secs(1))) {
        Err(GcError::Home(_)) => {}
        other => panic!("expected Home, got {other:?}"),
    }
}

#[test]
fn primary_is_never_a_candidate() {
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
fn ignored_env_in_old_worktree_is_kept() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    fs::write(repo.join(".gitignore"), b".env\n").expect("gitignore");
    git(&repo, &["add", ".gitignore"]);
    git(&repo, &["commit", "-m", "ignore env"]);
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "ignored-env");
    let env = wt.join(".env");
    fs::write(&env, b"SECRET=1\n").expect("env");
    let now = SystemTime::now() + Duration::from_secs(10);
    match classify_for_age_gc(&wt, false, Duration::from_secs(0), now) {
        GcDecision::Keep {
            reason: KeepReason::UniqueUntracked | KeepReason::DirtyWork,
        } => {}
        other => panic!("gitignored .env must keep the tree, got {other:?}"),
    }
    let rows = run_gc(&repo, &cfg(&repo, Duration::from_secs(0), now)).expect("gc");
    let row = rows
        .iter()
        .find(|(p, _)| p.file_name() == wt.file_name())
        .expect("ignored-env row");
    match &row.1 {
        GcDecision::Keep {
            reason: KeepReason::UniqueUntracked | KeepReason::DirtyWork,
        } => {}
        other => panic!("run_gc must keep leftover with .env, got {other:?}"),
    }
    assert!(wt.exists(), "worktree with gitignored .env must stay");
    assert!(env.exists(), "gitignored .env must not be deleted");
    assert_eq!(fs::read(&env).expect("read env"), b"SECRET=1\n");
}

#[test]
fn live_cwd_is_kept() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "live");
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
fn gitignored_untagged_node_modules_is_reclaimable() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    fs::write(repo.join(".gitignore"), b"node_modules\n").expect("gitignore");
    git(&repo, &["add", ".gitignore"]);
    git(&repo, &["commit", "-m", "ignore node_modules"]);
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "untagged-nm");
    let nm = wt.join("node_modules");
    fs::create_dir_all(&nm).expect("node_modules");
    fs::write(nm.join("foo"), b"pkg").expect("foo");
    assert!(
        !nm.join("CACHEDIR.TAG").exists(),
        "fixture must not have CACHEDIR.TAG"
    );
    match classify_worktree(&wt, false) {
        GcDecision::Reclaim { .. } => {}
        GcDecision::Keep {
            reason: KeepReason::UniqueUntracked,
        } => panic!("untagged gitignored node_modules must not keep UniqueUntracked"),
        other => panic!("expected reclaim untagged node_modules, got {other:?}"),
    }
    let now = SystemTime::now() + Duration::from_secs(10);
    match classify_for_age_gc(&wt, false, Duration::from_secs(0), now) {
        GcDecision::Reclaim { .. } => {}
        GcDecision::Keep {
            reason: KeepReason::UniqueUntracked,
        } => panic!("old leftover with only untagged node_modules must not keep UniqueUntracked"),
        other => panic!("expected Reclaim for old untagged node_modules leftover, got {other:?}"),
    }
    let rows = run_gc(&repo, &cfg(&repo, Duration::from_secs(0), now)).expect("gc");
    assert!(
        rows.iter().any(|(p, d)| {
            p.file_name() == wt.file_name() && matches!(d, GcDecision::Reclaim { .. })
        }),
        "old leftover with only untagged node_modules should reclaim: {rows:?}"
    );
    assert!(
        !wt.exists(),
        "worktree with only untagged node_modules should be gone"
    );
}

#[test]
fn unique_dangling_commit_is_saved_under_prefix() {
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
        Err(GcError::RegistryUnreadable(_)) => {}
        other => panic!("expected RegistryUnreadable, got {other:?}"),
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
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
    let fx = init_repo();
    let repo = fx.repo.clone();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "last-used");
    let used = worktree_last_used(&wt).expect("last used");
    assert!(used <= SystemTime::now() + Duration::from_secs(2));
}

fn add_sibling_worktree(repo: &Path, name: &str) -> PathBuf {
    let dest = repo.parent().expect("temp parent").join(name);
    git(
        repo,
        &["worktree", "add", dest.to_str().expect("utf8"), "-b", name],
    );
    dest
}

#[test]
fn remove_explicit_sibling_worktree_reclaims() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let wt = add_sibling_worktree(&repo, "sib-rm");
    assert_ne!(
        wt.parent().expect("parent"),
        repo.as_path(),
        "sibling parent must not be the repo"
    );
    match remove_explicit(&wt, "refs/workpen/reclaimed", false) {
        Ok(GcDecision::Reclaim { .. }) => {}
        other => panic!("sibling worktree must reclaim, got {other:?}"),
    }
    assert!(!wt.exists(), "sibling tree should be removed");
}

#[test]
fn remove_explicit_force_removes_locked() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let wt = add_sibling_worktree(&repo, "sib-lock");
    git(&repo, &["worktree", "lock", wt.to_str().expect("utf8")]);
    match remove_explicit(&wt, "refs/workpen/reclaimed", false) {
        Ok(GcDecision::Keep {
            reason: KeepReason::Locked,
        }) => {}
        other => panic!("locked without force must keep, got {other:?}"),
    }
    assert!(wt.exists(), "locked tree must stay without force");
    match remove_explicit(&wt, "refs/workpen/reclaimed", true) {
        Ok(GcDecision::Reclaim { .. }) => {}
        other => panic!("force must remove locked, got {other:?}"),
    }
    assert!(!wt.exists(), "forced locked tree should be removed");
}

#[test]
fn remove_explicit_untracked_leftover_rm() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "orphan-copy");
    let gitdir = repo.join(".git").join("worktrees").join("orphan-copy");
    fs::write(
        wt.join(".git"),
        format!("gitdir: {}\n", repo.join(".git").display()),
    )
    .expect("retarget git");
    if gitdir.exists() {
        fs::remove_dir_all(&gitdir).expect("unregister");
    }
    match remove_explicit(&wt, "refs/workpen/reclaimed", false) {
        Ok(GcDecision::Reclaim { .. }) => {}
        other => panic!("untracked leftover must rm after unique-work, got {other:?}"),
    }
    assert!(!wt.exists(), "untracked leftover should be removed");
}

#[test]
fn remove_explicit_other_repo_cwd_uses_path_registry() {
    let fx = init_repo();
    let repo_a = fx.repo.clone();
    let repo_b = repo_a.parent().expect("temp parent").join("other");
    fs::create_dir(&repo_b).expect("other");
    git(&repo_b, &["init", "-b", "main"]);
    git(&repo_b, &["config", "user.email", "dev@example.com"]);
    git(&repo_b, &["config", "user.name", "dev"]);
    git(&repo_b, &["config", "commit.gpgsign", "false"]);
    fs::write(repo_b.join("README"), b"b").expect("readme b");
    git(&repo_b, &["add", "README"]);
    git(&repo_b, &["commit", "-m", "init-b"]);
    let wt = add_sibling_worktree(&repo_a, "from-a");
    let prev = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&repo_b).expect("chdir B");
    let got = remove_explicit(&wt, "refs/workpen/reclaimed", false);
    let _ = std::env::set_current_dir(&prev);
    match got {
        Ok(GcDecision::Reclaim { .. }) => {}
        other => panic!("cwd B must still reclaim A's worktree, got {other:?}"),
    }
    assert!(!wt.exists(), "A's registered tree must be removed");
    assert!(repo_a.join("README").exists(), "repo A must stay");
    assert!(repo_b.join("README").exists(), "repo B must stay");
}

#[test]
fn classify_worktree_reclaim_has_empty_saved_refs() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "classify-save");
    fs::write(wt.join("README"), b"unique commit").expect("edit");
    git(&wt, &["add", "README"]);
    git(&wt, &["commit", "-m", "unique"]);
    let sha = git_out(&wt, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&wt, &["reset", "--hard", "HEAD~1"]);
    match classify_worktree(&wt, false) {
        GcDecision::Reclaim { saved_refs } => {
            assert!(
                saved_refs.is_empty(),
                "classify must not save refs, got {saved_refs:?}"
            );
        }
        other => panic!("unique dangling must classify Reclaim, got {other:?}"),
    }
    let listed = git_out(&repo, &["show-ref"]);
    assert!(
        !listed.contains("refs/workpen/reclaimed"),
        "classify must not write reclaimed refs: {listed}"
    );
    match remove_explicit(&wt, "refs/workpen/reclaimed", false) {
        Ok(GcDecision::Reclaim { saved_refs }) => {
            assert!(
                saved_refs
                    .iter()
                    .any(|r| r.contains("refs/workpen/reclaimed") && r.contains(&sha)),
                "remove_explicit must save, got {saved_refs:?}"
            );
        }
        other => panic!("remove_explicit must reclaim, got {other:?}"),
    }
    let listed = git_out(&repo, &["show-ref"]);
    assert!(
        listed.contains("refs/workpen/reclaimed"),
        "remove_explicit must write reclaimed refs: {listed}"
    );
}

#[cfg(unix)]
#[test]
fn remove_explicit_registry_unreadable() {
    use std::os::unix::fs::PermissionsExt;
    let fx = init_repo();
    let repo = fx.repo.clone();
    let wt = add_sibling_worktree(&repo, "sib-unreadable");
    let real = Command::new("sh")
        .args(["-c", "command -v git"])
        .output()
        .expect("which git");
    assert!(real.status.success(), "need git on PATH");
    let real = String::from_utf8_lossy(&real.stdout).trim().to_owned();
    let wrap_dir = tempfile::TempDir::new().expect("wrap");
    let wrap = wrap_dir.path().join("git");
    fs::write(
        &wrap,
        format!(
            "#!/bin/sh\ncase \" $* \" in\n*\" worktree list \"*) echo unreadable >&2; exit 1 ;;\nesac\nexec {real} \"$@\"\n"
        ),
    )
    .expect("wrapper");
    fs::set_permissions(&wrap, fs::Permissions::from_mode(0o755)).expect("chmod");
    let old = std::env::var_os("PATH");
    let mut path = wrap_dir.path().display().to_string();
    path.push(':');
    path.push_str(&std::env::var("PATH").unwrap_or_default());
    unsafe { std::env::set_var("PATH", &path) };
    let got = remove_explicit(&wt, "refs/workpen/reclaimed", false);
    match old {
        Some(v) => unsafe { std::env::set_var("PATH", v) },
        None => unsafe { std::env::remove_var("PATH") },
    }
    match got {
        Err(GcError::RegistryUnreadable(_)) => {}
        other => panic!("unreadable registry must fail closed, got {other:?}"),
    }
    assert!(wt.exists(), "must not delete when registry is unreadable");
}

#[test]
fn git_ignores_process_git_dir() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "git-dir-env");
    let decoy = repo.join("no-such-git-dir");
    let old = std::env::var_os("GIT_DIR");
    // Safety: serialized by CWD_LOCK; restored below.
    unsafe { std::env::set_var("GIT_DIR", &decoy) };
    let used = worktree_last_used(&wt);
    match old {
        Some(v) => unsafe { std::env::set_var("GIT_DIR", v) },
        None => unsafe { std::env::remove_var("GIT_DIR") },
    }
    used.expect("process GIT_DIR must not hide last-used");
}

#[cfg(unix)]
fn with_git_wrapper<T>(script: &str, f: impl FnOnce() -> T) -> T {
    use std::os::unix::fs::PermissionsExt;
    let real = Command::new("sh")
        .args(["-c", "command -v git"])
        .output()
        .expect("which git");
    assert!(real.status.success(), "need git on PATH");
    let real = String::from_utf8_lossy(&real.stdout).trim().to_owned();
    let wrap_dir = tempfile::TempDir::new().expect("wrap");
    let wrap = wrap_dir.path().join("git");
    fs::write(&wrap, script.replace("__GIT__", &real)).expect("wrapper");
    fs::set_permissions(&wrap, fs::Permissions::from_mode(0o755)).expect("chmod");
    let old = std::env::var_os("PATH");
    let mut path = wrap_dir.path().display().to_string();
    path.push(':');
    path.push_str(&std::env::var("PATH").unwrap_or_default());
    // Safety: serialized by CWD_LOCK; restored below.
    unsafe { std::env::set_var("PATH", &path) };
    let got = f();
    match old {
        Some(v) => unsafe { std::env::set_var("PATH", v) },
        None => unsafe { std::env::remove_var("PATH") },
    }
    got
}

#[cfg(unix)]
#[test]
fn remove_explicit_reflog_failure_keeps_tree() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let leftover = repo.join(".workpen-worktrees");
    let wt = add_leftover_worktree(&repo, &leftover, "reflog-fail");
    let got = with_git_wrapper(
        "#!/bin/sh\ncase \" $* \" in\n*\" reflog \"*) echo reflog failed >&2; exit 1 ;;\nesac\nexec __GIT__ \"$@\"\n",
        || remove_explicit(&wt, "refs/workpen/reclaimed", false),
    );
    match got {
        Ok(GcDecision::Keep {
            reason: KeepReason::StatusUnreadable,
        }) => {}
        other => panic!("reflog failure must keep StatusUnreadable, got {other:?}"),
    }
    assert!(wt.exists(), "must not delete when unique-commit save fails");
}

#[cfg(unix)]
#[test]
fn run_gc_reflog_failure_keeps_and_continues() {
    let fx = init_repo();
    let repo = fx.repo.clone();
    let leftover = repo.join(".workpen-worktrees");
    let fail = add_leftover_worktree(&repo, &leftover, "reflog-fail");
    let ok = add_leftover_worktree(&repo, &leftover, "reflog-ok");
    let now = SystemTime::now() + Duration::from_secs(10);
    let cfg = cfg(&repo, Duration::from_secs(0), now);
    let got = with_git_wrapper(
        "#!/bin/sh\ncase \" $* \" in\n*\" reflog \"*)\n  case \"$PWD/\" in\n  */reflog-fail/*|*/reflog-fail/) echo reflog failed >&2; exit 1 ;;\n  esac\n  ;;\nesac\nexec __GIT__ \"$@\"\n",
        || run_gc(&repo, &cfg),
    );
    let rows = got.expect("age-gc continues after save miss");
    let fail_row = rows
        .iter()
        .find(|(p, _)| p.file_name() == fail.file_name())
        .expect("reflog-fail row");
    assert_eq!(keep_reason(&fail_row.1), KeepReason::StatusUnreadable);
    assert!(fail.exists(), "save miss must not delete reflog-fail");
    let ok_row = rows
        .iter()
        .find(|(p, _)| p.file_name() == ok.file_name())
        .expect("reflog-ok row");
    match &ok_row.1 {
        GcDecision::Reclaim { .. } => {}
        other => panic!("sibling must still reclaim, got {other:?}"),
    }
    assert!(!ok.exists(), "other trees must still reclaim");
}
