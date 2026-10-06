//! Fail-closed leftover worktree age GC. Feature-gated (`gc`).
//!
//! Unique-work is `git status --porcelain=v1 -uall --ignored` (with
//! `status.showUntrackedFiles=all`). Last-used is `git log -1
//! --format=%ct`, the index mtime, and a bounded tree walk. Both clocks
//! are git CLI. There is no `gix` path in v1.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use crate::deny::{DenyPolicy, path_is_denied_glob};

/// Host knobs. Bline passes leftover_dir = ".bline-worktrees",
/// saved_ref_prefix = "refs/bline/reclaimed".
#[derive(Debug, Clone)]
pub struct GcConfig {
    pub leftover_dir: PathBuf,
    pub saved_ref_prefix: String,
    pub max_age: Duration,
    pub dry_run: bool,
    pub now: SystemTime,
}

impl GcConfig {
    pub fn new(cwd: &Path, max_age: Duration) -> Self {
        Self {
            leftover_dir: cwd.join(".workpen-worktrees"),
            saved_ref_prefix: "refs/workpen/reclaimed".into(),
            max_age,
            dry_run: false,
            now: SystemTime::now(),
        }
    }
}

/// Why a worktree must be kept. Hosts branch on this; do not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepReason {
    DirtyWork,
    UniqueUntracked,
    TooNew,
    UntrackedWorktree,
    NotAGitDir,
    StatusUnreadable,
    LiveCwd,
    Locked,
}

impl KeepReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DirtyWork => "unique uncommitted work",
            Self::UniqueUntracked => "unique untracked files",
            Self::TooNew => "newer than --max-age",
            Self::UntrackedWorktree => "untracked leftover (not a registered worktree)",
            Self::NotAGitDir => "not a git worktree",
            Self::StatusUnreadable => "git status unreadable",
            Self::LiveCwd => "live process cwd",
            Self::Locked => "locked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcDecision {
    Keep { reason: KeepReason },
    Reclaim { saved_refs: Vec<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum GcError {
    #[error("invalid duration: {0}")]
    InvalidDuration(String),
    #[error("worktree registry unreadable: {0}")]
    RegistryUnreadable(String),
    #[error("{0} is not a git repository; gc reclaims leftover worktrees of a git repo")]
    NotARepo(String),
    #[error("git {op} failed: {detail}")]
    Git { op: String, detail: String },
    #[error("refuse to treat home as a git workspace: {0}")]
    Home(String),
}

/// Parse a duration token (`7d`, `24h`, `60m`, `30s`). Number must be `> 0`.
/// Does not peel quotes. Hosts strip `'7d'` / `"7d"` first.
pub fn parse_max_age(raw: &str) -> Result<Duration, GcError> {
    let s = raw.trim();
    if s.chars().count() < 2 {
        return Err(GcError::InvalidDuration(format!(
            "{s} (use e.g. 30s, 60m, 24h, 7d)"
        )));
    }
    let unit_start = s.char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
    let (num, unit) = s.split_at(unit_start);
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| GcError::InvalidDuration(format!("{s} (use s, m, h, d)")))?;
    if n == 0 {
        return Err(GcError::InvalidDuration(format!(
            "duration must be greater than zero: {s}"
        )));
    }
    let dur = match unit.to_ascii_lowercase().as_str() {
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n.saturating_mul(60)),
        "h" => Duration::from_secs(n.saturating_mul(3600)),
        "d" => Duration::from_secs(n.saturating_mul(86400)),
        _ => {
            return Err(GcError::InvalidDuration(format!("{s} (use s, m, h, d)")));
        }
    };
    // `Instant + duration` panics when the sum does not fit. A timeout
    // that large must be a usage error, not an abort after the child starts.
    if std::time::Instant::now().checked_add(dur).is_none() {
        return Err(GcError::InvalidDuration(format!(
            "duration does not fit on the clock: {s}"
        )));
    }
    Ok(dur)
}

/// Age filter then classify. Untracked trees are never age-gc'd.
///
/// Uses [`DenyPolicy::default()`]. Hosts with extras should call
/// [`classify_for_age_gc_with_policy`].
pub fn classify_for_age_gc(
    path: &Path,
    untracked: bool,
    max_age: Duration,
    now: SystemTime,
) -> GcDecision {
    classify_for_age_gc_with_policy(path, untracked, max_age, now, &DenyPolicy::default())
}

/// Like [`classify_for_age_gc`], using `policy` for glob-only cache name checks.
pub fn classify_for_age_gc_with_policy(
    path: &Path,
    untracked: bool,
    max_age: Duration,
    now: SystemTime,
    policy: &DenyPolicy,
) -> GcDecision {
    if untracked {
        return GcDecision::Keep {
            reason: KeepReason::UntrackedWorktree,
        };
    }
    if newest_tree_mtime(path).is_err() {
        return GcDecision::Keep {
            reason: KeepReason::StatusUnreadable,
        };
    }
    let index = index_file(path);
    let last_used = last_used_from(path, index.as_deref()).unwrap_or(now);
    if now.duration_since(last_used).unwrap_or_default() < max_age {
        return GcDecision::Keep {
            reason: KeepReason::TooNew,
        };
    }
    classify_worktree_with_index(path, false, policy, IndexSource::Ready(index.as_deref()))
}

/// Remove one worktree after the unique-work check.
///
/// Discovers `--git-common-dir` from `path` (not `path.parent()`).
/// `force` unlocks porcelain locked (`git worktree remove --force --force`).
/// `force` does not skip dirty, unique, live-cwd, unreadable, or missing-git Keep.
/// An unreadable worktree registry is [`GcError::RegistryUnreadable`].
/// A same-repo checkout missing from the registry is leftover rm
/// (`remove_dir_all`) after unique-work. A directory with no `.git` is
/// [`KeepReason::NotAGitDir`].
///
/// Uses [`DenyPolicy::default()`]. Hosts with extras should call
/// [`remove_explicit_with_policy`].
pub fn remove_explicit(
    path: &Path,
    saved_ref_prefix: &str,
    force: bool,
) -> Result<GcDecision, GcError> {
    remove_explicit_with_policy(path, saved_ref_prefix, force, &DenyPolicy::default())
}

/// Like [`remove_explicit`], using `policy` for glob-only cache name checks.
pub fn remove_explicit_with_policy(
    path: &Path,
    saved_ref_prefix: &str,
    force: bool,
    policy: &DenyPolicy,
) -> Result<GcDecision, GcError> {
    if !path.is_dir() || !is_git_repo(path) {
        return Ok(GcDecision::Keep {
            reason: KeepReason::NotAGitDir,
        });
    }
    let common = git_common_dir(path).map_err(registry_unreadable)?;
    let repo = repo_cwd_from_common_dir(&common);
    let registered = registered_worktrees(&repo)?;
    let entry = registered.iter().find(|w| paths_eq(&w.path, path));
    let locked = entry.is_some_and(|w| w.locked);
    if locked && !force {
        return Ok(GcDecision::Keep {
            reason: KeepReason::Locked,
        });
    }
    if worktree_has_live_cwd(path) {
        return Ok(GcDecision::Keep {
            reason: KeepReason::LiveCwd,
        });
    }
    match classify_worktree_with_policy(path, false, policy) {
        keep @ GcDecision::Keep { .. } => Ok(keep),
        GcDecision::Reclaim { .. } => {
            let saved = match save_unique_commits(path, saved_ref_prefix) {
                Ok(saved) => saved,
                Err(_) => {
                    return Ok(GcDecision::Keep {
                        reason: KeepReason::StatusUnreadable,
                    });
                }
            };
            take_if_still_clean(&repo, path, saved, locked && force, entry.is_some(), policy)
        }
    }
}

/// Classify keep vs reclaim (age already applied by the caller when relevant).
///
/// `Reclaim.saved_refs` is empty here. Unique commits are saved in
/// [`run_gc`] and [`remove_explicit`].
///
/// Uses [`DenyPolicy::default()`]. Hosts with extras should call
/// [`classify_worktree_with_policy`].
pub fn classify_worktree(path: &Path, untracked: bool) -> GcDecision {
    classify_worktree_with_policy(path, untracked, &DenyPolicy::default())
}

/// Like [`classify_worktree`], using `policy` for glob-only cache name checks.
pub fn classify_worktree_with_policy(
    path: &Path,
    untracked: bool,
    policy: &DenyPolicy,
) -> GcDecision {
    classify_worktree_with_index(path, untracked, policy, IndexSource::Lookup)
}

fn classify_worktree_with_index(
    path: &Path,
    untracked: bool,
    policy: &DenyPolicy,
    index: IndexSource<'_>,
) -> GcDecision {
    if untracked {
        return GcDecision::Keep {
            reason: KeepReason::UntrackedWorktree,
        };
    }
    if !path.is_dir() {
        return GcDecision::Keep {
            reason: KeepReason::NotAGitDir,
        };
    }
    if !is_git_repo(path) {
        return GcDecision::Keep {
            reason: KeepReason::NotAGitDir,
        };
    }
    match unique_work_from(path, policy, index) {
        Some(reason) => GcDecision::Keep { reason },
        None => GcDecision::Reclaim {
            saved_refs: Vec::new(),
        },
    }
}

/// List registered worktrees, skip primary checkout, skip locked / live cwd,
/// classify the rest. Untracked leftovers under `leftover_dir` are reported
/// as Keep(UntrackedWorktree) and never removed by age gc.
///
/// Uses [`DenyPolicy::default()`]. Hosts with extras should call
/// [`run_gc_with_policy`].
pub fn run_gc(cwd: &Path, cfg: &GcConfig) -> Result<Vec<(PathBuf, GcDecision)>, GcError> {
    run_gc_with_policy(cwd, cfg, &DenyPolicy::default())
}

/// Like [`run_gc`], using `policy` for glob-only cache name checks.
pub fn run_gc_with_policy(
    cwd: &Path,
    cfg: &GcConfig,
    policy: &DenyPolicy,
) -> Result<Vec<(PathBuf, GcDecision)>, GcError> {
    refuse_home(cwd)?;
    let registered = registered_worktrees(cwd)?;
    let registered_paths: Vec<PathBuf> = registered.iter().map(|w| w.path.clone()).collect();
    let primary = registered
        .first()
        .map(|w| w.path.clone())
        .or_else(|| repo_root(cwd).ok());
    let current = std::env::current_dir().ok();
    let mut other: Option<Result<Vec<PathBuf>, ()>> = None;
    let mut reachable_cache: Option<Result<HashSet<String>, ()>> = None;
    let mut rows = Vec::new();
    for wt in &registered {
        if primary.as_ref().is_some_and(|p| paths_eq(p, &wt.path)) {
            continue;
        }
        if wt.locked {
            rows.push((
                wt.path.clone(),
                GcDecision::Keep {
                    reason: KeepReason::Locked,
                },
            ));
            continue;
        }
        let probed = other.get_or_insert_with(other_process_cwds);
        let other_view = match probed {
            Ok(cwds) => Ok(cwds.as_slice()),
            Err(()) => Err(()),
        };
        if worktree_has_live_cwd_from(&wt.path, current.as_deref(), other_view) {
            rows.push((
                wt.path.clone(),
                GcDecision::Keep {
                    reason: KeepReason::LiveCwd,
                },
            ));
            continue;
        }
        let mut decision =
            classify_for_age_gc_with_policy(&wt.path, false, cfg.max_age, cfg.now, policy);
        if let GcDecision::Reclaim { .. } = &decision
            && !cfg.dry_run
        {
            decision = reclaim_with_saved_refs(
                cwd,
                &wt.path,
                &cfg.saved_ref_prefix,
                policy,
                &mut reachable_cache,
            )?;
        }
        rows.push((wt.path.clone(), decision));
    }
    for path in untracked_leftovers(&cfg.leftover_dir, &registered_paths) {
        rows.push((
            path,
            GcDecision::Keep {
                reason: KeepReason::UntrackedWorktree,
            },
        ));
    }
    if !cfg.dry_run {
        git(cwd, &["worktree", "prune"]).map_err(|e| match e {
            GcError::Git { detail, .. } => GcError::Git {
                op: "worktree prune".into(),
                detail,
            },
            other => other,
        })?;
    }
    Ok(rows)
}

const CACHE_DIR_NAMES: &[&str] = &["target", "node_modules", ".venv", "dist", "__pycache__"];
const LAST_USED_WALK_LIMIT: usize = 4096;

struct Registered {
    path: PathBuf,
    locked: bool,
}

fn refuse_home(repo: &Path) -> Result<(), GcError> {
    let top = match git(repo, &["rev-parse", "--show-toplevel"]) {
        Ok(s) => PathBuf::from(s.trim()),
        Err(_) => return Ok(()),
    };
    if is_home(&top) {
        return Err(GcError::Home(top.display().to_string()));
    }
    Ok(())
}

fn is_home(path: &Path) -> bool {
    crate::guard::is_user_home_dir(path)
}

fn repo_root(cwd: &Path) -> Result<PathBuf, GcError> {
    let top = git(cwd, &["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(top.trim()))
}

fn is_git_repo(cwd: &Path) -> bool {
    if !cwd.join(".git").exists() {
        return false;
    }
    git(cwd, &["rev-parse", "--is-inside-work-tree"])
        .map(|s| s.trim() == "true")
        .unwrap_or(false)
}

fn registered_worktrees(cwd: &Path) -> Result<Vec<Registered>, GcError> {
    let out = git(cwd, &["worktree", "list", "--porcelain"]).map_err(|e| match e {
        GcError::Git { detail, .. } if detail.contains("not a git repository") => {
            GcError::NotARepo(cwd.display().to_string())
        }
        GcError::Git { detail, .. } => GcError::RegistryUnreadable(detail),
        other => other,
    })?;
    Ok(parse_worktree_list(&out))
}

fn parse_worktree_list(text: &str) -> Vec<Registered> {
    let mut trees = Vec::new();
    let mut path: Option<PathBuf> = None;
    let mut locked = false;
    let flush = |trees: &mut Vec<Registered>, path: &mut Option<PathBuf>, locked: &mut bool| {
        if let Some(p) = path.take() {
            trees.push(Registered {
                path: p,
                locked: *locked,
            });
            *locked = false;
        }
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("worktree ") {
            flush(&mut trees, &mut path, &mut locked);
            path = Some(PathBuf::from(rest));
        } else if line == "locked" || line.starts_with("locked ") {
            locked = true;
        }
    }
    flush(&mut trees, &mut path, &mut locked);
    trees
}

fn untracked_leftovers(leftover_dir: &Path, registered: &[PathBuf]) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(leftover_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        if registered.iter().any(|r| paths_eq(r, &p)) {
            continue;
        }
        out.push(p);
    }
    out
}

fn paths_eq(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

fn path_is_same_or_parent(root: &Path, inner: &Path) -> bool {
    if paths_eq(root, inner) {
        return true;
    }
    match (std::fs::canonicalize(root), std::fs::canonicalize(inner)) {
        (Ok(r), Ok(i)) => i.starts_with(&r),
        _ => inner.starts_with(root),
    }
}

fn worktree_has_live_cwd(path: &Path) -> bool {
    let current = std::env::current_dir().ok();
    let other = other_process_cwds();
    worktree_has_live_cwd_from(
        path,
        current.as_deref(),
        match &other {
            Ok(cwds) => Ok(cwds.as_slice()),
            Err(()) => Err(()),
        },
    )
}

/// Fail-closed: unknown other-process cwds count as live.
fn worktree_has_live_cwd_from(
    path: &Path,
    current: Option<&Path>,
    other: Result<&[PathBuf], ()>,
) -> bool {
    if let Some(cwd) = current
        && path_is_same_or_parent(path, cwd)
    {
        return true;
    }
    match other {
        Err(()) => true,
        Ok(cwds) => cwds.iter().any(|cwd| path_is_same_or_parent(path, cwd)),
    }
}

/// Other-process cwds. `Err` when an expected probe failed.
/// Windows has no `/proc` and no `lsof`; that is not a probe failure.
fn other_process_cwds() -> Result<Vec<PathBuf>, ()> {
    #[cfg(test)]
    CWD_PROBE_COUNT.with(|slot| slot.set(slot.get().saturating_add(1)));
    #[cfg(target_os = "linux")]
    {
        if let Ok(cwds) = linux_process_cwds() {
            return Ok(cwds);
        }
    }
    #[cfg(unix)]
    {
        lsof_process_cwds()
    }
    #[cfg(not(unix))]
    {
        Ok(Vec::new())
    }
}

#[cfg(target_os = "linux")]
fn linux_process_cwds() -> Result<Vec<PathBuf>, ()> {
    let rd = std::fs::read_dir("/proc").map_err(|_| ())?;
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let cwd_link = entry.path().join("cwd");
        if let Ok(cwd) = std::fs::read_link(cwd_link) {
            out.push(cwd);
        }
    }
    Ok(out)
}

#[cfg(unix)]
fn lsof_process_cwds() -> Result<Vec<PathBuf>, ()> {
    let out = Command::new("lsof")
        .args(["-a", "-d", "cwd", "-Fn"])
        .output()
        .map_err(|_| ())?;
    let paths: Vec<PathBuf> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix('n'))
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect();
    if !out.status.success() && paths.is_empty() {
        return Err(());
    }
    Ok(paths)
}

/// Newest of HEAD committer time (`git log -1 --format=%ct`), index
/// mtime, and a bounded tree walk. Git CLI, not gix.
pub fn worktree_last_used(path: &Path) -> Option<SystemTime> {
    let index = index_file(path);
    last_used_from(path, index.as_deref())
}

fn last_used_from(path: &Path, index: Option<&Path>) -> Option<SystemTime> {
    let mut latest = head_commit_time(path);
    if let Some(t) = index_mtime_at(index) {
        latest = Some(latest.map_or(t, |n| n.max(t)));
    }
    if let Ok(Some(t)) = newest_tree_mtime(path) {
        latest = Some(latest.map_or(t, |n| n.max(t)));
    }
    latest
}

fn head_commit_time(path: &Path) -> Option<SystemTime> {
    let out = git(path, &["log", "-1", "--format=%ct"]).ok()?;
    let secs: u64 = out.trim().parse().ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

fn index_file(path: &Path) -> Option<PathBuf> {
    #[cfg(test)]
    INDEX_RESOLVE_COUNT.with(|slot| slot.set(slot.get().saturating_add(1)));
    let raw = git(path, &["rev-parse", "--git-path", "index"]).ok()?;
    let index = PathBuf::from(raw.trim());
    Some(if index.is_absolute() {
        index
    } else {
        path.join(index)
    })
}

#[derive(Clone, Copy)]
enum IndexSource<'a> {
    Lookup,
    Ready(Option<&'a Path>),
}

fn index_mtime_at(index: Option<&Path>) -> Option<SystemTime> {
    std::fs::metadata(index?).and_then(|m| m.modified()).ok()
}

/// `git status` refreshes the index. That must not bump last-used.
fn restore_index_mtime_at(index: Option<&Path>, prev: SystemTime) {
    let Some(index) = index else {
        return;
    };
    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(index) {
        let _ = file.set_modified(prev);
    }
}

/// Finished walk of file mtimes. `Err` if `read_dir` failed or the
/// budget ran out with directories still queued. `DirEntry::metadata`
/// (lstat); do not switch to `fs::metadata`.
fn newest_tree_mtime(root: &Path) -> Result<Option<SystemTime>, ()> {
    let mut newest: Option<SystemTime> = None;
    let mut remaining = LAST_USED_WALK_LIMIT;
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root.to_path_buf());
    while remaining > 0 {
        let Some(dir) = queue.pop_front() else {
            return Ok(newest);
        };
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return Err(());
        };
        for entry in rd.flatten() {
            if remaining == 0 {
                return Err(());
            }
            remaining -= 1;
            let p = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == ".git" || is_age_cache_dir_name(&name) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                queue.push_back(p);
                continue;
            }
            if let Ok(t) = meta.modified() {
                newest = Some(newest.map_or(t, |n| n.max(t)));
            }
        }
    }
    if !queue.is_empty() {
        return Err(());
    }
    Ok(newest)
}

fn is_age_cache_dir_name(name: &str) -> bool {
    CACHE_DIR_NAMES.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// First path component matches [`CACHE_DIR_NAMES`] by name. No `CACHEDIR.TAG`.
/// Porcelain often lists only `!! target/`, not `!! target/.env`.
/// Cache walk matches deny globs only (full path and basename). It does
/// not apply dest-deny hardlink / incomplete-nlink fail-closed, and it
/// does not follow directory symlinks out of the cache tree.
fn cache_tree_has_denied_name(root: &Path, rel: &Path, policy: &DenyPolicy) -> bool {
    if cache_path_denied_glob(policy, rel) {
        return true;
    }
    let Some(std::path::Component::Normal(name)) = rel.components().next() else {
        return false;
    };
    let start = root.join(name);
    let mut remaining = LAST_USED_WALK_LIMIT;
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(start);
    while remaining > 0 {
        let Some(dir) = queue.pop_front() else {
            return false;
        };
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => return true,
        };
        for entry in rd.flatten() {
            if remaining == 0 {
                return true;
            }
            remaining -= 1;
            let p = entry.path();
            if cache_path_denied_glob(policy, &p) {
                return true;
            }
            let is_real_dir = match entry.file_type() {
                Ok(ft) => ft.is_dir(),
                Err(_) => match std::fs::symlink_metadata(&p) {
                    Ok(meta) => meta.file_type().is_dir(),
                    Err(_) => return true,
                },
            };
            if is_real_dir {
                queue.push_back(p);
            }
        }
    }
    !queue.is_empty()
}

fn cache_path_denied_glob(policy: &DenyPolicy, path: &Path) -> bool {
    let full = path.to_string_lossy().replace('\\', "/");
    if path_is_denied_glob(policy.globs(), &full) {
        return true;
    }
    path.file_name()
        .is_some_and(|base| path_is_denied_glob(policy.globs(), &base.to_string_lossy()))
}

fn is_under_known_cache(root: &Path, file: &Path) -> bool {
    let Ok(rel) = file.strip_prefix(root) else {
        return false;
    };
    let Some(std::path::Component::Normal(name)) = rel.components().next() else {
        return false;
    };
    is_age_cache_dir_name(&name.to_string_lossy())
}

/// Unique-work is `git status --porcelain=v1 -uall --ignored`. Git CLI, not gix.
/// Porcelain `??` / `!!` under a first-component cache dir name is not unique
/// work unless a deny-glob name exists in that tree (git often lists only
/// `!! target/`, not `!! target/.env`). Other XY statuses under those names
/// are DirtyWork (tracked dirty cache paths).
fn unique_work_reason(path: &Path, policy: &DenyPolicy) -> Option<KeepReason> {
    unique_work_from(path, policy, IndexSource::Lookup)
}

fn unique_work_from(
    path: &Path,
    policy: &DenyPolicy,
    source: IndexSource<'_>,
) -> Option<KeepReason> {
    let owned = match source {
        IndexSource::Lookup => index_file(path),
        IndexSource::Ready(_) => None,
    };
    let index = match source {
        IndexSource::Ready(index) => index,
        IndexSource::Lookup => owned.as_deref(),
    };
    let index_before = index_mtime_at(index);
    let out = match git(
        path,
        &[
            "-c",
            "status.showUntrackedFiles=all",
            "status",
            "--porcelain=v1",
            "-uall",
            "--ignored",
        ],
    ) {
        Ok(s) => s,
        Err(_) => return Some(KeepReason::StatusUnreadable),
    };
    if let Some(prev) = index_before {
        restore_index_mtime_at(index, prev);
    }
    let mut has_unique = false;
    for line in out.lines() {
        if line.is_empty() {
            continue;
        }
        let rel = porcelain_path(line);
        if line.starts_with("??") || line.starts_with("!!") {
            if is_under_known_cache(path, &path.join(&rel)) {
                if cache_tree_has_denied_name(path, &rel, policy) {
                    has_unique = true;
                }
                continue;
            }
            has_unique = true;
        } else {
            return Some(KeepReason::DirtyWork);
        }
    }
    // Git omits unreadable ignored dirs from porcelain. Walk them anyway.
    if !has_unique {
        for name in CACHE_DIR_NAMES {
            if !path.join(name).is_dir() {
                continue;
            }
            if cache_tree_has_denied_name(path, Path::new(name), policy) {
                has_unique = true;
                break;
            }
        }
    }
    if has_unique {
        Some(KeepReason::UniqueUntracked)
    } else {
        None
    }
}

fn porcelain_path(line: &str) -> PathBuf {
    let rest = if line.len() >= 3 { &line[3..] } else { line };
    let rest = rest.trim();
    if let Some((_, dest)) = rest.split_once(" -> ") {
        PathBuf::from(dest.trim_matches('"'))
    } else {
        PathBuf::from(rest.trim_matches('"'))
    }
}

fn save_unique_commits(path: &Path, prefix: &str) -> Result<Vec<String>, GcError> {
    let reflog = reflog_text(path)?;
    let reachable = reachable_branch_commits(path)?;
    save_reflog_shas(path, prefix, &reflog, &reachable)
}

fn reclaim_with_saved_refs(
    repo: &Path,
    tree: &Path,
    prefix: &str,
    policy: &DenyPolicy,
    reachable_cache: &mut Option<Result<HashSet<String>, ()>>,
) -> Result<GcDecision, GcError> {
    let reflog = match reflog_text(tree) {
        Ok(text) => text,
        Err(_) => {
            return Ok(GcDecision::Keep {
                reason: KeepReason::StatusUnreadable,
            });
        }
    };
    let saved = match reachable_cache
        .get_or_insert_with(|| reachable_branch_commits(repo).map_err(|_| ()))
    {
        Ok(set) => match save_reflog_shas(tree, prefix, &reflog, set) {
            Ok(saved) => saved,
            Err(_) => {
                return Ok(GcDecision::Keep {
                    reason: KeepReason::StatusUnreadable,
                });
            }
        },
        Err(()) => {
            return Ok(GcDecision::Keep {
                reason: KeepReason::StatusUnreadable,
            });
        }
    };
    take_if_still_clean(repo, tree, saved, false, true, policy)
}

fn reflog_text(path: &Path) -> Result<String, GcError> {
    git(path, &["reflog", "--format=%H"]).map_err(|e| match e {
        GcError::Git { detail, .. } => GcError::Git {
            op: "reflog".into(),
            detail,
        },
        other => other,
    })
}

/// Commits on local or remote-tracking branches.
/// Not `--all`: tags and backup refs are outside `branch -a`.
fn reachable_branch_commits(path: &Path) -> Result<HashSet<String>, GcError> {
    let out = git(path, &["rev-list", "--branches", "--remotes"])?;
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|sha| sha.len() >= 7)
        .map(str::to_owned)
        .collect())
}

fn save_reflog_shas(
    path: &Path,
    prefix: &str,
    reflog: &str,
    reachable: &HashSet<String>,
) -> Result<Vec<String>, GcError> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "worktree".into());
    let name = sanitize_ref_component(&name);
    let prefix = prefix.trim_end_matches('/');
    let mut saved = Vec::new();
    let mut seen = HashSet::new();
    for sha in reflog.lines() {
        let sha = sha.trim();
        if sha.len() < 7 || !seen.insert(sha.to_owned()) {
            continue;
        }
        if reachable.contains(sha) {
            continue;
        }
        let refname = format!("{prefix}/{name}/{sha}");
        git(path, &["update-ref", &refname, sha]).map_err(|e| match e {
            GcError::Git { detail, .. } => GcError::Git {
                op: "update-ref".into(),
                detail,
            },
            other => other,
        })?;
        saved.push(refname);
    }
    Ok(saved)
}

fn sanitize_ref_component(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let s = s.trim_matches('-').to_owned();
    if s.is_empty() { "worktree".into() } else { s }
}

fn git_common_dir(path: &Path) -> Result<PathBuf, GcError> {
    let raw = git(path, &["rev-parse", "--git-common-dir"])?;
    let p = PathBuf::from(raw.trim());
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(path.join(p))
    }
}

/// `$repo/.git` -> `$repo`. Bare or `--separate-git-dir` store -> the git dir.
fn repo_cwd_from_common_dir(common: &Path) -> PathBuf {
    match common.file_name() {
        Some(name) if name == ".git" => common.parent().unwrap_or(common).to_path_buf(),
        _ => common.to_path_buf(),
    }
}

fn registry_unreadable(err: GcError) -> GcError {
    match err {
        GcError::Git { detail, .. } => GcError::RegistryUnreadable(detail),
        other => other,
    }
}

/// Drop a tree that was clean before the reflog walk.
///
/// `git worktree remove --force` deletes files that appeared after that
/// snapshot, and it removes a tree a process has entered. Status and
/// live cwd are read again immediately before the remove.
fn take_if_still_clean(
    repo: &Path,
    tree: &Path,
    saved: Vec<String>,
    unlock: bool,
    registered: bool,
    policy: &DenyPolicy,
) -> Result<GcDecision, GcError> {
    fire_before_remove(tree);
    if let Some(reason) = unique_work_reason(tree, policy) {
        return Ok(GcDecision::Keep { reason });
    }
    if worktree_has_live_cwd(tree) {
        return Ok(GcDecision::Keep {
            reason: KeepReason::LiveCwd,
        });
    }
    if registered {
        remove_worktree(repo, tree, unlock)?;
    } else {
        std::fs::remove_dir_all(tree).map_err(|e| GcError::Git {
            op: "leftover rm".into(),
            detail: e.to_string(),
        })?;
    }
    Ok(GcDecision::Reclaim { saved_refs: saved })
}

#[cfg(test)]
thread_local! {
    static BEFORE_REMOVE: std::cell::Cell<Option<fn(&Path)>> = const { std::cell::Cell::new(None) };
    static CWD_PROBE_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static INDEX_RESOLVE_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(all(test, unix))]
thread_local! {
    static LIVE_SLEEPER: std::cell::RefCell<Option<std::process::Child>> =
        const { std::cell::RefCell::new(None) };
}

fn fire_before_remove(path: &Path) {
    #[cfg(test)]
    if let Some(hook) = BEFORE_REMOVE.with(|slot| slot.replace(None)) {
        hook(path);
    }
    #[cfg(not(test))]
    let _ = path;
}

fn remove_worktree(repo: &Path, tree: &Path, unlock: bool) -> Result<(), GcError> {
    let path_s = tree
        .to_str()
        .ok_or_else(|| GcError::Git {
            op: "worktree remove".into(),
            detail: "non-utf8 path".into(),
        })?
        .to_owned();
    let args: Vec<&str> = if unlock {
        vec!["worktree", "remove", "--force", "--force", &path_s]
    } else {
        vec!["worktree", "remove", "--force", &path_s]
    };
    match git(repo, &args) {
        Ok(_) => Ok(()),
        Err(_) => {
            git(tree, &args)?;
            Ok(())
        }
    }
}

/// Host keys restored after `env_clear`. No `GIT_*` except the two we set.
const GIT_FORWARD_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "USERPROFILE",
    "COMSPEC",
    "PATHEXT",
    "HOMEDRIVE",
    "HOMEPATH",
];

fn git(cwd: &Path, args: &[&str]) -> Result<String, GcError> {
    let mut cmd = Command::new("git");
    cmd.env_clear();
    for key in GIT_FORWARD_ENV {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    let out = cmd
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| GcError::Git {
            op: args.join(" "),
            detail: e.to_string(),
        })?;
    if !out.status.success() {
        return Err(GcError::Git {
            op: args.join(" "),
            detail: String::from_utf8_lossy(&out.stderr).trim().into(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parse_primary_and_locked() {
        let text = "worktree /repo\nHEAD abc\nbranch refs/heads/main\n\nworktree /repo/.wt\nHEAD def\nlocked\n";
        let trees = parse_worktree_list(text);
        assert_eq!(trees.len(), 2);
        assert!(!trees[0].locked);
        assert!(trees[1].locked);
    }

    #[test]
    fn recheck_keeps_a_file_planted_after_the_clean_snapshot() {
        let dir = tempfile::tempdir().expect("tmp");
        let repo = dir.path().join("origin");
        std::fs::create_dir(&repo).expect("origin");
        let git = |cwd: &Path, args: &[&str]| {
            super::git(cwd, args).unwrap_or_else(|err| panic!("{args:?}: {err:?}"));
        };
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.email", "dev@example.com"]);
        git(&repo, &["config", "user.name", "dev"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join("README"), b"x").expect("readme");
        git(&repo, &["add", "README"]);
        git(&repo, &["commit", "-m", "init"]);
        let wt = dir.path().join("wt");
        git(
            &repo,
            &["worktree", "add", wt.to_str().expect("utf8"), "-b", "wt"],
        );
        BEFORE_REMOVE.with(|slot| {
            slot.set(Some(|path| {
                std::fs::write(path.join("late.txt"), b"late").expect("plant");
            }));
        });
        let decision =
            super::take_if_still_clean(&repo, &wt, Vec::new(), false, true, &DenyPolicy::default())
                .expect("take");
        match decision {
            GcDecision::Keep {
                reason: KeepReason::UniqueUntracked,
            } => {}
            other => panic!("expected unique untracked, got {other:?}"),
        }
        assert!(wt.join("late.txt").is_file(), "late file must survive");
    }

    // fn(&Path) cannot return the child. reap_live_sleeper waits it.
    #[cfg(unix)]
    #[allow(clippy::zombie_processes)]
    fn hold_live_cwd(path: &Path) {
        let child = Command::new("/bin/sleep")
            .arg("60")
            .current_dir(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sleep");
        LIVE_SLEEPER.with(|slot| *slot.borrow_mut() = Some(child));
    }

    #[cfg(unix)]
    fn reap_live_sleeper() {
        let child = LIVE_SLEEPER.with(|slot| slot.borrow_mut().take());
        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[cfg(unix)]
    struct KillLiveSleeper;

    #[cfg(unix)]
    impl Drop for KillLiveSleeper {
        fn drop(&mut self) {
            reap_live_sleeper();
        }
    }

    #[cfg(unix)]
    #[test]
    fn recheck_keeps_a_live_cwd_that_starts_before_remove() {
        let _kill = KillLiveSleeper;
        reap_live_sleeper();
        let dir = tempfile::tempdir().expect("tmp");
        let repo = dir.path().join("origin");
        std::fs::create_dir(&repo).expect("origin");
        let git = |cwd: &Path, args: &[&str]| {
            super::git(cwd, args).unwrap_or_else(|err| panic!("{args:?}: {err:?}"));
        };
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.email", "dev@example.com"]);
        git(&repo, &["config", "user.name", "dev"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join("README"), b"x").expect("readme");
        git(&repo, &["add", "README"]);
        git(&repo, &["commit", "-m", "init"]);
        let wt = dir.path().join("wt");
        git(
            &repo,
            &["worktree", "add", wt.to_str().expect("utf8"), "-b", "wt"],
        );
        BEFORE_REMOVE.with(|slot| slot.set(Some(hold_live_cwd)));
        let decision =
            super::take_if_still_clean(&repo, &wt, Vec::new(), false, true, &DenyPolicy::default())
                .expect("take");
        match decision {
            GcDecision::Keep {
                reason: KeepReason::LiveCwd,
            } => {}
            other => panic!("a cwd that starts before remove must stay, got {other:?}"),
        }
        assert!(wt.exists(), "live cwd must not be removed");
    }

    #[test]
    fn parse_max_age_rejects_a_duration_the_clock_cannot_hold() {
        match parse_max_age("999999999999999d") {
            Err(GcError::InvalidDuration(msg)) => {
                assert!(
                    msg.contains("does not fit on the clock"),
                    "huge duration must name the clock: {msg}"
                );
            }
            other => panic!("huge duration must stay InvalidDuration, got {other:?}"),
        }
    }

    #[test]
    fn parse_max_age_rejects_bare_number() {
        match parse_max_age("7") {
            Err(GcError::InvalidDuration(msg)) => {
                assert!(msg.contains("30s"), "bare number must hint 30s: {msg}");
            }
            other => panic!("bare number must stay InvalidDuration, got {other:?}"),
        }
    }

    #[test]
    fn reachable_branch_commits_git_failure_stays_an_error() {
        let dir = tempfile::tempdir().expect("tmp");
        match reachable_branch_commits(dir.path()) {
            Err(GcError::Git { op, .. }) => {
                assert!(
                    op.contains("rev-list"),
                    "a failed reachability check must stay a git error: {op}"
                );
            }
            other => {
                panic!("git failure must be Err so commits are not skipped as reachable: {other:?}")
            }
        }
    }

    #[test]
    fn age_gc_probes_other_process_cwds_once() {
        CWD_PROBE_COUNT.with(|slot| slot.set(0));
        let dir = tempfile::tempdir().expect("tmp");
        let repo = dir.path().join("origin");
        std::fs::create_dir(&repo).expect("origin");
        let git = |cwd: &Path, args: &[&str]| {
            super::git(cwd, args).unwrap_or_else(|err| panic!("{args:?}: {err:?}"));
        };
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.email", "dev@example.com"]);
        git(&repo, &["config", "user.name", "dev"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join("README"), b"x").expect("readme");
        git(&repo, &["add", "README"]);
        git(&repo, &["commit", "-m", "init"]);
        for name in ["wt-a", "wt-b"] {
            let wt = dir.path().join(name);
            git(
                &repo,
                &["worktree", "add", wt.to_str().expect("utf8"), "-b", name],
            );
        }
        let cfg = GcConfig {
            leftover_dir: repo.join(".workpen-worktrees"),
            saved_ref_prefix: "refs/workpen/reclaimed".into(),
            max_age: Duration::from_secs(0),
            dry_run: true,
            now: SystemTime::now() + Duration::from_secs(10),
        };
        let rows = run_gc_with_policy(&repo, &cfg, &DenyPolicy::default()).expect("gc");
        assert!(rows.len() >= 2, "two linked trees: {rows:?}");
        let probes = CWD_PROBE_COUNT.with(|slot| slot.get());
        assert_eq!(
            probes, 1,
            "one cwd probe for every linked tree, got {probes}"
        );
    }

    #[test]
    fn age_gc_skips_cwd_probe_when_nothing_is_linked() {
        CWD_PROBE_COUNT.with(|slot| slot.set(0));
        let dir = tempfile::tempdir().expect("tmp");
        let repo = dir.path().join("origin");
        std::fs::create_dir(&repo).expect("origin");
        let git = |cwd: &Path, args: &[&str]| {
            super::git(cwd, args).unwrap_or_else(|err| panic!("{args:?}: {err:?}"));
        };
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.email", "dev@example.com"]);
        git(&repo, &["config", "user.name", "dev"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join("README"), b"x").expect("readme");
        git(&repo, &["add", "README"]);
        git(&repo, &["commit", "-m", "init"]);
        let cfg = GcConfig {
            leftover_dir: repo.join(".workpen-worktrees"),
            saved_ref_prefix: "refs/workpen/reclaimed".into(),
            max_age: Duration::from_secs(0),
            dry_run: true,
            now: SystemTime::now() + Duration::from_secs(10),
        };
        let rows = run_gc_with_policy(&repo, &cfg, &DenyPolicy::default()).expect("gc");
        assert!(rows.is_empty(), "primary is not a candidate: {rows:?}");
        let probes = CWD_PROBE_COUNT.with(|slot| slot.get());
        assert_eq!(probes, 0, "no linked tree, no cwd probe, got {probes}");
    }

    #[test]
    fn classify_age_resolves_index_once() {
        INDEX_RESOLVE_COUNT.with(|slot| slot.set(0));
        let dir = tempfile::tempdir().expect("tmp");
        let repo = dir.path().join("origin");
        std::fs::create_dir(&repo).expect("origin");
        let git = |cwd: &Path, args: &[&str]| {
            super::git(cwd, args).unwrap_or_else(|err| panic!("{args:?}: {err:?}"));
        };
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.email", "dev@example.com"]);
        git(&repo, &["config", "user.name", "dev"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join("README"), b"x").expect("readme");
        git(&repo, &["add", "README"]);
        git(&repo, &["commit", "-m", "init"]);
        let decision = classify_for_age_gc_with_policy(
            &repo,
            false,
            Duration::ZERO,
            SystemTime::now() + Duration::from_secs(3600),
            &DenyPolicy::default(),
        );
        assert!(
            matches!(decision, GcDecision::Reclaim { .. }),
            "old clean repo must reclaim, got {decision:?}"
        );
        let resolves = INDEX_RESOLVE_COUNT.with(|slot| slot.get());
        assert_eq!(
            resolves, 1,
            "one index resolve per age check, got {resolves}"
        );
    }

    #[test]
    fn probe_failure_is_live_when_current_dir_is_elsewhere() {
        let tree = tempfile::tempdir().expect("tree");
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        assert!(
            worktree_has_live_cwd_from(tree.path(), Some(elsewhere.path()), Err(())),
            "probe failure must keep the tree"
        );
        assert!(
            !worktree_has_live_cwd_from(tree.path(), Some(elsewhere.path()), Ok(&[])),
            "successful empty scan is not live"
        );
    }

    #[test]
    fn git_forward_env_has_no_git_keys() {
        for key in GIT_FORWARD_ENV {
            assert!(
                !key.starts_with("GIT_"),
                "forward list must not include {key}"
            );
        }
        assert!(GIT_FORWARD_ENV.contains(&"PATH"));
        assert!(GIT_FORWARD_ENV.contains(&"HOME") || GIT_FORWARD_ENV.contains(&"USERPROFILE"));
    }
}
