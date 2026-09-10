//! Fail-closed leftover worktree age GC. Feature-gated (`gc`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

/// Age and home-dir policy for leftover worktrees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcPolicy {
    max_age: Duration,
}

impl GcPolicy {
    pub fn new(max_age: Duration) -> Self {
        Self { max_age }
    }

    pub fn max_age(&self) -> Duration {
        self.max_age
    }
}

/// Why a worktree was kept. Hosts branch on this; do not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcKeepReason {
    Primary,
    Dirty,
    Unique,
    LiveCwd,
    Locked,
    Unreadable,
    Young,
    Home,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcDecision {
    Remove,
    Keep(GcKeepReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worktree {
    pub path: PathBuf,
    pub locked: bool,
    pub primary: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum GcError {
    #[error("refuse to treat home as a git workspace: {0}")]
    Home(String),
    #[error("git status unreadable (fail closed): {0}")]
    Unreadable(String),
    #[error("git failed: {0}")]
    Git(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    pub removed: Vec<PathBuf>,
    pub kept: Vec<(PathBuf, GcKeepReason)>,
}

pub fn list_worktrees(repo: &Path) -> Result<Vec<Worktree>, GcError> {
    refuse_home(repo)?;
    let out = git(repo, &["worktree", "list", "--porcelain"])?;
    parse_worktree_list(&out)
}

pub fn decide(
    tree: &Worktree,
    policy: &GcPolicy,
    now: SystemTime,
    cwd: &Path,
) -> Result<GcDecision, GcError> {
    if tree.primary {
        return Ok(GcDecision::Keep(GcKeepReason::Primary));
    }
    if is_home(&tree.path) {
        return Ok(GcDecision::Keep(GcKeepReason::Home));
    }
    if tree.locked {
        return Ok(GcDecision::Keep(GcKeepReason::Locked));
    }
    if cwd_inside(cwd, &tree.path) {
        return Ok(GcDecision::Keep(GcKeepReason::LiveCwd));
    }
    match worktree_age(&tree.path, now) {
        Ok(age) if age < policy.max_age => return Ok(GcDecision::Keep(GcKeepReason::Young)),
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match porcelain_status(&tree.path) {
        Ok(status) if status.has_tracked_changes => Ok(GcDecision::Keep(GcKeepReason::Dirty)),
        Ok(status) if status.has_untracked => Ok(GcDecision::Keep(GcKeepReason::Unique)),
        Ok(_) => Ok(GcDecision::Remove),
        Err(e) => Err(e),
    }
}

pub fn gc_leftovers(
    repo: &Path,
    policy: &GcPolicy,
    now: SystemTime,
    cwd: &Path,
) -> Result<GcReport, GcError> {
    let trees = list_worktrees(repo)?;
    let mut report = GcReport {
        removed: Vec::new(),
        kept: Vec::new(),
    };
    for tree in trees {
        match decide(&tree, policy, now, cwd) {
            Ok(GcDecision::Remove) => {
                remove_worktree(repo, &tree.path)?;
                report.removed.push(tree.path);
            }
            Ok(GcDecision::Keep(reason)) => report.kept.push((tree.path, reason)),
            Err(GcError::Unreadable(_)) => {
                report.kept.push((tree.path, GcKeepReason::Unreadable));
            }
            Err(e) => return Err(e),
        }
    }
    let _ = git(repo, &["worktree", "prune"]);
    Ok(report)
}

fn refuse_home(repo: &Path) -> Result<(), GcError> {
    let top = git(repo, &["rev-parse", "--show-toplevel"])?;
    let top = PathBuf::from(top.trim());
    if is_home(&top) {
        return Err(GcError::Home(top.display().to_string()));
    }
    Ok(())
}

fn is_home(path: &Path) -> bool {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .and_then(|h| std::fs::canonicalize(h).ok())
        .and_then(|home| std::fs::canonicalize(path).ok().map(|p| p == home))
        .unwrap_or(false)
}

fn cwd_inside(cwd: &Path, tree: &Path) -> bool {
    let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let tree = std::fs::canonicalize(tree).unwrap_or_else(|_| tree.to_path_buf());
    cwd == tree || cwd.starts_with(&tree)
}

fn worktree_age(path: &Path, now: SystemTime) -> Result<Duration, GcError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| GcError::Unreadable(format!("{} ({e})", path.display())))?;
    let modified = meta
        .modified()
        .map_err(|e| GcError::Unreadable(format!("{} ({e})", path.display())))?;
    Ok(now.duration_since(modified).unwrap_or(Duration::ZERO))
}

struct Status {
    has_tracked_changes: bool,
    has_untracked: bool,
}

fn porcelain_status(tree: &Path) -> Result<Status, GcError> {
    let out = git(tree, &["status", "--porcelain"]).map_err(|e| match e {
        GcError::Git(msg) => GcError::Unreadable(msg),
        other => other,
    })?;
    let mut status = Status {
        has_tracked_changes: false,
        has_untracked: false,
    };
    for line in out.lines() {
        if line.starts_with("??") {
            status.has_untracked = true;
        } else if !line.is_empty() {
            status.has_tracked_changes = true;
        }
    }
    Ok(status)
}

fn remove_worktree(repo: &Path, tree: &Path) -> Result<(), GcError> {
    git(
        repo,
        &[
            "worktree",
            "remove",
            tree.to_str()
                .ok_or_else(|| GcError::Git("non-utf8 path".into()))?,
        ],
    )?;
    Ok(())
}

fn git(cwd: &Path, args: &[&str]) -> Result<String, GcError> {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| GcError::Git(e.to_string()))?;
    if !out.status.success() {
        return Err(GcError::Git(
            String::from_utf8_lossy(&out.stderr).trim().into(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn parse_worktree_list(text: &str) -> Result<Vec<Worktree>, GcError> {
    let mut trees = Vec::new();
    let mut path: Option<PathBuf> = None;
    let mut locked = false;
    let mut first = true;
    let flush = |trees: &mut Vec<Worktree>,
                 path: &mut Option<PathBuf>,
                 locked: &mut bool,
                 first: &mut bool| {
        if let Some(p) = path.take() {
            trees.push(Worktree {
                path: p,
                locked: *locked,
                primary: *first,
            });
            *locked = false;
            *first = false;
        }
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("worktree ") {
            flush(&mut trees, &mut path, &mut locked, &mut first);
            path = Some(PathBuf::from(rest));
        } else if line == "locked" || line.starts_with("locked ") {
            locked = true;
        }
    }
    flush(&mut trees, &mut path, &mut locked, &mut first);
    Ok(trees)
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parse_primary_and_locked() {
        let text = "worktree /repo\nHEAD abc\nbranch refs/heads/main\n\nworktree /repo/.wt\nHEAD def\nlocked\n";
        let trees = parse_worktree_list(text).expect("parse");
        assert_eq!(trees.len(), 2);
        assert!(trees[0].primary);
        assert!(!trees[0].locked);
        assert!(!trees[1].primary);
        assert!(trees[1].locked);
    }
}
