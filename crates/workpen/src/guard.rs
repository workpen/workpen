//! Workspace PathGuard. Separate from dest-deny. Does not classify secrets.

use std::path::{Component, Path, PathBuf};

/// Allowed roots. Workspace plus optional extra roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGuard {
    workspace: PathBuf,
    roots: Vec<PathBuf>,
}

/// Why PathGuard rejected a path. Hosts branch on this; do not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathGuardKind {
    /// Resolved path is outside every allowed root (`..` or absolute escape).
    Escape,
    /// A symlink in the chain resolved outside the allowed roots.
    SymlinkVault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGuardDeny {
    pub kind: PathGuardKind,
    pub path: PathBuf,
    pub display: String,
}

impl PathGuardDeny {
    pub fn message(&self) -> String {
        match self.kind {
            PathGuardKind::Escape => {
                format!("path escapes workspace: {}", self.display)
            }
            PathGuardKind::SymlinkVault => {
                format!(
                    "path is a symlink that leaves the workspace: {}",
                    self.display
                )
            }
        }
    }
}

impl std::fmt::Display for PathGuardDeny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PathGuardError {
    #[error("{0}")]
    Denied(PathGuardDeny),
    #[error("path guard root is not usable: {0}")]
    Root(String),
}

impl PathGuard {
    pub fn new(workspace: impl AsRef<Path>) -> Result<Self, PathGuardError> {
        Self::with_extra_roots(workspace, std::iter::empty::<PathBuf>())
    }

    pub fn with_extra_roots(
        workspace: impl AsRef<Path>,
        extra: impl IntoIterator<Item = impl AsRef<Path>>,
    ) -> Result<Self, PathGuardError> {
        let workspace = canonicalize_root(workspace.as_ref())?;
        let mut roots = vec![workspace.clone()];
        for extra in extra {
            let root = canonicalize_root(extra.as_ref())?;
            if !roots.iter().any(|r| r == &root) {
                roots.push(root);
            }
        }
        Ok(Self { workspace, roots })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Classify one dest. Escape vs symlink vault only. Does not dest-deny.
    pub fn classify(&self, path: &Path) -> Option<PathGuardKind> {
        match self.check(path) {
            Ok(_) => None,
            Err(PathGuardError::Denied(d)) => Some(d.kind),
            Err(PathGuardError::Root(_)) => Some(PathGuardKind::Escape),
        }
    }

    pub fn check(&self, path: &Path) -> Result<PathBuf, PathGuardError> {
        let start = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.workspace.join(path)
        };
        walk_guarded(&start, &self.roots).map_err(|kind| {
            PathGuardError::Denied(PathGuardDeny {
                kind,
                path: path.to_path_buf(),
                display: path.display().to_string(),
            })
        })
    }
}

/// Refuse if any host-extracted dest leaves the workspace.
pub fn check_dests(guard: &PathGuard, dests: &[impl AsRef<Path>]) -> Result<(), PathGuardError> {
    for dest in dests {
        guard.check(dest.as_ref())?;
    }
    Ok(())
}

fn canonicalize_root(path: &Path) -> Result<PathBuf, PathGuardError> {
    std::fs::canonicalize(path)
        .map_err(|e| PathGuardError::Root(format!("{} ({e})", path.display())))
}

fn walk_guarded(start: &Path, roots: &[PathBuf]) -> Result<PathBuf, PathGuardKind> {
    let lexical = normalize_lexical(start);
    if let Ok(canon) = std::fs::canonicalize(&lexical) {
        if inside_any_root(&canon, roots) {
            return Ok(canon);
        }
        if inside_any_root(&lexical, roots) {
            return Err(PathGuardKind::SymlinkVault);
        }
        return Err(PathGuardKind::Escape);
    }

    let prefix = longest_existing_prefix(&lexical);
    if prefix.as_os_str().is_empty() {
        return if inside_any_root(&lexical, roots) {
            Ok(lexical)
        } else {
            Err(PathGuardKind::Escape)
        };
    }
    let prefix_canon = std::fs::canonicalize(&prefix).map_err(|_| PathGuardKind::Escape)?;
    let rest = lexical.strip_prefix(&prefix).unwrap_or(Path::new(""));
    let resolved = prefix_canon.join(rest);
    if inside_any_root(&resolved, roots) {
        return Ok(resolved);
    }
    if chain_has_symlink(&prefix) && inside_any_root(&prefix, roots) {
        return Err(PathGuardKind::SymlinkVault);
    }
    Err(PathGuardKind::Escape)
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Normal(name) => out.push(name),
        }
    }
    out
}

fn longest_existing_prefix(path: &Path) -> PathBuf {
    let mut last = PathBuf::new();
    let mut cur = PathBuf::new();
    for component in path.components() {
        cur.push(component);
        if cur.exists() {
            last.clone_from(&cur);
        } else {
            break;
        }
    }
    last
}

fn chain_has_symlink(path: &Path) -> bool {
    let mut cur = PathBuf::new();
    for component in path.components() {
        cur.push(component);
        if let Ok(meta) = std::fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                return true;
            }
        }
    }
    false
}

fn inside_any_root(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| path == root || path.starts_with(root))
}
