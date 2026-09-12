//! Workspace PathGuard. Separate from dest-deny. Does not classify secrets.

use std::io;
use std::path::{Component, Path, PathBuf};

/// Policy for absolute dests. Extra roots apply to absolute inputs only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbsolutePathPolicy {
    /// Reject every absolute path (builder default).
    Reject,
    /// Allow absolute paths that stay inside the primary workspace.
    AllowIfContained,
    /// Allow absolute paths inside the workspace or these extra roots.
    AllowAdditionalRoots(Vec<PathBuf>),
}

/// Allowed roots plus an absolute-path policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGuard {
    root: PathBuf,
    workspace: PathBuf,
    roots: Vec<PathBuf>,
    policy: AbsolutePathPolicy,
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
    #[error("path must not be empty")]
    EmptyPath,
    #[error("absolute paths are not allowed: {0}")]
    AbsolutePath(String),
    #[error("{0}")]
    Denied(PathGuardDeny),
    #[error("path guard root is not usable: {0}")]
    Root(String),
    #[error("failed to canonicalize path: {path}: {source}")]
    Canonicalize {
        path: String,
        #[source]
        source: io::Error,
    },
}

/// Extra-root resolution. Separate from PathGuardError so hosts can match variants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtraRootError {
    #[error("extra write dir must not be empty")]
    Empty,
    #[error("extra write dir does not exist: {path}")]
    Missing { path: String },
    #[error("extra write dir is not a directory: {path}")]
    NotDirectory { path: String },
    #[error("failed to canonicalize extra write dir {path}: {detail}")]
    Canonicalize { path: String, detail: String },
    #[error(
        "extra write dir {requested} escaped after canonicalize to {resolved} (not an explicit extra)"
    )]
    EscapedToRoot { requested: String, resolved: String },
}

/// Builder default policy is [`AbsolutePathPolicy::Reject`].
pub struct PathGuardBuilder {
    root: PathBuf,
    policy: AbsolutePathPolicy,
}

impl PathGuard {
    pub fn new(
        workspace: impl AsRef<Path>,
        policy: AbsolutePathPolicy,
    ) -> Result<Self, PathGuardError> {
        let root = workspace.as_ref().to_path_buf();
        let workspace = canonicalize_root(&root)?;
        let extra = match &policy {
            AbsolutePathPolicy::AllowAdditionalRoots(extra) => extra.as_slice(),
            AbsolutePathPolicy::Reject | AbsolutePathPolicy::AllowIfContained => &[],
        };
        let mut roots = vec![workspace.clone()];
        for extra in extra {
            let extra = canonicalize_root(extra)?;
            if !roots.iter().any(|r| r == &extra) {
                roots.push(extra);
            }
        }
        Ok(Self {
            root,
            workspace,
            roots,
            policy,
        })
    }

    pub fn builder(root: impl Into<PathBuf>) -> PathGuardBuilder {
        PathGuardBuilder {
            root: root.into(),
            policy: AbsolutePathPolicy::Reject,
        }
    }

    pub fn with_extra_roots(
        workspace: impl AsRef<Path>,
        extra: impl IntoIterator<Item = impl AsRef<Path>>,
    ) -> Result<Self, PathGuardError> {
        let extra = extra
            .into_iter()
            .map(|p| p.as_ref().to_path_buf())
            .collect::<Vec<_>>();
        Self::new(workspace, AbsolutePathPolicy::AllowAdditionalRoots(extra))
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn canon_root(&self) -> &Path {
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
            Err(_) => Some(PathGuardKind::Escape),
        }
    }

    pub fn check(&self, path: &Path) -> Result<PathBuf, PathGuardError> {
        self.check_path(&path.to_string_lossy())
    }

    /// Content ops. Follows the final component.
    pub fn check_path(&self, path: &str) -> Result<PathBuf, PathGuardError> {
        self.check_inner(path, Follow::Final)
    }

    /// Unlink / rename. Follows the parent only; appends the leaf.
    pub fn check_path_entry(&self, path: &str) -> Result<PathBuf, PathGuardError> {
        self.check_inner(path, Follow::Parent)
    }

    fn check_inner(&self, path: &str, follow: Follow) -> Result<PathBuf, PathGuardError> {
        if is_blank_path(path) {
            return Err(PathGuardError::EmptyPath);
        }
        let raw = Path::new(path);
        if raw.is_absolute() {
            let roots = self.absolute_roots(path)?;
            return self.resolve(path, raw, &roots, follow);
        }
        if relative_escapes_primary(raw) {
            return Err(self.denied(path, PathGuardKind::Escape));
        }
        let joined = self.workspace.join(raw);
        self.resolve(path, &joined, std::slice::from_ref(&self.workspace), follow)
    }

    fn absolute_roots(&self, path: &str) -> Result<Vec<PathBuf>, PathGuardError> {
        match &self.policy {
            AbsolutePathPolicy::Reject => Err(PathGuardError::AbsolutePath(path.to_owned())),
            AbsolutePathPolicy::AllowIfContained => Ok(vec![self.workspace.clone()]),
            AbsolutePathPolicy::AllowAdditionalRoots(_) => Ok(self.roots.clone()),
        }
    }

    fn resolve(
        &self,
        display: &str,
        start: &Path,
        roots: &[PathBuf],
        follow: Follow,
    ) -> Result<PathBuf, PathGuardError> {
        match follow {
            Follow::Final => walk_guarded(start, roots).map_err(|kind| self.denied(display, kind)),
            Follow::Parent => {
                let leaf = start.file_name().map(PathBuf::from);
                let parent = start.parent().unwrap_or(Path::new("."));
                let parent = if parent.as_os_str().is_empty() {
                    self.workspace.clone()
                } else {
                    walk_guarded(parent, roots).map_err(|kind| self.denied(display, kind))?
                };
                Ok(match leaf {
                    Some(name) => parent.join(name),
                    None => parent,
                })
            }
        }
    }

    fn denied(&self, display: &str, kind: PathGuardKind) -> PathGuardError {
        PathGuardError::Denied(PathGuardDeny {
            kind,
            path: PathBuf::from(display),
            display: display.to_owned(),
        })
    }
}

impl PathGuardBuilder {
    pub fn allow_root(mut self, extra: impl Into<PathBuf>) -> Self {
        let extra = extra.into();
        self.policy = match self.policy {
            AbsolutePathPolicy::AllowAdditionalRoots(mut roots) => {
                if !roots.iter().any(|r| r == &extra) {
                    roots.push(extra);
                }
                AbsolutePathPolicy::AllowAdditionalRoots(roots)
            }
            AbsolutePathPolicy::Reject | AbsolutePathPolicy::AllowIfContained => {
                AbsolutePathPolicy::AllowAdditionalRoots(vec![extra])
            }
        };
        self
    }

    pub fn absolute_policy(mut self, policy: AbsolutePathPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn build(self) -> Result<PathGuard, PathGuardError> {
        PathGuard::new(self.root, self.policy)
    }
}

/// Refuse if any host-extracted dest leaves the workspace.
pub fn check_dests(guard: &PathGuard, dests: &[impl AsRef<Path>]) -> Result<(), PathGuardError> {
    for dest in dests {
        guard.check(dest.as_ref())?;
    }
    Ok(())
}

/// Resolve `--root` against `cwd`. Must exist and be a directory.
/// A relative `../ws` becomes the absolute workspace, not a PathGuard escape.
/// Implicit canonicalize to `/` or the host temp root is refused unless asked.
pub fn resolve_workspace_root(cwd: &Path, root: &str) -> Result<PathBuf, PathGuardError> {
    let requested = root.trim();
    if requested.is_empty() {
        return Err(PathGuardError::Root(
            "workspace root must not be empty".into(),
        ));
    }
    let raw = PathBuf::from(requested);
    let abs = if raw.is_absolute() {
        raw
    } else {
        cwd.join(raw)
    };
    if !abs.exists() {
        return Err(PathGuardError::Root(format!(
            "workspace root does not exist: {}",
            abs.display()
        )));
    }
    if !abs.is_dir() {
        return Err(PathGuardError::Root(format!(
            "workspace root is not a directory: {}",
            abs.display()
        )));
    }
    let canon = canonicalize_root(&abs)?;
    if is_filesystem_root(&canon) && !requested_is_explicit_root(requested) {
        return Err(PathGuardError::Root(format!(
            "workspace root {requested} escaped after canonicalize to {}",
            canon.display()
        )));
    }
    if is_host_temp_root(&canon) && !requested_is_explicit_temp(requested) {
        return Err(PathGuardError::Root(format!(
            "workspace root {requested} escaped after canonicalize to {}",
            canon.display()
        )));
    }
    Ok(canon)
}

/// Resolve one extra write dir against `cwd`. Fail closed on missing,
/// not-a-dir, canonicalize failure, or implicit escape to `/` or host temp
/// unless the caller named that root explicitly.
pub fn resolve_extra_root(cwd: &Path, extra: &str) -> Result<PathBuf, ExtraRootError> {
    let extra = extra.trim();
    if extra.is_empty() {
        return Err(ExtraRootError::Empty);
    }
    let raw = PathBuf::from(extra);
    let abs = if raw.is_absolute() {
        raw
    } else {
        cwd.join(raw)
    };
    if !abs.exists() {
        return Err(ExtraRootError::Missing {
            path: abs.display().to_string(),
        });
    }
    if !abs.is_dir() {
        return Err(ExtraRootError::NotDirectory {
            path: abs.display().to_string(),
        });
    }
    let canon = dunce::canonicalize(&abs).map_err(|e| ExtraRootError::Canonicalize {
        path: abs.display().to_string(),
        detail: e.to_string(),
    })?;
    if is_filesystem_root(&canon) && !requested_is_explicit_root(extra) {
        return Err(ExtraRootError::EscapedToRoot {
            requested: extra.to_owned(),
            resolved: canon.display().to_string(),
        });
    }
    if is_host_temp_root(&canon) && !requested_is_explicit_temp(extra) {
        return Err(ExtraRootError::EscapedToRoot {
            requested: extra.to_owned(),
            resolved: canon.display().to_string(),
        });
    }
    Ok(canon)
}

#[derive(Clone, Copy)]
enum Follow {
    Final,
    Parent,
}

fn is_blank_path(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_whitespace() || matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')
    })
}

fn relative_escapes_primary(path: &Path) -> bool {
    let mut depth: i32 = 0;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                if depth == 0 {
                    return true;
                }
                depth -= 1;
            }
        }
    }
    false
}

fn canonicalize_root(path: &Path) -> Result<PathBuf, PathGuardError> {
    dunce::canonicalize(path).map_err(|e| PathGuardError::Root(format!("{} ({e})", path.display())))
}

fn walk_guarded(start: &Path, roots: &[PathBuf]) -> Result<PathBuf, PathGuardKind> {
    let lexical = normalize_lexical(start);
    if let Ok(canon) = dunce::canonicalize(&lexical) {
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
    let prefix_canon = dunce::canonicalize(&prefix).map_err(|_| PathGuardKind::Escape)?;
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
        if let Ok(meta) = std::fs::symlink_metadata(&cur)
            && meta.file_type().is_symlink()
        {
            return true;
        }
    }
    false
}

fn inside_any_root(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| path == root || path.starts_with(root))
}

fn is_filesystem_root(path: &Path) -> bool {
    path.parent().is_none_or(|p| p.as_os_str().is_empty())
}

fn requested_is_explicit_root(requested: &str) -> bool {
    let t = requested.trim();
    t == "/" || t == "\\" || (t.len() == 3 && t.as_bytes()[1] == b':' && t.ends_with(['\\', '/']))
}

fn is_host_temp_root(path: &Path) -> bool {
    if is_well_known_temp_name(path) {
        return true;
    }
    let tmp = std::env::temp_dir();
    if path == tmp {
        return true;
    }
    dunce::canonicalize(&tmp).is_ok_and(|canon| path == canon)
}

fn is_well_known_temp_name(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let s = s.trim_end_matches(['/', '\\']);
    s.eq_ignore_ascii_case("/tmp")
        || s.eq_ignore_ascii_case("/private/tmp")
        || s.eq_ignore_ascii_case("/var/tmp")
        || s.eq_ignore_ascii_case("/private/var/tmp")
}

fn requested_is_explicit_temp(requested: &str) -> bool {
    let t = requested.trim().trim_end_matches(['/', '\\']);
    if t.is_empty() {
        return false;
    }
    let p = Path::new(t);
    p.is_absolute() && (is_well_known_temp_name(p) || is_host_temp_root(p))
}
