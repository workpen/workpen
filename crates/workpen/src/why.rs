//! Combined dest-deny + PathGuard explanation.
//!
//! Dest-deny runs on the path as given. If `guard` is `Some`, PathGuard
//! resolves then dest-deny runs on the resolved path (same order as
//! [`crate::check_dest`]). The CLI `why` command uses `check_dest`
//! under `--root`.

use std::path::Path;

use crate::deny::{DenyPolicy, DestDeny, dest_deny_at};
use crate::guard::{PathGuard, PathGuardDeny, PathGuardError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    Allowed,
    DestDeny(DestDeny),
    PathGuard(PathGuardDeny),
    EmptyPath,
}

impl Why {
    pub fn message(&self) -> String {
        match self {
            Why::Allowed => "allowed".into(),
            Why::DestDeny(d) => d.message(),
            Why::PathGuard(d) => d.message(),
            Why::EmptyPath => PathGuardError::EmptyPath.to_string(),
        }
    }
}

pub fn explain(path: &Path, policy: &DenyPolicy, guard: Option<&PathGuard>) -> Why {
    if let Some(deny) = dest_deny_at(path, path.display().to_string(), policy) {
        return Why::DestDeny(deny);
    }
    if let Some(guard) = guard {
        match guard.check(path) {
            Err(PathGuardError::Denied(deny)) => return Why::PathGuard(deny),
            Err(PathGuardError::EmptyPath) => return Why::EmptyPath,
            Err(
                PathGuardError::Root(_)
                | PathGuardError::AbsolutePath(_)
                | PathGuardError::Canonicalize { .. },
            ) => {
                return Why::PathGuard(PathGuardDeny {
                    kind: crate::PathGuardKind::Escape,
                    path: path.to_path_buf(),
                    display: path.display().to_string(),
                });
            }
            Ok(resolved) => {
                if let Some(deny) = dest_deny_at(&resolved, path.display().to_string(), policy) {
                    return Why::DestDeny(deny);
                }
            }
        }
    }
    Why::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DenyPolicy;

    #[test]
    fn explain_env_is_dest_deny() {
        match explain(std::path::Path::new(".env"), &DenyPolicy::default(), None) {
            Why::DestDeny(d) => assert!(d.message().contains("deny glob")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn explain_path_guard_resolved_hardlink_is_dest_deny() {
        let dir = tempfile::tempdir().expect("workspace");
        let env = dir.path().join(".env");
        std::fs::write(&env, "SECRET=1\n").expect("env");
        let notes = dir.path().join("notes.txt");
        std::fs::hard_link(&env, &notes).expect("hardlink");
        let extras: [&std::path::Path; 0] = [];
        let guard = PathGuard::with_extra_roots(dir.path(), extras).expect("guard");
        let policy = DenyPolicy::default();
        // Process cwd is not the workspace. Raw "notes.txt" is not dest-deny;
        // PathGuard joins the workspace and must dest-deny the resolved sibling.
        match explain(std::path::Path::new("notes.txt"), &policy, Some(&guard)) {
            Why::DestDeny(d) => {
                assert_eq!(d.kind, crate::DestDenyKind::HardlinkSibling);
                assert_eq!(d.matched.as_deref(), Some(".env"));
                let msg = d.message();
                assert!(
                    msg.contains("denied name .env"),
                    "explain hardlink must say denied name .env: {msg}"
                );
            }
            other => panic!("resolved hardlink sibling must DestDeny, got {other:?}"),
        }
        match crate::check_dest("notes.txt", &policy, Some(&guard)) {
            Err(crate::CheckDestError::DestDeny(crate::DestDenyError::Denied(d))) => {
                assert_eq!(d.kind, crate::DestDenyKind::HardlinkSibling);
                assert_eq!(d.matched.as_deref(), Some(".env"));
            }
            other => panic!("check_dest must dest-deny the same shape, got {other:?}"),
        }
    }

    #[test]
    fn explain_empty_path_is_not_escape() {
        let dir = tempfile::tempdir().expect("workspace");
        let extras: [&std::path::Path; 0] = [];
        let guard = PathGuard::with_extra_roots(dir.path(), extras).expect("guard");
        for raw in ["", " "] {
            let why = explain(
                std::path::Path::new(raw),
                &DenyPolicy::default(),
                Some(&guard),
            );
            let msg = why.message();
            assert!(
                msg.to_ascii_lowercase().contains("empty"),
                "empty path must mention empty: {msg}"
            );
            assert!(
                !msg.contains("escapes workspace"),
                "empty path must not claim escape: {msg}"
            );
        }
    }
}
