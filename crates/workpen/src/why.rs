//! Combined dest-deny + PathGuard explanation.
//!
//! Dest-deny runs on the path as given. Hosts that have a workspace
//! root should join first, or call [`crate::check_dest`]. The CLI
//! `why` command uses `check_dest` under `--root`.

use std::path::Path;

use crate::deny::{DenyPolicy, DestDeny, classify_dest};
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
    if let Some(kind) = classify_dest(path, policy) {
        return Why::DestDeny(DestDeny {
            kind,
            path: path.to_path_buf(),
            display: path.display().to_string(),
        });
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
            Ok(_) => {}
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
