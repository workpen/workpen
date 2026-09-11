//! Combined dest-deny + PathGuard explanation for `workpen why`.

use std::path::Path;

use crate::deny::{DenyPolicy, DestDeny, classify_dest};
use crate::guard::{PathGuard, PathGuardDeny, PathGuardError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    Allowed,
    DestDeny(DestDeny),
    PathGuard(PathGuardDeny),
}

impl Why {
    pub fn message(&self) -> String {
        match self {
            Why::Allowed => "allowed".into(),
            Why::DestDeny(d) => d.message(),
            Why::PathGuard(d) => d.message(),
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
            Err(
                PathGuardError::Root(_)
                | PathGuardError::EmptyPath
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
}
