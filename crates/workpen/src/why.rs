//! Combined dest-deny + PathGuard explanation.
//!
//! [`explain`] follows [`crate::check_dest`], including fifo, socket,
//! and device. `/dev/null` stays allowed. On Windows, `NUL` stays
//! allowed. That is the null-device grant, including `\\.\NUL`,
//! `\\?\NUL`, and a normal path whose final component is `NUL`.
//! [`explain`] reports `allowed`. An extended `\\?\` path with a
//! drive or UNC prefix is a literal file, not that device.
//! `\\?\C:\dir\NUL` and `\\?\C:\dir\CON` stay ordinary. `CON` and
//! the other reserved names on a normal path are
//! [`Why::SpecialFile`]. The CLI `why` command still uses `check_dest`
//! under `--root`.

use std::path::Path;

use crate::check_dest;
use crate::deny::{CheckDestError, DenyPolicy, DestDeny, DestDenyError};
use crate::guard::{PathGuard, PathGuardDeny, PathGuardError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    Allowed,
    DestDeny(DestDeny),
    PathGuard(PathGuardDeny),
    EmptyPath,
    /// Fifo, socket, or device. Same text as [`crate::CheckDestError::SpecialFile`].
    /// `/dev/null` and Windows `NUL` stay [`Why::Allowed`]. `explain`
    /// reports `allowed` for that null-device grant. An extended
    /// `\\?\` drive path is a literal file, not this error.
    SpecialFile {
        path: String,
        kind: &'static str,
    },
    /// Same sentence as [`crate::check_dest`]. Not a workspace escape.
    Reported(String),
}

impl Why {
    pub fn message(&self) -> String {
        match self {
            Why::Allowed => "allowed".into(),
            Why::DestDeny(d) => d.message(),
            Why::PathGuard(d) => d.message(),
            Why::EmptyPath => PathGuardError::EmptyPath.to_string(),
            Why::SpecialFile { path, kind } => format!("refuse special file ({kind}): {path}"),
            Why::Reported(text) => text.clone(),
        }
    }
}

pub fn explain(path: &Path, policy: &DenyPolicy, guard: Option<&PathGuard>) -> Why {
    let Some(raw) = path.to_str() else {
        return Why::Reported(CheckDestError::NonUtf8.to_string());
    };
    match check_dest(raw, policy, guard) {
        Ok(_) => Why::Allowed,
        Err(CheckDestError::DestDeny(DestDenyError::Denied(deny))) => Why::DestDeny(deny),
        Err(CheckDestError::PathGuard(PathGuardError::EmptyPath)) => Why::EmptyPath,
        Err(CheckDestError::PathGuard(PathGuardError::Denied(deny))) => Why::PathGuard(deny),
        Err(CheckDestError::SpecialFile { path, kind }) => Why::SpecialFile { path, kind },
        Err(err) => Why::Reported(err.to_string()),
    }
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

    #[cfg(unix)]
    #[test]
    fn explain_refuses_fifo() {
        let dir = tempfile::tempdir().expect("workspace");
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success(), "mkfifo");
        let policy = DenyPolicy::default();
        match explain(&fifo, &policy, None) {
            Why::SpecialFile { kind, .. } => assert_eq!(kind, "fifo"),
            other => panic!("fifo must be SpecialFile, got {other:?}"),
        }
        let msg = explain(&fifo, &policy, None).message();
        assert!(
            msg.contains("refuse special file (fifo)"),
            "fifo message must match check_dest: {msg}"
        );
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&fifo, &alias).expect("symlink");
        match explain(&alias, &policy, None) {
            Why::SpecialFile { kind, .. } => assert_eq!(kind, "fifo"),
            other => panic!("symlink to fifo must be SpecialFile, got {other:?}"),
        }
        let alias_msg = explain(&alias, &policy, None).message();
        assert!(
            alias_msg.contains("refuse special file (fifo)"),
            "symlink fifo message must match check_dest: {alias_msg}"
        );
        if std::path::Path::new("/dev/null").exists() {
            assert_eq!(
                explain(std::path::Path::new("/dev/null"), &policy, None),
                Why::Allowed
            );
            let guard = PathGuard::new(
                dir.path(),
                crate::guard::AbsolutePathPolicy::AllowIfContained,
            )
            .expect("guard");
            assert_eq!(
                explain(std::path::Path::new("/dev/null"), &policy, Some(&guard)),
                Why::Allowed,
                "a workspace guard must not hide that /dev/null is allowed"
            );
        }
        if std::path::Path::new("/dev/zero").exists() {
            let guard = PathGuard::new(
                dir.path(),
                crate::guard::AbsolutePathPolicy::AllowIfContained,
            )
            .expect("guard");
            match explain(std::path::Path::new("/dev/zero"), &policy, Some(&guard)) {
                Why::SpecialFile { kind, .. } => assert_eq!(kind, "device"),
                other => panic!("guarded /dev/zero must be SpecialFile, got {other:?}"),
            }
        }
        if std::path::Path::new("/dev/zero").exists() {
            match explain(std::path::Path::new("/dev/zero"), &policy, None) {
                Why::SpecialFile { kind, .. } => assert_eq!(kind, "device"),
                other => panic!("/dev/zero must be SpecialFile, got {other:?}"),
            }
        }
        let readme = dir.path().join("readme.md");
        std::fs::write(&readme, "ok\n").expect("readme");
        assert_eq!(explain(&readme, &policy, None), Why::Allowed);
    }

    #[cfg(windows)]
    #[test]
    fn explain_windows_nul_is_the_null_device_grant() {
        let dir = tempfile::tempdir().expect("workspace");
        let policy = DenyPolicy::default();
        let nul = dir.path().join("NUL");
        let readme = dir.path().join("readme.txt");
        std::fs::write(&readme, b"ok\n").expect("readme");
        std::fs::write(dir.path().join(".env"), b"SECRET=1\n").expect(".env");
        for path in [
            std::path::Path::new("NUL"),
            std::path::Path::new(r"\\.\NUL"),
            std::path::Path::new(r"\\?\NUL"),
            nul.as_path(),
        ] {
            let why = explain(path, &policy, None);
            assert_eq!(why, Why::Allowed, "{path:?}");
            assert_eq!(
                why.message(),
                "allowed",
                "explain text for NUL is the null-device grant"
            );
        }
        let guard = PathGuard::new(
            dir.path(),
            crate::guard::AbsolutePathPolicy::AllowIfContained,
        )
        .expect("guard");
        assert_eq!(
            explain(&nul, &policy, Some(&guard)),
            Why::Allowed,
            "a workspace guard must not hide that NUL is allowed"
        );
        match explain(Path::new("CON"), &policy, None) {
            Why::SpecialFile { kind, .. } => assert_eq!(kind, "device"),
            other => panic!("CON must be SpecialFile, got {other:?}"),
        }
        let con_msg = explain(Path::new(r"\\.\CON"), &policy, None).message();
        assert!(
            con_msg.contains("refuse special file (device)"),
            "CON explain must match check_dest: {con_msg}"
        );
        match explain(&dir.path().join("CON"), &policy, Some(&guard)) {
            Why::SpecialFile { kind, .. } => assert_eq!(kind, "device"),
            other => panic!("guarded path ending in CON must be SpecialFile, got {other:?}"),
        }
        assert_eq!(explain(&readme, &policy, None), Why::Allowed);
        match explain(&dir.path().join(".env"), &policy, None) {
            Why::DestDeny(_) => {}
            other => panic!(".env beside NUL must stay dest-deny, got {other:?}"),
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

    #[test]
    fn dotdot_outside_is_escape_not_a_deny_glob() {
        let dir = tempfile::tempdir().expect("workspace");
        let extras: [&std::path::Path; 0] = [];
        let guard = PathGuard::with_extra_roots(dir.path(), extras).expect("guard");
        let outside = dir.path().join("..").join("notes-outside.txt");
        match check_dest(
            &outside.to_string_lossy(),
            &DenyPolicy::default(),
            Some(&guard),
        ) {
            Err(CheckDestError::PathGuard(err)) => {
                let msg = err.to_string();
                assert!(msg.contains("escapes workspace"), "{msg}");
                assert!(!msg.contains("deny glob"), "{msg}");
            }
            other => panic!("a .. path outside the workspace must escape, got {other:?}"),
        }
    }

    #[test]
    fn dotdot_back_inside_is_allowed() {
        let dir = tempfile::tempdir().expect("workspace");
        let readme = dir.path().join("readme.md");
        std::fs::write(&readme, "ok\n").expect("readme");
        let name = dir.path().file_name().expect("name");
        let dotted = dir.path().join("..").join(name).join("readme.md");
        let extras: [&std::path::Path; 0] = [];
        let guard = PathGuard::with_extra_roots(dir.path(), extras).expect("guard");
        check_dest(
            &dotted.to_string_lossy(),
            &DenyPolicy::default(),
            Some(&guard),
        )
        .unwrap_or_else(|err| panic!("a .. path back inside must be allowed, got {err}"));
    }

    #[test]
    fn explain_absolute_inside_is_not_escape() {
        let dir = tempfile::tempdir().expect("workspace");
        let readme = dir.path().join("readme.md");
        std::fs::write(&readme, "ok\n").expect("readme");
        let guard = PathGuard::builder(dir.path()).build().expect("guard");
        let msg = explain(&readme, &DenyPolicy::default(), Some(&guard)).message();
        assert!(msg.contains("absolute paths are not allowed"), "{msg}");
        assert!(!msg.contains("escapes workspace"), "{msg}");
    }

    #[test]
    fn explain_nul_is_not_escape() {
        let msg = explain(std::path::Path::new("a\0b"), &DenyPolicy::default(), None).message();
        assert!(msg.contains("NUL"), "{msg}");
        assert!(!msg.contains("escapes workspace"), "{msg}");
    }
}
