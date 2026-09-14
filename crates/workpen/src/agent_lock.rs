//! Optional extra dest-deny names from a committed `agent.lock`.
//!
//! Missing file is fine. Invalid file is an error. Steal the idea of a
//! small on-disk dest-deny list, not a competitor format.

use std::io;
use std::path::{Path, PathBuf};

/// Committed dest-deny file name under the workspace.
pub const AGENT_LOCK_NAME: &str = "agent.lock";

#[derive(Debug, thiserror::Error)]
pub enum AgentLockError {
    #[error("agent.lock is not readable: {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("agent.lock is invalid at {path}:{line}: {reason}")]
    Invalid {
        path: PathBuf,
        line: usize,
        reason: String,
    },
}

/// Load dest-deny globs from `workspace/agent.lock`.
///
/// Missing file returns an empty list. Comments (`#`) and blank lines
/// are skipped. Each remaining line is one glob.
pub fn load_agent_lock(workspace: &Path) -> Result<Vec<String>, AgentLockError> {
    load_agent_lock_file(&workspace.join(AGENT_LOCK_NAME))
}

/// Load dest-deny globs from an explicit path.
pub fn load_agent_lock_file(path: &Path) -> Result<Vec<String>, AgentLockError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(AgentLockError::Io {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    parse_agent_lock(path, &raw)
}

fn parse_agent_lock(path: &Path, raw: &str) -> Result<Vec<String>, AgentLockError> {
    let mut globs = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line_no = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains('\0') {
            return Err(AgentLockError::Invalid {
                path: path.to_path_buf(),
                line: line_no,
                reason: "NUL byte in dest-deny glob".into(),
            });
        }
        if trimmed.starts_with('[') || trimmed.contains('=') {
            return Err(AgentLockError::Invalid {
                path: path.to_path_buf(),
                line: line_no,
                reason: "expected one dest-deny glob per line".into(),
            });
        }
        if !globs.iter().any(|g| g == trimmed) {
            globs.push(trimmed.to_string());
        }
    }
    Ok(globs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn missing_file_is_empty() {
        let dir = TempDir::new().expect("tmp");
        let got = load_agent_lock(dir.path()).expect("missing");
        assert!(got.is_empty(), "missing agent.lock must be empty: {got:?}");
    }

    #[test]
    fn parse_globs_skips_comments() {
        let dir = TempDir::new().expect("tmp");
        std::fs::write(
            dir.path().join(AGENT_LOCK_NAME),
            "# team extras\n**/*.secret\n\n**/token.local\n",
        )
        .expect("write");
        let got = load_agent_lock(dir.path()).expect("parse");
        assert_eq!(got, ["**/*.secret", "**/token.local"]);
    }

    #[test]
    fn invalid_equals_line_is_error() {
        let dir = TempDir::new().expect("tmp");
        let path = dir.path().join(AGENT_LOCK_NAME);
        std::fs::write(&path, "globs = [\"**/*.secret\"]\n").expect("write");
        match load_agent_lock(dir.path()) {
            Err(AgentLockError::Invalid { line, .. }) => assert_eq!(line, 1),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
