//! Dest-deny predicate. Stubs typecheck; classify and argv scan land in PR 2.

use std::path::{Path, PathBuf};

/// Portable dest-deny policy. Same globs on every OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyPolicy {
    globs: Vec<String>,
}

impl Default for DenyPolicy {
    fn default() -> Self {
        Self {
            globs: default_secret_denies(),
        }
    }
}

impl DenyPolicy {
    pub fn new(globs: Vec<String>) -> Self {
        Self { globs }
    }

    /// `default_secret_denies()` plus extras. Extras never replace defaults.
    pub fn with_extra(extra: impl IntoIterator<Item = String>) -> Self {
        let mut globs = default_secret_denies();
        for g in extra {
            if !globs.iter().any(|x| x == &g) {
                globs.push(g);
            }
        }
        Self { globs }
    }

    pub fn globs(&self) -> &[String] {
        &self.globs
    }
}

/// Why dest-deny rejected a path. Hosts branch on this; do not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestDenyKind {
    /// Basename or full path matched a deny glob (raw or canonical).
    DenyGlob,
    /// Another directory entry shares this inode / NTFS file index and is denied.
    HardlinkSibling,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestDeny {
    pub kind: DestDenyKind,
    pub path: PathBuf,
    pub display: String,
}

impl DestDeny {
    /// Wording distinguishes glob vs hardlink.
    /// Hardlink must not say "matches deny glob".
    pub fn message(&self) -> String {
        match self.kind {
            DestDenyKind::DenyGlob => format!(
                "path denied by sandbox profile (matches deny glob): {}",
                self.display
            ),
            DestDenyKind::HardlinkSibling => format!(
                "path denied by sandbox profile (hardlink of a denied name): {}",
                self.display
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DestDenyError {
    #[error("{0}")]
    Denied(DestDeny),
    /// Argv token hit. Distinct wording from [`DestDeny::message`].
    #[error("command references path denied by sandbox profile: {token}")]
    CommandToken { token: String },
}

impl std::fmt::Display for DestDeny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// Classify one dest. Glob vs hardlink only. Does not jail `..`.
pub fn classify_dest(path: &Path, policy: &DenyPolicy) -> Option<DestDenyKind> {
    let _ = (path, policy);
    unimplemented!("dest-deny classify lands after the corpus")
}

pub fn is_path_denied(path: &Path, policy: &DenyPolicy) -> bool {
    classify_dest(path, policy).is_some()
}

pub fn dest_deny_message(path: &Path, display: &str, policy: &DenyPolicy) -> Option<String> {
    classify_dest(path, policy).map(|kind| {
        DestDeny {
            kind,
            path: path.to_path_buf(),
            display: display.to_owned(),
        }
        .message()
    })
}

/// Refuse if any host-extracted dest is a secret glob or hardlink sibling.
///
/// Does not check out-of-tree. Hosts then run PathGuard on the same dests.
pub fn deny_patch_dests(
    dests: &[impl AsRef<Path>],
    policy: &DenyPolicy,
) -> Result<(), DestDenyError> {
    for dest in dests {
        let dest = dest.as_ref();
        if let Some(kind) = classify_dest(dest, policy) {
            return Err(DestDenyError::Denied(DestDeny {
                kind,
                path: dest.to_path_buf(),
                display: dest.display().to_string(),
            }));
        }
    }
    Ok(())
}

/// Argv / command token scan. Does not parse a full shell.
pub fn reject_command_secret_path_tokens(
    command: &str,
    policy: &DenyPolicy,
) -> Result<(), DestDenyError> {
    let _ = (command, policy);
    unimplemented!("argv dest-deny scan lands after the corpus")
}

/// Committed dotenv templates, not live env files.
pub fn is_env_template_basename(name: &str) -> bool {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    base.starts_with(".env.")
        && (base.ends_with(".example") || base.ends_with(".sample") || base.ends_with(".template"))
}

pub fn path_matches_deny_glob(pattern: &str, path: &str) -> bool {
    let _ = (pattern, path);
    unimplemented!("glob matcher lands after the corpus")
}

pub fn path_is_denied_glob(globs: &[String], path: &str) -> bool {
    let _ = (globs, path);
    unimplemented!("glob matcher lands after the corpus")
}

/// v1 list is byte-identical to Bline `default_secret_denies()`.
/// Do not add `**/.azure/**` or `**/.config/gh/**`.
pub fn default_secret_denies() -> Vec<String> {
    vec![
        "**/.env".into(),
        "**/.env.*".into(),
        "**/*.pem".into(),
        "**/*.key".into(),
        "**/*.p12".into(),
        "**/*.pfx".into(),
        "**/id_rsa".into(),
        "**/id_ed25519".into(),
        "**/id_ecdsa".into(),
        "**/id_dsa".into(),
        "**/id_eddsa".into(),
        "**/.npmrc".into(),
        "**/.pypirc".into(),
        "**/.docker/config.json".into(),
        "**/kubeconfig".into(),
        "**/.kube/config".into(),
        "**/secrets.json".into(),
        "**/service-account*.json".into(),
        "**/.ssh/**".into(),
        "**/token.json".into(),
        "**/secring.gpg".into(),
        "**/.gnupg/private-keys-v1.d/**".into(),
        "**/credentials.json".into(),
        "**/.aws/credentials".into(),
        "**/.netrc".into(),
        "**/secrets/**".into(),
        "**/credentials/**".into(),
        "**/gateway/pairing.json".into(),
        "**/auth.json".into(),
        "**/auth-*.json".into(),
    ]
}
