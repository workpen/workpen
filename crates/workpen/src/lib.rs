//! Userspace containment stack. Not ready.

mod deny;

pub use deny::{
    DenyPolicy, DestDeny, DestDenyError, DestDenyKind, classify_dest, default_secret_denies,
    deny_patch_dests, dest_deny_message, is_env_template_basename, is_path_denied,
    path_is_denied_glob, path_matches_deny_glob, reject_command_secret_path_tokens,
};

/// Crate version from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_matches_package() {
        assert_eq!(super::VERSION, env!("CARGO_PKG_VERSION"));
    }
}
