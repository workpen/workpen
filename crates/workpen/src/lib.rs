//! Userspace containment stack. Not ready.
//!
//! Hosts call dest-deny with an explicit [`DenyPolicy`]. There is no
//! process-wide deny slot; a session wrapper can hold the policy:
//!
//! ```
//! use std::path::Path;
//! use workpen::{DenyPolicy, dest_deny_message, is_path_denied};
//!
//! let policy = DenyPolicy::default();
//! assert!(is_path_denied(Path::new(".env"), &policy));
//! assert!(dest_deny_message(Path::new(".env"), ".env", &policy).is_some());
//! ```
//!
//! Leftover worktree GC is behind `feature = "gc"`. Hosts pass
//! `leftover_dir` and `saved_ref_prefix` on `GcConfig`.

mod deny;
#[cfg(feature = "gc")]
mod gc;
mod guard;
mod why;
#[cfg(feature = "nono")]
mod wrap;

pub use deny::{
    CheckDestError, DenyPolicy, DestDeny, DestDenyError, DestDenyKind, check_dest, classify_dest,
    default_secret_denies, deny_patch_dests, dest_deny_message, is_env_template_basename,
    is_path_denied, path_is_denied_glob, path_matches_deny_glob, reject_command_secret_path_tokens,
    verify_post_open,
};
#[cfg(feature = "gc")]
pub use gc::{
    GcConfig, GcDecision, GcError, KeepReason, classify_for_age_gc, classify_worktree,
    parse_max_age, run_gc,
};
pub use guard::{PathGuard, PathGuardDeny, PathGuardError, PathGuardKind, check_dests};
pub use why::{Why, explain};
#[cfg(feature = "nono")]
pub use wrap::{
    KernelAccess, KernelApply, KernelError, KernelGrant, KernelPolicy, kernel_supported,
    process_jail,
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
