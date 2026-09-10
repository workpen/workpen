//! Userspace containment stack. Not ready.

mod deny;
#[cfg(feature = "gc")]
mod gc;
mod guard;
mod why;
#[cfg(feature = "nono")]
mod wrap;

pub use deny::{
    DenyPolicy, DestDeny, DestDenyError, DestDenyKind, classify_dest, default_secret_denies,
    deny_patch_dests, dest_deny_message, is_env_template_basename, is_path_denied,
    path_is_denied_glob, path_matches_deny_glob, reject_command_secret_path_tokens,
};
#[cfg(feature = "gc")]
pub use gc::{
    GcDecision, GcError, GcKeepReason, GcPolicy, GcReport, Worktree, decide, gc_leftovers,
    list_worktrees,
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
