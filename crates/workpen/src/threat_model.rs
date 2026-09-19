//! Crate threat model. Not a launch README.
//!
//! Hosts match [`crate::KernelError`] / [`crate::DestDenyError`] /
//! [`crate::KernelApply`] variants, not English. See also
//! [`docs/threat-model.md`](https://github.com/workpen/workpen/blob/main/docs/threat-model.md)
//! in the source tree.
//!
//! # Trust boundary
//!
//! The unit of isolation is a **child process**. This is not a VM and
//! not a hypervisor. The parent process is trusted. The child is not.
//!
//! # Layers
//!
//! * **PathGuard** refuses filesystem root and `$HOME` as the workspace
//!   or extra-root.
//! * **Userspace dest-deny** refuses secret dests in argv and
//!   [`crate::check_dest`] before spawn.
//! * **Kernel dest-deny** hides existing dests after spawn: Linux
//!   remount bind-over, macOS Seatbelt last-match, Windows DENY ACE.
//!
//! # What `KernelApply::Applied` does not mean
//!
//! * Linux remount can be skipped (`RemountSkipped`). Landlock still
//!   applies. Landlock cannot hide a file inside an allowed tree.
//!   In-tree dest-deny is then userspace argv only.
//! * Extra-root dests still fail-closed when remount is unavailable.
//! * Linux remount is a **launch snapshot**. `touch .env && cat .env`
//!   after spawn is userspace-only. macOS has name regexes. Windows
//!   denies existing dests only. Do not plant missing dests.
//! * `apply_pre_exec` dest-denies argv, then installs the hook. Hosts
//!   that cannot use `run_child` still call
//!   [`crate::KernelPolicy::dest_deny_command`].
//! * Argv dest-deny peels attached `--flag=.env`. It does not parse
//!   unknown script languages. Wrapper skip is
//!   `timeout` / `nohup` / `nice` / `time` / `stdbuf`.
//! * Extra-root `/tmp` walks dest-deny names under ordinary
//!   subdirectories. It does not walk every file under `/tmp`.
//! * Windows WFP win32 5 is `WfpSkipped`. AppContainer is still the
//!   net deny. Do not revert that skip.
//! * Parent-rename of a dest-deny ancestor (`mv workspace out`) is
//!   out of scope. Leaf `mv .env leaked` is a Seatbelt last-match
//!   contract on macOS.
//! * Child env scrubs `TMPDIR` / `TEMP` / `TMP`. The child uses the
//!   platform default temp.
//! * Windows `run_child` inherits or NUL. Hosts that need captured
//!   stdout call [`crate::KernelPolicy::run_child_output`].
//!
//! # Process hardening
//!
//! Unix `run_child` sets `RLIMIT_CORE=0` on the child. Linux also sets
//! `PR_SET_DUMPABLE=0`. macOS also sets `PT_DENY_ATTACH`. Failure is
//! [`crate::KernelError::Apply`]. The parent is not hardened. Windows
//! has no equivalent in this crate.
//!
//! # 1.0
//!
//! New [`crate::KernelError`] / [`crate::DestDenyError`] /
//! [`crate::KernelApply`] variants are breaking for exhaustive hosts
//! even in 0.x. Do not bump to 1.0 in the same change as a behavior
//! change. crates.io stays unpublished until a human launch yes.
