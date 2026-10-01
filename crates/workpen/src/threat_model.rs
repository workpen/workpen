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
//! * Linux remount ran. Skip is `RemountSkipped` when unshare / maps /
//!   `MS_PRIVATE` is denied. Landlock still applies. Landlock cannot
//!   hide a file inside an allowed tree. In-tree dest-deny is then
//!   userspace argv only. Default `run_child` still starts the child.
//!   [`crate::KernelPolicy::with_require_dest_hide`] (the `workpen run`
//!   CLI) refuses to spawn.
//! * `workpen run --tty` works on Windows. Windows returns
//!   [`crate::KernelError::Apply`]. On Unix the child gets a PTY. The
//!   parent still copies the master; dest-deny and the kernel jail
//!   still apply.
//! * Extra-root dests stay hidden when remount is unavailable. They
//!   stay readable and still fail closed.
//! * A hide of every name created after launch. When remount applies,
//!   missing dest-deny **basenames** at the workspace root (and
//!   extra-roots that are not `/tmp`) are occupied, then unlinked after
//!   the child exits. `touch .env && cat .env` at the root is then hide,
//!   not a leak. Nested `mkdir x && touch x/.env` is still userspace-only.
//!   macOS has name regexes. Windows denies existing dests only.
//!   Do not `create_dir_all` on a nested deny path. Do not vendor bwrap.
//! * `apply_pre_exec` skipped argv dest-deny. It dest-denies argv, then
//!   installs the hook. Hosts that cannot use `run_child` still call
//!   [`crate::KernelPolicy::dest_deny_command`]. That check resolves
//!   relative dests against `Command::current_dir` when set, else the
//!   first ReadWrite grant (a capture-dir jail still dest-denies the
//!   user cwd when the host sets `current_dir`).
//! * Extra-root `/tmp` remounts every hardlink. `/tmp` is one extra
//!   dest-deny name level. A hardlink under a deeper ordinary dir is
//!   not remounted. Path remount does not hide other hardlinks to the
//!   same inode. Userspace [`crate::check_dest`] still dest-denies
//!   hardlink siblings when the host calls it. In-child open of a
//!   planted `/tmp/proj/sub/leaked` is the same class as post-create.
//! * Windows WFP ran. Win32 5 is `WfpSkipped`. AppContainer is still
//!   the net deny. Do not revert that skip.
//! * Renaming the dest-deny parent is in scope. Parent-rename of a
//!   dest-deny ancestor (`mv workspace out`) is out of scope. Leaf
//!   `mv .env leaked` is a Seatbelt last-match contract on macOS.
//! * Windows `Stdio::piped` on `run_child` captures stdout. The child
//!   inherits the handle or gets NUL. Hosts that need captured stdout
//!   call [`crate::KernelPolicy::run_child_output`].
//!
//! # Promises
//!
//! * Argv dest-deny peels attached `--flag=.env` and GNU glued shorts
//!   (`-a.env`, clustered `-la.env`). It does not parse unknown script
//!   languages.
//! * Wrapper skip is `timeout`, `nohup`, `nice`, `time`, and `stdbuf`.
//! * The child environment removes `TMPDIR`, `TEMP`, and `TMP`. The
//!   child uses the platform default temp directory.
//! * When `run_child` returns, a grandchild that called `setsid` is
//!   not still running. Linux adopts it with `PR_SET_CHILD_SUBREAPER`.
//!   macOS records descendants seen while the command is alive and
//!   signals those pids. A macOS command that forks and exits before
//!   that descendant is observed can still leave it running.
//!
//! # Process hardening
//!
//! Unix `run_child` sets `RLIMIT_CORE=0` in `pre_exec`. That rlimit
//! survives `execve`. Linux also sets `PR_SET_DUMPABLE=0` and macOS
//! `PT_DENY_ATTACH` in the same hook. Failure is
//! [`crate::KernelError::Apply`]. The parent is not hardened. Windows
//! has no equivalent in this crate.
//!
//! Linux `execve` of a readable program sets dumpable to
//! `SUID_DUMP_USER` (`1`). `PR_SET_DUMPABLE=0` therefore covers only
//! the window between `pre_exec` and exec. The surviving child
//! contract is `RLIMIT_CORE=0` plus Landlock / remount / seccomp.
//! Do not inject a constructor or `LD_PRELOAD` to reset dumpable
//! after exec.
//!
//! # 1.0
//!
//! New [`crate::KernelError`] / [`crate::DestDenyError`] /
//! [`crate::KernelApply`] variants are breaking for exhaustive hosts
//! even in 0.x. Do not bump to 1.0 in the same change as a behavior
//! change. 0.7.0 is on crates.io; later publishes still wait on a release PR.
