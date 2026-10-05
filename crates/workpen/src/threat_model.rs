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
//! * On Unix, descriptors above stdio that lack `FD_CLOEXEC` get that
//!   flag before `exec`. An inherited secret fd does not survive into
//!   the command (`cat <&3`, including descriptor 65536 when the soft
//!   limit allows it). Standard streams stay open. The walk covers
//!   every open descriptor above stdio. When that list is unavailable,
//!   a soft `RLIMIT_NOFILE` that fits in a descriptor number is scanned
//!   in full. The reaper closes the same descriptors, except its report
//!   pipe and its watch.
//! * When `run_child` returns successfully, a grandchild that called
//!   `setsid` is not still running. Linux adopts it with
//!   `PR_SET_CHILD_SUBREAPER`, set before the command can run, so a
//!   grandchild that exits in the same turn is still adopted. macOS
//!   records the command's descendants, including one created by a fork
//!   the reaper is notified about, and signals those pids. A descendant
//!   past the recorded set is [`crate::KernelError::Descendants`]. On
//!   macOS a fork whose parent has exited is that error when a live
//!   process with the command's name is still outside the recorded set.
//!   A child the parent already waited for is not. The CLI exits 4 and
//!   prints `descendants were not fully stopped`. Hosts that spawn
//!   after `apply_pre_exec` and wait on that same thread call
//!   `finish_pre_exec` and match that variant. A wait that resumes on
//!   another thread uses [`crate::PreExecReport`] from
//!   `apply_pre_exec_report` and calls [`crate::PreExecReport::finish`].
//!   `discard_pre_exec`, or `Drop` on that report, closes the pipe when
//!   spawn fails.
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
//! change. 0.7.4 is on crates.io; later publishes still wait on a release PR. <!-- x-release-please-version -->
