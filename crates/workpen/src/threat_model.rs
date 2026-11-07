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
//!   hardlink siblings when the host calls it. A workspace `run` reads
//!   each hardlink directory once, not once per name.
//!   In-child open of a planted `/tmp/proj/sub/leaked` is the same
//!   class as post-create.
//! * Windows WFP ran. Win32 5 is `WfpSkipped`. AppContainer is still
//!   the net deny. Do not revert that skip. Network-blocked commands
//!   in one process share one AppContainer and one dynamic WFP
//!   session. `workspace` (`with_network(false)`) does not create
//!   either. [`shutdown_process_jail`](crate::shutdown_process_jail)
//!   deletes that blocked profile. Dynamic filters die with the
//!   session.
//! * `DISABLE_MAX_PRIVILEGE` removed `SeChangeNotifyPrivilege`.
//!   That flag keeps traverse checking and drops `SeDebugPrivilege`,
//!   `SeBackupPrivilege`, `SeRestorePrivilege`,
//!   `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, and
//!   `SeTcbPrivilege`. Git `usr\bin` tools run. MSYS opens
//!   `\BaseNamedObjects\msys-2.0S<n>-<install key>` with `OBJ_OPENIF`.
//!   The jail grants the restricted SID on that directory. The key is
//!   the MSYS hash of `msys-2.0.dll`, not a fixed id. The same grant
//!   is applied under `\Sessions\BNOLINKS\<session>` when the process
//!   is not in session 0. MSYS creates the per-user section `SID.1`
//!   in that directory and passes a null security descriptor
//!   (`sec_none`). The section inherits the directory, so the jail
//!   adds an inheritable allow for the user and `S-1-5-12`. An
//!   existing `SID.1` gets the same allow. MSYS then creates its
//!   signal pipe during `msys-2.0.dll` startup with a user security
//!   descriptor that does not name `S-1-5-12`, then opens the write end.
//!   For that program the jail is the debugger and points
//!   `CreateNamedPipeW` at a descriptor that includes `S-1-5-12`. A write outside the ReadWrite grant still fails.
//! * The workspace jail scanned the user profile. It denies `.ssh`,
//!   `.aws`, `.gnupg`, `.azure`, `.config\gh`, `.docker`, and `.kube`
//!   with the restricted SID and restores those ACLs when the jail
//!   drops. Missing names are skipped. It does not walk the profile.
//! * A jailed Windows child must not take over the parent console.
//!   The job blocks clipboard read and write, system parameters, and
//!   ExitWindows. A session with no window station does not enforce
//!   the clipboard limit. The child still inherits the parent console
//!   when the parent has one. `JOB_OBJECT_UILIMIT_HANDLES`
//!   is not set: it blocks USER handles owned outside the job, and
//!   MSYS init exits `0xC0000142`. `CREATE_NO_WINDOW` is not set:
//!   it hangs console programs such as `cmd`. Captured stdout and
//!   stderr are pipes and still work.
//! * `strict` and `read-only` on Windows can read the whole disk.
//!   They can read the workspace (`read-only` cannot write it),
//!   `SystemRoot`, `System32`, and `ProgramFiles`. Other paths are
//!   not readable. `workspace` is unchanged except the profile-secret
//!   list above.
//! * [`crate::KernelPolicy::spawn_reexec`] blocked the network. That
//!   call keeps outbound network open (internet client capability, no
//!   WFP BLOCK) and reuses one AppContainer in the process.
//!   [`crate::KernelApply::Applied`] there means the container is up.
//!   [`crate::KernelPolicy::run_child`] is unchanged.
//! * Renaming the dest-deny parent is in scope. Parent-rename of a
//!   dest-deny ancestor (`mv workspace out`) is out of scope. Leaf
//!   `mv .env leaked` is a Seatbelt last-match contract on macOS.
//! * Linux stdout forwarding writes one byte when a larger write
//!   returns `EAGAIN`. A pipe with a few free bytes does not spin.
//!   A reader that stops still fills the pipe, and `--timeout` ends
//!   that forward.
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
//! * On Windows, [`crate::check_dest`] and [`crate::explain`] treat
//!   `CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9`, `LPT1` through
//!   `LPT9`, `CONIN$`, and `CONOUT$` as devices. That includes the
//!   `\\.\` and `\\?\` device forms and a normal path whose final
//!   component is one of those names. A trailing colon, `::`, and
//!   `CON: :` still count. `NUL` stays allowed, the same
//!   null-device grant as `/dev/null`. `explain` reports `allowed`.
//!   The other names are [`crate::CheckDestError::SpecialFile`] and
//!   [`crate::Why::SpecialFile`]. `NUL.txt` stays an ordinary path.
//!   An extended `\\?\` path with a drive or UNC prefix is a literal
//!   path, not that device.
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
//!   the reaper is notified about, and signals those pids. It does not
//!   report success while one of those pids still answers `kill(pid, 0)`.
//!   A recorded pid that is still running is [`crate::KernelError::Descendants`].
//!   A descendant past the recorded set is that same error. On macOS a
//!   fork whose parent has exited is that error when a live
//!   session leader with the command's name is still outside the
//!   recorded set. That process called `setsid`. That name is read
//!   after exec. When the command has already
//!   exited, the name is the program's file name and the start time
//!   is the one taken while the process was stopped. A child the
//!   parent already waited for is not. The CLI exits 4 and
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
//! change. 0.7.9 is on crates.io; later publishes still wait on a release PR. <!-- x-release-please-version -->
