# Threat model

Crate rustdoc is canonical: `workpen::threat_model`.

This page is the same contract in one place for host authors. The
repo README is the public face.

## Trust boundary

The unit of isolation is a child process. This is not a VM.

The parent is trusted. The child is not.

## Layers

1. PathGuard refuses `/` and `$HOME` as the workspace or extra-root.
2. Userspace dest-deny refuses secret dests in argv and `check_dest`
   before spawn.
3. Kernel dest-deny hides dests that exist at spawn: Linux remount,
   macOS Seatbelt, Windows DENY ACE.

## `KernelApply::Applied` does not mean

- Linux remount ran. That is `RemountSkipped` when unshare / maps /
  `MS_PRIVATE` is denied. Landlock still applies. In-tree dest-deny is
  then argv only. Default
  `run_child` still starts the child. `workpen run` uses
  `with_require_dest_hide` and does not spawn.
- `workpen run --tty` works on Windows. Windows refuses. Dest-deny and
  the kernel jail still apply where the child starts.
- Extra-root dests stay hidden when remount is unavailable. Those
  dests stay readable and still fail closed.
- Nested post-create is hidden. When remount applies, missing
  dest-deny basenames at the workspace root are occupied
  (`touch .env && cat .env`). Nested `mkdir x && touch x/.env` is
  still a launch snapshot. macOS has name regexes. Windows denies
  existing dests only. Do not vendor bwrap. Do not `create_dir_all`
  on a nested deny path.
- `apply_pre_exec` skipped argv dest-deny. It dest-denies the same way
  `run_child` does. Hosts that spawn themselves can also call
  `dest_deny_command`. Relative dests resolve against
  `Command::current_dir` when set, else the first ReadWrite grant.
- Extra-root `/tmp` remounts every hardlink. `/tmp` is one dest-deny
  name level. A hardlink under a deeper ordinary dir is not remounted.
  `check_dest` still dest-denies hardlink siblings when the host calls
  it. A workspace `run` reads each hardlink directory once, not once
  per name. In-child open of a planted `/tmp/proj/sub/leaked`
  is the same class as post-create.
- Windows WFP ran. Win32 5 is `WfpSkipped`. AppContainer is still on.
  Network-blocked commands in one process share one AppContainer and
  one dynamic WFP session. `workspace` (`with_network(false)`) does
  not create either. `shutdown_process_jail` deletes the profile.
  Dynamic filters die with the session.
- `DISABLE_MAX_PRIVILEGE` removed `SeChangeNotifyPrivilege`. That
  flag keeps traverse checking and drops `SeDebugPrivilege`,
  `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`,
  `SeLoadDriverPrivilege`, and `SeTcbPrivilege`. Git `usr\bin` tools
  are expected to run. A write outside the ReadWrite grant still fails.
- The workspace jail scanned the user profile. It denies `.ssh`,
  `.aws`, `.gnupg`, `.azure`, `.config\gh`, `.docker`, and `.kube`
  with the restricted SID and restores those ACLs when the jail drops.
  Missing names are skipped. It does not walk the profile.
- A jailed Windows child cannot use the parent console or the
  clipboard. Clipboard read and write, system parameters, and
  ExitWindows are blocked. The child still inherits the parent console
  when the parent has one. `JOB_OBJECT_UILIMIT_HANDLES` is not set:
  it blocks USER handles owned outside the job, and MSYS init exits
  `0xC0000142`. `CREATE_NO_WINDOW` is not set: it hangs console
  programs such as `cmd`. Captured stdout and stderr are pipes and
  still work.
- `strict` and `read-only` on Windows can read the whole disk. They
  can read the workspace (`read-only` cannot write it), `SystemRoot`,
  `System32`, and `ProgramFiles`. Other paths are not readable.
  `workspace` is unchanged except the profile-secret list above.
- A long-lived Windows re-exec jail is per command. A host prepares
  one with `prepare_reexec` and spawns into it. Network stays open.
  The profile-secret directories stay unreadable. Filesystem root and
  home are refused as read-write roots. `workspace` `run_child` is a
  different path.
- Renaming the dest-deny parent is in scope. Parent-rename is out of
  scope. Leaf `mv .env leaked` is a macOS last-match contract.
- Windows `Stdio::piped` on `run_child` captures stdout for the host.
  It is a host-readable pipe. Use `run_child_output`.
- Linux stdout forwarding writes one byte when a larger write returns
  `EAGAIN`. A pipe with a few free bytes does not spin. A reader that
  stops still fills the pipe, and `--timeout` ends that forward.
- Linux `PR_SET_DUMPABLE=0` in `pre_exec` lasts after `execve`. A
  readable program starts dumpable again. `RLIMIT_CORE=0` survives.

## Promises

- Argv dest-deny includes attached `--flag=.env` and GNU glued shorts
  (`-a.env`, clustered `-la.env`).
- Wrapper skip is `timeout`, `nohup`, `nice`, `time`, and `stdbuf`.
- The child environment removes `TMPDIR`, `TEMP`, and `TMP`. The child
  uses the platform default temp directory.
- On Windows, `check_dest` and `explain` treat `CON`, `PRN`, `AUX`,
  `NUL`, `COM1` through `COM9`, `LPT1` through `LPT9`, `CONIN$`, and
  `CONOUT$` as devices. That includes the `\\.\` and `\\?\` device
  forms and a normal path whose final component is one of those names.
  A trailing colon, `::`, and `CON: :` still count. `NUL` stays allowed,
  the same null-device grant as `/dev/null`.
  `explain` reports `allowed`. The other names are
  `CheckDestError::SpecialFile` and `Why::SpecialFile`. `NUL.txt` stays
  an ordinary path. An extended `\\?\` path with a drive or UNC prefix
  is a literal path, not that device.
- On Unix, descriptors above stdio that lack `FD_CLOEXEC` get that
  flag before `exec`. An inherited secret fd does not survive into
  the command (`cat <&3`, including descriptor 65536 when the soft
  limit allows it). Standard streams stay open. The walk covers
  every open descriptor above stdio. When that list is unavailable,
  a soft `RLIMIT_NOFILE` that fits in a descriptor number is scanned
  in full. The reaper closes the same descriptors, except its report
  pipe and its watch.
- When `run_child` returns successfully, a grandchild that called
  `setsid` is not still running. Linux adopts it with
  `PR_SET_CHILD_SUBREAPER`, set before the command can run, so a
  grandchild that exits in the same turn is still adopted. macOS
  records the command's descendants, including one created by a fork
  the reaper is notified about, and signals those pids. It does not
  report success while one of those pids still answers `kill(pid, 0)`.
  A recorded pid that is still running is `KernelError::Descendants`.
  A descendant past the recorded set is that same error. On macOS a
  fork whose parent has exited is that error when a live session
  leader with the command's name is still outside the recorded set.
  That process called `setsid`. That name is read after exec. When
  the command has already exited, the name is the program's file
  name and the start time is the one taken while the process was
  stopped. A child the parent already waited for is not. The CLI
  exits 4 and prints
  `descendants were not fully stopped`. Hosts that spawn after
  `apply_pre_exec` and wait on that same thread call `finish_pre_exec`
  and match that variant. A wait that resumes on another thread uses
  `PreExecReport` from `apply_pre_exec_report` and calls
  `PreExecReport::finish`. `discard_pre_exec`, or `Drop` on that
  report, closes the pipe when spawn fails.

## Hosts

Match `KernelError`, `DestDenyError`, `CheckDestError`, and
`KernelApply` variants. Do not parse English.

New variants are breaking for exhaustive matches even in 0.x.

0.7.9 is on crates.io; later publishes still wait on a release PR. <!-- x-release-please-version -->
