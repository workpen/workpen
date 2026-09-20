# Threat model

Crate rustdoc is canonical: `workpen::threat_model`.

This page is the same contract in one place for host authors. It is
not a launch README. The repo README stays `Not ready.`

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
  then argv only. Default `run_child` still starts the child.
  `workpen run` uses `with_require_dest_hide` and does not spawn.
- Extra-root dests are readable when remount is unavailable. Those
  still fail closed.
- Linux remount covers files created after spawn. It does not. macOS
  has name regexes. Windows denies existing dests only.
- `apply_pre_exec` skipped argv dest-deny. It dest-denies the same way
  `run_child` does. Hosts that spawn themselves can also call
  `dest_deny_command`.
- Attached `--flag=.env` and GNU glued shorts (`-a.env`, clustered
  `-la.env`) are dest-denied.
- Wrapper skip is only `timeout` / `nohup` / `nice`. `time` and
  `stdbuf` are wrappers too.
- Extra-root `/tmp` is one dest-deny name level. A hardlink under a
  deeper ordinary dir is not remounted. `check_dest` still dest-denies
  hardlink siblings when the host calls it. In-child open of a planted
  `/tmp/proj/sub/leaked` is the same class as post-create.
- Windows WFP ran. Win32 5 is `WfpSkipped`. AppContainer is still on.
- Renaming the dest-deny parent unmasks nothing. Parent-rename is out
  of scope. Leaf `mv .env leaked` is a macOS last-match contract.
- The child inherits `TMPDIR`. Those names are scrubbed.
- Windows `Stdio::piped` on `run_child` is a host-readable pipe. Use
  `run_child_output`.
- Linux `PR_SET_DUMPABLE=0` in `pre_exec` lasts until `execve`. A
  readable program starts dumpable again. `RLIMIT_CORE=0` survives.

## Hosts

Match `KernelError`, `DestDenyError`, `CheckDestError`, and
`KernelApply` variants. Do not parse English.

New variants are breaking for exhaustive matches even in 0.x.

crates.io stays unpublished until a human says launch.
