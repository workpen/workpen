<p align="center">
  <img src="docs/brand/workpen.svg" alt="Workpen logo" width="160">
</p>

# Workpen

[![CI](https://github.com/workpen/workpen/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/workpen/workpen/actions/workflows/ci.yml)
[![Security](https://github.com/workpen/workpen/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/workpen/workpen/actions/workflows/security.yml)
[![crates.io](https://img.shields.io/crates/v/workpen?logo=rust)](https://crates.io/crates/workpen)
[![docs.rs](https://img.shields.io/docsrs/workpen?logo=docs.rs)](https://docs.rs/workpen)
[![Release](https://img.shields.io/github/v/release/workpen/workpen?logo=github)](https://github.com/workpen/workpen/releases/latest)

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](./LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14736/badge)](https://www.bestpractices.dev/projects/14736)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/workpen/workpen/badge)](https://securityscorecards.dev/viewer/?uri=github.com/workpen/workpen)
[![FOSSA Status](https://github.com/workpen/workpen/actions/workflows/fossa.yml/badge.svg?event=push)](https://github.com/workpen/workpen/actions/workflows/fossa.yml)

Workpen runs one untrusted command in a project directory. By default
the child cannot read secret files, cannot read your home directory,
cannot use the network, and cannot write outside that directory.
The parent is trusted. This is not a VM.

## Install

Library:

```toml
workpen = { version = "0.8", features = ["gc", "nono"] }
```

CLI:

```bash
cargo install workpen-cli --locked
cargo binstall workpen-cli
```

`cargo binstall` fetches the GitHub release archive. 0.8.0 ships Linux and macOS, on x86_64 and arm64. The file inside each archive is `workpen`. <!-- x-release-please-version -->

Git pin:

```toml
workpen = { git = "https://github.com/workpen/workpen", tag = "v0.8.0", features = ["gc", "nono"] } <!-- x-release-please-version -->
```

MSRV is 1.95.

## CLI

After `cargo install workpen-cli --locked`, paste this in a terminal:

```bash
rm -rf /tmp/wp && mkdir /tmp/wp && cd /tmp/wp
printf 'SECRET=1\n' > .env
printf 'hello notes\n' > notes.md
ln .env notes.txt

workpen why --root . .env
workpen why --root . notes.txt
workpen why --root . notes.md
workpen run --root . -- /bin/cat .env
workpen run --root . -- /bin/cat notes.md
```

`.env` is dest-deny. `notes.txt` is a hardlink of `.env`, so dest-deny
too. `workpen run` on `.env` refuses and does not print the secret.
`notes.md` is ordinary: `why` prints allowed, `run` prints
`hello notes`. From this repo, `bash examples/dest-deny.sh` is the
same commands.

`workpen run` checks dest-deny before it starts the child. By default
the network is off. `$HOME` is not a workspace and not an extra root.
`--extra-root` is an explicit extra directory with read-write access,
so a write outside the workspace is possible only when you pass that
flag. PathGuard still refuses `/` and `$HOME` as either root.

`agent.lock` in the workspace adds dest-deny globs on top of the
built-in list. One glob per line. A line that starts with `#` is a
comment. Blank lines are skipped. A missing file means the built-in
denies only. A file that is only comments does not turn those denies
off.

```text
# extra dest-deny globs, one per line
# secrets/**
```

Unix `--tty` gives the child a PTY. Windows `--tty` refuses. A
spawn-only run is [examples/run-echo.sh](examples/run-echo.sh). On
Linux, if the kernel cannot hide secret names, `workpen run` does not
start the child.

On Windows, `why` and `run` treat `CON`, `PRN`, `AUX`, `COM1` through
`COM9`, `LPT1` through `LPT9`, `CONIN$`, and `CONOUT$` as devices,
including `\\.\` and `\\?\` forms and a path whose last name is one of
those. A trailing colon still counts (`CON:`, `CON::`). `NUL` stays
allowed, the same way `/dev/null` does on Unix.
`explain` reports allowed for that null device. `NUL.txt` stays an
ordinary file.

`--timeout 1s` stops the command when that time is up, including
startup on macOS. The process exits 124. Units are `s`, `m`, `h`,
and `d`.

Commands: `why`, `run`, `policy`, `gc`, `init`, `doctor`. `workpen --help` prints usage. `workpen doctor` reports whether this machine can jail a child and does not start one.

`workpen gc --max-age 7d` looks under `.workpen-worktrees`. A registered worktree from `git worktree add` that lives outside that directory is left alone. `--dry-run` prints what it would remove and does not delete. It does not clean `target/`.

Library hosts that still want those registered worktrees set `GcConfig.age_gc_registered`. The same run skips the primary checkout, a locked worktree, and a directory any process is using as its working directory. On Windows that list is the processes this user can read. If the list cannot be read, the tree stays. It reads status again before delete. Dry-run uses that same probe. Untracked directories outside `leftover_dir` are not candidates. `workpen gc` does not turn the flag on.

## Library

```rust
use std::path::Path;
use workpen::{DenyPolicy, is_path_denied};

let policy = DenyPolicy::default();
assert!(is_path_denied(Path::new(".env"), &policy));
```

Kernel jail (feature `nono`): `process_jail` then `run_child`. PathGuard
refuses `/` and `$HOME` as the workspace or extra-root. Leftover
worktree GC is feature `gc`.

Crate rustdoc is canonical: `workpen::threat_model`. The same contract
in one page is [docs/threat-model.md](docs/threat-model.md).

## Limits

- On Linux, if the kernel cannot hide secret names, `workpen run`
  does not start the child. Library `run_child` still starts the child
  (`RemountSkipped`) unless you opt into `with_require_dest_hide`.
- Nested Linux post-create (`mkdir x && touch x/.env`) is a launch
  snapshot. Workspace-root missing dest-deny names are occupied when
  remount applies.
- Windows WFP without admin is skipped (`WfpSkipped`). AppContainer
  with no network capabilities is the unelevated net deny.
  `read-only` and `strict` reuse one AppContainer per process.
  `workspace` does not create one. The workspace jail denies
  `.ssh`, `.aws`, `.gnupg`, `.azure`, `.config\gh`, `.docker`, and
  `.kube` with the restricted SID and restores them when the jail
  drops. `strict` and `read-only` can read the workspace
  (`read_only` cannot write it), `SystemRoot`, `System32`, and
  `ProgramFiles`. `spawn_reexec` keeps network open for a host
  that re-execs into one long-lived jail. A denied open of
  `\BaseNamedObjects` skips that ACE and is not printed. Git `usr\bin` tools run.
  The jail grants the restricted SID on that install's MSYS shared
  directory. MSYS creates the per-user section in that directory
  without a security descriptor, so the directory gets an inheritable
  allow for the user and `S-1-5-12`. For an MSYS program the
  jail patches named-pipe creation so the signal pipe includes
  that SID. The job
  blocks clipboard use.
  A session with no window station does not
  enforce that limit. The child still inherits the parent console
  when the parent has one.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). DCO sign-off required.
Security: [SECURITY.md](SECURITY.md).

## License

MIT OR Apache-2.0.
