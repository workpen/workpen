# workpen

Dest-deny and a per-child process jail. The parent is trusted. The
child is not. This is not a VM.

[![CI](https://github.com/workpen/workpen/actions/workflows/ci.yml/badge.svg)](https://github.com/workpen/workpen/actions/workflows/ci.yml)

## Install

Library (git pin until crates.io has the same tag):

```toml
workpen = { git = "https://github.com/workpen/workpen", tag = "v0.5.0", features = ["gc", "nono"] }
```

CLI:

```bash
cargo install --git https://github.com/workpen/workpen --tag v0.5.0 --locked workpen-cli
```

MSRV is 1.95.

## CLI

```bash
workpen why --root . -- .env
workpen run --root . -- /bin/echo ok
```

`workpen run` dest-denies argv first, then jails the child. Unix
`--tty` gives the child a PTY. Windows `--tty` refuses. A copy-paste
run is [examples/run-echo.sh](examples/run-echo.sh).

Commands: `why`, `run`, `gc`. There is no `--help`.

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

- Linux remount skip: `workpen run` does not spawn. Library `run_child`
  still starts the child (`RemountSkipped`) unless you opt into
  `with_require_dest_hide`.
- Nested Linux post-create (`mkdir x && touch x/.env`) is a launch
  snapshot. Workspace-root missing dest-deny names are occupied when
  remount applies.
- Windows WFP without admin is skipped (`WfpSkipped`). AppContainer
  with no network capabilities is the unelevated net deny.
- Do not vendor bubblewrap.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). DCO sign-off required.
Security: [SECURITY.md](SECURITY.md).

## License

MIT OR Apache-2.0.
