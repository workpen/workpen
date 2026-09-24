# Roadmap

This is a near-term map, not a promise. Hosts should read
[docs/threat-model.md](docs/threat-model.md).

## Near

- Keep dest-deny, PathGuard, leftover GC, and per-child kernel jail
  as the library surface. 0.5.0 is the published crate.
- Keep Linux remount occupy for missing dest-deny basenames when
  remount applies. Nested post-create stays a snapshot.

## Medium

- crates.io 0.5.0 is already published through Trusted Publishing
  (`publish-crates.yml`). Further publishes wait on a release PR.
- Keep the public README and GitHub About current. Do not re-enable
  stealth.

## Long

- 1.0 freeze of `KernelError` / `KernelApply` after a human yes.
  New variants are breaking even in 0.x.

## Out of scope until a host asks

- Vendoring bubblewrap
- Default Docker / Apple `container` / Hyper-V `run_child`
- Adding `.git` to `default_secret_denies()`
