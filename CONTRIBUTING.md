# Contributing

## Where to start

Open issues labeled
[good first issue](https://github.com/workpen/workpen/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
or
[help wanted](https://github.com/workpen/workpen/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).

Security reports go through [SECURITY.md](SECURITY.md), not public
issues.

## Local check

MSRV is 1.95. Edition 2024.

```bash
make check
```

That runs fmt, clippy (`-D warnings`), rustdoc, tests with features
`gc,nono`, `cargo deny`, and the workflow-trigger lock.

## DCO

Every commit must be signed off:

```bash
git commit -s
```

Use the email from `git config user.email`. CI rejects commits
without `Signed-off-by`.

## Tests

Land a failing corpus test before product-module changes. Corpus
tests live under `crates/workpen/tests/`.

Do not copy source from Bline, Grok, or Codex into this repo. Port
behavior by writing a new test here first.

## Identity

Read [CONSTITUTION.md](CONSTITUTION.md) before changing license, org,
CLI name, or kernel strategy. The CLI name is `workpen`. Do not
vendor bubblewrap.

## nono dependency

`crates/workpen/Cargo.toml` pins nono with `default-features = false`.
The CLI enables the `nono` feature. That feature is the kernel wrap.
Do not drop it, and do not turn nono's default features back on.

`reqwest` and `aws-lc-sys` are not packages in `Cargo.lock`.
nono 0.81 still depends on `sigstore-verify` 0.15.1, and nono has no
feature to omit it. `sigstore-verify` 0.15 dropped `rustls-webpki`'s
`aws-lc-rs` feature, so `aws-lc-sys` left the lock. `rustls-webpki`
0.103.16 stays, through `ring`.
`cargo tree -p workpen-cli -e normal -i reqwest --locked` exits
non-zero. The same command for `aws-lc-sys` exits non-zero.
`cargo tree -p workpen-cli -e normal -i sigstore-verify --locked`
still prints `nono`.

Do not fork nono, vendor a stripped copy, or add a `[patch]`. Upstream
tracking is
[nolabs-ai/nono#2029](https://github.com/nolabs-ai/nono/issues/2029)
and
[nolabs-ai/nono#2030](https://github.com/nolabs-ai/nono/pull/2030).

## Pull requests

Use a Conventional Commits title (`feat:`, `fix:`, `docs:`, `chore:`).
One logical change per commit. Squash-merge is the default.
