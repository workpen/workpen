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

`reqwest` is not a package in `Cargo.lock`. `aws-lc-sys` still is.
nono 0.80 depends on `sigstore-verify` with no feature to omit it, and
`sigstore-verify` 0.14 enables `rustls-webpki`'s `aws-lc-rs` feature
with no flag to turn that off. `cargo tree -p workpen-cli -e normal -i
reqwest --locked` exits non-zero. The same command for `aws-lc-sys`
exits 0.

Do not fork nono, vendor a stripped copy, or add a `[patch]`. Upstream
tracking is
[nolabs-ai/nono#2029](https://github.com/nolabs-ai/nono/issues/2029)
and
[nolabs-ai/nono#2030](https://github.com/nolabs-ai/nono/pull/2030).

## Pull requests

Use a Conventional Commits title (`feat:`, `fix:`, `docs:`, `chore:`).
One logical change per commit. Squash-merge is the default.
