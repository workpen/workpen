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
`gc,nono`, `cargo deny`, workflow-trigger lock, and the stealth
assert.

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

Do not dest-parent-copy from Bline, Grok, or Codex.

## Identity

Read [CONSTITUTION.md](CONSTITUTION.md) before changing license, org,
CLI name, or kernel strategy. The CLI name is `workpen`. Do not
vendor bubblewrap.

## Pull requests

Use a Conventional Commits title (`feat:`, `fix:`, `docs:`, `chore:`).
One logical change per commit. Squash-merge is the default.
