# Governance

## Maintainer

The current maintainer is [SebTardif](https://github.com/SebTardif).

The maintainer:

- merges pull requests
- cuts releases (release-please; a human must approve a release PR)
- decides constitution amendments (human-labeled PR to
  [CONSTITUTION.md](CONSTITUTION.md))
- publishes GitHub Security Advisories

## Decisions

Routine changes land through pull requests with CI green and DCO
sign-off. Disagreements are resolved by the maintainer.

Identity (license, org, CLI name, kernel strategy) changes only via
an amendment to [CONSTITUTION.md](CONSTITUTION.md).

## Releases

Versions follow Conventional Commits via release-please. crates.io
publish stays off until a human says launch. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Escalation

Report security issues per [SECURITY.md](SECURITY.md). Conduct
issues follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
