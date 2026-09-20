# Security

Report vulnerabilities privately. Do not file a public issue for an
unfixed security problem.

## Private reports

Use GitHub Security Advisories:

https://github.com/workpen/workpen/security/advisories/new

The maintainer aims to acknowledge a private report within 48 hours
and to ship a fix for a confirmed critical issue within 60 days when
a fix is possible in this crate.

## Scope

Workpen jails a **child process**. The parent is trusted. This is not
a VM. See [docs/threat-model.md](docs/threat-model.md).

In scope: dest-deny bypass, PathGuard escape, kernel-jail apply bugs
in this repository.

Out of scope: kernel bugs in Landlock, Seatbelt, or Windows; host
misconfiguration; running the parent as untrusted.

## Supported versions

Only the latest tagged release and `main` are supported.

## Credits

A private report that leads to a fix is credited in the GitHub Security
Advisory and in [CHANGELOG.md](CHANGELOG.md) unless you ask otherwise.
