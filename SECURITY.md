# Security policy

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/bhshell/) gets security fixes.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/kr0no/bloodhound-shell/security/advisories/new),
or by email to kr0no@ka0labs.net if you can't use GitHub.

Include the bhshell version (`bhshell --version`), the BloodHound version, and the steps or data
needed to reproduce it. I'll reply within a week, and credit you in the release notes unless you
would rather not be named.

## Scope

In scope, bugs in bhshell itself, for example:

- leaking the session token, credentials or config stored under `~/.bhshell`
- TLS verification being skipped when it should not be
- data collected from Active Directory (names, descriptions and other attributes an attacker can
  set) that injects terminal escapes, CSV formulas or SVG content into bhshell's output or exports

Out of scope: bugs in the BloodHound server, the collectors or the API. Report those to
[SpecterOps](https://github.com/SpecterOps/BloodHound/security).
