# Changelog

All notable changes to bhshell. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-10-16

### Added

- `hunt` checks `pre2k`, `default-passwords` and `admin-twins`: pre-Windows 2000 computer accounts,
  accounts that may still have their default password, and admin accounts with a standard twin.
- `--names-only` prints just the object names, one per line, for feeding other tools.
- `owned` and `hvt` can mark many objects in one go.
- Progress is shown while large queries run.

### Changed

- The version now comes from the git tag. Installs from the repository show a development version
  such as `0.2.1.dev23+g1ca1496`.
- New startup banner.

### Fixed

- `hunt`: Tier Zero principals are left out of the `adcs` check.
- `hunt`: `pre2k` and `default-passwords` allow for the collector's time zone.
- `hunt`: sessions count as logons, and managed accounts are skipped in the password checks.
- `hunt`: domain-level GPO links are covered, template ESCs are filtered on the server and findings
  are no longer duplicated.
- `hunt`: summary counts and Path to T0 match the details.
- `search`: filters handle list, number and date properties, tags and backslashes.
- `lookup`: well-known SIDs resolve in every domain.
- `lookup`: full properties are fetched after a REST lookup.
- `computer`: broad groups are no longer unrolled in execution rights.
- Output: GPO links are named, `--all` CSV exports keep the summary and table titles no longer wrap.
- The shell starts when the session check hits a server error, and `--help` exits with 0.
- `cypher`: quoted, tab-separated and help options are parsed.
- `ou`: objects below a moved OU are counted once.
- AD CS: ESC13 requires a certificate that can be used for logon.
- AD CS: the CA host's own Administrators are left out of ESC7.
- `path`: wrapped links stay on the canvas in SVG output.
- `owned` / `hvt`: the selectors that keep an object tagged are named.

## [0.2.0] - 2026-10-15

### Added

- `gpo` command: where a GPO is linked, who it applies to and who outside Tier Zero can edit it.
- `ca` and `template` commands for enterprise CAs and certificate templates, with the ESC conditions
  each one meets.
- `cypher` shows and exports queries that return values instead of nodes.
- Views list the members of groups that hold inbound rights.

### Fixed

- AD CS: ESC3 enrollment agent links, the root CA issuer and the order ESCs are listed in.
- `path`: every shortest path is returned, not just one.
- `path`: Tier Zero searches stop at the first Tier Zero object.
- `path`: AD CS objects are accepted as endpoints.
- `ou`: moved objects are counted and placed once, and every object type is counted.
- Views list the most severe rights first, and owned principals first in members and execution
  rights.
- `owned` / `hvt`: the list has a row limit and says when it is empty, and removing a mark that is
  already gone mentions the pending analysis.
- `search`: `!=` and `!~` filters keep objects that lack the attribute.
- `hunt`: the default ERODC GetChanges right is ignored.
- `hunt`, `search`: `-d` warns when it matches no known domain.
- `lookup`: suggests the domain or GUID when GPOs, templates or CAs share a name.
- `lookup`: `NAME@DOMAIN` is treated as a user or group.
- `domains`: listed through the REST API, and domains that were never collected show as such instead
  of empty.
- `config`: query folders are saved as absolute paths.

## [0.1.1] - 2026-10-14

### Added

- `ou` command: OUs, containers and domains, the objects below them and the GPOs that apply.

### Fixed

- `path --owned` accepts a destination as a positional argument.

## [0.1.0] - 2026-10-13

First release: `user`, `computer`, `group`, `lookup`, `search`, `path`, `hunt`, `cypher`, saved
queries, `owned` / `hvt` marking and JSON, CSV, SVG and PNG exports.

[Unreleased]: https://github.com/kr0no/bloodhound-shell/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kr0no/bloodhound-shell/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kr0no/bloodhound-shell/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/kr0no/bloodhound-shell/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kr0no/bloodhound-shell/releases/tag/v0.1.0
