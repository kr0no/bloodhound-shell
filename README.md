# bhshell

![PyPI Status](https://img.shields.io/pypi/status/bhshell)
[![PyPI version](https://img.shields.io/pypi/v/bhshell)](https://pypi.org/project/bhshell/)
[![CI](https://github.com/kr0no/bloodhound-shell/actions/workflows/ci.yml/badge.svg)](https://github.com/kr0no/bloodhound-shell/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/kr0no/bloodhound-shell/blob/main/LICENSE)

An interactive command-line shell for BloodHound. Look up Active Directory objects,
hunt for weaknesses and find attack paths from the terminal, without opening the web UI.

## Installation

Requires Python 3.11+ and a BloodHound CE v9 server (tested on v9.7.1).

```bash
pipx install bhshell     # recommended
# or
pip install bhshell
```

## Quick Start

```console
$ bhshell --url http://127.0.0.1:8080

[bh: shell] > login -u admin
[+] Logged in as admin on 127.0.0.1:8080

[bh: shell] > hunt
  Severity   Check            Count   Example                      Description
  critical   dcsync           4       DCSYNCERS@PHANTOM.CORP       Non-Tier-Zero principals with replication rights
  critical   adcs             95      ALICE@PHANTOM.CORP           AD CS escalation paths (ESC*, GoldenCert)
  high       kerberoastable   2       ADMINISTRATOR@PHANTOM.CORP   Kerberoastable users
  ...
[*] Details: 'hunt CHECK' (e.g. 'hunt dcsync'), or 'hunt --all'.

[bh: shell] > user PHANTOM\svc_kerb_del --all -o svc_kerb_del.csv

[bh: shell] > ou phantom.corp -t

[bh: shell] > computer DF-MS-SHS -G

[bh: shell] > gpo 'ENABLE AV@phantom.corp' -c

[bh: shell] > path --owned -g
```

The same commands run non-interactively for scripting: `bhshell -c "hunt --json" > hunt.json`.

## What it does

| Command | Shows |
|---|---|
| `user`, `computer`, `group`, `lookup` | Kerberoastable / AS-REP roastable, delegation, password age, Tier Zero and owned flags, plus group nesting, inbound/outbound ACL control, sessions and local admin rights |
| `ou` | OUs, containers and whole domains: the OU tree with object, Tier Zero and owned counts, every object below an OU, the GPOs that apply (enforced links, blocked inheritance) and who outside Tier Zero can edit them, and who controls the OU; `user`/`computer -G` shows the GPOs applied to one object. Same-named OUs are picked by distinguished name |
| `gpo` | Where a GPO is linked, the users and computers it applies to (blocked inheritance and enforced links taken into account) and who outside Tier Zero can edit it |
| `ca`, `template` | Enterprise CAs and certificate templates: the ESC conditions a template meets (ESC2 and ESC15 included, which BloodHound has no edge for), the CA's host and settings (ESC6, ESC8), and who can enroll, manage (ESC7) or rewrite them (ESC4) |
| `search` | Objects matching property filters (`search -t user hasspn enabled`), with dates, ages (`90d`) and wildcards |
| `path` | Shortest paths to a target or to Tier Zero, from everything owned, or through `--via` steps; printed as hop chains, a terminal graph, or SVG/PNG for reports |
| `hunt` | Domain-wide checks by severity: DCSync, control of Tier Zero, AD CS (ESC*), Kerberoasting, privileged sessions, LAPS/gMSA readers, passwords in attributes or still at their default (pre-Windows 2000 computers, unused accounts, admin accounts with a standard twin), takeover primitives (Shadow Credentials, RBCD), GPO control, NTLM relay, trusts, possible honeytokens...; `hunt --owned` limits them to what your owned objects can do |
| `cypher`, `query` | Raw Cypher, and a library of saved queries: bundled, your own `.cyp` files (`~/.bhshell/queries/` or any folder set with `config query_dirs`) and those saved on the server |
| `owned`, `hvt` | Mark or unmark owned and Tier Zero objects, by name or from a file of names |
| `domains`, `trusts` | Per-domain counts, and the trust map with SID filtering status |

To add your own query, save it as a `.cyp` file in `~/.bhshell/queries/` and run it by name:

```console
$ cat ~/.bhshell/queries/stale-admins.cyp
// description: Enabled adminCount users who have not logged on for a year
MATCH (u:User) WHERE u.admincount = true AND u.enabled = true
  AND u.lastlogontimestamp < (datetime().epochseconds - 31536000) RETURN u

[bh: shell] > query run stale-admins -o stale-admins.csv
```

See [Query library](https://github.com/kr0no/bloodhound-shell/blob/main/docs/USAGE.md#query-library) for the format and for
keeping queries in other folders (a team repository, one folder per engagement).

Most commands take `--json` and `-o FILE` (JSON or CSV), and those that list objects also take
`--names-only` or `-o FILE.txt` for a plain list of names to hand to other tools. Login works with a password (plus MFA) or
an API token; secrets are prompted for or read from the environment, never passed as arguments.

## Documentation

The full usage guide (every command, view flag, search filter, path option, hunt check and
configuration setting) is in [docs/USAGE.md](https://github.com/kr0no/bloodhound-shell/blob/main/docs/USAGE.md).
Inside the shell, run `help` or `help <command>`.

## Contributing

Bug reports and pull requests are welcome at
[github.com/kr0no/bloodhound-shell/issues](https://github.com/kr0no/bloodhound-shell/issues).

```bash
git clone https://github.com/kr0no/bloodhound-shell.git
cd bloodhound-shell
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pre-commit install
python -m pytest
```

Without a server, `pytest` runs only the offline tests. The rest run against a BloodHound CE
instance loaded with the [sample data](https://bloodhound.specterops.io/get-started/quickstart/ce-ingest-sample-data):

```bash
export BHSHELL_TEST_URL=http://127.0.0.1:8080 BH_USER=admin BH_PASSWORD='...'
python -m pytest -m live
```

They only read from the server and never touch `~/.bhshell`.

## License

Distributed under the MIT License. See
[LICENSE](https://github.com/kr0no/bloodhound-shell/blob/main/LICENSE) for details.

BloodHound is a trademark of SpecterOps. bhshell is an independent project and is not affiliated
with or endorsed by SpecterOps.
