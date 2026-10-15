# bhshell usage guide

Full reference for [bhshell](../README.md). Install instructions and a quick start are in the README.

## Launching

Launcher options: `--url URL`, `-k/--insecure` (skip TLS verification; persisted like `--url`, `tls on` re-enables it), `--no-resume`,
`-c "CMD"` (repeatable, run commands and exit), `-s FILE` (run a script and exit), `--debug`.

Results go to stdout; status messages, warnings and errors go to stderr, so
`bhshell -c "hunt --json" > hunt.json` produces clean JSON. With `-c`/`-s` the exit code is
1 if any command failed (error, usage error or unknown command), 0 otherwise.

## Commands

| Category | Command | Purpose |
|---|---|---|
| Connection | `url [URL]` | Show or set the backend (default `http://127.0.0.1:8080/`) |
| | `tls [on\|off]` | TLS certificate verification |
| | `login [-u USER] [--otp CODE]` | Username/password → JWT (prompts for TOTP if MFA is enabled) |
| | `login --token [--token-id ID]` | API token (HMAC-signed requests) |
| | `logout` | Invalidate the session and delete the cached token |
| | `whoami` / `status` | Principal, roles, token expiry, server version, Cypher availability |
| | `config [KEY [VALUE]]` | Show or change persisted settings |
| Entities | `user NAME`, `computer NAME`, `group NAME`, `lookup NAME` | Triage summary + views |
| | `ou NAME [-t] [-c] [-G] [-I]` | OUs, containers and domains: tree, objects below, applied GPOs, inbound control; see [Exploring OUs](#exploring-ous) |
| | `gpo NAME [-l] [-c] [-I]` | GPOs: links, the users and computers they apply to, who can edit them; see [Exploring GPOs](#exploring-gpos) |
| | `ca NAME [-t] [-I]`, `template NAME [-I]` | AD CS: Enterprise CAs and certificate templates; see [Exploring AD CS](#exploring-ad-cs) |
| | `search [-t TYPE] [-d DOMAIN] FILTER ...` | List objects matching property filters |
| Cypher | `cypher [--json \| --names-only] [-o FILE] [-f FILE] QUERY` | Raw Cypher, rendered as node/edge tables, or as rows when it returns values |
| Marking | `owned list\|add\|remove`, `hvt list\|add\|remove` | Owned and Tier Zero objects; `add` and `remove` take several names or `-f FILE` |
| Analysis | `path SRC [DST] [--via X ...] [--exclude EDGE] [-g] [-p N]`, `path --owned [DST] [-g] [-p N]` | Attack paths: SRC → DST, SRC → Tier Zero, or everything owned → a target (Tier Zero by default); ordered by fewest actions |
| | `hunt [CHECK ...] [--all] [--list] [--owned \| --from NAME]` | Domain-wide weakness checks (summary, or details per check), optionally limited to what owned objects can do |
| | `domains`, `trusts` | Per-domain overview, and the trust map with SID-filtering status |
| | `query list\|show\|run NAME` | Saved Cypher queries (bundled, your own `.cyp` files, server-saved); see [Query library](#query-library) |

### Naming objects

`NAME` accepts `alice`, `alice@phantom.corp`, `PHANTOM\alice`, `FILESERVER01`, `FILESERVER01$`,
`FILESERVER01.phantom.corp`, a SID, or a distinguished name
(`CN=ALICE,OU=USERS,OU=TIER1,DC=PHANTOM,DC=CORP`). `-d/--domain` restricts the domain. With
`lookup`, `NAME@DOMAIN` means a user or a group; a computer is `FILESERVER01`,
`FILESERVER01$@phantom.corp` or its FQDN. When a name exists in more than one domain the command stops and lists the candidates (domain + SID);
re-run it with a qualified name. Same-named OUs in one domain are listed with their distinguished
names; pass the DN (or the object ID) to pick one.

### Views

With no view flags the **summary** is shown (distinguished name, Kerberoastable, AS-REP roastable,
delegation, password age, last logon, Tier Zero/owned, ...; risky values are highlighted).

| Flag | View |
|---|---|
| `-g, --groups` | Group memberships, direct and nested, with depth and the group it comes through |
| `-m, --members` | Group members, direct and nested (groups only) |
| `-O, --outbound` | Dangerous rights held over other objects (ACLs, credential access, delegation, ADCS, relay), direct or inherited through groups |
| `-I, --inbound` | Principals holding dangerous rights over the object |
| `-s, --sessions` | `HasSession` (user → computers, computer → users, group → members' sessions) |
| `-p, --local-admin, --privs` | `AdminTo`, `CanRDP`, `ExecuteDCOM`, `CanPSRemote`, `SQLAdmin`; computers also list who has these rights on them, with group members unrolled |
| `-G, --gpos` | GPOs that apply to the user or computer, and who outside Tier Zero can edit them (see [Exploring OUs](#exploring-ous)) |
| `-a, --all` | Summary plus every applicable view (for users and computers this includes `--gpos`) |
| `-n, --max-rows N` | Table rows shown per view (default `display_rows` = 100; `0` = all). A per-right count line is always shown |
| `--json` / `-o FILE.json\|.csv` | Raw JSON output / export (never capped by `--max-rows`) |
| `--names-only` / `-o FILE.txt` | Only the object names, one per line (see [Feeding other tools](#feeding-other-tools)) |

Rows are coloured by edge severity. `T0` and `owned` mark Tier Zero and owned counterparts, so an
owned principal with inbound control over a target stands out.

### Searching by attribute

`search` lists every object whose properties match all the filters given, as a table with the
filtered properties as columns:

```
search -t user hasspn enabled                          # Kerberoastable candidates
search -t user 'description~pass'                      # passwords in descriptions
search -t computer operatingsystem~2019 -d PHANTOM     # by OS, in one domain
search -t user pwdneverexpires 'pwdlastset<2019-01-01' -c lastlogon -o old.csv
search -t user enabled 'lastlogontimestamp<90d'        # enabled, no logon for 90 days
search name=sm_* !enabled                              # any type, disabled SM_ mailbox accounts
```

| Filter | Meaning |
|---|---|
| `ATTR` / `!ATTR` | true / false or unset |
| `ATTR=VALUE`, `ATTR!=VALUE` | equals / differs or unset (`null` = unset) |
| `ATTR~TEXT`, `ATTR!~TEXT` | contains / doesn't contain or unset |
| `ATTR<VALUE`, `>`, `<=`, `>=` | numbers, dates (`2020-01-01`) or ages (`90d` = 90 days ago) |

Text comparisons ignore case, and `*` at the start or end of a value is a wildcard. Quote filters
that contain spaces. `-t` takes any BloodHound type (`User`, `Computer`, `Group`, `OU`,
`GPO`, `CertTemplate`, ...; default: any), `-c ATTR,...` adds columns, `-l N` caps the results
fetched (default `max_results`, with a note when there are more) and `-n` the rows shown.
`--json` prints every property of each match. For OR conditions or relationships, use `cypher`.

### Feeding other tools

`--names-only` prints just the names of the objects a command lists, one per line, and `-o FILE.txt`
writes the same list to a file. It works with `search`, `hunt`, the entity views, `owned`/`hvt list`,
`cypher`, `query run` and `domains`. Names are BloodHound's (`ALICE@PHANTOM.CORP`,
`FILESERVER01.PHANTOM.CORP`), so computers are ready to use as targets and a name is never ambiguous
across domains. Every row is included, whatever `--max-rows` says.

Which column a table gives depends on its direction: `-I` lists the principals holding the rights,
`-O` the objects they are held over, an edge check of `hunt` the principals, and a node check the
objects themselves.

```
search -t computer enabled -d PHANTOM -o targets.txt     # hosts for netexec
hunt kerberoastable --names-only                          # roastable users
bhshell -c "group 'DOMAIN ADMINS' -m --names-only" > da.txt
```

The same file format goes back in through `owned add -f` and `hvt add -f`: one name per line, with
blank lines and lines starting with `#` skipped. Names can also be given together
(`owned add alice bob@phantom.corp`). A name that cannot be resolved is reported and the others are
still marked:

```
owned add -f cracked.txt
owned remove -t user alice bob
```

### Exploring OUs

`ou NAME` looks at an OU, a container (`CN=Users`) or a whole domain: where it sits, what is below
it, the GPOs that apply to it and who controls it. `NAME` is `WORKSTATIONS`,
`WORKSTATIONS@phantom.corp`, a distinguished name (`OU=COMPUTERS,OU=TIER1,DC=PHANTOM,DC=CORP`), an
object ID (GUID), or a domain (`phantom.corp`). `search -t OU` lists the OUs, and
`ou phantom.corp -t` shows them as a tree.

Several OUs often share a name (`USERS` under both `TIER0` and `TIER1`). The command then stops
and lists the candidates with their distinguished names; re-run it with the DN.

```
ou phantom.corp -t                                                # the whole OU tree of a domain
ou WORKSTATIONS@phantom.corp                                      # summary: location, objects below, linked GPOs
ou 'OU=SHARPHOUND,OU=COMPUTERS,OU=TIER0,DC=PHANTOM,DC=CORP' -G    # GPOs applied to everything in it
ou TIER1@phantom.corp -c -o tier1.csv                             # every object below it, with its location
ou TIER1@phantom.corp -I                                          # who can link GPOs to it or take it over
ou CN=Users,DC=phantom,DC=corp                                    # containers work too
computer DF-MS-SHS -G                                             # the GPOs that apply to one computer
user PHANTOM\alice -G                                             # ... or to one user
```

| Flag | View |
|---|---|
| (none) | Summary: distinguished name, whether the OU blocks GPO inheritance, creation date, location (`PHANTOM.CORP > TIER1`), users / computers / groups below it at any depth (enabled ones in brackets), other objects below it (certificate templates, CAs, ...; only when there are some), OUs and containers below it, Tier Zero and owned objects below it, and the GPOs linked to it (`(enforced)` marked) |
| `-t, --tree` | The OUs and containers below it, drawn as a tree with the object itself first |
| `-c, --contents` | Every object below it at any depth (OUs and containers excluded) |
| `-G, --gpos` | The GPOs applied to the objects in it, in precedence order, and who outside Tier Zero can edit them |
| `-I, --inbound` | Principals with dangerous rights over it (as for users) |
| `-a, --all` | Summary plus every view |
| `-d`, `-n`, `--json`, `-o FILE` | As for the other entity commands |

#### Tree

Each row counts everything below that entry, not only its direct children:

| Column | Meaning |
|---|---|
| Users (enabled), Computers (enabled), Groups | Objects anywhere below it; `20 (19)` is 20 users, 19 of them enabled |
| T0 below, Owned below | Tier Zero and owned objects anywhere below it |
| GPO links | GPOs linked directly to it |
| Blocks inheritance | The OU blocks GPO inheritance (OUs only) |
| T0, Owned | The entry itself is Tier Zero / owned |

Containers with no objects anywhere below them (mostly system containers such as `CN=System`
children) are left out, and a note says how many. OUs are always shown, even when empty. If the
server cannot run the aggregate queries the counts come from, the tree is still drawn, without
counts and without hiding anything.

#### Contents

Objects are listed Tier Zero first, then owned, then users, computers and groups, with disabled
accounts after enabled ones. **Location** is the path of sub-OUs from the explored one down to the
object (`COMPUTERS/SHARPHOUND` under `TIER0`), or `direct` for its direct children; **Depth**
counts the levels. The list stops at `max_results` objects, with a note giving the server's real
total; raise it with `config max_results N`, or use `-o FILE` to export what was fetched.

#### Applied GPOs

`-G` follows the OU chain from the domain down to the object (or to the explored OU, for `ou`)
and evaluates each GPO link on it the way Windows does:

* **Linked to** is where the link sits, from the domain down
  (`PHANTOM.CORP/TIER0/COMPUTERS/SHARPHOUND`): OU names such as `COMPUTERS` often repeat within a
  domain. `--json` and `-o` also give the OU's name.
* An OU that **blocks inheritance** stops the GPOs linked above it, unless the link is
  **enforced**. Such links are listed as `no (inheritance blocked at TIER0)`.
* Rows are in **precedence** order, the first one winning when two GPOs set the same thing:
  enforced links first (the one highest in the tree wins), then the other links from the closest
  OU up to the domain, then the links that do not apply.
* A GPO linked at several levels is applied once. Its later links are marked
  `yes (duplicate: already applied through PHANTOM.CORP)`.
* **Editable by (outside Tier Zero)** lists the principals outside Tier Zero with `GenericAll`,
  `GenericWrite`, `WriteDacl`, `WriteOwner` or `Owns` (and their limited-rights variants) over the
  GPO, owned ones first and marked `(owned)`. Editing a GPO runs code on every computer or user it
  applies to, so an owned principal here is a direct route to the objects below. The table shows
  three names per GPO; `--json` and `-o` have them all.
* **T0** and **Owned** mark GPOs that are Tier Zero or owned.

BloodHound does not collect GPO security filtering, WMI filters, loopback processing or the link
order within one OU, so a GPO listed as applying may still be filtered out on the host.

#### Where `ou` fits

* `hunt gpo-control` finds principals outside Tier Zero that can edit a GPO or link one to an OU.
  `ou NAME -G`, or `computer NAME -G` on a target, shows which of those GPOs reach it, and
  `gpo NAME` shows everything one of them reaches.
* `ou NAME -I` shows who holds `WriteGPLink` on an OU (they can link a GPO they control to it) or
  `GenericAll` / `WriteDacl` (control that extends to the objects inheriting the OU's ACEs).
* `path` already walks `GPLink` and `Contains` edges, so `path SRC TARGET` finds GPO-based routes;
  `ou` explains them.
* `ou ... -c -o FILE.csv` exports the scope of an OU (every object below it with its DN) for a
  report or a target list.

#### Data needed

The tree and the GPO links come from SharpHound's **Container** collection (`Contains` and
`GPLink` edges, `blocksinheritance` on OUs, `enforced` on links). A domain collected without it
has no OU data, and the views say so instead of showing empty results. Without Cypher, the REST
fallback gives the counts, the objects below an OU or a domain, and the GPOs linked to an OU or
above it (without enforcement or blocked inheritance); the tree and the GPOs applied to one object
need Cypher.

An object moved to another OU between two collections keeps both `Contains` edges in BloodHound,
so it shows up in two places. `ou` and `gpo` place it, and count it, once: in the container its
distinguished name names.

### Exploring GPOs

`gpo NAME` shows where a GPO is linked, which users and computers it applies to and who can edit
it. It is the next step after `hunt gpo-control`: once you know someone can edit a GPO, `gpo`
tells you what editing it gets you. `NAME` is the display name, `NAME@phantom.corp`, the
distinguished name (`CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=phantom,DC=corp`)
or the object ID. Display names often contain spaces, so quote them.

```
gpo 'Default Domain Policy' -d phantom.corp        # summary
gpo 'ENABLE AV@phantom.corp' -l                    # where it is linked and what each link reaches
gpo 'ENABLE AV@phantom.corp' -c -o enable-av.csv   # every user and computer it applies to
gpo 'ENABLE AV@phantom.corp' -I                    # everyone with rights over it, Tier Zero included
```

| Flag | View |
|---|---|
| (none) | Summary: distinguished name, SYSVOL path, creation date, where it is linked (`(enforced)` marked), the OUs where blocked inheritance stops it, the computers and users it applies to (enabled ones in brackets), how many of them are Tier Zero or owned, and the principals outside Tier Zero that can edit it |
| `-l, --links` | One row per link: whether it is enforced, the users and computers it reaches, the Tier Zero and owned ones among them, and the OUs that stop it |
| `-c, --affected` | Every user and computer it applies to: Tier Zero first, then owned, computers before users. **Location** is the path from the linked domain or OU down to the object's container (`PHANTOM.CORP/DOMAIN CONTROLLERS`) |
| `-I, --inbound` | Principals with dangerous rights over it (as for users) |
| `-a, --all` | Summary plus every view |
| `-d`, `-n`, `--json`, `-o FILE` | As for the other entity commands |

A link applies to the linked domain or OU and to everything below it, except below an OU that
blocks inheritance, unless the link is enforced. An object reached by two links is listed once,
under the closer one. Groups are left out, since GPOs only apply to users and computers. The
computer settings of a GPO run as SYSTEM on every computer in its scope, so a Tier Zero computer
there makes the GPO a route to Tier Zero.

BloodHound's own GPO panel also counts the objects placed directly in an OU that blocks
inheritance. Windows does not apply the GPO to them, and `gpo` does not count them, so its numbers
can be lower than BloodHound's for a GPO linked above such an OU. Security filtering and WMI
filters are not collected, as for `ou -G`.

The list stops at `max_results` objects, with a note giving the server's real total. Without
Cypher, the summary counts and the `-c` list come from BloodHound's REST endpoints (so they
include those extra objects, and have no location), and `-l` is not available.

### Exploring AD CS

`ca NAME` shows an Enterprise CA and `template NAME` a certificate template. `hunt adcs` lists the
ESC edges BloodHound found; these two commands show the CA and the template behind a finding, and
what a template allows when BloodHound found no edge. `NAME` is the name BloodHound shows
(`PHANTOM-DC01-CA@phantom.corp`, `USER@phantom.corp`; for templates the short name, not the
display name), the distinguished name or the object ID. `search -t EnterpriseCA` and
`search -t CertTemplate` list them.

```
ca PHANTOM-DC01-CA@phantom.corp                    # summary
ca PHANTOM-DC01-CA@phantom.corp -t                 # published templates and their ESC conditions
template ESC1@phantom.corp                         # one template
template WEBSERVER@phantom.corp -I                 # everyone with rights over it, Tier Zero included
```

| Flag | View |
|---|---|
| `ca` (none) | Summary: CA name and host name, user-specified SAN (`EDITF_ATTRIBUTESUBJECTALTNAME2`, ESC6), role separation, enrollment agent restrictions, web enrollment endpoints and whether they can be relayed to (ESC8), the computer hosting the CA and its admins outside Tier Zero (an admin of the host can forge certificates), whether the CA is trusted for NT authentication, the CA that issued its certificate, the published templates that meet ESC conditions, and who outside Tier Zero can enroll on it or manage it (`ManageCA`, `ManageCertificates`: ESC7) |
| `ca -t, --templates` | Every published template: schema version, whether its certificates can log on, whether the enrollee supplies the subject, manager approval, authorized signatures, the ESC conditions it meets and who outside Tier Zero can enroll in it. Templates that meet a condition and that someone can enroll in come first |
| `template` (none) | Summary: schema version, effective EKUs by name, authentication, enrollee-supplied subject, manager approval, authorized signatures, no security extension, validity, the CAs publishing it, the ESC conditions it meets, and who outside Tier Zero can enroll in it or rewrite it |
| `-I, --inbound` | Principals with rights over it (`Enroll`, `ManageCA`, `GenericAll`, ...), Tier Zero included |
| `-a, --all` | Summary plus every view |
| `-d`, `-n`, `--json`, `-o FILE` | As for the other entity commands |

The ESC conditions come from the template's settings. All but ESC4 need a certificate issued
without a manager's approval or an authorized signature (schema version 1 ignores signatures):

| Technique | Template condition |
|---|---|
| ESC1 | Logon certificate (Client Authentication, PKINIT, Smart Card Logon, Any Purpose or no EKU) and the enrollee supplies the subject |
| ESC2 | Any Purpose EKU, or no EKU |
| ESC3 | Certificate Request Agent EKU: an enrollment agent template |
| ESC4 | Someone outside Tier Zero can rewrite it (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `WritePKIEnrollmentFlag`, `WritePKINameFlag`) |
| ESC9 | Logon certificate without the security extension (`CT_FLAG_NO_SECURITY_EXTENSION`) |
| ESC13 | One of its issuance policies is linked to a group (`OIDGroupLink`) |
| ESC15 | Schema version 1 and the enrollee supplies the subject (CVE-2024-49019, fixed by the November 2024 update) |

A setting that was not collected never counts. A condition met is not an attack yet: the principal
must also be able to enroll in the template and on a CA that publishes it, and logon certificates
need a CA trusted for NT authentication. BloodHound checks all of that before adding an ESC edge.
It has no edge for ESC2 and ESC15, so `hunt adcs-templates` lists the templates open to them.

CA settings read from the CA host's registry show `not collected` when SharpHound could not read
them. ESC11 and ESC16 depend on CA settings BloodHound does not collect. Without Cypher, `ca` and
`template` show the object's own properties and `-I` falls back to REST; the ESC conditions, CAs and
enrollment rights need Cypher.

## Analysis

### Attack paths

```
path PHANTOM\svc_kerb_del 'domain admins@phantom.corp'                       # shortest path (BloodHound's native pathfinder)
path PHANTOM\svc_kerb_del                                                      # all shortest paths to any Tier Zero object
path --owned -o owned-paths.csv                                                # from every owned object to Tier Zero
path --owned FILESERVER01                                                      # from every owned object to another objective
path PHANTOM\svc_kerb_del --via ADMINSERVER01 'domain admins@phantom.corp'     # through ADMINSERVER01 on the way
path PHANTOM\svc_kerb_del --via ADMINSERVER01 --via KRB-DEL-01                 # several steps, then on to Tier Zero
path PHANTOM\svc_kerb_del --exclude sessions --exclude adcs                    # ignore techniques you can't or won't use
```

`--via` steps are visited in the order given. Each leg is searched on its own and the results are
chained, so every leg is a shortest path but the whole route may not be the shortest one through
those steps. If a leg has no path, the route stops there with a note.

`--owned` takes an optional destination: with none it heads for Tier Zero, with one for that
objective (a file server, a database host, a target user).

`--exclude EDGE` drops edges the search may not use, so the paths left are ones you can actually
walk given the techniques available to you. It takes edge groups (`sessions` (`HasSession`, which
is a point-in-time snapshot that may be gone), `acl`, `exec`, `delegation`, `adcs`, `relay`,
`trusts`) repeat the flag for several. With `--exclude` the Cypher pathfinder is always used (the
native one can't leave edges out).

Disabled users and computers can't log on, so a path only goes through one when the hop reaching it
grants the right to re-enable it: `GenericAll`, `GenericWrite`, `WriteAccountRestrictions`
(includes `userAccountControl`), `Owns`, `WriteDacl` or `WriteOwner`, held directly or through a
group. Such objects are marked `[disabled]`. Paths needing any other disabled object are skipped
and the objects listed in a note; the search then finds the next-shortest path around them.
`--include-disabled` turns this off. The source and an explicit destination are always allowed.

Paths are printed as hop chains, coloured by edge severity:

```
SMSASIMON@PHANTOM.CORP ─AddAllowedToAct→ JONAS-TEST-MS01.PHANTOM.CORP ─HasSession→ ADMINISTRATOR@PHANTOM.CORP [T0]
```

A header line gives the number of paths, the shortest length, the fewest actions and the
distinct first hops. Paths are ordered by the fewest *actions* first (hops the operator has to
carry out, counting `MemberOf`, `Contains`, `GPLink` and `DCFor` as free since rights flow along
them on their own) then by the fewest session-dependent hops, then by length. The shortest path is
not always the quietest, so the one listed first is the one that asks the least of you.

`-g/--graph` draws them as one graph instead, top to bottom, the way the BloodHound UI shows a
pathfinding result: each object is a box (Tier Zero and owned ones marked, `--via` steps with a
double border), each edge an arrow labelled with the right. Shared hops are drawn once, so branches
and merges are easy to see. If the graph is wider than the terminal, the list is shown instead.

When there are several paths, `-g` first prints the numbered list and asks which ones to draw
(`2`, `1,3`, `2-4`; Enter draws them all). `-p/--pick N` makes the same choice without asking, and
also narrows the list, `--json` and `-o`: `path --owned -g -p 2`. With `-c`/`-s` the shell never
asks.

```
           ╭────────────────╮
           │ ● SVC_KERB_DEL │
           ╰────────┬───────╯
                    │ MemberOf
                    ▼
           ╭────────────────╮
           │ ● DOMAIN USERS │
           ╰────────┬───────╯
                    │ AdminTo
                    ▼
           ╭─────────────────╮
           │ ● ADMINSERVER01 │
           ╰────────┬────────╯
      ╭ HasSession ─┤
      │             ╰ HasSession ─╮
      ▼                           ▼
╭───────────╮              ╭─────────────╮
│ ● ANDY T0 │              │ ● FABIAN T0 │
╰─────┬─────╯              ╰──────┬──────╯
      │             ╭─ MemberOf ──╯
      ╰─ MemberOf ──┤
                    ▼
         ╭────────────────────╮
         │ ● DOMAIN ADMINS T0 │
         ╰────────────────────╯
```

Sources and targets can be users, computers, groups, domains, OUs, GPOs, certificate templates
or CA objects (Enterprise, root and AIA CAs, the NTAuth store). Owned objects that are
already Tier Zero are listed in a note.

`-o FILE.svg` draws the paths shown (see `-n`) as one diagram for reports, with a legend and no
title so the report can caption it. Word inserts SVG directly. The layout (horizontal, vertical
or wrapped into rows) is picked to print as large as possible on a portrait page;
`--svg-layout` forces one.

`-o FILE.png` writes the same diagram as a PNG at twice the size (`--png-scale N`), tagged with
a matching DPI so Word inserts it at the same size as the SVG.

### Hunt checks

`hunt` runs every check and prints a summary; `hunt CHECK ...` or `hunt --all` shows the rows.
`-d DOMAIN` (FQDN or NetBIOS) scopes the checks, and `hunt --list` describes them.

| Severity | Checks |
|---|---|
| critical | `dcsync` (replication rights outside Tier Zero), `tier-zero-control` (ACL, delegation, credential-read or execution rights on Tier Zero objects from outside it), `broad-rights` (Everyone / Anonymous / Authenticated Users / Domain Users / Domain Computers / Users / Pre-Windows 2000 Compatible Access with control or execution rights), `adcs` (ESC*, ESC8 relay, GoldenCert) |
| high | `adcs-ca-control` (ESC7), `adcs-templates` (ESC2, ESC15), `adcs-pki-control` (ESC4, ESC5), `kerberoastable`, `asreproast`, `t0-sessions`, `cred-readers` (LAPS / gMSA / sMSA), `passwords-in-attributes`, `object-takeover` (Shadow Credentials, targeted Kerberoasting, RBCD, ESC14), `gpo-control`, `relay`, `foreign-access`, `unconstrained` (outside Tier Zero), `sidhistory`, `trust-sid-filtering` |
| medium | `constrained` (with protocol transition), `reenable`, `impersonable-admins`, `ntlm-hardening`, `stale-passwords` (`--days`, default 5 years), `pwd-not-required`, `legacy-os` |
| low | `admincount-orphans`, `no-laps` |
| info | `decoys` (possible honeytokens) |

Notes on some checks:

- `kerberoastable` and `asreproast` list first the users with a path to Tier Zero (one `allShortestPaths`
  query, skipped above 500 users and in the summary), then those whose tickets use RC4 (`Enc types`).
- `t0-sessions` lists Tier Zero or adminCount users logged on to computers outside Tier Zero:
  where to dump credentials.
- `passwords-in-attributes` reports `userPassword`, `unixUserPassword`, `unicodePwd` and
  `msSFU30Password`, and descriptions containing *pass*, *pwd*, *mdp*, *contraseña*... (case-insensitive).
- `impersonable-admins` lists Tier Zero users that are not marked sensitive and not in Protected
  Users: the ones constrained delegation, RBCD and S4U can impersonate.
- `relay` and `ntlm-hardening` rely on the NTLM properties SharpHound collects (`smbsigning`,
  `webclientrunning`, `ldapsigning`, `ldapsepa`). Without them they report nothing.
- `decoys` lists enabled users that look attractive (SPN, no pre-authentication, adminCount) but
  have never logged on. Check them before roasting or using them.
- `legacy-os` includes Windows 10 (end of support October 2025), except the LTSC/LTSB editions.
- `adcs-templates` lists the published templates that principals outside Tier Zero can enroll in
  and that meet the ESC2 or ESC15 conditions (see [Exploring AD CS](#exploring-ad-cs)). Enrollment
  rights on the CA are not checked.
- `adcs-pki-control` lists write and ownership rights from outside Tier Zero over certificate
  templates (ESC4) and over CA, root CA, AIA CA, NTAuth store and issuance policy objects (ESC5).
  BloodHound only adds an `ADCSESC4` edge when the rest of the chain holds.

#### From owned objects

`hunt --owned` runs only the checks marked *scoped* in `hunt --list`, restricted to rights held by
the owned objects and every group they belong to (the right is often held by a group). `hunt --from NAME`
does the same from one object. Detailed tables get a `From` column with the owned objects behind
each row, and `t0-sessions` becomes "computers where you can execute code that have a privileged
session". Naming a check that is not scoped (`hunt kerberoastable --owned`) is an error.

```console
[bh: shell] > hunt --owned
[bh: shell] > hunt tier-zero-control cred-readers --owned
[bh: shell] > hunt --all --from t1_tonymontana@phantom.corp
```

When a check hits `max_results`, the summary shows the server-side total (`~9985`) from a
`count()` query. For checks that drop Tier Zero objects (`unconstrained`, `admincount-orphans`,
`no-laps`) the total excludes them too.

### Domains and trusts

`domains` lists every domain with its SID, functional level, user/computer counts (enabled in
brackets), group and Tier Zero counts, and last collection time.

`trusts` lists each trust as **Trusting (source) → Trusted (target)**: principals of the *trusted*
domain can access the *trusting* one. The SID filtering column shows `enforced`, `DISABLED`,
`unknown (default: enforced)` or `n/a (same forest)`. SID filtering is on by default for cross-forest
trusts and off within a forest, so a missing property is not reported; only same-forest trusts, an
explicit `spoofsidhistoryblocked = false`, or abuse edges are. The abuse edges BloodHound adds
(`SpoofSIDHistory`, `AbuseTGTDelegation`) are listed against the trust they abuse.

### Query library

`query list` shows every saved query, `query show NAME` prints one and `query run NAME` runs it
(with `--json` and `-o FILE` like `cypher`). Queries come from four places; when two share a name,
the later one wins:

1. **Bundled**: the queries shipped in `bhshell/library/`.
2. **Your own**: `~/.bhshell/queries/*.cyp` (or `$BHSHELL_HOME/queries/`).
3. **Extra folders**: the folders listed in `config query_dirs`, in order.
4. **The server**: queries saved in the BloodHound UI, listed as `server:<name>`.

#### Adding your own queries

Save each query in its own `.cyp` file in `~/.bhshell/queries/` (create the folder if it does not
exist):

```
// name: stale-admins
// description: Enabled adminCount users who have not logged on for a year
MATCH (u:User)
WHERE u.admincount = true AND u.enabled = true AND u.lastlogontimestamp < (datetime().epochseconds - 31536000)
RETURN u
```

* The `// name:` and `// description:` header lines are optional. Without a name, the file name is
  used (`stale-admins.cyp` → `stale-admins`). The description is shown by `query list`.
* The query can return nodes or paths (`RETURN u`, `RETURN p`), shown as node and edge tables,
  or values (`RETURN u.name AS name, u.pwdlastset AS pwd`, `count(u)`), shown as a table of rows.
* Queries are picked up on the next `query` command, with no restart. Tab completion lists them
  after `query show` and `query run`.
* A file with the same name as a bundled query replaces it.

Test a query first with `cypher -f my-query.cyp`, which runs a file without saving it.

#### Keeping queries in other folders

To use queries from a folder of your own (a team repository, a folder per engagement, ...), list
it in the `query_dirs` setting. Separate several folders with `:` (`;` on Windows), as in `PATH`:

```
config query_dirs ~/git/team-queries:~/engagements/acme/queries
config query_dirs ''                 # back to the default (no extra folders)
```

Only the `.cyp` files directly inside each folder are loaded (not subfolders). A folder that does not
exist is reported in a note under `query list`. A relative folder (`queries`) is saved as an absolute
path, so the setting works wherever bhshell is started.

## How it works

```
bhshell/cli.py          command-line options
bhshell/client/         HTTP transport: JWT and HMAC auth, retries, error mapping, pagination
bhshell/models/         Node/Edge/Graph, summaries per object type, view results
bhshell/queries/        Cypher templates, edge taxonomy, and the logic behind each command
bhshell/render/         rich tables and panels, path graphs, SVG/PNG, JSON/CSV export
bhshell/shell/          the cmd2 app and one command set per area
```

Everything goes through `POST /api/v2/graphs/cypher`. If Cypher is disabled, the views fall back
to the per-entity REST endpoints, which can't tell ACL rights apart (they all show as `Controls`).
The OU tree and the applied GPOs have no REST equivalent; without Cypher, `ou` shows the counts,
the objects below an OU and the GPOs linked to it or above it, and `gpo` shows BloodHound's own
counts and list of the objects a GPO applies to. `domains` lists the domains with their user,
computer and group counts (enabled and Tier Zero counts need Cypher); `trusts`, `search`, `hunt` and
`path` to Tier Zero need Cypher.

Rights are queried per severity, each with its own `LIMIT max_results`, so a flood of low-impact
edges can't push `GetChangesAll` out of the result. When a query hits the limit, the shell asks
the server for the real total and says so in a note.

A 401 logs the shell out and deletes the cached token (the prompt turns red). Only GET/PUT/DELETE
are retried; a slow Cypher query runs once and fails after `read_timeout`.

## Files and security

Stored in `~/.bhshell/` (override with `BHSHELL_HOME`):

* `config.toml` holds the URL, TLS setting, timeouts, `page_size`, `max_results` (path cap per
  query), `display_rows` (table rows per view), `query_dirs` (extra query folders) and the last
  username. Values are validated:
  timeouts, `page_size` and `max_results` must be at least 1, `display_rows` at least 0 (0 = all).
* `session.json` holds the cached JWT (mode `0600`), resumed at startup if it is still valid. Set
  `config cache_session false` to disable this.
* `history` is the command history.
* `queries/` holds your own `.cyp` queries (see [Query library](#query-library)).
* CSV exports prefix cells starting with `=`, `+`, `-` or `@` with `'`. AD data such as descriptions
  and GPO names is attacker-controlled and could otherwise run as a spreadsheet formula. Names are
  also never interpreted as terminal markup.

Passwords and API keys are never accepted as arguments, so they never end up in history. They are
prompted for, or read from `BH_PASSWORD`, `BH_TOKEN_ID` and `BH_TOKEN_KEY`.

cmd2 output redirection (`>`, `|`) is **disabled**, because Cypher uses those characters and a query
could otherwise be piped to a system shell. Use `-o FILE` instead.

## Compatibility

bhshell targets BloodHound CE v9 and is tested against v9.7.1 and v9.8.0. It relies on the `Tag_Tier_Zero`
and `Tag_Owned` kinds and on the privilege-zone (`asset-group-tags`) API, so releases before
privilege zones are not supported. The object counts of `ou` use aggregate Cypher
(`RETURN labels(n), count(n)`); a server that rejects it still gets the views, without counts.

`owned add` / `hvt add` create a selector named `bhshell: <object>` in the Owned label or the
Tier Zero tier, one per object when several are given. `remove` only deletes selectors seeded with that object alone, so nothing else
gets unmarked. Changes show up after BH's next analysis run (about a minute): until then a removed
object still shows as owned, and a second `remove` says so. An object marked by a rule-based
selector can only be unmarked in the BH UI (Privilege Zones).
