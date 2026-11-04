# Cross-domain trust support for MSSQLHound

## Context

MSSQLHound only works with one domain today:
- `ad.Client` searches only `domainToDN(--domain)`.
- Every LDAP client uses `--dc` (`collector.go:269`).
- `ResolveName` drops the `DOMAIN\` prefix (`ad/client.go:895`).
- Trusted-domain SIDs are never resolved.
- Trusted-domain `WINDOWS_GROUP` logins are classified as machine-local groups (`collector.go:3281`, `:4150`).
- Linked servers inherit the *source* server's domain (`:4897`). `tryResolveSID` and `lookupSPNsForServer` ignore `server.Domain`.

Goal, using the decisions you made:

| Option | Behaviour |
|---|---|
| Always on, passive | Read the home domain's trust objects, using a home DC we already bind to, with no new hosts. Trusted-domain logins then get correct SID-keyed AD nodes, names, and local/domain classification. |
| `--follow-trusts` | Also bind to DCs of domains that trust us. Resolve principals there, enumerate their MSSQL SPNs, and collect their SQL Servers. |
| `--trust-depth N` (default 1) | 1 means direct trusts. More than 1 crawls *transitive* trusts only. |
| `--domain-dc dns=host[,…]` | DC overrides for proxy/SOCKS setups. |

Credentials: the home credentials are reused.

## Design

### 1. `internal/ad` (new file `trusts.go`, small edits to `client.go`)

- **`types.DomainInfo{DNSName, NetBIOSName, SID string; Direction, Type, Attributes int}`** goes in `types.go`.
- **`DomainIdentity()`** makes three queries:
  1. a base search on `baseDN` for `objectSid`;
  2. RootDSE `configurationNamingContext`;
  3. a one-level search under `CN=Partitions,<cfg>` with `(&(objectClass=crossRef)(nCName=<baseDN>))` for `nETBIOSName`.
- **`EnumerateTrusts()`** does a one-level search under `CN=System,<baseDN>` with `(objectClass=trustedDomain)`. It reads `trustPartner`, `flatName`, `securityIdentifier` (via `decodeSID`), `trustDirection`, `trustType` and `trustAttributes`.
  - The pure function `parseTrustEntry` does the parsing.
  - Downlevel trusts (`trustType` 1) put a NetBIOS name in `trustPartner`, so they are kept for identity but never used as a DNS name.
  - Types 3 and 4 (non-AD) are skipped.
- **`DomainSIDOf(sid)`** is exported. It turns `S-1-5-21-a-b-c-RID` into `S-1-5-21-a-b-c` and returns "" otherwise.
- **Root-cause fix to `Connect()`:** remember the first connection error and return it on later calls. Today a shared client whose bind failed binds again on every call, which is a lockout risk.
- **Root-cause fix to `ResolveComputerSID`:** strip an FQDN to its first label before building `sAMAccountName=<name>$` (`client.go:1022`). Today FQDN hosts never match.
- **Credential domain vs. target domain:** new `SetCredentialDomain(dns)`. It defaults to `c.domain`, so nothing changes until it's set.
  - `simpleBindNames` makes its first `user@` guess with `credDomain`.
  - The Windows SSPI bare-user path (`gssapi_windows.go:32`) uses `credDomain`.
  - `ntlmBind` uses the pure function `ntlmBindIdentity(user, credDomain, targetIsHome, hasHash)`:
    - target is home: exactly today's call;
    - cross-domain with a password: username `user@<credDomain>`, empty domain. go-ntlmssp `GetDomain` treats `@` as `domainNeeded=false` and sends an empty TargetName plus the UPN, which the reviewer confirmed in `bind.go:417/522` and `authenticate_message.go:102`;
    - cross-domain with an NT hash: a clear "unsupported, use -k or a password" error that is not an auth error. `ProcessChallengeWithHash` always takes the DC's TargetName.

### 2. `internal/collector/domains.go` (new): registry and per-server client set

- **`domainRegistry`** has an RWMutex and is keyed by SID, upper-case NetBIOS name and lower-case DNS name. Each entry is `{DomainInfo, DC, isHome, queryable, disabled}`.
  - `domainForSID`, `domainForName` (accepts `NETBIOS\x`, `dns\x` and `x@dns`) and `domainForHost` (longest matching DNS suffix). All comparisons are case-insensitive.
  - `disable(domain, reason)` is a circuit breaker for trusted domains only.
- **`isKnownDomainSID(sid, info)`** is true if any of these hold:
  - `HasPrefix(sid, info.DomainSID+"-")` (today's check);
  - `DomainSIDOf(sid) == DomainSIDOf(info.ComputerSID)`;
  - the registry has the SID's domain.

  `DomainSID` itself is left unchanged. With an empty registry the result is identical to today.
- **`domainClientSet`**: one per `processServer` call and one per `createADNodes` call, never shared across goroutines.
  - `forDomain(d)` creates clients lazily and closes them with `defer set.Close()`.
  - For trusted domains it connects eagerly. On failure it calls `registry.disable(d)` and returns nil, so later servers skip the dead DC instead of paying up to 90s of dial time each.
- **`resolveSIDAcrossDomains` / `resolveNameAcrossDomains(set, …)`:**
  - They route by `domainForSID` / `domainForName`.
  - A foreign SID or name goes only to its own domain's client (if queryable), otherwise it's a miss. It is **never sent to the home client**, which would match the foreign-security-principal stand-in object.
  - Results with `ObjectClass == ""` are discarded.
  - Unregistered qualifiers, such as alternate UPN suffixes, keep today's home-client behaviour.
- **`newADClient(domain)`:**
  - Use `--dc` for the home domain and for any *unregistered* domain (today's behaviour).
  - Use the registry DC (`--domain-dc`, or "" for SRV) only for registered trusted domains.
  - Compare against home with `EqualFold`.
  - Set `credDomain` to the UPN suffix of `--ldap-user`, or the home DNS name.
  - Return nil when the domain is disabled.
- **`setLDAPAuthFailed()` becomes `setLDAPAuthFailed(domain)`:**
  - Home, or `""`, sets today's global flag.
  - A trusted domain is disabled only in the registry.
  - The call sites at 1270, 1371, 1459, 1991, 2139, 2349, 2382, 2428, 2554, 3161 and 5034 pass the domain they actually used.
  - 1648 stays global, but is skipped once a home LDAP bind has succeeded (`homeBindOK`), because that proves the password. Otherwise every "login failed" from a trusted SQL Server would switch LDAP off.
  - 1365 and 1455 (the ADSI fallback) apply to the home domain only, because ADSI hard-codes `config.Domain`.
- **`discoverDomains(homeClient)`** is called once, in `buildServerList` after domain auto-detection. It reuses `sharedADClient` when it exists, and only runs when `Domain != "" && (!DomainEnumOnly || FollowTrusts)`. Nothing uses the registry otherwise, so `TestRunDomainEnumOnlySkipsCollection` does no new I/O.
  1. Home: `DomainIdentity` and `EnumerateTrusts`, then register each domain.
     - On a home auth error: `setLDAPAuthFailed(home)` and stop. No trusted bind ever happens before a successful home bind.
     - On any other error: log a warning and carry on with an empty registry, so behaviour stays as today.
  2. With `FollowTrusts`, run a BFS up to `TrustDepth` over trusts with `trustDirection` 1 or 3, meaning the partner trusts us. Hops past the first need transitive trust attributes (0x8 or 0x20, and not 0x1).
     - Connect once and confirm `DomainIdentity`.
     - Read the domain's trusts if depth < N.
     - Mark it `queryable`, or disable it.
  3. Log a domain table at info level.

### 3. Collector call sites (`collector.go`)

- **`serverDomain(server)`**, in this order:
  1. `domainForHost(hostname)`;
  2. `server.Domain`;
  3. today's per-site logic.

  It is used in `tryResolveSID` (1244, which today hard-codes `config.Domain`), `lookupSPNsForServer` (1952; `spnEnumerationDone` becomes per-domain in the registry), `resolveComputerSIDViaLDAP` (2083) and `resolveDataSourceToSID` (5008).
- **`processServer` (1810):** replace `sharedADClient` with a `domainClientSet`. The helpers at 1819, 1827 and 1830, and the WMI members at 2549, take the set and resolve names and SIDs across domains.
- **`createADNodes`:**
  - Resolve each SID through its own domain via the set (fixes the blocker).
  - Filters at 3180 and 2843 use `isKnownDomainSID`; the local-group checks at 3281 and 4150 use `!isKnownDomainSID`.
  - Trusted principals get nodes named upper-case `SAM@<THEIR DNS>` with `domain=<their DNS>`.
- **Server-domain naming:** the Computer node's `domain` (3097), Authenticated Users `<domain>-S-1-5-11` (3126, 3135, 4011), the coercion host suffix (4044) and the partial FQDN (1861) all use `domainOfServerInfo(info)`. That is the registry match on the FQDN, or else `config.Domain`, so single-domain output is identical.
- **What stays the same:** `mssql` `SetDomain` (1559, 1665) stays the home *credential* domain, because EPA's `parseLDAPUser` needs it.
- **Linked servers:**
  - `processLinkedServers` (4824) passes `domainForHost(resolvedHost or the DataSource FQDN)`, or else `sourceDomain`, to `addLinkedServerToQueue`.
  - `addLinkedServerToQueue` (5052) checks for duplicates under the lock, calls `tryResolveSID` **outside** it, then re-checks and appends. That stops slow cross-domain connects from blocking other workers.
- **Discovery:**
  - `enumerateServersFromAD` becomes `enumerateServersFromDomain(domain, client)`.
  - `server.Domain` is set to `domainForHost(spn.Hostname)`, or else the enumerated domain. SPNs sit on service accounts, so a host can belong to another domain.
  - The home domain runs as today.
  - With `FollowTrusts` and no explicit targets, each queryable trusted domain runs too, including `--scan-all-computers`. Failures there are warnings.
  - Explicit `-t` targets never widen the scope.

### 4. CLI, config, Kerberos

- **Config:** `FollowTrusts`, `TrustDepth` (default 1) and `DomainDCs map[string]string`.
- **Flags:** in the "domain" help group, parsed by `parseDomainDCMap`, which follows the `parsePortList` pattern (main.go:496).
- **Auto-generated krb5.conf** (`mssql/krb5_config.go`), when `FollowTrusts` is set:
  - `dns_lookup_kdc = true`;
  - a `[realms]` and `[domain_realm]` entry for each `--domain-dc` pair.

  This lets gokrb5 cross-realm referrals reach trusted KDCs. Nothing changes when the flag is off.

### 5. Docs

- README "Cross-domain trusts" section and flags table.
- Limitations to document:
  - NT-hash binds across trusts aren't supported.
  - UPN NTLM may fail over external, non-forest trusts.
  - Selective authentication may block binds.
  - Passive mode only sees *direct* trusts. Sibling domains in the forest need `--follow-trusts --trust-depth 2`.
- Fix the line about "cross-domain scenarios" (~851).
- RELEASE_NOTES entry.

## Tests (offline, run with `go test ./...`)

- **`internal/ad/trusts_test.go`:**
  - `DomainSIDOf`
  - `parseTrustEntry` (`ldap.NewEntry` with a binary SID; downlevel and MIT types)
  - `ntlmBindIdentity` matrix
  - `simpleBindNames` with `credDomain`
  - `ResolveComputerSID` FQDN stripping, via the pure helper
  - a cached `Connect` error returning without redialling (pre-set `connectErr`)
- **`internal/collector/domains_test.go`:**
  - registry lookups (SID, NetBIOS, DNS qualifier, UPN, longest suffix, case, unknown)
  - `isKnownDomainSID`, including an empty registry giving the same result as today
  - `serverDomain` precedence
  - linked-server domain selection
  - `setLDAPAuthFailed(trusted)` not setting the global flag
  - a disabled domain making `newADClient` return nil
- **Edge and node tests:**
  - Add a `runEdgeCreationWithSetup(t, info, cfg, setup func(*Collector))` helper; `runEdgeCreationWithConfig` delegates to it.
  - A trusted `WINDOWS_GROUP` gets a SID HasLogin but no `<host>-<SID>` local HasLogin.
  - A machine-local group stays local.
  - `createADNodes` emits `X@TRUSTED.LOCAL` (`setLDAPAuthFailed(home)` first, so no network).
  - `createServerNode` lists include trusted principals.
- **`cmd/mssqlhound/main_test.go`:** `TestParseDomainDCMap`.
- Existing tests stay green; the current baseline passes.

## Verification

1. `go test ./...`, which must be green.
2. `go build ./cmd/mssqlhound` (binary in the repo root); check that `./mssqlhound --help` lists the new flags.
3. Manual, in your trust lab:
   - `./mssqlhound -d home.local --dc <dc> --ldap-user 'HOME\u' --ldap-password … --domain-enum-only --follow-trusts -v`
   - Expected: the domain table plus SPNs from the trusted domains.
   - Then run a full collection and confirm in BloodHound that trusted logins link to the SharpHound objects by SID.

## Delivery

1. Copy this plan to `.claude/plans/cross-domain-trusts.md`, with the to-do list (rule 6).
2. Implement in the order: §1 → §2 → §3 → §4 → tests → docs. Add detailed comments on the non-obvious logic (rule 9): NTLM UPN, trust direction, the FSP pitfall, lockout guards.
3. Run `go test ./...`.
4. Commit and push to `claude/inspiring-ramanujan-dxa18r`.

## To-do

- [x] Save approved plan (this file)
- [x] §1 internal/ad trust & identity primitives (`internal/ad/trusts.go`, `client.go`)
- [x] §2 collector domain registry, client set, auth-failure scoping, discovery (`internal/collector/domains.go`)
- [x] §3 collector call sites (routing, classification, naming, linked servers, trusted enumeration)
- [x] §4 CLI flags, config, krb5 auto-config
- [x] Offline tests; `go test ./...`; `go build ./cmd/mssqlhound`
- [x] README + RELEASE_NOTES; commit and push to `claude/inspiring-ramanujan-dxa18r`
- [ ] Manual verification in a lab with a real trust (user)

Implementation notes (deviations from the plan text above):
- `DomainInfo` lives in `internal/ad` (with its trust helpers) rather than `internal/types`.
- `DomainSID` derivation in `internal/mssql` is unchanged; `isKnownDomainSID` adds the computer-SID and registry rules on top instead.
- `ResolveComputerSID` also rejects a short-name match whose `dNSHostName` differs from a requested FQDN, so `sql01.trusted.local` cannot resolve to the home domain's `SQL01$`.

Status: approved by the user on 2026-11-04.
