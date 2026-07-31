# Tier 2 — TDS over SMB Named Pipes (cross-platform, in-process)

## Context

MSSQLHound discovers SQL Server instances from `MSSQLSvc` SPNs in AD, then connects over
TCP. Instances that expose **only** named pipes are discovered but never collected: with
TCP 1433 unreachable, `collector.go:1465` skips `Connect` entirely and degrades to a
partial, SPN-only node via `processServerFromSPNData`. Those are holes in the graph.

Affected targets: instances hardened with TCP/IP disabled in SQL Server Configuration
Manager, and **Windows Internal Database** (WSUS `SUSDB`, AD FS config DB), which has no
TCP endpoint at all — only `MICROSOFT##WID\tsql\query`.

`go-mssqldb` ships a `namedpipe` package but it is unusable here: `namedpipe_windows.go:1`
is gated `//go:build windows && (amd64 || 386)`, `namedpipe_others.go` is an empty stub,
and it opens the pipe via the local Windows SMB client — Windows-only, caller's token
only, no proxy. We implement the transport **in-process** with a pure-Go SMB client, the
way impacket PR fortra/impacket#2202 did it: identical TDS logic, different transport.

**Outcome:** NP-only instances get collected from Linux, through SOCKS5, with optionally
distinct SMB credentials.

## Decisions

1. **Opt-in `--named-pipe`, with TCP→pipe fallback under it.** Default runs byte-identical.
2. **`--smb-user` / `--smb-password` / `--smb-hash`, falling back** to existing credentials.
3. **445 reachability is a fallback inside `CheckPort`**, not an entry in
   `--scan-all-computer-ports` (that list flows into `server.Port` and would both mint a
   bogus `SID:445` node per host and attempt TDS-over-TCP on 445).

## Library: `github.com/cloudsoda/go-smb2`

BSD-2 (fine against our Apache-2.0), actively maintained, `go 1.25`, and it already depends
on `jcmturner/gokrb5/v8 v8.4.4` — the exact module and version we ship, so `Krb5Initiator.Client`
takes our existing ccache/keytab client directly. Adds two modules (`cloudsoda/sddl`,
`geoffgarside/ber`). `DialConn(ctx, conn net.Conn, "host:445")` accepts a caller-supplied
conn, which is how SOCKS5 gets in.

Rejected: `hirochachacha/go-smb2` (dead since 2022, no Kerberos); `jfjallid/go-smb` (good
ergonomics but forks both gokrb5 and go-ldap — two Kerberos stacks and two LDAP stacks in
one binary); `RedTeamPentesting/adauth` (full MSRPC stack plus a third krb5 fork — mine its
`ccachetools` for reference, don't depend on it).

## Three verified facts that drive the design

Each was checked against the module source, not assumed.

**A. Registering a `ProtocolParser` would break requirement 1.** `msdsn/conn_str.go:543-556`
appends *every* non-hidden parser whose `ParseServer` succeeds, so a registered `np` parser
puts `Protocols=["tcp","np"]` on **every** default run — and `conn_str.go:562-565` sets
`DialTimeout = 15s × len(Protocols)`, silently doubling it. **Register only
`msdsn.ProtocolDialers["np"]` in `init()`; register no parser.** Set `cfg.Protocols` by hand
on the pipe pass. (If connection-string selection is ever wanted, add the parser with
`Hidden() == true` — that's how `admin` stays out of the default path.)

**B. Deadlines must be real.** `tds.go:1171` wraps every dialed conn in
`newTimeoutConn(conn, p.ConnTimeout)`, and `net.go:21-39` calls `SetDeadline` on **every**
Read and Write when the timeout is non-zero. It is dormant only because
`buildConnectionStringForStrategy` never emits `connection timeout=`. Returning nil from
the deadline setters is a one-line-away landmine.

**C. The buffered read is a prerequisite, not a mitigation.** `buf.go:158-160` does
`io.ReadFull(r.transport, r.rbuf[:8])` — an **8-byte** read as the first operation of every
TDS packet. An 8-byte SMB2 READ against a message-mode pipe holding a whole packet returns
`STATUS_BUFFER_OVERFLOW`, and cloudsoda's `conn.go accept()` treats that as an error and
**discards the attached partial payload**. Those bytes are gone from the pipe and the TDS
stream desynchronises unrecoverably. This fires on the very first packet, every time.

## Design

### New package `internal/mssql/nptransport`

Isolated in its own package because it contains an `init()` that mutates a process-global in
a third-party library — burying that in `internal/mssql` means every importer silently
mutates go-mssqldb state. It also confines the `go-smb2` dependency to one place and is
unit-testable without a `Client`.

| File | Contents |
|---|---|
| `nptransport.go` | `Params`, `Result`, `AuthConfig`, the `msdsn.ProtocolDialer` impl, `init()`, sentinel errors, `IsAuthError` |
| `pipeconn.go` | `pipeConn` (`net.Conn` adapter) + `pipeAddr` |
| `pipename.go` | `Candidates(instance string) []string` — pure |
| `smbauth.go` | NTLM / pass-the-hash / Krb5 initiator construction |

### Per-target state without the `Connector`

`ProtocolDialer.DialConnection(ctx, p)` sees only `*msdsn.Config`, so `connector.Dialer`
(where SOCKS5 lives today, `client.go:789-793`) is unreachable. We don't need it — we carry
our own dial closure:

```go
const Protocol = "np"

// Params is per-target state, reachable only from that target's Config,
// so it is safe under -w N.
type Params struct {
    Host           string   // FQDN preferred, for Kerberos
    Port           int      // 445
    PipeCandidates []string // relative to IPC$, tried in order
    Auth           AuthConfig
    TDSSPN         string   // stamped into p.ServerSPN if unset
    Logger         *slog.Logger

    // Replaces connector.Dialer. Proxy- and resolver-aware, supplied by internal/mssql.
    Dial func(ctx context.Context, network, addr string) (net.Conn, error)

    mu     sync.Mutex
    result Result
}

type dialer struct{} // stateless

func (dialer) CallBrowser(*msdsn.Config) bool { return false } // never touch UDP 1434
func (dialer) ParseBrowserData(msdsn.BrowserData, *msdsn.Config) error { return nil }
func (dialer) DialConnection(ctx context.Context, p *msdsn.Config) (net.Conn, error)

func init() {
    msdsn.ProtocolDialers[Protocol] = dialer{}
    // Deliberately NOT ProtocolParsers -- see fact A.
}
```

`DialConnection` must comma-ok both the map lookup and the type assertion and return
`ErrNoParams` rather than panicking. The only global mutation is one map write in `init()`;
all mutable state hangs off the per-target `*Params`.

`CallBrowser` returning false is a feature, not a limitation — it is what makes named pipes
work under SOCKS5, where `resolveInstancePort` (`client.go:1367`) hard-fails.

### The `net.Conn` adapter (`pipeConn`)

The core invariant, which needs the long comment CLAUDE.md rule 9 asks for:

```go
func (c *pipeConn) Read(b []byte) (int, error) {
    c.rmu.Lock(); defer c.rmu.Unlock()
    if c.rOff == c.rLen {
        if c.rErr != nil { return 0, c.rErr }
        c.rOff, c.rLen = 0, 0
        // INVARIANT: always read into the FULL rbuf, never into b. See fact C.
        // 64 KiB is above the 32767-byte TDS ceiling (tds.go:1152) and far above
        // the 4096-byte default (tds.go:187), so a whole pipe message always fits
        // and the READ completes STATUS_SUCCESS with a short count.
        // Mirrors impacket's _recv_buf.
        n, err := c.readWithDeadline(c.rbuf)
        if n > 0 { c.rLen = n }
        if err != nil {
            if n == 0 { return 0, err }
            c.rErr = err // deliver buffered bytes first
        }
    }
    n := copy(b, c.rbuf[c.rOff:c.rLen])
    c.rOff += n
    return n, nil // MUST NOT return (0, nil): io.ReadFull would spin
}
```

- **Deadlines** (fact B): `readWithDeadline` runs `f.Read` in a goroutine and selects on a
  timer. On timeout it **poisons** the conn and returns a `net.Error` with `Timeout() == true`.
  A timed-out SMB read cannot be resumed — the response may still land and desync the
  stream — so poisoning is the only correct behavior.
- **Addrs**: `pipeAddr{net:"np", addr:\\HOST\pipe\...}`. Never nil; go-mssqldb forwards them.
- **Context lifetime — easy-to-miss bug:** `DialConnection` receives the *dial* context,
  which `tds.go:1157-1163` cancels via `defer cancel()` as soon as connect returns. Binding
  the smb2 session/share/file to it makes every post-connect query fail ~20s later. Use it
  for negotiate/session-setup only, then rebind long-lived handles to an internal `closeCtx`
  cancelled in `Close()`.
- **Close order** under `sync.Once`, errors joined: file → share `Umount` → session `Logoff`
  → raw conn → cancel `closeCtx`.

### `--named-pipe` composition with the connect path

**`CheckPort` (`client.go:442-483`) is the mandatory change** — a pipe-only instance is
definitionally TCP-unreachable, so without this the fallback is never reached.

Factor today's proxy-aware dial body into `dialTCP(ctx, host, port, timeout)`; the same
closure is handed to `Params.Dial`, so there is one code path for proxy + `dialerWithResolver`
+ `resolveForProxy` and no drift.

```go
func (c *Client) CheckPort(ctx) error {
    tcpErr := c.checkTCPPort(ctx)   // exactly today's logic
    if !c.namedPipe { return tcpErr } // byte-identical default behavior
    c.reach.TCP = tcpErr == nil
    c.reach.SMB = c.probe(ctx, 445) == nil
    if c.reach.TCP || c.reach.SMB { return nil }
    return errors.Join(tcpErr, ...)
}
```

One extra fix inside `checkTCPPort`: the `port==0 && instanceName!=""` branch calls
`resolveInstancePort`, which hard-fails under SOCKS5. When `namedPipe` is set, demote that to
a verbose log and treat it as `tcpErr` so the 445 probe still runs — otherwise
`-x socks5://… --named-pipe -t host\INSTANCE` can never work.

`connectNative` (`client.go:486-818`): mechanically extract the existing body (EPA
pre-strategies + strategy loop) into `connectTCPStrategies`, unchanged, then:

```go
if c.reach.TCP || !c.namedPipe {
    if err := c.connectTCPStrategies(ctx); err == nil { return nil } else {
        lastErr = err
        if IsAuthError(err) { return err } // never burn the pipe on known-bad creds
    }
}
if c.namedPipe && c.reach.SMB { return c.connectNamedPipe(ctx, lastErr) }
```

`connectNamedPipe` gets its **own short strategy list — `encrypt` in `{true, false}` only**.
No `strict` (TDS 8.0 wraps the raw socket in TLS before any TDS exists; architecturally
impossible over a pipe — detect from `epaResult.StrictEncryption`, report, never retry). No
short-hostname variants (they exist to fix SPN mismatch; here the TDS SPN is stamped
explicitly). No `HostNameInCertificate`. Per attempt: `cfg.Protocols = []string{"np"}`,
`cfg.ProtocolParameters["np"] = c.npParams`, `cfg.DialTimeout = 20s`, and a **30s**
`PingContext` rather than the TCP path's 10s — SMB negotiate + session setup + tree connect
+ pipe open + prelogin + TLS-in-TDS + LOGIN7 does not fit in 10s over a SOCKS5 hop. Also
`db.SetMaxOpenConns(1)`, since each pooled conn is a full SMB session + TGS.

**EPA is not a blanket scope-out.** The pipe carries raw TDS, so `encrypt=true` (TLS-in-TDS)
works and `tls-unique` is available — the ordinary EPA path via `TLSConfig.VerifyConnection`
→ `SetCBT` (`client.go:772-786`) works verbatim. Only the two hand-rolled pre-strategies
`epaTLSDialer`/`epaTDSDialer` are out, because `preloginFakerConn` (`client.go:178-256`)
holds the raw pre-TLS socket and the TLS socket as two views of one connection.

### SMB credentials and the two Kerberos SPNs

Flags in `main()` (`main.go:110-146`) — **must** also be added to the `SetAnnotation` loop at
`main.go:158-179` or they land in the ungrouped bucket. `--named-pipe` and
`--named-pipe-path` → `Collection`; the three `--smb-*` → `Authentication`.

Resolution is one pure, table-tested function `resolveSMBCredentials`:

| Field | Chain |
|---|---|
| User | `--smb-user` → `--ldap-user` → `-u` |
| Password | `--smb-password` → `--ldap-password` → `-p` |
| NT hash | `--smb-hash` → `--nt-hash` |
| Domain | split from resolved user (`DOM\u`, `u@dom`) → `-d` |
| Kerberos | `-k` and no explicit `--smb-*` → reuse `--krb5-*` / `KRB5CCNAME` |

**Note the deliberate deviation:** `--ldap-user` sits *ahead of* `-u`. SMB is a domain-auth
surface like LDAP and EPA, whereas `-u` is documented as "SQL Server login username" and is
frequently a pure SQL login (`sa`) that cannot authenticate to SMB — using it would just burn
a failed logon against every machine. Same reasoning as the existing LDAP fallback at
`main.go:340-357`. Easy to flip if you disagree.

Validation in `run()`: `--smb-password` + `--smb-hash` → error; `--smb-hash` not 32 hex →
error (reuse the `--nt-hash` parser); `--smb-*` without `--named-pipe` → warn and ignore;
`--named-pipe` with no resolvable SMB identity → error early.

**Two SPNs from one TGT:** extract the client-construction half of
`krb5CustomProvider.GetIntegratedAuthenticator` (`krb5_auth_provider.go:50-146`) into
`newKrb5Client(opts) (*client.Client, error)`. gokrb5 caches a TGS per SPN from one TGT, so
`cifs/HOST` (SMB) and `MSSQLSvc/FQDN:port|instance` (TDS) are two `GetServiceTicket` calls on
one client — one `Login()`, no second AS-REQ. Reuse the existing CNAME canonicalization from
`krb5CustomAuthenticator.InitialBytes` for the `cifs/` host; a non-canonical name there is
the #1 cause of `KDC_ERR_S_PRINCIPAL_UNKNOWN`. Create one client per target, never share
across workers, `Destroy()` in `Client.Close()`.

### Identity

Because the pipe is a fallback transport on the *existing* target, no new `ServerToProcess`
is created and none of `addServerToProcess` (`collector.go:744-771`), `deduplicateByIP`
(`892-953`), or `generateFilename` (`6784`) needs to change. A pipe connection reaches the
same instance and must produce the same node.

Two wrinkles:

- With multiple `--scan-all-computer-ports`, every entry for a host would probe 445 and fall
  back to the same pipe → N duplicate collections. Add `AllowNamedPipe bool` to
  `ServerToProcess` and set it only on the first port entry in `scanAllComputerServers`
  (`collector.go:701-709`).
- **WID genuinely needs a distinct identity.** If `sql\query` is absent and we fall through
  to `MICROSOFT##WID\tsql\query`, that is a different instance and must not be filed under
  the host's default-instance identity — misfiling corrupts graph data. Handle as a
  post-connect fixup in `processServer`: read `client.NamedPipeResult()`, and if the pipe
  path implies a different instance, set `server.InstanceName` and recompute
  `ObjectIdentifier` with the same logic as `addServerToProcess`, guarding against a
  post-hoc duplicate. Filenames then fall out for free.

`Candidates` ordering: with no instance specified, try `sql\query`, and only on
`STATUS_OBJECT_NAME_NOT_FOUND` try `MICROSOFT##WID\tsql\query`. Advance to the next candidate
**only** on that status — `ACCESS_DENIED` and session/tree failures stop immediately.
`--named-pipe-path` is the escape hatch for relocated pipes.

### Error taxonomy and the lockout guard

Exported sentinels from `nptransport`: `ErrSMBUnreachable` (verbose), `ErrSMBAuth` (warn,
terminal), `ErrPipeNotFound` (info — "no SQL named pipe on this host"), `ErrPipeAccessDenied`
(info — "pipe exists, ACL denies this principal; expected for WID without local admin"),
`ErrStrictEncryptionUnsupported` (warn, terminal), `ErrNoParams`.

**Safety-critical:** `nptransport.IsAuthError` must be OR'd into `mssql.IsAuthError`
(`auth_errors.go:10`). SMB logon failures count toward AD lockout exactly like SQL logins,
and the existing `IsAuthError` early-break (`client.go:805`) is what prevents `-A` from
becoming a domain-wide lockout event.

## Scope-outs (document in `--help` and README)

EPA pre-strategies over pipes; TDS 8.0 / `ENCRYPT_STRICT`; SQL Browser on the pipe path
(deliberate); Windows-native `\\.\pipe\` (always go through SMB even on Windows, so there is
one code path on all platforms); DAC/`admin:` over pipes.

## Build order

1. `pipeconn.go` + tests — **resolve the fact-C risk before writing anything else**; it is
   the whole feasibility question.
2. `pipename.go` + tests.
3. `nptransport.go` + `smbauth.go` + registration tests.
4. `client.go`: `dialTCP` extraction, `CheckPort` restructure, `connectTCPStrategies`
   extraction, `connectNamedPipe`, `IsAuthError` extension.
5. `krb5_auth_provider.go`: `newKrb5Client` extraction.
6. `main.go`: flags, `resolveSMBCredentials`, validation, annotation loop.
7. `collector.go`: `Config` fields, `newMSSQLClient` setters, `AllowNamedPipe`, WID fixup.
8. Seam-driven E2E, README/TESTING.md.

## Verification

CI runs unit tests on ubuntu-latest plus a live **Linux** SQL Server job — which serves no
named pipes, so there is no CI target for a live SMB test. Everything below is fakes and
seams: standard library `testing` only (CONTRIBUTING.md forbids external frameworks),
table-driven with anonymous structs + `t.Run` (per `main_test.go:10`), package-level func
vars as seams (per `collector.go:157 serverProcessor`).

**The transport tests are the regression suite for the whole feature.** With a `fakePipe`
recording every `len(p)` it is asked to read:

- `TestReadAlwaysRequestsFullBuffer` — drive `io.ReadFull(conn, make([]byte, 8))`, assert
  every underlying read length is exactly 64 KiB. *This single assertion is the fact-C
  mitigation.*
- Single 4096-byte PRELOGIN packet → header + body correct, underlying `Read` called once.
- Two TDS packets in one message → two `ReadFull` cycles, one underlying read.
- Buffered bytes delivered before a sticky error; `Read` never returns `(0, nil)`.
- Close order + idempotency; read-deadline produces `net.Error` with `Timeout() == true`.
- `var _ net.Conn = (*pipeConn)(nil)`, non-nil addrs.

**Registration regression (this is what enforces requirement 1):**
`msdsn.ProtocolDialers["np"] != nil` **and** `ProtocolParsers` still has exactly
`{tcp, admin}`; `msdsn.Parse("server=x;…")` still yields `Protocols == ["tcp"]` and
`DialTimeout == 15s`. Fails loudly if someone later "helpfully" adds a parser.

**Wiring, without a server:** a `dialSMB` package-var seam swapped for a `net.Pipe()`-backed
fake running a scripted TDS PRELOGIN, driven through a real
`sql.OpenDB(mssqldb.NewConnectorConfig(cfg))` with `cfg.Protocols = ["np"]`. This establishes
the `net.Conn`-fake pattern the repo currently lacks.

**Elsewhere:** `CheckPort` unchanged when `--named-pipe` is off (identical error text, one
dial); `CheckPort` falls back to 445 (two loopback listeners); connect skips the pipe on
auth error; strict encryption rejected; `IsAuthError` includes SMB logon failure;
`resolveSMBCredentials` table over the chain permutations;
`scanAllComputerServers` sets `AllowNamedPipe` on the first port only.

**Manual, documented in TESTING.md, not in the CI matrix:** `//go:build integration` test
gated on `MSSQLHOUND_NP_HOST` with `t.Skip` when unset — default instance, named instance,
WID as admin, WID as non-admin (expect `ACCESS_DENIED`), and through SOCKS5.

Finally `go build ./cmd/mssqlhound` (binary in repo root) and `go test ./...` per CLAUDE.md.

## Top risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | cloudsoda discards the payload on `STATUS_BUFFER_OVERFLOW`; go-mssqldb's first read is 8 bytes, so this fires immediately | 64 KiB buffered adapter, built and tested first. If it still fails against a real server, escape hatch is a vendored patch to cloudsoda's `accept()` or a fork — contained to one package |
| 2 | Account lockout: `-A --named-pipe` with a wrong password hits every computer in the domain | `nptransport.IsAuthError` OR'd into `mssql.IsAuthError`; SMB auth failure terminal per target; explicitly tested |
| 3 | A future contributor registers a `ProtocolParser` | Never register one; registration tests fail loudly |
| 4 | 10s `PingContext` can't cover SMB setup + login over SOCKS5 | 30s ping + 20s `DialTimeout` on the pipe pass only, gated by `CheckPort` so we pay it only where 445 answered |
| 5 | Binding smb2 handles to the dial ctx that `tds.go:1163` cancels | Dial ctx for negotiate/setup only; internal `closeCtx` for long-lived handles |
| 6 | `cifs/` ticket for a non-canonical name → `KDC_ERR_S_PRINCIPAL_UNKNOWN` | Reuse existing CNAME canonicalization; log both SPNs at verbose |
| 7 | Detection footprint: extra 445 SYN + SMB setup to every domain computer under `-A` | Opt-in only; documented; run summary reports pipe-reached count |
