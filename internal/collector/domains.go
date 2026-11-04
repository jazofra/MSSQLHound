package collector

// Cross-domain trust support.
//
// MSSQLHound historically assumed every principal, server and SID belonged to
// the single --domain. In forests and trust relationships that is wrong: SQL
// Servers routinely carry logins such as TRUSTED\DBAs, linked servers point at
// hosts in other domains, and SIDs from a trusted domain cannot be resolved by
// the home DC (worse, the home DC returns a ForeignSecurityPrincipal stand-in
// object with no useful attributes).
//
// This file adds:
//
//   - domainRegistry: what we know about each domain (DNS, NetBIOS, SID, DC),
//     filled passively from the home domain's trustedDomain objects and, with
//     --follow-trusts, by binding to DCs of domains that trust ours.
//   - domainClientSet: a per-goroutine cache of LDAP clients keyed by domain,
//     so each lookup is answered by the domain that owns the principal.
//   - discovery (discoverDomains / crawlTrusts) with lockout-safe ordering.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/SpecterOps/MSSQLHound/internal/ad"
	"github.com/SpecterOps/MSSQLHound/internal/logging"
	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// errDomainUnavailable means the owning domain of a SID or name is known to be
// foreign but cannot be queried (not reachable, not followed, or disabled).
// Callers treat it as "not found" - crucially, they must NOT fall back to the
// home DC, which would match the ForeignSecurityPrincipal stand-in object.
var errDomainUnavailable = errors.New("owning domain is not queryable")

// errNoDomain means no domain is configured to answer the lookup.
var errNoDomain = errors.New("no domain available for lookup")

// domainEntry is everything known about one AD domain.
type domainEntry struct {
	ad.DomainInfo

	// DC is the domain controller to bind to for a trusted domain: the
	// --domain-dc override, or "" to let the AD client find one via DNS SRV.
	// The home domain always uses --dc and ignores this field.
	DC string

	isHome bool

	// queryable is true for the home domain and for trusted domains whose DC
	// accepted a bind during discovery (--follow-trusts). Only queryable
	// domains are ever contacted after discovery.
	queryable bool

	// disabled holds the reason a trusted domain must no longer be contacted
	// (failed bind, unreachable DC). It acts as a circuit breaker so that one
	// dead DC does not cost every server up to 3 x 30s of dial timeouts, and
	// so that rejected credentials are never retried against that domain.
	disabled string

	// spnSwept is set once MSSQLSvc SPNs were enumerated for the whole domain,
	// making per-host SPN lookups in that domain redundant.
	spnSwept bool
}

// domainRegistry indexes known domains by SID, NetBIOS name and DNS name.
// All methods are safe for concurrent use and tolerate a nil receiver (unit
// tests often build a bare Collector without one), in which case they behave
// as "nothing is known", preserving single-domain behaviour.
//
// Identity fields (DNSName, NetBIOSName, SID, isHome, DC) are only written
// during discovery, which runs single-threaded before any worker goroutine
// starts, so later readers may access them directly. The mutable runtime
// state (queryable, disabled, spnSwept) is always read and written under mu.
type domainRegistry struct {
	mu        sync.RWMutex
	entries   []*domainEntry
	bySID     map[string]*domainEntry // upper-case domain SID
	byNetBIOS map[string]*domainEntry // upper-case NetBIOS name
	byDNS     map[string]*domainEntry // lower-case DNS name
}

func newDomainRegistry() *domainRegistry {
	return &domainRegistry{
		bySID:     make(map[string]*domainEntry),
		byNetBIOS: make(map[string]*domainEntry),
		byDNS:     make(map[string]*domainEntry),
	}
}

// register adds a domain or merges new facts into an existing entry. Entries
// are matched by SID first, then DNS, then NetBIOS, so the same domain seen
// from several trust objects collapses into one entry.
func (r *domainRegistry) register(info ad.DomainInfo, isHome bool) *domainEntry {
	if r == nil {
		return nil
	}
	info.DNSName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(info.DNSName), "."))
	info.NetBIOSName = strings.ToUpper(strings.TrimSpace(info.NetBIOSName))
	info.SID = strings.ToUpper(strings.TrimSpace(info.SID))

	r.mu.Lock()
	defer r.mu.Unlock()

	var e *domainEntry
	if info.SID != "" {
		e = r.bySID[info.SID]
	}
	if e == nil && info.DNSName != "" {
		e = r.byDNS[info.DNSName]
	}
	if e == nil && info.NetBIOSName != "" {
		e = r.byNetBIOS[info.NetBIOSName]
	}
	if e == nil {
		e = &domainEntry{}
		r.entries = append(r.entries, e)
	}

	if e.DNSName == "" {
		e.DNSName = info.DNSName
	}
	if e.NetBIOSName == "" {
		e.NetBIOSName = info.NetBIOSName
	}
	if e.SID == "" {
		e.SID = info.SID
	}
	// Trust metadata describes the path from the home side; keep the first
	// (closest) observation rather than overwriting it from deeper hops.
	if e.TrustDirection == 0 && e.TrustType == 0 {
		e.TrustDirection = info.TrustDirection
		e.TrustType = info.TrustType
		e.TrustAttributes = info.TrustAttributes
	}
	if isHome {
		e.isHome = true
		e.queryable = true
	}

	if e.SID != "" {
		r.bySID[e.SID] = e
	}
	if e.DNSName != "" {
		r.byDNS[e.DNSName] = e
	}
	if e.NetBIOSName != "" {
		r.byNetBIOS[e.NetBIOSName] = e
	}
	return e
}

// forSID returns the domain owning a principal SID, or nil.
func (r *domainRegistry) forSID(sid string) *domainEntry {
	if r == nil {
		return nil
	}
	domainSID := strings.ToUpper(ad.DomainSIDOf(sid))
	if domainSID == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySID[domainSID]
}

// forDomain returns the entry for a DNS or NetBIOS domain name, or nil.
func (r *domainRegistry) forDomain(name string) *domainEntry {
	if r == nil {
		return nil
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e := r.byDNS[strings.ToLower(name)]; e != nil {
		return e
	}
	return r.byNetBIOS[strings.ToUpper(name)]
}

// forName returns the domain named by an account qualifier: "NETBIOS\user",
// "dns.name\user" or "user@dns.name". Bare names return nil.
func (r *domainRegistry) forName(name string) *domainEntry {
	if idx := strings.Index(name, "\\"); idx > 0 {
		return r.forDomain(name[:idx])
	}
	if idx := strings.LastIndex(name, "@"); idx >= 0 && idx < len(name)-1 {
		return r.forDomain(name[idx+1:])
	}
	return nil
}

// forHost returns the registered domain with the longest DNS suffix match for
// a host FQDN ("sql01.emea.corp.local" prefers emea.corp.local over
// corp.local). Short names and IP addresses return nil.
func (r *domainRegistry) forHost(host string) *domainEntry {
	if r == nil {
		return nil
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Walk suffixes from longest to shortest: drop one leading label at a time.
	for idx := strings.Index(host, "."); idx >= 0; {
		suffix := host[idx+1:]
		if e := r.byDNS[suffix]; e != nil {
			return e
		}
		next := strings.Index(suffix, ".")
		if next < 0 {
			break
		}
		idx += next + 1
	}
	return nil
}

// home returns the home domain entry, or nil before discovery succeeds.
func (r *domainRegistry) home() *domainEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if e.isHome {
			return e
		}
	}
	return nil
}

// usable reports whether a domain may be contacted right now.
func (r *domainRegistry) usable(e *domainEntry) bool {
	if r == nil || e == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return e.queryable && e.disabled == ""
}

func (r *domainRegistry) setDC(e *domainEntry, dc string) {
	if r == nil || e == nil {
		return
	}
	r.mu.Lock()
	e.DC = dc
	r.mu.Unlock()
}

func (r *domainRegistry) setQueryable(e *domainEntry) {
	if r == nil || e == nil {
		return
	}
	r.mu.Lock()
	e.queryable = true
	r.mu.Unlock()
}

// disable trips the circuit breaker for a trusted domain. The home domain is
// never disabled here; it keeps the collector-wide ldapAuthFailed semantics.
// Returns true when this call changed the state (so callers log only once).
func (r *domainRegistry) disable(e *domainEntry, reason string) bool {
	if r == nil || e == nil || e.isHome {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e.disabled != "" {
		return false
	}
	e.disabled = reason
	return true
}

func (r *domainRegistry) markSPNSwept(domain string) {
	if e := r.forDomain(domain); e != nil {
		r.mu.Lock()
		e.spnSwept = true
		r.mu.Unlock()
	}
}

func (r *domainRegistry) spnSwept(domain string) bool {
	e := r.forDomain(domain)
	if e == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return e.spnSwept
}

// usableTrusted returns the trusted (non-home) domains that are currently usable,
// sorted by DNS name for deterministic processing.
func (r *domainRegistry) usableTrusted() []*domainEntry {
	if r == nil {
		return nil
	}
	var out []*domainEntry
	r.mu.RLock()
	for _, e := range r.entries {
		if !e.isHome && e.queryable && e.disabled == "" && e.DNSName != "" {
			out = append(out, e)
		}
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].DNSName < out[j].DNSName })
	return out
}

// ---------------------------------------------------------------------------
// Collector helpers
// ---------------------------------------------------------------------------

// isKnownDomainSID reports whether sid belongs to an Active Directory domain
// (as opposed to a machine-local account database or a well-known SID).
//
// It is the single classification rule used for domain-principal nodes, the
// server node's domainPrincipalsWith* lists, and local-group detection:
//
//  1. today's rule: the SID is under serverInfo.DomainSID;
//  2. the SID is in the same domain as the server's computer account (this is
//     authoritative even when DomainSID was guessed from a foreign login);
//  3. the SID's domain is in the trust registry (home or trusted).
//
// With an empty registry, (1) and (2) give exactly the historical result for
// single-domain environments.
func (c *Collector) isKnownDomainSID(sid string, serverInfo *types.ServerInfo) bool {
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return false
	}
	if serverInfo.DomainSID != "" && strings.HasPrefix(sid, serverInfo.DomainSID+"-") {
		return true
	}
	domainSID := ad.DomainSIDOf(sid)
	if domainSID == "" {
		return false
	}
	if computerDomain := ad.DomainSIDOf(serverInfo.ComputerSID); computerDomain != "" && strings.EqualFold(computerDomain, domainSID) {
		return true
	}
	return c.domains.forSID(sid) != nil
}

// isLocalGroupPrincipal identifies logins for groups that live on the SQL
// Server machine itself: BUILTIN groups (S-1-5-32-*) and machine-local
// groups (S-1-5-21-* in the machine's own account database). A WINDOWS_GROUP
// whose SID belongs to any known AD domain - including a trusted one - is a
// domain group, not a local group.
func (c *Collector) isLocalGroupPrincipal(principal types.ServerPrincipal, serverInfo *types.ServerInfo) bool {
	if strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-32-") {
		return true
	}
	return principal.TypeDescription == "WINDOWS_GROUP" &&
		strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") &&
		!c.isKnownDomainSID(principal.SecurityIdentifier, serverInfo)
}

// domainOfServerInfo is the AD domain (upper-case DNS) a collected server
// belongs to, used for node naming. A registered domain matching the server's
// FQDN wins; otherwise the configured --domain is used, which is exactly the
// historical behaviour.
func (c *Collector) domainOfServerInfo(serverInfo *types.ServerInfo) string {
	for _, host := range []string{serverInfo.FQDN, serverInfo.Hostname} {
		if e := c.domains.forHost(host); e != nil && e.DNSName != "" {
			return strings.ToUpper(e.DNSName)
		}
	}
	return c.config.Domain
}

// principalDomainName is the domain used in a principal's display name
// (SAM@DOMAIN): the domain that owns its SID when registered, else the
// server's domain.
func (c *Collector) principalDomainName(sid string, serverInfo *types.ServerInfo) string {
	if e := c.domains.forSID(sid); e != nil {
		if e.DNSName != "" {
			return strings.ToUpper(e.DNSName)
		}
		if e.NetBIOSName != "" {
			return e.NetBIOSName
		}
	}
	return c.domainOfServerInfo(serverInfo)
}

// serverDomain picks the domain used for AD lookups about a server: a
// registered domain matching its FQDN, then the domain it was discovered in
// (server.Domain), then the configured --domain.
func (c *Collector) serverDomain(server *ServerToProcess) string {
	if e := c.domains.forHost(server.Hostname); e != nil && e.DNSName != "" {
		return e.DNSName
	}
	if server.Domain != "" {
		return server.Domain
	}
	return c.config.Domain
}

// isHomeDomain reports whether domain is the configured home domain.
func (c *Collector) isHomeDomain(domain string) bool {
	if domain == "" || strings.EqualFold(domain, c.config.Domain) {
		return true
	}
	e := c.domains.forDomain(domain)
	return e != nil && e.isHome
}

// credentialDNSDomain is the DNS domain the LDAP credentials belong to: the
// UPN suffix of --ldap-user when given as user@domain, else --domain.
func (c *Collector) credentialDNSDomain() string {
	if idx := strings.LastIndex(c.config.LDAPUser, "@"); idx >= 0 && idx < len(c.config.LDAPUser)-1 {
		return strings.ToLower(c.config.LDAPUser[idx+1:])
	}
	return strings.ToLower(c.config.Domain)
}

// buildADClient constructs an AD client for domain/dc without any policy
// checks. credDomain is non-empty only for trusted (cross-domain) targets.
func (c *Collector) buildADClient(domain, dc, credDomain string) *ad.Client {
	adClient := ad.NewClient(domain, dc, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword, c.getDNSResolver())
	if credDomain != "" {
		adClient.SetCredentialDomain(credDomain)
	}
	if c.config.NTHash != "" {
		adClient.SetNTHash(c.config.NTHash)
	}
	if c.config.UseKerberos {
		adClient.SetKerberosConfig(c.config.Krb5ConfigFile, c.config.Krb5CCacheFile, c.config.Krb5KeytabFile, c.config.Krb5Realm)
	}
	if c.config.Verbose {
		adClient.SetLogger(c.config.Logger)
	}
	if c.proxyDialer != nil {
		adClient.SetProxyDialer(c.proxyDialer)
	}
	return adClient
}

// trustedClientTarget returns the dial parameters for a trusted domain entry.
func (c *Collector) trustedClientTarget(e *domainEntry) (domain, dc, credDomain string) {
	return strings.ToUpper(e.DNSName), e.DC, c.credentialDNSDomain()
}

// noteLDAPError applies the lockout guards after a failed lookup in domain.
func (c *Collector) noteLDAPError(domain string, err error) {
	if err != nil && isLDAPAuthError(err) {
		c.setLDAPAuthFailed(domain)
	}
}

// ---------------------------------------------------------------------------
// Per-goroutine client cache
// ---------------------------------------------------------------------------

// domainClientSet caches one LDAP client per domain for the lifetime of a
// single unit of work (one processServer call, one createADNodes call). It is
// deliberately NOT shared across goroutines because ad.Client is not
// thread-safe. Close it with defer.
type domainClientSet struct {
	c       *Collector
	clients map[string]*ad.Client // lower-case domain -> client (nil = unavailable)
}

func (c *Collector) newDomainClientSet() *domainClientSet {
	return &domainClientSet{c: c, clients: make(map[string]*ad.Client)}
}

// forDomain returns a client for domain, creating it on first use, or nil when
// the domain must not or cannot be queried. Clients for trusted domains are
// connected eagerly so an unreachable DC trips the registry circuit breaker
// once, instead of every later lookup paying the dial timeout again.
func (s *domainClientSet) forDomain(domain string) *ad.Client {
	key := strings.ToLower(domain)
	if client, ok := s.clients[key]; ok {
		return client
	}
	client := s.c.newADClient(domain)
	if e := s.c.domains.forDomain(domain); client != nil && e != nil && !e.isHome {
		if err := client.Connect(); err != nil {
			s.c.trustedDomainFailed(domain, err)
			client.Close()
			client = nil
		}
	}
	s.clients[key] = client
	return client
}

// Close closes every client opened by the set.
func (s *domainClientSet) Close() {
	for _, client := range s.clients {
		if client != nil {
			client.Close()
		}
	}
	s.clients = map[string]*ad.Client{}
}

// targetForSID picks the domain that must answer a SID lookup.
func (s *domainClientSet) targetForSID(sid string) (string, error) {
	r := s.c.domains
	if e := r.forSID(sid); e != nil && !e.isHome {
		if !r.usable(e) || e.DNSName == "" {
			return "", errDomainUnavailable
		}
		return e.DNSName, nil
	}
	// A domain SID that is neither home nor registered is foreign: asking the
	// home DC would only find its ForeignSecurityPrincipal stand-in.
	if home := r.home(); home != nil && home.SID != "" {
		if domainSID := ad.DomainSIDOf(sid); domainSID != "" && !strings.EqualFold(domainSID, home.SID) {
			return "", errDomainUnavailable
		}
	}
	if s.c.config.Domain == "" {
		return "", errNoDomain
	}
	return s.c.config.Domain, nil
}

// targetForName picks the domain that must answer a name lookup.
//
// Only positive evidence routes a name away from the home domain: the
// qualifier must name a registered domain. Unregistered UPN suffixes (for
// example alternate suffixes such as user@corp.com) keep the historical
// home-domain lookup. A NetBIOS/DNS "X\user" qualifier that matches neither
// the home domain nor any registered domain is foreign when the home
// identity is known, and is reported as unavailable rather than matched
// against a same-named home account.
func (s *domainClientSet) targetForName(name string) (string, error) {
	r := s.c.domains
	if e := r.forName(name); e != nil {
		if e.isHome {
			return s.c.config.Domain, nil
		}
		if !r.usable(e) || e.DNSName == "" {
			return "", errDomainUnavailable
		}
		return e.DNSName, nil
	}
	if idx := strings.Index(name, "\\"); idx > 0 {
		if home := r.home(); home != nil && home.NetBIOSName != "" {
			qualifier := name[:idx]
			if !strings.EqualFold(qualifier, home.NetBIOSName) && !strings.EqualFold(qualifier, home.DNSName) &&
				!strings.EqualFold(qualifier, s.c.config.Domain) {
				return "", errDomainUnavailable
			}
		}
	}
	if s.c.config.Domain == "" {
		return "", errNoDomain
	}
	return s.c.config.Domain, nil
}

// resolveSID resolves a SID through the domain that owns it. Results without
// a recognised object class (ForeignSecurityPrincipal stand-ins) are dropped.
func (s *domainClientSet) resolveSID(sid string) (*types.DomainPrincipal, error) {
	domain, err := s.targetForSID(sid)
	if err != nil {
		return nil, err
	}
	client := s.forDomain(domain)
	if client == nil {
		return nil, errDomainUnavailable
	}
	principal, err := client.ResolveSID(sid)
	if err != nil {
		s.c.noteLDAPError(domain, err)
		return nil, err
	}
	if principal == nil || principal.ObjectClass == "" {
		return nil, fmt.Errorf("SID %s resolved to a non-principal object", sid)
	}
	return principal, nil
}

// resolveName resolves DOMAIN\name, name@domain or a bare name through the
// domain that owns it.
func (s *domainClientSet) resolveName(name string) (*types.DomainPrincipal, error) {
	domain, err := s.targetForName(name)
	if err != nil {
		return nil, err
	}
	client := s.forDomain(domain)
	if client == nil {
		return nil, errDomainUnavailable
	}
	principal, err := client.ResolveName(name)
	if err != nil {
		s.c.noteLDAPError(domain, err)
		return nil, err
	}
	return principal, nil
}

// resolveComputerSID resolves a computer account SID in domain.
func (s *domainClientSet) resolveComputerSID(domain, computerName string) (string, error) {
	if domain == "" {
		return "", errNoDomain
	}
	client := s.forDomain(domain)
	if client == nil {
		return "", errDomainUnavailable
	}
	sid, err := client.ResolveComputerSID(computerName)
	if err != nil {
		s.c.noteLDAPError(domain, err)
	}
	return sid, err
}

// trustedDomainFailed trips the circuit breaker for a trusted domain after a
// failed connect or bind, logging the reason once.
func (c *Collector) trustedDomainFailed(domain string, err error) {
	e := c.domains.forDomain(domain)
	if e == nil || e.isHome {
		c.noteLDAPError(domain, err)
		return
	}
	reason := "unreachable"
	if isLDAPAuthError(err) {
		reason = "authentication rejected"
	}
	if c.domains.disable(e, reason) {
		c.config.Logger.Warn("Disabling lookups in trusted domain", "domain", e.DNSName, "reason", reason, "error", ldapErrorSummary(err))
	}
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// shouldDiscoverDomains reports whether the trust registry is needed: always
// when collecting from SQL Servers (classification and naming use it), and in
// --domain-enum-only mode only when following trusts (to enumerate their SPNs).
func (c *Collector) shouldDiscoverDomains() bool {
	return c.config.Domain != "" && (!c.config.DomainEnumOnly || c.config.FollowTrusts)
}

// discoverDomains reads the home domain's identity and trusts and, with
// --follow-trusts, binds to the DCs of domains that trust us. It runs at most
// once per collection, from the single-threaded server-list phase.
//
// Lockout safety: the home bind happens first. If the home DC rejects the
// credentials, the collector-wide LDAP failure flag is set and no trusted DC
// is ever contacted. Each trusted domain then gets exactly one bind attempt.
func (c *Collector) discoverDomains(homeClient *ad.Client) {
	if c.domainsDiscovered || !c.shouldDiscoverDomains() {
		return
	}
	c.domainsDiscovered = true
	if c.domains == nil {
		c.domains = newDomainRegistry()
	}

	if homeClient == nil {
		homeClient = c.newADClient(c.config.Domain)
		if homeClient == nil {
			return
		}
		defer homeClient.Close()
	}

	// Bind first, separately from the queries, so a successful bind is
	// recorded even if a later search is refused by ACLs.
	if err := homeClient.Connect(); err != nil {
		c.noteLDAPError("", err)
		// Without --follow-trusts this is only a passive enrichment, and the
		// same bind failure is reported by the lookups that need LDAP, so keep
		// it out of the default output.
		level := logging.LevelVerbose
		if c.config.FollowTrusts {
			level = slog.LevelWarn
		}
		c.config.Logger.Log(context.Background(), level, "Could not bind to home domain; trust discovery skipped", "domain", c.config.Domain, "error", ldapErrorSummary(err))
		return
	}
	c.homeLDAPBindOK.Store(true)

	identity, err := homeClient.DomainIdentity()
	if err != nil {
		c.config.Logger.Warn("Could not read home domain identity; trust-aware resolution disabled", "domain", c.config.Domain, "error", ldapErrorSummary(err))
		return
	}
	if identity.DNSName == "" {
		identity.DNSName = c.config.Domain
	}
	c.domains.register(identity, true)

	trusts, err := homeClient.EnumerateTrusts()
	if err != nil {
		c.config.Logger.Warn("Could not enumerate domain trusts", "domain", c.config.Domain, "error", ldapErrorSummary(err))
	}
	for _, trust := range trusts {
		c.domains.register(trust, false)
	}

	if c.config.FollowTrusts {
		c.crawlTrusts(trusts)
	}
	c.logDiscoveredDomains()
}

// crawlTrusts performs a breadth-first walk over trusts, binding to each
// partner that trusts us. Depth 1 (the default) visits only direct trusts.
// Deeper hops are only taken through transitive trusts on both sides of the
// hop, because authentication cannot chain through an external
// (non-transitive) trust.
func (c *Collector) crawlTrusts(direct []ad.DomainInfo) {
	maxDepth := c.config.TrustDepth
	if maxDepth < 1 {
		maxDepth = 1
	}
	if c.config.NTHash != "" && !c.config.UseKerberos {
		c.config.Logger.Warn("--follow-trusts: NT hash authentication cannot cross domain trusts; trusted domains will not be queried (use a password or -k)")
		return
	}

	type hop struct {
		info  ad.DomainInfo
		depth int
	}
	visited := map[string]bool{strings.ToLower(c.config.Domain): true}
	var queue []hop
	for _, t := range direct {
		if t.TrustsUs() && t.DNSName != "" {
			queue = append(queue, hop{info: t, depth: 1})
		}
	}

	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		key := strings.ToLower(h.info.DNSName)
		if visited[key] {
			continue
		}
		visited[key] = true

		e := c.domains.register(h.info, false)
		if e == nil || e.isHome {
			continue
		}
		c.domains.setDC(e, c.config.DomainDCs[key])

		domain, dc, credDomain := c.trustedClientTarget(e)
		client := c.buildADClient(domain, dc, credDomain)
		identity, err := client.DomainIdentity()
		if err != nil {
			client.Close()
			c.trustedDomainFailed(domain, err)
			continue
		}
		c.domains.register(identity, false)
		c.domains.setQueryable(e)
		c.config.Logger.Info("Bound to trusted domain", "domain", e.DNSName, "auth", client.AuthMethod(), "depth", h.depth)

		if h.depth < maxDepth {
			next, err := client.EnumerateTrusts()
			if err != nil {
				c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Could not enumerate trusts of trusted domain", "domain", e.DNSName, "error", ldapErrorSummary(err))
			}
			for _, t := range next {
				// Record every partner for SID/name classification, even
				// those we cannot authenticate to.
				c.domains.register(t, false)
				if t.TrustsUs() && t.DNSName != "" && t.IsTransitive() && h.info.IsTransitive() {
					queue = append(queue, hop{info: t, depth: h.depth + 1})
				}
			}
		}
		client.Close()
	}
}

// logDiscoveredDomains prints one line per known domain.
func (c *Collector) logDiscoveredDomains() {
	r := c.domains
	if r == nil {
		return
	}
	r.mu.RLock()
	entries := append([]*domainEntry(nil), r.entries...)
	r.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isHome != entries[j].isHome {
			return entries[i].isHome
		}
		return entries[i].DNSName < entries[j].DNSName
	})
	for _, e := range entries {
		status := "known (not queried)"
		switch {
		case e.isHome:
			status = "home"
		case e.disabled != "":
			status = "disabled: " + e.disabled
		case e.queryable:
			status = "queryable"
		}
		c.config.Logger.Info("Domain", "dns", e.DNSName, "netbios", e.NetBIOSName, "sid", e.SID,
			"trustDirection", e.TrustDirection, "transitive", e.IsTransitive(), "status", status)
	}
}
