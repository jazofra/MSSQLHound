package collector

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/SpecterOps/MSSQLHound/internal/ad"
	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
	"github.com/SpecterOps/MSSQLHound/internal/types"
)

const (
	homeSID     = "S-1-5-21-111-111-111"
	emeaSID     = "S-1-5-21-222-222-222"
	partnerSID  = "S-1-5-21-333-333-333"
	machineSID  = "S-1-5-21-999-999-999" // a SQL Server's local account database
	unknownSID  = "S-1-5-21-444-444-444" // a domain nobody told us about
	trustedName = "partner.com"
)

// testRegistry returns a registry with a home domain (corp.local), a child
// domain (emea.corp.local) and a forest partner (partner.com). The trusted
// domains are registered but not queryable, so nothing ever dials a DC.
func testRegistry() *domainRegistry {
	r := newDomainRegistry()
	r.register(ad.DomainInfo{DNSName: "corp.local", NetBIOSName: "CORP", SID: homeSID}, true)
	r.register(ad.DomainInfo{DNSName: "emea.corp.local", NetBIOSName: "EMEA", SID: emeaSID,
		TrustDirection: ad.TrustDirectionBidirectional, TrustType: ad.TrustTypeUplevel, TrustAttributes: 0x20}, false)
	r.register(ad.DomainInfo{DNSName: trustedName, NetBIOSName: "PARTNER", SID: partnerSID,
		TrustDirection: ad.TrustDirectionBidirectional, TrustType: ad.TrustTypeUplevel, TrustAttributes: 0x8}, false)
	return r
}

func testCollector() *Collector {
	return &Collector{
		config:      &Config{Domain: "CORP.LOCAL"},
		domains:     testRegistry(),
		adSeenNodes: make(map[string]bool),
	}
}

func entryDNS(e *domainEntry) string {
	if e == nil {
		return "<nil>"
	}
	return e.DNSName
}

func TestDomainRegistryLookups(t *testing.T) {
	r := testRegistry()

	sidTests := map[string]string{
		emeaSID + "-1105":    "emea.corp.local",
		homeSID + "-500":     "corp.local",
		partnerSID + "-1234": trustedName,
		unknownSID + "-1000": "<nil>",
		"S-1-5-32-544":       "<nil>",
		emeaSID:              "<nil>", // a bare domain SID is not a principal SID
	}
	for sid, want := range sidTests {
		if got := entryDNS(r.forSID(sid)); got != want {
			t.Errorf("forSID(%q) = %s, want %s", sid, got, want)
		}
	}

	nameTests := map[string]string{
		`EMEA\bob`:            "emea.corp.local",
		`emea\bob`:            "emea.corp.local",
		`partner.com\bob`:     trustedName,
		"bob@PARTNER.COM":     trustedName,
		`CORP\alice`:          "corp.local",
		"alice@corp.local":    "corp.local",
		"bob":                 "<nil>",
		`UNKNOWN\bob`:         "<nil>",
		"bob@alternate-upn.x": "<nil>",
	}
	for name, want := range nameTests {
		if got := entryDNS(r.forName(name)); got != want {
			t.Errorf("forName(%q) = %s, want %s", name, got, want)
		}
	}

	hostTests := map[string]string{
		"sql01.emea.corp.local":  "emea.corp.local", // longest suffix wins over corp.local
		"sql01.corp.local":       "corp.local",
		"SQL01.PARTNER.COM.":     trustedName,
		"db.dev.emea.corp.local": "emea.corp.local",
		"sql01":                  "<nil>",
		"10.0.0.1":               "<nil>",
		"sql01.elsewhere.org":    "<nil>",
	}
	for host, want := range hostTests {
		if got := entryDNS(r.forHost(host)); got != want {
			t.Errorf("forHost(%q) = %s, want %s", host, got, want)
		}
	}
}

func TestDomainRegistryMergesObservations(t *testing.T) {
	r := newDomainRegistry()
	// Seen first through a trust object, then through the DC's own identity
	// (which carries no trust metadata, and here no NetBIOS name).
	r.register(ad.DomainInfo{DNSName: trustedName, NetBIOSName: "PARTNER", SID: partnerSID, TrustDirection: 3}, false)
	r.register(ad.DomainInfo{DNSName: "PARTNER.COM", SID: partnerSID}, false)
	if len(r.entries) != 1 {
		t.Fatalf("expected observations to merge into one entry, got %d", len(r.entries))
	}
	e := r.entries[0]
	if e.NetBIOSName != "PARTNER" || e.TrustDirection != 3 {
		t.Fatalf("merge lost data: %+v", e)
	}
}

func TestDomainRegistryNilSafe(t *testing.T) {
	var r *domainRegistry
	if r.forSID(emeaSID+"-1") != nil || r.forName(`EMEA\x`) != nil || r.forHost("a.b.c") != nil ||
		r.forDomain("corp.local") != nil || r.home() != nil || r.usable(nil) || r.spnSwept("x") {
		t.Fatal("nil registry must behave as empty")
	}
	r.markSPNSwept("x")
	if r.register(ad.DomainInfo{DNSName: "x"}, true) != nil {
		t.Fatal("nil registry register must be a no-op")
	}
}

func TestIsKnownDomainSID(t *testing.T) {
	info := &types.ServerInfo{DomainSID: homeSID, ComputerSID: homeSID + "-1001"}

	// Without a registry the result must match the historical DomainSID rule.
	bare := &Collector{config: &Config{}}
	for sid, want := range map[string]bool{
		homeSID + "-1105":    true,
		emeaSID + "-1105":    false,
		machineSID + "-1000": false,
		"S-1-5-32-544":       false,
		"S-1-5-18":           false,
	} {
		if got := bare.isKnownDomainSID(sid, info); got != want {
			t.Errorf("no registry: isKnownDomainSID(%q) = %v, want %v", sid, got, want)
		}
	}

	// The computer account's domain is authoritative even when DomainSID was
	// guessed from a login in another domain.
	guessedWrong := &types.ServerInfo{DomainSID: partnerSID, ComputerSID: homeSID + "-1001"}
	if !bare.isKnownDomainSID(homeSID+"-2000", guessedWrong) {
		t.Error("SID in the computer's domain must be a domain SID")
	}

	// With a registry, trusted domains are domain SIDs; unknown ones are not.
	c := testCollector()
	if !c.isKnownDomainSID(emeaSID+"-1105", info) || !c.isKnownDomainSID(partnerSID+"-7", info) {
		t.Error("registered trusted domain SIDs must be domain SIDs")
	}
	if c.isKnownDomainSID(machineSID+"-1000", info) || c.isKnownDomainSID(unknownSID+"-1000", info) {
		t.Error("unregistered SIDs must not be domain SIDs")
	}
}

func TestIsLocalGroupPrincipal(t *testing.T) {
	info := &types.ServerInfo{DomainSID: homeSID, ComputerSID: homeSID + "-1001"}
	group := func(name, sid string) types.ServerPrincipal {
		return types.ServerPrincipal{Name: name, TypeDescription: "WINDOWS_GROUP", SecurityIdentifier: sid}
	}

	c := testCollector()
	bare := &Collector{config: &Config{}}

	if !c.isLocalGroupPrincipal(group(`BUILTIN\Administrators`, "S-1-5-32-544"), info) {
		t.Error("BUILTIN group must be local")
	}
	if !c.isLocalGroupPrincipal(group(`SQL01\ConfigMgr_DViewAccess`, machineSID+"-1008"), info) {
		t.Error("machine-local group must stay local")
	}
	if c.isLocalGroupPrincipal(group(`CORP\DBAs`, homeSID+"-3000"), info) {
		t.Error("home domain group must not be local")
	}
	if c.isLocalGroupPrincipal(group(`PARTNER\DBAs`, partnerSID+"-3000"), info) {
		t.Error("trusted domain group must not be classified as machine-local")
	}
	// Historical behaviour is kept when the trust is unknown.
	if !bare.isLocalGroupPrincipal(group(`PARTNER\DBAs`, partnerSID+"-3000"), info) {
		t.Error("without trust knowledge the old classification must be preserved")
	}
	// Logins (not groups) are never local groups.
	login := types.ServerPrincipal{Name: `SQL01\bob`, TypeDescription: "WINDOWS_LOGIN", SecurityIdentifier: machineSID + "-1001"}
	if c.isLocalGroupPrincipal(login, info) {
		t.Error("a login is not a local group")
	}
}

func TestServerDomainPrecedence(t *testing.T) {
	c := testCollector()
	tests := []struct {
		server *ServerToProcess
		want   string
	}{
		// A registered domain matching the FQDN wins over everything else.
		{&ServerToProcess{Hostname: "sql01.partner.com", Domain: "OTHER.LOCAL"}, trustedName},
		// Then the domain the server was discovered in.
		{&ServerToProcess{Hostname: "sql01", Domain: "EMEA.CORP.LOCAL"}, "EMEA.CORP.LOCAL"},
		// Then --domain (the historical behaviour).
		{&ServerToProcess{Hostname: "sql01"}, "CORP.LOCAL"},
		{&ServerToProcess{Hostname: "sql01.unregistered.org"}, "CORP.LOCAL"},
	}
	for _, tt := range tests {
		if got := c.serverDomain(tt.server); got != tt.want {
			t.Errorf("serverDomain(%+v) = %q, want %q", *tt.server, got, tt.want)
		}
	}
}

func TestLinkedServerDomain(t *testing.T) {
	c := testCollector()
	if got := c.linkedServerDomain("CORP.LOCAL", "10.1.0.5", "sql02.partner.com"); got != "PARTNER.COM" {
		t.Errorf("reverse-DNS FQDN in a trusted domain: got %q", got)
	}
	if got := c.linkedServerDomain("CORP.LOCAL", "sql02"); got != "CORP.LOCAL" {
		t.Errorf("short name must fall back to the source domain: got %q", got)
	}
	if got := c.linkedServerDomain("CORP.LOCAL", "sql02.unregistered.org"); got != "CORP.LOCAL" {
		t.Errorf("unregistered FQDN must fall back to the source domain: got %q", got)
	}
}

func TestDomainOfServerInfoAndPrincipalNaming(t *testing.T) {
	c := testCollector()
	home := &types.ServerInfo{FQDN: "sql01.corp.local", Hostname: "sql01"}
	trusted := &types.ServerInfo{FQDN: "sql02.partner.com", Hostname: "sql02"}
	unregistered := &types.ServerInfo{FQDN: "sql03.elsewhere.org", Hostname: "sql03"}

	if got := c.domainOfServerInfo(home); got != "CORP.LOCAL" {
		t.Errorf("home server domain = %q", got)
	}
	if got := c.domainOfServerInfo(trusted); got != "PARTNER.COM" {
		t.Errorf("trusted server domain = %q", got)
	}
	if got := c.domainOfServerInfo(unregistered); got != "CORP.LOCAL" {
		t.Errorf("unregistered server must fall back to --domain, got %q", got)
	}
	if got := c.principalDomainName(emeaSID+"-1105", home); got != "EMEA.CORP.LOCAL" {
		t.Errorf("principal of a trusted domain named %q", got)
	}
	if got := c.principalDomainName(machineSID+"-1105", home); got != "CORP.LOCAL" {
		t.Errorf("unregistered principal must use the server domain, got %q", got)
	}
}

func TestSetLDAPAuthFailedScopesTrustedDomains(t *testing.T) {
	c := testCollector()
	c.config.Logger = discardLogger()
	partner := c.domains.forDomain(trustedName)
	c.domains.setQueryable(partner)

	if client := c.newADClient("PARTNER.COM"); client == nil {
		t.Fatal("queryable trusted domain must yield a client")
	} else if client.Domain() != "PARTNER.COM" {
		t.Fatalf("trusted client domain = %q", client.Domain())
	}

	// A rejection by the trusted DC disables only that domain.
	c.setLDAPAuthFailed("partner.com")
	if c.ldapAuthFailed {
		t.Fatal("trusted-domain rejection must not disable home LDAP")
	}
	if c.newADClient("PARTNER.COM") != nil {
		t.Fatal("disabled trusted domain must not yield a client")
	}
	if c.newADClient("CORP.LOCAL") == nil {
		t.Fatal("home domain must still be usable")
	}

	// A home rejection stops every bind, trusted ones included.
	c.setLDAPAuthFailed("")
	if !c.ldapAuthFailed || c.newADClient("CORP.LOCAL") != nil {
		t.Fatal("home rejection must stop all LDAP binds")
	}
}

func TestNewADClientNeverContactsUnfollowedTrusts(t *testing.T) {
	c := testCollector()
	// Registered but never confirmed queryable (passive mode): no client.
	if c.newADClient("partner.com") != nil {
		t.Fatal("passive mode must never build a client for a trusted domain")
	}
	// Unregistered domains keep the historical behaviour (bind via --dc).
	if c.newADClient("unregistered.org") == nil {
		t.Fatal("unregistered domain must keep historical behaviour")
	}
}

func TestDomainClientSetRouting(t *testing.T) {
	c := testCollector()
	set := c.newDomainClientSet()
	defer set.Close()

	// SIDs: home goes to --domain; foreign SIDs never fall back to home.
	if d, err := set.targetForSID(homeSID + "-500"); err != nil || d != "CORP.LOCAL" {
		t.Errorf("home SID -> (%q, %v)", d, err)
	}
	for _, sid := range []string{partnerSID + "-500", unknownSID + "-500"} {
		if _, err := set.targetForSID(sid); !errors.Is(err, errDomainUnavailable) {
			t.Errorf("foreign SID %s must be unavailable, got %v", sid, err)
		}
	}
	c.domains.setQueryable(c.domains.forDomain(trustedName))
	if d, err := set.targetForSID(partnerSID + "-500"); err != nil || d != trustedName {
		t.Errorf("queryable trusted SID -> (%q, %v)", d, err)
	}

	// Names.
	nameTests := []struct {
		name    string
		want    string
		wantErr error
	}{
		{`CORP\svc`, "CORP.LOCAL", nil},
		{`corp.local\svc`, "CORP.LOCAL", nil},
		{"svc", "CORP.LOCAL", nil},
		{"svc@alternate-upn.com", "CORP.LOCAL", nil}, // unregistered UPN suffix: historical lookup
		{`PARTNER\svc`, trustedName, nil},
		{`EMEA\svc`, "", errDomainUnavailable},  // registered but not queryable
		{`OTHER\svc`, "", errDomainUnavailable}, // positively not the home domain
	}
	for _, tt := range nameTests {
		d, err := set.targetForName(tt.name)
		if !errors.Is(err, tt.wantErr) || d != tt.want {
			t.Errorf("targetForName(%q) = (%q, %v), want (%q, %v)", tt.name, d, err, tt.want, tt.wantErr)
		}
	}

	// Without a known home identity the legacy home lookup is kept.
	legacy := (&Collector{config: &Config{Domain: "CORP.LOCAL"}}).newDomainClientSet()
	if d, err := legacy.targetForName(`OTHER\svc`); err != nil || d != "CORP.LOCAL" {
		t.Errorf("legacy targetForName = (%q, %v)", d, err)
	}
	if d, err := legacy.targetForSID(unknownSID + "-1"); err != nil || d != "CORP.LOCAL" {
		t.Errorf("legacy targetForSID = (%q, %v)", d, err)
	}
}

func TestShouldDiscoverDomains(t *testing.T) {
	tests := []struct {
		cfg  Config
		want bool
	}{
		{Config{}, false},
		{Config{Domain: "CORP.LOCAL"}, true},
		{Config{Domain: "CORP.LOCAL", DomainEnumOnly: true}, false},
		{Config{Domain: "CORP.LOCAL", DomainEnumOnly: true, FollowTrusts: true}, true},
	}
	for _, tt := range tests {
		cfg := tt.cfg
		if got := (&Collector{config: &cfg}).shouldDiscoverDomains(); got != tt.want {
			t.Errorf("shouldDiscoverDomains(%+v) = %v, want %v", tt.cfg, got, tt.want)
		}
	}
}

func TestCredentialDNSDomain(t *testing.T) {
	c := &Collector{config: &Config{Domain: "CORP.LOCAL", LDAPUser: `CORP\svc`}}
	if got := c.credentialDNSDomain(); got != "corp.local" {
		t.Errorf("NetBIOS user -> %q", got)
	}
	c.config.LDAPUser = "svc@Corp.Com"
	if got := c.credentialDNSDomain(); got != "corp.com" {
		t.Errorf("UPN user -> %q", got)
	}
}

// buildTrustedLoginServerInfo returns a home-domain SQL Server with logins
// from a trusted domain (a user and a group) and a machine-local group.
func buildTrustedLoginServerInfo() *types.ServerInfo {
	info := baseServerInfo()
	addWindowsLogin(info, `PARTNER\alice`, partnerSID+"-1105")
	addWindowsGroup(info, `PARTNER\DBAs`, partnerSID+"-3000", withMemberOf(roleMembership("sysadmin", testServerOID)))
	addWindowsGroup(info, testHostname+`\LocalOps`, machineSID+"-1008")
	return info
}

func TestTrustedDomainGroupIsNotLocalGroupInEdges(t *testing.T) {
	info := buildTrustedLoginServerInfo()
	result := runEdgeCreationWithSetup(t, info, &Config{Domain: "domain.com"}, func(c *Collector) {
		c.domains.register(ad.DomainInfo{DNSName: trustedName, NetBIOSName: "PARTNER", SID: partnerSID}, false)
	})
	hasLogin := bloodhound.EdgeKinds.HasLogin

	assertEdgeExists(t, result.Edges, hasLogin, partnerSID+"-3000", "*DBAs@*", "trusted group keeps its SID-keyed HasLogin")
	assertEdgeExists(t, result.Edges, hasLogin, partnerSID+"-1105", "*alice@*", "trusted user keeps its SID-keyed HasLogin")
	assertEdgeNotExists(t, result.Edges, hasLogin, testHostname+"-"+partnerSID+"-3000", "*",
		"trusted group must not be modelled as a machine-local group")
	assertEdgeExists(t, result.Edges, hasLogin, testHostname+"-"+machineSID+"-1008", "*LocalOps@*",
		"machine-local group is still modelled as a local group")
}

func TestTrustedDomainGroupWithoutTrustKnowledgeKeepsHistoricalEdges(t *testing.T) {
	result := runEdgeCreation(t, buildTrustedLoginServerInfo(), false)
	assertEdgeExists(t, result.Edges, bloodhound.EdgeKinds.HasLogin, testHostname+"-"+partnerSID+"-3000", "*",
		"without trust knowledge the old local-group edge is preserved")
}

func TestServerNodeListsTrustedDomainPrincipals(t *testing.T) {
	info := buildTrustedLoginServerInfo()
	c := testCollector()
	c.config.Domain = "domain.com"
	node := c.createServerNode(info)
	got, _ := node.Properties["domainPrincipalsWithSysadmin"].([]string)
	found := false
	for _, id := range got {
		if id == `PARTNER\DBAs@`+info.ObjectIdentifier {
			found = true
		}
	}
	if !found {
		t.Fatalf("domainPrincipalsWithSysadmin = %v, want the trusted PARTNER\\DBAs login", got)
	}
}

func TestCreateADNodesNamesTrustedPrincipalsByTheirDomain(t *testing.T) {
	info := buildTrustedLoginServerInfo()
	c, _ := New(&Config{TempDir: t.TempDir(), Domain: "DOMAIN.COM", Logger: discardLogger()})
	c.domains.register(ad.DomainInfo{DNSName: trustedName, NetBIOSName: "PARTNER", SID: partnerSID}, false)
	// Block every LDAP bind so the test never touches the network.
	c.setLDAPAuthFailed("")

	if err := c.createADNodes(info); err != nil {
		t.Fatalf("createADNodes: %v", err)
	}

	names := map[string]string{}
	for _, n := range append(append([]*bloodhound.Node{}, c.adUsers...), c.adGroups...) {
		names[n.ID], _ = n.Properties["name"].(string)
	}
	if got := names[partnerSID+"-1105"]; got != "alice@PARTNER.COM" {
		t.Errorf("trusted user node name = %q, want alice@PARTNER.COM", got)
	}
	if got := names[partnerSID+"-3000"]; got != "DBAs@PARTNER.COM" {
		t.Errorf("trusted group node name = %q, want DBAs@PARTNER.COM", got)
	}
	if _, ok := names[testHostname+"-"+partnerSID+"-3000"]; ok {
		t.Error("trusted group must not get a machine-local group node")
	}
	if _, ok := names[testHostname+"-"+machineSID+"-1008"]; !ok {
		t.Error("machine-local group node missing")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
