package ad

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// encodeSID is the inverse of decodeSID, used to build binary
// securityIdentifier attributes for trustedDomain test entries.
func encodeSID(t *testing.T, sid string) []byte {
	t.Helper()
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || parts[0] != "S" {
		t.Fatalf("bad SID %q", sid)
	}
	revision, _ := strconv.Atoi(parts[1])
	authority, _ := strconv.ParseUint(parts[2], 10, 48)
	subs := parts[3:]
	b := make([]byte, 8+4*len(subs))
	b[0] = byte(revision)
	b[1] = byte(len(subs))
	for i := 0; i < 6; i++ {
		b[2+i] = byte(authority >> (8 * (5 - i)))
	}
	for i, s := range subs {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			t.Fatalf("bad sub-authority %q", s)
		}
		binary.LittleEndian.PutUint32(b[8+4*i:], uint32(v))
	}
	return b
}

func TestEncodeSIDRoundTrip(t *testing.T) {
	sid := "S-1-5-21-1004336348-1177238915-682003330"
	if got := decodeSID(encodeSID(t, sid)); got != sid {
		t.Fatalf("round trip = %q, want %q", got, sid)
	}
}

func TestDomainSIDOf(t *testing.T) {
	tests := []struct {
		sid, want string
	}{
		{"S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3"},
		{"S-1-5-21-1004336348-1177238915-682003330-512", "S-1-5-21-1004336348-1177238915-682003330"},
		{" S-1-5-21-1-2-3-500 ", "S-1-5-21-1-2-3"},
		{"S-1-5-21-1-2-3", ""},     // a bare domain SID has no RID to strip
		{"S-1-5-32-544", ""},       // BUILTIN\Administrators
		{"S-1-5-11", ""},           // Authenticated Users
		{"S-1-5-21-1-2-3-x", ""},   // malformed RID
		{"S-1-5-21-1-2-3-4-5", ""}, // too many sub-authorities
		{"", ""},
	}
	for _, tt := range tests {
		if got := DomainSIDOf(tt.sid); got != tt.want {
			t.Errorf("DomainSIDOf(%q) = %q, want %q", tt.sid, got, tt.want)
		}
	}
}

func trustEntry(t *testing.T, attrs map[string]string, sid string) *ldap.Entry {
	t.Helper()
	values := map[string][]string{}
	for k, v := range attrs {
		values[k] = []string{v}
	}
	if sid != "" {
		values["securityIdentifier"] = []string{string(encodeSID(t, sid))}
	}
	return ldap.NewEntry("CN=x,CN=System,DC=corp,DC=local", values)
}

func TestParseTrustEntry(t *testing.T) {
	t.Run("uplevel bidirectional forest trust", func(t *testing.T) {
		info, ok := parseTrustEntry(trustEntry(t, map[string]string{
			"trustPartner":    "Partner.COM.",
			"flatName":        "partner",
			"trustDirection":  "3",
			"trustType":       "2",
			"trustAttributes": "8",
		}, "S-1-5-21-7-8-9"))
		if !ok {
			t.Fatal("expected entry to be kept")
		}
		if info.DNSName != "partner.com" || info.NetBIOSName != "PARTNER" || info.SID != "S-1-5-21-7-8-9" {
			t.Fatalf("unexpected identity: %+v", info)
		}
		if !info.TrustsUs() || !info.IsTransitive() {
			t.Fatalf("expected bidirectional transitive trust: %+v", info)
		}
	})

	t.Run("outbound-only external trust", func(t *testing.T) {
		info, ok := parseTrustEntry(trustEntry(t, map[string]string{
			"trustPartner":    "ext.local",
			"flatName":        "EXT",
			"trustDirection":  "2",
			"trustType":       "2",
			"trustAttributes": "4", // quarantined, not transitive
		}, "S-1-5-21-4-5-6"))
		if !ok {
			t.Fatal("expected entry to be kept for identification")
		}
		if info.TrustsUs() {
			t.Error("outbound-only trust must not be treated as trusting us")
		}
		if info.IsTransitive() {
			t.Error("external trust must not be transitive")
		}
	})

	t.Run("within-forest trust flagged non-transitive", func(t *testing.T) {
		info, _ := parseTrustEntry(trustEntry(t, map[string]string{
			"trustPartner": "child.corp.local", "trustDirection": "3", "trustType": "2",
			"trustAttributes": strconv.Itoa(trustAttrWithinForest | trustAttrNonTransitive),
		}, "S-1-5-21-1-1-1"))
		if info.IsTransitive() {
			t.Error("non-transitive flag must win")
		}
	})

	t.Run("downlevel trust keeps NetBIOS identity only", func(t *testing.T) {
		info, ok := parseTrustEntry(trustEntry(t, map[string]string{
			"trustPartner":   "OLDNT",
			"trustDirection": "1",
			"trustType":      "1",
		}, "S-1-5-21-2-2-2"))
		if !ok {
			t.Fatal("expected downlevel trust to be kept")
		}
		if info.DNSName != "" {
			t.Errorf("downlevel trustPartner must not become a DNS name, got %q", info.DNSName)
		}
		if info.NetBIOSName != "OLDNT" {
			t.Errorf("NetBIOSName = %q, want OLDNT", info.NetBIOSName)
		}
	})

	t.Run("MIT realm skipped", func(t *testing.T) {
		if _, ok := parseTrustEntry(trustEntry(t, map[string]string{
			"trustPartner": "REALM.EXAMPLE", "trustDirection": "3", "trustType": "3",
		}, "")); ok {
			t.Error("MIT realm trust must be skipped")
		}
	})

	t.Run("entry without SID or DNS dropped", func(t *testing.T) {
		if _, ok := parseTrustEntry(trustEntry(t, map[string]string{"trustType": "1"}, "")); ok {
			t.Error("useless entry must be dropped")
		}
	})
}

func TestNTLMBindIdentity(t *testing.T) {
	tests := []struct {
		name                 string
		user, target, cred   string
		cross, hash          bool
		wantDomain, wantUser string
		wantErr              error
	}{
		// Same-domain binds keep the historical parsing exactly.
		{"same domain netbios", `CORP\svc`, "corp.local", "", false, false, "CORP", "svc", nil},
		{"same domain upn", "svc@corp.local", "corp.local", "", false, false, "corp.local", "svc", nil},
		{"same domain bare", "svc", "CORP.LOCAL", "", false, false, "CORP.LOCAL", "svc", nil},
		{"same domain hash", `CORP\svc`, "corp.local", "", false, true, "CORP", "svc", nil},
		// Cross-domain binds use a UPN with an empty domain so go-ntlmssp does
		// not substitute the trusted DC's own domain name.
		{"cross netbios", `CORP\svc`, "trusted.local", "corp.local", true, false, "", "svc@corp.local", nil},
		{"cross dns prefix", `corp.local\svc`, "trusted.local", "corp.local", true, false, "", "svc@corp.local", nil},
		{"cross upn untouched", "svc@corp.com", "trusted.local", "corp.com", true, false, "", "svc@corp.com", nil},
		{"cross bare", "svc", "trusted.local", "corp.local", true, false, "", "svc@corp.local", nil},
		{"cross hash unsupported", `CORP\svc`, "trusted.local", "corp.local", true, true, "", "", errCrossDomainNTHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, user, err := ntlmBindIdentity(tt.user, tt.target, tt.cred, tt.cross, tt.hash)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if domain != tt.wantDomain || user != tt.wantUser {
				t.Fatalf("got (%q, %q), want (%q, %q)", domain, user, tt.wantDomain, tt.wantUser)
			}
		})
	}
}

func TestCrossDomainNTHashErrorIsNotAuthError(t *testing.T) {
	// Must not trip the invalid-credential lockout guards.
	if isLDAPAuthError(errCrossDomainNTHash) {
		t.Fatal("errCrossDomainNTHash must not look like LDAP result 49")
	}
}

func TestCrossDomainClientUsesCredentialDomain(t *testing.T) {
	client := NewClient("TRUSTED.LOCAL", "", false, `CORP\svc`, "password", "")
	if client.isCrossDomain() {
		t.Fatal("client without a credential domain must not be cross-domain")
	}
	client.SetCredentialDomain("corp.local")
	if !client.isCrossDomain() {
		t.Fatal("expected cross-domain client")
	}
	got := client.simpleBindNames()
	if len(got) == 0 || got[0] != "svc@corp.local" {
		t.Fatalf("first simple bind name = %v, want svc@corp.local first", got)
	}
	for _, name := range got {
		if strings.EqualFold(name, "svc@TRUSTED.LOCAL") {
			t.Fatalf("must not guess an account in the trusted domain: %v", got)
		}
	}

	// A credential domain equal to the target is not cross-domain.
	same := NewClient("corp.local", "", false, `CORP\svc`, "password", "")
	same.SetCredentialDomain("CORP.LOCAL")
	if same.isCrossDomain() {
		t.Fatal("same domain (case-insensitive) must not be cross-domain")
	}
}

func TestConnectReturnsCachedErrorWithoutRedialing(t *testing.T) {
	client := NewClient("corp.local", "dc.invalid", false, "", "", "")
	boom := errors.New("bind rejected")
	client.connectErr = boom

	if err := client.Connect(); !errors.Is(err, boom) {
		t.Fatalf("Connect() = %v, want cached error", err)
	}
	// Lookups on a failed client must fail fast with the same error.
	if _, err := client.ResolveSID("S-1-5-21-1-2-3-500"); !errors.Is(err, boom) {
		t.Fatalf("ResolveSID() = %v, want cached error", err)
	}
	if _, err := client.ResolveComputerSID("sql01"); !errors.Is(err, boom) {
		t.Fatalf("ResolveComputerSID() = %v, want cached error", err)
	}
}

func TestComputerSAMAccountName(t *testing.T) {
	tests := map[string]string{
		"sql01":                  "sql01$",
		"SQL01$":                 "SQL01$",
		"sql01.corp.local":       "sql01$",
		" sql01.emea.corp.local": "sql01$",
		"10.0.0.5":               "10.0.0.5$",
	}
	for in, want := range tests {
		if got := computerSAMAccountName(in); got != want {
			t.Errorf("computerSAMAccountName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestComputerFQDNMismatch(t *testing.T) {
	tests := []struct {
		requested, dnsHostName string
		want                   bool
	}{
		{"sql01.trusted.local", "sql01.corp.local", true}, // same short name, other domain
		{"SQL01.corp.local", "sql01.corp.local.", false},  // case and trailing dot ignored
		{"sql01", "sql01.corp.local", false},              // short name: no evidence
		{"sql01.corp.local", "", false},                   // no dNSHostName: no evidence
		{"10.0.0.5", "sql01.corp.local", false},           // IPs are never compared
	}
	for _, tt := range tests {
		if got := computerFQDNMismatch(tt.requested, tt.dnsHostName); got != tt.want {
			t.Errorf("computerFQDNMismatch(%q, %q) = %v, want %v", tt.requested, tt.dnsHostName, got, tt.want)
		}
	}
}
