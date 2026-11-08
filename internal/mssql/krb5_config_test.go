package mssql

import (
	"strings"
	"testing"
)

// legacyKrb5Config is the exact template GenerateKrb5Config produced before
// cross-domain support; single-domain runs must keep producing it verbatim.
const legacyKrb5Config = `[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_kdc = false
    udp_preference_limit = 1

[realms]
    CORP.LOCAL = {
        kdc = 10.0.0.1
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
`

func TestBuildKrb5ConfigSingleDomainUnchanged(t *testing.T) {
	if got := buildKrb5Config("corp.local", "10.0.0.1", nil, false); got != legacyKrb5Config {
		t.Fatalf("single-domain krb5.conf changed:\n%s", got)
	}
}

func TestBuildKrb5ConfigWithTrustedRealms(t *testing.T) {
	got := buildKrb5Config("CORP.LOCAL", "10.0.0.1", map[string]string{
		"partner.com":     "10.2.0.1",
		"emea.corp.local": "dc01.emea.corp.local",
		"corp.local":      "ignored-home-duplicate",
	}, true)

	for _, want := range []string{
		"dns_lookup_kdc = true",
		"CORP.LOCAL = {\n        kdc = 10.0.0.1\n    }",
		"EMEA.CORP.LOCAL = {\n        kdc = dc01.emea.corp.local\n    }",
		"PARTNER.COM = {\n        kdc = 10.2.0.1\n    }",
		".partner.com = PARTNER.COM",
		"emea.corp.local = EMEA.CORP.LOCAL",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("krb5.conf missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ignored-home-duplicate") {
		t.Error("a --domain-dc entry for the home domain must not override --dc")
	}
	// Deterministic ordering: EMEA before PARTNER.
	if strings.Index(got, "EMEA.CORP.LOCAL = {") > strings.Index(got, "PARTNER.COM = {") {
		t.Error("trusted realms must be sorted")
	}
}
