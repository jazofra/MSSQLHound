// Package mssql - Kerberos configuration helpers.
// Auto-generates a minimal krb5.conf when --domain and --dc are provided
// but no explicit krb5.conf path is given. This avoids requiring users to
// manually create /etc/krb5.conf on systems where it doesn't exist.
package mssql

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// GenerateKrb5Config creates a minimal krb5.conf in a temp file and returns its path.
// The caller is responsible for cleaning up the file (e.g. via os.Remove or defer).
func GenerateKrb5Config(domain, kdcAddress string) (string, error) {
	return GenerateKrb5ConfigWithTrusts(domain, kdcAddress, nil, false)
}

// GenerateKrb5ConfigWithTrusts is GenerateKrb5Config for cross-domain runs.
//
// Kerberos authentication to a service in a trusted domain works by
// referral: the home KDC hands out a cross-realm TGT and the client must
// then reach the trusted realm's KDC. A single-realm krb5.conf with
// dns_lookup_kdc = false leaves gokrb5 no way to find that KDC, so:
//   - every trustedKDCs entry (lower-case DNS domain -> KDC host) gets its own
//     [realms] stanza and [domain_realm] mapping, and
//   - dnsLookupKDC enables DNS SRV discovery for any other trusted realm.
//
// With nil trustedKDCs and dnsLookupKDC false the output is byte-for-byte the
// historical single-realm file.
func GenerateKrb5ConfigWithTrusts(domain, kdcAddress string, trustedKDCs map[string]string, dnsLookupKDC bool) (string, error) {
	content := buildKrb5Config(domain, kdcAddress, trustedKDCs, dnsLookupKDC)

	f, err := os.CreateTemp("", "mssqlhound-krb5-*.conf")
	if err != nil {
		return "", fmt.Errorf("creating temp krb5.conf: %w", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("writing temp krb5.conf: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("closing temp krb5.conf: %w", err)
	}
	return f.Name(), nil
}

// buildKrb5Config renders the krb5.conf text (see GenerateKrb5ConfigWithTrusts).
func buildKrb5Config(domain, kdcAddress string, trustedKDCs map[string]string, dnsLookupKDC bool) string {
	type realmEntry struct{ dns, kdc string }
	realms := []realmEntry{{strings.ToLower(domain), kdcAddress}}

	// Deterministic order keeps the generated file stable across runs.
	trusted := make([]string, 0, len(trustedKDCs))
	for dns := range trustedKDCs {
		if !strings.EqualFold(dns, domain) {
			trusted = append(trusted, dns)
		}
	}
	sort.Strings(trusted)
	for _, dns := range trusted {
		realms = append(realms, realmEntry{strings.ToLower(dns), trustedKDCs[dns]})
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[libdefaults]\n    default_realm = %s\n    dns_lookup_kdc = %t\n    udp_preference_limit = 1\n\n[realms]\n",
		strings.ToUpper(domain), dnsLookupKDC)
	for _, r := range realms {
		fmt.Fprintf(&b, "    %s = {\n        kdc = %s\n    }\n", strings.ToUpper(r.dns), r.kdc)
	}
	b.WriteString("\n[domain_realm]\n")
	for _, r := range realms {
		realm := strings.ToUpper(r.dns)
		fmt.Fprintf(&b, "    .%s = %s\n    %s = %s\n", r.dns, realm, r.dns, realm)
	}
	return b.String()
}
