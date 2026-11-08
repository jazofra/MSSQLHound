package ad

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Trust attribute values from MS-ADTS 6.1.6.7.9 (trustDirection),
// 6.1.6.7.15 (trustType) and 6.1.6.7.9 (trustAttributes).
const (
	// TrustDirectionInbound: the partner domain trusts the local domain, so
	// principals of the local domain can authenticate in the partner.
	TrustDirectionInbound = 1
	// TrustDirectionOutbound: the local domain trusts the partner; partner
	// principals can authenticate locally, but our credentials cannot be used
	// against the partner.
	TrustDirectionOutbound = 2
	// TrustDirectionBidirectional: both of the above.
	TrustDirectionBidirectional = 3

	// TrustTypeDownlevel is an NT4-style trust whose trustPartner is a NetBIOS
	// name rather than a DNS name.
	TrustTypeDownlevel = 1
	// TrustTypeUplevel is an Active Directory trust (DNS trustPartner).
	TrustTypeUplevel = 2
	// TrustTypeMIT is a trust with a non-Windows Kerberos realm.
	TrustTypeMIT = 3
	// TrustTypeDCE is unused in practice.
	TrustTypeDCE = 4

	trustAttrNonTransitive    = 0x1
	trustAttrForestTransitive = 0x8
	trustAttrWithinForest     = 0x20
)

// DomainInfo describes one Active Directory domain: either the domain a client
// is bound to (from DomainIdentity) or a partner read from a trustedDomain
// object (from EnumerateTrusts, in which case the Trust* fields are set from
// the point of view of the domain that holds the trust object).
type DomainInfo struct {
	DNSName         string // lower-case DNS name, e.g. "corp.local"; empty for downlevel trusts
	NetBIOSName     string // upper-case NetBIOS name, e.g. "CORP"
	SID             string // domain SID, e.g. "S-1-5-21-1-2-3"
	TrustDirection  int
	TrustType       int
	TrustAttributes int
}

// TrustsUs reports whether the partner domain accepts authentication from the
// domain that holds this trust object (inbound or bidirectional). Only such
// domains can be queried with our credentials.
func (d DomainInfo) TrustsUs() bool {
	return d.TrustDirection == TrustDirectionInbound || d.TrustDirection == TrustDirectionBidirectional
}

// IsTransitive reports whether trust can be chained through this partner.
// Within-forest (parent/child, tree-root) and forest trusts are transitive;
// external trusts and anything flagged non-transitive are not.
func (d DomainInfo) IsTransitive() bool {
	if d.TrustAttributes&trustAttrNonTransitive != 0 {
		return false
	}
	return d.TrustAttributes&(trustAttrWithinForest|trustAttrForestTransitive) != 0
}

// DomainSIDOf returns the domain portion of a domain principal SID
// ("S-1-5-21-a-b-c-RID" -> "S-1-5-21-a-b-c"). Domain and machine-local account
// SIDs both have exactly three sub-authorities after "21" followed by a RID.
// Any other shape (well-known SIDs such as S-1-5-32-544, bare domain SIDs,
// malformed input) returns "".
func DomainSIDOf(sid string) string {
	parts := strings.Split(strings.TrimSpace(sid), "-")
	if len(parts) != 8 || !strings.EqualFold(parts[0], "S") || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return ""
	}
	for _, p := range parts[4:] {
		if _, err := strconv.ParseUint(p, 10, 32); err != nil {
			return ""
		}
	}
	return strings.Join(parts[:7], "-")
}

// DomainIdentity returns the DNS name, NetBIOS name and SID of the domain this
// client is bound to.
//
// The SID comes from objectSid on the domain head object (the base DN). The
// NetBIOS name is not stored on the domain object; it lives on the domain's
// crossRef object in the configuration partition, located via the RootDSE.
// NetBIOS lookup is best effort: a failure there still returns the SID.
func (c *Client) DomainIdentity() (DomainInfo, error) {
	if err := c.Connect(); err != nil {
		return DomainInfo{}, err
	}

	info := DomainInfo{DNSName: strings.ToLower(c.domain)}

	head, err := c.conn.Search(ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"objectSid"}, nil,
	))
	if err != nil {
		return info, fmt.Errorf("read domain SID: %w", err)
	}
	if len(head.Entries) > 0 {
		info.SID = decodeSID(head.Entries[0].GetRawAttributeValue("objectSid"))
	}

	rootDSE, err := c.conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"configurationNamingContext"}, nil,
	))
	if err != nil || len(rootDSE.Entries) == 0 {
		return info, nil
	}
	configNC := rootDSE.Entries[0].GetAttributeValue("configurationNamingContext")
	if configNC == "" {
		return info, nil
	}

	partitions, err := c.conn.Search(ldap.NewSearchRequest(
		"CN=Partitions,"+configNC, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(&(objectClass=crossRef)(nCName=%s))", ldap.EscapeFilter(c.baseDN)),
		[]string{"nETBIOSName"}, nil,
	))
	if err == nil && len(partitions.Entries) > 0 {
		info.NetBIOSName = strings.ToUpper(partitions.Entries[0].GetAttributeValue("nETBIOSName"))
	}

	return info, nil
}

// EnumerateTrusts lists the trustedDomain objects of the bound domain. These
// live directly under CN=System and describe every direct trust (inbound,
// outbound, intra-forest and external). Non-AD trusts (MIT realms, DCE) are
// skipped because they cannot be queried over LDAP.
func (c *Client) EnumerateTrusts() ([]DomainInfo, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}

	result, err := c.conn.Search(ldap.NewSearchRequest(
		"CN=System,"+c.baseDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=trustedDomain)",
		[]string{"trustPartner", "flatName", "securityIdentifier", "trustDirection", "trustType", "trustAttributes"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("enumerate trusts: %w", err)
	}

	var trusts []DomainInfo
	for _, entry := range result.Entries {
		if info, ok := parseTrustEntry(entry); ok {
			trusts = append(trusts, info)
		}
	}
	return trusts, nil
}

// parseTrustEntry converts a trustedDomain LDAP entry into a DomainInfo.
//
// For uplevel (AD) trusts trustPartner is the partner's DNS name. For
// downlevel trusts it is a NetBIOS name, so it must not be used as a DNS name:
// such partners are kept for SID/NetBIOS identification only. Entries that
// carry neither a SID nor a DNS name are useless and are dropped.
func parseTrustEntry(entry *ldap.Entry) (DomainInfo, bool) {
	atoi := func(attr string) int {
		v, _ := strconv.Atoi(strings.TrimSpace(entry.GetAttributeValue(attr)))
		return v
	}

	info := DomainInfo{
		NetBIOSName:     strings.ToUpper(strings.TrimSpace(entry.GetAttributeValue("flatName"))),
		SID:             decodeSID(entry.GetRawAttributeValue("securityIdentifier")),
		TrustDirection:  atoi("trustDirection"),
		TrustType:       atoi("trustType"),
		TrustAttributes: atoi("trustAttributes"),
	}

	partner := strings.TrimSuffix(strings.TrimSpace(entry.GetAttributeValue("trustPartner")), ".")
	switch info.TrustType {
	case TrustTypeMIT, TrustTypeDCE:
		return DomainInfo{}, false
	case TrustTypeDownlevel:
		if info.NetBIOSName == "" {
			info.NetBIOSName = strings.ToUpper(partner)
		}
	default:
		info.DNSName = strings.ToLower(partner)
	}

	if info.SID == "" && info.DNSName == "" {
		return DomainInfo{}, false
	}
	return info, true
}
