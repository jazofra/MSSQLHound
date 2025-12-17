package discovery

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAPSession manages the connection to Active Directory
type LDAPSession struct {
	Conn *ldap.Conn
    Domain string
}

func NewLDAPSession(domainController string, domain string, username string, password string, useLDAPS bool) (*LDAPSession, error) {
    var conn *ldap.Conn
    var err error

    address := fmt.Sprintf("%s:%d", domainController, 389)
    if useLDAPS {
        address = fmt.Sprintf("%s:%d", domainController, 636)
        tlsConfig := &tls.Config{InsecureSkipVerify: true}
        conn, err = ldap.DialTLS("tcp", address, tlsConfig)
    } else {
        conn, err = ldap.Dial("tcp", address)
    }

    if err != nil {
        return nil, fmt.Errorf("failed to connect to LDAP: %v", err)
    }

    if username != "" && password != "" {
        // Simple bind
        // Normally username for bind is UPN (user@domain.com) or DOMAIN\User
        err = conn.Bind(username, password)
        if err != nil {
            return nil, fmt.Errorf("failed to bind to LDAP: %v", err)
        }
    } else {
        // Fallback to anonymous bind (unauthenticated) which usually fails for AD searches
        // But for non-AD LDAP or misconfigured AD, it might work.
        // We do NOT call BindCurrentWindowsUser here because that logic is now in NewWindowsDiscoverer
        // which bypasses go-ldap entirely.
        err = conn.UnauthenticatedBind("")
        if err != nil {
             return nil, fmt.Errorf("anonymous bind failed: %v", err)
        }
    }

    return &LDAPSession{Conn: conn, Domain: domain}, nil
}

func (s *LDAPSession) Close() {
    if s.Conn != nil {
        s.Conn.Close()
    }
}

// FindMSSQLSPNs searches for MSSQLSvc/* SPNs
func (s *LDAPSession) FindMSSQLSPNs() ([]string, error) {
    baseDN := s.domainToDN(s.Domain)
    filter := "(servicePrincipalName=MSSQLSvc/*)"
    attributes := []string{"servicePrincipalName", "dNSHostName", "sAMAccountName"}

    searchRequest := ldap.NewSearchRequest(
        baseDN,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        filter,
        attributes,
        nil,
    )

    // Use Paging for large result sets
    sr, err := s.Conn.SearchWithPaging(searchRequest, 1000)
    if err != nil {
        return nil, err
    }

    var spns []string
    for _, entry := range sr.Entries {
        for _, attr := range entry.Attributes {
            if attr.Name == "servicePrincipalName" {
                for _, val := range attr.Values {
                    if strings.HasPrefix(val, "MSSQLSvc/") {
                        spns = append(spns, val)
                    }
                }
            }
        }
    }
    return spns, nil
}

// FindComputers searches for all computer objects (for -CheckAllComputers)
func (s *LDAPSession) FindComputers() ([]string, error) {
    baseDN := s.domainToDN(s.Domain)
    filter := "(objectClass=computer)"
    attributes := []string{"dNSHostName"}

    searchRequest := ldap.NewSearchRequest(
        baseDN,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        filter,
        attributes,
        nil,
    )

    sr, err := s.Conn.SearchWithPaging(searchRequest, 1000)
    if err != nil {
        return nil, err
    }

    var computers []string
    for _, entry := range sr.Entries {
        dnsHostName := entry.GetAttributeValue("dNSHostName")
        if dnsHostName != "" {
            computers = append(computers, dnsHostName)
        }
    }
    return computers, nil
}

func (s *LDAPSession) domainToDN(domain string) string {
    parts := strings.Split(domain, ".")
    var dnParts []string
    for _, part := range parts {
        dnParts = append(dnParts, "DC="+part)
    }
    return strings.Join(dnParts, ",")
}
