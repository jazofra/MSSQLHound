//go:build windows

package discovery

func newSessionImpl(domainController string, domain string, username string, password string, useLDAPS bool) (Discoverer, error) {
    // If no credentials provided, try Windows Native (SSPI)
    if username == "" && password == "" {
        return NewWindowsDiscoverer(domainController, domain)
    }
    // Fallback to standard go-ldap with explicit credentials
    return NewLDAPSession(domainController, domain, username, password, useLDAPS)
}
