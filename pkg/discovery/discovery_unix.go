//go:build !windows

package discovery

func newSessionImpl(domainController string, domain string, username string, password string, useLDAPS bool, debug bool) (Discoverer, error) {
    return NewLDAPSession(domainController, domain, username, password, useLDAPS)
}
