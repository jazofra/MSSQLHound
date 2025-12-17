package discovery

// Discoverer is the interface for finding targets
type Discoverer interface {
	FindMSSQLSPNs() ([]string, error)
	FindComputers() ([]string, error)
	Close()
}

// NewSession creates a discovery session.
// On Windows, if no credentials are provided, it attempts to use the OS's native LDAP client (wldap32.dll) for seamless SSPI auth.
func NewSession(domainController string, domain string, username string, password string, useLDAPS bool) (Discoverer, error) {
	// Logic to switch implementation will be handled by platform-specific files or here if we export them.
    // Since we can't easily export "platform specific constructor" with the same name, we use a helper.
    return newSessionImpl(domainController, domain, username, password, useLDAPS)
}
