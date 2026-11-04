// Package ad provides Active Directory integration for SPN enumeration and SID resolution.
package ad

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// Client handles Active Directory operations via LDAP
type Client struct {
	conn             *ldap.Conn
	domain           string
	domainController string
	baseDN           string
	skipPrivateCheck bool
	ldapUser         string
	ldapPassword     string
	ntHash           string // NT hash (hex string) for pass-the-hash LDAP bind
	useKerberos      bool   // Use Kerberos authentication
	krb5ConfigFile   string // Path to krb5.conf
	krb5CCacheFile   string // Path to credential cache file
	krb5KeytabFile   string // Path to keytab file
	krb5Realm        string // Kerberos realm
	dnsResolver      string // DNS resolver IP
	resolver         *net.Resolver
	proxyDialer      interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}

	// Caches
	sidCache    map[string]*types.DomainPrincipal
	domainCache map[string]bool

	// Set after a successful bind; describes transport + auth method used
	authMethod string

	// credDomain is the DNS domain the bind credentials belong to. It is only
	// set when this client targets a domain OTHER than the credentials' own
	// domain (a trusted domain). When empty, or equal to domain, every bind
	// path behaves exactly as it did before cross-domain support existed.
	credDomain string

	// connectErr remembers the first Connect() failure so later lookups on the
	// same client return immediately instead of re-binding. Re-binding with
	// credentials that were just rejected risks AD account lockout, and
	// re-dialing an unreachable DC costs up to 3 x 30s per call.
	connectErr error

	// Optional logger for verbose output (e.g. Kerberos ticket dumping)
	logger *slog.Logger
}

// NewClient creates a new AD client
func NewClient(domain, domainController string, skipPrivateCheck bool, ldapUser, ldapPassword, dnsResolver string) *Client {
	client := &Client{
		domain:           domain,
		domainController: domainController,
		skipPrivateCheck: skipPrivateCheck,
		ldapUser:         ldapUser,
		ldapPassword:     ldapPassword,
		dnsResolver:      dnsResolver,
		sidCache:         make(map[string]*types.DomainPrincipal),
		domainCache:      make(map[string]bool),
	}

	// Create resolver if DNS resolver is specified
	if dnsResolver != "" {
		client.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, net.JoinHostPort(dnsResolver, "53"))
			},
		}
	} else {
		// Use default resolver
		client.resolver = net.DefaultResolver
	}

	return client
}

// AuthMethod returns a description of the transport and bind method used for
// the successful LDAP connection (e.g. "LDAPS:636 NTLM", "LDAP:389+StartTLS GSSAPI").
// Returns an empty string if Connect has not yet succeeded.
func (c *Client) AuthMethod() string {
	return c.authMethod
}

// Connect establishes a connection to the domain controller.
//
// It is idempotent: an already-connected client returns nil, and a client
// whose first attempt failed returns that same error without dialing or
// binding again (see connectErr for why).
func (c *Client) Connect() error {
	if c.conn != nil {
		return nil
	}
	if c.connectErr != nil {
		return c.connectErr
	}
	if err := c.connect(); err != nil {
		c.connectErr = err
		return err
	}
	return nil
}

// Domain returns the DNS domain this client queries.
func (c *Client) Domain() string {
	return c.domain
}

// SetCredentialDomain records the DNS domain the bind credentials belong to.
// Callers set it only when this client targets a trusted domain that differs
// from the credentials' domain; see isCrossDomain for the effect on binds.
func (c *Client) SetCredentialDomain(domain string) {
	c.credDomain = domain
}

// isCrossDomain reports whether this client binds to a domain other than the
// one its credentials belong to (i.e. authentication crosses a trust).
func (c *Client) isCrossDomain() bool {
	return c.credDomain != "" && !strings.EqualFold(c.credDomain, c.domain)
}

// credentialDomain is the domain used to qualify a bare --ldap-user name:
// the credentials' own domain when binding across a trust, otherwise the
// target domain (the historical behaviour).
func (c *Client) credentialDomain() string {
	if c.isCrossDomain() {
		return c.credDomain
	}
	return c.domain
}

// connect performs the actual DC resolution, dial and bind.
func (c *Client) connect() error {
	dc := c.domainController
	if dc == "" {
		// Try to resolve domain controller
		var err error
		dc, err = c.resolveDomainController()
		if err != nil {
			return fmt.Errorf("failed to resolve domain controller: %w", err)
		}
	}

	// Build server name for TLS (used throughout)
	serverName := dc
	if !strings.Contains(serverName, ".") && c.domain != "" {
		serverName = fmt.Sprintf("%s.%s", dc, c.domain)
	}

	// If explicit credentials provided, try multiple auth methods with TLS.
	// Credentials include: password, NT hash (pass-the-hash), or Kerberos (ccache/keytab).
	hasExplicitCreds := c.ldapUser != "" && (c.ldapPassword != "" || c.ntHash != "" || c.useKerberos)
	if hasExplicitCreds {
		return c.connectWithExplicitCredentials(dc, serverName)
	}

	// No explicit credentials - try GSSAPI with current user context
	return c.connectWithCurrentUser(dc, serverName)
}

// connectWithExplicitCredentials tries multiple authentication methods with explicit credentials.
//
// Authentication waterfall (stops at first success):
//
//   1. LDAPS:636 (direct TLS on dedicated port, most secure and reliable)
//      -> NTLM bind  -> SimpleBind  -> GSSAPI (Kerberos)
//
//   2. LDAP:389 + StartTLS (RFC 4511 sec 4.14: upgrade plaintext to TLS)
//      -> NTLM bind  -> SimpleBind  -> GSSAPI (Kerberos)
//
//   3. Plain LDAP:389 + NTLM or GSSAPI only (no TLS, but both NTLM and GSSAPI
//      provide their own signing/sealing, so credentials are not sent in cleartext)
//
// LDAPS is attempted before StartTLS because direct TLS is more reliable
// than an in-band upgrade -- StartTLS can fail if a middlebox strips the
// extension or the server's LDAP port doesn't advertise it.
//
// Auth errors ("Invalid Credentials" / result code 49) short-circuit the
// entire waterfall immediately: if the credentials are wrong, retrying with
// a different transport or bind method will not help and risks triggering
// Active Directory account lockout policies.
func (c *Client) connectWithExplicitCredentials(dc, serverName string) error {
	var errors []string

	// Build ordered list of bind methods based on auth mode.
	// Kerberos: only GSSAPI. NT hash: only NTLM. Password: NTLM -> SimpleBind -> GSSAPI.
	type bindMethod struct {
		name string
		fn   func(conn *ldap.Conn, dc string, overTLS bool) error
	}
	var bindMethods []bindMethod
	if c.useKerberos {
		bindMethods = []bindMethod{
			{"GSSAPI", func(conn *ldap.Conn, dc string, overTLS bool) error { return c.gssapiBind(conn, dc, overTLS) }},
		}
	} else if c.ntHash != "" {
		bindMethods = []bindMethod{
			{"NTLM", func(conn *ldap.Conn, _ string, _ bool) error { return c.ntlmBind(conn) }},
		}
	} else {
		bindMethods = []bindMethod{
			{"NTLM", func(conn *ldap.Conn, _ string, _ bool) error { return c.ntlmBind(conn) }},
			{"SimpleBind", func(conn *ldap.Conn, _ string, _ bool) error { return c.simpleBind(conn) }},
			{"GSSAPI", func(conn *ldap.Conn, dc string, overTLS bool) error { return c.gssapiBind(conn, dc, overTLS) }},
		}
	}

	// Transport configurations to try in order of preference.
	type transportConfig struct {
		label    string
		scheme   string
		port     string
		tls      *tls.Config
		startTLS bool
	}
	transports := []transportConfig{
		// LDAPS (port 636) - most secure, direct TLS
		{"LDAPS:636", "ldaps", "636", &tls.Config{
			ServerName: serverName, InsecureSkipVerify: true,
		}, false},
		// LDAP + StartTLS (port 389) - upgrade to TLS
		{"LDAP:389+StartTLS", "ldap", "389", nil, true},
	}
	// Plain LDAP with NTLM or GSSAPI only (both provide their own signing/sealing)
	transports = append(transports, transportConfig{
		"LDAP:389", "ldap", "389", nil, false,
	})

	// Try each transport+bind combination with a fresh connection per attempt.
	// A failed bind (especially NTLM) can leave the connection in a broken
	// state, so we must not reuse a connection after a bind failure.
	for _, t := range transports {
		for _, m := range bindMethods {
			// Plain LDAP (no TLS, no StartTLS) only allows NTLM and GSSAPI
			// (both provide their own signing/sealing, so credentials are protected)
			if !t.startTLS && t.tls == nil && m.name != "NTLM" && m.name != "GSSAPI" {
				continue
			}

			conn, err := c.dialLDAP(t.scheme, dc, t.port, t.tls)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s connect: %v", t.label, err))
				break // if we can't connect on this transport, skip to next transport
			}
			conn.SetTimeout(30 * time.Second)

			if t.startTLS {
				if tlsErr := c.startTLS(conn, dc); tlsErr != nil {
					errors = append(errors, fmt.Sprintf("%s StartTLS: %v", t.label, tlsErr))
					conn.Close()
					break // StartTLS failed, skip to next transport
				}
			}

			overTLS := t.tls != nil || t.startTLS
			if bindErr := m.fn(conn, dc, overTLS); bindErr == nil {
				c.conn = conn
				c.baseDN = domainToDN(c.domain)
				c.authMethod = fmt.Sprintf("%s %s", t.label, m.name)
				return nil
			} else {
				errors = append(errors, fmt.Sprintf("%s %s: %v", t.label, m.name, bindErr))
				conn.Close()
				if isLDAPAuthError(bindErr) && !isLDAPSSPIChannelBindingError(bindErr) {
					return fmt.Errorf("LDAP authentication failed (invalid credentials): %s", strings.Join(errors, "; "))
				}
			}
		}
	}

	return fmt.Errorf("all LDAP authentication methods failed with explicit credentials: %s", strings.Join(errors, "; "))
}

// connectWithCurrentUser tries GSSAPI authentication with the current user's credentials
func (c *Client) connectWithCurrentUser(dc, serverName string) error {
	// On non-Windows platforms, GSSAPI/SSPI is not available — fail fast with a clear message
	if runtime.GOOS != "windows" {
		return fmt.Errorf("LDAP authentication requires explicit credentials on %s (GSSAPI/Kerberos SSPI is only available on Windows). Use --ldap-user with --ldap-password, --nt-hash, or --kerberos to provide credentials", runtime.GOOS)
	}

	var errors []string

	// Try LDAPS first (port 636) - most reliable with channel binding
	conn, err := c.dialLDAP("ldaps", dc, "636", &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	if err == nil {
		conn.SetTimeout(30 * time.Second)
		bindErr := c.gssapiBind(conn, dc, true)
		if bindErr == nil {
			c.conn = conn
			c.baseDN = domainToDN(c.domain)
			c.authMethod = "LDAPS:636 GSSAPI"
			return nil
		}
		errors = append(errors, fmt.Sprintf("LDAPS:636 GSSAPI: %v", bindErr))
		conn.Close()
	} else {
		errors = append(errors, fmt.Sprintf("LDAPS:636 connect: %v", err))
	}

	// Try StartTLS on port 389
	conn, err = c.dialLDAP("ldap", dc, "389", nil)
	if err == nil {
		conn.SetTimeout(30 * time.Second)
		tlsErr := c.startTLS(conn, dc)
		if tlsErr == nil {
			bindErr2 := c.gssapiBind(conn, dc, true)
			if bindErr2 == nil {
				c.conn = conn
				c.baseDN = domainToDN(c.domain)
				c.authMethod = "LDAP:389+StartTLS GSSAPI"
				return nil
			}
			errors = append(errors, fmt.Sprintf("LDAP:389+StartTLS GSSAPI: %v", bindErr2))
		} else {
			errors = append(errors, fmt.Sprintf("LDAP:389 StartTLS: %v", tlsErr))
		}
		conn.Close()
	} else {
		errors = append(errors, fmt.Sprintf("LDAP:389+StartTLS connect: %v", err))
	}

	// Try plain LDAP without TLS (may work if DC doesn't require signing)
	conn, err = c.dialLDAP("ldap", dc, "389", nil)
	if err == nil {
		conn.SetTimeout(30 * time.Second)
		bindErr3 := c.gssapiBind(conn, dc, false)
		if bindErr3 == nil {
			c.conn = conn
			c.baseDN = domainToDN(c.domain)
			c.authMethod = "LDAP:389 GSSAPI"
			return nil
		}
		errors = append(errors, fmt.Sprintf("LDAP:389 GSSAPI: %v", bindErr3))
		conn.Close()
	} else {
		errors = append(errors, fmt.Sprintf("LDAP:389 connect: %v", err))
	}

	// Provide helpful troubleshooting message
	errMsg := fmt.Sprintf("all LDAP connection methods failed: %s", strings.Join(errors, "; "))

	// Check for common issues and provide suggestions
	if containsAny(errors, "80090346", "Invalid Credentials") {
		errMsg += "\n\nTroubleshooting suggestions for Kerberos authentication failures:"
		errMsg += "\n  1. Verify your Kerberos ticket is valid: run 'klist' to check"
		errMsg += "\n  2. Check time synchronization with the domain controller"
		errMsg += "\n  3. Try using explicit credentials with --ldap-user and --ldap-password"
		errMsg += "\n  4. If EPA (Extended Protection) is enabled, explicit credentials may be required"
	}
	if containsAny(errors, "Strong Auth Required", "integrity checking") {
		errMsg += "\n\nNote: The domain controller requires LDAP signing. GSSAPI should provide this,"
		errMsg += "\n      but if it's failing, try using explicit credentials which enables NTLM or Simple Bind."
	}

	return fmt.Errorf("%s", errMsg)
}

// isLDAPAuthError checks if a bind error indicates invalid credentials (LDAP
// Result Code 49). Continuing to try other bind methods with the same bad
// credentials would count toward AD account lockout.
func isLDAPAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "Invalid Credentials") ||
		strings.Contains(errStr, "Result Code 49")
}

// isLDAPSSPIChannelBindingError checks for Active Directory's SEC_E_BAD_BINDINGS
// failure. AD reports it as LDAP result 49 even when the password is correct,
// so password-based flows should continue to another bind method such as
// SimpleBind over TLS instead of reporting invalid credentials immediately.
func isLDAPSSPIChannelBindingError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "80090346") ||
		strings.Contains(errStr, "sec_e_bad_bindings")
}

// containsAny checks if any of the error strings contain any of the substrings
func containsAny(errors []string, substrings ...string) bool {
	for _, err := range errors {
		for _, sub := range substrings {
			if strings.Contains(err, sub) {
				return true
			}
		}
	}
	return false
}

// errCrossDomainNTHash is returned when an NT hash bind is attempted across a
// trust. It deliberately does not look like an LDAP auth error (result 49), so
// it never trips the lockout guards: the credentials were not rejected, the
// NTLM library simply cannot express them for another domain.
var errCrossDomainNTHash = fmt.Errorf("NTLM pass-the-hash binds across a domain trust are not supported (the NTLM library always uses the target DC's domain name); use a password or Kerberos (-k) for trusted domains")

// ntlmBind performs NTLM authentication
func (c *Client) ntlmBind(conn *ldap.Conn) error {
	domain, username, err := ntlmBindIdentity(c.ldapUser, c.domain, c.credDomain, c.isCrossDomain(), c.ntHash != "")
	if err != nil {
		return err
	}
	if c.ntHash != "" {
		return conn.NTLMBindWithHash(domain, username, c.ntHash)
	}
	return conn.NTLMBind(domain, username, c.ldapPassword)
}

// ntlmBindIdentity decides the (domain, username) pair handed to go-ldap's
// NTLM bind.
//
// Background on why cross-domain binds need special handling: go-ldap only
// puts the domain argument into the NTLM NEGOTIATE message. The AUTHENTICATE
// message is built by go-ntlmssp, which copies the domain from the server's
// CHALLENGE (TargetName) whenever the username has no "@" - so "HOME\user"
// sent to a TRUSTED DC would authenticate as "TRUSTED\user" and fail. When the
// username is a UPN ("user@home.local"), go-ntlmssp blanks the domain instead
// and sends the UPN as-is, which Windows resolves to the right account and
// passes through the trust. The hash-based path always uses TargetName, so it
// cannot work across a trust at all.
//
//   - Same domain (crossDomain=false): exactly the historical parsing, so
//     existing single-domain behaviour is unchanged.
//   - Cross domain with password: bind as UPN with an empty domain.
//   - Cross domain with NT hash: errCrossDomainNTHash.
func ntlmBindIdentity(ldapUser, targetDomain, credDomain string, crossDomain, hasHash bool) (string, string, error) {
	if !crossDomain {
		domain := targetDomain
		username := ldapUser
		if strings.Contains(username, "\\") {
			parts := strings.SplitN(username, "\\", 2)
			domain = parts[0]
			username = parts[1]
		} else if strings.Contains(username, "@") {
			parts := strings.SplitN(username, "@", 2)
			username = parts[0]
			domain = parts[1]
		}
		return domain, username, nil
	}

	if hasHash {
		return "", "", errCrossDomainNTHash
	}

	switch {
	case strings.Contains(ldapUser, "@"):
		// Already a UPN; pass it through untouched.
		return "", ldapUser, nil
	case strings.Contains(ldapUser, "\\"):
		parts := strings.SplitN(ldapUser, "\\", 2)
		// A DNS-style prefix (corp.local\user) is itself a usable UPN suffix;
		// a NetBIOS prefix is not, so fall back to the credentials' DNS domain.
		if strings.Contains(parts[0], ".") {
			return "", parts[1] + "@" + parts[0], nil
		}
		return "", parts[1] + "@" + credDomain, nil
	default:
		return "", ldapUser + "@" + credDomain, nil
	}
}

// simpleBind performs simple LDAP authentication (requires TLS for security)
// This is a fallback when NTLM and GSSAPI fail
func (c *Client) simpleBind(conn *ldap.Conn) error {
	var lastErr error
	for _, bindName := range c.simpleBindNames() {
		if err := conn.Bind(bindName, c.ldapPassword); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

func (c *Client) simpleBindNames() []string {
	username := strings.TrimSpace(c.ldapUser)
	if username == "" {
		return nil
	}

	lowerUsername := strings.ToLower(username)
	if strings.Contains(lowerUsername, "cn=") || strings.Contains(lowerUsername, "dc=") {
		return []string{username}
	}

	var names []string
	add := func(name string) {
		if name == "" {
			return
		}
		for _, existing := range names {
			if strings.EqualFold(existing, name) {
				return
			}
		}
		names = append(names, name)
	}

	if strings.Contains(username, "@") {
		add(username)
		return names
	}

	// The first UPN guess uses the credentials' domain. For a normal
	// single-domain client that is the target domain (historical behaviour);
	// across a trust it is the home domain, because user@trusted.local would
	// name an account that does not exist.
	bindDomain := c.credentialDomain()

	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		domainPart := parts[0]
		userPart := parts[1]
		if bindDomain != "" {
			add(fmt.Sprintf("%s@%s", userPart, bindDomain))
		}
		if strings.Contains(domainPart, ".") {
			add(fmt.Sprintf("%s@%s", userPart, domainPart))
		}
		add(username)
		add(fmt.Sprintf("%s@%s", userPart, domainPart))
		return names
	}

	if bindDomain != "" {
		add(fmt.Sprintf("%s@%s", username, bindDomain))
	}
	add(username)
	return names
}

func (c *Client) gssapiBind(conn *ldap.Conn, dc string, overTLS bool) error {
	var gssClient ldap.GSSAPIClient
	var closeFn func() error
	var err error

	if c.useKerberos {
		gssClient, closeFn, err = newKerberosGSSAPIClient(c.krb5ConfigFile, c.krb5CCacheFile, c.krb5KeytabFile, c.krb5Realm, c.ldapUser, c.ldapPassword, overTLS, c.logger)
	} else {
		// Windows SSPI qualifies a bare username with this domain, so it must be
		// the credentials' domain rather than a trusted target domain.
		gssClient, closeFn, err = newGSSAPIClient(c.credentialDomain(), c.ldapUser, c.ldapPassword)
	}
	if err != nil {
		return err
	}
	defer closeFn()

	serviceHost := dc
	if net.ParseIP(dc) != nil {
		// Kerberos SPNs require hostnames, not IP addresses.
		// Reverse DNS the IP to get the DC hostname for SPN construction.
		if names, err := c.resolver.LookupAddr(context.Background(), dc); err == nil && len(names) > 0 {
			serviceHost = strings.TrimSuffix(names[0], ".")
		} else {
			return fmt.Errorf("cannot construct Kerberos SPN for IP address %s: reverse DNS lookup failed (%w). Use the DC hostname instead of an IP with --dc, or ensure reverse DNS is configured", dc, err)
		}
	} else if !strings.Contains(serviceHost, ".") && c.domain != "" {
		serviceHost = fmt.Sprintf("%s.%s", dc, c.domain)
	}

	servicePrincipal := fmt.Sprintf("ldap/%s", strings.ToLower(serviceHost))
	if err := conn.GSSAPIBind(gssClient, servicePrincipal, ""); err == nil {
		return nil
	} else {
		// Retry with short hostname SPN if FQDN failed.
		shortHost := strings.SplitN(serviceHost, ".", 2)[0]
		if shortHost != "" && shortHost != serviceHost {
			fallbackSPN := fmt.Sprintf("ldap/%s", strings.ToLower(shortHost))
			if err2 := conn.GSSAPIBind(gssClient, fallbackSPN, ""); err2 == nil {
				return nil
			}
			return fmt.Errorf("GSSAPI bind failed for %s (%v) and %s", servicePrincipal, err, fallbackSPN)
		}
		return fmt.Errorf("GSSAPI bind failed for %s: %w", servicePrincipal, err)
	}
}

func (c *Client) startTLS(conn *ldap.Conn, dc string) error {
	serverName := dc
	if !strings.Contains(serverName, ".") && c.domain != "" {
		serverName = fmt.Sprintf("%s.%s", dc, c.domain)
	}

	return conn.StartTLS(&tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
}

// SetProxyDialer sets a SOCKS5 proxy dialer for all LDAP connections.
// It also rebuilds the DNS resolver to route through the proxy if a custom
// DNS resolver is configured.
// SetNTHash sets the NT hash (hex string) for pass-the-hash LDAP authentication.
func (c *Client) SetNTHash(hash string) {
	c.ntHash = hash
}

// SetLogger sets an optional structured logger for verbose output.
func (c *Client) SetLogger(l *slog.Logger) {
	c.logger = l
}

// SetKerberosConfig sets Kerberos authentication parameters for LDAP GSSAPI bind.
func (c *Client) SetKerberosConfig(configFile, ccacheFile, keytabFile, realm string) {
	c.useKerberos = true
	c.krb5ConfigFile = configFile
	c.krb5CCacheFile = ccacheFile
	c.krb5KeytabFile = keytabFile
	c.krb5Realm = realm
}

func (c *Client) SetProxyDialer(d interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}) {
	c.proxyDialer = d
	// Rebuild DNS resolver to route through proxy if DNS resolver is set
	if c.dnsResolver != "" && d != nil {
		c.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Force TCP: SOCKS5 doesn't support UDP, and DNS works fine over TCP
				return d.DialContext(ctx, "tcp", net.JoinHostPort(c.dnsResolver, "53"))
			},
		}
	}
}

// dialLDAP establishes an LDAP connection, routing through the proxy if configured.
// For "ldaps" scheme, it performs a TLS handshake after the TCP connection.
func (c *Client) dialLDAP(scheme, host, port string, tlsConfig *tls.Config) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	if c.proxyDialer == nil {
		url := fmt.Sprintf("%s://%s:%s", scheme, host, port)
		if tlsConfig != nil {
			return ldap.DialURL(url, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
		}
		return ldap.DialURL(url, ldap.DialWithDialer(dialer))
	}

	// Dial through proxy
	addr := net.JoinHostPort(host, port)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rawConn, err := c.proxyDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proxy dial to %s failed: %w", addr, err)
	}

	if scheme == "ldaps" {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake through proxy failed: %w", err)
		}
		conn := ldap.NewConn(tlsConn, true)
		conn.Start()
		return conn, nil
	}

	// Plain LDAP
	conn := ldap.NewConn(rawConn, false)
	conn.Start()
	return conn, nil
}

// Close closes the LDAP connection
func (c *Client) Close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

// resolveDomainController attempts to find a domain controller for the domain
func (c *Client) resolveDomainController() (string, error) {
	ctx := context.Background()

	// Try SRV record lookup
	_, addrs, err := c.resolver.LookupSRV(ctx, "ldap", "tcp", c.domain)
	if err == nil && len(addrs) > 0 {
		return strings.TrimSuffix(addrs[0].Target, "."), nil
	}

	// Fall back to using domain name directly
	return c.domain, nil
}

// EnumerateMSSQLSPNs finds all MSSQL service principal names in the domain
func (c *Client) EnumerateMSSQLSPNs() ([]types.SPN, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	// Search for accounts with MSSQLSvc SPNs
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(servicePrincipalName=MSSQLSvc/*)",
		[]string{"servicePrincipalName", "sAMAccountName", "objectSid", "distinguishedName"},
		nil,
	)

	// Use paging to handle large result sets
	var spns []types.SPN
	pagingControl := ldap.NewControlPaging(1000)
	searchRequest.Controls = append(searchRequest.Controls, pagingControl)

	for {
		result, err := c.conn.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("LDAP search failed: %w", err)
		}

		for _, entry := range result.Entries {
			accountName := entry.GetAttributeValue("sAMAccountName")
			sidBytes := entry.GetRawAttributeValue("objectSid")
			accountSID := decodeSID(sidBytes)

			for _, spn := range entry.GetAttributeValues("servicePrincipalName") {
				if !strings.HasPrefix(strings.ToUpper(spn), "MSSQLSVC/") {
					continue
				}

				parsed := parseSPN(spn)
				parsed.AccountName = accountName
				parsed.AccountSID = accountSID

				spns = append(spns, parsed)
			}
		}

		// Check if there are more pages
		pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			break
		}
		pagingCtrl := pagingResult.(*ldap.ControlPaging)
		if len(pagingCtrl.Cookie) == 0 {
			break
		}
		pagingControl.SetCookie(pagingCtrl.Cookie)
	}

	return spns, nil
}

// LookupMSSQLSPNsForHost finds MSSQL SPNs for a specific hostname
func (c *Client) LookupMSSQLSPNsForHost(hostname string) ([]types.SPN, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	// Extract short hostname for matching
	shortHost := hostname
	if idx := strings.Index(hostname, "."); idx > 0 {
		shortHost = hostname[:idx]
	}

	// Search for SPNs matching this hostname (MSSQLSvc/hostname or MSSQLSvc/hostname.domain)
	// Use a wildcard search to catch both short and FQDN forms
	filter := fmt.Sprintf("(|(servicePrincipalName=MSSQLSvc/%s*)(servicePrincipalName=MSSQLSvc/%s*))", shortHost, hostname)

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"servicePrincipalName", "sAMAccountName", "objectSid", "distinguishedName"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var spns []types.SPN

	for _, entry := range result.Entries {
		accountName := entry.GetAttributeValue("sAMAccountName")
		sidBytes := entry.GetRawAttributeValue("objectSid")
		accountSID := decodeSID(sidBytes)

		for _, spn := range entry.GetAttributeValues("servicePrincipalName") {
			if !strings.HasPrefix(strings.ToUpper(spn), "MSSQLSVC/") {
				continue
			}

			// Verify this SPN matches our target hostname
			parsed := parseSPN(spn)
			spnHost := strings.ToLower(parsed.Hostname)
			targetHost := strings.ToLower(hostname)
			targetShort := strings.ToLower(shortHost)

			// Check if the SPN hostname matches our target
			if spnHost == targetHost || spnHost == targetShort ||
				strings.HasPrefix(spnHost, targetShort+".") {
				parsed.AccountName = accountName
				parsed.AccountSID = accountSID
				spns = append(spns, parsed)
			}
		}
	}

	return spns, nil
}

// EnumerateAllComputers returns all computer objects in the domain
func (c *Client) EnumerateAllComputers() ([]string, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectCategory=computer)(objectClass=computer))",
		[]string{"dNSHostName", "name"},
		nil,
	)

	// Use paging to handle large result sets (AD default limit is 1000)
	var computers []string
	pagingControl := ldap.NewControlPaging(1000)
	searchRequest.Controls = append(searchRequest.Controls, pagingControl)

	for {
		result, err := c.conn.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("LDAP search failed: %w", err)
		}

		for _, entry := range result.Entries {
			hostname := entry.GetAttributeValue("dNSHostName")
			if hostname == "" {
				hostname = entry.GetAttributeValue("name")
			}
			if hostname != "" {
				computers = append(computers, hostname)
			}
		}

		// Check if there are more pages
		pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			break
		}
		pagingCtrl := pagingResult.(*ldap.ControlPaging)
		if len(pagingCtrl.Cookie) == 0 {
			break
		}
		pagingControl.SetCookie(pagingCtrl.Cookie)
	}

	return computers, nil
}

// ResolveSID resolves a SID to a domain principal
func (c *Client) ResolveSID(sid string) (*types.DomainPrincipal, error) {
	// Check cache first
	if cached, ok := c.sidCache[sid]; ok {
		return cached, nil
	}

	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	// Convert SID string to binary for LDAP search
	sidFilter := fmt.Sprintf("(objectSid=%s)", escapeSIDForLDAP(sid))

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		sidFilter,
		[]string{"sAMAccountName", "distinguishedName", "objectClass", "userAccountControl", "memberOf", "dNSHostName", "userPrincipalName"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("SID not found: %s", sid)
	}

	entry := result.Entries[0]

	principal := &types.DomainPrincipal{
		SID:               sid,
		SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
		DistinguishedName: entry.GetAttributeValue("distinguishedName"),
		Domain:            c.domain,
		MemberOf:          entry.GetAttributeValues("memberOf"),
	}

	// Determine object class
	classes := entry.GetAttributeValues("objectClass")
	for _, class := range classes {
		switch strings.ToLower(class) {
		case "user":
			principal.ObjectClass = "user"
		case "group":
			principal.ObjectClass = "group"
		case "computer":
			principal.ObjectClass = "computer"
		}
	}

	// Determine if enabled (for users/computers)
	uac := entry.GetAttributeValue("userAccountControl")
	if uac != "" {
		// UAC flag 0x0002 = ACCOUNTDISABLE
		principal.Enabled = !strings.Contains(uac, "2")
	}

	// Store raw LDAP attributes for AD enrichment on nodes
	dnsHostName := entry.GetAttributeValue("dNSHostName")
	userPrincipalName := entry.GetAttributeValue("userPrincipalName")
	principal.DNSHostName = dnsHostName
	principal.UserPrincipalName = userPrincipalName

	// Set the Name based on object class to match PowerShell behavior:
	// - For computers: use DNSHostName (FQDN) if available, otherwise SAMAccountName
	// - For users: use userPrincipalName if available, otherwise DOMAIN\SAMAccountName
	// - For groups: use DOMAIN\SAMAccountName
	switch principal.ObjectClass {
	case "computer":
		if dnsHostName != "" {
			principal.Name = dnsHostName
		} else {
			principal.Name = fmt.Sprintf("%s\\%s", c.domain, principal.SAMAccountName)
		}
	case "user":
		if userPrincipalName != "" {
			principal.Name = userPrincipalName
		} else {
			principal.Name = fmt.Sprintf("%s\\%s", c.domain, principal.SAMAccountName)
		}
	default:
		principal.Name = fmt.Sprintf("%s\\%s", c.domain, principal.SAMAccountName)
	}
	principal.ObjectIdentifier = sid

	// Cache the result
	c.sidCache[sid] = principal

	return principal, nil
}

// ResolveName resolves a name (DOMAIN\user or user@domain) to a domain principal
func (c *Client) ResolveName(name string) (*types.DomainPrincipal, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	var samAccountName string

	// Parse the name format
	if strings.Contains(name, "\\") {
		parts := strings.SplitN(name, "\\", 2)
		samAccountName = parts[1]
	} else if strings.Contains(name, "@") {
		parts := strings.SplitN(name, "@", 2)
		samAccountName = parts[0]
	} else {
		samAccountName = name
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(samAccountName)),
		[]string{"sAMAccountName", "distinguishedName", "objectClass", "objectSid", "userAccountControl", "memberOf", "dNSHostName", "userPrincipalName"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("name not found: %s", name)
	}

	entry := result.Entries[0]
	sidBytes := entry.GetRawAttributeValue("objectSid")
	sid := decodeSID(sidBytes)

	principal := &types.DomainPrincipal{
		SID:               sid,
		SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
		DistinguishedName: entry.GetAttributeValue("distinguishedName"),
		Domain:            c.domain,
		MemberOf:          entry.GetAttributeValues("memberOf"),
		ObjectIdentifier:  sid,
	}

	// Determine object class
	classes := entry.GetAttributeValues("objectClass")
	for _, class := range classes {
		switch strings.ToLower(class) {
		case "user":
			principal.ObjectClass = "user"
		case "group":
			principal.ObjectClass = "group"
		case "computer":
			principal.ObjectClass = "computer"
		}
	}

	// Store raw LDAP attributes for AD enrichment on nodes
	dnsHostName := entry.GetAttributeValue("dNSHostName")
	userPrincipalName := entry.GetAttributeValue("userPrincipalName")
	principal.DNSHostName = dnsHostName
	principal.UserPrincipalName = userPrincipalName

	// Set the Name based on object class to match PowerShell behavior
	switch principal.ObjectClass {
	case "computer":
		if dnsHostName != "" {
			principal.Name = dnsHostName
		} else {
			principal.Name = fmt.Sprintf("%s\\%s", c.domain, principal.SAMAccountName)
		}
	case "user":
		if userPrincipalName != "" {
			principal.Name = userPrincipalName
		} else {
			principal.Name = fmt.Sprintf("%s\\%s", c.domain, principal.SAMAccountName)
		}
	default:
		principal.Name = fmt.Sprintf("%s\\%s", c.domain, principal.SAMAccountName)
	}

	// Cache by SID
	c.sidCache[sid] = principal

	return principal, nil
}

// ValidateDomain checks if a domain is reachable and valid
func (c *Client) ValidateDomain(domain string) bool {
	// Check cache
	if valid, ok := c.domainCache[domain]; ok {
		return valid
	}

	ctx := context.Background()

	// Try to resolve the domain
	addrs, err := c.resolver.LookupHost(ctx, domain)
	if err != nil {
		c.domainCache[domain] = false
		return false
	}

	// Check if the IP is private (RFC 1918) unless skipped
	if !c.skipPrivateCheck {
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip != nil && isPrivateIP(ip) {
				c.domainCache[domain] = true
				return true
			}
		}
		// No private IPs found
		c.domainCache[domain] = false
		return false
	}

	c.domainCache[domain] = len(addrs) > 0
	return len(addrs) > 0
}

// ResolveComputerSID resolves a computer name to its SID
// The computer name can be provided with or without the trailing $
func (c *Client) ResolveComputerSID(computerName string) (string, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return "", err
		}
	}

	samName := computerSAMAccountName(computerName)

	// Check cache
	if cached, ok := c.sidCache[samName]; ok {
		if computerFQDNMismatch(computerName, cached.DNSHostName) {
			return "", fmt.Errorf("computer not found: %s (%s belongs to %s)", computerName, samName, cached.DNSHostName)
		}
		return cached.SID, nil
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=%s))", ldap.EscapeFilter(samName)),
		[]string{"sAMAccountName", "objectSid", "dNSHostName"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("computer not found: %s", computerName)
	}

	entry := result.Entries[0]
	sidBytes := entry.GetRawAttributeValue("objectSid")
	sid := decodeSID(sidBytes)

	if sid == "" {
		return "", fmt.Errorf("could not decode SID for computer: %s", computerName)
	}

	// Cache the result
	dnsHostName := entry.GetAttributeValue("dNSHostName")
	c.sidCache[samName] = &types.DomainPrincipal{
		SID:            sid,
		SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		ObjectClass:    "computer",
		DNSHostName:    dnsHostName,
	}

	if computerFQDNMismatch(computerName, dnsHostName) {
		return "", fmt.Errorf("computer not found: %s (%s belongs to %s)", computerName, samName, dnsHostName)
	}

	return sid, nil
}

// computerFQDNMismatch guards against a short-name collision across domains.
// Because ResolveComputerSID searches by the short sAMAccountName, looking up
// "sql01.trusted.local" in corp.local would otherwise return corp.local's own
// SQL01$ - a different machine. When the caller supplied an FQDN and the
// matched account advertises a different dNSHostName, the match is rejected.
func computerFQDNMismatch(requested, dnsHostName string) bool {
	requested = strings.TrimSuffix(strings.TrimSpace(requested), ".")
	dnsHostName = strings.TrimSuffix(strings.TrimSpace(dnsHostName), ".")
	if dnsHostName == "" || !strings.Contains(requested, ".") || net.ParseIP(requested) != nil {
		return false
	}
	return !strings.EqualFold(requested, dnsHostName)
}

// Helper functions

// computerSAMAccountName converts a host name into the sAMAccountName of its
// computer account. AD stores computer accounts as "<NETBIOSNAME>$", so an
// FQDN such as "sql01.corp.local" must be reduced to its first label before
// the "$" is appended; searching for "sql01.corp.local$" never matches.
// IP addresses are left intact (they cannot match either way).
func computerSAMAccountName(computerName string) string {
	name := strings.TrimSpace(computerName)
	if net.ParseIP(strings.TrimSuffix(name, "$")) == nil {
		if idx := strings.Index(name, "."); idx > 0 {
			name = name[:idx]
		}
	}
	if !strings.HasSuffix(name, "$") {
		name += "$"
	}
	return name
}

// domainToDN converts a domain name to an LDAP distinguished name
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, fmt.Sprintf("DC=%s", part))
	}
	return strings.Join(dnParts, ",")
}

// parseSPN parses an SPN string into its components
func parseSPN(spn string) types.SPN {
	result := types.SPN{FullSPN: spn}

	// Format: service/host:port or service/host
	parts := strings.SplitN(spn, "/", 2)
	if len(parts) < 2 {
		return result
	}

	result.ServiceClass = parts[0]
	hostPart := parts[1]

	// Check for port or instance name
	if idx := strings.Index(hostPart, ":"); idx != -1 {
		result.Hostname = hostPart[:idx]
		portOrInstance := hostPart[idx+1:]

		// If it's a number, it's a port; otherwise instance name
		if _, err := fmt.Sscanf(portOrInstance, "%d", new(int)); err == nil {
			result.Port = portOrInstance
		} else {
			result.InstanceName = portOrInstance
		}
	} else {
		result.Hostname = hostPart
	}

	return result
}

// decodeSID converts a binary SID to a string representation
func decodeSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	revision := b[0]
	subAuthCount := int(b[1])

	// Build authority (6 bytes, big-endian)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	// Add sub-authorities (4 bytes each, little-endian)
	for i := 0; i < subAuthCount && 8+i*4+4 <= len(b); i++ {
		subAuth := uint32(b[8+i*4]) |
			uint32(b[8+i*4+1])<<8 |
			uint32(b[8+i*4+2])<<16 |
			uint32(b[8+i*4+3])<<24
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

// escapeSIDForLDAP escapes a SID string for use in an LDAP filter
// This converts a SID like S-1-5-21-xxx to its binary escaped form
func escapeSIDForLDAP(sid string) string {
	// For now, use a simpler approach - search by string
	// In production, you'd want to convert the SID to binary and escape it
	return ldap.EscapeFilter(sid)
}

// isPrivateIP checks if an IP address is in a private range (RFC 1918)
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}
