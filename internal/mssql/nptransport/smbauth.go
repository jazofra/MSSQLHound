package nptransport

import (
	"fmt"
	"strings"

	smb2 "github.com/cloudsoda/go-smb2"
)

// ntHashLen is the length of an NT hash in bytes (an MD4 digest).
const ntHashLen = 16

// buildInitiator converts our credential description into the GSS initiator
// cloudsoda/go-smb2 expects for session setup.
func buildInitiator(a AuthConfig) (smb2.Initiator, error) {
	if a.Krb5Client != nil {
		if a.SMBSPN == "" {
			return nil, fmt.Errorf("%w: Kerberos requires an SMB service principal name", ErrSMBAuth)
		}
		// The client has already logged in, so this fetches a service ticket for
		// cifs/HOST from the TGT that the TDS layer also uses for MSSQLSvc/... —
		// one authentication, two service tickets.
		return &smb2.Krb5Initiator{
			Client:    a.Krb5Client,
			TargetSPN: a.SMBSPN,
		}, nil
	}

	if a.User == "" {
		return nil, fmt.Errorf("%w: no SMB username configured", ErrSMBAuth)
	}

	init := &smb2.NTLMInitiator{
		User:        a.User,
		Domain:      a.Domain,
		Workstation: a.Workstation,
		TargetSPN:   a.SMBSPN,
	}

	if len(a.NTHash) > 0 {
		if len(a.NTHash) != ntHashLen {
			return nil, fmt.Errorf("%w: NT hash must be %d bytes, got %d", ErrSMBAuth, ntHashLen, len(a.NTHash))
		}
		// Pass-the-hash: the hash replaces the password outright rather than
		// supplementing it, so leave Password empty to avoid ambiguity.
		init.Hash = a.NTHash
	} else {
		init.Password = a.Password
	}

	return init, nil
}

// SMBSPNFor builds the service principal name for the SMB service on a host.
//
// This is deliberately not the SQL SPN. SMB authenticates opening the pipe and
// needs cifs/HOST; TDS then authenticates the database session and needs
// MSSQLSvc/HOST:port-or-instance. Supplying the wrong one is the usual cause of
// KDC_ERR_S_PRINCIPAL_UNKNOWN on this path.
func SMBSPNFor(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// Strip any port; SPN hosts never carry one.
	if idx := strings.LastIndex(host, ":"); idx > 0 && !strings.Contains(host[idx:], "]") {
		host = host[:idx]
	}
	return "cifs/" + host
}

// SplitDomainUser separates a qualified username into its domain and account
// parts, accepting both the down-level DOMAIN\user form and the UPN user@domain
// form. An unqualified name yields an empty domain, leaving the caller free to
// fall back to a configured default.
func SplitDomainUser(user string) (domain, account string) {
	user = strings.TrimSpace(user)
	if user == "" {
		return "", ""
	}
	if idx := strings.Index(user, `\`); idx >= 0 {
		return user[:idx], user[idx+1:]
	}
	if idx := strings.LastIndex(user, "@"); idx > 0 {
		return user[idx+1:], user[:idx]
	}
	return "", user
}
