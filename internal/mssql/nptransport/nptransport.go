// Package nptransport carries TDS over an SMB named pipe, so that SQL Server
// instances reachable only by named pipes can be collected.
//
// Two kinds of target need this. Instances with TCP/IP disabled in SQL Server
// Configuration Manager are discoverable from their SPN but not connectable.
// Windows Internal Database — the engine behind WSUS and AD FS — has no TCP
// endpoint at all and is otherwise invisible to this tool.
//
// go-mssqldb ships its own named-pipe support, but it is Windows-only (the
// package is built under `windows && (amd64 || 386)`, with an empty stub
// elsewhere) and opens the pipe through the local Windows SMB client, so it
// cannot use alternate credentials or route through a proxy. This package speaks
// SMB in-process instead, which works on any platform and through SOCKS5.
//
// # How it plugs in
//
// go-mssqldb dispatches connections through msdsn.ProtocolDialers, keyed by the
// protocol names in Config.Protocols. Registering a dialer there is the driver's
// intended extension point, and it means the entire TDS layer above the transport
// — prelogin, TLS-in-TDS, LOGIN7, authentication — is reused untouched.
//
// # What is deliberately not registered
//
// A msdsn.ProtocolParser is NOT registered. msdsn.Parse appends every non-hidden
// parser that accepts the server string, so registering one would silently add
// "np" to Config.Protocols on every ordinary TCP connection in the process, and
// would double DialTimeout (which is computed as 15s per protocol). Callers opt
// in explicitly by setting Config.Protocols themselves.
package nptransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// Protocol is the name this transport registers under in msdsn.ProtocolDialers.
const Protocol = "np"

// DefaultPort is the SMB port. Named pipes are reached over SMB, never directly.
const DefaultPort = 445

// ipcShare is the share that hosts named pipes.
const ipcShare = "IPC$"

// Sentinel errors let callers classify a failure without parsing text. The
// distinction matters operationally: "no pipe here" is an ordinary negative
// result worth a quiet log line, whereas an authentication failure is terminal
// and must stop us before we generate more failed logons.
var (
	// ErrNoParams indicates the Config reached the dialer without the state it
	// needs. This is a programming error, never a server condition.
	ErrNoParams = errors.New("named pipe: no transport parameters in connection config")

	// ErrSMBUnreachable means TCP 445 could not be reached.
	ErrSMBUnreachable = errors.New("named pipe: SMB port unreachable")

	// ErrSMBAuth means the SMB session could not be authenticated. Terminal:
	// retrying burns failed logons and moves the account toward lockout.
	ErrSMBAuth = errors.New("named pipe: SMB authentication failed")

	// ErrPipeNotFound means no SQL Server named pipe exists at any candidate path.
	// Usually this host simply does not run SQL Server, or has named pipes
	// disabled on the instance.
	ErrPipeNotFound = errors.New("named pipe: no SQL Server pipe found")

	// ErrPipeAccessDenied means the pipe exists but its ACL rejects this
	// principal. Expected for Windows Internal Database without local admin.
	ErrPipeAccessDenied = errors.New("named pipe: access denied opening pipe")

	// ErrStrictEncryptionUnsupported reports the one encryption mode that cannot
	// work here. TDS 8.0 strict encryption wraps the raw socket in TLS before any
	// TDS is exchanged; a named pipe has no equivalent stage.
	ErrStrictEncryptionUnsupported = errors.New("named pipe: TDS 8.0 strict encryption is not supported over a named pipe")
)

// NTSTATUS codes we classify. cloudsoda/go-smb2 keeps its status table in an
// internal package, so the ones we care about are restated here.
const (
	statusLogonFailure               = 0xC000006D
	statusAccountRestriction         = 0xC000006E
	statusInvalidLogonHours          = 0xC000006F
	statusInvalidWorkstation         = 0xC0000070
	statusPasswordExpired            = 0xC0000071
	statusAccountDisabled            = 0xC0000072
	statusAccountExpired             = 0xC0000193
	statusPasswordMustChange         = 0xC0000224
	statusAccountLockedOut           = 0xC0000234
	statusLogonTypeNotGranted        = 0xC000015B
	statusTrustedRelationshipFailure = 0xC000018D
)

// AuthConfig carries the credentials used for the SMB session. These are
// deliberately separate from the SQL credentials: SMB authenticates the pipe
// open, and TDS then performs its own LOGIN7 over that pipe. The two identities
// can legitimately differ — a domain account may open the pipe while a SQL login
// authenticates to the database.
type AuthConfig struct {
	User        string
	Password    string
	Domain      string
	Workstation string

	// NTHash enables pass-the-hash. When set, Password is ignored.
	NTHash []byte

	// Krb5Client, when set, selects Kerberos over NTLM. It is a gokrb5 client
	// that has already logged in, so the SMB service ticket is fetched from the
	// same TGT the TDS layer uses — one Login, two service tickets.
	Krb5Client *client.Client

	// SMBSPN is the service principal name for the SMB service, i.e. cifs/HOST.
	// Distinct from the MSSQLSvc SPN used by TDS.
	SMBSPN string
}

// hasCredentials reports whether anything is available to authenticate with.
func (a AuthConfig) hasCredentials() bool {
	return a.Krb5Client != nil || a.User != "" || len(a.NTHash) > 0
}

// Result records what the transport actually reached, for the caller to inspect
// after a successful connection.
type Result struct {
	// PipePath is the pipe that was opened, relative to IPC$.
	PipePath string
	// Instance is the SQL Server instance implied by PipePath, "" for the
	// default instance. When the default pipe is absent and the Windows Internal
	// Database pipe answers instead, this is how the caller learns that it
	// reached a different instance than it asked for.
	Instance string
	// SMBAuth names the mechanism used: "kerberos", "ntlm-hash" or "ntlm".
	SMBAuth string
}

// Params is the per-target state the dialer needs. It travels in
// msdsn.Config.ProtocolParameters[Protocol].
//
// This indirection exists because msdsn.ProtocolDialer.DialConnection receives
// only the *msdsn.Config — it never sees the Connector, so Connector.Dialer (where
// a SOCKS5 proxy would normally live) is unreachable from here. Carrying our own
// Dial func in the Config sidesteps that entirely.
//
// Registration is process-global and happens once in init, but Params is
// per-Config, so concurrent collection of many targets is safe.
type Params struct {
	// Host is the SMB target. Prefer an FQDN: Kerberos service tickets are
	// name-sensitive.
	Host string
	// Port defaults to DefaultPort when zero.
	Port int
	// PipeCandidates are tried in order. Use Candidates to build this.
	PipeCandidates []string
	// Auth holds the SMB credentials.
	Auth AuthConfig
	// TDSSPN is stamped into Config.ServerSPN when that field is empty, honouring
	// the contract msdsn.ProtocolDialer documents for non-TCP transports.
	TDSSPN string
	// RequireSigning enforces SMB message signing.
	RequireSigning bool
	// Logger is optional.
	Logger *slog.Logger

	// Dial opens the underlying transport to the SMB port. It is supplied by the
	// caller so that proxy and DNS-resolver behaviour stays in one place rather
	// than being reimplemented here. Required.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	mu     sync.Mutex
	result Result
}

// Result returns what the last successful dial reached.
func (p *Params) Result() Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.result
}

func (p *Params) setResult(r Result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.result = r
}

func (p *Params) log() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (p *Params) port() int {
	if p.Port > 0 {
		return p.Port
	}
	return DefaultPort
}

// smbSession is the slice of an authenticated SMB session this package uses.
// Narrowing it to an interface keeps the transport testable without a server.
type smbSession interface {
	Mount(share string) (smbShare, error)
	Logoff() error
}

// smbShare is a mounted share that can open a pipe.
type smbShare interface {
	OpenPipe(name string) (io.ReadWriteCloser, error)
	Umount() error
}

// dialSMB negotiates and authenticates an SMB session over an established
// connection. It is a package variable so tests can substitute a fake; the repo
// uses this same seam idiom elsewhere (see collector.serverProcessor).
var dialSMB = realDialSMB

func realDialSMB(ctx context.Context, conn net.Conn, addr string, p *Params) (smbSession, error) {
	initiator, err := buildInitiator(p.Auth)
	if err != nil {
		return nil, err
	}

	d := &smb2.Dialer{
		Initiator: initiator,
		Negotiator: smb2.Negotiator{
			RequireMessageSigning: p.RequireSigning,
		},
	}

	sess, err := d.DialConn(ctx, conn, addr)
	if err != nil {
		return nil, err
	}
	return &realSession{sess: sess}, nil
}

type realSession struct{ sess *smb2.Session }

func (s *realSession) Mount(share string) (smbShare, error) {
	sh, err := s.sess.Mount(share)
	if err != nil {
		return nil, err
	}
	return &realShare{share: sh}, nil
}

func (s *realSession) Logoff() error { return s.sess.Logoff() }

type realShare struct{ share *smb2.Share }

func (s *realShare) OpenPipe(name string) (io.ReadWriteCloser, error) {
	return s.share.OpenFile(name, os.O_RDWR, 0)
}

func (s *realShare) Umount() error { return s.share.Umount() }

// withContext rebinds a session to a long-lived context where the underlying
// implementation supports it. See the note in DialConnection about why the dial
// context must not be retained.
type contextBinder interface{ bindContext(ctx context.Context) }

func (s *realSession) bindContext(ctx context.Context) { s.sess = s.sess.WithContext(ctx) }
func (s *realShare) bindContext(ctx context.Context)   { s.share = s.share.WithContext(ctx) }

// dialer implements msdsn.ProtocolDialer. It is a stateless value; everything
// mutable lives on the per-target Params.
type dialer struct{}

// CallBrowser reports whether the SQL Browser must be consulted first. It never
// is here, and that is a feature rather than a limitation: the browser protocol
// is UDP 1434, which cannot traverse a SOCKS5 proxy, and skipping it is what lets
// named-pipe collection work through one.
func (dialer) CallBrowser(*msdsn.Config) bool { return false }

// ParseBrowserData is required by the interface but unreachable, since
// CallBrowser always returns false.
func (dialer) ParseBrowserData(msdsn.BrowserData, *msdsn.Config) error { return nil }

// DialConnection opens a SQL Server named pipe and returns it as a net.Conn for
// go-mssqldb to run TDS over.
func (dialer) DialConnection(ctx context.Context, cfg *msdsn.Config) (net.Conn, error) {
	p, err := paramsFrom(cfg)
	if err != nil {
		return nil, err
	}

	// Honour the contract documented on msdsn.ProtocolDialer: a non-TCP transport
	// fills in ServerSPN when the caller left it empty, so Kerberos has a target.
	if cfg.ServerSPN == "" && p.TDSSPN != "" {
		cfg.ServerSPN = p.TDSSPN
	}

	addr := net.JoinHostPort(p.Host, fmt.Sprint(p.port()))
	log := p.log()

	raw, err := p.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSMBUnreachable, addr, err)
	}

	// The connection outlives this call, but ctx does not: go-mssqldb cancels the
	// dial context as soon as connect returns. Binding the SMB handles to it would
	// make every subsequent query fail once that cancellation fired. Long-lived
	// handles get closeCtx instead, which is cancelled by pipeConn.Close.
	closeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	// From here on, any failure must release everything opened so far.
	success := false
	var sess smbSession
	var share smbShare
	defer func() {
		if success {
			return
		}
		if share != nil {
			_ = share.Umount()
		}
		if sess != nil {
			_ = sess.Logoff()
		}
		_ = raw.Close()
		cancel()
	}()

	sess, err = dialSMB(ctx, raw, addr, p)
	if err != nil {
		return nil, classifySMBError(err)
	}
	bindContext(sess, closeCtx)

	share, err = sess.Mount(ipcShare)
	if err != nil {
		return nil, fmt.Errorf("mounting %s on %s: %w", ipcShare, p.Host, classifySMBError(err))
	}
	bindContext(share, closeCtx)

	pipe, pipePath, err := openFirstPipe(share, p.PipeCandidates, log)
	if err != nil {
		return nil, err
	}

	p.setResult(Result{
		PipePath: pipePath,
		Instance: InstanceFromPipePath(pipePath),
		SMBAuth:  authMechanism(p.Auth),
	})

	log.Debug("Opened SQL Server named pipe",
		"host", p.Host, "pipe", pipePath, "smb_auth", authMechanism(p.Auth))

	success = true
	return newPipeConn(pipeResources{
		file:    pipe,
		share:   share,
		session: sess,
		raw:     raw,
		cancel:  cancel,
	}, p.Host, pipePath), nil
}

func bindContext(v any, ctx context.Context) {
	if b, ok := v.(contextBinder); ok {
		b.bindContext(ctx)
	}
}

// openFirstPipe walks the candidate paths in order.
//
// Only "this pipe does not exist" advances to the next candidate. Access denied
// and every other failure stop immediately: the pipe was found, and hammering the
// host with further opens would produce nothing but audit noise and, for
// authentication failures, progress toward account lockout.
func openFirstPipe(share smbShare, candidates []string, log *slog.Logger) (io.ReadWriteCloser, string, error) {
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("%w: no candidate pipe paths were supplied", ErrPipeNotFound)
	}

	for _, name := range candidates {
		pipe, err := share.OpenPipe(name)
		if err == nil {
			return pipe, name, nil
		}

		switch {
		case errors.Is(err, os.ErrNotExist):
			log.Debug("Named pipe not present, trying next candidate", "pipe", name)
			continue
		case errors.Is(err, os.ErrPermission):
			return nil, "", fmt.Errorf("%w: %s", ErrPipeAccessDenied, name)
		default:
			return nil, "", fmt.Errorf("opening pipe %s: %w", name, classifySMBError(err))
		}
	}

	return nil, "", fmt.Errorf("%w: tried %s", ErrPipeNotFound, strings.Join(candidates, ", "))
}

// paramsFrom extracts the per-target state, tolerating a missing or wrongly typed
// entry rather than panicking on it.
func paramsFrom(cfg *msdsn.Config) (*Params, error) {
	if cfg == nil || cfg.ProtocolParameters == nil {
		return nil, ErrNoParams
	}
	raw, ok := cfg.ProtocolParameters[Protocol]
	if !ok {
		return nil, ErrNoParams
	}
	p, ok := raw.(*Params)
	if !ok {
		return nil, fmt.Errorf("%w: got %T", ErrNoParams, raw)
	}
	if p.Dial == nil {
		return nil, fmt.Errorf("%w: Dial is required", ErrNoParams)
	}
	if p.Host == "" {
		return nil, fmt.Errorf("%w: Host is required", ErrNoParams)
	}
	if !p.Auth.hasCredentials() {
		return nil, fmt.Errorf("%w: no SMB credentials configured", ErrSMBAuth)
	}
	return p, nil
}

func authMechanism(a AuthConfig) string {
	switch {
	case a.Krb5Client != nil:
		return "kerberos"
	case len(a.NTHash) > 0:
		return "ntlm-hash"
	default:
		return "ntlm"
	}
}

// classifySMBError maps an SMB failure onto our sentinels, so callers can tell an
// authentication failure (terminal, lockout-relevant) from an ordinary one.
func classifySMBError(err error) error {
	if err == nil {
		return nil
	}
	if isSMBAuthStatus(err) {
		return fmt.Errorf("%w: %w", ErrSMBAuth, err)
	}
	return err
}

// isSMBAuthStatus reports whether err represents a credential rejection.
//
// It checks the NTSTATUS code where one is available, and falls back to matching
// the rendered status name, because cloudsoda/go-smb2 surfaces some failures as
// plain errors whose text is the status name.
func isSMBAuthStatus(err error) bool {
	var re *smb2.ResponseError
	if errors.As(err, &re) {
		switch re.Code {
		case statusLogonFailure, statusAccountRestriction, statusInvalidLogonHours,
			statusInvalidWorkstation, statusPasswordExpired, statusAccountDisabled,
			statusAccountExpired, statusPasswordMustChange, statusAccountLockedOut,
			statusLogonTypeNotGranted, statusTrustedRelationshipFailure:
			return true
		}
	}

	text := strings.ToUpper(err.Error())
	for _, name := range []string{
		"STATUS_LOGON_FAILURE",
		"STATUS_ACCOUNT_RESTRICTION",
		"STATUS_INVALID_LOGON_HOURS",
		"STATUS_INVALID_WORKSTATION",
		"STATUS_PASSWORD_EXPIRED",
		"STATUS_ACCOUNT_DISABLED",
		"STATUS_ACCOUNT_EXPIRED",
		"STATUS_PASSWORD_MUST_CHANGE",
		"STATUS_ACCOUNT_LOCKED_OUT",
		"STATUS_LOGON_TYPE_NOT_GRANTED",
		"STATUS_TRUSTED_RELATIONSHIP_FAILURE",
	} {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

// IsAuthError reports whether err is an SMB credential rejection.
//
// This must be consulted alongside the SQL-side authentication check. SMB logon
// failures count toward Active Directory account lockout exactly as SQL logins
// do, so a run that sweeps many hosts with a bad credential has to stop on the
// first rejection rather than repeating it against every target.
func IsAuthError(err error) bool {
	return err != nil && (errors.Is(err, ErrSMBAuth) || isSMBAuthStatus(err))
}

// IsStrictEncryptionUnsupported reports the TDS 8.0 incompatibility.
func IsStrictEncryptionUnsupported(err error) bool {
	return errors.Is(err, ErrStrictEncryptionUnsupported)
}

func init() {
	msdsn.ProtocolDialers[Protocol] = dialer{}
	// Intentionally no msdsn.ProtocolParsers registration. See the package
	// comment: adding one would opt every TCP connection in the process into
	// this protocol and would double DialTimeout.
}
