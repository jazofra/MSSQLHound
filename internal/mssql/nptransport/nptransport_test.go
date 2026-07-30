package nptransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// --- Registration regression -------------------------------------------------
//
// These tests exist to keep the opt-in promise: enabling named pipes must not
// change how ordinary TCP connections behave anywhere else in the process.

func TestInitRegistersDialerOnly(t *testing.T) {
	if _, ok := msdsn.ProtocolDialers[Protocol]; !ok {
		t.Fatalf("ProtocolDialers[%q] is not registered", Protocol)
	}

	// Registering a ProtocolParser would make msdsn.Parse append "np" to
	// Config.Protocols for every connection in the process, and would double
	// DialTimeout (computed as 15s per protocol). We must never do that.
	var names []string
	for _, p := range msdsn.ProtocolParsers {
		names = append(names, p.Protocol())
		if p.Protocol() == Protocol {
			t.Errorf("a ProtocolParser is registered for %q; this silently opts every TCP connection into the named-pipe protocol", Protocol)
		}
	}
	if len(msdsn.ProtocolParsers) != 2 {
		t.Errorf("ProtocolParsers = %v, want exactly the two built-ins (tcp, admin)", names)
	}
}

func TestParseUnaffectedByRegistration(t *testing.T) {
	cfg, err := msdsn.Parse("server=sql01;user id=u;password=p;encrypt=true")
	if err != nil {
		t.Fatalf("msdsn.Parse() = %v", err)
	}

	if len(cfg.Protocols) != 1 || cfg.Protocols[0] != "tcp" {
		t.Errorf("Protocols = %v, want [tcp] for an ordinary connection string", cfg.Protocols)
	}
	if cfg.DialTimeout != 15*time.Second {
		t.Errorf("DialTimeout = %v, want 15s (one protocol); a second protocol would double it", cfg.DialTimeout)
	}
}

func TestCallBrowserAlwaysFalse(t *testing.T) {
	// The SQL Browser speaks UDP 1434, which cannot traverse a SOCKS5 proxy.
	// Never consulting it is what makes this transport work through one.
	if (dialer{}).CallBrowser(&msdsn.Config{Instance: "SQLEXPRESS"}) {
		t.Error("CallBrowser() = true, want false")
	}
	if err := (dialer{}).ParseBrowserData(msdsn.BrowserData{}, &msdsn.Config{}); err != nil {
		t.Errorf("ParseBrowserData() = %v, want nil", err)
	}
}

// --- Parameter plumbing ------------------------------------------------------

func TestDialConnectionRejectsBadParams(t *testing.T) {
	okDial := func(context.Context, string, string) (net.Conn, error) { return nil, nil }

	tests := []struct {
		name string
		cfg  *msdsn.Config
	}{
		{"nil config", nil},
		{"nil parameter map", &msdsn.Config{}},
		{"missing entry", &msdsn.Config{ProtocolParameters: map[string]any{}}},
		{"wrong type", &msdsn.Config{ProtocolParameters: map[string]any{Protocol: "not-params"}}},
		{"value instead of pointer", &msdsn.Config{ProtocolParameters: map[string]any{Protocol: Params{}}}},
		{"missing Dial", &msdsn.Config{ProtocolParameters: map[string]any{
			Protocol: &Params{Host: "sql01", Auth: AuthConfig{User: "u"}},
		}}},
		{"missing Host", &msdsn.Config{ProtocolParameters: map[string]any{
			Protocol: &Params{Dial: okDial, Auth: AuthConfig{User: "u"}},
		}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := (dialer{}).DialConnection(t.Context(), tc.cfg)
			if err == nil {
				t.Fatal("DialConnection() = nil error, want a failure")
			}
			if conn != nil {
				t.Error("DialConnection() returned a non-nil conn alongside an error")
			}
			if !errors.Is(err, ErrNoParams) {
				t.Errorf("DialConnection() = %v, want it to wrap ErrNoParams", err)
			}
		})
	}
}

func TestDialConnectionRequiresCredentials(t *testing.T) {
	cfg := &msdsn.Config{ProtocolParameters: map[string]any{
		Protocol: &Params{
			Host: "sql01",
			Dial: func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		},
	}}

	_, err := (dialer{}).DialConnection(t.Context(), cfg)
	if !errors.Is(err, ErrSMBAuth) {
		t.Errorf("DialConnection() with no credentials = %v, want ErrSMBAuth", err)
	}
}

// --- Fakes for the SMB layer -------------------------------------------------

type fakeSMBSession struct {
	share      *fakeSMBShare
	mountErr   error
	loggedOff  bool
	mountCalls []string
}

func (s *fakeSMBSession) Mount(share string) (smbShare, error) {
	s.mountCalls = append(s.mountCalls, share)
	if s.mountErr != nil {
		return nil, s.mountErr
	}
	return s.share, nil
}
func (s *fakeSMBSession) Logoff() error { s.loggedOff = true; return nil }

type fakeSMBShare struct {
	// openErrs maps a pipe path to the error opening it should produce. A path
	// absent from the map opens successfully.
	openErrs  map[string]error
	attempted []string
	unmounted bool
}

func (s *fakeSMBShare) OpenPipe(name string) (io.ReadWriteCloser, error) {
	s.attempted = append(s.attempted, name)
	if err, ok := s.openErrs[name]; ok {
		return nil, err
	}
	return &fakePipe{}, nil
}
func (s *fakeSMBShare) Umount() error { s.unmounted = true; return nil }

type fakeNetConn struct {
	net.Conn
	closed bool
}

func (c *fakeNetConn) Close() error { c.closed = true; return nil }

// harness wires a Params and a swapped dialSMB seam for a single test.
type harness struct {
	params  *Params
	cfg     *msdsn.Config
	session *fakeSMBSession
	share   *fakeSMBShare
	raw     *fakeNetConn
	dialErr error
	smbErr  error
}

func newHarness(t *testing.T, instance string) *harness {
	t.Helper()

	h := &harness{
		share: &fakeSMBShare{openErrs: map[string]error{}},
		raw:   &fakeNetConn{},
	}
	h.session = &fakeSMBSession{share: h.share}

	h.params = &Params{
		Host:           "sql01.corp.example",
		PipeCandidates: Candidates(instance),
		Auth:           AuthConfig{User: "svc", Password: "pw", Domain: "CORP"},
		TDSSPN:         "MSSQLSvc/sql01.corp.example:1433",
		Dial: func(context.Context, string, string) (net.Conn, error) {
			if h.dialErr != nil {
				return nil, h.dialErr
			}
			return h.raw, nil
		},
	}
	h.cfg = &msdsn.Config{ProtocolParameters: map[string]any{Protocol: h.params}}

	original := dialSMB
	t.Cleanup(func() { dialSMB = original })
	dialSMB = func(context.Context, net.Conn, string, *Params) (smbSession, error) {
		if h.smbErr != nil {
			return nil, h.smbErr
		}
		return h.session, nil
	}

	return h
}

func (h *harness) dial(t *testing.T) (net.Conn, error) {
	t.Helper()
	return (dialer{}).DialConnection(t.Context(), h.cfg)
}

// --- Dial behaviour ----------------------------------------------------------

func TestDialConnectionOpensDefaultPipe(t *testing.T) {
	h := newHarness(t, "")

	conn, err := h.dial(t)
	if err != nil {
		t.Fatalf("DialConnection() = %v", err)
	}
	defer conn.Close()

	if got := h.share.attempted; len(got) != 1 || got[0] != `sql\query` {
		t.Errorf("pipes attempted = %v, want just [sql\\query]", got)
	}
	if got := h.session.mountCalls; len(got) != 1 || got[0] != ipcShare {
		t.Errorf("mounts = %v, want [%s]", got, ipcShare)
	}

	res := h.params.Result()
	if res.PipePath != `sql\query` || res.Instance != "" || res.SMBAuth != "ntlm" {
		t.Errorf("Result() = %+v, want the default pipe with no instance over ntlm", res)
	}
}

// TestDialConnectionFallsThroughToWID covers the case that motivates the whole
// feature: a host with no default SQL pipe but a Windows Internal Database.
func TestDialConnectionFallsThroughToWID(t *testing.T) {
	h := newHarness(t, "")
	h.share.openErrs[`sql\query`] = os.ErrNotExist

	conn, err := h.dial(t)
	if err != nil {
		t.Fatalf("DialConnection() = %v", err)
	}
	defer conn.Close()

	want := []string{`sql\query`, `MICROSOFT##WID\tsql\query`}
	if got := h.share.attempted; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("pipes attempted = %v, want %v", got, want)
	}

	res := h.params.Result()
	if res.PipePath != `MICROSOFT##WID\tsql\query` {
		t.Errorf("Result().PipePath = %q, want the WID pipe", res.PipePath)
	}
	// The instance must be reported so the caller can file this under a distinct
	// identity rather than overwriting the host's default-instance node.
	if res.Instance != "MICROSOFT##WID" {
		t.Errorf("Result().Instance = %q, want %q", res.Instance, "MICROSOFT##WID")
	}
}

func TestDialConnectionAccessDeniedIsTerminal(t *testing.T) {
	h := newHarness(t, "")
	h.share.openErrs[`sql\query`] = os.ErrPermission

	_, err := h.dial(t)
	if !errors.Is(err, ErrPipeAccessDenied) {
		t.Fatalf("DialConnection() = %v, want ErrPipeAccessDenied", err)
	}
	// Access denied means the pipe is there and the ACL said no. Trying the next
	// candidate would be pointless noise against the host.
	if got := h.share.attempted; len(got) != 1 {
		t.Errorf("pipes attempted = %v, want to stop after the first", got)
	}
}

func TestDialConnectionNoPipeFound(t *testing.T) {
	h := newHarness(t, "")
	h.share.openErrs[`sql\query`] = os.ErrNotExist
	h.share.openErrs[`MICROSOFT##WID\tsql\query`] = os.ErrNotExist

	_, err := h.dial(t)
	if !errors.Is(err, ErrPipeNotFound) {
		t.Fatalf("DialConnection() = %v, want ErrPipeNotFound", err)
	}
	if !strings.Contains(err.Error(), `sql\query`) {
		t.Errorf("error %q should name the paths it tried", err)
	}
}

func TestDialConnectionUnreachable(t *testing.T) {
	h := newHarness(t, "")
	h.dialErr = errors.New("connection refused")

	_, err := h.dial(t)
	if !errors.Is(err, ErrSMBUnreachable) {
		t.Errorf("DialConnection() = %v, want ErrSMBUnreachable", err)
	}
}

func TestDialConnectionStampsServerSPN(t *testing.T) {
	h := newHarness(t, "")

	conn, err := h.dial(t)
	if err != nil {
		t.Fatalf("DialConnection() = %v", err)
	}
	defer conn.Close()

	// msdsn.ProtocolDialer documents that a non-TCP transport fills in ServerSPN
	// when the caller left it empty, so Kerberos has a target to request.
	if h.cfg.ServerSPN != "MSSQLSvc/sql01.corp.example:1433" {
		t.Errorf("ServerSPN = %q, want it stamped from Params.TDSSPN", h.cfg.ServerSPN)
	}
}

func TestDialConnectionPreservesExplicitServerSPN(t *testing.T) {
	h := newHarness(t, "")
	h.cfg.ServerSPN = "MSSQLSvc/override:1433"

	conn, err := h.dial(t)
	if err != nil {
		t.Fatalf("DialConnection() = %v", err)
	}
	defer conn.Close()

	if h.cfg.ServerSPN != "MSSQLSvc/override:1433" {
		t.Errorf("ServerSPN = %q, want the caller's value left alone", h.cfg.ServerSPN)
	}
}

// TestDialConnectionReleasesResourcesOnFailure guards against leaking an SMB
// session or socket for every unreachable host in a large sweep.
func TestDialConnectionReleasesResourcesOnFailure(t *testing.T) {
	h := newHarness(t, "")
	h.share.openErrs[`sql\query`] = os.ErrNotExist
	h.share.openErrs[`MICROSOFT##WID\tsql\query`] = os.ErrNotExist

	if _, err := h.dial(t); err == nil {
		t.Fatal("expected a failure")
	}

	if !h.share.unmounted {
		t.Error("share was not unmounted after a failed dial")
	}
	if !h.session.loggedOff {
		t.Error("session was not logged off after a failed dial")
	}
	if !h.raw.closed {
		t.Error("underlying connection was not closed after a failed dial")
	}
}

func TestDialConnectionNamedInstanceSkipsWID(t *testing.T) {
	h := newHarness(t, "SQLEXPRESS")

	conn, err := h.dial(t)
	if err != nil {
		t.Fatalf("DialConnection() = %v", err)
	}
	defer conn.Close()

	if got := h.share.attempted; len(got) != 1 || got[0] != `MSSQL$SQLEXPRESS\sql\query` {
		t.Errorf("pipes attempted = %v, want only the named-instance pipe", got)
	}
}

// --- Authentication classification -------------------------------------------

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"sentinel", fmt.Errorf("wrapped: %w", ErrSMBAuth), true},
		{"response error logon failure", &smb2.ResponseError{Code: statusLogonFailure}, true},
		{"response error locked out", &smb2.ResponseError{Code: statusAccountLockedOut}, true},
		{"response error password expired", &smb2.ResponseError{Code: statusPasswordExpired}, true},
		{"response error wrapped", fmt.Errorf("mount: %w", &smb2.ResponseError{Code: statusLogonFailure}), true},
		{"status name in text", errors.New("response error: STATUS_LOGON_FAILURE"), true},
		{"unrelated response error", &smb2.ResponseError{Code: 0xC0000022}, false},
		{"pipe missing", ErrPipeNotFound, false},
		{"unreachable", ErrSMBUnreachable, false},
		{"plain error", errors.New("connection refused"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAuthError(tc.err); got != tc.want {
				t.Errorf("IsAuthError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestAuthFailureIsClassifiedDuringDial is the lockout guard end to end: an SMB
// rejection must be recognisable as an auth error by the time it leaves the
// dialer, so callers stop instead of repeating it against the next host.
func TestAuthFailureIsClassifiedDuringDial(t *testing.T) {
	h := newHarness(t, "")
	h.smbErr = &smb2.ResponseError{Code: statusLogonFailure}

	_, err := h.dial(t)
	if !IsAuthError(err) {
		t.Fatalf("DialConnection() = %v, want an error IsAuthError recognises", err)
	}
	if !h.raw.closed {
		t.Error("underlying connection was not closed after an auth failure")
	}
}

func TestAuthMechanism(t *testing.T) {
	tests := []struct {
		name string
		auth AuthConfig
		want string
	}{
		{"password", AuthConfig{User: "u", Password: "p"}, "ntlm"},
		{"hash", AuthConfig{User: "u", NTHash: make([]byte, ntHashLen)}, "ntlm-hash"},
		{"kerberos", AuthConfig{Krb5Client: &krb5ClientStub}, "kerberos"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := authMechanism(tc.auth); got != tc.want {
				t.Errorf("authMechanism() = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- Initiator construction --------------------------------------------------

func TestBuildInitiator(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		init, err := buildInitiator(AuthConfig{User: "svc", Password: "pw", Domain: "CORP"})
		if err != nil {
			t.Fatalf("buildInitiator() = %v", err)
		}
		ntlm, ok := init.(*smb2.NTLMInitiator)
		if !ok {
			t.Fatalf("buildInitiator() = %T, want *smb2.NTLMInitiator", init)
		}
		if ntlm.Password != "pw" || ntlm.User != "svc" || ntlm.Domain != "CORP" {
			t.Errorf("initiator = %+v, want the supplied credentials", ntlm)
		}
	})

	t.Run("pass the hash clears the password", func(t *testing.T) {
		hash := make([]byte, ntHashLen)
		init, err := buildInitiator(AuthConfig{User: "svc", Password: "pw", NTHash: hash})
		if err != nil {
			t.Fatalf("buildInitiator() = %v", err)
		}
		ntlm := init.(*smb2.NTLMInitiator)
		if ntlm.Password != "" {
			t.Errorf("Password = %q, want empty when a hash is supplied", ntlm.Password)
		}
		if len(ntlm.Hash) != ntHashLen {
			t.Errorf("Hash length = %d, want %d", len(ntlm.Hash), ntHashLen)
		}
	})

	t.Run("wrong hash length rejected", func(t *testing.T) {
		_, err := buildInitiator(AuthConfig{User: "svc", NTHash: []byte{1, 2, 3}})
		if !errors.Is(err, ErrSMBAuth) {
			t.Errorf("buildInitiator() = %v, want ErrSMBAuth", err)
		}
	})

	t.Run("no username rejected", func(t *testing.T) {
		if _, err := buildInitiator(AuthConfig{}); !errors.Is(err, ErrSMBAuth) {
			t.Errorf("buildInitiator() = %v, want ErrSMBAuth", err)
		}
	})

	t.Run("kerberos requires an SPN", func(t *testing.T) {
		_, err := buildInitiator(AuthConfig{Krb5Client: &krb5ClientStub})
		if !errors.Is(err, ErrSMBAuth) {
			t.Errorf("buildInitiator() = %v, want ErrSMBAuth when the SMB SPN is missing", err)
		}
	})

	t.Run("kerberos", func(t *testing.T) {
		init, err := buildInitiator(AuthConfig{Krb5Client: &krb5ClientStub, SMBSPN: "cifs/sql01"})
		if err != nil {
			t.Fatalf("buildInitiator() = %v", err)
		}
		krb, ok := init.(*smb2.Krb5Initiator)
		if !ok {
			t.Fatalf("buildInitiator() = %T, want *smb2.Krb5Initiator", init)
		}
		if krb.TargetSPN != "cifs/sql01" {
			t.Errorf("TargetSPN = %q, want %q", krb.TargetSPN, "cifs/sql01")
		}
	})
}

func TestSMBSPNFor(t *testing.T) {
	tests := []struct{ in, want string }{
		{"sql01.corp.example", "cifs/sql01.corp.example"},
		{"sql01", "cifs/sql01"},
		{"sql01.corp.example:445", "cifs/sql01.corp.example"},
		{"  sql01  ", "cifs/sql01"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := SMBSPNFor(tc.in); got != tc.want {
			t.Errorf("SMBSPNFor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSplitDomainUser(t *testing.T) {
	tests := []struct {
		in             string
		domain, accout string
	}{
		{`CORP\svc`, "CORP", "svc"},
		{"svc@corp.example", "corp.example", "svc"},
		{"svc", "", "svc"},
		{"", "", ""},
		{`  CORP\svc  `, "CORP", "svc"},
	}
	for _, tc := range tests {
		d, a := SplitDomainUser(tc.in)
		if d != tc.domain || a != tc.accout {
			t.Errorf("SplitDomainUser(%q) = (%q, %q), want (%q, %q)", tc.in, d, a, tc.domain, tc.accout)
		}
	}
}

// krb5ClientStub is a zero-valued gokrb5 client used only to select the Kerberos
// code path. Nothing in these tests performs a real KDC exchange.
var krb5ClientStub client.Client
