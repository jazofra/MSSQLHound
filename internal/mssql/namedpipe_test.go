package mssql

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/mssql/nptransport"
)

// listenLoopback starts a TCP listener that accepts and immediately closes, and
// returns its port. Used to stand in for a reachable service.
func listenLoopback(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() = %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() = %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func useSMBPort(t *testing.T, port int) {
	t.Helper()
	original := smbProbePort
	t.Cleanup(func() { smbProbePort = original })
	smbProbePort = port
}

// TestCheckPortUnchangedWhenNamedPipeDisabled is the opt-in guarantee: with the
// flag off, CheckPort must behave exactly as it did before this feature existed.
func TestCheckPortUnchangedWhenNamedPipeDisabled(t *testing.T) {
	// A live SMB listener that would rescue the target if it were consulted.
	useSMBPort(t, listenLoopback(t))

	c := NewClient("127.0.0.1", "sa", "pw")
	c.port = closedPort(t)
	c.portCheckTimeout = 500 * time.Millisecond

	err := c.CheckPort(t.Context())
	if err == nil {
		t.Fatal("CheckPort() = nil, want failure: SMB must not be probed when the option is off")
	}
	if !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("CheckPort() = %v, want the original unreachable error", err)
	}
	if c.reachSMB {
		t.Error("reachSMB was set even though named pipes are disabled")
	}
}

func TestCheckPortFallsBackTo445(t *testing.T) {
	useSMBPort(t, listenLoopback(t))

	c := NewClient("127.0.0.1", "sa", "pw")
	c.port = closedPort(t)
	c.portCheckTimeout = 500 * time.Millisecond
	c.SetNamedPipe(true, "", nptransport.AuthConfig{User: "svc", Password: "pw"})

	if err := c.CheckPort(t.Context()); err != nil {
		t.Fatalf("CheckPort() = %v, want nil: SMB is reachable so the target is worth trying", err)
	}
	if c.reachTCP {
		t.Error("reachTCP = true, want false")
	}
	if !c.reachSMB {
		t.Error("reachSMB = false, want true")
	}
}

func TestCheckPortFailsWhenNeitherReachable(t *testing.T) {
	useSMBPort(t, closedPort(t))

	c := NewClient("127.0.0.1", "sa", "pw")
	c.port = closedPort(t)
	c.portCheckTimeout = 500 * time.Millisecond
	c.SetNamedPipe(true, "", nptransport.AuthConfig{User: "svc", Password: "pw"})

	err := c.CheckPort(t.Context())
	if err == nil {
		t.Fatal("CheckPort() = nil, want failure when neither transport answers")
	}
	if c.reachTCP || c.reachSMB {
		t.Errorf("reach flags = {tcp:%v smb:%v}, want both false", c.reachTCP, c.reachSMB)
	}
}

func TestCheckPortSucceedsOnTCPWithoutSMB(t *testing.T) {
	useSMBPort(t, closedPort(t))

	c := NewClient("127.0.0.1", "sa", "pw")
	c.port = listenLoopback(t)
	c.portCheckTimeout = 500 * time.Millisecond
	c.SetNamedPipe(true, "", nptransport.AuthConfig{User: "svc", Password: "pw"})

	if err := c.CheckPort(t.Context()); err != nil {
		t.Fatalf("CheckPort() = %v, want nil", err)
	}
	if !c.reachTCP {
		t.Error("reachTCP = false, want true")
	}
}

func TestBuildNamedPipeConnectionString(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*Client)
		encrypt     string
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "SQL auth",
			setup:       func(c *Client) {},
			encrypt:     "true",
			wantContain: []string{"server=sql01", "user id=sa", "password=pw", "encrypt=true", "app name=MSSQLHound"},
			// A port is meaningless over a pipe, and an instance would make
			// go-mssqldb want the SQL Browser, which this transport never uses.
			wantAbsent: []string{"port=", "instance="},
		},
		{
			name: "Kerberos emits the MSSQLSvc SPN",
			setup: func(c *Client) {
				c.useKerberos = true
			},
			encrypt:     "false",
			wantContain: []string{"trusted_connection=yes", "ServerSPN=MSSQLSvc/sql01:1433", "encrypt=false"},
			wantAbsent:  []string{"port=", "instance="},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient("sql01", "sa", "pw")
			tc.setup(c)

			got := c.buildNamedPipeConnectionString(tc.encrypt)
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("connection string %q missing %q", got, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("connection string %q must not contain %q", got, absent)
				}
			}
		})
	}
}

func TestServerSPNForTDS(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   string
	}{
		{"default instance uses the port", "sql01", "MSSQLSvc/sql01:1433"},
		{"explicit port", "sql01:1533", "MSSQLSvc/sql01:1533"},
		{"named instance uses the instance", `sql01\SQLEXPRESS`, "MSSQLSvc/sql01:SQLEXPRESS"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(tc.server, "sa", "pw")
			if got := c.serverSPNForTDS(); got != tc.want {
				t.Errorf("serverSPNForTDS() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStrictEncryptionRejectedOnPipe pins an architectural limit: TDS 8.0 strict
// encryption wraps the raw socket in TLS before any TDS is exchanged, and a pipe
// has no equivalent stage. It must be reported, never retried.
func TestStrictEncryptionRejectedOnPipe(t *testing.T) {
	c := NewClient("sql01", "sa", "pw")
	c.SetNamedPipe(true, "", nptransport.AuthConfig{User: "svc", Password: "pw"})
	c.epaResult = &EPATestResult{StrictEncryption: true}

	err := c.connectNamedPipe(t.Context())
	if !nptransport.IsStrictEncryptionUnsupported(err) {
		t.Fatalf("connectNamedPipe() = %v, want ErrStrictEncryptionUnsupported", err)
	}
}

// TestIsAuthErrorIncludesSMBLogonFailure is the account-lockout guard. An SMB
// rejection has to be recognised here, or a sweep with a bad credential would
// keep authenticating against every remaining host.
func TestIsAuthErrorIncludesSMBLogonFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"SMB auth sentinel", nptransport.ErrSMBAuth, true},
		{"SMB status text", errors.New("response error: STATUS_LOGON_FAILURE"), true},
		{"SQL login failure still detected", errors.New("mssql: Login failed for user 'sa'"), true},
		{"untrusted domain still detected", errors.New("untrusted domain"), true},
		{"pipe missing is not an auth error", nptransport.ErrPipeNotFound, false},
		{"access denied is not an auth error", nptransport.ErrPipeAccessDenied, false},
		{"unreachable is not an auth error", nptransport.ErrSMBUnreachable, false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAuthError(tc.err); got != tc.want {
				t.Errorf("IsAuthError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestNewNamedPipeParams(t *testing.T) {
	t.Run("derives candidates and SPNs", func(t *testing.T) {
		c := NewClient(`sql01.corp.example\SQLEXPRESS`, "sa", "pw")
		c.SetNamedPipe(true, "", nptransport.AuthConfig{User: "svc", Password: "pw"})

		p := c.newNamedPipeParams()

		if len(p.PipeCandidates) != 1 || p.PipeCandidates[0] != `MSSQL$SQLEXPRESS\sql\query` {
			t.Errorf("PipeCandidates = %v, want the named-instance pipe", p.PipeCandidates)
		}
		// The SMB session and the database session authenticate separately and
		// need different service principals.
		if p.Auth.SMBSPN != "cifs/sql01.corp.example" {
			t.Errorf("Auth.SMBSPN = %q, want cifs/sql01.corp.example", p.Auth.SMBSPN)
		}
		if p.TDSSPN != "MSSQLSvc/sql01.corp.example:SQLEXPRESS" {
			t.Errorf("TDSSPN = %q, want the MSSQLSvc SPN", p.TDSSPN)
		}
		if p.Dial == nil {
			t.Error("Dial must be set, or the transport cannot reach the host")
		}
	})

	t.Run("explicit path replaces discovery", func(t *testing.T) {
		c := NewClient("sql01", "sa", "pw")
		c.SetNamedPipe(true, `MICROSOFT##WID\tsql\query`, nptransport.AuthConfig{User: "svc"})

		p := c.newNamedPipeParams()
		if len(p.PipeCandidates) != 1 || p.PipeCandidates[0] != `MICROSOFT##WID\tsql\query` {
			t.Errorf("PipeCandidates = %v, want only the explicit path", p.PipeCandidates)
		}
	})

	t.Run("default instance probes WID as a fallback", func(t *testing.T) {
		c := NewClient("sql01", "sa", "pw")
		c.SetNamedPipe(true, "", nptransport.AuthConfig{User: "svc"})

		p := c.newNamedPipeParams()
		if len(p.PipeCandidates) != 2 {
			t.Fatalf("PipeCandidates = %v, want the default pipe then WID", p.PipeCandidates)
		}
	})
}

func TestNamedPipeResult(t *testing.T) {
	c := NewClient("sql01", "sa", "pw")

	if _, ok := c.NamedPipeResult(); ok {
		t.Error("NamedPipeResult() reported a result before any pipe connection")
	}

	c.npParams = &nptransport.Params{}
	if _, ok := c.NamedPipeResult(); ok {
		t.Error("NamedPipeResult() reported a result when no pipe was opened")
	}
}

// TestConnectSkipsPipeWhenDisabled proves the fallback cannot fire unless the
// option is on.
func TestConnectSkipsPipeWhenDisabled(t *testing.T) {
	c := NewClient("127.0.0.1", "sa", "pw")
	c.port = closedPort(t)
	c.namedPipe = false
	c.reachSMB = true // would be enough to try the pipe, if the option were on

	err := c.connectNative(t.Context())
	if err == nil {
		t.Fatal("connectNative() = nil, want failure")
	}
	if c.npParams != nil {
		t.Error("named pipe params were built even though the option is disabled")
	}
}

// TestConnectAttemptsBothWhenReachabilityUnknown is a regression guard for
// callers that connect without a prior CheckPort — the collector's
// short-name-to-FQDN retry is one. Treating an unprobed target as unreachable
// would silently skip it whenever --named-pipe was enabled.
func TestConnectAttemptsBothWhenReachabilityUnknown(t *testing.T) {
	c := NewClient("127.0.0.1", "sa", "pw")
	c.port = closedPort(t)
	c.portCheckTimeout = 500 * time.Millisecond
	c.SetNamedPipe(true, "", nptransport.AuthConfig{User: "svc", Password: "pw"})

	if c.reachChecked {
		t.Fatal("reachChecked should start false")
	}

	err := c.connectNative(t.Context())
	if err == nil {
		t.Fatal("connectNative() = nil, want failure against a closed port")
	}
	// The point is not that it succeeded, but that it tried the pipe rather than
	// bailing out with "no reachable transport".
	if strings.Contains(err.Error(), "no reachable transport") {
		t.Errorf("connectNative() = %v, want a real attempt rather than an early skip", err)
	}
	if c.npParams == nil {
		t.Error("named pipe was never attempted for an unprobed target")
	}
}

// TestConnectSkipsPipeWhenProbedUnreachable is the complement: once CheckPort has
// actually reported SMB unreachable, the pipe must not be attempted.
func TestConnectSkipsPipeWhenProbedUnreachable(t *testing.T) {
	useSMBPort(t, closedPort(t))

	c := NewClient("127.0.0.1", "sa", "pw")
	c.port = listenLoopback(t)
	c.portCheckTimeout = 500 * time.Millisecond
	c.SetNamedPipe(true, "", nptransport.AuthConfig{User: "svc", Password: "pw"})

	if err := c.CheckPort(t.Context()); err != nil {
		t.Fatalf("CheckPort() = %v", err)
	}
	if !c.reachChecked || c.reachSMB {
		t.Fatalf("want reachChecked=true reachSMB=false, got %v/%v", c.reachChecked, c.reachSMB)
	}

	// The loopback listener accepts and closes, so TCP login fails; the pipe must
	// not then be tried, because SMB was probed and found closed.
	_ = c.connectNative(t.Context())
	if c.npParams != nil {
		t.Error("named pipe was attempted even though SMB was probed unreachable")
	}
}
