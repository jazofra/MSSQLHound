//go:build integration

package mssql

import (
	"os"
	"testing"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/mssql/nptransport"
)

// Named-pipe collection cannot be exercised by the CI integration job: that job
// runs SQL Server on Linux, which does not serve named pipes at all. These tests
// therefore target a Windows host supplied through the environment and skip when
// one is not configured.
//
// Required:
//
//	MSSQLHOUND_NP_HOST      Windows host running SQL Server (FQDN preferred)
//	MSSQLHOUND_NP_USER      SMB user, DOMAIN\user or user@domain
//	MSSQLHOUND_NP_PASSWORD  password for that user
//
// Optional:
//
//	MSSQLHOUND_NP_INSTANCE  named instance to target
//	MSSQLHOUND_NP_PATH      explicit pipe path under IPC$
//	MSSQLHOUND_NP_SQL_USER  SQL login, when it differs from the SMB identity
//	MSSQLHOUND_NP_SQL_PASS  password for that SQL login
//
// See TESTING.md for the manual matrix this is meant to cover.
func npTestTarget(t *testing.T) (host string, auth nptransport.AuthConfig) {
	t.Helper()

	host = os.Getenv("MSSQLHOUND_NP_HOST")
	if host == "" {
		t.Skip("MSSQLHOUND_NP_HOST is not set; skipping named-pipe integration test")
	}

	user := os.Getenv("MSSQLHOUND_NP_USER")
	if user == "" {
		t.Skip("MSSQLHOUND_NP_USER is not set; skipping named-pipe integration test")
	}

	domain, account := nptransport.SplitDomainUser(user)
	return host, nptransport.AuthConfig{
		User:     account,
		Domain:   domain,
		Password: os.Getenv("MSSQLHOUND_NP_PASSWORD"),
	}
}

func newNPClient(t *testing.T) *Client {
	t.Helper()

	host, auth := npTestTarget(t)
	target := host
	if instance := os.Getenv("MSSQLHOUND_NP_INSTANCE"); instance != "" {
		target = host + `\` + instance
	}

	sqlUser := os.Getenv("MSSQLHOUND_NP_SQL_USER")
	sqlPass := os.Getenv("MSSQLHOUND_NP_SQL_PASS")
	if sqlUser == "" {
		sqlUser, sqlPass = auth.Domain+`\`+auth.User, auth.Password
	}

	c := NewClient(target, sqlUser, sqlPass)
	c.SetNamedPipe(true, os.Getenv("MSSQLHOUND_NP_PATH"), auth)
	c.SetPortCheckTimeout(5 * time.Second)
	c.SetVerbose(true)
	return c
}

func TestNamedPipeConnect(t *testing.T) {
	c := newNPClient(t)
	defer c.Close()

	if err := c.CheckPort(t.Context()); err != nil {
		t.Fatalf("CheckPort() = %v", err)
	}
	if !c.reachSMB {
		t.Fatal("SMB is not reachable on the target; the pipe cannot be tried")
	}

	// Force the pipe path even when TCP is reachable, so this exercises the
	// transport rather than falling back to the ordinary connection.
	if err := c.connectNamedPipe(t.Context()); err != nil {
		t.Fatalf("connectNamedPipe() = %v", err)
	}

	res, ok := c.NamedPipeResult()
	if !ok {
		t.Fatal("NamedPipeResult() reported no result after a successful connection")
	}
	t.Logf("connected over %s (instance %q, smb auth %s)", res.PipePath, res.Instance, res.SMBAuth)

	var one int
	if err := c.DBW().QueryRowContext(t.Context(), "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query over named pipe = %v", err)
	}
	if one != 1 {
		t.Errorf("SELECT 1 returned %d", one)
	}
}

// TestNamedPipeCollectsServerInfo proves the transport carries a full collection,
// not just a handshake.
func TestNamedPipeCollectsServerInfo(t *testing.T) {
	c := newNPClient(t)
	defer c.Close()

	if err := c.CheckPort(t.Context()); err != nil {
		t.Fatalf("CheckPort() = %v", err)
	}
	if err := c.connectNamedPipe(t.Context()); err != nil {
		t.Fatalf("connectNamedPipe() = %v", err)
	}

	info, err := c.CollectServerInfo(t.Context())
	if err != nil {
		t.Fatalf("CollectServerInfo() = %v", err)
	}
	if info.Version == "" {
		t.Error("collected server info has no version")
	}
	t.Logf("collected %s (%s)", info.Hostname, info.Version)
}
