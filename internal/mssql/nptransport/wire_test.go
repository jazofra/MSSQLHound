package nptransport

import (
	"context"
	"database/sql"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	mssqldb "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// TDS packet types exchanged during connection setup.
const (
	packetTypePrelogin         = 0x12
	packetTypeTabularResult    = 0x04
	preloginTokenVersion       = 0x00
	preloginTokenEncryption    = 0x01
	preloginTokenTerminator    = 0xFF
	preloginEncryptionNotSup   = 0x02
	preloginVersionPayloadSize = 6
)

// buildPreloginResponse assembles a TDS PRELOGIN response advertising that the
// server does not support encryption, which is the simplest negotiation that
// lets go-mssqldb proceed past prelogin.
func buildPreloginResponse() []byte {
	// Option table: two entries of five bytes each, then a one-byte terminator.
	const tableSize = 5 + 5 + 1
	versionOffset := tableSize
	encryptionOffset := versionOffset + preloginVersionPayloadSize
	payloadSize := encryptionOffset + 1

	payload := make([]byte, payloadSize)

	payload[0] = preloginTokenVersion
	binary.BigEndian.PutUint16(payload[1:3], uint16(versionOffset))
	binary.BigEndian.PutUint16(payload[3:5], preloginVersionPayloadSize)

	payload[5] = preloginTokenEncryption
	binary.BigEndian.PutUint16(payload[6:8], uint16(encryptionOffset))
	binary.BigEndian.PutUint16(payload[8:10], 1)

	payload[10] = preloginTokenTerminator

	// Version payload: major, minor, build, subbuild.
	payload[versionOffset] = 16
	payload[encryptionOffset] = preloginEncryptionNotSup

	packet := make([]byte, 8+payloadSize)
	packet[0] = packetTypeTabularResult
	packet[1] = 0x01 // end of message
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[8:], payload)
	return packet
}

// scriptedPipe answers a PRELOGIN with a canned response and then reports EOF,
// standing in for a named pipe on a real SQL Server.
type scriptedPipe struct {
	mu sync.Mutex
	// writes records every packet go-mssqldb sent.
	writes [][]byte
	// readLens records the buffer size of every read the adapter issued, which is
	// what proves the buffered-read invariant holds through the real driver.
	readLens []int
	pending  []byte
	answered bool
}

func (p *scriptedPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	cp := make([]byte, len(b))
	copy(cp, b)
	p.writes = append(p.writes, cp)

	// Answer the first PRELOGIN; everything after it goes unanswered.
	if !p.answered && len(b) > 0 && b[0] == packetTypePrelogin {
		p.pending = buildPreloginResponse()
		p.answered = true
	}
	return len(b), nil
}

func (p *scriptedPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.readLens = append(p.readLens, len(b))
	if len(p.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(b, p.pending)
	p.pending = p.pending[n:]
	return n, nil
}

func (p *scriptedPipe) Close() error { return nil }

func (p *scriptedPipe) snapshot() ([][]byte, []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w := make([][]byte, len(p.writes))
	copy(w, p.writes)
	r := make([]int, len(p.readLens))
	copy(r, p.readLens)
	return w, r
}

// TestDriverDrivesPipeTransport wires a real go-mssqldb connector to the named
// pipe transport and checks that TDS actually flows over it.
//
// This is the only test that exercises the whole path — Config.Protocols routing,
// ProtocolParameters lookup, the net.Conn adapter, and the driver's own packet
// framing — without a live SMB server, so it is what catches wiring regressions
// that the unit tests cannot see.
func TestDriverDrivesPipeTransport(t *testing.T) {
	pipe := &scriptedPipe{}
	share := &scriptedShare{pipe: pipe}
	session := &scriptedSession{share: share}

	original := dialSMB
	t.Cleanup(func() { dialSMB = original })
	dialSMB = func(context.Context, net.Conn, string, *Params) (smbSession, error) {
		return session, nil
	}

	params := &Params{
		Host:           "sql01",
		PipeCandidates: []string{`sql\query`},
		Auth:           AuthConfig{User: "svc", Password: "pw"},
		TDSSPN:         "MSSQLSvc/sql01:1433",
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			return client, nil
		},
	}

	cfg, err := msdsn.Parse("server=sql01;user id=svc;password=pw;encrypt=false;app name=MSSQLHound")
	if err != nil {
		t.Fatalf("msdsn.Parse() = %v", err)
	}
	cfg.Protocols = []string{Protocol}
	if cfg.ProtocolParameters == nil {
		cfg.ProtocolParameters = map[string]any{}
	}
	cfg.ProtocolParameters[Protocol] = params

	db := sql.OpenDB(mssqldb.NewConnectorConfig(cfg))
	defer db.Close()
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// The connection is expected to fail: the scripted pipe answers prelogin and
	// then goes silent, so login cannot complete. What matters is what crossed the
	// transport before it did.
	_ = db.PingContext(ctx)

	writes, readLens := pipe.snapshot()

	if len(writes) == 0 {
		t.Fatal("no TDS packets reached the pipe; the driver never used this transport")
	}

	first := writes[0]
	if len(first) < 8 {
		t.Fatalf("first packet is %d bytes, too short to be a TDS packet", len(first))
	}
	if first[0] != packetTypePrelogin {
		t.Errorf("first packet type = 0x%02X, want PRELOGIN (0x%02X)", first[0], packetTypePrelogin)
	}
	if got := int(binary.BigEndian.Uint16(first[2:4])); got != len(first) {
		t.Errorf("declared packet length %d does not match the %d bytes written", got, len(first))
	}

	if len(readLens) == 0 {
		t.Fatal("the driver never read from the pipe")
	}
	// The invariant that makes this transport work at all: go-mssqldb asks for an
	// 8-byte TDS header first, but the adapter must never turn that into an 8-byte
	// SMB read, or the server answers STATUS_BUFFER_OVERFLOW and the payload is
	// discarded by the SMB client.
	for i, n := range readLens {
		if n != readBufSize {
			t.Errorf("read %d requested %d bytes from the pipe, want %d", i, n, readBufSize)
		}
	}

	// Having answered prelogin, the driver should have moved on and sent more.
	if len(writes) < 2 {
		t.Errorf("only %d packet(s) sent; the prelogin response was not consumed correctly", len(writes))
	}
}

type scriptedSession struct{ share *scriptedShare }

func (s *scriptedSession) Mount(string) (smbShare, error) { return s.share, nil }
func (s *scriptedSession) Logoff() error                  { return nil }

type scriptedShare struct{ pipe *scriptedPipe }

func (s *scriptedShare) OpenPipe(string) (io.ReadWriteCloser, error) { return s.pipe, nil }
func (s *scriptedShare) Umount() error                               { return nil }
