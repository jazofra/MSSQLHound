package nptransport

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePipe stands in for an SMB named pipe. It hands back one queued message per
// Read call (mimicking message-mode pipe semantics) and, crucially, records the
// length of the buffer it was asked to fill so tests can assert on it.
type fakePipe struct {
	mu       sync.Mutex
	messages [][]byte
	readLens []int
	writes   [][]byte
	// readErr is returned once the queued messages run out. Defaults to io.EOF.
	readErr error
	// errWithLastMessage delivers readErr alongside the final message rather than
	// on the following call, exercising the sticky-error path.
	errWithLastMessage bool
	closed             bool
	// block, when non-nil, makes Read wait on it before returning, so deadline
	// behaviour can be tested deterministically.
	block chan struct{}
}

func (f *fakePipe) Read(b []byte) (int, error) {
	f.mu.Lock()
	f.readLens = append(f.readLens, len(b))
	block := f.block
	f.mu.Unlock()

	if block != nil {
		<-block
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.messages) == 0 {
		if f.readErr != nil {
			return 0, f.readErr
		}
		return 0, io.EOF
	}

	msg := f.messages[0]
	f.messages = f.messages[1:]
	n := copy(b, msg)

	if len(f.messages) == 0 && f.errWithLastMessage && f.readErr != nil {
		return n, f.readErr
	}
	return n, nil
}

func (f *fakePipe) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(b))
	copy(cp, b)
	f.writes = append(f.writes, cp)
	return len(b), nil
}

func (f *fakePipe) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakePipe) recordedReadLens() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int, len(f.readLens))
	copy(out, f.readLens)
	return out
}

// tdsPacket builds a TDS packet with a valid 8-byte header and a body of the
// requested size, so tests exercise the same read shape go-mssqldb produces.
func tdsPacket(packetType byte, bodyLen int) []byte {
	total := 8 + bodyLen
	p := make([]byte, total)
	p[0] = packetType
	p[1] = 0x01 // EOM
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	for i := range bodyLen {
		p[8+i] = byte('a' + i%26)
	}
	return p
}

func newTestConn(f *fakePipe) *pipeConn {
	return newPipeConn(pipeResources{file: f}, "SQL01", `sql\query`)
}

// TestReadAlwaysRequestsFullBuffer is the single most important test in this
// package. go-mssqldb opens every TDS packet with an 8-byte header read; if that
// 8-byte request reached the pipe as an 8-byte SMB2 READ, cloudsoda/go-smb2 would
// answer STATUS_BUFFER_OVERFLOW and silently discard the payload, desynchronising
// the stream. The adapter must always ask the pipe for the full buffer.
func TestReadAlwaysRequestsFullBuffer(t *testing.T) {
	f := &fakePipe{messages: [][]byte{tdsPacket(0x12, 4088)}}
	c := newTestConn(f)

	header := make([]byte, 8)
	if _, err := io.ReadFull(c, header); err != nil {
		t.Fatalf("ReadFull(header) = %v, want nil", err)
	}

	lens := f.recordedReadLens()
	if len(lens) == 0 {
		t.Fatal("underlying pipe was never read")
	}
	for i, n := range lens {
		if n != readBufSize {
			t.Errorf("underlying read %d requested %d bytes, want %d", i, n, readBufSize)
		}
	}
}

func TestSingleTDSPacketOneUnderlyingRead(t *testing.T) {
	want := tdsPacket(0x04, 4088)
	f := &fakePipe{messages: [][]byte{want}}
	c := newTestConn(f)

	header := make([]byte, 8)
	if _, err := io.ReadFull(c, header); err != nil {
		t.Fatalf("ReadFull(header) = %v", err)
	}
	size := int(binary.BigEndian.Uint16(header[2:4]))
	body := make([]byte, size-8)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatalf("ReadFull(body) = %v", err)
	}

	got := append(append([]byte{}, header...), body...)
	if string(got) != string(want) {
		t.Errorf("round-tripped packet does not match original")
	}
	if n := len(f.recordedReadLens()); n != 1 {
		t.Errorf("underlying reads = %d, want 1 (buffer should serve both reads)", n)
	}
}

func TestTwoPacketsInOneMessage(t *testing.T) {
	p1 := tdsPacket(0x04, 100)
	p2 := tdsPacket(0x04, 200)
	combined := append(append([]byte{}, p1...), p2...)
	f := &fakePipe{messages: [][]byte{combined}}
	c := newTestConn(f)

	for i, want := range [][]byte{p1, p2} {
		header := make([]byte, 8)
		if _, err := io.ReadFull(c, header); err != nil {
			t.Fatalf("packet %d: ReadFull(header) = %v", i, err)
		}
		size := int(binary.BigEndian.Uint16(header[2:4]))
		body := make([]byte, size-8)
		if _, err := io.ReadFull(c, body); err != nil {
			t.Fatalf("packet %d: ReadFull(body) = %v", i, err)
		}
		got := append(append([]byte{}, header...), body...)
		if string(got) != string(want) {
			t.Errorf("packet %d does not match original", i)
		}
	}

	if n := len(f.recordedReadLens()); n != 1 {
		t.Errorf("underlying reads = %d, want 1 (both packets came from one message)", n)
	}
}

func TestBufferedBytesDeliveredBeforeStickyError(t *testing.T) {
	payload := []byte("trailing-bytes")
	f := &fakePipe{
		messages:           [][]byte{payload},
		readErr:            io.EOF,
		errWithLastMessage: true,
	}
	c := newTestConn(f)

	got := make([]byte, len(payload))
	n, err := c.Read(got)
	if err != nil {
		t.Fatalf("first Read returned err = %v, want nil (buffered bytes come first)", err)
	}
	if n != len(payload) || string(got[:n]) != string(payload) {
		t.Fatalf("first Read = %q, want %q", got[:n], payload)
	}

	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Errorf("second Read err = %v, want io.EOF", err)
	}
}

// TestReadNeverReturnsZeroNil guards the invariant that makes io.ReadFull safe:
// a (0, nil) return would spin it forever.
func TestReadNeverReturnsZeroNil(t *testing.T) {
	f := &fakePipe{messages: [][]byte{[]byte("abc"), []byte("de")}}
	c := newTestConn(f)

	for i := range 8 {
		n, err := c.Read(make([]byte, 4))
		if err != nil {
			break
		}
		if n == 0 {
			t.Fatalf("Read %d returned (0, nil), which would spin io.ReadFull", i)
		}
	}
}

func TestReadEmptyBufferIsNoop(t *testing.T) {
	f := &fakePipe{messages: [][]byte{[]byte("abc")}}
	c := newTestConn(f)

	n, err := c.Read(nil)
	if n != 0 || err != nil {
		t.Errorf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if got := len(f.recordedReadLens()); got != 0 {
		t.Errorf("Read(nil) issued %d underlying reads, want 0", got)
	}
}

// recorder tracks teardown ordering across the SMB object graph.
type recorder struct {
	mu    sync.Mutex
	order []string
}

func (r *recorder) note(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, s)
}

type fakeShare struct{ r *recorder }

func (s fakeShare) Umount() error { s.r.note("share"); return nil }

type fakeSession struct{ r *recorder }

func (s fakeSession) Logoff() error { s.r.note("session"); return nil }

type fakeRawConn struct {
	net.Conn
	r *recorder
}

func (c fakeRawConn) Close() error { c.r.note("raw"); return nil }

type recordingPipe struct {
	*fakePipe
	r *recorder
}

func (p recordingPipe) Close() error { p.r.note("file"); return p.fakePipe.Close() }

func TestCloseOrderAndIdempotency(t *testing.T) {
	r := &recorder{}
	cancelled := false
	c := newPipeConn(pipeResources{
		file:    recordingPipe{fakePipe: &fakePipe{}, r: r},
		share:   fakeShare{r: r},
		session: fakeSession{r: r},
		raw:     fakeRawConn{r: r},
		cancel:  func() { cancelled = true },
	}, "SQL01", `sql\query`)

	if err := c.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close() = %v, want nil", err)
	}

	want := []string{"file", "share", "session", "raw"}
	if len(r.order) != len(want) {
		t.Fatalf("close order = %v, want %v (second Close must be a no-op)", r.order, want)
	}
	for i := range want {
		if r.order[i] != want[i] {
			t.Errorf("close order = %v, want %v", r.order, want)
			break
		}
	}
	if !cancelled {
		t.Error("Close() did not cancel the connection-scoped context")
	}
}

func TestCloseJoinsErrors(t *testing.T) {
	sentinel := errors.New("umount boom")
	c := newPipeConn(pipeResources{
		file:  &fakePipe{},
		share: errShare{err: sentinel},
	}, "SQL01", `sql\query`)

	err := c.Close()
	if !errors.Is(err, sentinel) {
		t.Errorf("Close() = %v, want it to wrap %v", err, sentinel)
	}
}

type errShare struct{ err error }

func (s errShare) Umount() error { return s.err }

func TestReadDeadlineExceeded(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	f := &fakePipe{messages: [][]byte{[]byte("never-delivered")}, block: block}
	c := newTestConn(f)

	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() = %v", err)
	}

	_, err := c.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("Read() = nil error, want a timeout")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read() err = %v, want a net.Error with Timeout() true", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Read() err = %v, want it to wrap os.ErrDeadlineExceeded", err)
	}

	// A missed deadline poisons the connection: the abandoned SMB response could
	// still arrive and be mistaken for the next reply, so nothing may proceed.
	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Error("Read() after a missed deadline succeeded, want failure (conn is poisoned)")
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Error("Write() after a missed deadline succeeded, want failure (conn is poisoned)")
	}
}

func TestWriteDeadlineExceeded(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	// blockingWriter stalls in Write until released.
	bw := &blockingWriter{block: block}
	c := newPipeConn(pipeResources{file: bw}, "SQL01", `sql\query`)

	if err := c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline() = %v", err)
	}

	_, err := c.Write([]byte("payload"))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Write() err = %v, want a net.Error with Timeout() true", err)
	}
}

type blockingWriter struct{ block chan struct{} }

func (w *blockingWriter) Read([]byte) (int, error) { return 0, io.EOF }
func (w *blockingWriter) Write(b []byte) (int, error) {
	<-w.block
	return len(b), nil
}
func (w *blockingWriter) Close() error { return nil }

func TestWriteForwardsWholePackets(t *testing.T) {
	f := &fakePipe{}
	c := newTestConn(f)

	packet := tdsPacket(0x01, 64)
	n, err := c.Write(packet)
	if err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if n != len(packet) {
		t.Errorf("Write() = %d, want %d", n, len(packet))
	}
	if len(f.writes) != 1 || string(f.writes[0]) != string(packet) {
		t.Errorf("underlying writes = %d, want one whole packet", len(f.writes))
	}
}

func TestAddrsAreNeverNil(t *testing.T) {
	c := newTestConn(&fakePipe{})

	if c.LocalAddr() == nil || c.RemoteAddr() == nil {
		t.Fatal("LocalAddr/RemoteAddr must never be nil: go-mssqldb calls String() on them")
	}
	if got := c.RemoteAddr().Network(); got != "np" {
		t.Errorf("RemoteAddr().Network() = %q, want %q", got, "np")
	}
	if got := c.RemoteAddr().String(); !strings.Contains(got, `\\SQL01\pipe\sql\query`) {
		t.Errorf("RemoteAddr().String() = %q, want it to name the pipe", got)
	}
}

func TestDeadlineSettersAcceptZero(t *testing.T) {
	c := newTestConn(&fakePipe{})
	for _, tc := range []struct {
		name string
		fn   func(time.Time) error
	}{
		{"SetDeadline", c.SetDeadline},
		{"SetReadDeadline", c.SetReadDeadline},
		{"SetWriteDeadline", c.SetWriteDeadline},
	} {
		if err := tc.fn(time.Time{}); err != nil {
			t.Errorf("%s(zero) = %v, want nil", tc.name, err)
		}
	}
}
