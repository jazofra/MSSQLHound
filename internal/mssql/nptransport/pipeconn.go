package nptransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// readBufSize is the size of the internal read buffer, and it is the single most
// important constant in this package. See pipeConn.Read for the full reasoning.
//
// 64 KiB is chosen because it sits above two ceilings at once:
//   - the maximum TDS packet size go-mssqldb will negotiate (32767 bytes, see
//     go-mssqldb tds.go), and
//   - the default TDS packet size (4096 bytes).
//
// It is also exactly cloudsoda/go-smb2's singleCreditMaxPayloadSize, so a read of
// this size is still serviced as a single SMB2 READ even when the server does not
// grant SMB2_GLOBAL_CAP_LARGE_MTU.
const readBufSize = 64 * 1024

// pipeResources bundles the SMB objects that must be torn down when the
// connection closes. Each field is an interface rather than a concrete
// cloudsoda/go-smb2 type so that tests can substitute fakes without an SMB server.
// Any field may be nil; Close skips nil entries.
type pipeResources struct {
	file    io.ReadWriteCloser // the opened named pipe on IPC$
	share   umounter           // the mounted IPC$ share
	session logoffer           // the authenticated SMB session
	raw     net.Conn           // the underlying TCP (or SOCKS5) connection to :445
	cancel  context.CancelFunc // cancels the connection-scoped context
}

type umounter interface{ Umount() error }
type logoffer interface{ Logoff() error }

// pipeConn adapts an SMB named pipe to net.Conn so that go-mssqldb can drive a
// normal TDS session over it.
//
// Two behaviours here are load-bearing and must not be "simplified" away:
//
//  1. Reads are always issued against the full internal buffer, never against the
//     caller's buffer (see Read).
//  2. Deadlines are implemented for real rather than being accepted and ignored
//     (see readWithDeadline).
type pipeConn struct {
	res    pipeResources
	local  net.Addr
	remote net.Addr

	// Read state, guarded by rmu. rbuf holds bytes fetched from the pipe but not
	// yet handed to the caller; the valid window is rbuf[rOff:rLen].
	rmu  sync.Mutex
	rbuf []byte
	rOff int
	rLen int
	// rErr is sticky. It is recorded when the underlying pipe returns an error
	// alongside buffered bytes, and is only surfaced once those bytes have been
	// drained, so that a final short read followed by io.EOF is not lost.
	rErr error

	wmu sync.Mutex

	// dmu guards the deadline fields, which callers may set from another
	// goroutine while a Read or Write is in flight.
	dmu sync.Mutex
	rdl time.Time
	wdl time.Time

	// poisoned marks the connection as unusable. A timed-out SMB read cannot be
	// abandoned safely: the response may still arrive and would be mistaken for
	// the answer to the next request, desynchronising the TDS stream. Once a
	// deadline is missed the only correct action is to fail every subsequent
	// operation.
	poisoned atomic.Bool

	closeOnce sync.Once
	closeErr  error
}

// newPipeConn wraps an opened named pipe and its owning SMB resources in a net.Conn.
func newPipeConn(res pipeResources, host, pipePath string) *pipeConn {
	return &pipeConn{
		res:    res,
		rbuf:   make([]byte, readBufSize),
		local:  pipeAddr{addr: "np:local"},
		remote: pipeAddr{addr: fmt.Sprintf(`\\%s\pipe\%s`, host, pipePath)},
	}
}

// Read implements io.Reader.
//
// THE CORE INVARIANT: the underlying pipe is always read into the full rbuf,
// never directly into b.
//
// go-mssqldb begins every TDS packet by reading an 8-byte header:
//
//	buf := r.rbuf[:headerSize]
//	_, err := io.ReadFull(r.transport, buf)   // go-mssqldb buf.go, readNextPacket
//
// If that 8-byte request were forwarded to the pipe as an 8-byte SMB2 READ, a
// message-mode pipe holding a whole TDS packet would answer STATUS_BUFFER_OVERFLOW
// with the partial payload attached. cloudsoda/go-smb2 discards that payload:
//
//	case smb2.SMB2_READ:
//	    if status == erref.STATUS_BUFFER_OVERFLOW {
//	        return nil, &ResponseError{Code: uint32(status)}   // conn.go — p.Data() dropped
//	    }
//
// (Contrast the SMB2_IOCTL case immediately above it, which deliberately returns
// p.Data() alongside the error.) Those bytes are consumed from the pipe and are
// unrecoverable, so the TDS stream would desynchronise on the very first packet of
// every connection — not intermittently, but always.
//
// Reading into the full 64 KiB buffer means a whole pipe message always fits, the
// READ completes with STATUS_SUCCESS and a short count, and the caller's small
// reads are served from memory. This mirrors impacket's _recv_buf in its
// named-pipe TDS transport.
func (c *pipeConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.poisoned.Load() {
		return 0, errPoisoned
	}

	c.rmu.Lock()
	defer c.rmu.Unlock()

	if c.rOff == c.rLen {
		// Buffer drained. Surface a previously recorded error now, not before.
		if c.rErr != nil {
			return 0, c.rErr
		}
		c.rOff, c.rLen = 0, 0

		n, err := c.readWithDeadline(c.rbuf)
		if n > 0 {
			c.rLen = n
		}
		if err != nil {
			if n == 0 {
				return 0, err
			}
			// Bytes arrived alongside the error (a final short read before EOF).
			// Hand those over first; the error keeps until the next call.
			c.rErr = err
		}
	}

	n := copy(b, c.rbuf[c.rOff:c.rLen])
	c.rOff += n
	// Returning (0, nil) here would spin io.ReadFull forever. It cannot happen:
	// len(b) > 0 was checked above, and rOff < rLen is guaranteed because a read
	// that produced no bytes returned its error directly.
	return n, nil
}

// Write implements io.Writer. go-mssqldb emits exactly one whole TDS packet per
// Write (see tdsBuffer.FinishPacket), which maps cleanly onto one pipe message.
func (c *pipeConn) Write(b []byte) (int, error) {
	if c.poisoned.Load() {
		return 0, errPoisoned
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

	deadline := c.writeDeadline()
	if deadline.IsZero() {
		return c.res.file.Write(b)
	}

	type result struct {
		n   int
		err error
	}
	// Buffered so the worker never blocks if we have already given up on it.
	done := make(chan result, 1)
	go func() {
		n, err := c.res.file.Write(b)
		done <- result{n, err}
	}()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case r := <-done:
		return r.n, r.err
	case <-timer.C:
		c.poisoned.Store(true)
		return 0, newTimeoutError("write")
	}
}

// readWithDeadline performs one read against the underlying pipe, honouring any
// read deadline currently set. Callers must hold rmu.
func (c *pipeConn) readWithDeadline(buf []byte) (int, error) {
	deadline := c.readDeadline()
	if deadline.IsZero() {
		// Common case: no deadline in play, so no goroutine and no timer.
		return c.res.file.Read(buf)
	}

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		// Reads into buf (which is c.rbuf) even if we abandon it below. That is
		// safe: abandoning sets poisoned, after which no code path ever reads
		// rbuf again, and Close unblocks this goroutine by closing the pipe.
		n, err := c.res.file.Read(buf)
		done <- result{n, err}
	}()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case r := <-done:
		return r.n, r.err
	case <-timer.C:
		c.poisoned.Store(true)
		return 0, newTimeoutError("read")
	}
}

func (c *pipeConn) readDeadline() time.Time {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	return c.rdl
}

func (c *pipeConn) writeDeadline() time.Time {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	return c.wdl
}

// Close tears down the pipe and everything beneath it, innermost first, and is
// safe to call more than once. Errors from every layer are joined rather than
// short-circuited so that a failure partway down still releases the rest.
func (c *pipeConn) Close() error {
	c.closeOnce.Do(func() {
		var errs []error
		if c.res.file != nil {
			errs = append(errs, c.res.file.Close())
		}
		if c.res.share != nil {
			errs = append(errs, c.res.share.Umount())
		}
		if c.res.session != nil {
			errs = append(errs, c.res.session.Logoff())
		}
		if c.res.raw != nil {
			errs = append(errs, c.res.raw.Close())
		}
		if c.res.cancel != nil {
			c.res.cancel()
		}
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.local }
func (c *pipeConn) RemoteAddr() net.Addr { return c.remote }

func (c *pipeConn) SetDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.rdl, c.wdl = t, t
	return nil
}

func (c *pipeConn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.rdl = t
	return nil
}

func (c *pipeConn) SetWriteDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.wdl = t
	return nil
}

// pipeAddr is a net.Addr describing a named pipe. go-mssqldb forwards LocalAddr
// and RemoteAddr to callers that may call String() on them, so neither may be nil.
type pipeAddr struct{ addr string }

func (pipeAddr) Network() string  { return "np" }
func (a pipeAddr) String() string { return a.addr }

// errPoisoned is returned by every operation on a connection whose deadline was
// missed. It reports itself as a timeout so that callers treating net.Error
// specially continue to do the right thing.
var errPoisoned = newTimeoutError("connection")

// timeoutError satisfies net.Error with Timeout() true, and unwraps to
// os.ErrDeadlineExceeded so errors.Is works the way callers expect.
type timeoutError struct{ op string }

func newTimeoutError(op string) *timeoutError { return &timeoutError{op: op} }

func (e *timeoutError) Error() string {
	return fmt.Sprintf("named pipe %s: %v", e.op, os.ErrDeadlineExceeded)
}
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return false }
func (e *timeoutError) Unwrap() error   { return os.ErrDeadlineExceeded }

// Compile-time proof that the adapter really is a net.Conn.
var _ net.Conn = (*pipeConn)(nil)
var _ net.Error = (*timeoutError)(nil)
