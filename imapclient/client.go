/*
Package imapclient provides an IMAP4 client, primarily for testing the IMAP4 server.

Commands can be sent to the server free-form, but responses are parsed strictly.
Behaviour that may not be required by the IMAP4 specification may be expected by
this client.
*/
package imapclient

/*
- Try to keep the parsing method names and the types similar to the ABNF names in the RFCs.

- todo: have mode for imap4rev1 vs imap4rev2, refusing what is not allowed. we are accepting too much now.
- todo: stricter parsing. xnonspace() and xword() should be replaced by proper parsers.
*/

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

// Conn is an IMAP connection to a server.
type Conn struct {
	// Connection, may be original TCP or TLS connection. Reads go through c.br, and
	// writes through c.bw. It wraps a tracing reading/writer and may wrap flate
	// compression.
	conn        net.Conn
	connBroken  bool // If connection is broken, we won't flush (and write) again.
	br          *bufio.Reader
	bw          *bufio.Writer
	compress    bool // If compression is enabled, we must flush flateWriter and its target original bufio writer.
	flateWriter *moxio.FlateWriter
	flateBW     *bufio.Writer

	log       mlog.Log
	panic     bool
	tagGen    int
	record    bool // If true, bytes read are added to recordBuf. recorded() resets.
	recordBuf []byte

	Preauth      bool
	LastTag      string
	CapAvailable map[Capability]struct{} // Capabilities available at server, from CAPABILITY command or response code. All uppercase.
	CapEnabled   map[Capability]struct{} // Capabilities enabled through ENABLE command. All uppercase.
}

// Error is a parse or other protocol error.
type Error struct{ err error }

func (e Error) Error() string {
	return e.err.Error()
}

func (e Error) Unwrap() error {
	return e.err
}

// New creates a new client on conn.
//
// If xpanic is true, functions that would return an error instead panic. For parse
// errors, the resulting stack traces show typically show what was being parsed.
//
// The initial untagged greeting response is read and must be "OK" or
// "PREAUTH". If preauth, the connection is already in authenticated state,
// typically through TLS client certificate. This is indicated in Conn.Preauth.
func New(cid int64, conn net.Conn, xpanic bool) (client *Conn, rerr error) {
	log := mlog.New("imapclient", nil).WithCid(cid)
	c := Conn{
		conn:         conn,
		br:           bufio.NewReader(moxio.NewTraceReader(log, "CR: ", conn)),
		log:          log,
		panic:        xpanic,
		CapAvailable: map[Capability]struct{}{},
		CapEnabled:   map[Capability]struct{}{},
	}
	// Writes are buffered and write to Conn, which may panic.
	c.bw = bufio.NewWriter(moxio.NewTraceWriter(log, "CW: ", &c))

	defer c.recover(&rerr)
	tag := c.xnonspace()
	if tag != "*" {
		c.xerrorf("expected untagged *, got %q", tag)
	}
	c.xspace()
	ut := c.xuntagged()
	switch x := ut.(type) {
	case UntaggedResult:
		if x.Status != OK {
			c.xerrorf("greeting, got status %q, expected OK", x.Status)
		}
		return &c, nil
	case UntaggedPreauth:
		c.Preauth = true
		return &c, nil
	case UntaggedBye:
		c.xerrorf("greeting: server sent bye")
	default:
		c.xerrorf("unexpected untagged %v", ut)
	}
	panic("not reached")
}

func (c *Conn) recover(rerr *error) {
	if c.panic {
		return
	}

	x := recover()
	if x == nil {
		return
	}
	err, ok := x.(Error)
	if !ok {
		panic(x)
	}
	*rerr = err
}

func (c *Conn) xerrorf(format string, args ...any) {
	panic(Error{fmt.Errorf(format, args...)})
}

func (c *Conn) xcheckf(err error, format string, args ...any) {
	if err != nil {
		c.xerrorf("%s: %w", fmt.Sprintf(format, args...), err)
	}
}

func (c *Conn) xcheck(err error) {
	if err != nil {
		panic(err)
	}
}

// Write writes directly to the connection. Write errors do take the connection's
// panic mode into account, i.e. Write can panic.
func (c *Conn) Write(buf []byte) (n int, rerr error) {
	defer c.recover(&rerr)

	n, rerr = c.conn.Write(buf)
	if rerr != nil {
		c.connBroken = true
	}
	c.xcheckf(rerr, "write")
	return n, nil
}

func (c *Conn) xflush() {
	// Not writing any more when connection is broken.
	if c.connBroken {
		return
	}

	err := c.bw.Flush()
	c.xcheckf(err, "flush")

	// If compression is active, we need to flush the deflate stream.
	if c.compress {
		err := c.flateWriter.Flush()
		c.xcheckf(err, "flush deflate")
		err = c.flateBW.Flush()
		c.xcheckf(err, "flush deflate buffer")
	}
}

// Close closes the connection, flushing and closing any compression and TLS layer.
//
// You may want to call Logout first. Closing a connection with a mailbox with
// deleted messages not yet expunged will not expunge those messages.
func (c *Conn) Close() (rerr error) {
	defer c.recover(&rerr)

	if c.conn == nil {
		return nil
	}
	if !c.connBroken && c.flateWriter != nil {
		err := c.flateWriter.Close()
		c.xcheckf(err, "close deflate writer")
		err = c.flateBW.Flush()
		c.xcheckf(err, "flush deflate buffer")
		c.flateWriter = nil
		c.flateBW = nil
	}
	err := c.conn.Close()
	c.xcheckf(err, "close connection")
	c.conn = nil
	return
}

// TLSConnectionState returns the TLS connection state if the connection uses TLS.
func (c *Conn) TLSConnectionState() *tls.ConnectionState {
	if conn, ok := c.conn.(*tls.Conn); ok {
		cs := conn.ConnectionState()
		return &cs
	}
	return nil
}

// Commandf writes a free-form IMAP command to the server. An ending \r\n is
// written too.
// If tag is empty, a next unique tag is assigned.
func (c *Conn) Commandf(tag string, format string, args ...any) (rerr error) {
	defer c.recover(&rerr)

	if tag == "" {
		tag = c.nextTag()
	}
	c.LastTag = tag

	_, err := fmt.Fprintf(c.bw, "%s %s\r\n", tag, fmt.Sprintf(format, args...))
	c.xcheckf(err, "write command")
	c.xflush()
	return
}

func (c *Conn) nextTag() string {
	c.tagGen++
	return fmt.Sprintf("x%03d", c.tagGen)
}

// Response reads from the IMAP server until a tagged response line is found.
// The tag must be the same as the tag for the last written command.
// Result holds the status of the command. The caller must check if this the status is OK.
func (c *Conn) Response() (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)

	for {
		tag := c.xnonspace()
		c.xspace()
		if tag == "*" {
			untagged = append(untagged, c.xuntagged())
			continue
		}

		if tag != c.LastTag {
			c.xerrorf("got tag %q, expected %q", tag, c.LastTag)
		}

		status := c.xstatus()
		c.xspace()
		result = c.xresult(status)
		c.xcrlf()
		return
	}
}

// ReadUntagged reads a single untagged response line.
// Useful for reading lines from IDLE.
func (c *Conn) ReadUntagged() (untagged Untagged, rerr error) {
	defer c.recover(&rerr)

	tag := c.xnonspace()
	if tag != "*" {
		c.xerrorf("got tag %q, expected untagged", tag)
	}
	c.xspace()
	ut := c.xuntagged()
	return ut, nil
}

// Readline reads a line, including CRLF.
// Used with IDLE and synchronous literals.
func (c *Conn) Readline() (line string, rerr error) {
	defer c.recover(&rerr)

	line, err := c.br.ReadString('\n')
	c.xcheckf(err, "read line")
	return line, nil
}

// ReadContinuation reads a line. If it is a continuation, i.e. starts with a +, it
// is returned without leading "+ " and without trailing crlf. Otherwise, a command
// response is returned. A successfully read continuation can return an empty line.
// Callers should check rerr and result.Status being empty to check if a
// continuation was read.
func (c *Conn) ReadContinuation() (line string, untagged []Untagged, result Result, rerr error) {
	if !c.peek('+') {
		untagged, result, rerr = c.Response()
		c.xcheckf(rerr, "reading non-continuation response")
		c.xerrorf("response status %q, expected OK", result.Status)
	}
	c.xtake("+ ")
	line, err := c.Readline()
	c.xcheckf(err, "read line")
	line = strings.TrimSuffix(line, "\r\n")
	return
}

// Writelinef writes the formatted format and args as a single line, adding CRLF.
// Used with IDLE and synchronous literals.
func (c *Conn) Writelinef(format string, args ...any) (rerr error) {
	defer c.recover(&rerr)

	s := fmt.Sprintf(format, args...)
	_, err := fmt.Fprintf(c.bw, "%s\r\n", s)
	c.xcheckf(err, "writeline")
	c.xflush()
	return nil
}

// WriteSyncLiteral first writes the synchronous literal size, then reads the
// continuation "+" and finally writes the data.
func (c *Conn) WriteSyncLiteral(s string) (untagged []Untagged, rerr error) {
	defer c.recover(&rerr)

	_, err := fmt.Fprintf(c.bw, "{%d}\r\n", len(s))
	c.xcheckf(err, "write sync literal size")
	c.xflush()

	plus, err := c.br.Peek(1)
	c.xcheckf(err, "read continuation")
	if plus[0] == '+' {
		_, err = c.Readline()
		c.xcheckf(err, "read continuation line")

		_, err = c.bw.Write([]byte(s))
		c.xcheckf(err, "write literal data")
		c.xflush()
		return nil, nil
	}
	untagged, result, err := c.Response()
	if err == nil && result.Status == OK {
		c.xerrorf("no continuation, but invalid ok response (%q)", result.More)
	}
	return untagged, fmt.Errorf("no continuation (%s)", result.Status)
}

// Transactf writes format and args as an IMAP command, using Commandf with an
// empty tag. I.e. format must not contain a tag. Transactf then reads a response
// using ReadResponse and checks the result status is OK.
func (c *Conn) Transactf(format string, args ...any) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)

	err := c.Commandf("", format, args...)
	if err != nil {
		return nil, Result{}, err
	}
	return c.ResponseOK()
}

func (c *Conn) ResponseOK() (untagged []Untagged, result Result, rerr error) {
	untagged, result, rerr = c.Response()
	if rerr != nil {
		return nil, Result{}, rerr
	}
	if result.Status != OK {
		c.xerrorf("response status %q, expected OK", result.Status)
	}
	return untagged, result, rerr
}

func (c *Conn) xgetUntagged(l []Untagged, dst any) {
	if len(l) != 1 {
		c.xerrorf("got %d untagged, expected 1: %v", len(l), l)
	}
	got := l[0]
	gotv := reflect.ValueOf(got)
	dstv := reflect.ValueOf(dst)
	if gotv.Type() != dstv.Type().Elem() {
		c.xerrorf("got %v, expected %v", gotv.Type(), dstv.Type().Elem())
	}
	dstv.Elem().Set(gotv)
}
