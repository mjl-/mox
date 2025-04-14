/*
Package imapclient provides an IMAP4 client implementing IMAP4rev1 (RFC 3501),
IMAP4rev2 (RFC 9051) and various extensions.

Warning: Currently primarily for testing the mox IMAP4 server. Behaviour that
may not be required by the IMAP4 specification may be expected by this client.

See [Conn] for a high-level client for executing IMAP commands. Use its embedded
[Proto] for lower-level writing of commands and reading of responses.
*/
package imapclient

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

// Conn is an connection to an IMAP server.
//
// Method names on Conn are the names of IMAP commands. CloseMailbox, which
// executes the IMAP CLOSE command, is an exception. The Close method closes the
// connection.
//
// The methods starting with MSN are the original (old) IMAP commands. The variants
// starting with UID should almost always be used instead, if available.
//
// The methods on Conn typically return errors of type Error or Response. Error
// represents protocol and i/o level errors, including io.ErrDeadlineExceeded and
// various errors for closed connections. Response is returned as error if the IMAP
// result is NO or BAD instead of OK. The responses returned by the IMAP command
// methods can also be non-zero on errors. Callers may wish to process any untagged
// responses.
//
// The IMAP command methods defined on Conn don't interpret the untagged responses
// except for  untagged CAPABILITY and untagged ENABLED responses, and the
// CAPABILITY response code. Fields CapAvailable and CapEnabled are updated when
// those untagged responses are received.
//
// Capabilities indicate which optional IMAP functionality is supported by a
// server. Capabilities are typically implicitly enabled when the client sends a
// command using syntax of an optional extension. Extensions without new syntax
// from client to server, but with new behaviour or syntax from server to client,
// the client needs to explicitly enable the capability with the ENABLE command,
// see the Enable method.
type Conn struct {
	// If true, server sent a PREAUTH tag and the connection is already authenticated,
	// e.g. based on TLS certificate authentication.
	Preauth bool

	// Capabilities available at server, from CAPABILITY command or response code.
	CapAvailable []Capability
	// Capabilities marked as enabled by the server, typically after an ENABLE command.
	CapEnabled []Capability

	// Proto provides lower-level functions for interacting with the IMAP connection,
	// such as reading and writing individual lines/commands/responses.
	Proto
}

// Proto provides low-level operations for writing requests and reading responses
// on an IMAP connection.
//
// To implement the IDLE command, write "IDLE" using [Proto.WriteCommandf], then
// read a line with [Proto.Readline]. If it starts with "+ ", the connection is in
// idle mode and untagged responses can be read using [Proto.ReadUntagged]. If the
// line doesn't start with "+ ", use [ParseResult] to interpret it as a response to
// IDLE, which should be a NO or BAD. To abort idle mode, write "DONE" using
// [Proto.Writelinef] and wait until a result line has been read.
type Proto struct {
	// Connection, may be original TCP or TLS connection. Reads go through c.br, and
	// writes through c.xbw. The "x" for the writes indicate that failed writes cause
	// an i/o panic, which is either turned into a returned error, or passed on (see
	// boolean panic). The reader and writer wrap a tracing reading/writer and may wrap
	// flate compression.
	conn         net.Conn
	connBroken   bool // If connection is broken, we won't flush (and write) again.
	br           *bufio.Reader
	tr           *moxio.TraceReader
	xbw          *bufio.Writer
	compress     bool // If compression is enabled, we must flush flateWriter and its target original bufio writer.
	xflateWriter *moxio.FlateWriter
	xflateBW     *bufio.Writer
	xtw          *moxio.TraceWriter

	log       mlog.Log
	errHandle func(err error) // If set, called for all errors. Can panic. Used for imapserver tests.
	tagGen    int
	record    bool // If true, bytes read are added to recordBuf. recorded() resets.
	recordBuf []byte

	lastTag string
}

// Error is a parse or other protocol error.
type Error struct{ err error }

func (e Error) Error() string {
	return e.err.Error()
}

func (e Error) Unwrap() error {
	return e.err
}

// Opts has optional fields that influence behaviour of a Conn.
type Opts struct {
	Logger *slog.Logger

	// Error is called for IMAP-level and connection-level errors during the IMAP
	// command methods on Conn, not for errors in calls on Proto. Error is allowed to
	// call panic.
	Error func(err error)
}

// New initializes a new IMAP client on conn.
//
// Conn should normally be a TLS connection, typically connected to port 993 of an
// IMAP server. Alternatively, conn can be a plain TCP connection to port 143. TLS
// should be enabled on plain TCP connections with the [Conn.StartTLS] method.
//
// The initial untagged greeting response is read and must be "OK" or
// "PREAUTH". If preauth, the connection is already in authenticated state,
// typically through TLS client certificate. This is indicated in Conn.Preauth.
//
// Logging is written to opts.Logger. In particular, IMAP protocol traces are
// written with prefixes "CR: " and "CW: " (client read/write) as quoted strings at
// levels Debug-4, with authentication messages at Debug-6 and (user) data at level
// Debug-8.
func New(conn net.Conn, opts *Opts) (client *Conn, rerr error) {
	c := Conn{
		Proto: Proto{conn: conn},
	}

	var clog *slog.Logger
	if opts != nil {
		c.errHandle = opts.Error
		clog = opts.Logger
	} else {
		clog = slog.Default()
	}
	c.log = mlog.New("imapclient", clog)

	c.tr = moxio.NewTraceReader(c.log, "CR: ", &c)
	c.br = bufio.NewReader(c.tr)

	// Writes are buffered and write to Conn, which may panic.
	c.xtw = moxio.NewTraceWriter(c.log, "CW: ", &c)
	c.xbw = bufio.NewWriter(c.xtw)

	defer c.recoverErr(&rerr)
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
		if x.Code != nil {
			if caps, ok := x.Code.(CodeCapability); ok {
				c.CapAvailable = caps
			}
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

func (c *Conn) recoverErr(rerr *error) {
	c.recover(rerr, nil)
}

func (c *Conn) recover(rerr *error, resp *Response) {
	if *rerr != nil {
		if r, ok := (*rerr).(Response); ok && resp != nil {
			*resp = r
		}
		c.errHandle(*rerr)
		return
	}

	x := recover()
	if x == nil {
		return
	}
	var err error
	switch e := x.(type) {
	case Error:
		err = e
	case Response:
		err = e
		if resp != nil {
			*resp = e
		}
	default:
		panic(x)
	}
	if c.errHandle != nil {
		c.errHandle(err)
	}
	*rerr = err
}

func (p *Proto) recover(rerr *error) {
	if *rerr != nil {
		return
	}

	x := recover()
	if x == nil {
		return
	}
	switch e := x.(type) {
	case Error:
		*rerr = e
	default:
		panic(x)
	}
}

func (p *Proto) xerrorf(format string, args ...any) {
	panic(Error{fmt.Errorf(format, args...)})
}

func (p *Proto) xcheckf(err error, format string, args ...any) {
	if err != nil {
		p.xerrorf("%s: %w", fmt.Sprintf(format, args...), err)
	}
}

func (p *Proto) xcheck(err error) {
	if err != nil {
		panic(err)
	}
}

// xresponse sets resp if err is a Response and resp is not nil.
func (p *Proto) xresponse(err error, resp *Response) {
	if err == nil {
		return
	}
	if r, ok := err.(Response); ok && resp != nil {
		*resp = r
	}
	panic(err)
}

// Write writes directly to underlying connection (TCP, TLS). For internal use
// only, to implement io.Writer. Write errors do take the connection's panic mode
// into account, i.e. Write can panic.
func (p *Proto) Write(buf []byte) (n int, rerr error) {
	defer p.recover(&rerr)

	n, rerr = p.conn.Write(buf)
	if rerr != nil {
		p.connBroken = true
	}
	p.xcheckf(rerr, "write")
	return n, nil
}

// Read reads directly from the underlying connection (TCP, TLS). For internal use
// only, to implement io.Reader.
func (p *Proto) Read(buf []byte) (n int, err error) {
	return p.conn.Read(buf)
}

func (p *Proto) xflush() {
	// Not writing any more when connection is broken.
	if p.connBroken {
		return
	}

	err := p.xbw.Flush()
	p.xcheckf(err, "flush")

	// If compression is active, we need to flush the deflate stream.
	if p.compress {
		err := p.xflateWriter.Flush()
		p.xcheckf(err, "flush deflate")
		err = p.xflateBW.Flush()
		p.xcheckf(err, "flush deflate buffer")
	}
}

func (p *Proto) xtraceread(level slog.Level) func() {
	if p.tr == nil {
		// For ParseUntagged and other parse functions.
		return func() {}
	}
	p.tr.SetTrace(level)
	return func() {
		p.tr.SetTrace(mlog.LevelTrace)
	}
}

func (p *Proto) xtracewrite(level slog.Level) func() {
	if p.xtw == nil {
		// For ParseUntagged and other parse functions.
		return func() {}
	}

	p.xflush()
	p.xtw.SetTrace(level)
	return func() {
		p.xflush()
		p.xtw.SetTrace(mlog.LevelTrace)
	}
}

// Close closes the connection, flushing and closing any compression and TLS layer.
//
// You may want to call Logout first. Closing a connection with a mailbox with
// deleted messages not yet expunged will not expunge those messages.
//
// Closing a TLS connection that is logged out, or closing a TLS connection with
// compression enabled (i.e. two layered streams), may cause spurious errors
// because the server may immediate close the underlying connection when it sees
// the connection is being closed.
func (c *Conn) Close() (rerr error) {
	defer c.recoverErr(&rerr)

	if c.conn == nil {
		return nil
	}
	if !c.connBroken && c.xflateWriter != nil {
		err := c.xflateWriter.Close()
		c.xcheckf(err, "close deflate writer")
		err = c.xflateBW.Flush()
		c.xcheckf(err, "flush deflate buffer")
		c.xflateWriter = nil
		c.xflateBW = nil
	}
	err := c.conn.Close()
	c.xcheckf(err, "close connection")
	c.conn = nil
	return
}

// TLSConnectionState returns the TLS connection state if the connection uses TLS,
// either because the conn passed to [New] was a TLS connection, or because
// [Conn.StartTLS] was called.
func (c *Conn) TLSConnectionState() *tls.ConnectionState {
	if conn, ok := c.conn.(*tls.Conn); ok {
		cs := conn.ConnectionState()
		return &cs
	}
	return nil
}

// WriteCommandf writes a free-form IMAP command to the server. An ending \r\n is
// written too.
//
// If tag is empty, a next unique tag is assigned.
func (p *Proto) WriteCommandf(tag string, format string, args ...any) (rerr error) {
	defer p.recover(&rerr)

	if tag == "" {
		p.nextTag()
	} else {
		p.lastTag = tag
	}

	fmt.Fprintf(p.xbw, "%s %s\r\n", p.lastTag, fmt.Sprintf(format, args...))
	p.xflush()
	return
}

func (p *Proto) nextTag() string {
	p.tagGen++
	p.lastTag = fmt.Sprintf("x%03d", p.tagGen)
	return p.lastTag
}

// LastTag returns the tag last used for a command. For checking against a command
// completion result.
func (p *Proto) LastTag() string {
	return p.lastTag
}

// LastTagSet sets a new last tag, as used for checking against a command completion result.
func (p *Proto) LastTagSet(tag string) {
	p.lastTag = tag
}

// ReadResponse reads from the IMAP server until a tagged response line is found.
// The tag must be the same as the tag for the last written command.
//
// If an error is returned, resp can still be non-empty, and a caller may wish to
// process resp.Untagged.
//
// Caller should check resp.Status for the result of the command too.
//
// Common types for the return error:
// - Error, for protocol errors
// - Various I/O errors from the underlying connection, including os.ErrDeadlineExceeded
func (p *Proto) ReadResponse() (resp Response, rerr error) {
	defer p.recover(&rerr)

	for {
		tag := p.xnonspace()
		p.xspace()
		if tag == "*" {
			resp.Untagged = append(resp.Untagged, p.xuntagged())
			continue
		}

		if tag != p.lastTag {
			p.xerrorf("got tag %q, expected %q", tag, p.lastTag)
		}

		status := p.xstatus()
		p.xspace()
		resp.Result = p.xresult(status)
		p.xcrlf()
		return
	}
}

// ParseCode parses a response code. The string must not have enclosing brackets.
//
// Example:
//
//	"APPENDUID 123 10"
func ParseCode(s string) (code Code, rerr error) {
	p := Proto{br: bufio.NewReader(strings.NewReader(s + "]"))}
	defer p.recover(&rerr)
	code = p.xrespCode()
	p.xtake("]")
	buf, err := io.ReadAll(p.br)
	p.xcheckf(err, "read")
	if len(buf) != 0 {
		p.xerrorf("leftover data %q", buf)
	}
	return code, nil
}

// ParseResult parses a line, including required crlf, as a command result line.
//
// Example:
//
//	"tag1 OK [APPENDUID 123 10] message added\r\n"
func ParseResult(s string) (tag string, result Result, rerr error) {
	p := Proto{br: bufio.NewReader(strings.NewReader(s))}
	defer p.recover(&rerr)
	tag = p.xnonspace()
	p.xspace()
	status := p.xstatus()
	p.xspace()
	result = p.xresult(status)
	p.xcrlf()
	return
}

// ReadUntagged reads a single untagged response line.
func (p *Proto) ReadUntagged() (untagged Untagged, rerr error) {
	defer p.recover(&rerr)
	return p.readUntagged()
}

// ParseUntagged parses a line, including required crlf, as untagged response.
//
// Example:
//
//	"* BYE shutting down connection\r\n"
func ParseUntagged(s string) (untagged Untagged, rerr error) {
	p := Proto{br: bufio.NewReader(strings.NewReader(s))}
	defer p.recover(&rerr)
	untagged, rerr = p.readUntagged()
	return
}

func (p *Proto) readUntagged() (untagged Untagged, rerr error) {
	defer p.recover(&rerr)
	tag := p.xnonspace()
	if tag != "*" {
		p.xerrorf("got tag %q, expected untagged", tag)
	}
	p.xspace()
	ut := p.xuntagged()
	return ut, nil
}

// Readline reads a line, including CRLF.
// Used with IDLE and synchronous literals.
func (p *Proto) Readline() (line string, rerr error) {
	defer p.recover(&rerr)

	line, err := p.br.ReadString('\n')
	p.xcheckf(err, "read line")
	return line, nil
}

func (c *Conn) readContinuation() (line string, rerr error) {
	defer c.recover(&rerr, nil)
	line, rerr = c.ReadContinuation()
	if rerr != nil {
		if resp, ok := rerr.(Response); ok {
			c.processUntagged(resp.Untagged)
			c.processResult(resp.Result)
		}
	}
	return
}

// ReadContinuation reads a line. If it is a continuation, i.e. starts with "+", it
// is returned without leading "+ " and without trailing crlf. Otherwise, an error
// is returned, which can be a Response with Untagged that a caller may wish to
// process. A successfully read continuation can return an empty line.
func (p *Proto) ReadContinuation() (line string, rerr error) {
	defer p.recover(&rerr)

	if !p.peek('+') {
		var resp Response
		resp, rerr = p.ReadResponse()
		if rerr == nil {
			rerr = resp
		}
		return "", rerr
	}
	p.xtake("+ ")
	line, err := p.Readline()
	p.xcheckf(err, "read line")
	line = strings.TrimSuffix(line, "\r\n")
	return
}

// Writelinef writes the formatted format and args as a single line, adding CRLF.
// Used with IDLE and synchronous literals.
func (p *Proto) Writelinef(format string, args ...any) (rerr error) {
	defer p.recover(&rerr)

	s := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.xbw, "%s\r\n", s)
	p.xflush()
	return nil
}

// WriteSyncLiteral first writes the synchronous literal size, then reads the
// continuation "+" and finally writes the data. If the literal is not accepted, an
// error is returned, which may be a Response.
func (p *Proto) WriteSyncLiteral(s string) (rerr error) {
	defer p.recover(&rerr)

	fmt.Fprintf(p.xbw, "{%d}\r\n", len(s))
	p.xflush()

	plus, err := p.br.Peek(1)
	p.xcheckf(err, "read continuation")
	if plus[0] == '+' {
		_, err = p.Readline()
		p.xcheckf(err, "read continuation line")

		defer p.xtracewrite(mlog.LevelTracedata)()
		_, err = p.xbw.Write([]byte(s))
		p.xcheckf(err, "write literal data")
		p.xtracewrite(mlog.LevelTrace)
		return nil
	}
	var resp Response
	resp, rerr = p.ReadResponse()
	if rerr == nil {
		rerr = resp
	}
	return
}

func (c *Conn) processUntagged(l []Untagged) {
	for _, ut := range l {
		switch e := ut.(type) {
		case UntaggedCapability:
			c.CapAvailable = []Capability(e)
		case UntaggedEnabled:
			c.CapEnabled = append(c.CapEnabled, e...)
		}
	}
}

func (c *Conn) processResult(r Result) {
	if r.Code == nil {
		return
	}
	switch e := r.Code.(type) {
	case CodeCapability:
		c.CapAvailable = []Capability(e)
	}
}

// transactf writes format and args as an IMAP command, using Commandf with an
// empty tag. I.e. format must not contain a tag. Transactf then reads a response
// using ReadResponse and checks the result status is OK.
func (c *Conn) transactf(format string, args ...any) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	err := c.WriteCommandf("", format, args...)
	if err != nil {
		return Response{}, err
	}

	return c.responseOK()
}

func (c *Conn) responseOK() (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	resp, rerr = c.ReadResponse()
	c.processUntagged(resp.Untagged)
	c.processResult(resp.Result)
	if rerr == nil && resp.Status != OK {
		rerr = resp
	}
	return
}
