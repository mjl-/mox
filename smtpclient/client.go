// Package smtpclient is an SMTP client, used by the queue for sending outgoing messages.
package smtpclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtp"
)

// todo future: add function to deliver message to multiple recipients. requires more elaborate return value, indicating success per message: some recipients may succeed, others may fail, and we should still deliver. to prevent backscatter, we also sometimes don't allow multiple recipients. ../rfc/5321:1144

var (
	metricCommands = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_smtpclient_command_duration_seconds",
			Help:    "SMTP client command duration and result codes in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30, 60, 120},
		},
		[]string{
			"cmd",
			"code",
			"secode",
		},
	)
)

var (
	ErrSize                = errors.New("message too large for remote smtp server") // SMTP server announced a maximum message size and the message to be delivered exceeds it.
	Err8bitmimeUnsupported = errors.New("remote smtp server does not implement 8bitmime extension, required by message")
	ErrSMTPUTF8Unsupported = errors.New("remote smtp server does not implement smtputf8 extension, required by message")
	ErrStatus              = errors.New("remote smtp server sent unexpected response status code") // Relatively common, e.g. when a 250 OK was expected and server sent 451 temporary error.
	ErrProtocol            = errors.New("smtp protocol error")                                     // After a malformed SMTP response or inconsistent multi-line response.
	ErrTLS                 = errors.New("tls error")                                               // E.g. handshake failure, or hostname validation was required and failed.
	ErrBotched             = errors.New("smtp connection is botched")                              // Set on a client, and returned for new operations, after an i/o error or malformed SMTP response.
	ErrClosed              = errors.New("client is closed")
)

// TLSMode indicates if TLS must, should or must not be used.
type TLSMode string

const (
	// TLS with STARTTLS for MX SMTP servers, with validated certificate is required: matching name, not expired, trusted by CA.
	TLSStrictStartTLS TLSMode = "strictstarttls"

	// TLS immediately ("implicit TLS"), with validated certificate is required: matching name, not expired, trusted by CA.
	TLSStrictImmediate TLSMode = "strictimmediate"

	// Use TLS if remote claims to support it, but do not validate the certificate
	// (not trusted by CA, different host name or expired certificate is accepted).
	TLSOpportunistic TLSMode = "opportunistic"

	// TLS must not be attempted, e.g. due to earlier TLS handshake error.
	TLSSkip TLSMode = "skip"
)

// Client is an SMTP client that can deliver messages to a mail server.
//
// Use New to make a new client.
type Client struct {
	// OrigConn is the original (TCP) connection. We'll read from/write to conn, which
	// can be wrapped in a tls.Client. We close origConn instead of conn because
	// closing the TLS connection would send a TLS close notification, which may block
	// for 5s if the server isn't reading it (because it is also sending it).
	origConn net.Conn
	conn     net.Conn

	r        *bufio.Reader
	w        *bufio.Writer
	tr       *moxio.TraceReader // Kept for changing trace levels between cmd/auth/data.
	tw       *moxio.TraceWriter
	log      *mlog.Log
	lastlog  time.Time // For adding delta timestamps between log lines.
	cmds     []string  // Last or active command, for generating errors and metrics.
	cmdStart time.Time // Start of command.

	botched  bool // If set, protocol is out of sync and no further commands can be sent.
	needRset bool // If set, a new delivery requires an RSET command.

	extEcodes         bool // Remote server supports sending extended error codes.
	extStartTLS       bool // Remote server supports STARTTLS.
	ext8bitmime       bool
	extSize           bool     // Remote server supports SIZE parameter.
	maxSize           int64    // Max size of email message.
	extPipelining     bool     // Remote server supports command pipelining.
	extSMTPUTF8       bool     // Remote server supports SMTPUTF8 extension.
	extAuthMechanisms []string // Supported authentication mechanisms.
}

// Error represents a failure to deliver a message.
//
// Code, Secode, Command and Line are only set for SMTP-level errors, and are zero
// values otherwise.
type Error struct {
	// Whether failure is permanent, typically because of 5xx response.
	Permanent bool
	// SMTP response status, e.g. 2xx for success, 4xx for transient error and 5xx for
	// permanent failure.
	Code int
	// Short enhanced status, minus first digit and dot. Can be empty, e.g. for io
	// errors or if remote does not send enhanced status codes. If remote responds with
	// "550 5.7.1 ...", the Secode will be "7.1".
	Secode string
	// SMTP command causing failure.
	Command string
	// For errors due to SMTP responses, the full SMTP line excluding CRLF that caused
	// the error. Typically the last line read.
	Line string
	// Underlying error, e.g. one of the Err variables in this package, or io errors.
	Err error
}

// Unwrap returns the underlying Err.
func (e Error) Unwrap() error {
	return e.Err
}

// Error returns a readable error string.
func (e Error) Error() string {
	s := ""
	if e.Err != nil {
		s = e.Err.Error() + ", "
	}
	if e.Permanent {
		s += "permanent"
	} else {
		s += "transient"
	}
	if e.Line != "" {
		s += ": " + e.Line
	}
	return s
}

// New initializes an SMTP session on the given connection, returning a client that
// can be used to deliver messages.
//
// New optionally starts TLS (for submission), reads the server greeting,
// identifies itself with a HELO or EHLO command, initializes TLS with STARTTLS if
// remote supports it and optionally authenticates. If successful, a client is
// returned on which eventually Close must be called. Otherwise an error is
// returned and the caller is responsible for closing the connection.
//
// Connecting to the correct host is outside the scope of the client. The queue
// managing outgoing messages decides which host to deliver to, taking multiple MX
// records with preferences, other DNS records, MTA-STS, retries and special
// cases into account.
//
// tlsMode indicates if TLS is required, optional or should not be used. A
// certificate is only validated (trusted, match remoteHostname and not expired)
// for the strict tls modes. By default, SMTP does not verify TLS for
// interopability reasons, but MTA-STS or DANE can require it. If opportunistic TLS
// is used, and a TLS error is encountered, the caller may want to try again (on a
// new connection) without TLS.
//
// If auth is non-empty, authentication will be done with the first algorithm
// supported by the server. If none of the algorithms are supported, an error is
// returned.
func New(ctx context.Context, log *mlog.Log, conn net.Conn, tlsMode TLSMode, ourHostname, remoteHostname dns.Domain, auth []sasl.Client) (*Client, error) {
	c := &Client{
		origConn: conn,
		lastlog:  time.Now(),
		cmds:     []string{"(none)"},
	}
	c.log = log.Fields(mlog.Field("smtpclient", "")).MoreFields(func() []mlog.Pair {
		now := time.Now()
		l := []mlog.Pair{
			mlog.Field("delta", now.Sub(c.lastlog)),
		}
		c.lastlog = now
		return l
	})

	if tlsMode == TLSStrictImmediate {
		tlsconfig := tls.Config{
			ServerName: remoteHostname.ASCII,
			RootCAs:    mox.Conf.Static.TLS.CertPool,
			MinVersion: tls.VersionTLS12, // ../rfc/8996:31 ../rfc/8997:66
		}
		tlsconn := tls.Client(conn, &tlsconfig)
		if err := tlsconn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		c.conn = tlsconn
		tlsversion, ciphersuite := mox.TLSInfo(tlsconn)
		c.log.Debug("tls client handshake done", mlog.Field("tls", tlsversion), mlog.Field("ciphersuite", ciphersuite), mlog.Field("servername", remoteHostname))
	} else {
		c.conn = conn
	}

	// We don't wrap reads in a timeoutReader for fear of an optional TLS wrapper doing
	// reads without the client asking for it. Such reads could result in a timeout
	// error.
	c.tr = moxio.NewTraceReader(c.log, "RS: ", c.conn)
	c.r = bufio.NewReader(c.tr)
	// We use a single write timeout of 30 seconds.
	// todo future: use different timeouts ../rfc/5321:3610
	c.tw = moxio.NewTraceWriter(c.log, "LC: ", timeoutWriter{c.conn, 30 * time.Second, c.log})
	c.w = bufio.NewWriter(c.tw)

	if err := c.hello(ctx, tlsMode, ourHostname, remoteHostname, auth); err != nil {
		return nil, err
	}
	return c, nil
}

// xbotchf generates a temporary error and marks the client as botched. e.g. for
// i/o errors or invalid protocol messages.
func (c *Client) xbotchf(code int, secode string, lastLine, format string, args ...any) {
	panic(c.botchf(code, secode, lastLine, format, args...))
}

// botchf generates a temporary error and marks the client as botched. e.g. for
// i/o errors or invalid protocol messages.
func (c *Client) botchf(code int, secode string, lastLine, format string, args ...any) error {
	c.botched = true
	return c.errorf(false, code, secode, lastLine, format, args...)
}

func (c *Client) errorf(permanent bool, code int, secode, lastLine, format string, args ...any) error {
	var cmd string
	if len(c.cmds) > 0 {
		cmd = c.cmds[0]
	}
	return Error{permanent, code, secode, cmd, lastLine, fmt.Errorf(format, args...)}
}

func (c *Client) xerrorf(permanent bool, code int, secode, lastLine, format string, args ...any) {
	panic(c.errorf(permanent, code, secode, lastLine, format, args...))
}

// timeoutWriter passes each Write on to conn after setting a write deadline on conn based on
// timeout.
type timeoutWriter struct {
	conn    net.Conn
	timeout time.Duration
	log     *mlog.Log
}

func (w timeoutWriter) Write(buf []byte) (int, error) {
	if err := w.conn.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		w.log.Errorx("setting write deadline", err)
	}

	return w.conn.Write(buf)
}

var bufs = moxio.NewBufpool(8, 2*1024)

func (c *Client) readline() (string, error) {
	// todo: could have per-operation timeouts. and rfc suggests higher minimum timeouts. ../rfc/5321:3610
	if err := c.conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		c.log.Errorx("setting read deadline", err)
	}

	line, err := bufs.Readline(c.r)
	if err != nil {
		return line, c.botchf(0, "", "", "%s: %w", strings.Join(c.cmds, ","), err)
	}
	return line, nil
}

func (c *Client) xtrace(level mlog.Level) func() {
	c.xflush()
	c.tr.SetTrace(level)
	c.tw.SetTrace(level)
	return func() {
		c.xflush()
		c.tr.SetTrace(mlog.LevelTrace)
		c.tw.SetTrace(mlog.LevelTrace)
	}
}

func (c *Client) xwritelinef(format string, args ...any) {
	c.xbwritelinef(format, args...)
	c.xflush()
}

func (c *Client) xwriteline(line string) {
	c.xbwriteline(line)
	c.xflush()
}

func (c *Client) xbwritelinef(format string, args ...any) {
	c.xbwriteline(fmt.Sprintf(format, args...))
}

func (c *Client) xbwriteline(line string) {
	_, err := fmt.Fprintf(c.w, "%s\r\n", line)
	if err != nil {
		c.xbotchf(0, "", "", "write: %w", err)
	}
}

func (c *Client) xflush() {
	err := c.w.Flush()
	if err != nil {
		c.xbotchf(0, "", "", "writes: %w", err)
	}
}

// read response, possibly multiline, with supporting extended codes based on configuration in client.
func (c *Client) xread() (code int, secode, lastLine string, texts []string) {
	var err error
	code, secode, lastLine, texts, err = c.read()
	if err != nil {
		panic(err)
	}
	return
}

func (c *Client) read() (code int, secode, lastLine string, texts []string, rerr error) {
	return c.readecode(c.extEcodes)
}

// read response, possibly multiline.
// if ecodes, extended codes are parsed.
func (c *Client) readecode(ecodes bool) (code int, secode, lastLine string, texts []string, rerr error) {
	for {
		co, sec, text, line, last, err := c.read1(ecodes)
		if err != nil {
			rerr = err
			return
		}
		texts = append(texts, text)
		if code != 0 && co != code {
			// ../rfc/5321:2771
			err := c.botchf(0, "", line, "%w: multiline response with different codes, previous %d, last %d", ErrProtocol, code, co)
			return 0, "", "", nil, err
		}
		code = co
		if last {
			if code != smtp.C334ContinueAuth {
				cmd := ""
				if len(c.cmds) > 0 {
					cmd = c.cmds[0]
					// We only keep the last, so we're not creating new slices all the time.
					if len(c.cmds) > 1 {
						c.cmds = c.cmds[1:]
					}
				}
				metricCommands.WithLabelValues(cmd, fmt.Sprintf("%d", co), sec).Observe(float64(time.Since(c.cmdStart)) / float64(time.Second))
				c.log.Debug("smtpclient command result", mlog.Field("cmd", cmd), mlog.Field("code", co), mlog.Field("secode", sec), mlog.Field("duration", time.Since(c.cmdStart)))
			}
			return co, sec, line, texts, nil
		}
	}
}

func (c *Client) xreadecode(ecodes bool) (code int, secode, lastLine string, texts []string) {
	var err error
	code, secode, lastLine, texts, err = c.readecode(ecodes)
	if err != nil {
		panic(err)
	}
	return
}

// read single response line.
// if ecodes, extended codes are parsed.
func (c *Client) read1(ecodes bool) (code int, secode, text, line string, last bool, rerr error) {
	line, rerr = c.readline()
	if rerr != nil {
		return
	}
	i := 0
	for ; i < len(line) && line[i] >= '0' && line[i] <= '9'; i++ {
	}
	if i != 3 {
		rerr = c.botchf(0, "", line, "%w: expected response code: %s", ErrProtocol, line)
		return
	}
	v, err := strconv.ParseInt(line[:i], 10, 32)
	if err != nil {
		rerr = c.botchf(0, "", line, "%w: bad response code (%s): %s", ErrProtocol, err, line)
		return
	}
	code = int(v)
	major := code / 100
	s := line[3:]
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, " ") {
		last = s[0] == ' '
		s = s[1:]
	} else if s == "" {
		// Allow missing space. ../rfc/5321:2570 ../rfc/5321:2612
		last = true
	} else {
		rerr = c.botchf(0, "", line, "%w: expected space or dash after response code: %s", ErrProtocol, line)
		return
	}

	if ecodes {
		secode, s = parseEcode(major, s)
	}

	return code, secode, s, line, last, nil
}

func parseEcode(major int, s string) (secode string, remain string) {
	o := 0
	bad := false
	take := func(need bool, a, b byte) bool {
		if !bad && o < len(s) && s[o] >= a && s[o] <= b {
			o++
			return true
		}
		bad = bad || need
		return false
	}
	digit := func(need bool) bool {
		return take(need, '0', '9')
	}
	dot := func() bool {
		return take(true, '.', '.')
	}

	digit(true)
	dot()
	xo := o
	digit(true)
	for digit(false) {
	}
	dot()
	digit(true)
	for digit(false) {
	}
	secode = s[xo:o]
	take(false, ' ', ' ')
	if bad || int(s[0])-int('0') != major {
		return "", s
	}
	return secode, s[o:]
}

func (c *Client) recover(rerr *error) {
	x := recover()
	if x == nil {
		return
	}
	cerr, ok := x.(Error)
	if !ok {
		metrics.PanicInc("smtpclient")
		panic(x)
	}
	*rerr = cerr
}

func (c *Client) hello(ctx context.Context, tlsMode TLSMode, ourHostname, remoteHostname dns.Domain, auth []sasl.Client) (rerr error) {
	defer c.recover(&rerr)

	// perform EHLO handshake, falling back to HELO if server does not appear to
	// implement EHLO.
	hello := func(heloOK bool) {
		// Write EHLO and parse the supported extensions.
		// ../rfc/5321:987
		c.cmds[0] = "ehlo"
		c.cmdStart = time.Now()
		// Syntax: ../rfc/5321:1827
		c.xwritelinef("EHLO %s", ourHostname.ASCII)
		code, _, lastLine, remains := c.xreadecode(false)
		switch code {
		// ../rfc/5321:997
		// ../rfc/5321:3098
		case smtp.C500BadSyntax, smtp.C501BadParamSyntax, smtp.C502CmdNotImpl, smtp.C503BadCmdSeq, smtp.C504ParamNotImpl:
			if !heloOK {
				c.xerrorf(true, code, "", lastLine, "%w: remote claims ehlo is not supported", ErrProtocol)
			}
			// ../rfc/5321:996
			c.cmds[0] = "helo"
			c.cmdStart = time.Now()
			c.xwritelinef("HELO %s", ourHostname.ASCII)
			code, _, lastLine, _ = c.xreadecode(false)
			if code != smtp.C250Completed {
				c.xerrorf(code/100 == 5, code, "", lastLine, "%w: expected 250 to HELO, got %d", ErrStatus, code)
			}
			return
		case smtp.C250Completed:
		default:
			c.xerrorf(code/100 == 5, code, "", lastLine, "%w: expected 250, got %d", ErrStatus, code)
		}
		for _, s := range remains[1:] {
			// ../rfc/5321:1869
			s = strings.ToUpper(strings.TrimSpace(s))
			switch s {
			case "STARTTLS":
				c.extStartTLS = true
			case "ENHANCEDSTATUSCODES":
				c.extEcodes = true
			case "8BITMIME":
				c.ext8bitmime = true
			case "PIPELINING":
				c.extPipelining = true
			default:
				// For SMTPUTF8 we must ignore any parameter. ../rfc/6531:207
				if s == "SMTPUTF8" || strings.HasPrefix(s, "SMTPUTF8 ") {
					c.extSMTPUTF8 = true
				} else if strings.HasPrefix(s, "SIZE ") {
					c.extSize = true
					if v, err := strconv.ParseInt(s[len("SIZE "):], 10, 64); err == nil {
						c.maxSize = v
					}
				} else if strings.HasPrefix(s, "AUTH ") {
					c.extAuthMechanisms = strings.Split(s[len("AUTH "):], " ")
				}
			}
		}
	}

	// Read greeting.
	c.cmds = []string{"(greeting)"}
	c.cmdStart = time.Now()
	code, _, lastLine, _ := c.xreadecode(false)
	if code != smtp.C220ServiceReady {
		c.xerrorf(code/100 == 5, code, "", lastLine, "%w: expected 220, got %d", ErrStatus, code)
	}

	// Write EHLO, falling back to HELO if server doesn't appear to support it.
	hello(true)

	// Attempt TLS if remote understands STARTTLS and we aren't doing immediate TLS or if caller requires it.
	if c.extStartTLS && (tlsMode != TLSSkip && tlsMode != TLSStrictImmediate) || tlsMode == TLSStrictStartTLS {
		c.log.Debug("starting tls client", mlog.Field("tlsmode", tlsMode), mlog.Field("servername", remoteHostname))
		c.cmds[0] = "starttls"
		c.cmdStart = time.Now()
		c.xwritelinef("STARTTLS")
		code, secode, lastLine, _ := c.xread()
		// ../rfc/3207:107
		if code != smtp.C220ServiceReady {
			c.xerrorf(code/100 == 5, code, secode, lastLine, "%w: STARTTLS: got %d, expected 220", ErrTLS, code)
		}

		// We don't want to do TLS on top of c.r because it also prints protocol traces: We
		// don't want to log the TLS stream. So we'll do TLS on the underlying connection,
		// but make sure any bytes already read and in the buffer are used for the TLS
		// handshake.
		conn := c.conn
		if n := c.r.Buffered(); n > 0 {
			conn = &moxio.PrefixConn{
				PrefixReader: io.LimitReader(c.r, int64(n)),
				Conn:         conn,
			}
		}

		// For TLSStrictStartTLS, the Go TLS library performs the checks needed for MTA-STS.
		// ../rfc/8461:646
		// todo: possibly accept older TLS versions for TLSOpportunistic?
		tlsConfig := &tls.Config{
			ServerName:         remoteHostname.ASCII,
			RootCAs:            mox.Conf.Static.TLS.CertPool,
			InsecureSkipVerify: tlsMode != TLSStrictStartTLS,
			MinVersion:         tls.VersionTLS12, // ../rfc/8996:31 ../rfc/8997:66
		}
		nconn := tls.Client(conn, tlsConfig)
		c.conn = nconn

		nctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		err := nconn.HandshakeContext(nctx)
		if err != nil {
			c.xerrorf(false, 0, "", "", "%w: STARTTLS TLS handshake: %s", ErrTLS, err)
		}
		cancel()
		c.tr = moxio.NewTraceReader(c.log, "RS: ", c.conn)
		c.tw = moxio.NewTraceWriter(c.log, "LC: ", c.conn) // No need to wrap in timeoutWriter, it would just set the timeout on the underlying connection, which is still active.
		c.r = bufio.NewReader(c.tr)
		c.w = bufio.NewWriter(c.tw)

		tlsversion, ciphersuite := mox.TLSInfo(nconn)
		c.log.Debug("starttls client handshake done", mlog.Field("tls", tlsversion), mlog.Field("ciphersuite", ciphersuite), mlog.Field("servername", remoteHostname), mlog.Field("insecureskipverify", tlsConfig.InsecureSkipVerify))

		hello(false)
	}

	if len(auth) > 0 {
		return c.auth(auth)
	}
	return
}

// ../rfc/4954:139
func (c *Client) auth(auth []sasl.Client) (rerr error) {
	defer c.recover(&rerr)

	c.cmds[0] = "auth"
	c.cmdStart = time.Now()

	var a sasl.Client
	var name string
	var cleartextCreds bool
	for _, x := range auth {
		name, cleartextCreds = x.Info()
		for _, s := range c.extAuthMechanisms {
			if s == name {
				a = x
				break
			}
		}
	}
	if a == nil {
		c.xerrorf(true, 0, "", "", "no matching authentication mechanisms, server supports %s", strings.Join(c.extAuthMechanisms, ", "))
	}

	abort := func() (int, string, string) {
		// Abort authentication. ../rfc/4954:193
		c.xwriteline("*")

		// Server must respond with 501. // ../rfc/4954:195
		code, secode, lastline, _ := c.xread()
		if code != smtp.C501BadParamSyntax {
			c.botched = true
		}
		return code, secode, lastline
	}

	toserver, last, err := a.Next(nil)
	if err != nil {
		c.xerrorf(false, 0, "", "", "initial step in auth mechanism %s: %w", name, err)
	}
	if cleartextCreds {
		defer c.xtrace(mlog.LevelTraceauth)()
	}
	if toserver == nil {
		c.xwriteline("AUTH " + name)
	} else if len(toserver) == 0 {
		c.xwriteline("AUTH " + name + " =") // ../rfc/4954:214
	} else {
		c.xwriteline("AUTH " + name + " " + base64.StdEncoding.EncodeToString(toserver))
	}
	for {
		if cleartextCreds && last {
			c.xtrace(mlog.LevelTrace) // Restore.
		}

		code, secode, lastLine, texts := c.xreadecode(last)
		if code == smtp.C235AuthSuccess {
			if !last {
				c.xerrorf(false, code, secode, lastLine, "server completed authentication earlier than client expected")
			}
			return nil
		} else if code == smtp.C334ContinueAuth {
			if last {
				c.xerrorf(false, code, secode, lastLine, "server requested unexpected continuation of authentication")
			}
			if len(texts) != 1 {
				abort()
				c.xerrorf(false, code, secode, lastLine, "server responded with multiline contination")
			}
			fromserver, err := base64.StdEncoding.DecodeString(texts[0])
			if err != nil {
				abort()
				c.xerrorf(false, code, secode, lastLine, "malformed base64 data in authentication continuation response")
			}
			toserver, last, err = a.Next(fromserver)
			if err != nil {
				// For failing SCRAM, the client stops due to message about invalid proof. The
				// server still sends an authentication result (it probably should send 501
				// instead).
				xcode, xsecode, lastline := abort()
				c.xerrorf(false, xcode, xsecode, lastline, "client aborted authentication: %w", err)
			}
			c.xwriteline(base64.StdEncoding.EncodeToString(toserver))
		} else {
			c.xerrorf(code/100 == 5, code, secode, lastLine, "unexpected response during authentication, expected 334 continue or 235 auth success")
		}
	}
}

// Supports8BITMIME returns whether the SMTP server supports the 8BITMIME
// extension, needed for sending data with non-ASCII bytes.
func (c *Client) Supports8BITMIME() bool {
	return c.ext8bitmime
}

// SupportsSMTPUTF8 returns whether the SMTP server supports the SMTPUTF8
// extension, needed for sending messages with UTF-8 in headers or in an (SMTP)
// address.
func (c *Client) SupportsSMTPUTF8() bool {
	return c.extSMTPUTF8
}

// Deliver attempts to deliver a message to a mail server.
//
// mailFrom must be an email address, or empty in case of a DSN. rcptTo must be
// an email address.
//
// If the message contains bytes with the high bit set, req8bitmime must be true. If
// set, the remote server must support the 8BITMIME extension or delivery will
// fail.
//
// If the message is internationalized, e.g. when headers contain non-ASCII
// character, or when UTF-8 is used in a localpart, reqSMTPUTF8 must be true. If set,
// the remote server must support the SMTPUTF8 extension or delivery will fail.
//
// Deliver uses the following SMTP extensions if the remote server supports them:
// 8BITMIME, SMTPUTF8, SIZE, PIPELINING, ENHANCEDSTATUSCODES, STARTTLS.
//
// Returned errors can be of type Error, one of the Err-variables in this package
// or other underlying errors, e.g. for i/o. Use errors.Is to check.
func (c *Client) Deliver(ctx context.Context, mailFrom string, rcptTo string, msgSize int64, msg io.Reader, req8bitmime, reqSMTPUTF8 bool) (rerr error) {
	defer c.recover(&rerr)

	if c.origConn == nil {
		return ErrClosed
	} else if c.botched {
		return ErrBotched
	} else if c.needRset {
		if err := c.Reset(); err != nil {
			return err
		}
	}

	if !c.ext8bitmime && req8bitmime {
		// Temporary error, e.g. OpenBSD spamd does not announce 8bitmime support, but once
		// you get through, the mail server behind it probably does. Just needs a few
		// retries.
		c.xerrorf(false, 0, "", "", "%w", Err8bitmimeUnsupported)
	}
	if !c.extSMTPUTF8 && reqSMTPUTF8 {
		// ../rfc/6531:313
		c.xerrorf(false, 0, "", "", "%w", ErrSMTPUTF8Unsupported)
	}

	if c.extSize && msgSize > c.maxSize {
		c.xerrorf(true, 0, "", "", "%w: message is %d bytes, remote has a %d bytes maximum size", ErrSize, msgSize, c.maxSize)
	}

	var mailSize, bodyType string
	if c.extSize {
		mailSize = fmt.Sprintf(" SIZE=%d", msgSize)
	}
	if c.ext8bitmime {
		if req8bitmime {
			bodyType = " BODY=8BITMIME"
		} else {
			bodyType = " BODY=7BIT"
		}
	}
	var smtputf8Arg string
	if reqSMTPUTF8 {
		// ../rfc/6531:213
		smtputf8Arg = " SMTPUTF8"
	}

	// Transaction overview: ../rfc/5321:1015
	// MAIL FROM: ../rfc/5321:1879
	// RCPT TO: ../rfc/5321:1916
	// DATA: ../rfc/5321:1992
	lineMailFrom := fmt.Sprintf("MAIL FROM:<%s>%s%s%s", mailFrom, mailSize, bodyType, smtputf8Arg)
	lineRcptTo := fmt.Sprintf("RCPT TO:<%s>", rcptTo)

	// We are going into a transaction. We'll clear this when done.
	c.needRset = true

	if c.extPipelining {
		c.cmds = []string{"mailfrom", "rcptto", "data"}
		c.cmdStart = time.Now()
		// todo future: write in a goroutine to prevent potential deadlock if remote does not consume our writes before expecting us to read. could potentially happen with greylisting and a small tcp send window?
		c.xbwriteline(lineMailFrom)
		c.xbwriteline(lineRcptTo)
		c.xbwriteline("DATA")
		c.xflush()

		// We read the response to RCPT TO and DATA without panic on read error. Servers
		// may be aborting the connection after a failed MAIL FROM, e.g. outlook when it
		// has blocklisted your IP. We don't want the read for the response to RCPT TO to
		// cause a read error as it would result in an unhelpful error message and a
		// temporary instead of permanent error code.

		mfcode, mfsecode, mflastline, _ := c.xread()
		rtcode, rtsecode, rtlastline, _, rterr := c.read()
		datacode, datasecode, datalastline, _, dataerr := c.read()

		if mfcode != smtp.C250Completed {
			c.xerrorf(mfcode/100 == 5, mfcode, mfsecode, mflastline, "%w: got %d, expected 2xx", ErrStatus, mfcode)
		}
		if rterr != nil {
			panic(rterr)
		}
		if rtcode != smtp.C250Completed {
			c.xerrorf(rtcode/100 == 5, rtcode, rtsecode, rtlastline, "%w: got %d, expected 2xx", ErrStatus, rtcode)
		}
		if dataerr != nil {
			panic(dataerr)
		}
		if datacode != smtp.C354Continue {
			c.xerrorf(datacode/100 == 5, datacode, datasecode, datalastline, "%w: got %d, expected 354", ErrStatus, datacode)
		}
	} else {
		c.cmds[0] = "mailfrom"
		c.cmdStart = time.Now()
		c.xwriteline(lineMailFrom)
		code, secode, lastline, _ := c.xread()
		if code != smtp.C250Completed {
			c.xerrorf(code/100 == 5, code, secode, lastline, "%w: got %d, expected 2xx", ErrStatus, code)
		}

		c.cmds[0] = "rcptto"
		c.cmdStart = time.Now()
		c.xwriteline(lineRcptTo)
		code, secode, lastline, _ = c.xread()
		if code != smtp.C250Completed {
			c.xerrorf(code/100 == 5, code, secode, lastline, "%w: got %d, expected 2xx", ErrStatus, code)
		}

		c.cmds[0] = "data"
		c.cmdStart = time.Now()
		c.xwriteline("DATA")
		code, secode, lastline, _ = c.xread()
		if code != smtp.C354Continue {
			c.xerrorf(code/100 == 5, code, secode, lastline, "%w: got %d, expected 354", ErrStatus, code)
		}
	}

	// For a DATA write, the suggested timeout is 3 minutes, we use 30 seconds for all
	// writes through timeoutWriter. ../rfc/5321:3651
	defer c.xtrace(mlog.LevelTracedata)()
	err := smtp.DataWrite(c.w, msg)
	if err != nil {
		c.xbotchf(0, "", "", "writing message as smtp data: %w", err)
	}
	c.xflush()
	c.xtrace(mlog.LevelTrace) // Restore.
	code, secode, lastline, _ := c.xread()
	if code != smtp.C250Completed {
		c.xerrorf(code/100 == 5, code, secode, lastline, "%w: got %d, expected 2xx", ErrStatus, code)
	}

	c.needRset = false
	return
}

// Reset sends an SMTP RSET command to reset the message transaction state. Deliver
// automatically sends it if needed.
func (c *Client) Reset() (rerr error) {
	if c.origConn == nil {
		return ErrClosed
	} else if c.botched {
		return ErrBotched
	}

	defer c.recover(&rerr)

	// ../rfc/5321:2079
	c.cmds[0] = "rset"
	c.cmdStart = time.Now()
	c.xwriteline("RSET")
	code, secode, lastline, _ := c.xread()
	if code != smtp.C250Completed {
		c.xerrorf(code/100 == 5, code, secode, lastline, "%w: got %d, expected 2xx", ErrStatus, code)
	}
	c.needRset = false
	return
}

// Botched returns whether this connection is botched, e.g. a protocol error
// occurred and the connection is in unknown state, and cannot be used for message
// delivery.
func (c *Client) Botched() bool {
	return c.botched || c.origConn == nil
}

// Close cleans up the client, closing the underlying connection.
//
// If the connection is in initialized and not botched, a QUIT command is sent and
// the response read with a short timeout before closing the underlying connection.
//
// Close returns any error encountered during QUIT and closing.
func (c *Client) Close() (rerr error) {
	if c.origConn == nil {
		return ErrClosed
	}

	defer c.recover(&rerr)

	if !c.botched {
		// ../rfc/5321:2205
		c.cmds[0] = "quit"
		c.cmdStart = time.Now()
		c.xwriteline("QUIT")
		if err := c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			c.log.Infox("setting read deadline for reading quit response", err)
		} else if _, err := bufs.Readline(c.r); err != nil {
			rerr = fmt.Errorf("reading response to quit command: %v", err)
			c.log.Debugx("reading quit response", err)
		}
	}

	err := c.origConn.Close()
	if c.conn != c.origConn {
		// This is the TLS connection. Close will attempt to write a close notification.
		// But it will fail quickly because the underlying socket was closed.
		c.conn.Close()
	}
	c.origConn = nil
	c.conn = nil
	if rerr != nil {
		rerr = err
	}
	return
}
