// Package smtpclient is an SMTP client, for submitting to an SMTP server or
// delivering from a queue.
//
// Email clients can submit a message to SMTP server, after which the server is
// responsible for delivery to the final destination. A submission client
// typically connects with TLS, and PKIX-verifies the server's certificate. The
// client then authenticates using a SASL mechanism.
//
// Email servers manage a message queue, from which they will try to deliver
// messages. In case of temporary failures, the message is kept in the queue and
// tried again later. For delivery, no authentication is done. TLS is opportunistic
// by default (TLS certificates not verified), but TLS and certificate verification
// can be opted into by domains by specifying an MTA-STS policy for the domain, or
// DANE TLSA records for their MX hosts.
//
// Delivering a message from a queue would involve:
//  1. Looking up an MTA-STS policy, through a cache.
//  2. Resolving the MX targets for a domain, through smtpclient.GatherDestinations,
//     and for each destination try delivery through:
//  3. Looking up IP addresses for the destination, with smtpclient.GatherIPs.
//  4. Looking up TLSA records for DANE, in case of authentic DNS responses
//     (DNSSEC), with smtpclient.GatherTLSA.
//  5. Dialing the MX target with smtpclient.Dial.
//  6. Initializing a SMTP session with smtpclient.New, with proper TLS
//     configuration based on discovered MTA-STS and DANE policies, and finally calling
//     client.Deliver.
package smtpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/dane"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/stub"
	"github.com/mjl-/mox/tlsrpt"
)

// todo future: add function to deliver message to multiple recipients. requires more elaborate return value, indicating success per message: some recipients may succeed, others may fail, and we should still deliver. to prevent backscatter, we also sometimes don't allow multiple recipients. ../rfc/5321:1144

var (
	MetricCommands             stub.HistogramVec = stub.HistogramVecIgnore{}
	MetricTLSRequiredNoIgnored stub.CounterVec   = stub.CounterVecIgnore{}
	MetricPanicInc                               = func() {}
)

var (
	ErrSize                  = errors.New("message too large for remote smtp server") // SMTP server announced a maximum message size and the message to be delivered exceeds it.
	Err8bitmimeUnsupported   = errors.New("remote smtp server does not implement 8bitmime extension, required by message")
	ErrSMTPUTF8Unsupported   = errors.New("remote smtp server does not implement smtputf8 extension, required by message")
	ErrRequireTLSUnsupported = errors.New("remote smtp server does not implement requiretls extension, required for delivery")
	ErrStatus                = errors.New("remote smtp server sent unexpected response status code") // Relatively common, e.g. when a 250 OK was expected and server sent 451 temporary error.
	ErrProtocol              = errors.New("smtp protocol error")                                     // After a malformed SMTP response or inconsistent multi-line response.
	ErrTLS                   = errors.New("tls error")                                               // E.g. handshake failure, or hostname verification was required and failed.
	ErrBotched               = errors.New("smtp connection is botched")                              // Set on a client, and returned for new operations, after an i/o error or malformed SMTP response.
	ErrClosed                = errors.New("client is closed")
)

// TLSMode indicates if TLS must, should or must not be used.
type TLSMode string

const (
	// TLS immediately ("implicit TLS"), directly starting TLS on the TCP connection,
	// so not using STARTTLS. Whether PKIX and/or DANE is verified is specified
	// separately.
	TLSImmediate TLSMode = "immediate"

	// Required TLS with STARTTLS for SMTP servers. The STARTTLS command is always
	// executed, even if the server does not announce support.
	// Whether PKIX and/or DANE is verified is specified separately.
	TLSRequiredStartTLS TLSMode = "requiredstarttls"

	// Use TLS with STARTTLS if remote claims to support it.
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
	origConn              net.Conn
	conn                  net.Conn
	tlsVerifyPKIX         bool
	ignoreTLSVerifyErrors bool
	rootCAs               *x509.CertPool
	remoteHostname        dns.Domain       // TLS with SNI and name verification.
	daneRecords           []adns.TLSA      // For authenticating (START)TLS connection.
	daneMoreHostnames     []dns.Domain     // Additional allowed names in TLS certificate for DANE-TA.
	daneVerifiedRecord    *adns.TLSA       // If non-nil, then will be set to verified DANE record if any.
	clientCert            *tls.Certificate // If non-nil, tls client authentication is done.
	tlsConfigOpts         *tls.Config      // If non-nil, tls config to use.

	// TLS connection success/failure are added. These are always non-nil, regardless
	// of what was passed in opts. It lets us unconditionally dereference them.
	recipientDomainResult *tlsrpt.Result // Either "sts" or "no-policy-found".
	hostResult            *tlsrpt.Result // Either "dane" or "no-policy-found".

	r                       *bufio.Reader
	w                       *bufio.Writer
	tr                      *moxio.TraceReader // Kept for changing trace levels between cmd/auth/data.
	tw                      *moxio.TraceWriter
	log                     mlog.Log
	lastlog                 time.Time // For adding delta timestamps between log lines.
	cmds                    []string  // Last or active command, for generating errors and metrics.
	cmdStart                time.Time // Start of command.
	tls                     bool      // Whether connection is TLS protected.
	firstReadAfterHandshake bool      // To detect TLS alert error from remote just after handshake.

	botched  bool // If set, protocol is out of sync and no further commands can be sent.
	needRset bool // If set, a new delivery requires an RSET command.

	remoteHelo            string // From 220 greeting line.
	extEcodes             bool   // Remote server supports sending extended error codes.
	extStartTLS           bool   // Remote server supports STARTTLS.
	ext8bitmime           bool
	extSize               bool              // Remote server supports SIZE parameter. Must only be used if > 0.
	maxSize               int64             // Max size of email message.
	extPipelining         bool              // Remote server supports command pipelining.
	extSMTPUTF8           bool              // Remote server supports SMTPUTF8 extension.
	extAuthMechanisms     []string          // Supported authentication mechanisms.
	extRequireTLS         bool              // Remote supports REQUIRETLS extension.
	ExtLimits             map[string]string // For LIMITS extension, only if present and valid, with uppercase keys.
	ExtLimitMailMax       int               // Max "MAIL" commands in a connection, if > 0.
	ExtLimitRcptMax       int               // Max "RCPT" commands in a transaction, if > 0.
	ExtLimitRcptDomainMax int               // Max unique domains in a connection, if > 0.
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
	// the error. First line of a multi-line response.
	Line string
	// Optional additional lines in case of multi-line SMTP response.  Most SMTP
	// responses are single-line, leaving this field empty.
	MoreLines []string
	// Underlying error, e.g. one of the Err variables in this package, or io errors.
	Err error
}

type Response Error

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

// Opts influence behaviour of Client.
type Opts struct {
	// If auth is non-nil, authentication will be done with the returned sasl client.
	// The function should select the preferred mechanism. Mechanisms are in upper
	// case.
	//
	// The TLS connection state can be used for the SCRAM PLUS mechanisms, binding the
	// authentication exchange to a TLS connection. It is only present for TLS
	// connections.
	//
	// If no mechanism is supported, a nil client and nil error can be returned, and
	// the connection will fail.
	Auth func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error)

	DANERecords        []adns.TLSA  // If not nil, DANE records to verify.
	DANEMoreHostnames  []dns.Domain // For use with DANE, where additional certificate host names are allowed.
	DANEVerifiedRecord *adns.TLSA   // If non-empty, set to the DANE record that verified the TLS connection.

	// If set, TLS verification errors (for DANE or PKIX) are ignored. Useful for
	// delivering messages with message header "TLS-Required: No".
	// Certificates are still verified, and results are still tracked for TLS
	// reporting, but the connections will continue.
	IgnoreTLSVerifyErrors bool

	// If not nil, used instead of the system default roots for TLS PKIX verification.
	RootCAs *x509.CertPool

	// If set, the TLS client certificate authentication is done.
	ClientCert *tls.Certificate

	// TLS verification successes/failures is added to these TLS reporting results.
	// Once the STARTTLS handshake is attempted, a successful/failed connection is
	// tracked.
	RecipientDomainResult *tlsrpt.Result // MTA-STS or no policy.
	HostResult            *tlsrpt.Result // DANE or no policy.

	// If not nil, the TLS config to use instead of the default. Useful for custom
	// certificate verification or TLS parameters. The other DANE/TLS/certificate
	// fields in [Opts], and the tlsVerifyPKIX and remoteHostname parameters to [New]
	// have no effect when TLSConfig is set.
	TLSConfig *tls.Config
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
// Connecting to the correct host for delivery can be done using the Gather
// functions, and with Dial. The queue managing outgoing messages typically decides
// which host to deliver to, taking multiple MX records with preferences, other DNS
// records, MTA-STS, retries and special cases into account.
//
// tlsMode indicates if and how TLS may/must (not) be used.
//
// tlsVerifyPKIX indicates if TLS certificates must be validated against the
// PKIX/WebPKI certificate authorities (if TLS is done).
//
// DANE-verification is done when opts.DANERecords is not nil.
//
// TLS verification errors will be ignored if opts.IgnoreTLSVerification is set.
//
// If TLS is done, PKIX verification is always performed for tracking the results
// for TLS reporting, but if tlsVerifyPKIX is false, the verification result does
// not affect the connection.
//
// At the time of writing, delivery of email on the internet is done with
// opportunistic TLS without PKIX verification by default. Recipient domains can
// opt-in to PKIX verification by publishing an MTA-STS policy, or opt-in to DANE
// verification by publishing DNSSEC-protected TLSA records in DNS.
func New(ctx context.Context, elog *slog.Logger, conn net.Conn, tlsMode TLSMode, tlsVerifyPKIX bool, ehloHostname, remoteHostname dns.Domain, opts Opts) (*Client, error) {
	ensureResult := func(r *tlsrpt.Result) *tlsrpt.Result {
		if r == nil {
			return &tlsrpt.Result{}
		}
		return r
	}

	c := &Client{
		origConn:              conn,
		tlsVerifyPKIX:         tlsVerifyPKIX,
		ignoreTLSVerifyErrors: opts.IgnoreTLSVerifyErrors,
		rootCAs:               opts.RootCAs,
		remoteHostname:        remoteHostname,
		daneRecords:           opts.DANERecords,
		daneMoreHostnames:     opts.DANEMoreHostnames,
		daneVerifiedRecord:    opts.DANEVerifiedRecord,
		clientCert:            opts.ClientCert,
		lastlog:               time.Now(),
		cmds:                  []string{"(none)"},
		recipientDomainResult: ensureResult(opts.RecipientDomainResult),
		hostResult:            ensureResult(opts.HostResult),
		tlsConfigOpts:         opts.TLSConfig,
	}
	c.log = mlog.New("smtpclient", elog).WithFunc(func() []slog.Attr {
		now := time.Now()
		l := []slog.Attr{
			slog.Duration("delta", now.Sub(c.lastlog)),
		}
		c.lastlog = now
		return l
	})

	if tlsMode == TLSImmediate {
		config := c.tlsConfig()
		tlsconn := tls.Client(conn, config)
		// The tlsrpt tracking isn't used by caller, but won't hurt.
		if err := tlsconn.HandshakeContext(ctx); err != nil {
			c.tlsResultAdd(0, 1, err)
			return nil, err
		}
		c.firstReadAfterHandshake = true
		c.tlsResultAdd(1, 0, nil)
		c.conn = tlsconn
		version, ciphersuite := moxio.TLSInfo(tlsconn.ConnectionState())
		c.log.Debug("tls client handshake done",
			slog.String("version", version),
			slog.String("ciphersuite", ciphersuite),
			slog.Any("servername", remoteHostname))
		c.tls = true
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

	if err := c.hello(ctx, tlsMode, ehloHostname, opts.Auth); err != nil {
		return nil, err
	}
	return c, nil
}

// reportedError wraps an error while indicating it was already tracked for TLS
// reporting.
type reportedError struct{ err error }

func (e reportedError) Error() string {
	return e.err.Error()
}

func (e reportedError) Unwrap() error {
	return e.err
}

func (c *Client) tlsConfig() *tls.Config {
	// We always manage verification ourselves: We need to report in detail about
	// failures. And we may have to verify both PKIX and DANE, record errors for
	// each, and possibly ignore the errors.

	if c.tlsConfigOpts != nil {
		return c.tlsConfigOpts
	}

	verifyConnection := func(cs tls.ConnectionState) error {
		// Collect verification errors. If there are none at the end, TLS validation
		// succeeded. We may find validation problems below, record them for a TLS report
		// but continue due to policies. We track the TLS reporting result in this
		// function, wrapping errors in a reportedError.
		var daneErr, pkixErr error

		// DANE verification.
		// daneRecords can be non-nil and empty, that's intended.
		if c.daneRecords != nil {
			verified, record, err := dane.Verify(c.log.Logger, c.daneRecords, cs, c.remoteHostname, c.daneMoreHostnames, c.rootCAs)
			c.log.Debugx("dane verification", err, slog.Bool("verified", verified), slog.Any("record", record))
			if verified {
				if c.daneVerifiedRecord != nil {
					*c.daneVerifiedRecord = record
				}
			} else {
				// Track error for reports.
				// todo spec: may want to propose adding a result for no-dane-match. dane allows multiple records, some mismatching/failing isn't fatal and reporting on each record is probably not productive. ../rfc/8460:541
				fd := c.tlsrptFailureDetails(tlsrpt.ResultValidationFailure, "dane-no-match")
				if err != nil {
					// todo future: potentially add more details. e.g. dane-ta verification errors. tlsrpt does not have "result types" to indicate those kinds of errors. we would probably have to pass c.daneResult to dane.Verify.

					// We may have encountered errors while evaluation some of the TLSA records.
					fd.FailureReasonCode += "+errors"
				}
				c.hostResult.Add(0, 0, fd)

				if c.ignoreTLSVerifyErrors {
					// We ignore the failure and continue the connection.
					c.log.Infox("verifying dane failed, continuing with connection", err)
					MetricTLSRequiredNoIgnored.IncLabels("daneverification")
				} else {
					// This connection will fail.
					daneErr = dane.ErrNoMatch
				}
			}
		}

		// PKIX verification.
		opts := x509.VerifyOptions{
			DNSName:       cs.ServerName,
			Intermediates: x509.NewCertPool(),
			Roots:         c.rootCAs,
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
			resultType, reasonCode := tlsrpt.TLSFailureDetails(err)
			fd := c.tlsrptFailureDetails(resultType, reasonCode)
			c.recipientDomainResult.Add(0, 0, fd)

			if c.tlsVerifyPKIX && !c.ignoreTLSVerifyErrors {
				pkixErr = err
			}
		}

		if daneErr != nil && pkixErr != nil {
			return reportedError{errors.Join(daneErr, pkixErr)}
		} else if daneErr != nil {
			return reportedError{daneErr}
		} else if pkixErr != nil {
			return reportedError{pkixErr}
		}
		return nil
	}

	var certs []tls.Certificate
	if c.clientCert != nil {
		certs = []tls.Certificate{*c.clientCert}
	}

	return &tls.Config{
		ServerName: c.remoteHostname.ASCII, // For SNI.
		// todo: possibly accept older TLS versions for TLSOpportunistic? or would our private key be at risk?
		MinVersion:         tls.VersionTLS12, // ../rfc/8996:31 ../rfc/8997:66
		InsecureSkipVerify: true,             // VerifyConnection below is called and will do all verification.
		VerifyConnection:   verifyConnection,
		Certificates:       certs,
	}
}

// xbotchf generates a temporary error and marks the client as botched. e.g. for
// i/o errors or invalid protocol messages.
func (c *Client) xbotchf(code int, secode string, firstLine string, moreLines []string, format string, args ...any) {
	panic(c.botchf(code, secode, firstLine, moreLines, format, args...))
}

// botchf generates a temporary error and marks the client as botched. e.g. for
// i/o errors or invalid protocol messages.
func (c *Client) botchf(code int, secode string, firstLine string, moreLines []string, format string, args ...any) error {
	c.botched = true
	return c.errorf(false, code, secode, firstLine, moreLines, format, args...)
}

func (c *Client) errorf(permanent bool, code int, secode, firstLine string, moreLines []string, format string, args ...any) error {
	var cmd string
	if len(c.cmds) > 0 {
		cmd = c.cmds[0]
	}
	return Error{permanent, code, secode, cmd, firstLine, moreLines, fmt.Errorf(format, args...)}
}

func (c *Client) xerrorf(permanent bool, code int, secode, firstLine string, moreLines []string, format string, args ...any) {
	panic(c.errorf(permanent, code, secode, firstLine, moreLines, format, args...))
}

// timeoutWriter passes each Write on to conn after setting a write deadline on conn based on
// timeout.
type timeoutWriter struct {
	conn    net.Conn
	timeout time.Duration
	log     mlog.Log
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

	line, err := bufs.Readline(c.log, c.r)
	if err != nil {
		// See if this is a TLS alert from remote, and one other than 0 (which notifies
		// that the connection is being closed. If so, we register a TLS connection
		// failure. This handles TLS alerts that happen just after a successful handshake.
		var netErr *net.OpError
		if c.firstReadAfterHandshake && errors.As(err, &netErr) && netErr.Op == "remote error" && netErr.Err != nil && reflect.ValueOf(netErr.Err).Kind() == reflect.Uint8 && reflect.ValueOf(netErr.Err).Uint() != 0 {
			resultType, reasonCode := tlsrpt.TLSFailureDetails(err)
			// We count -1 success to compensate for the assumed success right after the handshake.
			c.tlsResultAddFailureDetails(-1, 1, c.tlsrptFailureDetails(resultType, reasonCode))
		}

		return line, c.botchf(0, "", "", nil, "%s: %w", strings.Join(c.cmds, ","), err)
	}
	c.firstReadAfterHandshake = false
	return line, nil
}

func (c *Client) xtrace(level slog.Level) func() {
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
		c.xbotchf(0, "", "", nil, "write: %w", err)
	}
}

func (c *Client) xflush() {
	err := c.w.Flush()
	if err != nil {
		c.xbotchf(0, "", "", nil, "writes: %w", err)
	}
}

// read response, possibly multiline, with supporting extended codes based on configuration in client.
func (c *Client) xread() (code int, secode, firstLine string, moreLines []string) {
	var err error
	code, secode, firstLine, moreLines, err = c.read()
	if err != nil {
		panic(err)
	}
	return
}

func (c *Client) read() (code int, secode, firstLine string, moreLines []string, rerr error) {
	code, secode, _, firstLine, moreLines, _, rerr = c.readecode(c.extEcodes)
	return
}

// read response, possibly multiline.
// if ecodes, extended codes are parsed.
func (c *Client) readecode(ecodes bool) (code int, secode, lastText, firstLine string, moreLines, moreTexts []string, rerr error) {
	first := true
	for {
		co, sec, text, line, last, err := c.read1(ecodes)
		if first {
			firstLine = line
			first = false
		} else if line != "" {
			moreLines = append(moreLines, line)
			if text != "" {
				moreTexts = append(moreTexts, text)
			}
		}
		if err != nil {
			rerr = err
			return
		}
		if code != 0 && co != code {
			// ../rfc/5321:2771
			err := c.botchf(0, "", firstLine, moreLines, "%w: multiline response with different codes, previous %d, last %d", ErrProtocol, code, co)
			return 0, "", "", "", nil, nil, err
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
				MetricCommands.ObserveLabels(float64(time.Since(c.cmdStart))/float64(time.Second), cmd, fmt.Sprintf("%d", co), sec)
				c.log.Debug("smtpclient command result",
					slog.String("cmd", cmd),
					slog.Int("code", co),
					slog.String("secode", sec),
					slog.Duration("duration", time.Since(c.cmdStart)))
			}
			return co, sec, text, firstLine, moreLines, moreTexts, nil
		}
	}
}

func (c *Client) xreadecode(ecodes bool) (code int, secode, lastText, firstLine string, moreLines, moreTexts []string) {
	var err error
	code, secode, lastText, firstLine, moreLines, moreTexts, err = c.readecode(ecodes)
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
		rerr = c.botchf(0, "", line, nil, "%w: expected response code: %s", ErrProtocol, line)
		return
	}
	v, err := strconv.ParseInt(line[:i], 10, 32)
	if err != nil {
		rerr = c.botchf(0, "", line, nil, "%w: bad response code (%s): %s", ErrProtocol, err, line)
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
		rerr = c.botchf(0, "", line, nil, "%w: expected space or dash after response code: %s", ErrProtocol, line)
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
		MetricPanicInc()
		panic(x)
	}
	*rerr = cerr
}

func (c *Client) hello(ctx context.Context, tlsMode TLSMode, ehloHostname dns.Domain, auth func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error)) (rerr error) {
	defer c.recover(&rerr)

	// perform EHLO handshake, falling back to HELO if server does not appear to
	// implement EHLO.
	hello := func(heloOK bool) {
		// Write EHLO and parse the supported extensions.
		// ../rfc/5321:987
		c.cmds[0] = "ehlo"
		c.cmdStart = time.Now()
		// Syntax: ../rfc/5321:1827
		c.xwritelinef("EHLO %s", ehloHostname.ASCII)
		code, _, _, firstLine, moreLines, moreTexts := c.xreadecode(false)
		switch code {
		// ../rfc/5321:997
		// ../rfc/5321:3098
		case smtp.C500BadSyntax, smtp.C501BadParamSyntax, smtp.C502CmdNotImpl, smtp.C503BadCmdSeq, smtp.C504ParamNotImpl:
			if !heloOK {
				c.xerrorf(true, code, "", firstLine, moreLines, "%w: remote claims ehlo is not supported", ErrProtocol)
			}
			// ../rfc/5321:996
			c.cmds[0] = "helo"
			c.cmdStart = time.Now()
			c.xwritelinef("HELO %s", ehloHostname.ASCII)
			code, _, _, firstLine, _, _ = c.xreadecode(false)
			if code != smtp.C250Completed {
				c.xerrorf(code/100 == 5, code, "", firstLine, moreLines, "%w: expected 250 to HELO, got %d", ErrStatus, code)
			}
			return
		case smtp.C250Completed:
		default:
			c.xerrorf(code/100 == 5, code, "", firstLine, moreLines, "%w: expected 250, got %d", ErrStatus, code)
		}
		for _, s := range moreTexts {
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
			case "REQUIRETLS":
				c.extRequireTLS = true
			default:
				// For SMTPUTF8 we must ignore any parameter. ../rfc/6531:207
				if s == "SMTPUTF8" || strings.HasPrefix(s, "SMTPUTF8 ") {
					c.extSMTPUTF8 = true
				} else if strings.HasPrefix(s, "SIZE ") {
					// ../rfc/1870:77
					c.extSize = true
					if v, err := strconv.ParseInt(s[len("SIZE "):], 10, 64); err == nil {
						c.maxSize = v
					}
				} else if strings.HasPrefix(s, "AUTH ") {
					c.extAuthMechanisms = strings.Split(s[len("AUTH "):], " ")
				} else if strings.HasPrefix(s, "LIMITS ") {
					c.ExtLimits, c.ExtLimitMailMax, c.ExtLimitRcptMax, c.ExtLimitRcptDomainMax = parseLimits([]byte(s[len("LIMITS"):]))
				}
			}
		}
	}

	// Read greeting.
	c.cmds = []string{"(greeting)"}
	c.cmdStart = time.Now()
	code, _, _, firstLine, moreLines, _ := c.xreadecode(false)
	if code != smtp.C220ServiceReady {
		c.xerrorf(code/100 == 5, code, "", firstLine, moreLines, "%w: expected 220, got %d", ErrStatus, code)
	}
	// ../rfc/5321:2588
	_, c.remoteHelo, _ = strings.Cut(firstLine, " ")

	// Write EHLO, falling back to HELO if server doesn't appear to support it.
	hello(true)

	// Attempt TLS if remote understands STARTTLS and we aren't doing immediate TLS or if caller requires it.
	if c.extStartTLS && tlsMode == TLSOpportunistic || tlsMode == TLSRequiredStartTLS {
		c.log.Debug("starting tls client", slog.Any("tlsmode", tlsMode), slog.Any("servername", c.remoteHostname))
		c.cmds[0] = "starttls"
		c.cmdStart = time.Now()
		c.xwritelinef("STARTTLS")
		code, secode, firstLine, _ := c.xread()
		// ../rfc/3207:107
		if code != smtp.C220ServiceReady {
			c.tlsResultAddFailureDetails(0, 1, c.tlsrptFailureDetails(tlsrpt.ResultSTARTTLSNotSupported, fmt.Sprintf("smtp-starttls-reply-code-%d", code)))
			c.xerrorf(code/100 == 5, code, secode, firstLine, moreLines, "%w: STARTTLS: got %d, expected 220", ErrTLS, code)
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

		tlsConfig := c.tlsConfig()
		nconn := tls.Client(conn, tlsConfig)
		c.conn = nconn

		nctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		err := nconn.HandshakeContext(nctx)
		if err != nil {
			// For each STARTTLS failure, we track a failed TLS session. For deliveries with
			// multiple MX targets, we may add multiple failures, and delivery may succeed with
			// a later MX target with which we can do STARTTLS. ../rfc/8460:524
			c.tlsResultAdd(0, 1, err)
			c.xerrorf(false, 0, "", "", nil, "%w: STARTTLS TLS handshake: %s", ErrTLS, err)
		}
		c.firstReadAfterHandshake = true
		cancel()
		c.tr = moxio.NewTraceReader(c.log, "RS: ", c.conn)
		c.tw = moxio.NewTraceWriter(c.log, "LC: ", c.conn) // No need to wrap in timeoutWriter, it would just set the timeout on the underlying connection, which is still active.
		c.r = bufio.NewReader(c.tr)
		c.w = bufio.NewWriter(c.tw)

		version, ciphersuite := moxio.TLSInfo(nconn.ConnectionState())
		c.log.Debug("starttls client handshake done",
			slog.Any("tlsmode", tlsMode),
			slog.Bool("verifypkix", c.tlsVerifyPKIX),
			slog.Bool("verifydane", c.daneRecords != nil),
			slog.Bool("ignoretlsverifyerrors", c.ignoreTLSVerifyErrors),
			slog.String("version", version),
			slog.String("ciphersuite", ciphersuite),
			slog.Any("servername", c.remoteHostname),
			slog.Any("danerecord", c.daneVerifiedRecord))
		c.tls = true
		// Track successful TLS connection. ../rfc/8460:515
		c.tlsResultAdd(1, 0, nil)

		hello(false)
	} else if tlsMode == TLSOpportunistic {
		// Result: ../rfc/8460:538
		c.tlsResultAddFailureDetails(0, 0, c.tlsrptFailureDetails(tlsrpt.ResultSTARTTLSNotSupported, ""))
	}

	if auth != nil {
		return c.auth(auth)
	}
	return
}

// parse text after "LIMITS", including leading space.
func parseLimits(b []byte) (map[string]string, int, int, int) {
	// ../rfc/9422:150
	var o int
	// Read next " name=value".
	pair := func() ([]byte, []byte) {
		if o >= len(b) || b[o] != ' ' {
			return nil, nil
		}
		o++

		ns := o
		for o < len(b) {
			c := b[o]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				o++
			} else {
				break
			}
		}
		es := o
		if ns == es || o >= len(b) || b[o] != '=' {
			return nil, nil
		}
		o++
		vs := o
		for o < len(b) {
			c := b[o]
			if c > 0x20 && c < 0x7f && c != ';' {
				o++
			} else {
				break
			}
		}
		if vs == o {
			return nil, nil
		}
		return b[ns:es], b[vs:o]
	}
	limits := map[string]string{}
	var mailMax, rcptMax, rcptDomainMax int
	for o < len(b) {
		name, value := pair()
		if name == nil {
			// We skip the entire LIMITS extension for syntax errors. ../rfc/9422:232
			return nil, 0, 0, 0
		}
		k := strings.ToUpper(string(name))
		if _, ok := limits[k]; ok {
			// Not specified, but we treat duplicates as error.
			return nil, 0, 0, 0
		}
		limits[k] = string(value)
		// For individual value syntax errors, we skip that value, leaving the default 0.
		// ../rfc/9422:254
		switch string(name) {
		case "MAILMAX":
			if v, err := strconv.Atoi(string(value)); err == nil && v > 0 && len(value) <= 6 {
				mailMax = v
			}
		case "RCPTMAX":
			if v, err := strconv.Atoi(string(value)); err == nil && v > 0 && len(value) <= 6 {
				rcptMax = v
			}
		case "RCPTDOMAINMAX":
			if v, err := strconv.Atoi(string(value)); err == nil && v > 0 && len(value) <= 6 {
				rcptDomainMax = v
			}
		}
	}
	return limits, mailMax, rcptMax, rcptDomainMax
}

func addrIP(addr net.Addr) string {
	if t, ok := addr.(*net.TCPAddr); ok {
		return t.IP.String()
	}
	host, _, _ := net.SplitHostPort(addr.String())
	ip := net.ParseIP(host)
	if ip == nil {
		return "" // For pipe during tests.
	}
	return ip.String()
}

// tlsrptFailureDetails returns FailureDetails with connection details (such as
// IP addresses) for inclusion in a TLS report.
func (c *Client) tlsrptFailureDetails(resultType tlsrpt.ResultType, reasonCode string) tlsrpt.FailureDetails {
	return tlsrpt.FailureDetails{
		ResultType:          resultType,
		SendingMTAIP:        addrIP(c.origConn.LocalAddr()),
		ReceivingMXHostname: c.remoteHostname.ASCII,
		ReceivingMXHelo:     c.remoteHelo,
		ReceivingIP:         addrIP(c.origConn.RemoteAddr()),
		FailedSessionCount:  1,
		FailureReasonCode:   reasonCode,
	}
}

// tlsResultAdd adds TLS success/failure to all results.
func (c *Client) tlsResultAdd(success, failure int64, err error) {
	// Only track failure if not already done so in tls.Config.VerifyConnection.
	var fds []tlsrpt.FailureDetails
	var repErr reportedError
	if err != nil && !errors.As(err, &repErr) {
		resultType, reasonCode := tlsrpt.TLSFailureDetails(err)
		fd := c.tlsrptFailureDetails(resultType, reasonCode)
		fds = []tlsrpt.FailureDetails{fd}
	}
	c.tlsResultAddFailureDetails(success, failure, fds...)
}

func (c *Client) tlsResultAddFailureDetails(success, failure int64, fds ...tlsrpt.FailureDetails) {
	c.recipientDomainResult.Add(success, failure, fds...)
	c.hostResult.Add(success, failure, fds...)
}

// ../rfc/4954:139
func (c *Client) auth(auth func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error)) (rerr error) {
	defer c.recover(&rerr)

	c.cmds[0] = "auth"
	c.cmdStart = time.Now()

	mechanisms := make([]string, len(c.extAuthMechanisms))
	for i, m := range c.extAuthMechanisms {
		mechanisms[i] = strings.ToUpper(m)
	}
	a, err := auth(mechanisms, c.TLSConnectionState())
	if err != nil {
		c.xerrorf(true, 0, "", "", nil, "get authentication mechanism: %s, server supports %s", err, strings.Join(c.extAuthMechanisms, ", "))
	} else if a == nil {
		c.xerrorf(true, 0, "", "", nil, "no matching authentication mechanisms, server supports %s", strings.Join(c.extAuthMechanisms, ", "))
	}
	name, cleartextCreds := a.Info()

	abort := func() (int, string, string, []string) {
		// Abort authentication. ../rfc/4954:193
		c.xwriteline("*")

		// Server must respond with 501. // ../rfc/4954:195
		code, secode, firstLine, moreLines := c.xread()
		if code != smtp.C501BadParamSyntax {
			c.botched = true
		}
		return code, secode, firstLine, moreLines
	}

	toserver, last, err := a.Next(nil)
	if err != nil {
		c.xerrorf(false, 0, "", "", nil, "initial step in auth mechanism %s: %w", name, err)
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

		code, secode, lastText, firstLine, moreLines, _ := c.xreadecode(last)
		if code == smtp.C235AuthSuccess {
			if !last {
				c.xerrorf(false, code, secode, firstLine, moreLines, "server completed authentication earlier than client expected")
			}
			return nil
		} else if code == smtp.C334ContinueAuth {
			if last {
				c.xerrorf(false, code, secode, firstLine, moreLines, "server requested unexpected continuation of authentication")
			}
			if len(moreLines) > 0 {
				abort()
				c.xerrorf(false, code, secode, firstLine, moreLines, "server responded with multiline contination")
			}
			fromserver, err := base64.StdEncoding.DecodeString(lastText)
			if err != nil {
				abort()
				c.xerrorf(false, code, secode, firstLine, moreLines, "malformed base64 data in authentication continuation response")
			}
			toserver, last, err = a.Next(fromserver)
			if err != nil {
				// For failing SCRAM, the client stops due to message about invalid proof. The
				// server still sends an authentication result (it probably should send 501
				// instead).
				xcode, xsecode, xfirstLine, xmoreLines := abort()
				c.xerrorf(false, xcode, xsecode, xfirstLine, xmoreLines, "client aborted authentication: %w", err)
			}
			c.xwriteline(base64.StdEncoding.EncodeToString(toserver))
		} else {
			c.xerrorf(code/100 == 5, code, secode, firstLine, moreLines, "unexpected response during authentication, expected 334 continue or 235 auth success")
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

// SupportsStartTLS returns whether the SMTP server supports the STARTTLS
// extension.
func (c *Client) SupportsStartTLS() bool {
	return c.extStartTLS
}

// SupportsRequireTLS returns whether the SMTP server supports the REQUIRETLS
// extension. The REQUIRETLS extension is only announced after enabling
// STARTTLS.
func (c *Client) SupportsRequireTLS() bool {
	return c.extRequireTLS
}

// TLSConnectionState returns TLS details if TLS is enabled, and nil otherwise.
func (c *Client) TLSConnectionState() *tls.ConnectionState {
	if tlsConn, ok := c.conn.(*tls.Conn); ok {
		cs := tlsConn.ConnectionState()
		return &cs
	}
	return nil
}

// Deliver attempts to deliver a message to a mail server.
//
// mailFrom must be an email address, or empty in case of a DSN. rcptTo must be
// an email address.
//
// If the message contains bytes with the high bit set, req8bitmime should be true.
// If set, the remote server must support the 8BITMIME extension or delivery will
// fail.
//
// If the message is internationalized, e.g. when headers contain non-ASCII
// character, or when UTF-8 is used in a localpart, reqSMTPUTF8 must be true. If set,
// the remote server must support the SMTPUTF8 extension or delivery will fail.
//
// If requireTLS is true, the remote server must support the REQUIRETLS
// extension, or delivery will fail.
//
// Deliver uses the following SMTP extensions if the remote server supports them:
// 8BITMIME, SMTPUTF8, SIZE, PIPELINING, ENHANCEDSTATUSCODES, STARTTLS.
//
// Returned errors can be of type Error, one of the Err-variables in this package
// or other underlying errors, e.g. for i/o. Use errors.Is to check.
func (c *Client) Deliver(ctx context.Context, mailFrom string, rcptTo string, msgSize int64, msg io.Reader, req8bitmime, reqSMTPUTF8, requireTLS bool) (rerr error) {
	_, err := c.DeliverMultiple(ctx, mailFrom, []string{rcptTo}, msgSize, msg, req8bitmime, reqSMTPUTF8, requireTLS)
	return err
}

var errNoRecipientsPipelined = errors.New("no recipients accepted in pipelined transaction")
var errNoRecipients = errors.New("no recipients accepted in transaction")

// DeliverMultiple is like Deliver, but attempts to deliver a message to multiple
// recipients.  Errors about the entire transaction, such as i/o errors or error
// responses to the MAIL FROM or DATA commands, are returned by a non-nil rerr. If
// rcptTo has a single recipient, an error to the RCPT TO command is returned in
// rerr instead of rcptResps. Otherwise, the SMTP response for each recipient is
// returned in rcptResps.
//
// The caller should take extLimit* into account when sending. And recognize
// recipient response code "452" to mean that a recipient limit was reached,
// another transaction can be attempted immediately after instead of marking the
// delivery attempt as failed. Also code "552" must be treated like temporary error
// code "452" for historic reasons.
func (c *Client) DeliverMultiple(ctx context.Context, mailFrom string, rcptTo []string, msgSize int64, msg io.Reader, req8bitmime, reqSMTPUTF8, requireTLS bool) (rcptResps []Response, rerr error) {
	defer c.recover(&rerr)

	if len(rcptTo) == 0 {
		return nil, fmt.Errorf("need at least one recipient")
	}

	if c.origConn == nil {
		return nil, ErrClosed
	} else if c.botched {
		return nil, ErrBotched
	} else if c.needRset {
		if err := c.Reset(); err != nil {
			return nil, err
		}
	}

	if !c.ext8bitmime && req8bitmime {
		c.xerrorf(true, 0, "", "", nil, "%w", Err8bitmimeUnsupported)
	}
	if !c.extSMTPUTF8 && reqSMTPUTF8 {
		// ../rfc/6531:313
		c.xerrorf(false, 0, "", "", nil, "%w", ErrSMTPUTF8Unsupported)
	}
	if !c.extRequireTLS && requireTLS {
		c.xerrorf(false, 0, "", "", nil, "%w", ErrRequireTLSUnsupported)
	}

	// Max size enforced, only when not zero. ../rfc/1870:79
	if c.extSize && c.maxSize > 0 && msgSize > c.maxSize {
		c.xerrorf(true, 0, "", "", nil, "%w: message is %d bytes, remote has a %d bytes maximum size", ErrSize, msgSize, c.maxSize)
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
	var requiretlsArg string
	if requireTLS {
		// ../rfc/8689:155
		requiretlsArg = " REQUIRETLS"
	}

	// Transaction overview: ../rfc/5321:1015
	// MAIL FROM: ../rfc/5321:1879
	// RCPT TO: ../rfc/5321:1916
	// DATA: ../rfc/5321:1992
	lineMailFrom := fmt.Sprintf("MAIL FROM:<%s>%s%s%s%s", mailFrom, mailSize, bodyType, smtputf8Arg, requiretlsArg)

	// We are going into a transaction. We'll clear this when done.
	c.needRset = true

	if c.extPipelining {
		c.cmds = make([]string, 1+len(rcptTo)+1)
		c.cmds[0] = "mailfrom"
		for i := range rcptTo {
			c.cmds[1+i] = "rcptto"
		}
		c.cmds[len(c.cmds)-1] = "data"
		c.cmdStart = time.Now()

		// Write and read in separte goroutines. Otherwise, writing a large recipient list
		// could block when a server doesn't read more commands before we read their
		// response.
		errc := make(chan error, 1)
		// Make sure we don't return before we're done writing to the connection.
		defer func() {
			if errc != nil {
				<-errc
			}
		}()
		go func() {
			var b bytes.Buffer
			b.WriteString(lineMailFrom)
			b.WriteString("\r\n")
			for _, rcpt := range rcptTo {
				b.WriteString("RCPT TO:<")
				b.WriteString(rcpt)
				b.WriteString(">\r\n")
			}
			b.WriteString("DATA\r\n")
			_, err := c.w.Write(b.Bytes())
			if err == nil {
				err = c.w.Flush()
			}
			errc <- err
		}()

		// Read response to MAIL FROM.
		mfcode, mfsecode, mffirstLine, mfmoreLines := c.xread()

		// We read the response to RCPT TOs and DATA without panic on read error. Servers
		// may be aborting the connection after a failed MAIL FROM, e.g. outlook when it
		// has blocklisted your IP. We don't want the read for the response to RCPT TO to
		// cause a read error as it would result in an unhelpful error message and a
		// temporary instead of permanent error code.

		// Read responses to RCPT TO.
		rcptResps = make([]Response, len(rcptTo))
		nok := 0
		for i := range rcptTo {
			code, secode, firstLine, moreLines, err := c.read()
			// 552 should be treated as temporary historically, ../rfc/5321:3576
			permanent := code/100 == 5 && code != smtp.C552MailboxFull
			rcptResps[i] = Response{permanent, code, secode, "rcptto", firstLine, moreLines, err}
			if code == smtp.C250Completed {
				nok++
			}
		}

		// Read response to DATA.
		datacode, datasecode, datafirstLine, datamoreLines, dataerr := c.read()

		writeerr := <-errc
		errc = nil

		// If MAIL FROM failed, it's an error for the entire transaction. We may have been
		// blocked.
		if mfcode != smtp.C250Completed {
			if writeerr != nil || dataerr != nil {
				c.botched = true
			}
			c.xerrorf(mfcode/100 == 5, mfcode, mfsecode, mffirstLine, mfmoreLines, "%w: got %d, expected 2xx", ErrStatus, mfcode)
		}

		// If there was an i/o error writing the commands, there is no point continuing.
		if writeerr != nil {
			c.xbotchf(0, "", "", nil, "writing pipelined mail/rcpt/data: %w", writeerr)
		}

		// If remote closed the connection before writing a DATA response, and the RCPT
		// TO's failed (e.g. after deciding we're on a blocklist), use the last response
		// for a rcptto as result.
		if dataerr != nil && errors.Is(dataerr, io.ErrUnexpectedEOF) && nok == 0 {
			c.botched = true
			r := rcptResps[len(rcptResps)-1]
			c.xerrorf(r.Permanent, r.Code, r.Secode, r.Line, r.MoreLines, "%w: server closed connection just before responding to data command", ErrStatus)
		}

		// If the data command had an i/o or protocol error, it's also a failure for the
		// entire transaction.
		if dataerr != nil {
			panic(dataerr)
		}

		// If we didn't have any successful recipient, there is no point in continuing.
		if nok == 0 {
			// Servers may return success for a DATA without valid recipients. Write a dot to
			// end DATA and restore the connection to a known state.
			// ../rfc/2920:328
			if datacode == smtp.C354Continue {
				_, doterr := fmt.Fprintf(c.w, ".\r\n")
				if doterr == nil {
					doterr = c.w.Flush()
				}
				if doterr == nil {
					_, _, _, _, doterr = c.read()
				}
				if doterr != nil {
					c.botched = true
				}
			}

			if len(rcptTo) == 1 {
				panic(Error(rcptResps[0]))
			}
			c.xerrorf(false, 0, "", "", nil, "%w", errNoRecipientsPipelined)
		}

		if datacode != smtp.C354Continue {
			c.xerrorf(datacode/100 == 5, datacode, datasecode, datafirstLine, datamoreLines, "%w: got %d, expected 354", ErrStatus, datacode)
		}

	} else {
		c.cmds[0] = "mailfrom"
		c.cmdStart = time.Now()
		c.xwriteline(lineMailFrom)
		code, secode, firstLine, moreLines := c.xread()
		if code != smtp.C250Completed {
			c.xerrorf(code/100 == 5, code, secode, firstLine, moreLines, "%w: got %d, expected 2xx", ErrStatus, code)
		}

		rcptResps = make([]Response, len(rcptTo))
		nok := 0
		for i, rcpt := range rcptTo {
			c.cmds[0] = "rcptto"
			c.cmdStart = time.Now()
			c.xwriteline(fmt.Sprintf("RCPT TO:<%s>", rcpt))
			code, secode, firstLine, moreLines = c.xread()
			if i > 0 && (code == smtp.C452StorageFull || code == smtp.C552MailboxFull) {
				// Remote doesn't accept more recipients for this transaction. Don't send more, give
				// remaining recipients the same error result.
				for j := i; j < len(rcptTo); j++ {
					rcptResps[j] = Response{false, code, secode, "rcptto", firstLine, moreLines, fmt.Errorf("no more recipients accepted in transaction")}
				}
				break
			}
			var err error
			if code == smtp.C250Completed {
				nok++
			} else {
				err = fmt.Errorf("%w: got %d, expected 2xx", ErrStatus, code)
			}
			rcptResps[i] = Response{code/100 == 5, code, secode, "rcptto", firstLine, moreLines, err}
		}

		if nok == 0 {
			if len(rcptTo) == 1 {
				panic(Error(rcptResps[0]))
			}
			c.xerrorf(false, 0, "", "", nil, "%w", errNoRecipients)
		}

		c.cmds[0] = "data"
		c.cmdStart = time.Now()
		c.xwriteline("DATA")
		code, secode, firstLine, moreLines = c.xread()
		if code != smtp.C354Continue {
			c.xerrorf(code/100 == 5, code, secode, firstLine, moreLines, "%w: got %d, expected 354", ErrStatus, code)
		}
	}

	// For a DATA write, the suggested timeout is 3 minutes, we use 30 seconds for all
	// writes through timeoutWriter. ../rfc/5321:3651
	defer c.xtrace(mlog.LevelTracedata)()
	err := smtp.DataWrite(c.w, msg)
	if err != nil {
		c.xbotchf(0, "", "", nil, "writing message as smtp data: %w", err)
	}
	c.xflush()
	c.xtrace(mlog.LevelTrace) // Restore.
	code, secode, firstLine, moreLines := c.xread()
	if code != smtp.C250Completed {
		c.xerrorf(code/100 == 5, code, secode, firstLine, moreLines, "%w: got %d, expected 2xx", ErrStatus, code)
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
	code, secode, firstLine, moreLines := c.xread()
	if code != smtp.C250Completed {
		c.xerrorf(code/100 == 5, code, secode, firstLine, moreLines, "%w: got %d, expected 2xx", ErrStatus, code)
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
// If the connection is initialized and not botched, a QUIT command is sent and the
// response read with a short timeout before closing the underlying connection.
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
		} else if _, err := bufs.Readline(c.log, c.r); err != nil {
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

// Conn returns the connection with the initialized SMTP session, possibly wrapping
// a TLS connection, and handling protocol trace logging. Once the caller uses this
// connection it is in control, and responsible for closing the connection, and
// other functions on the client must not be called anymore.
func (c *Client) Conn() (net.Conn, error) {
	if err := c.conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clearing io deadlines: %w", err)
	}
	return c.conn, nil
}
