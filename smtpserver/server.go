// Package smtpserver implements an SMTP server for submission and incoming delivery of mail messages.
package smtpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math"
	"net"
	"net/textproto"
	"os"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/exp/maps"
	"golang.org/x/text/unicode/norm"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/iprev"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/ratelimit"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
)

// We use panic and recover for error handling while executing commands.
// These errors signal the connection must be closed.
var errIO = errors.New("io error")

// If set, regular delivery/submit is sidestepped, email is accepted and
// delivered to the account named mox.
var Localserve bool

var limiterConnectionRate, limiterConnections *ratelimit.Limiter

// For delivery rate limiting. Variable because changed during tests.
var limitIPMasked1MessagesPerMinute int = 500
var limitIPMasked1SizePerMinute int64 = 1000 * 1024 * 1024

// Maximum number of RCPT TO commands (i.e. recipients) for a single message
// delivery. Must be at least 100. Announced in LIMIT extension.
const rcptToLimit = 1000

func init() {
	// Also called by tests, so they don't trigger the rate limiter.
	limitersInit()
}

func limitersInit() {
	mox.LimitersInit()
	// todo future: make these configurable
	limiterConnectionRate = &ratelimit.Limiter{
		WindowLimits: []ratelimit.WindowLimit{
			{
				Window: time.Minute,
				Limits: [...]int64{300, 900, 2700},
			},
		},
	}
	limiterConnections = &ratelimit.Limiter{
		WindowLimits: []ratelimit.WindowLimit{
			{
				Window: time.Duration(math.MaxInt64), // All of time.
				Limits: [...]int64{30, 90, 270},
			},
		},
	}
}

var (
	// Delays for bad/suspicious behaviour. Zero during tests.
	badClientDelay              = time.Second      // Before reads and after 1-byte writes for probably spammers.
	authFailDelay               = time.Second      // Response to authentication failure.
	unknownRecipientsDelay      = 5 * time.Second  // Response when all recipients are unknown.
	firstTimeSenderDelayDefault = 15 * time.Second // Before accepting message from first-time sender.
)

type codes struct {
	code   int
	secode string // Enhanced code, but without the leading major int from code.
}

var (
	metricConnection = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_smtpserver_connection_total",
			Help: "Incoming SMTP connections.",
		},
		[]string{
			"kind", // "deliver" or "submit"
		},
	)
	metricCommands = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_smtpserver_command_duration_seconds",
			Help:    "SMTP server command duration and result codes in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30, 60, 120},
		},
		[]string{
			"kind", // "deliver" or "submit"
			"cmd",
			"code",
			"ecode",
		},
	)
	metricDelivery = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_smtpserver_delivery_total",
			Help: "SMTP incoming message delivery from external source, not submission. Result values: delivered, reject, unknownuser, accounterror, delivererror. Reason indicates why a message was rejected/accepted.",
		},
		[]string{
			"result",
			"reason",
		},
	)
	// Similar between ../webmail/webmail.go:/metricSubmission and ../smtpserver/server.go:/metricSubmission and ../webapisrv/server.go:/metricSubmission
	metricSubmission = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_smtpserver_submission_total",
			Help: "SMTP server incoming submission results, known values (those ending with error are server errors): ok, badmessage, badfrom, badheader, messagelimiterror, recipientlimiterror, localserveerror, queueerror.",
		},
		[]string{
			"result",
		},
	)
	metricServerErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_smtpserver_errors_total",
			Help: "SMTP server errors, known values: dkimsign, queuedsn.",
		},
		[]string{
			"error",
		},
	)
)

var jitterRand = mox.NewPseudoRand()

func durationDefault(delay *time.Duration, def time.Duration) time.Duration {
	if delay == nil {
		return def
	}
	return *delay
}

// Listen initializes network listeners for incoming SMTP connection.
// The listeners are stored for a later call to Serve.
func Listen() {
	names := maps.Keys(mox.Conf.Static.Listeners)
	sort.Strings(names)
	for _, name := range names {
		listener := mox.Conf.Static.Listeners[name]

		var tlsConfig, tlsConfigDelivery *tls.Config
		if listener.TLS != nil {
			tlsConfig = listener.TLS.Config
			// For SMTP delivery, if we get a TLS handshake for an SNI hostname that we don't
			// allow, we'll fallback to a certificate for the listener hostname instead of
			// causing the connection to fail. May improve interoperability.
			tlsConfigDelivery = listener.TLS.ConfigFallback
		}

		maxMsgSize := listener.SMTPMaxMessageSize
		if maxMsgSize == 0 {
			maxMsgSize = config.DefaultMaxMsgSize
		}

		if listener.SMTP.Enabled {
			hostname := mox.Conf.Static.HostnameDomain
			if listener.Hostname != "" {
				hostname = listener.HostnameDomain
			}
			port := config.Port(listener.SMTP.Port, 25)
			for _, ip := range listener.IPs {
				firstTimeSenderDelay := durationDefault(listener.SMTP.FirstTimeSenderDelay, firstTimeSenderDelayDefault)
				listen1("smtp", name, ip, port, hostname, tlsConfigDelivery, false, false, maxMsgSize, false, listener.SMTP.RequireSTARTTLS, !listener.SMTP.NoRequireTLS, listener.SMTP.DNSBLZones, firstTimeSenderDelay)
			}
		}
		if listener.Submission.Enabled {
			hostname := mox.Conf.Static.HostnameDomain
			if listener.Hostname != "" {
				hostname = listener.HostnameDomain
			}
			port := config.Port(listener.Submission.Port, 587)
			for _, ip := range listener.IPs {
				listen1("submission", name, ip, port, hostname, tlsConfig, true, false, maxMsgSize, !listener.Submission.NoRequireSTARTTLS, !listener.Submission.NoRequireSTARTTLS, true, nil, 0)
			}
		}

		if listener.Submissions.Enabled {
			hostname := mox.Conf.Static.HostnameDomain
			if listener.Hostname != "" {
				hostname = listener.HostnameDomain
			}
			port := config.Port(listener.Submissions.Port, 465)
			for _, ip := range listener.IPs {
				listen1("submissions", name, ip, port, hostname, tlsConfig, true, true, maxMsgSize, true, true, true, nil, 0)
			}
		}
	}
}

var servers []func()

func listen1(protocol, name, ip string, port int, hostname dns.Domain, tlsConfig *tls.Config, submission, xtls bool, maxMessageSize int64, requireTLSForAuth, requireTLSForDelivery, requireTLS bool, dnsBLs []dns.Domain, firstTimeSenderDelay time.Duration) {
	log := mlog.New("smtpserver", nil)
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	if os.Getuid() == 0 {
		log.Print("listening for smtp",
			slog.String("listener", name),
			slog.String("address", addr),
			slog.String("protocol", protocol))
	}
	network := mox.Network(ip)
	ln, err := mox.Listen(network, addr)
	if err != nil {
		log.Fatalx("smtp: listen for smtp", err, slog.String("protocol", protocol), slog.String("listener", name))
	}
	if xtls {
		ln = tls.NewListener(ln, tlsConfig)
	}

	serve := func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Infox("smtp: accept", err, slog.String("protocol", protocol), slog.String("listener", name))
				continue
			}

			// Package is set on the resolver by the dkim/spf/dmarc/etc packages.
			resolver := dns.StrictResolver{Log: log.Logger}
			go serve(name, mox.Cid(), hostname, tlsConfig, conn, resolver, submission, xtls, maxMessageSize, requireTLSForAuth, requireTLSForDelivery, requireTLS, dnsBLs, firstTimeSenderDelay)
		}
	}

	servers = append(servers, serve)
}

// Serve starts serving on all listeners, launching a goroutine per listener.
func Serve() {
	for _, serve := range servers {
		go serve()
	}
}

type conn struct {
	cid int64

	// OrigConn is the original (TCP) connection. We'll read from/write to conn, which
	// can be wrapped in a tls.Server. We close origConn instead of conn because
	// closing the TLS connection would send a TLS close notification, which may block
	// for 5s if the server isn't reading it (because it is also sending it).
	origConn net.Conn
	conn     net.Conn

	tls                   bool
	extRequireTLS         bool // Whether to announce and allow the REQUIRETLS extension.
	resolver              dns.Resolver
	r                     *bufio.Reader
	w                     *bufio.Writer
	tr                    *moxio.TraceReader // Kept for changing trace level during cmd/auth/data.
	tw                    *moxio.TraceWriter
	slow                  bool      // If set, reads are done with a 1 second sleep, and writes are done 1 byte at a time, to keep spammers busy.
	lastlog               time.Time // Used for printing the delta time since the previous logging for this connection.
	submission            bool      // ../rfc/6409:19 applies
	tlsConfig             *tls.Config
	localIP               net.IP
	remoteIP              net.IP
	hostname              dns.Domain
	log                   mlog.Log
	maxMessageSize        int64
	requireTLSForAuth     bool
	requireTLSForDelivery bool      // If set, delivery is only allowed with TLS (STARTTLS), except if delivery is to a TLS reporting address.
	cmd                   string    // Current command.
	cmdStart              time.Time // Start of current command.
	ncmds                 int       // Number of commands processed. Used to abort connection when first incoming command is unknown/invalid.
	dnsBLs                []dns.Domain
	firstTimeSenderDelay  time.Duration

	// If non-zero, taken into account during Read and Write. Set while processing DATA
	// command, we don't want the entire delivery to take too long.
	deadline time.Time

	hello dns.IPDomain // Claimed remote name. Can be ip address for ehlo.
	ehlo  bool         // If set, we had EHLO instead of HELO.

	authFailed int            // Number of failed auth attempts. For slowing down remote with many failures.
	username   string         // Only when authenticated.
	account    *store.Account // Only when authenticated.

	// We track good/bad message transactions to disconnect spammers trying to guess addresses.
	transactionGood int
	transactionBad  int

	// Message transaction.
	mailFrom             *smtp.Path
	requireTLS           *bool     // MAIL FROM with REQUIRETLS set.
	futureRelease        time.Time // MAIL FROM with HOLDFOR or HOLDUNTIL.
	futureReleaseRequest string    // For use in DSNs, either "for;" or "until;" plus original value. ../rfc/4865:305
	has8bitmime          bool      // If MAIL FROM parameter BODY=8BITMIME was sent. Required for SMTPUTF8.
	smtputf8             bool      // todo future: we should keep track of this per recipient. perhaps only a specific recipient requires smtputf8, e.g. due to a utf8 localpart.
	msgsmtputf8          bool      // Is SMTPUTF8 required for the received message. Default to the same value as `smtputf8`, but is re-evaluated after the whole message (envelope and data) is received.
	recipients           []recipient
}

type rcptAccount struct {
	accountName      string
	destination      config.Destination
	canonicalAddress string // Optional catchall part stripped and/or lowercased.
}

type rcptAlias struct {
	alias            config.Alias
	canonicalAddress string // Optional catchall part stripped and/or lowercased.
}

type recipient struct {
	addr smtp.Path

	// If account and alias are both not set, this is not for a local address. This is
	// normal for submission, where messages are added to the queue. For incoming
	// deliveries, this will result in an error.
	account *rcptAccount // If set, recipient address is for this local account.
	alias   *rcptAlias   // If set, for a local alias.
}

func isClosed(err error) bool {
	return errors.Is(err, errIO) || moxio.IsClosed(err)
}

// completely reset connection state as if greeting has just been sent.
// ../rfc/3207:210
func (c *conn) reset() {
	c.ehlo = false
	c.hello = dns.IPDomain{}
	c.username = ""
	if c.account != nil {
		err := c.account.Close()
		c.log.Check(err, "closing account")
	}
	c.account = nil
	c.rset()
}

// for rset command, and a few more cases that reset the mail transaction state.
// ../rfc/5321:2502
func (c *conn) rset() {
	c.mailFrom = nil
	c.requireTLS = nil
	c.futureRelease = time.Time{}
	c.futureReleaseRequest = ""
	c.has8bitmime = false
	c.smtputf8 = false
	c.msgsmtputf8 = false
	c.recipients = nil
}

func (c *conn) earliestDeadline(d time.Duration) time.Time {
	e := time.Now().Add(d)
	if !c.deadline.IsZero() && c.deadline.Before(e) {
		return c.deadline
	}
	return e
}

func (c *conn) xcheckAuth() {
	if c.submission && c.account == nil {
		// ../rfc/4954:623
		xsmtpUserErrorf(smtp.C530SecurityRequired, smtp.SePol7Other0, "authentication required")
	}
}

func (c *conn) xtrace(level slog.Level) func() {
	c.xflush()
	c.tr.SetTrace(level)
	c.tw.SetTrace(level)
	return func() {
		c.xflush()
		c.tr.SetTrace(mlog.LevelTrace)
		c.tw.SetTrace(mlog.LevelTrace)
	}
}

// setSlow marks the connection slow (or now), so reads are done with 3 second
// delay for each read, and writes are done at 1 byte per second, to try to slow
// down spammers.
func (c *conn) setSlow(on bool) {
	if on && !c.slow {
		c.log.Debug("connection changed to slow")
	} else if !on && c.slow {
		c.log.Debug("connection restored to regular pace")
	}
	c.slow = on
}

// Write writes to the connection. It panics on i/o errors, which is handled by the
// connection command loop.
func (c *conn) Write(buf []byte) (int, error) {
	chunk := len(buf)
	if c.slow {
		chunk = 1
	}

	// We set a single deadline for Write and Read. This may be a TLS connection.
	// SetDeadline works on the underlying connection. If we wouldn't touch the read
	// deadline, and only set the write deadline and do a bunch of writes, the TLS
	// library would still have to do reads on the underlying connection, and may reach
	// a read deadline that was set for some earlier read.
	// We have one deadline for the whole write. In case of slow writing, we'll write
	// the last chunk in one go, so remote smtp clients don't abort the connection for
	// being slow.
	deadline := c.earliestDeadline(30 * time.Second)
	if err := c.conn.SetDeadline(deadline); err != nil {
		c.log.Errorx("setting deadline for write", err)
	}

	var n int
	for len(buf) > 0 {
		nn, err := c.conn.Write(buf[:chunk])
		if err != nil {
			panic(fmt.Errorf("write: %s (%w)", err, errIO))
		}
		n += nn
		buf = buf[chunk:]
		if len(buf) > 0 && badClientDelay > 0 {
			mox.Sleep(mox.Context, badClientDelay)

			// Make sure we don't take too long, otherwise the remote SMTP client may close the
			// connection.
			if time.Until(deadline) < 2*badClientDelay {
				chunk = len(buf)
			}
		}
	}
	return n, nil
}

// Read reads from the connection. It panics on i/o errors, which is handled by the
// connection command loop.
func (c *conn) Read(buf []byte) (int, error) {
	if c.slow && badClientDelay > 0 {
		mox.Sleep(mox.Context, badClientDelay)
	}

	// todo future: make deadline configurable for callers, and through config file? ../rfc/5321:3610 ../rfc/6409:492
	// See comment about Deadline instead of individual read/write deadlines at Write.
	if err := c.conn.SetDeadline(c.earliestDeadline(30 * time.Second)); err != nil {
		c.log.Errorx("setting deadline for read", err)
	}

	n, err := c.conn.Read(buf)
	if err != nil {
		panic(fmt.Errorf("read: %s (%w)", err, errIO))
	}
	return n, err
}

// Cache of line buffers for reading commands.
// Filled on demand.
var bufpool = moxio.NewBufpool(8, 2*1024)

func (c *conn) readline() string {
	line, err := bufpool.Readline(c.log, c.r)
	if err != nil && errors.Is(err, moxio.ErrLineTooLong) {
		c.writecodeline(smtp.C500BadSyntax, smtp.SeProto5Other0, "line too long, smtp max is 512, we reached 2048", nil)
		panic(fmt.Errorf("%s (%w)", err, errIO))
	} else if err != nil {
		panic(fmt.Errorf("%s (%w)", err, errIO))
	}
	return line
}

// Buffered-write command response line to connection with codes and msg.
// Err is not sent to remote but is used for logging and can be empty.
func (c *conn) bwritecodeline(code int, secode string, msg string, err error) {
	var ecode string
	if secode != "" {
		ecode = fmt.Sprintf("%d.%s", code/100, secode)
	}
	metricCommands.WithLabelValues(c.kind(), c.cmd, fmt.Sprintf("%d", code), ecode).Observe(float64(time.Since(c.cmdStart)) / float64(time.Second))
	c.log.Debugx("smtp command result", err,
		slog.String("kind", c.kind()),
		slog.String("cmd", c.cmd),
		slog.Int("code", code),
		slog.String("ecode", ecode),
		slog.Duration("duration", time.Since(c.cmdStart)))

	var sep string
	if ecode != "" {
		sep = " "
	}

	// Separate by newline and wrap long lines.
	lines := strings.Split(msg, "\n")
	for i, line := range lines {
		// ../rfc/5321:3506 ../rfc/5321:2583 ../rfc/5321:2756
		var prelen = 3 + 1 + len(ecode) + len(sep)
		for prelen+len(line) > 510 {
			e := 510 - prelen
			for ; e > 400 && line[e] != ' '; e-- {
			}
			// todo future: understand if ecode should be on each line. won't hurt. at least as long as we don't do expn or vrfy.
			c.bwritelinef("%d-%s%s%s", code, ecode, sep, line[:e])
			line = line[e:]
		}
		spdash := " "
		if i < len(lines)-1 {
			spdash = "-"
		}
		c.bwritelinef("%d%s%s%s%s", code, spdash, ecode, sep, line)
	}
}

// Buffered-write a formatted response line to connection.
func (c *conn) bwritelinef(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprint(c.w, msg+"\r\n")
}

// Flush pending buffered writes to connection.
func (c *conn) xflush() {
	c.w.Flush() // Errors will have caused a panic in Write.
}

// Write (with flush) a response line with codes and message. err is not written, used for logging and can be nil.
func (c *conn) writecodeline(code int, secode string, msg string, err error) {
	c.bwritecodeline(code, secode, msg, err)
	c.xflush()
}

// Write (with flush) a formatted response line to connection.
func (c *conn) writelinef(format string, args ...any) {
	c.bwritelinef(format, args...)
	c.xflush()
}

var cleanClose struct{} // Sentinel value for panic/recover indicating clean close of connection.

func serve(listenerName string, cid int64, hostname dns.Domain, tlsConfig *tls.Config, nc net.Conn, resolver dns.Resolver, submission, tls bool, maxMessageSize int64, requireTLSForAuth, requireTLSForDelivery, requireTLS bool, dnsBLs []dns.Domain, firstTimeSenderDelay time.Duration) {
	var localIP, remoteIP net.IP
	if a, ok := nc.LocalAddr().(*net.TCPAddr); ok {
		localIP = a.IP
	} else {
		// For net.Pipe, during tests.
		localIP = net.ParseIP("127.0.0.10")
	}
	if a, ok := nc.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = a.IP
	} else {
		// For net.Pipe, during tests.
		remoteIP = net.ParseIP("127.0.0.10")
	}

	c := &conn{
		cid:                   cid,
		origConn:              nc,
		conn:                  nc,
		submission:            submission,
		tls:                   tls,
		extRequireTLS:         requireTLS,
		resolver:              resolver,
		lastlog:               time.Now(),
		tlsConfig:             tlsConfig,
		localIP:               localIP,
		remoteIP:              remoteIP,
		hostname:              hostname,
		maxMessageSize:        maxMessageSize,
		requireTLSForAuth:     requireTLSForAuth,
		requireTLSForDelivery: requireTLSForDelivery,
		dnsBLs:                dnsBLs,
		firstTimeSenderDelay:  firstTimeSenderDelay,
	}
	var logmutex sync.Mutex
	c.log = mlog.New("smtpserver", nil).WithFunc(func() []slog.Attr {
		logmutex.Lock()
		defer logmutex.Unlock()
		now := time.Now()
		l := []slog.Attr{
			slog.Int64("cid", c.cid),
			slog.Duration("delta", now.Sub(c.lastlog)),
		}
		c.lastlog = now
		if c.username != "" {
			l = append(l, slog.String("username", c.username))
		}
		return l
	})
	c.tr = moxio.NewTraceReader(c.log, "RC: ", c)
	c.tw = moxio.NewTraceWriter(c.log, "LS: ", c)
	c.r = bufio.NewReader(c.tr)
	c.w = bufio.NewWriter(c.tw)

	metricConnection.WithLabelValues(c.kind()).Inc()
	c.log.Info("new connection",
		slog.Any("remote", c.conn.RemoteAddr()),
		slog.Any("local", c.conn.LocalAddr()),
		slog.Bool("submission", submission),
		slog.Bool("tls", tls),
		slog.String("listener", listenerName))

	defer func() {
		c.origConn.Close() // Close actual TCP socket, regardless of TLS on top.
		c.conn.Close()     // If TLS, will try to write alert notification to already closed socket, returning error quickly.

		if c.account != nil {
			err := c.account.Close()
			c.log.Check(err, "closing account")
			c.account = nil
		}

		x := recover()
		if x == nil || x == cleanClose {
			c.log.Info("connection closed")
		} else if err, ok := x.(error); ok && isClosed(err) {
			c.log.Infox("connection closed", err)
		} else {
			c.log.Error("unhandled panic", slog.Any("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Smtpserver)
		}
	}()

	select {
	case <-mox.Shutdown.Done():
		// ../rfc/5321:2811 ../rfc/5321:1666 ../rfc/3463:420
		c.writecodeline(smtp.C421ServiceUnavail, smtp.SeSys3NotAccepting2, "shutting down", nil)
		return
	default:
	}

	if !limiterConnectionRate.Add(c.remoteIP, time.Now(), 1) {
		c.writecodeline(smtp.C421ServiceUnavail, smtp.SePol7Other0, "connection rate from your ip or network too high, slow down please", nil)
		return
	}

	// If remote IP/network resulted in too many authentication failures, refuse to serve.
	if submission && !mox.LimiterFailedAuth.CanAdd(c.remoteIP, time.Now(), 1) {
		metrics.AuthenticationRatelimitedInc("submission")
		c.log.Debug("refusing connection due to many auth failures", slog.Any("remoteip", c.remoteIP))
		c.writecodeline(smtp.C421ServiceUnavail, smtp.SePol7Other0, "too many auth failures", nil)
		return
	}

	if !limiterConnections.Add(c.remoteIP, time.Now(), 1) {
		c.log.Debug("refusing connection due to many open connections", slog.Any("remoteip", c.remoteIP))
		c.writecodeline(smtp.C421ServiceUnavail, smtp.SePol7Other0, "too many open connections from your ip or network", nil)
		return
	}
	defer limiterConnections.Add(c.remoteIP, time.Now(), -1)

	// We register and unregister the original connection, in case c.conn is replaced
	// with a TLS connection later on.
	mox.Connections.Register(nc, "smtp", listenerName)
	defer mox.Connections.Unregister(nc)

	// ../rfc/5321:964 ../rfc/5321:4294 about announcing software and version
	// Syntax: ../rfc/5321:2586
	// We include the string ESMTP. https://cr.yp.to/smtp/greeting.html recommends it.
	// Should not be too relevant nowadays, but does not hurt and default blackbox
	// exporter SMTP health check expects it.
	c.writelinef("%d %s ESMTP mox %s", smtp.C220ServiceReady, c.hostname.ASCII, moxvar.Version)

	for {
		command(c)

		// If another command is present, don't flush our buffered response yet. Holding
		// off will cause us to respond with a single packet.
		n := c.r.Buffered()
		if n > 0 {
			buf, err := c.r.Peek(n)
			if err == nil && bytes.IndexByte(buf, '\n') >= 0 {
				continue
			}
		}
		c.xflush()
	}
}

var commands = map[string]func(c *conn, p *parser){
	"helo":     (*conn).cmdHelo,
	"ehlo":     (*conn).cmdEhlo,
	"starttls": (*conn).cmdStarttls,
	"auth":     (*conn).cmdAuth,
	"mail":     (*conn).cmdMail,
	"rcpt":     (*conn).cmdRcpt,
	"data":     (*conn).cmdData,
	"rset":     (*conn).cmdRset,
	"vrfy":     (*conn).cmdVrfy,
	"expn":     (*conn).cmdExpn,
	"help":     (*conn).cmdHelp,
	"noop":     (*conn).cmdNoop,
	"quit":     (*conn).cmdQuit,
}

func command(c *conn) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		err, ok := x.(error)
		if !ok {
			panic(x)
		}

		if isClosed(err) {
			panic(err)
		}

		var serr smtpError
		if errors.As(err, &serr) {
			c.writecodeline(serr.code, serr.secode, fmt.Sprintf("%s (%s)", serr.errmsg, mox.ReceivedID(c.cid)), serr.err)
			if serr.printStack {
				debug.PrintStack()
			}
		} else {
			// Other type of panic, we pass it on, aborting the connection.
			c.log.Errorx("command panic", err)
			panic(err)
		}
	}()

	// todo future: we could wait for either a line or shutdown, and just close the connection on shutdown.

	line := c.readline()
	t := strings.SplitN(line, " ", 2)
	var args string
	if len(t) == 2 {
		args = " " + t[1]
	}
	cmd := t[0]
	cmdl := strings.ToLower(cmd)

	// todo future: should we return an error for lines that are too long? perhaps for submission or in a pedantic mode. we would have to take extensions for MAIL into account. ../rfc/5321:3500 ../rfc/5321:3552

	select {
	case <-mox.Shutdown.Done():
		// ../rfc/5321:2811 ../rfc/5321:1666 ../rfc/3463:420
		c.writecodeline(smtp.C421ServiceUnavail, smtp.SeSys3NotAccepting2, "shutting down", nil)
		panic(errIO)
	default:
	}

	c.cmd = cmdl
	c.cmdStart = time.Now()

	p := newParser(args, c.smtputf8, c)
	fn, ok := commands[cmdl]
	if !ok {
		c.cmd = "(unknown)"
		if c.ncmds == 0 {
			// Other side is likely speaking something else than SMTP, send error message and
			// stop processing because there is a good chance whatever they sent has multiple
			// lines.
			c.writecodeline(smtp.C500BadSyntax, smtp.SeProto5Syntax2, "please try again speaking smtp", nil)
			panic(errIO)
		}
		// note: not "command not implemented", see ../rfc/5321:2934 ../rfc/5321:2539
		xsmtpUserErrorf(smtp.C500BadSyntax, smtp.SeProto5BadCmdOrSeq1, "unknown command")
	}
	c.ncmds++
	fn(c, p)
}

// For use in metric labels.
func (c *conn) kind() string {
	if c.submission {
		return "submission"
	}
	return "smtp"
}

func (c *conn) xneedHello() {
	if c.hello.IsZero() {
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "no ehlo/helo yet")
	}
}

// If smtp server is configured to require TLS for all mail delivery (except to TLS
// reporting address), abort command.
func (c *conn) xneedTLSForDelivery(rcpt smtp.Path) {
	// For TLS reports, we allow the message in even without TLS, because there may be
	// TLS interopability problems. ../rfc/8460:316
	if c.requireTLSForDelivery && !c.tls && !isTLSReportRecipient(rcpt) {
		// ../rfc/3207:148
		xsmtpUserErrorf(smtp.C530SecurityRequired, smtp.SePol7Other0, "STARTTLS required for mail delivery")
	}
}

func isTLSReportRecipient(rcpt smtp.Path) bool {
	_, _, _, dest, err := mox.LookupAddress(rcpt.Localpart, rcpt.IPDomain.Domain, false, false)
	return err == nil && (dest.HostTLSReports || dest.DomainTLSReports)
}

func (c *conn) cmdHelo(p *parser) {
	c.cmdHello(p, false)
}

func (c *conn) cmdEhlo(p *parser) {
	c.cmdHello(p, true)
}

// ../rfc/5321:1783
func (c *conn) cmdHello(p *parser, ehlo bool) {
	var remote dns.IPDomain
	if c.submission && !mox.Pedantic {
		// Mail clients regularly put bogus information in the hostname/ip. For submission,
		// the value is of no use, so there is not much point in annoying the user with
		// errors they cannot fix themselves. Except when in pedantic mode.
		remote = dns.IPDomain{IP: c.remoteIP}
	} else {
		p.xspace()
		if ehlo {
			remote = p.xipdomain(true)
		} else {
			remote = dns.IPDomain{Domain: p.xdomain()}

			// Verify a remote domain name has an A or AAAA record, CNAME not allowed. ../rfc/5321:722
			cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
			ctx, cancel := context.WithTimeout(cidctx, time.Minute)
			_, _, err := c.resolver.LookupIPAddr(ctx, remote.Domain.ASCII+".")
			cancel()
			if dns.IsNotFound(err) {
				xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeProto5Other0, "your ehlo domain does not resolve to an IP address")
			}
			// For success or temporary resolve errors, we'll just continue.
		}
		// ../rfc/5321:1827
		// Though a few paragraphs earlier is a claim additional data can occur for address
		// literals (IP addresses), although the ABNF in that document does not allow it.
		// We allow additional text, but only if space-separated.
		if len(remote.IP) > 0 && p.space() {
			p.remainder() // ../rfc/5321:1802 ../rfc/2821:1632
		}
		p.xend()
	}

	// Reset state as if RSET command has been issued. ../rfc/5321:2093 ../rfc/5321:2453
	c.rset()

	c.ehlo = ehlo
	c.hello = remote

	// https://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml

	c.bwritelinef("250-%s", c.hostname.ASCII)
	c.bwritelinef("250-PIPELINING")                // ../rfc/2920:108
	c.bwritelinef("250-SIZE %d", c.maxMessageSize) // ../rfc/1870:70
	// ../rfc/3207:237
	if !c.tls && c.tlsConfig != nil {
		// ../rfc/3207:90
		c.bwritelinef("250-STARTTLS")
	} else if c.extRequireTLS {
		// ../rfc/8689:202
		// ../rfc/8689:143
		c.bwritelinef("250-REQUIRETLS")
	}
	if c.submission {
		// ../rfc/4954:123
		if c.tls || !c.requireTLSForAuth {
			// We always mention the SCRAM PLUS variants, even if TLS is not active: It is a
			// hint to the client that a TLS connection can use TLS channel binding during
			// authentication. The client should select the bare variant when TLS isn't
			// present, and also not indicate the server supports the PLUS variant in that
			// case, or it would trigger the mechanism downgrade detection.
			c.bwritelinef("250-AUTH SCRAM-SHA-256-PLUS SCRAM-SHA-256 SCRAM-SHA-1-PLUS SCRAM-SHA-1 CRAM-MD5 PLAIN LOGIN")
		} else {
			c.bwritelinef("250-AUTH ")
		}
		// ../rfc/4865:127
		t := time.Now().Add(queue.FutureReleaseIntervalMax).UTC() // ../rfc/4865:98
		c.bwritelinef("250-FUTURERELEASE %d %s", queue.FutureReleaseIntervalMax/time.Second, t.Format(time.RFC3339))
	}
	c.bwritelinef("250-ENHANCEDSTATUSCODES") // ../rfc/2034:71
	// todo future? c.writelinef("250-DSN")
	c.bwritelinef("250-8BITMIME")                       // ../rfc/6152:86
	c.bwritelinef("250-LIMITS RCPTMAX=%d", rcptToLimit) // ../rfc/9422:301
	c.bwritecodeline(250, "", "SMTPUTF8", nil)          // ../rfc/6531:201
	c.xflush()
}

// ../rfc/3207:96
func (c *conn) cmdStarttls(p *parser) {
	c.xneedHello()
	p.xend()

	if c.tls {
		// ../rfc/3207:235
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "already speaking tls")
	}
	if c.account != nil {
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "cannot starttls after authentication")
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

	// We add the cid to the output, to help debugging in case of a failing TLS connection.
	c.writecodeline(smtp.C220ServiceReady, smtp.SeOther00, "go! ("+mox.ReceivedID(c.cid)+")", nil)
	tlsConn := tls.Server(conn, c.tlsConfig)
	cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
	ctx, cancel := context.WithTimeout(cidctx, time.Minute)
	defer cancel()
	c.log.Debug("starting tls server handshake")
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		panic(fmt.Errorf("starttls handshake: %s (%w)", err, errIO))
	}
	cancel()
	tlsversion, ciphersuite := moxio.TLSInfo(tlsConn)
	c.log.Debug("tls server handshake done", slog.String("tls", tlsversion), slog.String("ciphersuite", ciphersuite))
	c.conn = tlsConn
	c.tr = moxio.NewTraceReader(c.log, "RC: ", c)
	c.tw = moxio.NewTraceWriter(c.log, "LS: ", c)
	c.r = bufio.NewReader(c.tr)
	c.w = bufio.NewWriter(c.tw)

	c.reset() // ../rfc/3207:210
	c.tls = true
}

// ../rfc/4954:139
func (c *conn) cmdAuth(p *parser) {
	c.xneedHello()

	if !c.submission {
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "authentication only allowed on submission ports")
	}
	if c.account != nil {
		// ../rfc/4954:152
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "already authenticated")
	}
	if c.mailFrom != nil {
		// ../rfc/4954:157
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "authentication not allowed during mail transaction")
	}

	// If authentication fails due to missing derived secrets, we don't hold it against
	// the connection. There is no way to indicate server support for an authentication
	// mechanism, but that a mechanism won't work for an account.
	var missingDerivedSecrets bool

	// For many failed auth attempts, slow down verification attempts.
	// Dropping the connection could also work, but more so when we have a connection rate limiter.
	// ../rfc/4954:770
	if c.authFailed > 3 && authFailDelay > 0 {
		// ../rfc/4954:770
		mox.Sleep(mox.Context, time.Duration(c.authFailed-3)*authFailDelay)
	}
	c.authFailed++ // Compensated on success.
	defer func() {
		if missingDerivedSecrets {
			c.authFailed--
		}
		// On the 3rd failed authentication, start responding slowly. Successful auth will
		// cause fast responses again.
		if c.authFailed >= 3 {
			c.setSlow(true)
		}
	}()

	var authVariant string
	authResult := "error"
	defer func() {
		metrics.AuthenticationInc("submission", authVariant, authResult)
		if authResult == "ok" {
			mox.LimiterFailedAuth.Reset(c.remoteIP, time.Now())
		} else if !missingDerivedSecrets {
			mox.LimiterFailedAuth.Add(c.remoteIP, time.Now(), 1)
		}
	}()

	// ../rfc/4954:699
	p.xspace()
	mech := p.xsaslMech()

	// Read the first parameter, either as initial parameter or by sending a
	// continuation with the optional encChal (must already be base64-encoded).
	xreadInitial := func(encChal string) []byte {
		var auth string
		if p.empty() {
			c.writelinef("%d %s", smtp.C334ContinueAuth, encChal) // ../rfc/4954:205
			// todo future: handle max length of 12288 octets and return proper responde codes otherwise ../rfc/4954:253
			auth = c.readline()
			if auth == "*" {
				// ../rfc/4954:193
				authResult = "aborted"
				xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5Other0, "authentication aborted")
			}
		} else {
			p.xspace()
			if !mox.Pedantic {
				// Windows Mail 16005.14326.21606.0 sends two spaces between "AUTH PLAIN" and the
				// base64 data.
				for p.space() {
				}
			}
			auth = p.remainder()
			if auth == "" {
				// ../rfc/4954:235
				xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5Syntax2, "missing initial auth base64 parameter after space")
			} else if auth == "=" {
				// ../rfc/4954:214
				auth = "" // Base64 decode below will result in empty buffer.
			}
		}
		buf, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			// ../rfc/4954:235
			xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5Syntax2, "invalid base64: %s", err)
		}
		return buf
	}

	xreadContinuation := func() []byte {
		line := c.readline()
		if line == "*" {
			authResult = "aborted"
			xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5Other0, "authentication aborted")
		}
		buf, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			// ../rfc/4954:235
			xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5Syntax2, "invalid base64: %s", err)
		}
		return buf
	}

	switch mech {
	case "PLAIN":
		authVariant = "plain"

		// ../rfc/4954:343
		// ../rfc/4954:326
		if !c.tls && c.requireTLSForAuth {
			xsmtpUserErrorf(smtp.C538EncReqForAuth, smtp.SePol7EncReqForAuth11, "authentication requires tls")
		}

		// Password is in line in plain text, so hide it.
		defer c.xtrace(mlog.LevelTraceauth)()
		buf := xreadInitial("")
		c.xtrace(mlog.LevelTrace) // Restore.
		plain := bytes.Split(buf, []byte{0})
		if len(plain) != 3 {
			xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5BadParams4, "auth data should have 3 nul-separated tokens, got %d", len(plain))
		}
		authz := norm.NFC.String(string(plain[0]))
		authc := norm.NFC.String(string(plain[1]))
		password := string(plain[2])

		if authz != "" && authz != authc {
			authResult = "badcreds"
			xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "cannot assume other role")
		}

		acc, err := store.OpenEmailAuth(c.log, authc, password)
		if err != nil && errors.Is(err, store.ErrUnknownCredentials) {
			// ../rfc/4954:274
			authResult = "badcreds"
			c.log.Info("failed authentication attempt", slog.String("username", authc), slog.Any("remote", c.remoteIP))
			xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad user/pass")
		}
		xcheckf(err, "verifying credentials")

		authResult = "ok"
		c.authFailed = 0
		c.setSlow(false)
		c.account = acc
		c.username = authc
		// ../rfc/4954:276
		c.writecodeline(smtp.C235AuthSuccess, smtp.SePol7Other0, "nice", nil)

	case "LOGIN":
		// LOGIN is obsoleted in favor of PLAIN, only implemented to support legacy
		// clients, see Internet-Draft (I-D):
		// https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00

		authVariant = "login"

		// ../rfc/4954:343
		// ../rfc/4954:326
		if !c.tls && c.requireTLSForAuth {
			xsmtpUserErrorf(smtp.C538EncReqForAuth, smtp.SePol7EncReqForAuth11, "authentication requires tls")
		}

		// Read user name. The I-D says the client should ignore the server challenge, but
		// also that some clients may require challenge "Username:" instead of "User
		// Name". We can't sent both...
		// I-D says maximum length must be 64 bytes. We allow more, for long user names
		// (domains).
		encChal := base64.StdEncoding.EncodeToString([]byte("User Name"))
		username := string(xreadInitial(encChal))
		username = norm.NFC.String(username)

		// Again, client should ignore the challenge, we send the same as the example in
		// the I-D.
		c.writelinef("%d %s", smtp.C334ContinueAuth, base64.StdEncoding.EncodeToString([]byte("Password")))

		// Password is in line in plain text, so hide it.
		defer c.xtrace(mlog.LevelTraceauth)()
		password := string(xreadContinuation())
		c.xtrace(mlog.LevelTrace) // Restore.

		acc, err := store.OpenEmailAuth(c.log, username, password)
		if err != nil && errors.Is(err, store.ErrUnknownCredentials) {
			// ../rfc/4954:274
			authResult = "badcreds"
			c.log.Info("failed authentication attempt", slog.String("username", username), slog.Any("remote", c.remoteIP))
			xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad user/pass")
		}
		xcheckf(err, "verifying credentials")

		authResult = "ok"
		c.authFailed = 0
		c.setSlow(false)
		c.account = acc
		c.username = username
		// ../rfc/4954:276
		c.writecodeline(smtp.C235AuthSuccess, smtp.SePol7Other0, "hello ancient smtp implementation", nil)

	case "CRAM-MD5":
		authVariant = strings.ToLower(mech)

		p.xempty()

		// ../rfc/2195:82
		chal := fmt.Sprintf("<%d.%d@%s>", uint64(mox.CryptoRandInt()), time.Now().UnixNano(), mox.Conf.Static.HostnameDomain.ASCII)
		c.writelinef("%d %s", smtp.C334ContinueAuth, base64.StdEncoding.EncodeToString([]byte(chal)))

		resp := xreadContinuation()
		t := strings.Split(string(resp), " ")
		if len(t) != 2 || len(t[1]) != 2*md5.Size {
			xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5BadParams4, "malformed cram-md5 response")
		}
		addr := norm.NFC.String(t[0])
		c.log.Debug("cram-md5 auth", slog.String("address", addr))
		acc, _, err := store.OpenEmail(c.log, addr)
		if err != nil {
			if errors.Is(err, store.ErrUnknownCredentials) {
				c.log.Info("failed authentication attempt", slog.String("username", addr), slog.Any("remote", c.remoteIP))
				xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad user/pass")
			}
		}
		xcheckf(err, "looking up address")
		defer func() {
			if acc != nil {
				err := acc.Close()
				c.log.Check(err, "closing account")
			}
		}()
		var ipadhash, opadhash hash.Hash
		acc.WithRLock(func() {
			err := acc.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
				password, err := bstore.QueryTx[store.Password](tx).Get()
				if err == bstore.ErrAbsent {
					c.log.Info("failed authentication attempt", slog.String("username", addr), slog.Any("remote", c.remoteIP))
					xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad user/pass")
				}
				if err != nil {
					return err
				}

				ipadhash = password.CRAMMD5.Ipad
				opadhash = password.CRAMMD5.Opad
				return nil
			})
			xcheckf(err, "tx read")
		})
		if ipadhash == nil || opadhash == nil {
			missingDerivedSecrets = true
			c.log.Info("cram-md5 auth attempt without derived secrets set, save password again to store secrets", slog.String("username", addr))
			c.log.Info("failed authentication attempt", slog.String("username", addr), slog.Any("remote", c.remoteIP))
			xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad user/pass")
		}

		// ../rfc/2195:138 ../rfc/2104:142
		ipadhash.Write([]byte(chal))
		opadhash.Write(ipadhash.Sum(nil))
		digest := fmt.Sprintf("%x", opadhash.Sum(nil))
		if digest != t[1] {
			c.log.Info("failed authentication attempt", slog.String("username", addr), slog.Any("remote", c.remoteIP))
			xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad user/pass")
		}

		authResult = "ok"
		c.authFailed = 0
		c.setSlow(false)
		c.account = acc
		acc = nil // Cancel cleanup.
		c.username = addr
		// ../rfc/4954:276
		c.writecodeline(smtp.C235AuthSuccess, smtp.SePol7Other0, "nice", nil)

	case "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1":
		// todo: improve handling of errors during scram. e.g. invalid parameters. should we abort the imap command, or continue until the end and respond with a scram-level error?
		// todo: use single implementation between ../imapserver/server.go and ../smtpserver/server.go

		// Passwords cannot be retrieved or replayed from the trace.

		authVariant = strings.ToLower(mech)
		var h func() hash.Hash
		switch authVariant {
		case "scram-sha-1", "scram-sha-1-plus":
			h = sha1.New
		case "scram-sha-256", "scram-sha-256-plus":
			h = sha256.New
		default:
			xsmtpServerErrorf(codes{smtp.C554TransactionFailed, smtp.SeSys3Other0}, "missing scram auth method case")
		}

		var cs *tls.ConnectionState
		channelBindingRequired := strings.HasSuffix(authVariant, "-plus")
		if channelBindingRequired && !c.tls {
			// ../rfc/4954:630
			xsmtpUserErrorf(smtp.C538EncReqForAuth, smtp.SePol7EncReqForAuth11, "scram plus mechanism requires tls connection")
		}
		if c.tls {
			xcs := c.conn.(*tls.Conn).ConnectionState()
			cs = &xcs
		}
		c0 := xreadInitial("")
		ss, err := scram.NewServer(h, c0, cs, channelBindingRequired)
		xcheckf(err, "starting scram")
		authc := norm.NFC.String(ss.Authentication)
		c.log.Debug("scram auth", slog.String("authentication", authc))
		acc, _, err := store.OpenEmail(c.log, authc)
		if err != nil {
			// todo: we could continue scram with a generated salt, deterministically generated
			// from the username. that way we don't have to store anything but attackers cannot
			// learn if an account exists. same for absent scram saltedpassword below.
			c.log.Info("failed authentication attempt", slog.String("username", authc), slog.Any("remote", c.remoteIP))
			xsmtpUserErrorf(smtp.C454TempAuthFail, smtp.SeSys3Other0, "scram not possible")
		}
		defer func() {
			if acc != nil {
				err := acc.Close()
				c.log.Check(err, "closing account")
			}
		}()
		if ss.Authorization != "" && ss.Authorization != ss.Authentication {
			xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "authentication with authorization for different user not supported")
		}
		var xscram store.SCRAM
		acc.WithRLock(func() {
			err := acc.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
				password, err := bstore.QueryTx[store.Password](tx).Get()
				if err == bstore.ErrAbsent {
					c.log.Info("failed authentication attempt", slog.String("username", authc), slog.Any("remote", c.remoteIP))
					xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad user/pass")
				}
				xcheckf(err, "fetching credentials")
				switch authVariant {
				case "scram-sha-1", "scram-sha-1-plus":
					xscram = password.SCRAMSHA1
				case "scram-sha-256", "scram-sha-256-plus":
					xscram = password.SCRAMSHA256
				default:
					xsmtpServerErrorf(codes{smtp.C554TransactionFailed, smtp.SeSys3Other0}, "missing scram auth credentials case")
				}
				if len(xscram.Salt) == 0 || xscram.Iterations == 0 || len(xscram.SaltedPassword) == 0 {
					missingDerivedSecrets = true
					c.log.Info("scram auth attempt without derived secrets set, save password again to store secrets", slog.String("address", authc))
					c.log.Info("failed authentication attempt", slog.String("username", authc), slog.Any("remote", c.remoteIP))
					xsmtpUserErrorf(smtp.C454TempAuthFail, smtp.SeSys3Other0, "scram not possible")
				}
				return nil
			})
			xcheckf(err, "read tx")
		})
		s1, err := ss.ServerFirst(xscram.Iterations, xscram.Salt)
		xcheckf(err, "scram first server step")
		c.writelinef("%d %s", smtp.C334ContinueAuth, base64.StdEncoding.EncodeToString([]byte(s1))) // ../rfc/4954:187
		c2 := xreadContinuation()
		s3, err := ss.Finish(c2, xscram.SaltedPassword)
		if len(s3) > 0 {
			c.writelinef("%d %s", smtp.C334ContinueAuth, base64.StdEncoding.EncodeToString([]byte(s3))) // ../rfc/4954:187
		}
		if err != nil {
			c.readline() // Should be "*" for cancellation.
			if errors.Is(err, scram.ErrInvalidProof) {
				authResult = "badcreds"
				c.log.Info("failed authentication attempt", slog.String("username", authc), slog.Any("remote", c.remoteIP))
				xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad credentials")
			}
			xcheckf(err, "server final")
		}

		// Client must still respond, but there is nothing to say. See ../rfc/9051:6221
		// The message should be empty. todo: should we require it is empty?
		xreadContinuation()

		authResult = "ok"
		c.authFailed = 0
		c.setSlow(false)
		c.account = acc
		acc = nil // Cancel cleanup.
		c.username = authc
		// ../rfc/4954:276
		c.writecodeline(smtp.C235AuthSuccess, smtp.SePol7Other0, "nice", nil)

	default:
		// ../rfc/4954:176
		xsmtpUserErrorf(smtp.C504ParamNotImpl, smtp.SeProto5BadParams4, "mechanism %s not supported", mech)
	}
}

// ../rfc/5321:1879 ../rfc/5321:1025
func (c *conn) cmdMail(p *parser) {
	// requirements for maximum line length:
	// ../rfc/5321:3500 (base max of 512 including crlf) ../rfc/4954:134 (+500) ../rfc/1870:92 (+26) ../rfc/6152:90 (none specified) ../rfc/6531:231 (+10)
	// todo future: enforce? doesn't really seem worth it...

	if c.transactionBad > 10 && c.transactionGood == 0 {
		// If we get many bad transactions, it's probably a spammer that is guessing user names.
		// Useful in combination with rate limiting.
		// ../rfc/5321:4349
		c.writecodeline(smtp.C550MailboxUnavail, smtp.SeAddr1Other0, "too many failures", nil)
		panic(errIO)
	}

	c.xneedHello()
	c.xcheckAuth()
	if c.mailFrom != nil {
		// ../rfc/5321:2507, though ../rfc/5321:1029 contradicts, implying a MAIL would also reset, but ../rfc/5321:1160 decides.
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "already have MAIL")
	}
	// Ensure clear transaction state on failure.
	defer func() {
		x := recover()
		if x != nil {
			// ../rfc/5321:2514
			c.rset()
			panic(x)
		}
	}()
	p.xtake(" FROM:")
	// note: no space allowed after colon. ../rfc/5321:1093
	// Microsoft Outlook 365 Apps for Enterprise sends it with submission. For delivery
	// it is mostly used by spammers, but has been seen with legitimate senders too.
	if !mox.Pedantic {
		p.space()
	}
	rawRevPath := p.xrawReversePath()
	paramSeen := map[string]bool{}
	for p.space() {
		// ../rfc/5321:2273
		key := p.xparamKeyword()

		K := strings.ToUpper(key)
		if paramSeen[K] {
			// e.g. ../rfc/6152:128
			xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5BadParams4, "duplicate param %q", key)
		}
		paramSeen[K] = true

		switch K {
		case "SIZE":
			p.xtake("=")
			size := p.xnumber(20, true) // ../rfc/1870:90
			if size > c.maxMessageSize {
				// ../rfc/1870:136 ../rfc/3463:382
				ecode := smtp.SeSys3MsgLimitExceeded4
				if size < config.DefaultMaxMsgSize {
					ecode = smtp.SeMailbox2MsgLimitExceeded3
				}
				xsmtpUserErrorf(smtp.C552MailboxFull, ecode, "message too large")
			}
			// We won't verify the message is exactly the size the remote claims. Buf if it is
			// larger, we'll abort the transaction when remote crosses the boundary.
		case "BODY":
			p.xtake("=")
			// ../rfc/6152:90
			v := p.xparamValue()
			switch strings.ToUpper(v) {
			case "7BIT":
				c.has8bitmime = false
			case "8BITMIME":
				c.has8bitmime = true
			default:
				xsmtpUserErrorf(smtp.C555UnrecognizedAddrParams, smtp.SeProto5BadParams4, "unrecognized parameter %q", key)
			}
		case "AUTH":
			// ../rfc/4954:455

			// We act as if we don't trust the client to specify a mailbox. Instead, we always
			// check the rfc5321.mailfrom and rfc5322.from before accepting the submission.
			// ../rfc/4954:538

			// ../rfc/4954:704
			// todo future: should we accept utf-8-addr-xtext if there is no smtputf8, and utf-8 if there is? need to find a spec ../rfc/6533:259
			p.xtake("=")
			p.xtake("<")
			p.xtext()
			p.xtake(">")
		case "SMTPUTF8":
			// ../rfc/6531:213
			c.smtputf8 = true
			c.msgsmtputf8 = true
		case "REQUIRETLS":
			// ../rfc/8689:155
			if !c.tls {
				xsmtpUserErrorf(smtp.C530SecurityRequired, smtp.SePol7EncNeeded10, "requiretls only allowed on tls-encrypted connections")
			} else if !c.extRequireTLS {
				xsmtpUserErrorf(smtp.C555UnrecognizedAddrParams, smtp.SeSys3NotSupported3, "REQUIRETLS not allowed for this connection")
			}
			v := true
			c.requireTLS = &v
		case "HOLDFOR", "HOLDUNTIL":
			// Only for submission ../rfc/4865:163
			if !c.submission {
				xsmtpUserErrorf(smtp.C555UnrecognizedAddrParams, smtp.SeSys3NotSupported3, "unrecognized parameter %q", key)
			}
			if K == "HOLDFOR" && paramSeen["HOLDUNTIL"] || K == "HOLDUNTIL" && paramSeen["HOLDFOR"] {
				// ../rfc/4865:260
				xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5BadParams4, "cannot use both HOLDUNTIL and HOLFOR")
			}
			p.xtake("=")
			// ../rfc/4865:263 ../rfc/4865:267 We are not following the advice of treating
			// semantic errors as syntax errors
			if K == "HOLDFOR" {
				n := p.xnumber(9, false) // ../rfc/4865:92
				if n > int64(queue.FutureReleaseIntervalMax/time.Second) {
					// ../rfc/4865:250
					xsmtpUserErrorf(smtp.C554TransactionFailed, smtp.SeProto5BadParams4, "future release interval too far in the future")
				}
				c.futureRelease = time.Now().Add(time.Duration(n) * time.Second)
				c.futureReleaseRequest = fmt.Sprintf("for;%d", n)
			} else {
				t, s := p.xdatetimeutc()
				ival := time.Until(t)
				if ival <= 0 {
					// Likely a mistake by the user.
					xsmtpUserErrorf(smtp.C554TransactionFailed, smtp.SeProto5BadParams4, "requested future release time is in the past")
				} else if ival > queue.FutureReleaseIntervalMax {
					// ../rfc/4865:255
					xsmtpUserErrorf(smtp.C554TransactionFailed, smtp.SeProto5BadParams4, "requested future release time is too far in the future")
				}
				c.futureRelease = t
				c.futureReleaseRequest = "until;" + s
			}
		default:
			// ../rfc/5321:2230
			xsmtpUserErrorf(smtp.C555UnrecognizedAddrParams, smtp.SeSys3NotSupported3, "unrecognized parameter %q", key)
		}
	}

	// We now know if we have to parse the address with support for utf8.
	pp := newParser(rawRevPath, c.smtputf8, c)
	rpath := pp.xbareReversePath()
	pp.xempty()
	pp = nil
	p.xend()

	// For submission, check if reverse path is allowed. I.e. authenticated account
	// must have the rpath configured. We do a check again on rfc5322.from during DATA.
	rpathAllowed := func() bool {
		// ../rfc/6409:349
		if rpath.IsZero() {
			return true
		}
		accName, _, _, _, err := mox.LookupAddress(rpath.Localpart, rpath.IPDomain.Domain, false, false)
		return err == nil && accName == c.account.Name
	}

	if !c.submission && !rpath.IPDomain.Domain.IsZero() {
		// If rpath domain has null MX record or is otherwise not accepting email, reject.
		// ../rfc/7505:181
		// ../rfc/5321:4045
		cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
		ctx, cancel := context.WithTimeout(cidctx, time.Minute)
		valid, err := checkMXRecords(ctx, c.resolver, rpath.IPDomain.Domain)
		cancel()
		if err != nil {
			c.log.Infox("temporary reject for temporary mx lookup error", err)
			xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeNet4Other0}, "cannot verify mx records for mailfrom domain")
		} else if !valid {
			c.log.Info("permanent reject because mailfrom domain does not accept mail")
			xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SePol7SenderHasNullMX27, "mailfrom domain not configured for mail")
		}
	}

	if c.submission && (len(rpath.IPDomain.IP) > 0 || !rpathAllowed()) {
		// ../rfc/6409:522
		c.log.Info("submission with unconfigured mailfrom", slog.String("user", c.username), slog.String("mailfrom", rpath.String()))
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SePol7DeliveryUnauth1, "must match authenticated user")
	} else if !c.submission && len(rpath.IPDomain.IP) > 0 {
		// todo future: allow if the IP is the same as this connection is coming from? does later code allow this?
		c.log.Info("delivery from address without domain", slog.String("mailfrom", rpath.String()))
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SePol7Other0, "domain name required")
	}

	if Localserve && strings.HasPrefix(string(rpath.Localpart), "mailfrom") {
		c.xlocalserveError(rpath.Localpart)
	}

	c.mailFrom = &rpath

	c.bwritecodeline(smtp.C250Completed, smtp.SeAddr1Other0, "looking good", nil)
}

// ../rfc/5321:1916 ../rfc/5321:1054
func (c *conn) cmdRcpt(p *parser) {
	c.xneedHello()
	c.xcheckAuth()
	if c.mailFrom == nil {
		// ../rfc/5321:1088
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "missing MAIL FROM")
	}

	// ../rfc/5321:1985
	p.xtake(" TO:")
	// note: no space allowed after colon. ../rfc/5321:1093
	// Microsoft Outlook 365 Apps for Enterprise sends it with submission. For delivery
	// it is mostly used by spammers, but has been seen with legitimate senders too.
	if !mox.Pedantic {
		p.space()
	}
	var fpath smtp.Path
	if p.take("<POSTMASTER>") {
		fpath = smtp.Path{Localpart: "postmaster"}
	} else {
		fpath = p.xforwardPath()
	}
	for p.space() {
		// ../rfc/5321:2275
		key := p.xparamKeyword()
		// K := strings.ToUpper(key)
		// todo future: DSN, ../rfc/3461, with "NOTIFY"
		// ../rfc/5321:2230
		xsmtpUserErrorf(smtp.C555UnrecognizedAddrParams, smtp.SeSys3NotSupported3, "unrecognized parameter %q", key)
	}
	p.xend()

	// Check if TLS is enabled if required. It's not great that sender/recipient
	// addresses may have been exposed in plaintext before we can reject delivery. The
	// recipient could be the tls reporting addresses, which must always be able to
	// receive in plain text.
	c.xneedTLSForDelivery(fpath)

	// todo future: for submission, should we do explicit verification that domains are fully qualified? also for mail from. ../rfc/6409:420

	if len(c.recipients) >= rcptToLimit {
		// ../rfc/5321:3535 ../rfc/5321:3571
		xsmtpUserErrorf(smtp.C452StorageFull, smtp.SeProto5TooManyRcpts3, "max of %d recipients reached", rcptToLimit)
	}

	// We don't want to allow delivery to multiple recipients with a null reverse path.
	// Why would anyone send like that? Null reverse path is intended for delivery
	// notifications, they should go to a single recipient.
	if !c.submission && len(c.recipients) > 0 && c.mailFrom.IsZero() {
		xsmtpUserErrorf(smtp.C452StorageFull, smtp.SeProto5TooManyRcpts3, "only one recipient allowed with null reverse address")
	}

	// Do not accept multiple recipients if remote does not pass SPF. Because we don't
	// want to generate DSNs to unverified domains. This is the moment we
	// can refuse individual recipients, DATA will be too late. Because mail
	// servers must handle a max recipient limit gracefully and still send to the
	// recipients that are accepted, this should not cause problems. Though we are in
	// violation because the limit must be >= 100.
	// ../rfc/5321:3598
	// ../rfc/5321:4045
	// Also see ../rfc/7489:2214
	if !c.submission && len(c.recipients) == 1 && !Localserve {
		// note: because of check above, mailFrom cannot be the null address.
		var pass bool
		d := c.mailFrom.IPDomain.Domain
		if !d.IsZero() {
			// todo: use this spf result for DATA.
			spfArgs := spf.Args{
				RemoteIP:          c.remoteIP,
				MailFromLocalpart: c.mailFrom.Localpart,
				MailFromDomain:    d,
				HelloDomain:       c.hello,
				LocalIP:           c.localIP,
				LocalHostname:     c.hostname,
			}
			cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
			spfctx, spfcancel := context.WithTimeout(cidctx, time.Minute)
			defer spfcancel()
			receivedSPF, _, _, _, err := spf.Verify(spfctx, c.log.Logger, c.resolver, spfArgs)
			spfcancel()
			if err != nil {
				c.log.Errorx("spf verify for multiple recipients", err)
			}
			pass = receivedSPF.Identity == spf.ReceivedMailFrom && receivedSPF.Result == spf.StatusPass
		}
		if !pass {
			xsmtpUserErrorf(smtp.C452StorageFull, smtp.SeProto5TooManyRcpts3, "only one recipient allowed without spf pass")
		}
	}

	if Localserve && strings.HasPrefix(string(fpath.Localpart), "rcptto") {
		c.xlocalserveError(fpath.Localpart)
	}

	if len(fpath.IPDomain.IP) > 0 {
		if !c.submission {
			xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, "not accepting email for ip")
		}
		c.recipients = append(c.recipients, recipient{fpath, nil, nil})
	} else if accountName, alias, canonical, addr, err := mox.LookupAddress(fpath.Localpart, fpath.IPDomain.Domain, true, true); err == nil {
		// note: a bare postmaster, without domain, is handled by LookupAddress. ../rfc/5321:735
		if alias != nil {
			c.recipients = append(c.recipients, recipient{fpath, nil, &rcptAlias{*alias, canonical}})
		} else {
			c.recipients = append(c.recipients, recipient{fpath, &rcptAccount{accountName, addr, canonical}, nil})
		}

	} else if Localserve {
		// If the address isn't known, and we are in localserve, deliver to the mox user.
		// If account or destination doesn't exist, it will be handled during delivery. For
		// submissions, which is the common case, we'll deliver to the logged in user,
		// which is typically the mox user.
		acc, _ := mox.Conf.Account("mox")
		dest := acc.Destinations["mox@localhost"]
		c.recipients = append(c.recipients, recipient{fpath, &rcptAccount{"mox", dest, "mox@localhost"}, nil})
	} else if errors.Is(err, mox.ErrDomainNotFound) {
		if !c.submission {
			xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, "not accepting email for domain")
		}
		// We'll be delivering this email.
		c.recipients = append(c.recipients, recipient{fpath, nil, nil})
	} else if errors.Is(err, mox.ErrAddressNotFound) {
		if c.submission {
			// For submission, we're transparent about which user exists. Should be fine for the typical small-scale deploy.
			// ../rfc/5321:1071
			xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, "no such user")
		}
		// We pretend to accept. We don't want to let remote know the user does not exist
		// until after DATA. Because then remote has committed to sending a message.
		// note: not local for !c.submission is the signal this address is in error.
		c.recipients = append(c.recipients, recipient{fpath, nil, nil})
	} else {
		c.log.Errorx("looking up account for delivery", err, slog.Any("rcptto", fpath))
		xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeSys3Other0}, "error processing")
	}
	c.bwritecodeline(smtp.C250Completed, smtp.SeAddr1Other0, "now on the list", nil)
}

// ../rfc/6531:497
func (c *conn) isSMTPUTF8Required(part *message.Part) bool {
	hasNonASCII := func(r io.Reader) bool {
		br := bufio.NewReader(r)
		for {
			b, err := br.ReadByte()
			if err == io.EOF {
				break
			}
			xcheckf(err, "read header")
			if b > unicode.MaxASCII {
				return true
			}
		}
		return false
	}
	var hasNonASCIIPartHeader func(p *message.Part) bool
	hasNonASCIIPartHeader = func(p *message.Part) bool {
		if hasNonASCII(p.HeaderReader()) {
			return true
		}
		for _, pp := range p.Parts {
			if hasNonASCIIPartHeader(&pp) {
				return true
			}
		}
		return false
	}

	// Check "MAIL FROM".
	if hasNonASCII(strings.NewReader(string(c.mailFrom.Localpart))) {
		return true
	}
	// Check all "RCPT TO".
	for _, rcpt := range c.recipients {
		if hasNonASCII(strings.NewReader(string(rcpt.addr.Localpart))) {
			return true
		}
	}
	// Check header in all message parts.
	return hasNonASCIIPartHeader(part)
}

// ../rfc/5321:1992 ../rfc/5321:1098
func (c *conn) cmdData(p *parser) {
	c.xneedHello()
	c.xcheckAuth()
	if c.mailFrom == nil {
		// ../rfc/5321:1130
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "missing MAIL FROM")
	}
	if len(c.recipients) == 0 {
		// ../rfc/5321:1130
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "missing RCPT TO")
	}

	// ../rfc/5321:2066
	p.xend()

	// todo future: we could start a reader for a single line. we would then create a context that would be canceled on i/o errors.

	// Entire delivery should be done within 30 minutes, or we abort.
	cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
	cmdctx, cmdcancel := context.WithTimeout(cidctx, 30*time.Minute)
	defer cmdcancel()
	// Deadline is taken into account by Read and Write.
	c.deadline, _ = cmdctx.Deadline()
	defer func() {
		c.deadline = time.Time{}
	}()

	// ../rfc/5321:1994
	c.writelinef("354 see you at the bare dot")

	// Mark as tracedata.
	defer c.xtrace(mlog.LevelTracedata)()

	// We read the data into a temporary file. We limit the size and do basic analysis while reading.
	dataFile, err := store.CreateMessageTemp(c.log, "smtp-deliver")
	if err != nil {
		xsmtpServerErrorf(errCodes(smtp.C451LocalErr, smtp.SeSys3Other0, err), "creating temporary file for message: %s", err)
	}
	defer store.CloseRemoveTempFile(c.log, dataFile, "smtpserver delivered message")
	msgWriter := message.NewWriter(dataFile)
	dr := smtp.NewDataReader(c.r)
	n, err := io.Copy(&limitWriter{maxSize: c.maxMessageSize, w: msgWriter}, dr)
	c.xtrace(mlog.LevelTrace) // Restore.
	if err != nil {
		if errors.Is(err, errMessageTooLarge) {
			// ../rfc/1870:136 and ../rfc/3463:382
			ecode := smtp.SeSys3MsgLimitExceeded4
			if n < config.DefaultMaxMsgSize {
				ecode = smtp.SeMailbox2MsgLimitExceeded3
			}
			c.writecodeline(smtp.C451LocalErr, ecode, fmt.Sprintf("error copying data to file (%s)", mox.ReceivedID(c.cid)), err)
			panic(fmt.Errorf("remote sent too much DATA: %w", errIO))
		}

		if errors.Is(err, smtp.ErrCRLF) {
			c.writecodeline(smtp.C500BadSyntax, smtp.SeProto5Syntax2, fmt.Sprintf("invalid bare \\r or \\n, may be smtp smuggling (%s)", mox.ReceivedID(c.cid)), err)
			return
		}

		// Something is failing on our side. We want to let remote know. So write an error response,
		// then discard the remaining data so the remote client is more likely to see our
		// response. Our write is synchronous, there is a risk no window/buffer space is
		// available and our write blocks us from reading remaining data, leading to
		// deadlock. We have a timeout on our connection writes though, so worst case we'll
		// abort the connection due to expiration.
		c.writecodeline(smtp.C451LocalErr, smtp.SeSys3Other0, fmt.Sprintf("error copying data to file (%s)", mox.ReceivedID(c.cid)), err)
		io.Copy(io.Discard, dr)
		return
	}

	// Basic sanity checks on messages before we send them out to the world. Just
	// trying to be strict in what we do to others and liberal in what we accept.
	if c.submission {
		if !msgWriter.HaveBody {
			// ../rfc/6409:541
			xsmtpUserErrorf(smtp.C554TransactionFailed, smtp.SeMsg6Other0, "message requires both header and body section")
		}
		// Check only for pedantic mode because ios mail will attempt to send smtputf8 with
		// non-ascii in message from localpart without using 8bitmime.
		if mox.Pedantic && msgWriter.Has8bit && !c.has8bitmime {
			// ../rfc/5321:906
			xsmtpUserErrorf(smtp.C500BadSyntax, smtp.SeMsg6Other0, "message with non-us-ascii requires 8bitmime extension")
		}
	}

	if Localserve && mox.Pedantic {
		// Require that message can be parsed fully.
		p, err := message.Parse(c.log.Logger, false, dataFile)
		if err == nil {
			err = p.Walk(c.log.Logger, nil)
		}
		if err != nil {
			// ../rfc/6409:541
			xsmtpUserErrorf(smtp.C554TransactionFailed, smtp.SeMsg6Other0, "malformed message: %v", err)
		}
	}

	// Now that we have all the whole message (envelope + data), we can check if the SMTPUTF8 extension is required.
	var part *message.Part
	if c.smtputf8 || c.submission || mox.Pedantic {
		// Try to parse the message.
		// Do nothing if something bad happen during Parse and Walk, just keep the current value for c.msgsmtputf8.
		p, err := message.Parse(c.log.Logger, true, dataFile)
		if err == nil {
			// Message parsed without error. Keep the result to avoid parsing the message again.
			part = &p
			err = part.Walk(c.log.Logger, nil)
			if err == nil {
				c.msgsmtputf8 = c.isSMTPUTF8Required(part)
			}
		}
		if c.smtputf8 != c.msgsmtputf8 {
			c.log.Debug("smtputf8 flag changed", slog.Bool("smtputf8", c.smtputf8), slog.Bool("msgsmtputf8", c.msgsmtputf8))
		}
	}
	if !c.smtputf8 && c.msgsmtputf8 && mox.Pedantic {
		metricSubmission.WithLabelValues("missingsmtputf8").Inc()
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeMsg6Other0, "smtputf8 extension is required but was not added to the MAIL command")
	}

	// Prepare "Received" header.
	// ../rfc/5321:2051 ../rfc/5321:3302
	// ../rfc/5321:3311 ../rfc/6531:578
	var recvFrom string
	var iprevStatus iprev.Status // Only for delivery, not submission.
	var iprevAuthentic bool
	if c.submission {
		// Hide internal hosts.
		// todo future: make this a config option, where admins specify ip ranges that they don't want exposed. also see ../rfc/5321:4321
		recvFrom = message.HeaderCommentDomain(mox.Conf.Static.HostnameDomain, c.msgsmtputf8)
	} else {
		if len(c.hello.IP) > 0 {
			recvFrom = smtp.AddressLiteral(c.hello.IP)
		} else {
			// ASCII-only version added after the extended-domain syntax below, because the
			// comment belongs to "BY" which comes immediately after "FROM".
			recvFrom = c.hello.Domain.XName(c.msgsmtputf8)
		}
		iprevctx, iprevcancel := context.WithTimeout(cmdctx, time.Minute)
		var revName string
		var revNames []string
		iprevStatus, revName, revNames, iprevAuthentic, err = iprev.Lookup(iprevctx, c.resolver, c.remoteIP)
		iprevcancel()
		if err != nil {
			c.log.Infox("reverse-forward lookup", err, slog.Any("remoteip", c.remoteIP))
		}
		c.log.Debug("dns iprev check", slog.Any("addr", c.remoteIP), slog.Any("status", iprevStatus))
		var name string
		if revName != "" {
			name = revName
		} else if len(revNames) > 0 {
			name = revNames[0]
		}
		name = strings.TrimSuffix(name, ".")
		recvFrom += " ("
		if name != "" && name != c.hello.Domain.XName(c.msgsmtputf8) {
			recvFrom += name + " "
		}
		recvFrom += smtp.AddressLiteral(c.remoteIP) + ")"
		if c.msgsmtputf8 && c.hello.Domain.Unicode != "" {
			recvFrom += " (" + c.hello.Domain.ASCII + ")"
		}
	}
	recvBy := mox.Conf.Static.HostnameDomain.XName(c.msgsmtputf8)
	recvBy += " (" + smtp.AddressLiteral(c.localIP) + ")" // todo: hide ip if internal?
	if c.msgsmtputf8 && mox.Conf.Static.HostnameDomain.Unicode != "" {
		// This syntax is part of "VIA".
		recvBy += " (" + mox.Conf.Static.HostnameDomain.ASCII + ")"
	}

	// ../rfc/3848:34 ../rfc/6531:791
	with := "SMTP"
	if c.msgsmtputf8 {
		with = "UTF8SMTP"
	} else if c.ehlo {
		with = "ESMTP"
	}
	if c.tls {
		with += "S"
	}
	if c.account != nil {
		// ../rfc/4954:660
		with += "A"
	}

	// Assume transaction does not succeed. If it does, we'll compensate.
	c.transactionBad++

	recvHdrFor := func(rcptTo string) string {
		recvHdr := &message.HeaderWriter{}
		// For additional Received-header clauses, see:
		// https://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml#table-mail-parameters-8
		withComment := ""
		if c.requireTLS != nil && *c.requireTLS {
			// Comment is actually part of ID ABNF rule. ../rfc/5321:3336
			withComment = " (requiretls)"
		}
		recvHdr.Add(" ", "Received:", "from", recvFrom, "by", recvBy, "via", "tcp", "with", with+withComment, "id", mox.ReceivedID(c.cid)) // ../rfc/5321:3158
		if c.tls {
			tlsConn := c.conn.(*tls.Conn)
			tlsComment := mox.TLSReceivedComment(c.log, tlsConn.ConnectionState())
			recvHdr.Add(" ", tlsComment...)
		}
		// We leave out an empty "for" clause. This is empty for messages submitted to
		// multiple recipients, so the message stays identical and a single smtp
		// transaction can deliver, only transferring the data once.
		if rcptTo != "" {
			recvHdr.Add(" ", "for", "<"+rcptTo+">;")
		}
		recvHdr.Add(" ", time.Now().Format(message.RFC5322Z))
		return recvHdr.String()
	}

	// Submission is easiest because user is trusted. Far fewer checks to make. So
	// handle it first, and leave the rest of the function for handling wild west
	// internet traffic.
	if c.submission {
		c.submit(cmdctx, recvHdrFor, msgWriter, dataFile, part)
	} else {
		c.deliver(cmdctx, recvHdrFor, msgWriter, iprevStatus, iprevAuthentic, dataFile)
	}
}

// Check if a message has unambiguous "TLS-Required: No" header. Messages must not
// contain multiple TLS-Required headers. The only valid value is "no". But we'll
// accept multiple headers as long as all they are all "no".
// ../rfc/8689:223
func hasTLSRequiredNo(h textproto.MIMEHeader) bool {
	l := h.Values("Tls-Required")
	if len(l) == 0 {
		return false
	}
	for _, v := range l {
		if !strings.EqualFold(v, "no") {
			return false
		}
	}
	return true
}

// submit is used for mail from authenticated users that we will try to deliver.
func (c *conn) submit(ctx context.Context, recvHdrFor func(string) string, msgWriter *message.Writer, dataFile *os.File, part *message.Part) {
	// Similar between ../smtpserver/server.go:/submit\( and ../webmail/api.go:/MessageSubmit\( and ../webapisrv/server.go:/Send\(

	var msgPrefix []byte

	// Check that user is only sending email as one of its configured identities. Not
	// for other users.
	// We don't check the Sender field, there is no expectation of verification, ../rfc/7489:2948
	// and with Resent headers it seems valid to have someone else as Sender. ../rfc/5322:1578
	msgFrom, _, header, err := message.From(c.log.Logger, true, dataFile, part)
	if err != nil {
		metricSubmission.WithLabelValues("badmessage").Inc()
		c.log.Infox("parsing message From address", err, slog.String("user", c.username))
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeMsg6Other0, "cannot parse header or From address: %v", err)
	}
	if !mox.AllowMsgFrom(c.account.Name, msgFrom) {
		// ../rfc/6409:522
		metricSubmission.WithLabelValues("badfrom").Inc()
		c.log.Infox("verifying message from address", mox.ErrAddressNotFound, slog.String("user", c.username), slog.Any("msgfrom", msgFrom))
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SePol7DeliveryUnauth1, "message from address must belong to authenticated user")
	}

	// TLS-Required: No header makes us not enforce recipient domain's TLS policy.
	// ../rfc/8689:206
	// Only when requiretls smtp extension wasn't used. ../rfc/8689:246
	if c.requireTLS == nil && hasTLSRequiredNo(header) {
		v := false
		c.requireTLS = &v
	}

	// Outgoing messages should not have a Return-Path header. The final receiving mail
	// server will add it.
	// ../rfc/5321:3233
	if mox.Pedantic && header.Values("Return-Path") != nil {
		metricSubmission.WithLabelValues("badheader").Inc()
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeMsg6Other0, "message should not have Return-Path header")
	}

	// Add Message-Id header if missing.
	// ../rfc/5321:4131 ../rfc/6409:751
	messageID := header.Get("Message-Id")
	if messageID == "" {
		messageID = mox.MessageIDGen(c.msgsmtputf8)
		msgPrefix = append(msgPrefix, fmt.Sprintf("Message-Id: <%s>\r\n", messageID)...)
	}

	// ../rfc/6409:745
	if header.Get("Date") == "" {
		msgPrefix = append(msgPrefix, "Date: "+time.Now().Format(message.RFC5322Z)+"\r\n"...)
	}

	// Check outgoing message rate limit.
	err = c.account.DB.Read(ctx, func(tx *bstore.Tx) error {
		rcpts := make([]smtp.Path, len(c.recipients))
		for i, r := range c.recipients {
			rcpts[i] = r.addr
		}
		msglimit, rcptlimit, err := c.account.SendLimitReached(tx, rcpts)
		xcheckf(err, "checking sender limit")
		if msglimit >= 0 {
			metricSubmission.WithLabelValues("messagelimiterror").Inc()
			xsmtpUserErrorf(smtp.C451LocalErr, smtp.SePol7DeliveryUnauth1, "max number of messages (%d) over past 24h reached, try increasing per-account setting MaxOutgoingMessagesPerDay", msglimit)
		} else if rcptlimit >= 0 {
			metricSubmission.WithLabelValues("recipientlimiterror").Inc()
			xsmtpUserErrorf(smtp.C451LocalErr, smtp.SePol7DeliveryUnauth1, "max number of new/first-time recipients (%d) over past 24h reached, try increasing per-account setting MaxFirstTimeRecipientsPerDay", rcptlimit)
		}
		return nil
	})
	xcheckf(err, "read-only transaction")

	// We gather any X-Mox-Extra-* headers into the "extra" data during queueing, which
	// will make it into any webhook we deliver.
	// todo: remove the X-Mox-Extra-* headers from the message. we don't currently rewrite the message...
	// todo: should we not canonicalize keys?
	var extra map[string]string
	for k, vl := range header {
		if !strings.HasPrefix(k, "X-Mox-Extra-") {
			continue
		}
		if extra == nil {
			extra = map[string]string{}
		}
		xk := k[len("X-Mox-Extra-"):]
		// We don't allow duplicate keys.
		if _, ok := extra[xk]; ok || len(vl) > 1 {
			xsmtpUserErrorf(smtp.C554TransactionFailed, smtp.SeMsg6Other0, "duplicate x-mox-extra- key %q", xk)
		}
		extra[xk] = vl[len(vl)-1]
	}

	// todo future: in a pedantic mode, we can parse the headers, and return an error if rcpt is only in To or Cc header, and not in the non-empty Bcc header. indicates a client that doesn't blind those bcc's.

	// Add DKIM signatures.
	confDom, ok := mox.Conf.Domain(msgFrom.Domain)
	if !ok {
		c.log.Error("domain disappeared", slog.Any("domain", msgFrom.Domain))
		xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeSys3Other0}, "internal error")
	}

	selectors := mox.DKIMSelectors(confDom.DKIM)
	if len(selectors) > 0 {
		canonical := mox.CanonicalLocalpart(msgFrom.Localpart, confDom)
		if dkimHeaders, err := dkim.Sign(ctx, c.log.Logger, canonical, msgFrom.Domain, selectors, c.msgsmtputf8, store.FileMsgReader(msgPrefix, dataFile)); err != nil {
			c.log.Errorx("dkim sign for domain", err, slog.Any("domain", msgFrom.Domain))
			metricServerErrors.WithLabelValues("dkimsign").Inc()
		} else {
			msgPrefix = append(msgPrefix, []byte(dkimHeaders)...)
		}
	}

	authResults := message.AuthResults{
		Hostname: mox.Conf.Static.HostnameDomain.XName(c.msgsmtputf8),
		Comment:  mox.Conf.Static.HostnameDomain.ASCIIExtra(c.msgsmtputf8),
		Methods: []message.AuthMethod{
			{
				Method: "auth",
				Result: "pass",
				Props: []message.AuthProp{
					message.MakeAuthProp("smtp", "mailfrom", c.mailFrom.XString(c.msgsmtputf8), true, c.mailFrom.ASCIIExtra(c.msgsmtputf8)),
				},
			},
		},
	}
	msgPrefix = append(msgPrefix, []byte(authResults.Header())...)

	// We always deliver through the queue. It would be more efficient to deliver
	// directly for local accounts, but we don't want to circumvent all the anti-spam
	// measures. Accounts on a single mox instance should be allowed to block each
	// other.

	accConf, _ := c.account.Conf()
	loginAddr, err := smtp.ParseAddress(c.username)
	xcheckf(err, "parsing login address")
	useFromID := slices.Contains(accConf.ParsedFromIDLoginAddresses, loginAddr)
	var localpartBase string
	var fromID string
	var genFromID bool
	if useFromID {
		// With submission, user can bring their own fromid.
		t := strings.SplitN(string(c.mailFrom.Localpart), confDom.LocalpartCatchallSeparator, 2)
		localpartBase = t[0]
		if len(t) == 2 {
			fromID = t[1]
			if fromID != "" && len(c.recipients) > 1 {
				xsmtpServerErrorf(codes{smtp.C554TransactionFailed, smtp.SeProto5TooManyRcpts3}, "cannot send to multiple recipients with chosen fromid")
			}
		} else {
			genFromID = true
		}
	}
	now := time.Now()
	qml := make([]queue.Msg, len(c.recipients))
	for i, rcpt := range c.recipients {
		if Localserve {
			code, timeout := mox.LocalserveNeedsError(rcpt.addr.Localpart)
			if timeout {
				c.log.Info("timing out submission due to special localpart")
				mox.Sleep(mox.Context, time.Hour)
				xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeSys3Other0}, "timing out submission due to special localpart")
			} else if code != 0 {
				c.log.Info("failure due to special localpart", slog.Int("code", code))
				xsmtpServerErrorf(codes{code, smtp.SeOther00}, "failure with code %d due to special localpart", code)
			}
		}

		fp := *c.mailFrom
		if useFromID {
			if genFromID {
				fromID = xrandomID(16)
			}
			fp.Localpart = smtp.Localpart(localpartBase + confDom.LocalpartCatchallSeparator + fromID)
		}

		// For multiple recipients, we don't make each message prefix unique, leaving out
		// the "for" clause in the Received header. This allows the queue to deliver the
		// messages in a single smtp transaction.
		var rcptTo string
		if len(c.recipients) == 1 {
			rcptTo = rcpt.addr.String()
		}
		xmsgPrefix := append([]byte(recvHdrFor(rcptTo)), msgPrefix...)
		msgSize := int64(len(xmsgPrefix)) + msgWriter.Size
		qm := queue.MakeMsg(fp, rcpt.addr, msgWriter.Has8bit, c.msgsmtputf8, msgSize, messageID, xmsgPrefix, c.requireTLS, now, header.Get("Subject"))
		if !c.futureRelease.IsZero() {
			qm.NextAttempt = c.futureRelease
			qm.FutureReleaseRequest = c.futureReleaseRequest
		}
		qm.FromID = fromID
		qm.Extra = extra
		qml[i] = qm
	}

	// todo: it would be good to have a limit on messages (count and total size) a user has in the queue. also/especially with futurerelease. ../rfc/4865:387
	if err := queue.Add(ctx, c.log, c.account.Name, dataFile, qml...); err != nil && errors.Is(err, queue.ErrFromID) && !genFromID {
		// todo: should we return this error during the "rcpt to" command?
		// secode is not an exact match, but seems closest.
		xsmtpServerErrorf(errCodes(smtp.C554TransactionFailed, smtp.SeAddr1SenderSyntax7, err), "bad fromid in smtp mail from address: %s", err)
	} else if err != nil {
		// Aborting the transaction is not great. But continuing and generating DSNs will
		// probably result in errors as well...
		metricSubmission.WithLabelValues("queueerror").Inc()
		c.log.Errorx("queuing message", err)
		xsmtpServerErrorf(errCodes(smtp.C451LocalErr, smtp.SeSys3Other0, err), "error delivering message: %v", err)
	}
	metricSubmission.WithLabelValues("ok").Inc()
	for i, rcpt := range c.recipients {
		c.log.Info("messages queued for delivery",
			slog.Any("mailfrom", *c.mailFrom),
			slog.Any("rcptto", rcpt.addr),
			slog.Bool("smtputf8", c.smtputf8),
			slog.Bool("msgsmtputf8", c.msgsmtputf8),
			slog.Int64("msgsize", qml[i].Size))
	}

	err = c.account.DB.Write(ctx, func(tx *bstore.Tx) error {
		for _, rcpt := range c.recipients {
			outgoing := store.Outgoing{Recipient: rcpt.addr.XString(true)}
			if err := tx.Insert(&outgoing); err != nil {
				return fmt.Errorf("adding outgoing message: %v", err)
			}
		}
		return nil
	})
	xcheckf(err, "adding outgoing messages")

	c.transactionGood++
	c.transactionBad-- // Compensate for early earlier pessimistic increase.

	c.rset()
	c.writecodeline(smtp.C250Completed, smtp.SeMailbox2Other0, "it is done", nil)
}

func xrandomID(n int) string {
	return base64.RawURLEncoding.EncodeToString(xrandom(n))
}

func xrandom(n int) []byte {
	buf := make([]byte, n)
	x, err := cryptorand.Read(buf)
	xcheckf(err, "read random")
	if x != n {
		xcheckf(errors.New("short random read"), "read random")
	}
	return buf
}

func ipmasked(ip net.IP) (string, string, string) {
	if ip.To4() != nil {
		m1 := ip.String()
		m2 := ip.Mask(net.CIDRMask(26, 32)).String()
		m3 := ip.Mask(net.CIDRMask(21, 32)).String()
		return m1, m2, m3
	}
	m1 := ip.Mask(net.CIDRMask(64, 128)).String()
	m2 := ip.Mask(net.CIDRMask(48, 128)).String()
	m3 := ip.Mask(net.CIDRMask(32, 128)).String()
	return m1, m2, m3
}

func (c *conn) xlocalserveError(lp smtp.Localpart) {
	code, timeout := mox.LocalserveNeedsError(lp)
	if timeout {
		c.log.Info("timing out due to special localpart")
		mox.Sleep(mox.Context, time.Hour)
		xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeSys3Other0}, "timing out command due to special localpart")
	} else if code != 0 {
		c.log.Info("failure due to special localpart", slog.Int("code", code))
		metricDelivery.WithLabelValues("delivererror", "localserve").Inc()
		xsmtpServerErrorf(codes{code, smtp.SeOther00}, "failure with code %d due to special localpart", code)
	}
}

// deliver is called for incoming messages from external, typically untrusted
// sources. i.e. not submitted by authenticated users.
func (c *conn) deliver(ctx context.Context, recvHdrFor func(string) string, msgWriter *message.Writer, iprevStatus iprev.Status, iprevAuthentic bool, dataFile *os.File) {
	// todo: in decision making process, if we run into (some) temporary errors, attempt to continue. if we decide to accept, all good. if we decide to reject, we'll make it a temporary reject.

	var msgFrom smtp.Address
	var envelope *message.Envelope
	var headers textproto.MIMEHeader
	var isDSN bool
	part, err := message.Parse(c.log.Logger, false, dataFile)
	if err == nil {
		// todo: is it enough to check only the the content-type header? in other places we look at the content-types of the parts before considering a message a dsn. should we change other places to this simpler check?
		isDSN = part.MediaType == "MULTIPART" && part.MediaSubType == "REPORT" && strings.EqualFold(part.ContentTypeParams["report-type"], "delivery-status")
		msgFrom, envelope, headers, err = message.From(c.log.Logger, false, dataFile, &part)
	}
	if err != nil {
		c.log.Infox("parsing message for From address", err)
	}

	// Basic loop detection. ../rfc/5321:4065 ../rfc/5321:1526
	if len(headers.Values("Received")) > 100 {
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeNet4Loop6, "loop detected, more than 100 Received headers")
	}

	// TLS-Required: No header makes us not enforce recipient domain's TLS policy.
	// Since we only deliver locally at the moment, this won't influence our behaviour.
	// Once we forward, it would our delivery attempts.
	// ../rfc/8689:206
	// Only when requiretls smtp extension wasn't used. ../rfc/8689:246
	if c.requireTLS == nil && hasTLSRequiredNo(headers) {
		v := false
		c.requireTLS = &v
	}

	// We'll be building up an Authentication-Results header.
	authResults := message.AuthResults{
		Hostname: mox.Conf.Static.HostnameDomain.XName(c.msgsmtputf8),
	}

	commentAuthentic := func(v bool) string {
		if v {
			return "with dnssec"
		}
		return "without dnssec"
	}

	// Reverse IP lookup results.
	// todo future: how useful is this?
	// ../rfc/5321:2481
	authResults.Methods = append(authResults.Methods, message.AuthMethod{
		Method:  "iprev",
		Result:  string(iprevStatus),
		Comment: commentAuthentic(iprevAuthentic),
		Props: []message.AuthProp{
			message.MakeAuthProp("policy", "iprev", c.remoteIP.String(), false, ""),
		},
	})

	// SPF and DKIM verification in parallel.
	var wg sync.WaitGroup

	// DKIM
	wg.Add(1)
	var dkimResults []dkim.Result
	var dkimErr error
	go func() {
		defer func() {
			x := recover() // Should not happen, but don't take program down if it does.
			if x != nil {
				c.log.Error("dkim verify panic", slog.Any("err", x))
				debug.PrintStack()
				metrics.PanicInc(metrics.Dkimverify)
			}
		}()
		defer wg.Done()
		// We always evaluate all signatures. We want to build up reputation for each
		// domain in the signature.
		const ignoreTestMode = false
		// todo future: longer timeout? we have to read through the entire email, which can be large, possibly multiple times.
		dkimctx, dkimcancel := context.WithTimeout(ctx, time.Minute)
		defer dkimcancel()
		// todo future: we could let user configure which dkim headers they require

		// For localserve, fake dkim selector DNS records for hosted domains to give
		// dkim-signatures a chance to pass for deliveries from queue.
		resolver := c.resolver
		if Localserve {
			// Lookup based on message From address is an approximation.
			if dc, ok := mox.Conf.Domain(msgFrom.Domain); ok && len(dc.DKIM.Selectors) > 0 {
				txts := map[string][]string{}
				for name, sel := range dc.DKIM.Selectors {
					dkimr := dkim.Record{
						Version:   "DKIM1",
						Hashes:    []string{sel.HashEffective},
						PublicKey: sel.Key.Public(),
					}
					if _, ok := sel.Key.(ed25519.PrivateKey); ok {
						dkimr.Key = "ed25519"
					} else if _, ok := sel.Key.(*rsa.PrivateKey); !ok {
						err := fmt.Errorf("unrecognized private key for DKIM selector %q: %T", name, sel.Key)
						xcheckf(err, "making dkim record")
					}
					txt, err := dkimr.Record()
					xcheckf(err, "making DKIM DNS TXT record")
					txts[name+"._domainkey."+msgFrom.Domain.ASCII+"."] = []string{txt}
				}
				resolver = dns.MockResolver{TXT: txts}
			}
		}
		dkimResults, dkimErr = dkim.Verify(dkimctx, c.log.Logger, resolver, c.msgsmtputf8, dkim.DefaultPolicy, dataFile, ignoreTestMode)
		dkimcancel()
	}()

	// SPF.
	// ../rfc/7208:472
	var receivedSPF spf.Received
	var spfDomain dns.Domain
	var spfExpl string
	var spfAuthentic bool
	var spfErr error
	spfArgs := spf.Args{
		RemoteIP:          c.remoteIP,
		MailFromLocalpart: c.mailFrom.Localpart,
		MailFromDomain:    c.mailFrom.IPDomain.Domain, // Can be empty.
		HelloDomain:       c.hello,
		LocalIP:           c.localIP,
		LocalHostname:     c.hostname,
	}
	wg.Add(1)
	go func() {
		defer func() {
			x := recover() // Should not happen, but don't take program down if it does.
			if x != nil {
				c.log.Error("spf verify panic", slog.Any("err", x))
				debug.PrintStack()
				metrics.PanicInc(metrics.Spfverify)
			}
		}()
		defer wg.Done()
		spfctx, spfcancel := context.WithTimeout(ctx, time.Minute)
		defer spfcancel()
		resolver := c.resolver
		// For localserve, give hosted domains a chance to pass for deliveries from queue.
		if Localserve && c.remoteIP.IsLoopback() {
			// Lookup based on message From address is an approximation.
			if _, ok := mox.Conf.Domain(msgFrom.Domain); ok {
				resolver = dns.MockResolver{
					TXT: map[string][]string{msgFrom.Domain.ASCII + ".": {"v=spf1 ip4:127.0.0.1/8 ip6:::1 ~all"}},
				}
			}
		}
		receivedSPF, spfDomain, spfExpl, spfAuthentic, spfErr = spf.Verify(spfctx, c.log.Logger, resolver, spfArgs)
		spfcancel()
		if spfErr != nil {
			c.log.Infox("spf verify", spfErr)
		}
	}()

	// Wait for DKIM and SPF validation to finish.
	wg.Wait()

	// Give immediate response if all recipients are unknown.
	nunknown := 0
	for _, r := range c.recipients {
		if r.account == nil && r.alias == nil {
			nunknown++
		}
	}
	if nunknown == len(c.recipients) {
		// During RCPT TO we found that the address does not exist.
		c.log.Info("deliver attempt to unknown user(s)", slog.Any("recipients", c.recipients))

		// Crude attempt to slow down someone trying to guess names. Would work better
		// with connection rate limiter.
		if unknownRecipientsDelay > 0 {
			mox.Sleep(ctx, unknownRecipientsDelay)
		}

		// todo future: if remote does not look like a properly configured mail system, respond with generic 451 error? to prevent any random internet system from discovering accounts. we could give proper response if spf for ehlo or mailfrom passes.
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, "no such user(s)")
	}

	// Add DKIM results to Authentication-Results header.
	authResAddDKIM := func(result, comment, reason string, props []message.AuthProp) {
		dm := message.AuthMethod{
			Method:  "dkim",
			Result:  result,
			Comment: comment,
			Reason:  reason,
			Props:   props,
		}
		authResults.Methods = append(authResults.Methods, dm)
	}
	if dkimErr != nil {
		c.log.Errorx("dkim verify", dkimErr)
		authResAddDKIM("none", "", dkimErr.Error(), nil)
	} else if len(dkimResults) == 0 {
		c.log.Info("no dkim-signature header", slog.Any("mailfrom", c.mailFrom))
		authResAddDKIM("none", "", "no dkim signatures", nil)
	}
	for i, r := range dkimResults {
		var domain, selector dns.Domain
		var identity *dkim.Identity
		var comment string
		var props []message.AuthProp
		if r.Sig != nil {
			if r.Record != nil && r.Record.PublicKey != nil {
				if pubkey, ok := r.Record.PublicKey.(*rsa.PublicKey); ok {
					comment = fmt.Sprintf("%d bit rsa, ", pubkey.N.BitLen())
				}
			}

			sig := base64.StdEncoding.EncodeToString(r.Sig.Signature)
			sig = sig[:12] // Must be at least 8 characters and unique among the signatures.
			props = []message.AuthProp{
				message.MakeAuthProp("header", "d", r.Sig.Domain.XName(c.msgsmtputf8), true, r.Sig.Domain.ASCIIExtra(c.msgsmtputf8)),
				message.MakeAuthProp("header", "s", r.Sig.Selector.XName(c.msgsmtputf8), true, r.Sig.Selector.ASCIIExtra(c.msgsmtputf8)),
				message.MakeAuthProp("header", "a", r.Sig.Algorithm(), false, ""),
				message.MakeAuthProp("header", "b", sig, false, ""), // ../rfc/6008:147
			}
			domain = r.Sig.Domain
			selector = r.Sig.Selector
			if r.Sig.Identity != nil {
				props = append(props, message.MakeAuthProp("header", "i", r.Sig.Identity.String(), true, ""))
				identity = r.Sig.Identity
			}
			if r.RecordAuthentic {
				comment += "with dnssec"
			} else {
				comment += "without dnssec"
			}
		}
		var errmsg string
		if r.Err != nil {
			errmsg = r.Err.Error()
		}
		authResAddDKIM(string(r.Status), comment, errmsg, props)
		c.log.Debugx("dkim verification result", r.Err,
			slog.Int("index", i),
			slog.Any("mailfrom", c.mailFrom),
			slog.Any("status", r.Status),
			slog.Any("domain", domain),
			slog.Any("selector", selector),
			slog.Any("identity", identity))
	}

	// Add SPF results to Authentication-Results header. ../rfc/7208:2141
	var spfIdentity *dns.Domain
	var mailFromValidation = store.ValidationUnknown
	var ehloValidation = store.ValidationUnknown
	switch receivedSPF.Identity {
	case spf.ReceivedHELO:
		if len(spfArgs.HelloDomain.IP) == 0 {
			spfIdentity = &spfArgs.HelloDomain.Domain
		}
		ehloValidation = store.SPFValidation(receivedSPF.Result)
	case spf.ReceivedMailFrom:
		spfIdentity = &spfArgs.MailFromDomain
		mailFromValidation = store.SPFValidation(receivedSPF.Result)
	}
	var props []message.AuthProp
	if spfIdentity != nil {
		props = []message.AuthProp{message.MakeAuthProp("smtp", string(receivedSPF.Identity), spfIdentity.XName(c.msgsmtputf8), true, spfIdentity.ASCIIExtra(c.msgsmtputf8))}
	}
	var spfComment string
	if spfAuthentic {
		spfComment = "with dnssec"
	} else {
		spfComment = "without dnssec"
	}
	authResults.Methods = append(authResults.Methods, message.AuthMethod{
		Method:  "spf",
		Result:  string(receivedSPF.Result),
		Comment: spfComment,
		Props:   props,
	})
	switch receivedSPF.Result {
	case spf.StatusPass:
		c.log.Debug("spf pass", slog.Any("ip", spfArgs.RemoteIP), slog.String("mailfromdomain", spfArgs.MailFromDomain.ASCII)) // todo: log the domain that was actually verified.
	case spf.StatusFail:
		if spfExpl != "" {
			// Filter out potentially hostile text. ../rfc/7208:2529
			for _, b := range []byte(spfExpl) {
				if b < ' ' || b >= 0x7f {
					spfExpl = ""
					break
				}
			}
			if spfExpl != "" {
				if len(spfExpl) > 800 {
					spfExpl = spfExpl[:797] + "..."
				}
				spfExpl = "remote claims: " + spfExpl
			}
		}
		if spfExpl == "" {
			spfExpl = fmt.Sprintf("your ip %s is not on the SPF allowlist for domain %s", spfArgs.RemoteIP, spfDomain.ASCII)
		}
		c.log.Info("spf fail", slog.String("explanation", spfExpl)) // todo future: get this to the client. how? in smtp session in case of a reject due to dmarc fail?
	case spf.StatusTemperror:
		c.log.Infox("spf temperror", spfErr)
	case spf.StatusPermerror:
		c.log.Infox("spf permerror", spfErr)
	case spf.StatusNone, spf.StatusNeutral, spf.StatusSoftfail:
	default:
		c.log.Error("unknown spf status, treating as None/Neutral", slog.Any("status", receivedSPF.Result))
		receivedSPF.Result = spf.StatusNone
	}

	// DMARC
	var dmarcUse bool
	var dmarcResult dmarc.Result
	const applyRandomPercentage = true
	// dmarcMethod is added to authResults when delivering to recipients: accounts can
	// have different policy override rules.
	var dmarcMethod message.AuthMethod
	var msgFromValidation = store.ValidationNone
	if msgFrom.IsZero() {
		dmarcResult.Status = dmarc.StatusNone
		dmarcMethod = message.AuthMethod{
			Method: "dmarc",
			Result: string(dmarcResult.Status),
		}
	} else {
		msgFromValidation = alignment(ctx, c.log, msgFrom.Domain, dkimResults, receivedSPF.Result, spfIdentity)

		// We are doing the DMARC evaluation now. But we only store it for inclusion in an
		// aggregate report when we actually use it. We use an evaluation for each
		// recipient, with each a potentially different result due to mailing
		// list/forwarding configuration. If we reject a message due to being spam, we
		// don't want to spend any resources for the sender domain, and we don't want to
		// give the sender any more information about us, so we won't record the
		// evaluation.
		// todo future: also not send for first-time senders? they could be spammers getting through our filter, don't want to give them insights either. though we currently would have no reasonable way to decide if they are still reputationless at the time we are composing/sending aggregate reports.

		dmarcctx, dmarccancel := context.WithTimeout(ctx, time.Minute)
		defer dmarccancel()
		dmarcUse, dmarcResult = dmarc.Verify(dmarcctx, c.log.Logger, c.resolver, msgFrom.Domain, dkimResults, receivedSPF.Result, spfIdentity, applyRandomPercentage)
		dmarccancel()
		var comment string
		if dmarcResult.RecordAuthentic {
			comment = "with dnssec"
		} else {
			comment = "without dnssec"
		}
		dmarcMethod = message.AuthMethod{
			Method:  "dmarc",
			Result:  string(dmarcResult.Status),
			Comment: comment,
			Props: []message.AuthProp{
				// ../rfc/7489:1489
				message.MakeAuthProp("header", "from", msgFrom.Domain.ASCII, true, msgFrom.Domain.ASCIIExtra(c.msgsmtputf8)),
			},
		}

		if dmarcResult.Status == dmarc.StatusPass && msgFromValidation == store.ValidationRelaxed {
			msgFromValidation = store.ValidationDMARC
		}

		// todo future: consider enforcing an spf (soft)fail if there is no dmarc policy or the dmarc policy is none. ../rfc/7489:1507
	}
	c.log.Debug("dmarc verification", slog.Any("result", dmarcResult.Status), slog.Any("domain", msgFrom.Domain))

	// Prepare for analyzing content, calculating reputation.
	ipmasked1, ipmasked2, ipmasked3 := ipmasked(c.remoteIP)
	var verifiedDKIMDomains []string
	dkimSeen := map[string]bool{}
	for _, r := range dkimResults {
		// A message can have multiple signatures for the same identity. For example when
		// signing the message multiple times with different algorithms (rsa and ed25519).
		if r.Status != dkim.StatusPass {
			continue
		}
		d := r.Sig.Domain.Name()
		if !dkimSeen[d] {
			dkimSeen[d] = true
			verifiedDKIMDomains = append(verifiedDKIMDomains, d)
		}
	}

	// When we deliver, we try to remove from rejects mailbox based on message-id.
	// We'll parse it when we need it, but it is the same for each recipient.
	var messageID string
	var parsedMessageID bool

	// We build up a DSN for each failed recipient. If we have recipients in dsnMsg
	// after processing, we queue the DSN. Unless all recipients failed, in which case
	// we may just fail the mail transaction instead (could be common for failure to
	// deliver to a single recipient, e.g. for junk mail).
	// ../rfc/3464:436
	type deliverError struct {
		rcptTo    smtp.Path
		code      int
		secode    string
		userError bool
		errmsg    string
	}
	var deliverErrors []deliverError
	addError := func(rcpt recipient, code int, secode string, userError bool, errmsg string) {
		e := deliverError{rcpt.addr, code, secode, userError, errmsg}
		c.log.Info("deliver error",
			slog.Any("rcptto", e.rcptTo),
			slog.Int("code", code),
			slog.String("secode", "secode"),
			slog.Bool("usererror", userError),
			slog.String("errmsg", errmsg))
		deliverErrors = append(deliverErrors, e)
	}

	// Sort recipients: local accounts, aliases, unknown. For ensuring we don't deliver
	// to an alias destination that was also explicitly sent to.
	rcptScore := func(r recipient) int {
		if r.account != nil {
			return 0
		} else if r.alias != nil {
			return 1
		}
		return 2
	}
	sort.SliceStable(c.recipients, func(i, j int) bool {
		return rcptScore(c.recipients[i]) < rcptScore(c.recipients[j])
	})

	// Return whether address is a regular explicit recipient in this transaction. Used
	// to prevent delivering a message to an address both for alias and explicit
	// addressee. Relies on c.recipients being sorted as above.
	regularRecipient := func(addr smtp.Path) bool {
		for _, rcpt := range c.recipients {
			if rcpt.account == nil {
				break
			} else if rcpt.addr.Equal(addr) {
				return true
			}
		}
		return false
	}

	// Prepare a message, analyze it against account's junk filter.
	// The returned analysis has an open account that must be closed by the caller.
	// We call this for all alias destinations, also when we already delivered to that
	// recipient: It may be the only recipient that would allow the message.
	messageAnalyze := func(log mlog.Log, smtpRcptTo, deliverTo smtp.Path, accountName string, destination config.Destination, canonicalAddr string) (a *analysis, rerr error) {
		acc, err := store.OpenAccount(log, accountName)
		if err != nil {
			log.Errorx("open account", err, slog.Any("account", accountName))
			metricDelivery.WithLabelValues("accounterror", "").Inc()
			return nil, err
		}
		defer func() {
			if a == nil {
				err := acc.Close()
				log.Check(err, "closing account during analysis")
			}
		}()

		m := store.Message{
			Received:           time.Now(),
			RemoteIP:           c.remoteIP.String(),
			RemoteIPMasked1:    ipmasked1,
			RemoteIPMasked2:    ipmasked2,
			RemoteIPMasked3:    ipmasked3,
			EHLODomain:         c.hello.Domain.Name(),
			MailFrom:           c.mailFrom.String(),
			MailFromLocalpart:  c.mailFrom.Localpart,
			MailFromDomain:     c.mailFrom.IPDomain.Domain.Name(),
			RcptToLocalpart:    smtpRcptTo.Localpart,
			RcptToDomain:       smtpRcptTo.IPDomain.Domain.Name(),
			MsgFromLocalpart:   msgFrom.Localpart,
			MsgFromDomain:      msgFrom.Domain.Name(),
			MsgFromOrgDomain:   publicsuffix.Lookup(ctx, log.Logger, msgFrom.Domain).Name(),
			EHLOValidated:      ehloValidation == store.ValidationPass,
			MailFromValidated:  mailFromValidation == store.ValidationPass,
			MsgFromValidated:   msgFromValidation == store.ValidationStrict || msgFromValidation == store.ValidationDMARC || msgFromValidation == store.ValidationRelaxed,
			EHLOValidation:     ehloValidation,
			MailFromValidation: mailFromValidation,
			MsgFromValidation:  msgFromValidation,
			DKIMDomains:        verifiedDKIMDomains,
			DSN:                isDSN,
			Size:               msgWriter.Size,
		}
		if c.tls {
			tlsState := c.conn.(*tls.Conn).ConnectionState()
			m.ReceivedTLSVersion = tlsState.Version
			m.ReceivedTLSCipherSuite = tlsState.CipherSuite
			if c.requireTLS != nil {
				m.ReceivedRequireTLS = *c.requireTLS
			}
		} else {
			m.ReceivedTLSVersion = 1 // Signals plain text delivery.
		}

		var msgTo, msgCc []message.Address
		if envelope != nil {
			msgTo = envelope.To
			msgCc = envelope.CC
		}
		d := delivery{c.tls, &m, dataFile, smtpRcptTo, deliverTo, destination, canonicalAddr, acc, msgTo, msgCc, msgFrom, c.dnsBLs, dmarcUse, dmarcResult, dkimResults, iprevStatus}

		r := analyze(ctx, log, c.resolver, d)
		return &r, nil
	}

	// Either deliver the message, or call addError to register the recipient as failed.
	// If recipient is an alias, we may be delivering to multiple address/accounts and
	// we will consider a message delivered if we delivered it to at least one account
	// (others may be over quota).
	processRecipient := func(rcpt recipient) {
		log := c.log.With(slog.Any("mailfrom", c.mailFrom), slog.Any("rcptto", rcpt.addr))

		// If this is not a valid local user, we send back a DSN. This can only happen when
		// there are also valid recipients, and only when remote is SPF-verified, so the DSN
		// should not cause backscatter.
		// In case of serious errors, we abort the transaction. We may have already
		// delivered some messages. Perhaps it would be better to continue with other
		// deliveries, and return an error at the end? Though the failure conditions will
		// probably prevent any other successful deliveries too...
		// We'll continue delivering to other recipients. ../rfc/5321:3275
		if rcpt.account == nil && rcpt.alias == nil {
			metricDelivery.WithLabelValues("unknownuser", "").Inc()
			addError(rcpt, smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, true, "no such user")
			return
		}

		// la holds all analysis, and message preparation, for all accounts (multiple for
		// aliases). Each has an open account that we we close on return.
		var la []analysis
		defer func() {
			for _, a := range la {
				err := a.d.acc.Close()
				log.Check(err, "close account")
			}
		}()

		// For aliases, we prepare & analyze for each recipient. We accept the message if
		// any recipient accepts it. Regular destination have just a single account to
		// check. We check all alias destinations, even if we already explicitly delivered
		// to them: they may be the only destination that would accept the message.
		var a0 *analysis // Analysis we've used for accept/reject decision.
		if rcpt.alias != nil {
			// Check if msgFrom address is acceptable. This doesn't take validation into
			// consideration. If the header was forged, the message may be rejected later on.
			if !aliasAllowedMsgFrom(rcpt.alias.alias, msgFrom) {
				addError(rcpt, smtp.C550MailboxUnavail, smtp.SePol7ExpnProhibited2, true, "not allowed to send to destination")
				return
			}

			la = make([]analysis, 0, len(rcpt.alias.alias.ParsedAddresses))
			for _, aa := range rcpt.alias.alias.ParsedAddresses {
				a, err := messageAnalyze(log, rcpt.addr, aa.Address.Path(), aa.AccountName, aa.Destination, rcpt.alias.canonicalAddress)
				if err != nil {
					addError(rcpt, smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing")
					return
				}
				la = append(la, *a)
				if a.accept && a0 == nil {
					// Address that caused us to accept.
					a0 = &la[len(la)-1]
				}
			}
			if a0 == nil {
				// First address, for rejecting.
				a0 = &la[0]
			}
		} else {
			a, err := messageAnalyze(log, rcpt.addr, rcpt.addr, rcpt.account.accountName, rcpt.account.destination, rcpt.account.canonicalAddress)
			if err != nil {
				addError(rcpt, smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing")
				return
			}
			la = []analysis{*a}
			a0 = &la[0]
		}

		if !a0.accept && a0.reason == reasonHighRate {
			log.Info("incoming message rejected for high rate, not storing in rejects mailbox", slog.String("reason", a0.reason), slog.Any("msgfrom", msgFrom))
			metricDelivery.WithLabelValues("reject", a0.reason).Inc()
			c.setSlow(true)
			addError(rcpt, a0.code, a0.secode, a0.userError, a0.errmsg)
			return
		}

		// Any DMARC result override is stored in the evaluation for outgoing DMARC
		// aggregate reports, and added to the Authentication-Results message header.
		// We want to tell the sender that we have an override, e.g. for mailing lists, so
		// they don't overestimate the potential damage of switching from p=none to
		// p=reject.
		var dmarcOverrides []string
		if a0.dmarcOverrideReason != "" {
			dmarcOverrides = []string{a0.dmarcOverrideReason}
		}
		if dmarcResult.Record != nil && !dmarcUse {
			dmarcOverrides = append(dmarcOverrides, string(dmarcrpt.PolicyOverrideSampledOut))
		}

		// Add per-recipient DMARC method to Authentication-Results. Each account can have
		// their own override rules, e.g. based on configured mailing lists/forwards.
		// ../rfc/7489:1486
		rcptDMARCMethod := dmarcMethod
		if len(dmarcOverrides) > 0 {
			if rcptDMARCMethod.Comment != "" {
				rcptDMARCMethod.Comment += ", "
			}
			rcptDMARCMethod.Comment += "override " + strings.Join(dmarcOverrides, ",")
		}
		rcptAuthResults := authResults
		rcptAuthResults.Methods = append([]message.AuthMethod{}, authResults.Methods...)
		rcptAuthResults.Methods = append(rcptAuthResults.Methods, rcptDMARCMethod)

		// Prepend reason as message header, for easy display in mail clients.
		var xmox string
		if a0.reason != "" {
			xmox = "X-Mox-Reason: " + a0.reason + "\r\n"
		}
		xmox += a0.headers

		for i := range la {
			// ../rfc/5321:3204
			// Received-SPF header goes before Received. ../rfc/7208:2038
			la[i].d.m.MsgPrefix = []byte(
				xmox +
					"Delivered-To: " + la[i].d.deliverTo.XString(c.msgsmtputf8) + "\r\n" + // ../rfc/9228:274
					"Return-Path: <" + c.mailFrom.String() + ">\r\n" + // ../rfc/5321:3300
					rcptAuthResults.Header() +
					receivedSPF.Header() +
					recvHdrFor(rcpt.addr.String()),
			)
			la[i].d.m.Size += int64(len(la[i].d.m.MsgPrefix))
		}

		// Store DMARC evaluation for inclusion in an aggregate report. Only if there is at
		// least one reporting address: We don't want to needlessly store a row in a
		// database for each delivery attempt. If we reject a message for being junk, we
		// are also not going to send it a DMARC report. The DMARC check is done early in
		// the analysis, we will report on rejects because of DMARC, because it could be
		// valuable feedback about forwarded or mailing list messages.
		// ../rfc/7489:1492
		if !mox.Conf.Static.NoOutgoingDMARCReports && dmarcResult.Record != nil && len(dmarcResult.Record.AggregateReportAddresses) > 0 && (a0.accept && !a0.d.m.IsReject || a0.reason == reasonDMARCPolicy) {
			// Disposition holds our decision on whether to accept the message. Not what the
			// DMARC evaluation resulted in. We can override, e.g. because of mailing lists,
			// forwarding, or local policy.
			// We treat quarantine as reject, so never claim to quarantine.
			// ../rfc/7489:1691
			disposition := dmarcrpt.DispositionNone
			if !a0.accept {
				disposition = dmarcrpt.DispositionReject
			}

			// unknownDomain returns whether the sender is domain with which this account has
			// not had positive interaction.
			unknownDomain := func() (unknown bool) {
				err := a0.d.acc.DB.Read(ctx, func(tx *bstore.Tx) (err error) {
					// See if we received a non-junk message from this organizational domain.
					q := bstore.QueryTx[store.Message](tx)
					q.FilterNonzero(store.Message{MsgFromOrgDomain: a0.d.m.MsgFromOrgDomain})
					q.FilterEqual("Notjunk", true)
					q.FilterEqual("IsReject", false)
					exists, err := q.Exists()
					if err != nil {
						return fmt.Errorf("querying for non-junk message from organizational domain: %v", err)
					}
					if exists {
						return nil
					}

					// See if we sent a message to this organizational domain.
					qr := bstore.QueryTx[store.Recipient](tx)
					qr.FilterNonzero(store.Recipient{OrgDomain: a0.d.m.MsgFromOrgDomain})
					exists, err = qr.Exists()
					if err != nil {
						return fmt.Errorf("querying for message sent to organizational domain: %v", err)
					}
					if !exists {
						unknown = true
					}
					return nil
				})
				if err != nil {
					log.Errorx("checking if sender is unknown domain, for dmarc aggregate report evaluation", err)
				}
				return
			}

			r := dmarcResult.Record
			addresses := make([]string, len(r.AggregateReportAddresses))
			for i, a := range r.AggregateReportAddresses {
				addresses[i] = a.String()
			}
			sp := dmarcrpt.Disposition(r.SubdomainPolicy)
			if r.SubdomainPolicy == dmarc.PolicyEmpty {
				sp = dmarcrpt.Disposition(r.Policy)
			}
			eval := dmarcdb.Evaluation{
				// Evaluated and IntervalHours set by AddEvaluation.
				PolicyDomain: dmarcResult.Domain.Name(),

				// Optional evaluations don't cause a report to be sent, but will be included.
				// Useful for automated inter-mailer messages, we don't want to get in a reporting
				// loop. We also don't want to be used for sending reports to unsuspecting domains
				// we have no relation with.
				// todo: would it make sense to also mark some percentage of mailing-list-policy-overrides optional? to lower the load on mail servers of folks sending to large mailing lists.
				Optional: a0.d.destination.DMARCReports || a0.d.destination.HostTLSReports || a0.d.destination.DomainTLSReports || a0.reason == reasonDMARCPolicy && unknownDomain(),

				Addresses: addresses,

				PolicyPublished: dmarcrpt.PolicyPublished{
					Domain:          dmarcResult.Domain.Name(),
					ADKIM:           dmarcrpt.Alignment(r.ADKIM),
					ASPF:            dmarcrpt.Alignment(r.ASPF),
					Policy:          dmarcrpt.Disposition(r.Policy),
					SubdomainPolicy: sp,
					Percentage:      r.Percentage,
					// We don't save ReportingOptions, we don't do per-message failure reporting.
				},
				SourceIP:        c.remoteIP.String(),
				Disposition:     disposition,
				AlignedDKIMPass: dmarcResult.AlignedDKIMPass,
				AlignedSPFPass:  dmarcResult.AlignedSPFPass,
				EnvelopeTo:      rcpt.addr.IPDomain.String(),
				EnvelopeFrom:    c.mailFrom.IPDomain.String(),
				HeaderFrom:      msgFrom.Domain.Name(),
			}

			for _, s := range dmarcOverrides {
				reason := dmarcrpt.PolicyOverrideReason{Type: dmarcrpt.PolicyOverride(s)}
				eval.OverrideReasons = append(eval.OverrideReasons, reason)
			}

			// We'll include all signatures for the organizational domain, even if they weren't
			// relevant due to strict alignment requirement.
			for _, dkimResult := range dkimResults {
				if dkimResult.Sig == nil || publicsuffix.Lookup(ctx, log.Logger, msgFrom.Domain) != publicsuffix.Lookup(ctx, log.Logger, dkimResult.Sig.Domain) {
					continue
				}
				r := dmarcrpt.DKIMAuthResult{
					Domain:   dkimResult.Sig.Domain.Name(),
					Selector: dkimResult.Sig.Selector.ASCII,
					Result:   dmarcrpt.DKIMResult(dkimResult.Status),
				}
				eval.DKIMResults = append(eval.DKIMResults, r)
			}

			switch receivedSPF.Identity {
			case spf.ReceivedHELO:
				spfAuthResult := dmarcrpt.SPFAuthResult{
					Domain: spfArgs.HelloDomain.String(), // Can be unicode and also IP.
					Scope:  dmarcrpt.SPFDomainScopeHelo,
					Result: dmarcrpt.SPFResult(receivedSPF.Result),
				}
				eval.SPFResults = []dmarcrpt.SPFAuthResult{spfAuthResult}
			case spf.ReceivedMailFrom:
				spfAuthResult := dmarcrpt.SPFAuthResult{
					Domain: spfArgs.MailFromDomain.Name(), // Can be unicode.
					Scope:  dmarcrpt.SPFDomainScopeMailFrom,
					Result: dmarcrpt.SPFResult(receivedSPF.Result),
				}
				eval.SPFResults = []dmarcrpt.SPFAuthResult{spfAuthResult}
			}

			err := dmarcdb.AddEvaluation(ctx, dmarcResult.Record.AggregateReportingInterval, &eval)
			log.Check(err, "adding dmarc evaluation to database for aggregate report")
		}

		if !a0.accept {
			for _, a := range la {
				// Don't add message if address was also explicitly present in a RCPT TO command.
				if rcpt.alias != nil && regularRecipient(a.d.deliverTo) {
					continue
				}

				conf, _ := a.d.acc.Conf()
				if conf.RejectsMailbox == "" {
					continue
				}
				present, _, messagehash, err := rejectPresent(log, a.d.acc, conf.RejectsMailbox, a.d.m, dataFile)
				if err != nil {
					log.Errorx("checking whether reject is already present", err)
					continue
				} else if present {
					log.Info("reject message is already present, ignoring")
					continue
				}
				a.d.m.IsReject = true
				a.d.m.Seen = true // We don't want to draw attention.
				// Regular automatic junk flags configuration applies to these messages. The
				// default is to treat these as neutral, so they won't cause outright rejections
				// due to reputation for later delivery attempts.
				a.d.m.MessageHash = messagehash
				a.d.acc.WithWLock(func() {
					hasSpace := true
					var err error
					if !conf.KeepRejects {
						hasSpace, err = a.d.acc.TidyRejectsMailbox(c.log, conf.RejectsMailbox)
					}
					if err != nil {
						log.Errorx("tidying rejects mailbox", err)
					} else if hasSpace {
						if err := a.d.acc.DeliverMailbox(log, conf.RejectsMailbox, a.d.m, dataFile); err != nil {
							log.Errorx("delivering spammy mail to rejects mailbox", err)
						} else {
							log.Info("delivered spammy mail to rejects mailbox")
						}
					} else {
						log.Info("not storing spammy mail to full rejects mailbox")
					}
				})
			}

			log.Info("incoming message rejected", slog.String("reason", a0.reason), slog.Any("msgfrom", msgFrom))
			metricDelivery.WithLabelValues("reject", a0.reason).Inc()
			c.setSlow(true)
			addError(rcpt, a0.code, a0.secode, a0.userError, a0.errmsg)
			return
		}

		delayFirstTime := true
		if rcpt.account != nil && a0.dmarcReport != nil {
			// todo future: add rate limiting to prevent DoS attacks. ../rfc/7489:2570
			if err := dmarcdb.AddReport(ctx, a0.dmarcReport, msgFrom.Domain); err != nil {
				log.Errorx("saving dmarc aggregate report in database", err)
			} else {
				log.Info("dmarc aggregate report processed")
				a0.d.m.Flags.Seen = true
				delayFirstTime = false
			}
		}
		if rcpt.account != nil && a0.tlsReport != nil {
			// todo future: add rate limiting to prevent DoS attacks.
			if err := tlsrptdb.AddReport(ctx, c.log, msgFrom.Domain, c.mailFrom.String(), a0.d.destination.HostTLSReports, a0.tlsReport); err != nil {
				log.Errorx("saving TLSRPT report in database", err)
			} else {
				log.Info("tlsrpt report processed")
				a0.d.m.Flags.Seen = true
				delayFirstTime = false
			}
		}

		// If this is a first-time sender and not a forwarded/mailing list message, wait
		// before actually delivering. If this turns out to be a spammer, we've kept one of
		// their connections busy.
		a0conf, _ := a0.d.acc.Conf()
		if delayFirstTime && !a0.d.m.IsForward && !a0.d.m.IsMailingList && a0.reason == reasonNoBadSignals && !a0conf.NoFirstTimeSenderDelay && c.firstTimeSenderDelay > 0 {
			log.Debug("delaying before delivering from sender without reputation", slog.Duration("delay", c.firstTimeSenderDelay))
			mox.Sleep(mox.Context, c.firstTimeSenderDelay)
		}

		if Localserve {
			code, timeout := mox.LocalserveNeedsError(rcpt.addr.Localpart)
			if timeout {
				log.Info("timing out due to special localpart")
				mox.Sleep(mox.Context, time.Hour)
				xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeOther00}, "timing out delivery due to special localpart")
			} else if code != 0 {
				log.Info("failure due to special localpart", slog.Int("code", code))
				metricDelivery.WithLabelValues("delivererror", "localserve").Inc()
				addError(rcpt, code, smtp.SeOther00, false, fmt.Sprintf("failure with code %d due to special localpart", code))
				return
			}
		}

		// Gather the message-id before we deliver and the file may be consumed.
		if !parsedMessageID {
			if p, err := message.Parse(c.log.Logger, false, store.FileMsgReader(a0.d.m.MsgPrefix, dataFile)); err != nil {
				log.Infox("parsing message for message-id", err)
			} else if header, err := p.Header(); err != nil {
				log.Infox("parsing message header for message-id", err)
			} else {
				messageID = header.Get("Message-Id")
			}
			parsedMessageID = true
		}

		// Finally deliver the message to the account(s).
		var nerr int       // Number of non-quota errors.
		var nfull int      // Number of failed deliveries due to over quota.
		var ndelivered int // Number delivered to account.
		for _, a := range la {
			// Don't deliver to recipient that was explicitly present in SMTP transaction, or
			// is sending the message to an alias they are member of.
			if rcpt.alias != nil && (regularRecipient(a.d.deliverTo) || a.d.deliverTo.Equal(msgFrom.Path())) {
				continue
			}

			var delivered bool
			a.d.acc.WithWLock(func() {
				if err := a.d.acc.DeliverMailbox(log, a.mailbox, a.d.m, dataFile); err != nil {
					log.Errorx("delivering", err)
					metricDelivery.WithLabelValues("delivererror", a0.reason).Inc()
					if errors.Is(err, store.ErrOverQuota) {
						nfull++
					} else {
						addError(rcpt, smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing")
						nerr++
					}
					return
				}
				delivered = true
				ndelivered++
				metricDelivery.WithLabelValues("delivered", a0.reason).Inc()
				log.Info("incoming message delivered", slog.String("reason", a0.reason), slog.Any("msgfrom", msgFrom))

				conf, _ := a.d.acc.Conf()
				if conf.RejectsMailbox != "" && a.d.m.MessageID != "" {
					if err := a.d.acc.RejectsRemove(log, conf.RejectsMailbox, a.d.m.MessageID); err != nil {
						log.Errorx("removing message from rejects mailbox", err, slog.String("messageid", messageID))
					}
				}
			})

			// Pass delivered messages to queue for DSN processing and/or hooks.
			if delivered {
				mr := store.FileMsgReader(a.d.m.MsgPrefix, dataFile)
				part, err := a.d.m.LoadPart(mr)
				if err != nil {
					log.Errorx("loading parsed part for evaluating webhook", err)
				} else {
					err = queue.Incoming(context.Background(), log, a.d.acc, messageID, *a.d.m, part, a.mailbox)
					log.Check(err, "queueing webhook for incoming delivery")
				}
			} else if nerr > 0 && ndelivered == 0 {
				// Don't continue if we had an error and haven't delivered yet. If we only had
				// quota-related errors, we keep trying for an account to deliver to.
				break
			}
		}
		if ndelivered == 0 && (nerr > 0 || nfull > 0) {
			if nerr == 0 {
				addError(rcpt, smtp.C452StorageFull, smtp.SeMailbox2Full2, true, "account storage full")
			} else {
				addError(rcpt, smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing")
			}
		}
	}

	// For each recipient, do final spam analysis and delivery.
	for _, rcpt := range c.recipients {
		processRecipient(rcpt)
	}

	// If all recipients failed to deliver, return an error.
	if len(c.recipients) == len(deliverErrors) {
		same := true
		e0 := deliverErrors[0]
		var serverError bool
		var msgs []string
		major := 4
		for _, e := range deliverErrors {
			serverError = serverError || !e.userError
			if e.code != e0.code || e.secode != e0.secode {
				same = false
			}
			msgs = append(msgs, e.errmsg)
			if e.code >= 500 {
				major = 5
			}
		}
		if same {
			xsmtpErrorf(e0.code, e0.secode, !serverError, "%s", strings.Join(msgs, "\n"))
		}

		// Not all failures had the same error. We'll return each error on a separate line.
		lines := []string{}
		for _, e := range deliverErrors {
			s := fmt.Sprintf("%d %d.%s %s", e.code, e.code/100, e.secode, e.errmsg)
			lines = append(lines, s)
		}
		code := smtp.C451LocalErr
		secode := smtp.SeSys3Other0
		if major == 5 {
			code = smtp.C554TransactionFailed
		}
		lines = append(lines, "multiple errors")
		xsmtpErrorf(code, secode, !serverError, strings.Join(lines, "\n"))
	}
	// Generate one DSN for all failed recipients.
	if len(deliverErrors) > 0 {
		now := time.Now()
		dsnMsg := dsn.Message{
			SMTPUTF8:   c.msgsmtputf8,
			From:       smtp.Path{Localpart: "postmaster", IPDomain: deliverErrors[0].rcptTo.IPDomain},
			To:         *c.mailFrom,
			Subject:    "mail delivery failure",
			MessageID:  mox.MessageIDGen(false),
			References: messageID,

			// Per-message details.
			ReportingMTA:    mox.Conf.Static.HostnameDomain.ASCII,
			ReceivedFromMTA: smtp.Ehlo{Name: c.hello, ConnIP: c.remoteIP},
			ArrivalDate:     now,
		}

		if len(deliverErrors) > 1 {
			dsnMsg.TextBody = "Multiple delivery failures occurred.\n\n"
		}

		for _, e := range deliverErrors {
			kind := "Permanent"
			if e.code/100 == 4 {
				kind = "Transient"
			}
			dsnMsg.TextBody += fmt.Sprintf("%s delivery failure to:\n\n\t%s\n\nError:\n\n\t%s\n\n", kind, e.errmsg, e.rcptTo.XString(false))
			rcpt := dsn.Recipient{
				FinalRecipient:  e.rcptTo,
				Action:          dsn.Failed,
				Status:          fmt.Sprintf("%d.%s", e.code/100, e.secode),
				LastAttemptDate: now,
			}
			dsnMsg.Recipients = append(dsnMsg.Recipients, rcpt)
		}

		header, err := message.ReadHeaders(bufio.NewReader(&moxio.AtReader{R: dataFile}))
		if err != nil {
			c.log.Errorx("reading headers of incoming message for dsn, continuing dsn without headers", err)
		}
		dsnMsg.Original = header

		if Localserve {
			c.log.Error("not queueing dsn for incoming delivery due to localserve")
		} else if err := queueDSN(context.TODO(), c.log, c, *c.mailFrom, dsnMsg, c.requireTLS != nil && *c.requireTLS); err != nil {
			metricServerErrors.WithLabelValues("queuedsn").Inc()
			c.log.Errorx("queuing DSN for incoming delivery, no DSN sent", err)
		}
	}

	c.transactionGood++
	c.transactionBad-- // Compensate for early earlier pessimistic increase.
	c.rset()
	c.writecodeline(smtp.C250Completed, smtp.SeMailbox2Other0, "it is done", nil)
}

// Return whether msgFrom address is allowed to send a message to alias.
func aliasAllowedMsgFrom(alias config.Alias, msgFrom smtp.Address) bool {
	for _, aa := range alias.ParsedAddresses {
		if aa.Address == msgFrom {
			return true
		}
	}
	lp, err := smtp.ParseLocalpart(alias.LocalpartStr)
	xcheckf(err, "parsing alias localpart")
	if msgFrom == smtp.NewAddress(lp, alias.Domain) {
		return alias.AllowMsgFrom
	}
	return alias.PostPublic
}

// ecode returns either ecode, or a more specific error based on err.
// For example, ecode can be turned from an "other system" error into a "mail
// system full" if the error indicates no disk space is available.
func errCodes(code int, ecode string, err error) codes {
	switch {
	case moxio.IsStorageSpace(err):
		switch ecode {
		case smtp.SeMailbox2Other0:
			if code == smtp.C451LocalErr {
				code = smtp.C452StorageFull
			}
			ecode = smtp.SeMailbox2Full2
		case smtp.SeSys3Other0:
			if code == smtp.C451LocalErr {
				code = smtp.C452StorageFull
			}
			ecode = smtp.SeSys3StorageFull1
		}
	}
	return codes{code, ecode}
}

// ../rfc/5321:2079
func (c *conn) cmdRset(p *parser) {
	// ../rfc/5321:2106
	p.xend()

	c.rset()
	c.bwritecodeline(smtp.C250Completed, smtp.SeOther00, "all clear", nil)
}

// ../rfc/5321:2108 ../rfc/5321:1222
func (c *conn) cmdVrfy(p *parser) {
	// No EHLO/HELO needed.
	// ../rfc/5321:2448

	// ../rfc/5321:2119 ../rfc/6531:641
	p.xspace()
	p.xstring()
	if p.space() {
		p.xtake("SMTPUTF8")
	}
	p.xend()

	// todo future: we could support vrfy and expn for submission? though would need to see if its rfc defines it.

	// ../rfc/5321:4239
	xsmtpUserErrorf(smtp.C252WithoutVrfy, smtp.SePol7Other0, "no verify but will try delivery")
}

// ../rfc/5321:2135 ../rfc/5321:1272
func (c *conn) cmdExpn(p *parser) {
	// No EHLO/HELO needed.
	// ../rfc/5321:2448

	// ../rfc/5321:2149 ../rfc/6531:645
	p.xspace()
	p.xstring()
	if p.space() {
		p.xtake("SMTPUTF8")
	}
	p.xend()

	// todo: we could implement expn for local aliases for authenticated users, when members have permission to list. would anyone use it?

	// ../rfc/5321:4239
	xsmtpUserErrorf(smtp.C252WithoutVrfy, smtp.SePol7Other0, "no expand but will try delivery")
}

// ../rfc/5321:2151
func (c *conn) cmdHelp(p *parser) {
	// Let's not strictly parse the request for help. We are ignoring the text anyway.
	// ../rfc/5321:2166

	c.bwritecodeline(smtp.C214Help, smtp.SeOther00, "see rfc 5321 (smtp)", nil)
}

// ../rfc/5321:2191
func (c *conn) cmdNoop(p *parser) {
	// No idea why, but if an argument follows, it must adhere to the string ABNF production...
	// ../rfc/5321:2203
	if p.space() {
		p.xstring()
	}
	p.xend()

	c.bwritecodeline(smtp.C250Completed, smtp.SeOther00, "alrighty", nil)
}

// ../rfc/5321:2205
func (c *conn) cmdQuit(p *parser) {
	// ../rfc/5321:2226
	p.xend()

	c.writecodeline(smtp.C221Closing, smtp.SeOther00, "okay thanks bye", nil)
	panic(cleanClose)
}
