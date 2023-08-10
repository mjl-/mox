// Package smtpserver implements an SMTP server for submission and incoming delivery of mail messages.
package smtpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dmarcdb"
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

// Most logging should be done through conn.log* functions.
// Only use log in contexts without connection.
var xlog = mlog.New("smtpserver")

// We use panic and recover for error handling while executing commands.
// These errors signal the connection must be closed.
var errIO = errors.New("fatal io error")

// If set, regular delivery/submit is sidestepped, email is accepted and
// delivered to the account named mox.
var Localserve bool

var limiterConnectionRate, limiterConnections *ratelimit.Limiter

// For delivery rate limiting. Variable because changed during tests.
var limitIPMasked1MessagesPerMinute int = 500
var limitIPMasked1SizePerMinute int64 = 1000 * 1024 * 1024

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
	// Similar between ../webmail/webmail.go:/metricSubmission and ../smtpserver/server.go:/metricSubmission
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

var jitterRand = mox.NewRand()

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

		var tlsConfig *tls.Config
		if listener.TLS != nil {
			tlsConfig = listener.TLS.Config
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
				listen1("smtp", name, ip, port, hostname, tlsConfig, false, false, maxMsgSize, false, listener.SMTP.RequireSTARTTLS, listener.SMTP.DNSBLZones, firstTimeSenderDelay)
			}
		}
		if listener.Submission.Enabled {
			hostname := mox.Conf.Static.HostnameDomain
			if listener.Hostname != "" {
				hostname = listener.HostnameDomain
			}
			port := config.Port(listener.Submission.Port, 587)
			for _, ip := range listener.IPs {
				listen1("submission", name, ip, port, hostname, tlsConfig, true, false, maxMsgSize, !listener.Submission.NoRequireSTARTTLS, !listener.Submission.NoRequireSTARTTLS, nil, 0)
			}
		}

		if listener.Submissions.Enabled {
			hostname := mox.Conf.Static.HostnameDomain
			if listener.Hostname != "" {
				hostname = listener.HostnameDomain
			}
			port := config.Port(listener.Submissions.Port, 465)
			for _, ip := range listener.IPs {
				listen1("submissions", name, ip, port, hostname, tlsConfig, true, true, maxMsgSize, true, true, nil, 0)
			}
		}
	}
}

var servers []func()

func listen1(protocol, name, ip string, port int, hostname dns.Domain, tlsConfig *tls.Config, submission, xtls bool, maxMessageSize int64, requireTLSForAuth, requireTLSForDelivery bool, dnsBLs []dns.Domain, firstTimeSenderDelay time.Duration) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	if os.Getuid() == 0 {
		xlog.Print("listening for smtp", mlog.Field("listener", name), mlog.Field("address", addr), mlog.Field("protocol", protocol))
	}
	network := mox.Network(ip)
	ln, err := mox.Listen(network, addr)
	if err != nil {
		xlog.Fatalx("smtp: listen for smtp", err, mlog.Field("protocol", protocol), mlog.Field("listener", name))
	}
	if xtls {
		ln = tls.NewListener(ln, tlsConfig)
	}

	serve := func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				xlog.Infox("smtp: accept", err, mlog.Field("protocol", protocol), mlog.Field("listener", name))
				continue
			}
			resolver := dns.StrictResolver{} // By leaving Pkg empty, it'll be set by each package that uses the resolver, e.g. spf/dkim/dmarc.
			go serve(name, mox.Cid(), hostname, tlsConfig, conn, resolver, submission, xtls, maxMessageSize, requireTLSForAuth, requireTLSForDelivery, dnsBLs, firstTimeSenderDelay)
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
	log                   *mlog.Log
	maxMessageSize        int64
	requireTLSForAuth     bool
	requireTLSForDelivery bool
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
	mailFrom    *smtp.Path
	has8bitmime bool // If MAIL FROM parameter BODY=8BITMIME was sent. Required for SMTPUTF8.
	smtputf8    bool // todo future: we should keep track of this per recipient. perhaps only a specific recipient requires smtputf8, e.g. due to a utf8 localpart. we should decide ourselves if the message needs smtputf8, e.g. due to utf8 header values.
	recipients  []rcptAccount
}

type rcptAccount struct {
	rcptTo smtp.Path
	local  bool // Whether recipient is a local user.

	// Only valid for local delivery.
	accountName      string
	destination      config.Destination
	canonicalAddress string // Optional catchall part stripped and/or lowercased.
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
	c.has8bitmime = false
	c.smtputf8 = false
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

func (c *conn) xtrace(level mlog.Level) func() {
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

	var n int
	for len(buf) > 0 {
		// We set a single deadline for Write and Read. This may be a TLS connection.
		// SetDeadline works on the underlying connection. If we wouldn't touch the read
		// deadline, and only set the write deadline and do a bunch of writes, the TLS
		// library would still have to do reads on the underlying connection, and may reach
		// a read deadline that was set for some earlier read.
		if err := c.conn.SetDeadline(c.earliestDeadline(30 * time.Second)); err != nil {
			c.log.Errorx("setting deadline for write", err)
		}

		nn, err := c.conn.Write(buf[:chunk])
		if err != nil {
			panic(fmt.Errorf("write: %s (%w)", err, errIO))
		}
		n += nn
		buf = buf[chunk:]
		if len(buf) > 0 && badClientDelay > 0 {
			mox.Sleep(mox.Context, badClientDelay)
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
	line, err := bufpool.Readline(c.r)
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
	c.log.Debugx("smtp command result", err, mlog.Field("kind", c.kind()), mlog.Field("cmd", c.cmd), mlog.Field("code", fmt.Sprintf("%d", code)), mlog.Field("ecode", ecode), mlog.Field("duration", time.Since(c.cmdStart)))

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

func serve(listenerName string, cid int64, hostname dns.Domain, tlsConfig *tls.Config, nc net.Conn, resolver dns.Resolver, submission, tls bool, maxMessageSize int64, requireTLSForAuth, requireTLSForDelivery bool, dnsBLs []dns.Domain, firstTimeSenderDelay time.Duration) {
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
	c.log = xlog.MoreFields(func() []mlog.Pair {
		now := time.Now()
		l := []mlog.Pair{
			mlog.Field("cid", c.cid),
			mlog.Field("delta", now.Sub(c.lastlog)),
		}
		c.lastlog = now
		if c.username != "" {
			l = append(l, mlog.Field("username", c.username))
		}
		return l
	})
	c.tr = moxio.NewTraceReader(c.log, "RC: ", c)
	c.tw = moxio.NewTraceWriter(c.log, "LS: ", c)
	c.r = bufio.NewReader(c.tr)
	c.w = bufio.NewWriter(c.tw)

	metricConnection.WithLabelValues(c.kind()).Inc()
	c.log.Info("new connection", mlog.Field("remote", c.conn.RemoteAddr()), mlog.Field("local", c.conn.LocalAddr()), mlog.Field("submission", submission), mlog.Field("tls", tls), mlog.Field("listener", listenerName))

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
			c.log.Error("unhandled panic", mlog.Field("err", x))
			debug.PrintStack()
			metrics.PanicInc("smtpserver")
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
		c.log.Debug("refusing connection due to many auth failures", mlog.Field("remoteip", c.remoteIP))
		c.writecodeline(smtp.C421ServiceUnavail, smtp.SePol7Other0, "too many auth failures", nil)
		return
	}

	if !limiterConnections.Add(c.remoteIP, time.Now(), 1) {
		c.log.Debug("refusing connection due to many open connections", mlog.Field("remoteip", c.remoteIP))
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

// If smtp server is configured to require TLS for all mail delivery, abort command.
func (c *conn) xneedTLSForDelivery() {
	if c.requireTLSForDelivery && !c.tls {
		// ../rfc/3207:148
		xsmtpUserErrorf(smtp.C530SecurityRequired, smtp.SePol7Other0, "STARTTLS required for mail delivery")
	}
}

func (c *conn) cmdHelo(p *parser) {
	c.cmdHello(p, false)
}

func (c *conn) cmdEhlo(p *parser) {
	c.cmdHello(p, true)
}

// ../rfc/5321:1783
func (c *conn) cmdHello(p *parser, ehlo bool) {
	// ../rfc/5321:1827, though a few paragraphs earlier at ../rfc/5321:1802 is a claim
	// additional data can occur.
	p.xspace()
	var remote dns.IPDomain
	if ehlo {
		remote = p.xipdomain(true)
	} else {
		remote = dns.IPDomain{Domain: p.xdomain()}
		if !c.submission {
			// Verify a remote domain name has an A or AAAA record, CNAME not allowed. ../rfc/5321:722
			cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
			ctx, cancel := context.WithTimeout(cidctx, time.Minute)
			_, err := c.resolver.LookupIPAddr(ctx, remote.Domain.ASCII+".")
			cancel()
			if dns.IsNotFound(err) {
				xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeProto5Other0, "your ehlo domain does not resolve to an IP address")
			}
			// For success or temporary resolve errors, we'll just continue.
		}
	}
	p.remainder() // ../rfc/5321:1802
	p.xend()

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
	}
	if c.submission {
		// ../rfc/4954:123
		if c.tls || !c.requireTLSForAuth {
			c.bwritelinef("250-AUTH SCRAM-SHA-256 SCRAM-SHA-1 CRAM-MD5 PLAIN")
		} else {
			c.bwritelinef("250-AUTH ")
		}
	}
	c.bwritelinef("250-ENHANCEDSTATUSCODES") // ../rfc/2034:71
	// todo future? c.writelinef("250-DSN")
	c.bwritelinef("250-8BITMIME")              // ../rfc/6152:86
	c.bwritecodeline(250, "", "SMTPUTF8", nil) // ../rfc/6531:201
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

	c.writecodeline(smtp.C220ServiceReady, smtp.SeOther00, "go!", nil)
	tlsConn := tls.Server(conn, c.tlsConfig)
	cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
	ctx, cancel := context.WithTimeout(cidctx, time.Minute)
	defer cancel()
	c.log.Debug("starting tls server handshake")
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		panic(fmt.Errorf("starttls handshake: %s (%w)", err, errIO))
	}
	cancel()
	tlsversion, ciphersuite := mox.TLSInfo(tlsConn)
	c.log.Debug("tls server handshake done", mlog.Field("tls", tlsversion), mlog.Field("ciphersuite", ciphersuite))
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

	// todo future: we may want to normalize usernames and passwords, see stringprep in ../rfc/4013:38 and possibly newer mechanisms (though they are opt-in and that may not have happened yet).

	// For many failed auth attempts, slow down verification attempts.
	// Dropping the connection could also work, but more so when we have a connection rate limiter.
	// ../rfc/4954:770
	if c.authFailed > 3 && authFailDelay > 0 {
		// ../rfc/4954:770
		mox.Sleep(mox.Context, time.Duration(c.authFailed-3)*authFailDelay)
	}
	c.authFailed++ // Compensated on success.
	defer func() {
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
		switch authResult {
		case "ok":
			mox.LimiterFailedAuth.Reset(c.remoteIP, time.Now())
		default:
			mox.LimiterFailedAuth.Add(c.remoteIP, time.Now(), 1)
		}
	}()

	// todo: implement "AUTH LOGIN"? it looks like PLAIN, but without the continuation. it is an obsolete sasl mechanism. an account in desktop outlook appears to go through the cloud, attempting to submit email only with unadvertised and AUTH LOGIN. it appears they don't know "plain".

	// ../rfc/4954:699
	p.xspace()
	mech := p.xsaslMech()

	xreadInitial := func() []byte {
		var auth string
		if p.empty() {
			c.writelinef("%d ", smtp.C334ContinueAuth) // ../rfc/4954:205
			// todo future: handle max length of 12288 octets and return proper responde codes otherwise ../rfc/4954:253
			auth = c.readline()
			if auth == "*" {
				// ../rfc/4954:193
				authResult = "aborted"
				xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5Other0, "authentication aborted")
			}
		} else {
			p.xspace()
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
		buf := xreadInitial()
		c.xtrace(mlog.LevelTrace) // Restore.
		plain := bytes.Split(buf, []byte{0})
		if len(plain) != 3 {
			xsmtpUserErrorf(smtp.C501BadParamSyntax, smtp.SeProto5BadParams4, "auth data should have 3 nul-separated tokens, got %d", len(plain))
		}
		authz := string(plain[0])
		authc := string(plain[1])
		password := string(plain[2])

		if authz != "" && authz != authc {
			authResult = "badcreds"
			xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "cannot assume other role")
		}

		acc, err := store.OpenEmailAuth(authc, password)
		if err != nil && errors.Is(err, store.ErrUnknownCredentials) {
			// ../rfc/4954:274
			authResult = "badcreds"
			c.log.Info("failed authentication attempt", mlog.Field("username", authc), mlog.Field("remote", c.remoteIP))
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
		addr := t[0]
		c.log.Debug("cram-md5 auth", mlog.Field("address", addr))
		acc, _, err := store.OpenEmail(addr)
		if err != nil {
			if errors.Is(err, store.ErrUnknownCredentials) {
				c.log.Info("failed authentication attempt", mlog.Field("username", addr), mlog.Field("remote", c.remoteIP))
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
					c.log.Info("failed authentication attempt", mlog.Field("username", addr), mlog.Field("remote", c.remoteIP))
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
			c.log.Info("cram-md5 auth attempt without derived secrets set, save password again to store secrets", mlog.Field("username", addr))
			c.log.Info("failed authentication attempt", mlog.Field("username", addr), mlog.Field("remote", c.remoteIP))
			xsmtpUserErrorf(smtp.C535AuthBadCreds, smtp.SePol7AuthBadCreds8, "bad user/pass")
		}

		// ../rfc/2195:138 ../rfc/2104:142
		ipadhash.Write([]byte(chal))
		opadhash.Write(ipadhash.Sum(nil))
		digest := fmt.Sprintf("%x", opadhash.Sum(nil))
		if digest != t[1] {
			c.log.Info("failed authentication attempt", mlog.Field("username", addr), mlog.Field("remote", c.remoteIP))
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

	case "SCRAM-SHA-1", "SCRAM-SHA-256":
		// todo: improve handling of errors during scram. e.g. invalid parameters. should we abort the imap command, or continue until the end and respond with a scram-level error?
		// todo: use single implementation between ../imapserver/server.go and ../smtpserver/server.go

		authVariant = strings.ToLower(mech)
		var h func() hash.Hash
		if authVariant == "scram-sha-1" {
			h = sha1.New
		} else {
			h = sha256.New
		}

		// Passwords cannot be retrieved or replayed from the trace.

		c0 := xreadInitial()
		ss, err := scram.NewServer(h, c0)
		xcheckf(err, "starting scram")
		c.log.Debug("scram auth", mlog.Field("authentication", ss.Authentication))
		acc, _, err := store.OpenEmail(ss.Authentication)
		if err != nil {
			// todo: we could continue scram with a generated salt, deterministically generated
			// from the username. that way we don't have to store anything but attackers cannot
			// learn if an account exists. same for absent scram saltedpassword below.
			c.log.Info("failed authentication attempt", mlog.Field("username", ss.Authentication), mlog.Field("remote", c.remoteIP))
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
				if authVariant == "scram-sha-1" {
					xscram = password.SCRAMSHA1
				} else {
					xscram = password.SCRAMSHA256
				}
				if err == bstore.ErrAbsent || err == nil && (len(xscram.Salt) == 0 || xscram.Iterations == 0 || len(xscram.SaltedPassword) == 0) {
					c.log.Info("scram auth attempt without derived secrets set, save password again to store secrets", mlog.Field("address", ss.Authentication))
					c.log.Info("failed authentication attempt", mlog.Field("username", ss.Authentication), mlog.Field("remote", c.remoteIP))
					xsmtpUserErrorf(smtp.C454TempAuthFail, smtp.SeSys3Other0, "scram not possible")
				}
				xcheckf(err, "fetching credentials")
				return err
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
				c.log.Info("failed authentication attempt", mlog.Field("username", ss.Authentication), mlog.Field("remote", c.remoteIP))
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
		c.username = ss.Authentication
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
	// todo future: enforce?

	if c.transactionBad > 10 && c.transactionGood == 0 {
		// If we get many bad transactions, it's probably a spammer that is guessing user names.
		// Useful in combination with rate limiting.
		// ../rfc/5321:4349
		c.writecodeline(smtp.C550MailboxUnavail, smtp.SeAddr1Other0, "too many failures", nil)
		panic(errIO)
	}

	c.xneedHello()
	c.xcheckAuth()
	c.xneedTLSForDelivery()
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
	// note: no space after colon. ../rfc/5321:1093
	// Allow illegal space for submission only, not for regular SMTP. Microsoft Outlook
	// 365 Apps for Enterprise sends it.
	if c.submission && !moxvar.Pedantic {
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
			size := p.xnumber(20) // ../rfc/1870:90
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
		accName, _, _, err := mox.FindAccount(rpath.Localpart, rpath.IPDomain.Domain, false)
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
		c.log.Info("submission with unconfigured mailfrom", mlog.Field("user", c.username), mlog.Field("mailfrom", rpath.String()))
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SePol7DeliveryUnauth1, "must match authenticated user")
	} else if !c.submission && len(rpath.IPDomain.IP) > 0 {
		// todo future: allow if the IP is the same as this connection is coming from? does later code allow this?
		c.log.Info("delivery from address without domain", mlog.Field("mailfrom", rpath.String()))
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
	c.xneedTLSForDelivery()
	if c.mailFrom == nil {
		// ../rfc/5321:1088
		xsmtpUserErrorf(smtp.C503BadCmdSeq, smtp.SeProto5BadCmdOrSeq1, "missing MAIL FROM")
	}

	// ../rfc/5321:1985
	p.xtake(" TO:")
	// note: no space after colon. ../rfc/5321:1093
	// Allow illegal space for submission only, not for regular SMTP. Microsoft Outlook
	// 365 Apps for Enterprise sends it.
	if c.submission && !moxvar.Pedantic {
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

	// todo future: for submission, should we do explicit verification that domains are fully qualified? also for mail from. ../rfc/6409:420

	if len(c.recipients) >= 100 {
		// ../rfc/5321:3535 ../rfc/5321:3571
		xsmtpUserErrorf(smtp.C452StorageFull, smtp.SeProto5TooManyRcpts3, "max of 100 recipients reached")
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
			receivedSPF, _, _, err := spf.Verify(spfctx, c.resolver, spfArgs)
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

	if Localserve {
		if strings.HasPrefix(string(fpath.Localpart), "rcptto") {
			c.xlocalserveError(fpath.Localpart)
		}

		// If account or destination doesn't exist, it will be handled during delivery. For
		// submissions, which is the common case, we'll deliver to the logged in user,
		// which is typically the mox user.
		acc, _ := mox.Conf.Account("mox")
		dest := acc.Destinations["mox@localhost"]
		c.recipients = append(c.recipients, rcptAccount{fpath, true, "mox", dest, "mox@localhost"})
	} else if len(fpath.IPDomain.IP) > 0 {
		if !c.submission {
			xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, "not accepting email for ip")
		}
		c.recipients = append(c.recipients, rcptAccount{fpath, false, "", config.Destination{}, ""})
	} else if accountName, canonical, addr, err := mox.FindAccount(fpath.Localpart, fpath.IPDomain.Domain, true); err == nil {
		// note: a bare postmaster, without domain, is handled by FindAccount. ../rfc/5321:735
		c.recipients = append(c.recipients, rcptAccount{fpath, true, accountName, addr, canonical})
	} else if errors.Is(err, mox.ErrDomainNotFound) {
		if !c.submission {
			xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, "not accepting email for domain")
		}
		// We'll be delivering this email.
		c.recipients = append(c.recipients, rcptAccount{fpath, false, "", config.Destination{}, ""})
	} else if errors.Is(err, mox.ErrAccountNotFound) {
		if c.submission {
			// For submission, we're transparent about which user exists. Should be fine for the typical small-scale deploy.
			// ../rfc/5321:1071
			xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, "no such user")
		}
		// We pretend to accept. We don't want to let remote know the user does not exist
		// until after DATA. Because then remote has committed to sending a message.
		// note: not local for !c.submission is the signal this address is in error.
		c.recipients = append(c.recipients, rcptAccount{fpath, false, "", config.Destination{}, ""})
	} else {
		c.log.Errorx("looking up account for delivery", err, mlog.Field("rcptto", fpath))
		xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeSys3Other0}, "error processing")
	}
	c.bwritecodeline(smtp.C250Completed, smtp.SeAddr1Other0, "now on the list", nil)
}

// ../rfc/5321:1992 ../rfc/5321:1098
func (c *conn) cmdData(p *parser) {
	c.xneedHello()
	c.xcheckAuth()
	c.xneedTLSForDelivery()
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
	dataFile, err := store.CreateMessageTemp("smtp-deliver")
	if err != nil {
		xsmtpServerErrorf(errCodes(smtp.C451LocalErr, smtp.SeSys3Other0, err), "creating temporary file for message: %s", err)
	}
	defer func() {
		if dataFile != nil {
			err := os.Remove(dataFile.Name())
			c.log.Check(err, "removing temporary message file", mlog.Field("path", dataFile.Name()))
			err = dataFile.Close()
			c.log.Check(err, "removing temporary message file")
		}
	}()
	msgWriter := &message.Writer{Writer: dataFile}
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
		if !msgWriter.HaveHeaders {
			// ../rfc/6409:541
			xsmtpUserErrorf(smtp.C554TransactionFailed, smtp.SeMsg6Other0, "message requires both header and body section")
		}
		// Check only for pedantic mode because ios mail will attempt to send smtputf8 with
		// non-ascii in message from localpart without using 8bitmime.
		if moxvar.Pedantic && msgWriter.Has8bit && !c.has8bitmime {
			// ../rfc/5321:906
			xsmtpUserErrorf(smtp.C500BadSyntax, smtp.SeMsg6Other0, "message with non-us-ascii requires 8bitmime extension")
		}
	}

	if Localserve {
		// Require that message can be parsed fully.
		p, err := message.Parse(dataFile)
		if err == nil {
			err = p.Walk(nil)
		}
		if err != nil {
			// ../rfc/6409:541
			xsmtpUserErrorf(smtp.C554TransactionFailed, smtp.SeMsg6Other0, "malformed message: %v", err)
		}
	}

	// Prepare "Received" header.
	// ../rfc/5321:2051 ../rfc/5321:3302
	// ../rfc/5321:3311 ../rfc/6531:578
	var recvFrom string
	var iprevStatus iprev.Status // Only for delivery, not submission.
	if c.submission {
		// Hide internal hosts.
		// todo future: make this a config option, where admins specify ip ranges that they don't want exposed. also see ../rfc/5321:4321
		recvFrom = message.HeaderCommentDomain(mox.Conf.Static.HostnameDomain, c.smtputf8)
	} else {
		if len(c.hello.IP) > 0 {
			recvFrom = smtp.AddressLiteral(c.hello.IP)
		} else {
			// ASCII-only version added after the extended-domain syntax below, because the
			// comment belongs to "BY" which comes immediately after "FROM".
			recvFrom = c.hello.Domain.XName(c.smtputf8)
		}
		iprevctx, iprevcancel := context.WithTimeout(cmdctx, time.Minute)
		var revName string
		var revNames []string
		iprevStatus, revName, revNames, err = iprev.Lookup(iprevctx, c.resolver, c.remoteIP)
		iprevcancel()
		if err != nil {
			c.log.Infox("reverse-forward lookup", err, mlog.Field("remoteip", c.remoteIP))
		}
		c.log.Debug("dns iprev check", mlog.Field("addr", c.remoteIP), mlog.Field("status", iprevStatus))
		var name string
		if revName != "" {
			name = revName
		} else if len(revNames) > 0 {
			name = revNames[0]
		}
		name = strings.TrimSuffix(name, ".")
		recvFrom += " ("
		if name != "" && name != c.hello.Domain.XName(c.smtputf8) {
			recvFrom += name + " "
		}
		recvFrom += smtp.AddressLiteral(c.remoteIP) + ")"
		if c.smtputf8 && c.hello.Domain.Unicode != "" {
			recvFrom += " (" + c.hello.Domain.ASCII + ")"
		}
	}
	recvBy := mox.Conf.Static.HostnameDomain.XName(c.smtputf8)
	recvBy += " (" + smtp.AddressLiteral(c.localIP) + ")" // todo: hide ip if internal?
	if c.smtputf8 && mox.Conf.Static.HostnameDomain.Unicode != "" {
		// This syntax is part of "VIA".
		recvBy += " (" + mox.Conf.Static.HostnameDomain.ASCII + ")"
	}

	// ../rfc/3848:34 ../rfc/6531:791
	with := "SMTP"
	if c.smtputf8 {
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
		recvHdr.Add(" ", "Received:", "from", recvFrom, "by", recvBy, "via", "tcp", "with", with, "id", mox.ReceivedID(c.cid)) // ../rfc/5321:3158
		if c.tls {
			tlsConn := c.conn.(*tls.Conn)
			tlsComment := message.TLSReceivedComment(c.log, tlsConn.ConnectionState())
			recvHdr.Add(" ", tlsComment...)
		}
		recvHdr.Add(" ", "for", "<"+rcptTo+">;", time.Now().Format(message.RFC5322Z))
		return recvHdr.String()
	}

	// Submission is easiest because user is trusted. Far fewer checks to make. So
	// handle it first, and leave the rest of the function for handling wild west
	// internet traffic.
	if c.submission {
		c.submit(cmdctx, recvHdrFor, msgWriter, &dataFile)
	} else {
		c.deliver(cmdctx, recvHdrFor, msgWriter, iprevStatus, &dataFile)
	}
}

// submit is used for mail from authenticated users that we will try to deliver.
func (c *conn) submit(ctx context.Context, recvHdrFor func(string) string, msgWriter *message.Writer, pdataFile **os.File) {
	// Similar between ../smtpserver/server.go:/submit\( and ../webmail/webmail.go:/MessageSubmit\(

	dataFile := *pdataFile

	var msgPrefix []byte

	// Check that user is only sending email as one of its configured identities. Not
	// for other users.
	// We don't check the Sender field, there is no expectation of verification, ../rfc/7489:2948
	// and with Resent headers it seems valid to have someone else as Sender. ../rfc/5322:1578
	msgFrom, header, err := message.From(dataFile)
	if err != nil {
		metricSubmission.WithLabelValues("badmessage").Inc()
		c.log.Infox("parsing message From address", err, mlog.Field("user", c.username))
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeMsg6Other0, "cannot parse header or From address: %v", err)
	}
	accName, _, _, err := mox.FindAccount(msgFrom.Localpart, msgFrom.Domain, true)
	if err != nil || accName != c.account.Name {
		// ../rfc/6409:522
		if err == nil {
			err = mox.ErrAccountNotFound
		}
		metricSubmission.WithLabelValues("badfrom").Inc()
		c.log.Infox("verifying message From address", err, mlog.Field("user", c.username), mlog.Field("msgfrom", msgFrom))
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SePol7DeliveryUnauth1, "must match authenticated user")
	}

	// Outgoing messages should not have a Return-Path header. The final receiving mail
	// server will add it.
	// ../rfc/5321:3233
	if header.Values("Return-Path") != nil {
		metricSubmission.WithLabelValues("badheader").Inc()
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeMsg6Other0, "message must not have Return-Path header")
	}

	// Add Message-Id header if missing.
	// ../rfc/5321:4131 ../rfc/6409:751
	messageID := header.Get("Message-Id")
	if messageID == "" {
		messageID = mox.MessageIDGen(c.smtputf8)
		msgPrefix = append(msgPrefix, fmt.Sprintf("Message-Id: <%s>\r\n", messageID)...)
	}

	// ../rfc/6409:745
	if header.Get("Date") == "" {
		msgPrefix = append(msgPrefix, "Date: "+time.Now().Format(message.RFC5322Z)+"\r\n"...)
	}

	// Check outoging message rate limit.
	err = c.account.DB.Read(ctx, func(tx *bstore.Tx) error {
		rcpts := make([]smtp.Path, len(c.recipients))
		for i, r := range c.recipients {
			rcpts[i] = r.rcptTo
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

	// todo future: in a pedantic mode, we can parse the headers, and return an error if rcpt is only in To or Cc header, and not in the non-empty Bcc header. indicates a client that doesn't blind those bcc's.

	// Add DKIM signatures.
	confDom, ok := mox.Conf.Domain(msgFrom.Domain)
	if !ok {
		c.log.Error("domain disappeared", mlog.Field("domain", msgFrom.Domain))
		xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeSys3Other0}, "internal error")
	}

	dkimConfig := confDom.DKIM
	if len(dkimConfig.Sign) > 0 {
		if canonical, err := mox.CanonicalLocalpart(msgFrom.Localpart, confDom); err != nil {
			c.log.Errorx("determining canonical localpart for dkim signing", err, mlog.Field("localpart", msgFrom.Localpart))
		} else if dkimHeaders, err := dkim.Sign(ctx, canonical, msgFrom.Domain, dkimConfig, c.smtputf8, store.FileMsgReader(msgPrefix, dataFile)); err != nil {
			c.log.Errorx("dkim sign for domain", err, mlog.Field("domain", msgFrom.Domain))
			metricServerErrors.WithLabelValues("dkimsign").Inc()
		} else {
			msgPrefix = append(msgPrefix, []byte(dkimHeaders)...)
		}
	}

	authResults := message.AuthResults{
		Hostname: mox.Conf.Static.HostnameDomain.XName(c.smtputf8),
		Comment:  mox.Conf.Static.HostnameDomain.ASCIIExtra(c.smtputf8),
		Methods: []message.AuthMethod{
			{
				Method: "auth",
				Result: "pass",
				Props: []message.AuthProp{
					message.MakeAuthProp("smtp", "mailfrom", c.mailFrom.XString(c.smtputf8), true, c.mailFrom.ASCIIExtra(c.smtputf8)),
				},
			},
		},
	}
	msgPrefix = append(msgPrefix, []byte(authResults.Header())...)

	// We always deliver through the queue. It would be more efficient to deliver
	// directly, but we don't want to circumvent all the anti-spam measures. Accounts
	// on a single mox instance should be allowed to block each other.
	for i, rcptAcc := range c.recipients {
		if Localserve {
			code, timeout := localserveNeedsError(rcptAcc.rcptTo.Localpart)
			if timeout {
				c.log.Info("timing out submission due to special localpart")
				mox.Sleep(mox.Context, time.Hour)
				xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeSys3Other0}, "timing out submission due to special localpart")
			} else if code != 0 {
				c.log.Info("failure due to special localpart", mlog.Field("code", code))
				xsmtpServerErrorf(codes{code, smtp.SeOther00}, "failure with code %d due to special localpart", code)
			}
		}

		xmsgPrefix := append([]byte(recvHdrFor(rcptAcc.rcptTo.String())), msgPrefix...)
		// todo: don't convert the headers to a body? it seems the body part is optional. does this have consequences for us in other places? ../rfc/5322:343
		if !msgWriter.HaveHeaders {
			xmsgPrefix = append(xmsgPrefix, "\r\n"...)
		}

		msgSize := int64(len(xmsgPrefix)) + msgWriter.Size
		if _, err := queue.Add(ctx, c.log, c.account.Name, *c.mailFrom, rcptAcc.rcptTo, msgWriter.Has8bit, c.smtputf8, msgSize, messageID, xmsgPrefix, dataFile, nil, i == len(c.recipients)-1); err != nil {
			// Aborting the transaction is not great. But continuing and generating DSNs will
			// probably result in errors as well...
			metricSubmission.WithLabelValues("queueerror").Inc()
			c.log.Errorx("queuing message", err)
			xsmtpServerErrorf(errCodes(smtp.C451LocalErr, smtp.SeSys3Other0, err), "error delivering message: %v", err)
		}
		metricSubmission.WithLabelValues("ok").Inc()
		c.log.Info("message queued for delivery", mlog.Field("mailfrom", *c.mailFrom), mlog.Field("rcptto", rcptAcc.rcptTo), mlog.Field("smtputf8", c.smtputf8), mlog.Field("msgsize", msgSize))

		err := c.account.DB.Insert(ctx, &store.Outgoing{Recipient: rcptAcc.rcptTo.XString(true)})
		xcheckf(err, "adding outgoing message")
	}

	err = dataFile.Close()
	c.log.Check(err, "closing file after submission")
	*pdataFile = nil

	c.transactionGood++
	c.transactionBad-- // Compensate for early earlier pessimistic increase.

	c.rset()
	c.writecodeline(smtp.C250Completed, smtp.SeMailbox2Other0, "it is done", nil)
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

func localserveNeedsError(lp smtp.Localpart) (code int, timeout bool) {
	s := string(lp)
	if strings.HasSuffix(s, "temperror") {
		return smtp.C451LocalErr, false
	} else if strings.HasSuffix(s, "permerror") {
		return smtp.C550MailboxUnavail, false
	} else if strings.HasSuffix(s, "timeout") {
		return 0, true
	}
	if len(s) < 3 {
		return 0, false
	}
	s = s[len(s)-3:]
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, false
	}
	if v < 400 || v > 600 {
		return 0, false
	}
	return int(v), false
}

func (c *conn) xlocalserveError(lp smtp.Localpart) {
	code, timeout := localserveNeedsError(lp)
	if timeout {
		c.log.Info("timing out due to special localpart")
		mox.Sleep(mox.Context, time.Hour)
		xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeSys3Other0}, "timing out command due to special localpart")
	} else if code != 0 {
		c.log.Info("failure due to special localpart", mlog.Field("code", code))
		metricDelivery.WithLabelValues("delivererror", "localserve").Inc()
		xsmtpServerErrorf(codes{code, smtp.SeOther00}, "failure with code %d due to special localpart", code)
	}
}

// deliver is called for incoming messages from external, typically untrusted
// sources. i.e. not submitted by authenticated users.
func (c *conn) deliver(ctx context.Context, recvHdrFor func(string) string, msgWriter *message.Writer, iprevStatus iprev.Status, pdataFile **os.File) {
	dataFile := *pdataFile

	// todo: in decision making process, if we run into (some) temporary errors, attempt to continue. if we decide to accept, all good. if we decide to reject, we'll make it a temporary reject.

	msgFrom, headers, err := message.From(dataFile)
	if err != nil {
		c.log.Infox("parsing message for From address", err)
	}

	// Basic loop detection. ../rfc/5321:4065 ../rfc/5321:1526
	if len(headers.Values("Received")) > 100 {
		xsmtpUserErrorf(smtp.C550MailboxUnavail, smtp.SeNet4Loop6, "loop detected, more than 100 Received headers")
	}

	// We'll be building up an Authentication-Results header.
	authResults := message.AuthResults{
		Hostname: mox.Conf.Static.HostnameDomain.XName(c.smtputf8),
	}

	// Reverse IP lookup results.
	// todo future: how useful is this?
	// ../rfc/5321:2481
	authResults.Methods = append(authResults.Methods, message.AuthMethod{
		Method: "iprev",
		Result: string(iprevStatus),
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
				c.log.Error("dkim verify panic", mlog.Field("err", x))
				debug.PrintStack()
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
		dkimResults, dkimErr = dkim.Verify(dkimctx, c.resolver, c.smtputf8, dkim.DefaultPolicy, dataFile, ignoreTestMode)
		dkimcancel()
	}()

	// SPF.
	// ../rfc/7208:472
	var receivedSPF spf.Received
	var spfDomain dns.Domain
	var spfExpl string
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
				c.log.Error("dkim verify panic", mlog.Field("err", x))
				debug.PrintStack()
			}
		}()
		defer wg.Done()
		spfctx, spfcancel := context.WithTimeout(ctx, time.Minute)
		defer spfcancel()
		receivedSPF, spfDomain, spfExpl, spfErr = spf.Verify(spfctx, c.resolver, spfArgs)
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
		if !r.local {
			nunknown++
		}
	}
	if nunknown == len(c.recipients) {
		// During RCPT TO we found that the address does not exist.
		c.log.Info("deliver attempt to unknown user(s)", mlog.Field("recipients", c.recipients))

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
		c.log.Info("no dkim-signature header", mlog.Field("mailfrom", c.mailFrom))
		authResAddDKIM("none", "", "no dkim signatures", nil)
	}
	for i, r := range dkimResults {
		var domain, selector dns.Domain
		var identity *dkim.Identity
		var comment string
		var props []message.AuthProp
		if r.Sig != nil {
			// todo future: also specify whether dns record was dnssec-signed.
			if r.Record != nil && r.Record.PublicKey != nil {
				if pubkey, ok := r.Record.PublicKey.(*rsa.PublicKey); ok {
					comment = fmt.Sprintf("%d bit rsa", pubkey.N.BitLen())
				}
			}

			sig := base64.StdEncoding.EncodeToString(r.Sig.Signature)
			sig = sig[:12] // Must be at least 8 characters and unique among the signatures.
			props = []message.AuthProp{
				message.MakeAuthProp("header", "d", r.Sig.Domain.XName(c.smtputf8), true, r.Sig.Domain.ASCIIExtra(c.smtputf8)),
				message.MakeAuthProp("header", "s", r.Sig.Selector.XName(c.smtputf8), true, r.Sig.Selector.ASCIIExtra(c.smtputf8)),
				message.MakeAuthProp("header", "a", r.Sig.Algorithm(), false, ""),
				message.MakeAuthProp("header", "b", sig, false, ""), // ../rfc/6008:147
			}
			domain = r.Sig.Domain
			selector = r.Sig.Selector
			if r.Sig.Identity != nil {
				props = append(props, message.MakeAuthProp("header", "i", r.Sig.Identity.String(), true, ""))
				identity = r.Sig.Identity
			}
		}
		var errmsg string
		if r.Err != nil {
			errmsg = r.Err.Error()
		}
		authResAddDKIM(string(r.Status), comment, errmsg, props)
		c.log.Debugx("dkim verification result", r.Err, mlog.Field("index", i), mlog.Field("mailfrom", c.mailFrom), mlog.Field("status", r.Status), mlog.Field("domain", domain), mlog.Field("selector", selector), mlog.Field("identity", identity))
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
		props = []message.AuthProp{message.MakeAuthProp("smtp", string(receivedSPF.Identity), spfIdentity.XName(c.smtputf8), true, spfIdentity.ASCIIExtra(c.smtputf8))}
	}
	authResults.Methods = append(authResults.Methods, message.AuthMethod{
		Method: "spf",
		Result: string(receivedSPF.Result),
		Props:  props,
	})
	switch receivedSPF.Result {
	case spf.StatusPass:
		c.log.Debug("spf pass", mlog.Field("ip", spfArgs.RemoteIP), mlog.Field("mailfromdomain", spfArgs.MailFromDomain.ASCII)) // todo: log the domain that was actually verified.
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
		c.log.Info("spf fail", mlog.Field("explanation", spfExpl)) // todo future: get this to the client. how? in smtp session in case of a reject due to dmarc fail?
	case spf.StatusTemperror:
		c.log.Infox("spf temperror", spfErr)
	case spf.StatusPermerror:
		c.log.Infox("spf permerror", spfErr)
	case spf.StatusNone, spf.StatusNeutral, spf.StatusSoftfail:
	default:
		c.log.Error("unknown spf status, treating as None/Neutral", mlog.Field("status", receivedSPF.Result))
		receivedSPF.Result = spf.StatusNone
	}

	// DMARC
	var dmarcUse bool
	var dmarcResult dmarc.Result
	const applyRandomPercentage = true
	var dmarcMethod message.AuthMethod
	var msgFromValidation = store.ValidationNone
	if msgFrom.IsZero() {
		dmarcResult.Status = dmarc.StatusNone
		dmarcMethod = message.AuthMethod{
			Method: "dmarc",
			Result: string(dmarcResult.Status),
		}
	} else {
		msgFromValidation = alignment(ctx, msgFrom.Domain, dkimResults, receivedSPF.Result, spfIdentity)

		dmarcctx, dmarccancel := context.WithTimeout(ctx, time.Minute)
		defer dmarccancel()
		dmarcUse, dmarcResult = dmarc.Verify(dmarcctx, c.resolver, msgFrom.Domain, dkimResults, receivedSPF.Result, spfIdentity, applyRandomPercentage)
		dmarccancel()
		dmarcMethod = message.AuthMethod{
			Method: "dmarc",
			Result: string(dmarcResult.Status),
			Props: []message.AuthProp{
				// ../rfc/7489:1489
				message.MakeAuthProp("header", "from", msgFrom.Domain.ASCII, true, msgFrom.Domain.ASCIIExtra(c.smtputf8)),
			},
		}

		if dmarcResult.Status == dmarc.StatusPass && msgFromValidation == store.ValidationRelaxed {
			msgFromValidation = store.ValidationDMARC
		}

		// todo future: consider enforcing an spf fail if there is no dmarc policy or the dmarc policy is none. ../rfc/7489:1507
	}
	authResults.Methods = append(authResults.Methods, dmarcMethod)
	c.log.Debug("dmarc verification", mlog.Field("result", dmarcResult.Status), mlog.Field("domain", msgFrom.Domain))

	// Prepare for analyzing content, calculating reputation.
	ipmasked1, ipmasked2, ipmasked3 := ipmasked(c.remoteIP)
	var verifiedDKIMDomains []string
	for _, r := range dkimResults {
		// A message can have multiple signatures for the same identity. For example when
		// signing the message multiple times with different algorithms (rsa and ed25519).
		seen := map[string]bool{}
		if r.Status != dkim.StatusPass {
			continue
		}
		d := r.Sig.Domain.Name()
		if !seen[d] {
			seen[d] = true
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
	addError := func(rcptAcc rcptAccount, code int, secode string, userError bool, errmsg string) {
		e := deliverError{rcptAcc.rcptTo, code, secode, userError, errmsg}
		c.log.Info("deliver error", mlog.Field("rcptto", e.rcptTo), mlog.Field("code", code), mlog.Field("secode", "secode"), mlog.Field("usererror", userError), mlog.Field("errmsg", errmsg))
		deliverErrors = append(deliverErrors, e)
	}

	// For each recipient, do final spam analysis and delivery.
	for _, rcptAcc := range c.recipients {
		log := c.log.Fields(mlog.Field("mailfrom", c.mailFrom), mlog.Field("rcptto", rcptAcc.rcptTo))

		// If this is not a valid local user, we send back a DSN. This can only happen when
		// there are also valid recipients, and only when remote is SPF-verified, so the DSN
		// should not cause backscatter.
		// In case of serious errors, we abort the transaction. We may have already
		// delivered some messages. Perhaps it would be better to continue with other
		// deliveries, and return an error at the end? Though the failure conditions will
		// probably prevent any other successful deliveries too...
		// We'll continue delivering to other recipients. ../rfc/5321:3275
		if !rcptAcc.local {
			metricDelivery.WithLabelValues("unknownuser", "").Inc()
			addError(rcptAcc, smtp.C550MailboxUnavail, smtp.SeAddr1UnknownDestMailbox1, true, "no such user")
			continue
		}

		acc, err := store.OpenAccount(rcptAcc.accountName)
		if err != nil {
			log.Errorx("open account", err, mlog.Field("account", rcptAcc.accountName))
			metricDelivery.WithLabelValues("accounterror", "").Inc()
			addError(rcptAcc, smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing")
			continue
		}
		defer func() {
			if acc != nil {
				err := acc.Close()
				log.Check(err, "closing account after delivery")
			}
		}()

		// We don't want to let a single IP or network deliver too many messages to an
		// account. They may fill up the mailbox, either with messages that have to be
		// purged, or by filling the disk. We check both cases for IP's and networks.
		var rateError bool // Whether returned error represents a rate error.
		err = acc.DB.Read(ctx, func(tx *bstore.Tx) (retErr error) {
			now := time.Now()
			defer func() {
				log.Debugx("checking message and size delivery rates", retErr, mlog.Field("duration", time.Since(now)))
			}()

			checkCount := func(msg store.Message, window time.Duration, limit int) {
				if retErr != nil {
					return
				}
				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(msg)
				q.FilterGreater("Received", now.Add(-window))
				q.FilterEqual("Expunged", false)
				n, err := q.Count()
				if err != nil {
					retErr = err
					return
				}
				if n >= limit {
					rateError = true
					retErr = fmt.Errorf("more than %d messages in past %s from your ip/network", limit, window)
				}
			}

			checkSize := func(msg store.Message, window time.Duration, limit int64) {
				if retErr != nil {
					return
				}
				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(msg)
				q.FilterGreater("Received", now.Add(-window))
				q.FilterEqual("Expunged", false)
				size := msgWriter.Size
				err := q.ForEach(func(v store.Message) error {
					size += v.Size
					return nil
				})
				if err != nil {
					retErr = err
					return
				}
				if size > limit {
					rateError = true
					retErr = fmt.Errorf("more than %d bytes in past %s from your ip/network", limit, window)
				}
			}

			// todo future: make these configurable
			// todo: should we have a limit for forwarded messages? they are stored with empty RemoteIPMasked*

			const day = 24 * time.Hour
			checkCount(store.Message{RemoteIPMasked1: ipmasked1}, time.Minute, limitIPMasked1MessagesPerMinute)
			checkCount(store.Message{RemoteIPMasked1: ipmasked1}, day, 20*500)
			checkCount(store.Message{RemoteIPMasked2: ipmasked2}, time.Minute, 1500)
			checkCount(store.Message{RemoteIPMasked2: ipmasked2}, day, 20*1500)
			checkCount(store.Message{RemoteIPMasked3: ipmasked3}, time.Minute, 4500)
			checkCount(store.Message{RemoteIPMasked3: ipmasked3}, day, 20*4500)

			const MB = 1024 * 1024
			checkSize(store.Message{RemoteIPMasked1: ipmasked1}, time.Minute, limitIPMasked1SizePerMinute)
			checkSize(store.Message{RemoteIPMasked1: ipmasked1}, day, 3*1000*MB)
			checkSize(store.Message{RemoteIPMasked2: ipmasked2}, time.Minute, 3000*MB)
			checkSize(store.Message{RemoteIPMasked2: ipmasked2}, day, 3*3000*MB)
			checkSize(store.Message{RemoteIPMasked3: ipmasked3}, time.Minute, 9000*MB)
			checkSize(store.Message{RemoteIPMasked3: ipmasked3}, day, 3*9000*MB)

			return retErr
		})
		if err != nil && !rateError {
			log.Errorx("checking delivery rates", err)
			metricDelivery.WithLabelValues("checkrates", "").Inc()
			addError(rcptAcc, smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing")
			continue
		} else if err != nil {
			log.Debugx("refusing due to high delivery rate", err)
			metricDelivery.WithLabelValues("highrate", "").Inc()
			c.setSlow(true)
			addError(rcptAcc, smtp.C452StorageFull, smtp.SeMailbox2Full2, true, err.Error())
			continue
		}

		// ../rfc/5321:3204
		// Received-SPF header goes before Received. ../rfc/7208:2038
		msgPrefix := []byte(
			"Delivered-To: " + rcptAcc.rcptTo.XString(c.smtputf8) + "\r\n" + // ../rfc/9228:274
				"Return-Path: <" + c.mailFrom.String() + ">\r\n" + // ../rfc/5321:3300
				authResults.Header() +
				receivedSPF.Header() +
				recvHdrFor(rcptAcc.rcptTo.String()),
		)
		if !msgWriter.HaveHeaders {
			msgPrefix = append(msgPrefix, "\r\n"...)
		}

		m := &store.Message{
			Received:           time.Now(),
			RemoteIP:           c.remoteIP.String(),
			RemoteIPMasked1:    ipmasked1,
			RemoteIPMasked2:    ipmasked2,
			RemoteIPMasked3:    ipmasked3,
			EHLODomain:         c.hello.Domain.Name(),
			MailFrom:           c.mailFrom.String(),
			MailFromLocalpart:  c.mailFrom.Localpart,
			MailFromDomain:     c.mailFrom.IPDomain.Domain.Name(),
			RcptToLocalpart:    rcptAcc.rcptTo.Localpart,
			RcptToDomain:       rcptAcc.rcptTo.IPDomain.Domain.Name(),
			MsgFromLocalpart:   msgFrom.Localpart,
			MsgFromDomain:      msgFrom.Domain.Name(),
			MsgFromOrgDomain:   publicsuffix.Lookup(ctx, msgFrom.Domain).Name(),
			EHLOValidated:      ehloValidation == store.ValidationPass,
			MailFromValidated:  mailFromValidation == store.ValidationPass,
			MsgFromValidated:   msgFromValidation == store.ValidationStrict || msgFromValidation == store.ValidationDMARC || msgFromValidation == store.ValidationRelaxed,
			EHLOValidation:     ehloValidation,
			MailFromValidation: mailFromValidation,
			MsgFromValidation:  msgFromValidation,
			DKIMDomains:        verifiedDKIMDomains,
			Size:               int64(len(msgPrefix)) + msgWriter.Size,
			MsgPrefix:          msgPrefix,
		}
		d := delivery{m, dataFile, rcptAcc, acc, msgFrom, c.dnsBLs, dmarcUse, dmarcResult, dkimResults, iprevStatus}
		a := analyze(ctx, log, c.resolver, d)
		if a.reason != "" {
			xmoxreason := "X-Mox-Reason: " + a.reason + "\r\n"
			m.MsgPrefix = append([]byte(xmoxreason), m.MsgPrefix...)
			m.Size += int64(len(xmoxreason))
		}
		if !a.accept {
			conf, _ := acc.Conf()
			if conf.RejectsMailbox != "" {
				present, messageid, messagehash, err := rejectPresent(log, acc, conf.RejectsMailbox, m, dataFile)
				if err != nil {
					log.Errorx("checking whether reject is already present", err)
				} else if !present {
					m.IsReject = true
					m.Seen = true // We don't want to draw attention.
					// Regular automatic junk flags configuration applies to these messages. The
					// default is to treat these as neutral, so they won't cause outright rejections
					// due to reputation for later delivery attempts.
					m.MessageID = messageid
					m.MessageHash = messagehash
					acc.WithWLock(func() {
						hasSpace := true
						var err error
						if !conf.KeepRejects {
							hasSpace, err = acc.TidyRejectsMailbox(c.log, conf.RejectsMailbox)
						}
						if err != nil {
							log.Errorx("tidying rejects mailbox", err)
						} else if hasSpace {
							if err := acc.DeliverMailbox(log, conf.RejectsMailbox, m, dataFile, false); err != nil {
								log.Errorx("delivering spammy mail to rejects mailbox", err)
							} else {
								log.Info("delivered spammy mail to rejects mailbox")
							}
						} else {
							log.Info("not storing spammy mail to full rejects mailbox")
						}
					})
				} else {
					log.Info("reject message is already present, ignoring")
				}
			}

			log.Info("incoming message rejected", mlog.Field("reason", a.reason), mlog.Field("msgfrom", msgFrom))
			metricDelivery.WithLabelValues("reject", a.reason).Inc()
			c.setSlow(true)
			addError(rcptAcc, a.code, a.secode, a.userError, a.errmsg)
			continue
		}

		delayFirstTime := true
		if a.dmarcReport != nil {
			// todo future: add rate limiting to prevent DoS attacks. ../rfc/7489:2570
			if err := dmarcdb.AddReport(ctx, a.dmarcReport, msgFrom.Domain); err != nil {
				log.Errorx("saving dmarc report in database", err)
			} else {
				log.Info("dmarc report processed")
				m.Flags.Seen = true
				delayFirstTime = false
			}
		}
		if a.tlsReport != nil {
			// todo future: add rate limiting to prevent DoS attacks.
			if err := tlsrptdb.AddReport(ctx, msgFrom.Domain, c.mailFrom.String(), a.tlsReport); err != nil {
				log.Errorx("saving TLSRPT report in database", err)
			} else {
				log.Info("tlsrpt report processed")
				m.Flags.Seen = true
				delayFirstTime = false
			}
		}

		// If a forwarded message and this is a first-time sender, wait before actually
		// delivering. If this turns out to be a spammer, we've kept one of their
		// connections busy.
		if delayFirstTime && !m.IsForward && a.reason == reasonNoBadSignals && c.firstTimeSenderDelay > 0 {
			log.Debug("delaying before delivering from sender without reputation", mlog.Field("delay", c.firstTimeSenderDelay))
			mox.Sleep(mox.Context, c.firstTimeSenderDelay)
		}

		// Gather the message-id before we deliver and the file may be consumed.
		if !parsedMessageID {
			if p, err := message.Parse(store.FileMsgReader(m.MsgPrefix, dataFile)); err != nil {
				log.Infox("parsing message for message-id", err)
			} else if header, err := p.Header(); err != nil {
				log.Infox("parsing message header for message-id", err)
			} else {
				messageID = header.Get("Message-Id")
			}
		}

		if Localserve {
			code, timeout := localserveNeedsError(rcptAcc.rcptTo.Localpart)
			if timeout {
				c.log.Info("timing out due to special localpart")
				mox.Sleep(mox.Context, time.Hour)
				xsmtpServerErrorf(codes{smtp.C451LocalErr, smtp.SeOther00}, "timing out delivery due to special localpart")
			} else if code != 0 {
				c.log.Info("failure due to special localpart", mlog.Field("code", code))
				metricDelivery.WithLabelValues("delivererror", "localserve").Inc()
				addError(rcptAcc, code, smtp.SeOther00, false, fmt.Sprintf("failure with code %d due to special localpart", code))
			}
		}
		acc.WithWLock(func() {
			if err := acc.DeliverMailbox(log, a.mailbox, m, dataFile, false); err != nil {
				log.Errorx("delivering", err)
				metricDelivery.WithLabelValues("delivererror", a.reason).Inc()
				addError(rcptAcc, smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing")
				return
			}
			metricDelivery.WithLabelValues("delivered", a.reason).Inc()
			log.Info("incoming message delivered", mlog.Field("reason", a.reason), mlog.Field("msgfrom", msgFrom))

			conf, _ := acc.Conf()
			if conf.RejectsMailbox != "" && messageID != "" {
				if err := acc.RejectsRemove(log, conf.RejectsMailbox, messageID); err != nil {
					log.Errorx("removing message from rejects mailbox", err, mlog.Field("messageid", messageID))
				}
			}
		})

		err = acc.Close()
		log.Check(err, "closing account after delivering")
		acc = nil
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
			SMTPUTF8:   c.smtputf8,
			From:       smtp.Path{Localpart: "postmaster", IPDomain: deliverErrors[0].rcptTo.IPDomain},
			To:         *c.mailFrom,
			Subject:    "mail delivery failure",
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
		} else if err := queueDSN(context.TODO(), c, *c.mailFrom, dsnMsg); err != nil {
			metricServerErrors.WithLabelValues("queuedsn").Inc()
			c.log.Errorx("queuing DSN for incoming delivery, no DSN sent", err)
		}
	}

	err = os.Remove(dataFile.Name())
	c.log.Check(err, "removing file after delivery")
	err = dataFile.Close()
	c.log.Check(err, "closing data file after delivery")
	*pdataFile = nil

	c.transactionGood++
	c.transactionBad-- // Compensate for early earlier pessimistic increase.
	c.rset()
	c.writecodeline(smtp.C250Completed, smtp.SeMailbox2Other0, "it is done", nil)
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
