// Package imapserver implements an IMAPv4 server, rev2 (RFC 9051) and rev1 with extensions (RFC 3501 and more).
package imapserver

/*
Implementation notes

IMAP4rev2 includes functionality that was in extensions for IMAP4rev1. The
extensions sometimes include features not in IMAP4rev2. We want IMAP4rev1-only
implementations to use extensions, so we implement the full feature set of the
extension and announce it as capability. The extensions: LITERAL+, IDLE,
NAMESPACE, BINARY, UNSELECT, UIDPLUS, ESEARCH, SEARCHRES, SASL-IR, ENABLE,
LIST-EXTENDED, SPECIAL-USE, MOVE, UTF8=ONLY.

We take a liberty with UTF8=ONLY. We are supposed to wait for ENABLE of
UTF8=ACCEPT or IMAP4rev2 before we respond with quoted strings that contain
non-ASCII UTF-8. Until that's enabled, we do use UTF-7 for mailbox names. See
../rfc/6855:251

- We never execute multiple commands at the same time for a connection. We expect a client to open multiple connections instead. ../rfc/9051:1110
- Do not write output on a connection with an account lock held. Writing can block, a slow client could block account operations.
- When handling commands that modify the selected mailbox, always check that the mailbox is not opened readonly. And always revalidate the selected mailbox, another session may have deleted the mailbox.
- After making changes to an account/mailbox/message, you must broadcast changes. You must do this with the account lock held. Otherwise, other later changes (e.g. message deliveries) may be made and broadcast before changes that were made earlier. Make sure to commit changes in the database first, because the commit may fail.
- Mailbox hierarchies are slash separated, no leading slash. We keep the case, except INBOX is renamed to Inbox, also for submailboxes in INBOX. We don't allow existence of a child where its parent does not exist. We have no \NoInferiors or \NoSelect. Newly created mailboxes are automatically subscribed.
- For CONDSTORE and QRESYNC support, we set "modseq" for each change/expunge. Once expunged, a modseq doesn't change anymore. We don't yet remove old expunged records. The records aren't too big. Next step may be to let an admin reclaim space manually.
*/

/*
- todo: do not return binary data for a fetch body. at least not for imap4rev1. we should be encoding it as base64?
- todo: on expunge we currently remove the message even if other sessions still have a reference to the uid. if they try to query the uid, they'll get an error. we could be nicer and only actually remove the message when the last reference has gone. we could add a new flag to store.Message marking the message as expunged, not give new session access to such messages, and make store remove them at startup, and clean them when the last session referencing the session goes. however, it will get much more complicated. renaming messages would need special handling. and should we do the same for removed mailboxes?
- todo: try to recover from syntax errors when the last command line ends with a }, i.e. a literal. we currently abort the entire connection. we may want to read some amount of literal data and continue with a next command.
- todo future: more extensions: OBJECTID, MULTISEARCH, REPLACE, NOTIFY, CATENATE, MULTIAPPEND, SORT, THREAD, CREATE-SPECIAL-USE.
*/

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
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
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/ratelimit"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/store"
)

var (
	metricIMAPConnection = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_imap_connection_total",
			Help: "Incoming IMAP connections.",
		},
		[]string{
			"service", // imap, imaps
		},
	)
	metricIMAPCommands = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_imap_command_duration_seconds",
			Help:    "IMAP command duration and result codes in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20},
		},
		[]string{
			"cmd",
			"result", // ok, panic, ioerror, badsyntax, servererror, usererror, error
		},
	)
)

var limiterConnectionrate, limiterConnections *ratelimit.Limiter

func init() {
	// Also called by tests, so they don't trigger the rate limiter.
	limitersInit()
}

func limitersInit() {
	mox.LimitersInit()
	limiterConnectionrate = &ratelimit.Limiter{
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

// Delay after bad/suspicious behaviour. Tests set these to zero.
var badClientDelay = time.Second // Before reads and after 1-byte writes for probably spammers.
var authFailDelay = time.Second  // After authentication failure.

// Capabilities (extensions) the server supports. Connections will add a few more, e.g. STARTTLS, LOGINDISABLED, AUTH=PLAIN.
// ENABLE: ../rfc/5161
// LITERAL+: ../rfc/7888
// IDLE: ../rfc/2177
// SASL-IR: ../rfc/4959
// BINARY: ../rfc/3516
// UNSELECT: ../rfc/3691
// UIDPLUS: ../rfc/4315
// ESEARCH: ../rfc/4731
// SEARCHRES: ../rfc/5182
// MOVE: ../rfc/6851
// UTF8=ONLY: ../rfc/6855
// LIST-EXTENDED: ../rfc/5258
// SPECIAL-USE: ../rfc/6154
// LIST-STATUS: ../rfc/5819
// ID: ../rfc/2971
// AUTH=SCRAM-SHA-256-PLUS and AUTH=SCRAM-SHA-256: ../rfc/7677 ../rfc/5802
// AUTH=SCRAM-SHA-1-PLUS and AUTH=SCRAM-SHA-1: ../rfc/5802
// AUTH=CRAM-MD5: ../rfc/2195
// APPENDLIMIT, we support the max possible size, 1<<63 - 1: ../rfc/7889:129
// CONDSTORE: ../rfc/7162:411
// QRESYNC: ../rfc/7162:1323
// STATUS=SIZE: ../rfc/8438 ../rfc/9051:8024
//
// We always announce support for SCRAM PLUS-variants, also on connections without
// TLS. The client should not be selecting PLUS variants on non-TLS connections,
// instead opting to do the bare SCRAM variant without indicating the server claims
// to support the PLUS variant (skipping the server downgrade detection check).
const serverCapabilities = "IMAP4rev2 IMAP4rev1 ENABLE LITERAL+ IDLE SASL-IR BINARY UNSELECT UIDPLUS ESEARCH SEARCHRES MOVE UTF8=ACCEPT LIST-EXTENDED SPECIAL-USE LIST-STATUS AUTH=SCRAM-SHA-256-PLUS AUTH=SCRAM-SHA-256 AUTH=SCRAM-SHA-1-PLUS AUTH=SCRAM-SHA-1 AUTH=CRAM-MD5 ID APPENDLIMIT=9223372036854775807 CONDSTORE QRESYNC STATUS=SIZE"

type conn struct {
	cid               int64
	state             state
	conn              net.Conn
	tls               bool               // Whether TLS has been initialized.
	br                *bufio.Reader      // From remote, with TLS unwrapped in case of TLS.
	line              chan lineErr       // If set, instead of reading from br, a line is read from this channel. For reading a line in IDLE while also waiting for mailbox/account updates.
	lastLine          string             // For detecting if syntax error is fatal, i.e. if this ends with a literal. Without crlf.
	bw                *bufio.Writer      // To remote, with TLS added in case of TLS.
	tr                *moxio.TraceReader // Kept to change trace level when reading/writing cmd/auth/data.
	tw                *moxio.TraceWriter
	slow              bool        // If set, reads are done with a 1 second sleep, and writes are done 1 byte at a time, to keep spammers busy.
	lastlog           time.Time   // For printing time since previous log line.
	tlsConfig         *tls.Config // TLS config to use for handshake.
	remoteIP          net.IP
	noRequireSTARTTLS bool
	cmd               string // Currently executing, for deciding to applyChanges and logging.
	cmdMetric         string // Currently executing, for metrics.
	cmdStart          time.Time
	ncmds             int // Number of commands processed. Used to abort connection when first incoming command is unknown/invalid.
	log               mlog.Log
	enabled           map[capability]bool // All upper-case.

	// Set by SEARCH with SAVE. Can be used by commands accepting a sequence-set with
	// value "$". When used, UIDs must be verified to still exist, because they may
	// have been expunged. Cleared by a SELECT or EXAMINE.
	// Nil means no searchResult is present. An empty list is a valid searchResult,
	// just not matching any messages.
	// ../rfc/5182:13 ../rfc/9051:4040
	searchResult []store.UID

	// Only when authenticated.
	authFailed int    // Number of failed auth attempts. For slowing down remote with many failures.
	username   string // Full username as used during login.
	account    *store.Account
	comm       *store.Comm // For sending/receiving changes on mailboxes in account, e.g. from messages incoming on smtp, or another imap client.

	mailboxID int64       // Only for StateSelected.
	readonly  bool        // If opened mailbox is readonly.
	uids      []store.UID // UIDs known in this session, sorted. todo future: store more space-efficiently, as ranges.
}

// capability for use with ENABLED and CAPABILITY. We always keep this upper case,
// e.g. IMAP4REV2. These values are treated case-insensitive, but it's easier for
// comparison to just always have the same case.
type capability string

const (
	capIMAP4rev2  capability = "IMAP4REV2"
	capUTF8Accept capability = "UTF8=ACCEPT"
	capCondstore  capability = "CONDSTORE"
	capQresync    capability = "QRESYNC"
)

type lineErr struct {
	line string
	err  error
}

type state byte

const (
	stateNotAuthenticated state = iota
	stateAuthenticated
	stateSelected
)

func stateCommands(cmds ...string) map[string]struct{} {
	r := map[string]struct{}{}
	for _, cmd := range cmds {
		r[cmd] = struct{}{}
	}
	return r
}

var (
	commandsStateAny              = stateCommands("capability", "noop", "logout", "id")
	commandsStateNotAuthenticated = stateCommands("starttls", "authenticate", "login")
	commandsStateAuthenticated    = stateCommands("enable", "select", "examine", "create", "delete", "rename", "subscribe", "unsubscribe", "list", "namespace", "status", "append", "idle", "lsub")
	commandsStateSelected         = stateCommands("close", "unselect", "expunge", "search", "fetch", "store", "copy", "move", "uid expunge", "uid search", "uid fetch", "uid store", "uid copy", "uid move")
)

var commands = map[string]func(c *conn, tag, cmd string, p *parser){
	// Any state.
	"capability": (*conn).cmdCapability,
	"noop":       (*conn).cmdNoop,
	"logout":     (*conn).cmdLogout,
	"id":         (*conn).cmdID,

	// Notauthenticated.
	"starttls":     (*conn).cmdStarttls,
	"authenticate": (*conn).cmdAuthenticate,
	"login":        (*conn).cmdLogin,

	// Authenticated and selected.
	"enable":      (*conn).cmdEnable,
	"select":      (*conn).cmdSelect,
	"examine":     (*conn).cmdExamine,
	"create":      (*conn).cmdCreate,
	"delete":      (*conn).cmdDelete,
	"rename":      (*conn).cmdRename,
	"subscribe":   (*conn).cmdSubscribe,
	"unsubscribe": (*conn).cmdUnsubscribe,
	"list":        (*conn).cmdList,
	"lsub":        (*conn).cmdLsub,
	"namespace":   (*conn).cmdNamespace,
	"status":      (*conn).cmdStatus,
	"append":      (*conn).cmdAppend,
	"idle":        (*conn).cmdIdle,

	// Selected.
	"check":       (*conn).cmdCheck,
	"close":       (*conn).cmdClose,
	"unselect":    (*conn).cmdUnselect,
	"expunge":     (*conn).cmdExpunge,
	"uid expunge": (*conn).cmdUIDExpunge,
	"search":      (*conn).cmdSearch,
	"uid search":  (*conn).cmdUIDSearch,
	"fetch":       (*conn).cmdFetch,
	"uid fetch":   (*conn).cmdUIDFetch,
	"store":       (*conn).cmdStore,
	"uid store":   (*conn).cmdUIDStore,
	"copy":        (*conn).cmdCopy,
	"uid copy":    (*conn).cmdUIDCopy,
	"move":        (*conn).cmdMove,
	"uid move":    (*conn).cmdUIDMove,
}

var errIO = errors.New("io error")             // For read/write errors and errors that should close the connection.
var errProtocol = errors.New("protocol error") // For protocol errors for which a stack trace should be printed.

var sanityChecks bool

// check err for sanity.
// if not nil and checkSanity true (set during tests), then panic. if not nil during normal operation, just log.
func (c *conn) xsanity(err error, format string, args ...any) {
	if err == nil {
		return
	}
	if sanityChecks {
		panic(fmt.Errorf("%s: %s", fmt.Sprintf(format, args...), err))
	}
	c.log.Errorx(fmt.Sprintf(format, args...), err)
}

type msgseq uint32

// Listen initializes all imap listeners for the configuration, and stores them for Serve to start them.
func Listen() {
	names := maps.Keys(mox.Conf.Static.Listeners)
	sort.Strings(names)
	for _, name := range names {
		listener := mox.Conf.Static.Listeners[name]

		var tlsConfig *tls.Config
		if listener.TLS != nil {
			tlsConfig = listener.TLS.Config
		}

		if listener.IMAP.Enabled {
			port := config.Port(listener.IMAP.Port, 143)
			for _, ip := range listener.IPs {
				listen1("imap", name, ip, port, tlsConfig, false, listener.IMAP.NoRequireSTARTTLS)
			}
		}

		if listener.IMAPS.Enabled {
			port := config.Port(listener.IMAPS.Port, 993)
			for _, ip := range listener.IPs {
				listen1("imaps", name, ip, port, tlsConfig, true, false)
			}
		}
	}
}

var servers []func()

func listen1(protocol, listenerName, ip string, port int, tlsConfig *tls.Config, xtls, noRequireSTARTTLS bool) {
	log := mlog.New("imapserver", nil)
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	if os.Getuid() == 0 {
		log.Print("listening for imap",
			slog.String("listener", listenerName),
			slog.String("addr", addr),
			slog.String("protocol", protocol))
	}
	network := mox.Network(ip)
	ln, err := mox.Listen(network, addr)
	if err != nil {
		log.Fatalx("imap: listen for imap", err, slog.String("protocol", protocol), slog.String("listener", listenerName))
	}
	if xtls {
		ln = tls.NewListener(ln, tlsConfig)
	}

	serve := func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Infox("imap: accept", err, slog.String("protocol", protocol), slog.String("listener", listenerName))
				continue
			}

			metricIMAPConnection.WithLabelValues(protocol).Inc()
			go serve(listenerName, mox.Cid(), tlsConfig, conn, xtls, noRequireSTARTTLS)
		}
	}

	servers = append(servers, serve)
}

// Serve starts serving on all listeners, launching a goroutine per listener.
func Serve() {
	for _, serve := range servers {
		go serve()
	}
	servers = nil
}

// returns whether this connection accepts utf-8 in strings.
func (c *conn) utf8strings() bool {
	return c.enabled[capIMAP4rev2] || c.enabled[capUTF8Accept]
}

func (c *conn) encodeMailbox(s string) string {
	if c.utf8strings() {
		return s
	}
	return utf7encode(s)
}

func (c *conn) xdbwrite(fn func(tx *bstore.Tx)) {
	err := c.account.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		fn(tx)
		return nil
	})
	xcheckf(err, "transaction")
}

func (c *conn) xdbread(fn func(tx *bstore.Tx)) {
	err := c.account.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
		fn(tx)
		return nil
	})
	xcheckf(err, "transaction")
}

// Closes the currently selected/active mailbox, setting state from selected to authenticated.
// Does not remove messages marked for deletion.
func (c *conn) unselect() {
	if c.state == stateSelected {
		c.state = stateAuthenticated
	}
	c.mailboxID = 0
	c.uids = nil
}

func (c *conn) setSlow(on bool) {
	if on && !c.slow {
		c.log.Debug("connection changed to slow")
	} else if !on && c.slow {
		c.log.Debug("connection restored to regular pace")
	}
	c.slow = on
}

// Write makes a connection an io.Writer. It panics for i/o errors. These errors
// are handled in the connection command loop.
func (c *conn) Write(buf []byte) (int, error) {
	chunk := len(buf)
	if c.slow {
		chunk = 1
	}

	var n int
	for len(buf) > 0 {
		err := c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		c.log.Check(err, "setting write deadline")

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

// Cache of line buffers for reading commands.
// QRESYNC recommends 8k max line lengths. ../rfc/7162:2159
var bufpool = moxio.NewBufpool(8, 16*1024)

// read line from connection, not going through line channel.
func (c *conn) readline0() (string, error) {
	if c.slow && badClientDelay > 0 {
		mox.Sleep(mox.Context, badClientDelay)
	}

	d := 30 * time.Minute
	if c.state == stateNotAuthenticated {
		d = 30 * time.Second
	}
	err := c.conn.SetReadDeadline(time.Now().Add(d))
	c.log.Check(err, "setting read deadline")

	line, err := bufpool.Readline(c.log, c.br)
	if err != nil && errors.Is(err, moxio.ErrLineTooLong) {
		return "", fmt.Errorf("%s (%w)", err, errProtocol)
	} else if err != nil {
		return "", fmt.Errorf("%s (%w)", err, errIO)
	}
	return line, nil
}

func (c *conn) lineChan() chan lineErr {
	if c.line == nil {
		c.line = make(chan lineErr, 1)
		go func() {
			line, err := c.readline0()
			c.line <- lineErr{line, err}
		}()
	}
	return c.line
}

// readline from either the c.line channel, or otherwise read from connection.
func (c *conn) readline(readCmd bool) string {
	var line string
	var err error
	if c.line != nil {
		le := <-c.line
		c.line = nil
		line, err = le.line, le.err
	} else {
		line, err = c.readline0()
	}
	if err != nil {
		if readCmd && errors.Is(err, os.ErrDeadlineExceeded) {
			err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			c.log.Check(err, "setting write deadline")
			c.writelinef("* BYE inactive")
		}
		if !errors.Is(err, errIO) && !errors.Is(err, errProtocol) {
			err = fmt.Errorf("%s (%w)", err, errIO)
		}
		panic(err)
	}
	c.lastLine = line

	// We typically respond immediately (IDLE is an exception).
	// The client may not be reading, or may have disappeared.
	// Don't wait more than 5 minutes before closing down the connection.
	// The write deadline is managed in IDLE as well.
	// For unauthenticated connections, we require the client to read faster.
	wd := 5 * time.Minute
	if c.state == stateNotAuthenticated {
		wd = 30 * time.Second
	}
	err = c.conn.SetWriteDeadline(time.Now().Add(wd))
	c.log.Check(err, "setting write deadline")

	return line
}

// write tagged command response, but first write pending changes.
func (c *conn) writeresultf(format string, args ...any) {
	c.bwriteresultf(format, args...)
	c.xflush()
}

// write buffered tagged command response, but first write pending changes.
func (c *conn) bwriteresultf(format string, args ...any) {
	switch c.cmd {
	case "fetch", "store", "search":
		// ../rfc/9051:5862 ../rfc/7162:2033
	default:
		if c.comm != nil {
			c.applyChanges(c.comm.Get(), false)
		}
	}
	c.bwritelinef(format, args...)
}

func (c *conn) writelinef(format string, args ...any) {
	c.bwritelinef(format, args...)
	c.xflush()
}

// Buffer line for write.
func (c *conn) bwritelinef(format string, args ...any) {
	format += "\r\n"
	fmt.Fprintf(c.bw, format, args...)
}

func (c *conn) xflush() {
	err := c.bw.Flush()
	xcheckf(err, "flush") // Should never happen, the Write caused by the Flush should panic on i/o error.
}

func (c *conn) readCommand(tag *string) (cmd string, p *parser) {
	line := c.readline(true)
	p = newParser(line, c)
	p.context("tag")
	*tag = p.xtag()
	p.context("command")
	p.xspace()
	cmd = p.xcommand()
	return cmd, newParser(p.remainder(), c)
}

func (c *conn) xreadliteral(size int64, sync bool) string {
	if sync {
		c.writelinef("+ ")
	}
	buf := make([]byte, size)
	if size > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			c.log.Errorx("setting read deadline", err)
		}

		_, err := io.ReadFull(c.br, buf)
		if err != nil {
			// Cannot use xcheckf due to %w handling of errIO.
			panic(fmt.Errorf("reading literal: %s (%w)", err, errIO))
		}
	}
	return string(buf)
}

func (c *conn) xhighestModSeq(tx *bstore.Tx, mailboxID int64) store.ModSeq {
	qms := bstore.QueryTx[store.Message](tx)
	qms.FilterNonzero(store.Message{MailboxID: mailboxID})
	qms.SortDesc("ModSeq")
	qms.Limit(1)
	m, err := qms.Get()
	if err == bstore.ErrAbsent {
		return store.ModSeq(0)
	}
	xcheckf(err, "looking up highest modseq for mailbox")
	return m.ModSeq
}

var cleanClose struct{} // Sentinel value for panic/recover indicating clean close of connection.

func serve(listenerName string, cid int64, tlsConfig *tls.Config, nc net.Conn, xtls, noRequireSTARTTLS bool) {
	var remoteIP net.IP
	if a, ok := nc.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = a.IP
	} else {
		// For net.Pipe, during tests.
		remoteIP = net.ParseIP("127.0.0.10")
	}

	c := &conn{
		cid:               cid,
		conn:              nc,
		tls:               xtls,
		lastlog:           time.Now(),
		tlsConfig:         tlsConfig,
		remoteIP:          remoteIP,
		noRequireSTARTTLS: noRequireSTARTTLS,
		enabled:           map[capability]bool{},
		cmd:               "(greeting)",
		cmdStart:          time.Now(),
	}
	var logmutex sync.Mutex
	c.log = mlog.New("imapserver", nil).WithFunc(func() []slog.Attr {
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
	c.tr = moxio.NewTraceReader(c.log, "C: ", c.conn)
	c.tw = moxio.NewTraceWriter(c.log, "S: ", c)
	// todo: tracing should be done on whatever comes out of c.br. the remote connection write a command plus data, and bufio can read it in one read, causing a command parser that sets the tracing level to data to have no effect. we are now typically logging sent messages, when mail clients append to the Sent mailbox.
	c.br = bufio.NewReader(c.tr)
	c.bw = bufio.NewWriter(c.tw)

	// Many IMAP connections use IDLE to wait for new incoming messages. We'll enable
	// keepalive to get a higher chance of the connection staying alive, or otherwise
	// detecting broken connections early.
	xconn := c.conn
	if xtls {
		xconn = c.conn.(*tls.Conn).NetConn()
	}
	if tcpconn, ok := xconn.(*net.TCPConn); ok {
		if err := tcpconn.SetKeepAlivePeriod(5 * time.Minute); err != nil {
			c.log.Errorx("setting keepalive period", err)
		} else if err := tcpconn.SetKeepAlive(true); err != nil {
			c.log.Errorx("enabling keepalive", err)
		}
	}

	c.log.Info("new connection",
		slog.Any("remote", c.conn.RemoteAddr()),
		slog.Any("local", c.conn.LocalAddr()),
		slog.Bool("tls", xtls),
		slog.String("listener", listenerName))

	defer func() {
		c.conn.Close()

		if c.account != nil {
			c.comm.Unregister()
			err := c.account.Close()
			c.xsanity(err, "close account")
			c.account = nil
			c.comm = nil
		}

		x := recover()
		if x == nil || x == cleanClose {
			c.log.Info("connection closed")
		} else if err, ok := x.(error); ok && isClosed(err) {
			c.log.Infox("connection closed", err)
		} else {
			c.log.Error("unhandled panic", slog.Any("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Imapserver)
		}
	}()

	select {
	case <-mox.Shutdown.Done():
		// ../rfc/9051:5381
		c.writelinef("* BYE mox shutting down")
		return
	default:
	}

	if !limiterConnectionrate.Add(c.remoteIP, time.Now(), 1) {
		c.writelinef("* BYE connection rate from your ip or network too high, slow down please")
		return
	}

	// If remote IP/network resulted in too many authentication failures, refuse to serve.
	if !mox.LimiterFailedAuth.CanAdd(c.remoteIP, time.Now(), 1) {
		metrics.AuthenticationRatelimitedInc("imap")
		c.log.Debug("refusing connection due to many auth failures", slog.Any("remoteip", c.remoteIP))
		c.writelinef("* BYE too many auth failures")
		return
	}

	if !limiterConnections.Add(c.remoteIP, time.Now(), 1) {
		c.log.Debug("refusing connection due to many open connections", slog.Any("remoteip", c.remoteIP))
		c.writelinef("* BYE too many open connections from your ip or network")
		return
	}
	defer limiterConnections.Add(c.remoteIP, time.Now(), -1)

	// We register and unregister the original connection, in case it c.conn is
	// replaced with a TLS connection later on.
	mox.Connections.Register(nc, "imap", listenerName)
	defer mox.Connections.Unregister(nc)

	c.writelinef("* OK [CAPABILITY %s] mox imap", c.capabilities())

	for {
		c.command()
		c.xflush() // For flushing errors, or possibly commands that did not flush explicitly.
	}
}

// isClosed returns whether i/o failed, typically because the connection is closed.
// For connection errors, we often want to generate fewer logs.
func isClosed(err error) bool {
	return errors.Is(err, errIO) || errors.Is(err, errProtocol) || moxio.IsClosed(err)
}

func (c *conn) command() {
	var tag, cmd, cmdlow string
	var p *parser

	defer func() {
		var result string
		defer func() {
			metricIMAPCommands.WithLabelValues(c.cmdMetric, result).Observe(float64(time.Since(c.cmdStart)) / float64(time.Second))
		}()

		logFields := []slog.Attr{
			slog.String("cmd", c.cmd),
			slog.Duration("duration", time.Since(c.cmdStart)),
		}
		c.cmd = ""

		x := recover()
		if x == nil || x == cleanClose {
			c.log.Debug("imap command done", logFields...)
			result = "ok"
			if x == cleanClose {
				panic(x)
			}
			return
		}
		err, ok := x.(error)
		if !ok {
			c.log.Error("imap command panic", append([]slog.Attr{slog.Any("panic", x)}, logFields...)...)
			result = "panic"
			panic(x)
		}

		var sxerr syntaxError
		var uerr userError
		var serr serverError
		if isClosed(err) {
			c.log.Infox("imap command ioerror", err, logFields...)
			result = "ioerror"
			if errors.Is(err, errProtocol) {
				debug.PrintStack()
			}
			panic(err)
		} else if errors.As(err, &sxerr) {
			result = "badsyntax"
			if c.ncmds == 0 {
				// Other side is likely speaking something else than IMAP, send error message and
				// stop processing because there is a good chance whatever they sent has multiple
				// lines.
				c.writelinef("* BYE please try again speaking imap")
				panic(errIO)
			}
			c.log.Debugx("imap command syntax error", sxerr.err, logFields...)
			c.log.Info("imap syntax error", slog.String("lastline", c.lastLine))
			fatal := strings.HasSuffix(c.lastLine, "+}")
			if fatal {
				err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				c.log.Check(err, "setting write deadline")
			}
			if sxerr.line != "" {
				c.bwritelinef("%s", sxerr.line)
			}
			code := ""
			if sxerr.code != "" {
				code = "[" + sxerr.code + "] "
			}
			c.bwriteresultf("%s BAD %s%s unrecognized syntax/command: %v", tag, code, cmd, sxerr.errmsg)
			if fatal {
				c.xflush()
				panic(fmt.Errorf("aborting connection after syntax error for command with non-sync literal: %w", errProtocol))
			}
		} else if errors.As(err, &serr) {
			result = "servererror"
			c.log.Errorx("imap command server error", err, logFields...)
			debug.PrintStack()
			c.bwriteresultf("%s NO %s %v", tag, cmd, err)
		} else if errors.As(err, &uerr) {
			result = "usererror"
			c.log.Debugx("imap command user error", err, logFields...)
			if uerr.code != "" {
				c.bwriteresultf("%s NO [%s] %s %v", tag, uerr.code, cmd, err)
			} else {
				c.bwriteresultf("%s NO %s %v", tag, cmd, err)
			}
		} else {
			// Other type of panic, we pass it on, aborting the connection.
			result = "panic"
			c.log.Errorx("imap command panic", err, logFields...)
			panic(err)
		}
	}()

	tag = "*"
	cmd, p = c.readCommand(&tag)
	cmdlow = strings.ToLower(cmd)
	c.cmd = cmdlow
	c.cmdStart = time.Now()
	c.cmdMetric = "(unrecognized)"

	select {
	case <-mox.Shutdown.Done():
		// ../rfc/9051:5375
		c.writelinef("* BYE shutting down")
		panic(errIO)
	default:
	}

	fn := commands[cmdlow]
	if fn == nil {
		xsyntaxErrorf("unknown command %q", cmd)
	}
	c.cmdMetric = c.cmd
	c.ncmds++

	// Check if command is allowed in this state.
	if _, ok1 := commandsStateAny[cmdlow]; ok1 {
	} else if _, ok2 := commandsStateNotAuthenticated[cmdlow]; ok2 && c.state == stateNotAuthenticated {
	} else if _, ok3 := commandsStateAuthenticated[cmdlow]; ok3 && c.state == stateAuthenticated || c.state == stateSelected {
	} else if _, ok4 := commandsStateSelected[cmdlow]; ok4 && c.state == stateSelected {
	} else if ok1 || ok2 || ok3 || ok4 {
		xuserErrorf("not allowed in this connection state")
	} else {
		xserverErrorf("unrecognized command")
	}

	fn(c, tag, cmd, p)
}

func (c *conn) broadcast(changes []store.Change) {
	if len(changes) == 0 {
		return
	}
	c.log.Debug("broadcast changes", slog.Any("changes", changes))
	c.comm.Broadcast(changes)
}

// matchStringer matches a string against reference + mailbox patterns.
type matchStringer interface {
	MatchString(s string) bool
}

type noMatch struct{}

// MatchString for noMatch always returns false.
func (noMatch) MatchString(s string) bool {
	return false
}

// xmailboxPatternMatcher returns a matcher for mailbox names given the reference and patterns.
// Patterns can include "%" and "*", matching any character excluding and including a slash respectively.
func xmailboxPatternMatcher(ref string, patterns []string) matchStringer {
	if strings.HasPrefix(ref, "/") {
		return noMatch{}
	}

	var subs []string
	for _, pat := range patterns {
		if strings.HasPrefix(pat, "/") {
			continue
		}

		s := pat
		if ref != "" {
			s = path.Join(ref, pat)
		}

		// Fix casing for all Inbox paths.
		first := strings.SplitN(s, "/", 2)[0]
		if strings.EqualFold(first, "Inbox") {
			s = "Inbox" + s[len("Inbox"):]
		}

		// ../rfc/9051:2361
		var rs string
		for _, c := range s {
			if c == '%' {
				rs += "[^/]*"
			} else if c == '*' {
				rs += ".*"
			} else {
				rs += regexp.QuoteMeta(string(c))
			}
		}
		subs = append(subs, rs)
	}

	if len(subs) == 0 {
		return noMatch{}
	}
	rs := "^(" + strings.Join(subs, "|") + ")$"
	re, err := regexp.Compile(rs)
	xcheckf(err, "compiling regexp for mailbox patterns")
	return re
}

func (c *conn) sequence(uid store.UID) msgseq {
	return uidSearch(c.uids, uid)
}

func uidSearch(uids []store.UID, uid store.UID) msgseq {
	s := 0
	e := len(uids)
	for s < e {
		i := (s + e) / 2
		m := uids[i]
		if uid == m {
			return msgseq(i + 1)
		} else if uid < m {
			e = i
		} else {
			s = i + 1
		}
	}
	return 0
}

func (c *conn) xsequence(uid store.UID) msgseq {
	seq := c.sequence(uid)
	if seq <= 0 {
		xserverErrorf("unknown uid %d (%w)", uid, errProtocol)
	}
	return seq
}

func (c *conn) sequenceRemove(seq msgseq, uid store.UID) {
	i := seq - 1
	if c.uids[i] != uid {
		xserverErrorf(fmt.Sprintf("got uid %d at msgseq %d, expected uid %d", uid, seq, c.uids[i]))
	}
	copy(c.uids[i:], c.uids[i+1:])
	c.uids = c.uids[:len(c.uids)-1]
	if sanityChecks {
		checkUIDs(c.uids)
	}
}

// add uid to the session. care must be taken that pending changes are fetched
// while holding the account wlock, and applied before adding this uid, because
// those pending changes may contain another new uid that has to be added first.
func (c *conn) uidAppend(uid store.UID) {
	if uidSearch(c.uids, uid) > 0 {
		xserverErrorf("uid already present (%w)", errProtocol)
	}
	if len(c.uids) > 0 && uid < c.uids[len(c.uids)-1] {
		xserverErrorf("new uid %d is smaller than last uid %d (%w)", uid, c.uids[len(c.uids)-1], errProtocol)
	}
	c.uids = append(c.uids, uid)
	if sanityChecks {
		checkUIDs(c.uids)
	}
}

// sanity check that uids are in ascending order.
func checkUIDs(uids []store.UID) {
	for i, uid := range uids {
		if uid == 0 || i > 0 && uid <= uids[i-1] {
			xserverErrorf("bad uids %v", uids)
		}
	}
}

func (c *conn) xnumSetUIDs(isUID bool, nums numSet) []store.UID {
	_, uids := c.xnumSetConditionUIDs(false, true, isUID, nums)
	return uids
}

func (c *conn) xnumSetCondition(isUID bool, nums numSet) []any {
	uidargs, _ := c.xnumSetConditionUIDs(true, false, isUID, nums)
	return uidargs
}

func (c *conn) xnumSetConditionUIDs(forDB, returnUIDs bool, isUID bool, nums numSet) ([]any, []store.UID) {
	if nums.searchResult {
		// Update previously stored UIDs. Some may have been deleted.
		// Once deleted a UID will never come back, so we'll just remove those uids.
		o := 0
		for _, uid := range c.searchResult {
			if uidSearch(c.uids, uid) > 0 {
				c.searchResult[o] = uid
				o++
			}
		}
		c.searchResult = c.searchResult[:o]
		uidargs := make([]any, len(c.searchResult))
		for i, uid := range c.searchResult {
			uidargs[i] = uid
		}
		return uidargs, c.searchResult
	}

	var uidargs []any
	var uids []store.UID

	add := func(uid store.UID) {
		if forDB {
			uidargs = append(uidargs, uid)
		}
		if returnUIDs {
			uids = append(uids, uid)
		}
	}

	if !isUID {
		// Sequence numbers that don't exist, or * on an empty mailbox, should result in a BAD response. ../rfc/9051:7018
		for _, r := range nums.ranges {
			var ia, ib int
			if r.first.star {
				if len(c.uids) == 0 {
					xsyntaxErrorf("invalid seqset * on empty mailbox")
				}
				ia = len(c.uids) - 1
			} else {
				ia = int(r.first.number - 1)
				if ia >= len(c.uids) {
					xsyntaxErrorf("msgseq %d not in mailbox", r.first.number)
				}
			}
			if r.last == nil {
				add(c.uids[ia])
				continue
			}

			if r.last.star {
				if len(c.uids) == 0 {
					xsyntaxErrorf("invalid seqset * on empty mailbox")
				}
				ib = len(c.uids) - 1
			} else {
				ib = int(r.last.number - 1)
				if ib >= len(c.uids) {
					xsyntaxErrorf("msgseq %d not in mailbox", r.last.number)
				}
			}
			if ia > ib {
				ia, ib = ib, ia
			}
			for _, uid := range c.uids[ia : ib+1] {
				add(uid)
			}
		}
		return uidargs, uids
	}

	// UIDs that do not exist can be ignored.
	if len(c.uids) == 0 {
		return nil, nil
	}

	for _, r := range nums.ranges {
		last := r.first
		if r.last != nil {
			last = *r.last
		}

		uida := store.UID(r.first.number)
		if r.first.star {
			uida = c.uids[len(c.uids)-1]
		}

		uidb := store.UID(last.number)
		if last.star {
			uidb = c.uids[len(c.uids)-1]
		}

		if uida > uidb {
			uida, uidb = uidb, uida
		}

		// Binary search for uida.
		s := 0
		e := len(c.uids)
		for s < e {
			m := (s + e) / 2
			if uida < c.uids[m] {
				e = m
			} else if uida > c.uids[m] {
				s = m + 1
			} else {
				break
			}
		}

		for _, uid := range c.uids[s:] {
			if uid >= uida && uid <= uidb {
				add(uid)
			} else if uid > uidb {
				break
			}
		}
	}

	return uidargs, uids
}

func (c *conn) ok(tag, cmd string) {
	c.bwriteresultf("%s OK %s done", tag, cmd)
	c.xflush()
}

// xcheckmailboxname checks if name is valid, returning an INBOX-normalized name.
// I.e. it changes various casings of INBOX and INBOX/* to Inbox and Inbox/*.
// Name is invalid if it contains leading/trailing/double slashes, or when it isn't
// unicode-normalized, or when empty or has special characters.
func xcheckmailboxname(name string, allowInbox bool) string {
	name, isinbox, err := store.CheckMailboxName(name, allowInbox)
	if isinbox {
		xuserErrorf("special mailboxname Inbox not allowed")
	} else if err != nil {
		xusercodeErrorf("CANNOT", "%s", err)
	}
	return name
}

// Lookup mailbox by name.
// If the mailbox does not exist, panic is called with a user error.
// Must be called with account rlock held.
func (c *conn) xmailbox(tx *bstore.Tx, name string, missingErrCode string) store.Mailbox {
	mb, err := c.account.MailboxFind(tx, name)
	xcheckf(err, "finding mailbox")
	if mb == nil {
		// missingErrCode can be empty, or e.g. TRYCREATE or ALREADYEXISTS.
		xusercodeErrorf(missingErrCode, "%w", store.ErrUnknownMailbox)
	}
	return *mb
}

// Lookup mailbox by ID.
// If the mailbox does not exist, panic is called with a user error.
// Must be called with account rlock held.
func (c *conn) xmailboxID(tx *bstore.Tx, id int64) store.Mailbox {
	mb := store.Mailbox{ID: id}
	err := tx.Get(&mb)
	if err == bstore.ErrAbsent {
		xuserErrorf("%w", store.ErrUnknownMailbox)
	}
	return mb
}

// Apply changes to our session state.
// If initial is false, updates like EXISTS and EXPUNGE are written to the client.
// If initial is true, we only apply the changes.
// Should not be called while holding locks, as changes are written to client connections, which can block.
// Does not flush output.
func (c *conn) applyChanges(changes []store.Change, initial bool) {
	if len(changes) == 0 {
		return
	}

	err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	c.log.Check(err, "setting write deadline")

	c.log.Debug("applying changes", slog.Any("changes", changes))

	// Only keep changes for the selected mailbox, and changes that are always relevant.
	var n []store.Change
	for _, change := range changes {
		var mbID int64
		switch ch := change.(type) {
		case store.ChangeAddUID:
			mbID = ch.MailboxID
		case store.ChangeRemoveUIDs:
			mbID = ch.MailboxID
		case store.ChangeFlags:
			mbID = ch.MailboxID
		case store.ChangeRemoveMailbox, store.ChangeAddMailbox, store.ChangeRenameMailbox, store.ChangeAddSubscription:
			n = append(n, change)
			continue
		case store.ChangeMailboxCounts, store.ChangeMailboxSpecialUse, store.ChangeMailboxKeywords, store.ChangeThread:
		default:
			panic(fmt.Errorf("missing case for %#v", change))
		}
		if c.state == stateSelected && mbID == c.mailboxID {
			n = append(n, change)
		}
	}
	changes = n

	qresync := c.enabled[capQresync]
	condstore := c.enabled[capCondstore]

	i := 0
	for i < len(changes) {
		// First process all new uids. So we only send a single EXISTS.
		var adds []store.ChangeAddUID
		for ; i < len(changes); i++ {
			ch, ok := changes[i].(store.ChangeAddUID)
			if !ok {
				break
			}
			seq := c.sequence(ch.UID)
			if seq > 0 && initial {
				continue
			}
			c.uidAppend(ch.UID)
			adds = append(adds, ch)
		}
		if len(adds) > 0 {
			if initial {
				continue
			}
			// Write the exists, and the UID and flags as well. Hopefully the client waits for
			// long enough after the EXISTS to see these messages, and doesn't request them
			// again with a FETCH.
			c.bwritelinef("* %d EXISTS", len(c.uids))
			for _, add := range adds {
				seq := c.xsequence(add.UID)
				var modseqStr string
				if condstore {
					modseqStr = fmt.Sprintf(" MODSEQ (%d)", add.ModSeq.Client())
				}
				c.bwritelinef("* %d FETCH (UID %d FLAGS %s%s)", seq, add.UID, flaglist(add.Flags, add.Keywords).pack(c), modseqStr)
			}
			continue
		}

		change := changes[i]
		i++

		switch ch := change.(type) {
		case store.ChangeRemoveUIDs:
			var vanishedUIDs numSet
			for _, uid := range ch.UIDs {
				var seq msgseq
				if initial {
					seq = c.sequence(uid)
					if seq <= 0 {
						continue
					}
				} else {
					seq = c.xsequence(uid)
				}
				c.sequenceRemove(seq, uid)
				if !initial {
					if qresync {
						vanishedUIDs.append(uint32(uid))
					} else {
						c.bwritelinef("* %d EXPUNGE", seq)
					}
				}
			}
			if qresync {
				// VANISHED without EARLIER. ../rfc/7162:2004
				for _, s := range vanishedUIDs.Strings(4*1024 - 32) {
					c.bwritelinef("* VANISHED %s", s)
				}
			}
		case store.ChangeFlags:
			// The uid can be unknown if we just expunged it while another session marked it as deleted just before.
			seq := c.sequence(ch.UID)
			if seq <= 0 {
				continue
			}
			if !initial {
				var modseqStr string
				if condstore {
					modseqStr = fmt.Sprintf(" MODSEQ (%d)", ch.ModSeq.Client())
				}
				c.bwritelinef("* %d FETCH (UID %d FLAGS %s%s)", seq, ch.UID, flaglist(ch.Flags, ch.Keywords).pack(c), modseqStr)
			}
		case store.ChangeRemoveMailbox:
			// Only announce \NonExistent to modern clients, otherwise they may ignore the
			// unrecognized \NonExistent and interpret this as a newly created mailbox, while
			// the goal was to remove it...
			if c.enabled[capIMAP4rev2] {
				c.bwritelinef(`* LIST (\NonExistent) "/" %s`, astring(c.encodeMailbox(ch.Name)).pack(c))
			}
		case store.ChangeAddMailbox:
			c.bwritelinef(`* LIST (%s) "/" %s`, strings.Join(ch.Flags, " "), astring(c.encodeMailbox(ch.Mailbox.Name)).pack(c))
		case store.ChangeRenameMailbox:
			// OLDNAME only with IMAP4rev2 or NOTIFY ../rfc/9051:2726 ../rfc/5465:628
			var oldname string
			if c.enabled[capIMAP4rev2] {
				oldname = fmt.Sprintf(` ("OLDNAME" (%s))`, string0(c.encodeMailbox(ch.OldName)).pack(c))
			}
			c.bwritelinef(`* LIST (%s) "/" %s%s`, strings.Join(ch.Flags, " "), astring(c.encodeMailbox(ch.NewName)).pack(c), oldname)
		case store.ChangeAddSubscription:
			c.bwritelinef(`* LIST (%s) "/" %s`, strings.Join(append([]string{`\Subscribed`}, ch.Flags...), " "), astring(c.encodeMailbox(ch.Name)).pack(c))
		default:
			panic(fmt.Sprintf("internal error, missing case for %#v", change))
		}
	}
}

// Capability returns the capabilities this server implements and currently has
// available given the connection state.
//
// State: any
func (c *conn) cmdCapability(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1208 ../rfc/3501:1300

	// Request syntax: ../rfc/9051:6464 ../rfc/3501:4669
	p.xempty()

	caps := c.capabilities()

	// Response syntax: ../rfc/9051:6427 ../rfc/3501:4655
	c.bwritelinef("* CAPABILITY %s", caps)
	c.ok(tag, cmd)
}

// capabilities returns non-empty string with available capabilities based on connection state.
// For use in cmdCapability and untagged OK responses on connection start, login and authenticate.
func (c *conn) capabilities() string {
	caps := serverCapabilities
	// ../rfc/9051:1238
	// We only allow starting without TLS when explicitly configured, in violation of RFC.
	if !c.tls && c.tlsConfig != nil {
		caps += " STARTTLS"
	}
	if c.tls || c.noRequireSTARTTLS {
		caps += " AUTH=PLAIN"
	} else {
		caps += " LOGINDISABLED"
	}
	return caps
}

// No op, but useful for retrieving pending changes as untagged responses, e.g. of
// message delivery.
//
// State: any
func (c *conn) cmdNoop(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1261 ../rfc/3501:1363

	// Request syntax: ../rfc/9051:6464 ../rfc/3501:4669
	p.xempty()
	c.ok(tag, cmd)
}

// Logout, after which server closes the connection.
//
// State: any
func (c *conn) cmdLogout(tag, cmd string, p *parser) {
	// Commands: ../rfc/3501:1407 ../rfc/9051:1290

	// Request syntax: ../rfc/9051:6464 ../rfc/3501:4669
	p.xempty()

	c.unselect()
	c.state = stateNotAuthenticated
	// Response syntax: ../rfc/9051:6886 ../rfc/3501:4935
	c.bwritelinef("* BYE thanks")
	c.ok(tag, cmd)
	panic(cleanClose)
}

// Clients can use ID to tell the server which software they are using. Servers can
// respond with their version. For statistics/logging/debugging purposes.
//
// State: any
func (c *conn) cmdID(tag, cmd string, p *parser) {
	// Command: ../rfc/2971:129

	// Request syntax: ../rfc/2971:241
	p.xspace()
	var params map[string]string
	if p.take("(") {
		params = map[string]string{}
		for !p.take(")") {
			if len(params) > 0 {
				p.xspace()
			}
			k := p.xstring()
			p.xspace()
			v := p.xnilString()
			if _, ok := params[k]; ok {
				xsyntaxErrorf("duplicate key %q", k)
			}
			params[k] = v
		}
	} else {
		p.xnil()
	}
	p.xempty()

	// We just log the client id.
	c.log.Info("client id", slog.Any("params", params))

	// Response syntax: ../rfc/2971:243
	// We send our name and version. ../rfc/2971:193
	c.bwritelinef(`* ID ("name" "mox" "version" %s)`, string0(moxvar.Version).pack(c))
	c.ok(tag, cmd)
}

// STARTTLS enables TLS on the connection, after a plain text start.
// Only allowed if TLS isn't already enabled, either through connecting to a
// TLS-enabled TCP port, or a previous STARTTLS command.
// After STARTTLS, plain text authentication typically becomes available.
//
// Status: Not authenticated.
func (c *conn) cmdStarttls(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1340 ../rfc/3501:1468

	// Request syntax: ../rfc/9051:6473 ../rfc/3501:4676
	p.xempty()

	if c.tls {
		xsyntaxErrorf("tls already active") // ../rfc/9051:1353
	}

	conn := c.conn
	if n := c.br.Buffered(); n > 0 {
		buf := make([]byte, n)
		_, err := io.ReadFull(c.br, buf)
		xcheckf(err, "reading buffered data for tls handshake")
		conn = &prefixConn{buf, conn}
	}
	// We add the cid to facilitate debugging in case of TLS connection failure.
	c.ok(tag, cmd+" ("+mox.ReceivedID(c.cid)+")")

	cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
	ctx, cancel := context.WithTimeout(cidctx, time.Minute)
	defer cancel()
	tlsConn := tls.Server(conn, c.tlsConfig)
	c.log.Debug("starting tls server handshake")
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		panic(fmt.Errorf("starttls handshake: %s (%w)", err, errIO))
	}
	cancel()
	tlsversion, ciphersuite := moxio.TLSInfo(tlsConn)
	c.log.Debug("tls server handshake done", slog.String("tls", tlsversion), slog.String("ciphersuite", ciphersuite))

	c.conn = tlsConn
	c.tr = moxio.NewTraceReader(c.log, "C: ", c.conn)
	c.tw = moxio.NewTraceWriter(c.log, "S: ", c)
	c.br = bufio.NewReader(c.tr)
	c.bw = bufio.NewWriter(c.tw)
	c.tls = true
}

// Authenticate using SASL. Supports multiple back and forths between client and
// server to finish authentication, unlike LOGIN which is just a single
// username/password.
//
// Status: Not authenticated.
func (c *conn) cmdAuthenticate(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1403 ../rfc/3501:1519
	// Examples: ../rfc/9051:1520 ../rfc/3501:1631

	// For many failed auth attempts, slow down verification attempts.
	if c.authFailed > 3 && authFailDelay > 0 {
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
		metrics.AuthenticationInc("imap", authVariant, authResult)
		switch authResult {
		case "ok":
			mox.LimiterFailedAuth.Reset(c.remoteIP, time.Now())
		default:
			mox.LimiterFailedAuth.Add(c.remoteIP, time.Now(), 1)
		}
	}()

	// Request syntax: ../rfc/9051:6341 ../rfc/3501:4561
	p.xspace()
	authType := p.xatom()

	xreadInitial := func() []byte {
		var line string
		if p.empty() {
			c.writelinef("+ ")
			line = c.readline(false)
		} else {
			// ../rfc/9051:1407 ../rfc/4959:84
			p.xspace()
			line = p.remainder()
			if line == "=" {
				// ../rfc/9051:1450
				line = "" // Base64 decode will result in empty buffer.
			}
		}
		// ../rfc/9051:1442 ../rfc/3501:1553
		if line == "*" {
			authResult = "aborted"
			xsyntaxErrorf("authenticate aborted by client")
		}
		buf, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			xsyntaxErrorf("parsing base64: %v", err)
		}
		return buf
	}

	xreadContinuation := func() []byte {
		line := c.readline(false)
		if line == "*" {
			authResult = "aborted"
			xsyntaxErrorf("authenticate aborted by client")
		}
		buf, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			xsyntaxErrorf("parsing base64: %v", err)
		}
		return buf
	}

	switch strings.ToUpper(authType) {
	case "PLAIN":
		authVariant = "plain"

		if !c.noRequireSTARTTLS && !c.tls {
			// ../rfc/9051:5194
			xusercodeErrorf("PRIVACYREQUIRED", "tls required for login")
		}

		// Plain text passwords, mark as traceauth.
		defer c.xtrace(mlog.LevelTraceauth)()
		buf := xreadInitial()
		c.xtrace(mlog.LevelTrace) // Restore.
		plain := bytes.Split(buf, []byte{0})
		if len(plain) != 3 {
			xsyntaxErrorf("bad plain auth data, expected 3 nul-separated tokens, got %d tokens", len(plain))
		}
		authz := string(plain[0])
		authc := string(plain[1])
		password := string(plain[2])

		if authz != "" && authz != authc {
			xusercodeErrorf("AUTHORIZATIONFAILED", "cannot assume role")
		}

		acc, err := store.OpenEmailAuth(c.log, authc, password)
		if err != nil {
			if errors.Is(err, store.ErrUnknownCredentials) {
				authResult = "badcreds"
				c.log.Info("authentication failed", slog.String("username", authc))
				xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
			}
			xusercodeErrorf("", "error")
		}
		c.account = acc
		c.username = authc

	case "CRAM-MD5":
		authVariant = strings.ToLower(authType)

		// ../rfc/9051:1462
		p.xempty()

		// ../rfc/2195:82
		chal := fmt.Sprintf("<%d.%d@%s>", uint64(mox.CryptoRandInt()), time.Now().UnixNano(), mox.Conf.Static.HostnameDomain.ASCII)
		c.writelinef("+ %s", base64.StdEncoding.EncodeToString([]byte(chal)))

		resp := xreadContinuation()
		t := strings.Split(string(resp), " ")
		if len(t) != 2 || len(t[1]) != 2*md5.Size {
			xsyntaxErrorf("malformed cram-md5 response")
		}
		addr := t[0]
		c.log.Debug("cram-md5 auth", slog.String("address", addr))
		acc, _, err := store.OpenEmail(c.log, addr)
		if err != nil {
			if errors.Is(err, store.ErrUnknownCredentials) {
				c.log.Info("failed authentication attempt", slog.String("username", addr), slog.Any("remote", c.remoteIP))
				xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
			}
			xserverErrorf("looking up address: %v", err)
		}
		defer func() {
			if acc != nil {
				err := acc.Close()
				c.xsanity(err, "close account")
			}
		}()
		var ipadhash, opadhash hash.Hash
		acc.WithRLock(func() {
			err := acc.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
				password, err := bstore.QueryTx[store.Password](tx).Get()
				if err == bstore.ErrAbsent {
					c.log.Info("failed authentication attempt", slog.String("username", addr), slog.Any("remote", c.remoteIP))
					xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
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
			c.log.Info("cram-md5 auth attempt without derived secrets set, save password again to store secrets", slog.String("username", addr))
			c.log.Info("failed authentication attempt", slog.String("username", addr), slog.Any("remote", c.remoteIP))
			xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
		}

		// ../rfc/2195:138 ../rfc/2104:142
		ipadhash.Write([]byte(chal))
		opadhash.Write(ipadhash.Sum(nil))
		digest := fmt.Sprintf("%x", opadhash.Sum(nil))
		if digest != t[1] {
			c.log.Info("failed authentication attempt", slog.String("username", addr), slog.Any("remote", c.remoteIP))
			xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
		}

		c.account = acc
		acc = nil // Cancel cleanup.
		c.username = addr

	case "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1":
		// todo: improve handling of errors during scram. e.g. invalid parameters. should we abort the imap command, or continue until the end and respond with a scram-level error?
		// todo: use single implementation between ../imapserver/server.go and ../smtpserver/server.go

		// No plaintext credentials, we can log these normally.

		authVariant = strings.ToLower(authType)
		var h func() hash.Hash
		switch authVariant {
		case "scram-sha-1", "scram-sha-1-plus":
			h = sha1.New
		case "scram-sha-256", "scram-sha-256-plus":
			h = sha256.New
		default:
			xserverErrorf("missing case for scram variant")
		}

		var cs *tls.ConnectionState
		requireChannelBinding := strings.HasSuffix(authVariant, "-plus")
		if requireChannelBinding && !c.tls {
			xuserErrorf("cannot use plus variant with tls channel binding without tls")
		}
		if c.tls {
			xcs := c.conn.(*tls.Conn).ConnectionState()
			cs = &xcs
		}
		c0 := xreadInitial()
		ss, err := scram.NewServer(h, c0, cs, requireChannelBinding)
		if err != nil {
			xsyntaxErrorf("starting scram: %s", err)
		}
		c.log.Debug("scram auth", slog.String("authentication", ss.Authentication))
		acc, _, err := store.OpenEmail(c.log, ss.Authentication)
		if err != nil {
			// todo: we could continue scram with a generated salt, deterministically generated
			// from the username. that way we don't have to store anything but attackers cannot
			// learn if an account exists. same for absent scram saltedpassword below.
			xuserErrorf("scram not possible")
		}
		defer func() {
			if acc != nil {
				err := acc.Close()
				c.xsanity(err, "close account")
			}
		}()
		if ss.Authorization != "" && ss.Authorization != ss.Authentication {
			xuserErrorf("authentication with authorization for different user not supported")
		}
		var xscram store.SCRAM
		acc.WithRLock(func() {
			err := acc.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
				password, err := bstore.QueryTx[store.Password](tx).Get()
				switch authVariant {
				case "scram-sha-1", "scram-sha-1-plus":
					xscram = password.SCRAMSHA1
				case "scram-sha-256", "scram-sha-256-plus":
					xscram = password.SCRAMSHA256
				default:
					xserverErrorf("missing case for scram credentials")
				}
				if err == bstore.ErrAbsent || err == nil && (len(xscram.Salt) == 0 || xscram.Iterations == 0 || len(xscram.SaltedPassword) == 0) {
					c.log.Info("scram auth attempt without derived secrets set, save password again to store secrets", slog.String("address", ss.Authentication))
					xuserErrorf("scram not possible")
				}
				xcheckf(err, "fetching credentials")
				return err
			})
			xcheckf(err, "read tx")
		})
		s1, err := ss.ServerFirst(xscram.Iterations, xscram.Salt)
		xcheckf(err, "scram first server step")
		c.writelinef("+ %s", base64.StdEncoding.EncodeToString([]byte(s1)))
		c2 := xreadContinuation()
		s3, err := ss.Finish(c2, xscram.SaltedPassword)
		if len(s3) > 0 {
			c.writelinef("+ %s", base64.StdEncoding.EncodeToString([]byte(s3)))
		}
		if err != nil {
			c.readline(false) // Should be "*" for cancellation.
			if errors.Is(err, scram.ErrInvalidProof) {
				authResult = "badcreds"
				c.log.Info("failed authentication attempt", slog.String("username", ss.Authentication), slog.Any("remote", c.remoteIP))
				xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
			}
			xuserErrorf("server final: %w", err)
		}

		// Client must still respond, but there is nothing to say. See ../rfc/9051:6221
		// The message should be empty. todo: should we require it is empty?
		xreadContinuation()

		c.account = acc
		acc = nil // Cancel cleanup.
		c.username = ss.Authentication

	default:
		xuserErrorf("method not supported")
	}

	c.setSlow(false)
	authResult = "ok"
	c.authFailed = 0
	c.comm = store.RegisterComm(c.account)
	c.state = stateAuthenticated
	c.writeresultf("%s OK [CAPABILITY %s] authenticate done", tag, c.capabilities())
}

// Login logs in with username and password.
//
// Status: Not authenticated.
func (c *conn) cmdLogin(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1597 ../rfc/3501:1663

	authResult := "error"
	defer func() {
		metrics.AuthenticationInc("imap", "login", authResult)
	}()

	// todo: get this line logged with traceauth. the plaintext password is included on the command line, which we've already read (before dispatching to this function).

	// Request syntax: ../rfc/9051:6667 ../rfc/3501:4804
	p.xspace()
	userid := p.xastring()
	p.xspace()
	password := p.xastring()
	p.xempty()

	if !c.noRequireSTARTTLS && !c.tls {
		// ../rfc/9051:5194
		xusercodeErrorf("PRIVACYREQUIRED", "tls required for login")
	}

	// For many failed auth attempts, slow down verification attempts.
	if c.authFailed > 3 && authFailDelay > 0 {
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

	acc, err := store.OpenEmailAuth(c.log, userid, password)
	if err != nil {
		authResult = "badcreds"
		var code string
		if errors.Is(err, store.ErrUnknownCredentials) {
			code = "AUTHENTICATIONFAILED"
			c.log.Info("failed authentication attempt", slog.String("username", userid), slog.Any("remote", c.remoteIP))
		}
		xusercodeErrorf(code, "login failed")
	}
	c.account = acc
	c.username = userid
	c.authFailed = 0
	c.setSlow(false)
	c.comm = store.RegisterComm(acc)
	c.state = stateAuthenticated
	authResult = "ok"
	c.writeresultf("%s OK [CAPABILITY %s] login done", tag, c.capabilities())
}

// Enable explicitly opts in to an extension. A server can typically send new kinds
// of responses to a client. Most extensions do not require an ENABLE because a
// client implicitly opts in to new response syntax by making a requests that uses
// new optional extension request syntax.
//
// State: Authenticated and selected.
func (c *conn) cmdEnable(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1652 ../rfc/5161:80
	// Examples: ../rfc/9051:1728 ../rfc/5161:147

	// Request syntax: ../rfc/9051:6518 ../rfc/5161:207
	p.xspace()
	caps := []string{p.xatom()}
	for !p.empty() {
		p.xspace()
		caps = append(caps, p.xatom())
	}

	// Clients should only send capabilities that need enabling.
	// We should only echo that we recognize as needing enabling.
	var enabled string
	var qresync bool
	for _, s := range caps {
		cap := capability(strings.ToUpper(s))
		switch cap {
		case capIMAP4rev2,
			capUTF8Accept,
			capCondstore: // ../rfc/7162:384
			c.enabled[cap] = true
			enabled += " " + s
		case capQresync:
			c.enabled[cap] = true
			enabled += " " + s
			qresync = true
		}
	}
	// QRESYNC enabled CONDSTORE too ../rfc/7162:1391
	if qresync && !c.enabled[capCondstore] {
		c.xensureCondstore(nil)
		enabled += " CONDSTORE"
	}

	// Response syntax: ../rfc/9051:6520 ../rfc/5161:211
	c.bwritelinef("* ENABLED%s", enabled)
	c.ok(tag, cmd)
}

// The CONDSTORE extension can be enabled in many different ways. ../rfc/7162:368
// If a mailbox is selected, an untagged OK with HIGHESTMODSEQ is written to the
// client. If tx is non-nil, it is used to read the HIGHESTMODSEQ from the
// database. Otherwise a new read-only transaction is created.
func (c *conn) xensureCondstore(tx *bstore.Tx) {
	if !c.enabled[capCondstore] {
		c.enabled[capCondstore] = true
		// todo spec: can we send an untagged enabled response?
		// ../rfc/7162:603
		if c.mailboxID <= 0 {
			return
		}
		var modseq store.ModSeq
		if tx != nil {
			modseq = c.xhighestModSeq(tx, c.mailboxID)
		} else {
			c.xdbread(func(tx *bstore.Tx) {
				modseq = c.xhighestModSeq(tx, c.mailboxID)
			})
		}
		c.bwritelinef("* OK [HIGHESTMODSEQ %d] after condstore-enabling command", modseq.Client())
	}
}

// State: Authenticated and selected.
func (c *conn) cmdSelect(tag, cmd string, p *parser) {
	c.cmdSelectExamine(true, tag, cmd, p)
}

// State: Authenticated and selected.
func (c *conn) cmdExamine(tag, cmd string, p *parser) {
	c.cmdSelectExamine(false, tag, cmd, p)
}

// Select and examine are almost the same commands. Select just opens a mailbox for
// read/write and examine opens a mailbox readonly.
//
// State: Authenticated and selected.
func (c *conn) cmdSelectExamine(isselect bool, tag, cmd string, p *parser) {
	// Select command: ../rfc/9051:1754 ../rfc/3501:1743 ../rfc/7162:1146 ../rfc/7162:1432
	// Examine command: ../rfc/9051:1868 ../rfc/3501:1855
	// Select examples: ../rfc/9051:1831 ../rfc/3501:1826 ../rfc/7162:1159 ../rfc/7162:1479

	// Select request syntax: ../rfc/9051:7005 ../rfc/3501:4996 ../rfc/4466:652 ../rfc/7162:2559 ../rfc/7162:2598
	// Examine request syntax: ../rfc/9051:6551 ../rfc/3501:4746
	p.xspace()
	name := p.xmailbox()

	var qruidvalidity uint32
	var qrmodseq int64                                    // QRESYNC required parameters.
	var qrknownUIDs, qrknownSeqSet, qrknownUIDSet *numSet // QRESYNC optional parameters.
	if p.space() {
		seen := map[string]bool{}
		p.xtake("(")
		for len(seen) == 0 || !p.take(")") {
			w := p.xtakelist("CONDSTORE", "QRESYNC")
			if seen[w] {
				xsyntaxErrorf("duplicate select parameter %s", w)
			}
			seen[w] = true

			switch w {
			case "CONDSTORE":
				// ../rfc/7162:363
				c.xensureCondstore(nil) // ../rfc/7162:373
			case "QRESYNC":
				// ../rfc/7162:2598
				// Note: unlike with CONDSTORE, there are no QRESYNC-related commands/parameters
				// that enable capabilities.
				if !c.enabled[capQresync] {
					// ../rfc/7162:1446
					xsyntaxErrorf("QRESYNC must first be enabled")
				}
				p.xspace()
				p.xtake("(")
				qruidvalidity = p.xnznumber() // ../rfc/7162:2606
				p.xspace()
				qrmodseq = p.xnznumber64()
				if p.take(" ") {
					seqMatchData := p.take("(")
					if !seqMatchData {
						ss := p.xnumSet0(false, false) // ../rfc/7162:2608
						qrknownUIDs = &ss
						seqMatchData = p.take(" (")
					}
					if seqMatchData {
						ss0 := p.xnumSet0(false, false)
						qrknownSeqSet = &ss0
						p.xspace()
						ss1 := p.xnumSet0(false, false)
						qrknownUIDSet = &ss1
						p.xtake(")")
					}
				}
				p.xtake(")")
			default:
				panic("missing case for select param " + w)
			}
		}
	}
	p.xempty()

	// Deselect before attempting the new select. This means we will deselect when an
	// error occurs during select.
	// ../rfc/9051:1809
	if c.state == stateSelected {
		// ../rfc/9051:1812 ../rfc/7162:2111
		c.bwritelinef("* OK [CLOSED] x")
		c.unselect()
	}

	name = xcheckmailboxname(name, true)

	var highestModSeq store.ModSeq
	var highDeletedModSeq store.ModSeq
	var firstUnseen msgseq = 0
	var mb store.Mailbox
	c.account.WithRLock(func() {
		c.xdbread(func(tx *bstore.Tx) {
			mb = c.xmailbox(tx, name, "")

			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: mb.ID})
			q.FilterEqual("Expunged", false)
			q.SortAsc("UID")
			c.uids = []store.UID{}
			var seq msgseq = 1
			err := q.ForEach(func(m store.Message) error {
				c.uids = append(c.uids, m.UID)
				if firstUnseen == 0 && !m.Seen {
					firstUnseen = seq
				}
				seq++
				return nil
			})
			if sanityChecks {
				checkUIDs(c.uids)
			}
			xcheckf(err, "fetching uids")

			// Condstore extension, find the highest modseq.
			if c.enabled[capCondstore] {
				highestModSeq = c.xhighestModSeq(tx, mb.ID)
			}
			// For QRESYNC, we need to know the highest modset of deleted expunged records to
			// maintain synchronization.
			if c.enabled[capQresync] {
				highDeletedModSeq, err = c.account.HighestDeletedModSeq(tx)
				xcheckf(err, "getting highest deleted modseq")
			}
		})
	})
	c.applyChanges(c.comm.Get(), true)

	var flags string
	if len(mb.Keywords) > 0 {
		flags = " " + strings.Join(mb.Keywords, " ")
	}
	c.bwritelinef(`* FLAGS (\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent%s)`, flags)
	c.bwritelinef(`* OK [PERMANENTFLAGS (\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent \*)] x`)
	if !c.enabled[capIMAP4rev2] {
		c.bwritelinef(`* 0 RECENT`)
	}
	c.bwritelinef(`* %d EXISTS`, len(c.uids))
	if !c.enabled[capIMAP4rev2] && firstUnseen > 0 {
		// ../rfc/9051:8051 ../rfc/3501:1774
		c.bwritelinef(`* OK [UNSEEN %d] x`, firstUnseen)
	}
	c.bwritelinef(`* OK [UIDVALIDITY %d] x`, mb.UIDValidity)
	c.bwritelinef(`* OK [UIDNEXT %d] x`, mb.UIDNext)
	c.bwritelinef(`* LIST () "/" %s`, astring(c.encodeMailbox(mb.Name)).pack(c))
	if c.enabled[capCondstore] {
		// ../rfc/7162:417
		// ../rfc/7162-eid5055 ../rfc/7162:484 ../rfc/7162:1167
		c.bwritelinef(`* OK [HIGHESTMODSEQ %d] x`, highestModSeq.Client())
	}

	// If QRESYNC uidvalidity matches, we send any changes. ../rfc/7162:1509
	if qruidvalidity == mb.UIDValidity {
		// We send the vanished UIDs at the end, so we can easily combine the modseq
		// changes and vanished UIDs that result from that, with the vanished UIDs from the
		// case where we don't store enough history.
		vanishedUIDs := map[store.UID]struct{}{}

		var preVanished store.UID
		var oldClientUID store.UID
		// If samples of known msgseq and uid pairs are given (they must be in order), we
		// use them to determine the earliest UID for which we send VANISHED responses.
		// ../rfc/7162:1579
		if qrknownSeqSet != nil {
			if !qrknownSeqSet.isBasicIncreasing() {
				xuserErrorf("QRESYNC known message sequence set must be numeric and strictly increasing")
			}
			if !qrknownUIDSet.isBasicIncreasing() {
				xuserErrorf("QRESYNC known uid set must be numeric and strictly increasing")
			}
			seqiter := qrknownSeqSet.newIter()
			uiditer := qrknownUIDSet.newIter()
			for {
				msgseq, ok0 := seqiter.Next()
				uid, ok1 := uiditer.Next()
				if !ok0 && !ok1 {
					break
				} else if !ok0 || !ok1 {
					xsyntaxErrorf("invalid combination of known sequence set and uid set, must be of equal length")
				}
				i := int(msgseq - 1)
				if i < 0 || i >= len(c.uids) || c.uids[i] != store.UID(uid) {
					if uidSearch(c.uids, store.UID(uid)) <= 0 {
						// We will check this old client UID for consistency below.
						oldClientUID = store.UID(uid)
					}
					break
				}
				preVanished = store.UID(uid + 1)
			}
		}

		// We gather vanished UIDs and report them at the end. This seems OK because we
		// already sent HIGHESTMODSEQ, and a client should know not to commit that value
		// until after it has seen the tagged OK of this command. The RFC has a remark
		// about ordering of some untagged responses, it's not immediately clear what it
		// means, but given the examples appears to allude to servers that decide to not
		// send expunge/vanished before the tagged OK.
		// ../rfc/7162:1340

		// We are reading without account lock. Similar to when we process FETCH/SEARCH
		// requests. We don't have to reverify existence of the mailbox, so we don't
		// rlock, even briefly.
		c.xdbread(func(tx *bstore.Tx) {
			if oldClientUID > 0 {
				// The client sent a UID that is now removed. This is typically fine. But we check
				// that it is consistent with the modseq the client sent. If the UID already didn't
				// exist at that modseq, the client may be missing some information.
				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: mb.ID, UID: oldClientUID})
				m, err := q.Get()
				if err == nil {
					// If client claims to be up to date up to and including qrmodseq, and the message
					// was deleted at or before that time, we send changes from just before that
					// modseq, and we send vanished for all UIDs.
					if m.Expunged && qrmodseq >= m.ModSeq.Client() {
						qrmodseq = m.ModSeq.Client() - 1
						preVanished = 0
						qrknownUIDs = nil
						c.bwritelinef("* OK [ALERT] Synchronization inconsistency in client detected. Client tried to sync with a UID that was removed at or after the MODSEQ it sent in the request. Sending all historic message removals for selected mailbox. Full synchronization recommended.")
					}
				} else if err != bstore.ErrAbsent {
					xcheckf(err, "checking old client uid")
				}
			}

			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: mb.ID})
			// Note: we don't filter by Expunged.
			q.FilterGreater("ModSeq", store.ModSeqFromClient(qrmodseq))
			q.FilterLessEqual("ModSeq", highestModSeq)
			q.SortAsc("ModSeq")
			err := q.ForEach(func(m store.Message) error {
				if m.Expunged && m.UID < preVanished {
					return nil
				}
				// If known UIDs was specified, we only report about those UIDs. ../rfc/7162:1523
				if qrknownUIDs != nil && !qrknownUIDs.contains(uint32(m.UID)) {
					return nil
				}
				if m.Expunged {
					vanishedUIDs[m.UID] = struct{}{}
					return nil
				}
				msgseq := c.sequence(m.UID)
				if msgseq > 0 {
					c.bwritelinef("* %d FETCH (UID %d FLAGS %s MODSEQ (%d))", msgseq, m.UID, flaglist(m.Flags, m.Keywords).pack(c), m.ModSeq.Client())
				}
				return nil
			})
			xcheckf(err, "listing changed messages")
		})

		// Add UIDs from client's known UID set to vanished list if we don't have enough history.
		if qrmodseq < highDeletedModSeq.Client() {
			// If no known uid set was in the request, we substitute 1:max or the empty set.
			// ../rfc/7162:1524
			if qrknownUIDs == nil {
				if len(c.uids) > 0 {
					qrknownUIDs = &numSet{ranges: []numRange{{first: setNumber{number: 1}, last: &setNumber{number: uint32(c.uids[len(c.uids)-1])}}}}
				} else {
					qrknownUIDs = &numSet{}
				}
			}

			iter := qrknownUIDs.newIter()
			for {
				v, ok := iter.Next()
				if !ok {
					break
				}
				if c.sequence(store.UID(v)) <= 0 {
					vanishedUIDs[store.UID(v)] = struct{}{}
				}
			}
		}

		// Now that we have all vanished UIDs, send them over compactly.
		if len(vanishedUIDs) > 0 {
			l := maps.Keys(vanishedUIDs)
			sort.Slice(l, func(i, j int) bool {
				return l[i] < l[j]
			})
			// ../rfc/7162:1985
			for _, s := range compactUIDSet(l).Strings(4*1024 - 32) {
				c.bwritelinef("* VANISHED (EARLIER) %s", s)
			}
		}
	}

	if isselect {
		c.bwriteresultf("%s OK [READ-WRITE] x", tag)
		c.readonly = false
	} else {
		c.bwriteresultf("%s OK [READ-ONLY] x", tag)
		c.readonly = true
	}
	c.mailboxID = mb.ID
	c.state = stateSelected
	c.searchResult = nil
	c.xflush()
}

// Create makes a new mailbox, and its parents too if absent.
//
// State: Authenticated and selected.
func (c *conn) cmdCreate(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1900 ../rfc/3501:1888
	// Examples: ../rfc/9051:1951 ../rfc/6154:411 ../rfc/4466:212 ../rfc/3501:1933

	// Request syntax: ../rfc/9051:6484 ../rfc/6154:468 ../rfc/4466:500 ../rfc/3501:4687
	p.xspace()
	name := p.xmailbox()
	// todo: support CREATE-SPECIAL-USE ../rfc/6154:296
	p.xempty()

	origName := name
	name = strings.TrimRight(name, "/") // ../rfc/9051:1930
	name = xcheckmailboxname(name, false)

	var changes []store.Change
	var created []string // Created mailbox names.

	c.account.WithWLock(func() {
		c.xdbwrite(func(tx *bstore.Tx) {
			var exists bool
			var err error
			changes, created, exists, err = c.account.MailboxCreate(tx, name)
			if exists {
				// ../rfc/9051:1914
				xuserErrorf("mailbox already exists")
			}
			xcheckf(err, "creating mailbox")
		})

		c.broadcast(changes)
	})

	for _, n := range created {
		var oldname string
		// OLDNAME only with IMAP4rev2 or NOTIFY ../rfc/9051:2726 ../rfc/5465:628
		if c.enabled[capIMAP4rev2] && n == name && name != origName && !(name == "Inbox" || strings.HasPrefix(name, "Inbox/")) {
			oldname = fmt.Sprintf(` ("OLDNAME" (%s))`, string0(c.encodeMailbox(origName)).pack(c))
		}
		c.bwritelinef(`* LIST (\Subscribed) "/" %s%s`, astring(c.encodeMailbox(n)).pack(c), oldname)
	}
	c.ok(tag, cmd)
}

// Delete removes a mailbox and all its messages.
// Inbox cannot be removed.
//
// State: Authenticated and selected.
func (c *conn) cmdDelete(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1972 ../rfc/3501:1946
	// Examples:  ../rfc/9051:2025 ../rfc/3501:1992

	// Request syntax: ../rfc/9051:6505 ../rfc/3501:4716
	p.xspace()
	name := p.xmailbox()
	p.xempty()

	name = xcheckmailboxname(name, false)

	// Messages to remove after having broadcasted the removal of messages.
	var removeMessageIDs []int64

	c.account.WithWLock(func() {
		var mb store.Mailbox
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			mb = c.xmailbox(tx, name, "NONEXISTENT")

			var hasChildren bool
			var err error
			changes, removeMessageIDs, hasChildren, err = c.account.MailboxDelete(context.TODO(), c.log, tx, mb)
			if hasChildren {
				xusercodeErrorf("HASCHILDREN", "mailbox has a child, only leaf mailboxes can be deleted")
			}
			xcheckf(err, "deleting mailbox")
		})

		c.broadcast(changes)
	})

	for _, mID := range removeMessageIDs {
		p := c.account.MessagePath(mID)
		err := os.Remove(p)
		c.log.Check(err, "removing message file for mailbox delete", slog.String("path", p))
	}

	c.ok(tag, cmd)
}

// Rename changes the name of a mailbox.
// Renaming INBOX is special, it moves the inbox messages to a new mailbox, leaving inbox empty.
// Renaming a mailbox with submailboxes also renames all submailboxes.
// Subscriptions stay with the old name, though newly created missing parent
// mailboxes for the destination name are automatically subscribed.
//
// State: Authenticated and selected.
func (c *conn) cmdRename(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:2062 ../rfc/3501:2040
	// Examples: ../rfc/9051:2132 ../rfc/3501:2092

	// Request syntax: ../rfc/9051:6863 ../rfc/3501:4908
	p.xspace()
	src := p.xmailbox()
	p.xspace()
	dst := p.xmailbox()
	p.xempty()

	src = xcheckmailboxname(src, true)
	dst = xcheckmailboxname(dst, false)

	c.account.WithWLock(func() {
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			srcMB := c.xmailbox(tx, src, "NONEXISTENT")

			// Inbox is very special. Unlike other mailboxes, its children are not moved. And
			// unlike a regular move, its messages are moved to a newly created mailbox. We do
			// indeed create a new destination mailbox and actually move the messages.
			// ../rfc/9051:2101
			if src == "Inbox" {
				exists, err := c.account.MailboxExists(tx, dst)
				xcheckf(err, "checking if destination mailbox exists")
				if exists {
					xusercodeErrorf("ALREADYEXISTS", "destination mailbox %q already exists", dst)
				}
				if dst == src {
					xuserErrorf("cannot move inbox to itself")
				}

				uidval, err := c.account.NextUIDValidity(tx)
				xcheckf(err, "next uid validity")

				dstMB := store.Mailbox{
					Name:        dst,
					UIDValidity: uidval,
					UIDNext:     1,
					Keywords:    srcMB.Keywords,
					HaveCounts:  true,
				}
				err = tx.Insert(&dstMB)
				xcheckf(err, "create new destination mailbox")

				modseq, err := c.account.NextModSeq(tx)
				xcheckf(err, "assigning next modseq")

				changes = make([]store.Change, 2) // Placeholders filled in below.

				// Move existing messages, with their ID's and on-disk files intact, to the new
				// mailbox. We keep the expunged messages, the destination mailbox doesn't care
				// about them.
				var oldUIDs []store.UID
				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: srcMB.ID})
				q.FilterEqual("Expunged", false)
				q.SortAsc("UID")
				err = q.ForEach(func(m store.Message) error {
					om := m
					om.ID = 0
					om.ModSeq = modseq
					om.PrepareExpunge()
					oldUIDs = append(oldUIDs, om.UID)

					mc := m.MailboxCounts()
					srcMB.Sub(mc)
					dstMB.Add(mc)

					m.MailboxID = dstMB.ID
					m.UID = dstMB.UIDNext
					dstMB.UIDNext++
					m.CreateSeq = modseq
					m.ModSeq = modseq
					if err := tx.Update(&m); err != nil {
						return fmt.Errorf("updating message to move to new mailbox: %w", err)
					}

					changes = append(changes, m.ChangeAddUID())

					if err := tx.Insert(&om); err != nil {
						return fmt.Errorf("adding empty expunge message record to inbox: %w", err)
					}
					return nil
				})
				xcheckf(err, "moving messages from inbox to destination mailbox")

				err = tx.Update(&dstMB)
				xcheckf(err, "updating uidnext and counts in destination mailbox")

				err = tx.Update(&srcMB)
				xcheckf(err, "updating counts for inbox")

				var dstFlags []string
				if tx.Get(&store.Subscription{Name: dstMB.Name}) == nil {
					dstFlags = []string{`\Subscribed`}
				}
				changes[0] = store.ChangeRemoveUIDs{MailboxID: srcMB.ID, UIDs: oldUIDs, ModSeq: modseq}
				changes[1] = store.ChangeAddMailbox{Mailbox: dstMB, Flags: dstFlags}
				// changes[2:...] are ChangeAddUIDs
				changes = append(changes, srcMB.ChangeCounts(), dstMB.ChangeCounts())
				return
			}

			var notExists, alreadyExists bool
			var err error
			changes, _, notExists, alreadyExists, err = c.account.MailboxRename(tx, srcMB, dst)
			if notExists {
				// ../rfc/9051:5140
				xusercodeErrorf("NONEXISTENT", "%s", err)
			} else if alreadyExists {
				xusercodeErrorf("ALREADYEXISTS", "%s", err)
			}
			xcheckf(err, "renaming mailbox")
		})
		c.broadcast(changes)
	})

	c.ok(tag, cmd)
}

// Subscribe marks a mailbox path as subscribed. The mailbox does not have to
// exist. Subscribed may mean an email client will show the mailbox in its UI
// and/or periodically fetch new messages for the mailbox.
//
// State: Authenticated and selected.
func (c *conn) cmdSubscribe(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:2172 ../rfc/3501:2135
	// Examples: ../rfc/9051:2198 ../rfc/3501:2162

	// Request syntax: ../rfc/9051:7083 ../rfc/3501:5059
	p.xspace()
	name := p.xmailbox()
	p.xempty()

	name = xcheckmailboxname(name, true)

	c.account.WithWLock(func() {
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			var err error
			changes, err = c.account.SubscriptionEnsure(tx, name)
			xcheckf(err, "ensuring subscription")
		})

		c.broadcast(changes)
	})

	c.ok(tag, cmd)
}

// Unsubscribe marks a mailbox as not subscribed. The mailbox doesn't have to exist.
//
// State: Authenticated and selected.
func (c *conn) cmdUnsubscribe(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:2203 ../rfc/3501:2166
	// Examples: ../rfc/9051:2219 ../rfc/3501:2181

	// Request syntax: ../rfc/9051:7143 ../rfc/3501:5077
	p.xspace()
	name := p.xmailbox()
	p.xempty()

	name = xcheckmailboxname(name, true)

	c.account.WithWLock(func() {
		c.xdbwrite(func(tx *bstore.Tx) {
			// It's OK if not currently subscribed, ../rfc/9051:2215
			err := tx.Delete(&store.Subscription{Name: name})
			if err == bstore.ErrAbsent {
				exists, err := c.account.MailboxExists(tx, name)
				xcheckf(err, "checking if mailbox exists")
				if !exists {
					xuserErrorf("mailbox does not exist")
				}
				return
			}
			xcheckf(err, "removing subscription")
		})

		// todo: can we send untagged message about a mailbox no longer being subscribed?
	})

	c.ok(tag, cmd)
}

// LSUB command for listing subscribed mailboxes.
// Removed in IMAP4rev2, only in IMAP4rev1.
//
// State: Authenticated and selected.
func (c *conn) cmdLsub(tag, cmd string, p *parser) {
	// Command: ../rfc/3501:2374
	// Examples: ../rfc/3501:2415

	// Request syntax: ../rfc/3501:4806
	p.xspace()
	ref := p.xmailbox()
	p.xspace()
	pattern := p.xlistMailbox()
	p.xempty()

	re := xmailboxPatternMatcher(ref, []string{pattern})

	var lines []string
	c.xdbread(func(tx *bstore.Tx) {
		q := bstore.QueryTx[store.Subscription](tx)
		q.SortAsc("Name")
		subscriptions, err := q.List()
		xcheckf(err, "querying subscriptions")

		have := map[string]bool{}
		subscribedKids := map[string]bool{}
		ispercent := strings.HasSuffix(pattern, "%")
		for _, sub := range subscriptions {
			name := sub.Name
			if ispercent {
				for p := path.Dir(name); p != "."; p = path.Dir(p) {
					subscribedKids[p] = true
				}
			}
			if !re.MatchString(name) {
				continue
			}
			have[name] = true
			line := fmt.Sprintf(`* LSUB () "/" %s`, astring(c.encodeMailbox(name)).pack(c))
			lines = append(lines, line)

		}

		// ../rfc/3501:2394
		if !ispercent {
			return
		}
		qmb := bstore.QueryTx[store.Mailbox](tx)
		qmb.SortAsc("Name")
		err = qmb.ForEach(func(mb store.Mailbox) error {
			if have[mb.Name] || !subscribedKids[mb.Name] || !re.MatchString(mb.Name) {
				return nil
			}
			line := fmt.Sprintf(`* LSUB (\NoSelect) "/" %s`, astring(c.encodeMailbox(mb.Name)).pack(c))
			lines = append(lines, line)
			return nil
		})
		xcheckf(err, "querying mailboxes")
	})

	// Response syntax: ../rfc/3501:4833 ../rfc/3501:4837
	for _, line := range lines {
		c.bwritelinef("%s", line)
	}
	c.ok(tag, cmd)
}

// The namespace command returns the mailbox path separator. We only implement
// the personal mailbox hierarchy, no shared/other.
//
// In IMAP4rev2, it was an extension before.
//
// State: Authenticated and selected.
func (c *conn) cmdNamespace(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3098 ../rfc/2342:137
	// Examples: ../rfc/9051:3117 ../rfc/2342:155
	// Request syntax: ../rfc/9051:6767 ../rfc/2342:410
	p.xempty()

	// Response syntax: ../rfc/9051:6778 ../rfc/2342:415
	c.bwritelinef(`* NAMESPACE (("" "/")) NIL NIL`)
	c.ok(tag, cmd)
}

// The status command returns information about a mailbox, such as the number of
// messages, "uid validity", etc. Nowadays, the extended LIST command can return
// the same information about many mailboxes for one command.
//
// State: Authenticated and selected.
func (c *conn) cmdStatus(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3328 ../rfc/3501:2424 ../rfc/7162:1127
	// Examples: ../rfc/9051:3400 ../rfc/3501:2501 ../rfc/7162:1139

	// Request syntax: ../rfc/9051:7053 ../rfc/3501:5036
	p.xspace()
	name := p.xmailbox()
	p.xspace()
	p.xtake("(")
	attrs := []string{p.xstatusAtt()}
	for !p.take(")") {
		p.xspace()
		attrs = append(attrs, p.xstatusAtt())
	}
	p.xempty()

	name = xcheckmailboxname(name, true)

	var mb store.Mailbox

	var responseLine string
	c.account.WithRLock(func() {
		c.xdbread(func(tx *bstore.Tx) {
			mb = c.xmailbox(tx, name, "")
			responseLine = c.xstatusLine(tx, mb, attrs)
		})
	})

	c.bwritelinef("%s", responseLine)
	c.ok(tag, cmd)
}

// Response syntax: ../rfc/9051:6681 ../rfc/9051:7070 ../rfc/9051:7059 ../rfc/3501:4834
func (c *conn) xstatusLine(tx *bstore.Tx, mb store.Mailbox, attrs []string) string {
	status := []string{}
	for _, a := range attrs {
		A := strings.ToUpper(a)
		switch A {
		case "MESSAGES":
			status = append(status, A, fmt.Sprintf("%d", mb.Total+mb.Deleted))
		case "UIDNEXT":
			status = append(status, A, fmt.Sprintf("%d", mb.UIDNext))
		case "UIDVALIDITY":
			status = append(status, A, fmt.Sprintf("%d", mb.UIDValidity))
		case "UNSEEN":
			status = append(status, A, fmt.Sprintf("%d", mb.Unseen))
		case "DELETED":
			status = append(status, A, fmt.Sprintf("%d", mb.Deleted))
		case "SIZE":
			status = append(status, A, fmt.Sprintf("%d", mb.Size))
		case "RECENT":
			status = append(status, A, "0")
		case "APPENDLIMIT":
			// ../rfc/7889:255
			status = append(status, A, "NIL")
		case "HIGHESTMODSEQ":
			// ../rfc/7162:366
			status = append(status, A, fmt.Sprintf("%d", c.xhighestModSeq(tx, mb.ID).Client()))
		default:
			xsyntaxErrorf("unknown attribute %q", a)
		}
	}
	return fmt.Sprintf("* STATUS %s (%s)", astring(c.encodeMailbox(mb.Name)).pack(c), strings.Join(status, " "))
}

func flaglist(fl store.Flags, keywords []string) listspace {
	l := listspace{}
	flag := func(v bool, s string) {
		if v {
			l = append(l, bare(s))
		}
	}
	flag(fl.Seen, `\Seen`)
	flag(fl.Answered, `\Answered`)
	flag(fl.Flagged, `\Flagged`)
	flag(fl.Deleted, `\Deleted`)
	flag(fl.Draft, `\Draft`)
	flag(fl.Forwarded, `$Forwarded`)
	flag(fl.Junk, `$Junk`)
	flag(fl.Notjunk, `$NotJunk`)
	flag(fl.Phishing, `$Phishing`)
	flag(fl.MDNSent, `$MDNSent`)
	for _, k := range keywords {
		l = append(l, bare(k))
	}
	return l
}

// Append adds a message to a mailbox.
//
// State: Authenticated and selected.
func (c *conn) cmdAppend(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3406 ../rfc/6855:204 ../rfc/3501:2527
	// Examples: ../rfc/9051:3482 ../rfc/3501:2589

	// Request syntax: ../rfc/9051:6325 ../rfc/6855:219 ../rfc/3501:4547
	p.xspace()
	name := p.xmailbox()
	p.xspace()
	var storeFlags store.Flags
	var keywords []string
	if p.hasPrefix("(") {
		// Error must be a syntax error, to properly abort the connection due to literal.
		var err error
		storeFlags, keywords, err = store.ParseFlagsKeywords(p.xflagList())
		if err != nil {
			xsyntaxErrorf("parsing flags: %v", err)
		}
		p.xspace()
	}
	var tm time.Time
	if p.hasPrefix(`"`) {
		tm = p.xdateTime()
		p.xspace()
	} else {
		tm = time.Now()
	}
	// todo: only with utf8 should we we accept message headers with utf-8. we currently always accept them.
	// todo: this is only relevant if we also support the CATENATE extension?
	// ../rfc/6855:204
	utf8 := p.take("UTF8 (")
	size, sync := p.xliteralSize(0, utf8)

	name = xcheckmailboxname(name, true)
	c.xdbread(func(tx *bstore.Tx) {
		c.xmailbox(tx, name, "TRYCREATE")
	})
	if sync {
		c.writelinef("+ ")
	}

	// Read the message into a temporary file.
	msgFile, err := store.CreateMessageTemp(c.log, "imap-append")
	xcheckf(err, "creating temp file for message")
	defer func() {
		p := msgFile.Name()
		err := msgFile.Close()
		c.xsanity(err, "closing APPEND temporary file")
		err = os.Remove(p)
		c.xsanity(err, "removing APPEND temporary file")
	}()
	defer c.xtrace(mlog.LevelTracedata)()
	mw := message.NewWriter(msgFile)
	msize, err := io.Copy(mw, io.LimitReader(c.br, size))
	c.xtrace(mlog.LevelTrace) // Restore.
	if err != nil {
		// Cannot use xcheckf due to %w handling of errIO.
		panic(fmt.Errorf("reading literal message: %s (%w)", err, errIO))
	}
	if msize != size {
		xserverErrorf("read %d bytes for message, expected %d (%w)", msize, size, errIO)
	}

	if utf8 {
		line := c.readline(false)
		np := newParser(line, c)
		np.xtake(")")
		np.xempty()
	} else {
		line := c.readline(false)
		np := newParser(line, c)
		np.xempty()
	}
	p.xempty()
	if !sync {
		name = xcheckmailboxname(name, true)
	}

	var mb store.Mailbox
	var m store.Message
	var pendingChanges []store.Change

	c.account.WithWLock(func() {
		var changes []store.Change
		c.xdbwrite(func(tx *bstore.Tx) {
			mb = c.xmailbox(tx, name, "TRYCREATE")

			// Ensure keywords are stored in mailbox.
			var mbKwChanged bool
			mb.Keywords, mbKwChanged = store.MergeKeywords(mb.Keywords, keywords)
			if mbKwChanged {
				changes = append(changes, mb.ChangeKeywords())
			}

			m = store.Message{
				MailboxID:     mb.ID,
				MailboxOrigID: mb.ID,
				Received:      tm,
				Flags:         storeFlags,
				Keywords:      keywords,
				Size:          mw.Size,
			}

			ok, maxSize, err := c.account.CanAddMessageSize(tx, m.Size)
			xcheckf(err, "checking quota")
			if !ok {
				// ../rfc/9051:5155
				xusercodeErrorf("OVERQUOTA", "account over maximum total message size %d", maxSize)
			}

			mb.Add(m.MailboxCounts())

			// Update mailbox before delivering, which updates uidnext which we mustn't overwrite.
			err = tx.Update(&mb)
			xcheckf(err, "updating mailbox counts")

			err = c.account.DeliverMessage(c.log, tx, &m, msgFile, true, false, false, true)
			xcheckf(err, "delivering message")
		})

		// Fetch pending changes, possibly with new UIDs, so we can apply them before adding our own new UID.
		if c.comm != nil {
			pendingChanges = c.comm.Get()
		}

		// Broadcast the change to other connections.
		changes = append(changes, m.ChangeAddUID(), mb.ChangeCounts())
		c.broadcast(changes)
	})

	if c.mailboxID == mb.ID {
		c.applyChanges(pendingChanges, false)
		c.uidAppend(m.UID)
		// todo spec: with condstore/qresync, is there a mechanism to the client know the modseq for the appended uid? in theory an untagged fetch with the modseq after the OK APPENDUID could make sense, but this probably isn't allowed.
		c.bwritelinef("* %d EXISTS", len(c.uids))
	}

	c.writeresultf("%s OK [APPENDUID %d %d] appended", tag, mb.UIDValidity, m.UID)
}

// Idle makes a client wait until the server sends untagged updates, e.g. about
// message delivery or mailbox create/rename/delete/subscription, etc. It allows a
// client to get updates in real-time, not needing the use for NOOP.
//
// State: Authenticated and selected.
func (c *conn) cmdIdle(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3542 ../rfc/2177:49
	// Example: ../rfc/9051:3589 ../rfc/2177:119

	// Request syntax: ../rfc/9051:6594 ../rfc/2177:163
	p.xempty()

	c.writelinef("+ waiting")

	var line string
wait:
	for {
		select {
		case le := <-c.lineChan():
			c.line = nil
			xcheckf(le.err, "get line")
			line = le.line
			break wait
		case <-c.comm.Pending:
			c.applyChanges(c.comm.Get(), false)
			c.xflush()
		case <-mox.Shutdown.Done():
			// ../rfc/9051:5375
			c.writelinef("* BYE shutting down")
			panic(errIO)
		}
	}

	// Reset the write deadline. In case of little activity, with a command timeout of
	// 30 minutes, we have likely passed it.
	err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	c.log.Check(err, "setting write deadline")

	if strings.ToUpper(line) != "DONE" {
		// We just close the connection because our protocols are out of sync.
		panic(fmt.Errorf("%w: in IDLE, expected DONE", errIO))
	}

	c.ok(tag, cmd)
}

// Check is an old deprecated command that is supposed to execute some mailbox consistency checks.
//
// State: Selected
func (c *conn) cmdCheck(tag, cmd string, p *parser) {
	// Command: ../rfc/3501:2618

	// Request syntax: ../rfc/3501:4679
	p.xempty()

	c.account.WithRLock(func() {
		c.xdbread(func(tx *bstore.Tx) {
			c.xmailboxID(tx, c.mailboxID) // Validate.
		})
	})

	c.ok(tag, cmd)
}

// Close undoes select/examine, closing the currently opened mailbox and deleting
// messages that were marked for deletion with the \Deleted flag.
//
// State: Selected
func (c *conn) cmdClose(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3636 ../rfc/3501:2652 ../rfc/7162:1836

	// Request syntax: ../rfc/9051:6476 ../rfc/3501:4679
	p.xempty()

	if c.readonly {
		c.unselect()
		c.ok(tag, cmd)
		return
	}

	remove, _ := c.xexpunge(nil, true)

	defer func() {
		for _, m := range remove {
			p := c.account.MessagePath(m.ID)
			err := os.Remove(p)
			c.xsanity(err, "removing message file for expunge for close")
		}
	}()

	c.unselect()
	c.ok(tag, cmd)
}

// expunge messages marked for deletion in currently selected/active mailbox.
// if uidSet is not nil, only messages matching the set are deleted.
//
// messages that have been marked expunged from the database are returned, but the
// corresponding files still have to be removed.
//
// the highest modseq in the mailbox is returned, typically associated with the
// removal of the messages, but if no messages were expunged the current latest max
// modseq for the mailbox is returned.
func (c *conn) xexpunge(uidSet *numSet, missingMailboxOK bool) (remove []store.Message, highestModSeq store.ModSeq) {
	var modseq store.ModSeq

	c.account.WithWLock(func() {
		var mb store.Mailbox

		c.xdbwrite(func(tx *bstore.Tx) {
			mb = store.Mailbox{ID: c.mailboxID}
			err := tx.Get(&mb)
			if err == bstore.ErrAbsent {
				if missingMailboxOK {
					return
				}
				xuserErrorf("%w", store.ErrUnknownMailbox)
			}

			qm := bstore.QueryTx[store.Message](tx)
			qm.FilterNonzero(store.Message{MailboxID: c.mailboxID})
			qm.FilterEqual("Deleted", true)
			qm.FilterEqual("Expunged", false)
			qm.FilterFn(func(m store.Message) bool {
				// Only remove if this session knows about the message and if present in optional uidSet.
				return uidSearch(c.uids, m.UID) > 0 && (uidSet == nil || uidSet.containsUID(m.UID, c.uids, c.searchResult))
			})
			qm.SortAsc("UID")
			remove, err = qm.List()
			xcheckf(err, "listing messages to delete")

			if len(remove) == 0 {
				highestModSeq = c.xhighestModSeq(tx, c.mailboxID)
				return
			}

			// Assign new modseq.
			modseq, err = c.account.NextModSeq(tx)
			xcheckf(err, "assigning next modseq")
			highestModSeq = modseq

			removeIDs := make([]int64, len(remove))
			anyIDs := make([]any, len(remove))
			var totalSize int64
			for i, m := range remove {
				removeIDs[i] = m.ID
				anyIDs[i] = m.ID
				mb.Sub(m.MailboxCounts())
				totalSize += m.Size
				// Update "remove", because RetrainMessage below will save the message.
				remove[i].Expunged = true
				remove[i].ModSeq = modseq
			}
			qmr := bstore.QueryTx[store.Recipient](tx)
			qmr.FilterEqual("MessageID", anyIDs...)
			_, err = qmr.Delete()
			xcheckf(err, "removing message recipients")

			qm = bstore.QueryTx[store.Message](tx)
			qm.FilterIDs(removeIDs)
			n, err := qm.UpdateNonzero(store.Message{Expunged: true, ModSeq: modseq})
			if err == nil && n != len(removeIDs) {
				err = fmt.Errorf("only %d messages set to expunged, expected %d", n, len(removeIDs))
			}
			xcheckf(err, "marking messages marked for deleted as expunged")

			err = tx.Update(&mb)
			xcheckf(err, "updating mailbox counts")

			err = c.account.AddMessageSize(c.log, tx, -totalSize)
			xcheckf(err, "updating disk usage")

			// Mark expunged messages as not needing training, then retrain them, so if they
			// were trained, they get untrained.
			for i := range remove {
				remove[i].Junk = false
				remove[i].Notjunk = false
			}
			err = c.account.RetrainMessages(context.TODO(), c.log, tx, remove, true)
			xcheckf(err, "untraining expunged messages")
		})

		// Broadcast changes to other connections. We may not have actually removed any
		// messages, so take care not to send an empty update.
		if len(remove) > 0 {
			ouids := make([]store.UID, len(remove))
			for i, m := range remove {
				ouids[i] = m.UID
			}
			changes := []store.Change{
				store.ChangeRemoveUIDs{MailboxID: c.mailboxID, UIDs: ouids, ModSeq: modseq},
				mb.ChangeCounts(),
			}
			c.broadcast(changes)
		}
	})
	return remove, highestModSeq
}

// Unselect is similar to close in that it closes the currently active mailbox, but
// it does not remove messages marked for deletion.
//
// State: Selected
func (c *conn) cmdUnselect(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3667 ../rfc/3691:89

	// Request syntax: ../rfc/9051:6476 ../rfc/3691:135
	p.xempty()

	c.unselect()
	c.ok(tag, cmd)
}

// Expunge deletes messages marked with \Deleted in the currently selected mailbox.
// Clients are wiser to use UID EXPUNGE because it allows a UID sequence set to
// explicitly opt in to removing specific messages.
//
// State: Selected
func (c *conn) cmdExpunge(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3687 ../rfc/3501:2695 ../rfc/7162:1770

	// Request syntax: ../rfc/9051:6476 ../rfc/3501:4679
	p.xempty()

	if c.readonly {
		xuserErrorf("mailbox open in read-only mode")
	}

	c.cmdxExpunge(tag, cmd, nil)
}

// UID expunge deletes messages marked with \Deleted in the currently selected
// mailbox if they match a UID sequence set.
//
// State: Selected
func (c *conn) cmdUIDExpunge(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:4775 ../rfc/4315:75 ../rfc/7162:1873

	// Request syntax: ../rfc/9051:7125 ../rfc/9051:7129 ../rfc/4315:298
	p.xspace()
	uidSet := p.xnumSet()
	p.xempty()

	if c.readonly {
		xuserErrorf("mailbox open in read-only mode")
	}

	c.cmdxExpunge(tag, cmd, &uidSet)
}

// Permanently delete messages for the currently selected/active mailbox. If uidset
// is not nil, only those UIDs are removed.
// State: Selected
func (c *conn) cmdxExpunge(tag, cmd string, uidSet *numSet) {
	// Command: ../rfc/9051:3687 ../rfc/3501:2695

	remove, highestModSeq := c.xexpunge(uidSet, false)

	defer func() {
		for _, m := range remove {
			p := c.account.MessagePath(m.ID)
			err := os.Remove(p)
			c.xsanity(err, "removing message file for expunge")
		}
	}()

	// Response syntax: ../rfc/9051:6742 ../rfc/3501:4864
	var vanishedUIDs numSet
	qresync := c.enabled[capQresync]
	for _, m := range remove {
		seq := c.xsequence(m.UID)
		c.sequenceRemove(seq, m.UID)
		if qresync {
			vanishedUIDs.append(uint32(m.UID))
		} else {
			c.bwritelinef("* %d EXPUNGE", seq)
		}
	}
	if !vanishedUIDs.empty() {
		// VANISHED without EARLIER. ../rfc/7162:2004
		for _, s := range vanishedUIDs.Strings(4*1024 - 32) {
			c.bwritelinef("* VANISHED %s", s)
		}
	}

	if c.enabled[capCondstore] {
		c.writeresultf("%s OK [HIGHESTMODSEQ %d] expunged", tag, highestModSeq.Client())
	} else {
		c.ok(tag, cmd)
	}
}

// State: Selected
func (c *conn) cmdSearch(tag, cmd string, p *parser) {
	c.cmdxSearch(false, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdUIDSearch(tag, cmd string, p *parser) {
	c.cmdxSearch(true, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdFetch(tag, cmd string, p *parser) {
	c.cmdxFetch(false, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdUIDFetch(tag, cmd string, p *parser) {
	c.cmdxFetch(true, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdStore(tag, cmd string, p *parser) {
	c.cmdxStore(false, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdUIDStore(tag, cmd string, p *parser) {
	c.cmdxStore(true, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdCopy(tag, cmd string, p *parser) {
	c.cmdxCopy(false, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdUIDCopy(tag, cmd string, p *parser) {
	c.cmdxCopy(true, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdMove(tag, cmd string, p *parser) {
	c.cmdxMove(false, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdUIDMove(tag, cmd string, p *parser) {
	c.cmdxMove(true, tag, cmd, p)
}

func (c *conn) gatherCopyMoveUIDs(isUID bool, nums numSet) ([]store.UID, []any) {
	// Gather uids, then sort so we can return a consistently simple and hard to
	// misinterpret COPYUID/MOVEUID response. It seems safer to have UIDs in ascending
	// order, because requested uid set of 12:10 is equal to 10:12, so if we would just
	// echo whatever the client sends us without reordering, the client can reorder our
	// response and interpret it differently than we intended.
	// ../rfc/9051:5072
	uids := c.xnumSetUIDs(isUID, nums)
	sort.Slice(uids, func(i, j int) bool {
		return uids[i] < uids[j]
	})
	uidargs := make([]any, len(uids))
	for i, uid := range uids {
		uidargs[i] = uid
	}
	return uids, uidargs
}

// Copy copies messages from the currently selected/active mailbox to another named
// mailbox.
//
// State: Selected
func (c *conn) cmdxCopy(isUID bool, tag, cmd string, p *parser) {
	// Command: ../rfc/9051:4602 ../rfc/3501:3288

	// Request syntax: ../rfc/9051:6482 ../rfc/3501:4685
	p.xspace()
	nums := p.xnumSet()
	p.xspace()
	name := p.xmailbox()
	p.xempty()

	name = xcheckmailboxname(name, true)

	uids, uidargs := c.gatherCopyMoveUIDs(isUID, nums)

	// Files that were created during the copy. Remove them if the operation fails.
	var createdIDs []int64
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		for _, id := range createdIDs {
			p := c.account.MessagePath(id)
			err := os.Remove(p)
			c.xsanity(err, "cleaning up created file")
		}
		panic(x)
	}()

	var mbDst store.Mailbox
	var origUIDs, newUIDs []store.UID
	var flags []store.Flags
	var keywords [][]string
	var modseq store.ModSeq // For messages in new mailbox, assigned when first message is copied.

	c.account.WithWLock(func() {
		var mbKwChanged bool

		c.xdbwrite(func(tx *bstore.Tx) {
			mbSrc := c.xmailboxID(tx, c.mailboxID) // Validate.
			mbDst = c.xmailbox(tx, name, "TRYCREATE")
			if mbDst.ID == mbSrc.ID {
				xuserErrorf("cannot copy to currently selected mailbox")
			}

			if len(uidargs) == 0 {
				xuserErrorf("no matching messages to copy")
			}

			var err error
			modseq, err = c.account.NextModSeq(tx)
			xcheckf(err, "assigning next modseq")

			// Reserve the uids in the destination mailbox.
			uidFirst := mbDst.UIDNext
			mbDst.UIDNext += store.UID(len(uidargs))

			// Fetch messages from database.
			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: c.mailboxID})
			q.FilterEqual("UID", uidargs...)
			q.FilterEqual("Expunged", false)
			xmsgs, err := q.List()
			xcheckf(err, "fetching messages")

			if len(xmsgs) != len(uidargs) {
				xserverErrorf("uid and message mismatch")
			}

			// See if quota allows copy.
			var totalSize int64
			for _, m := range xmsgs {
				totalSize += m.Size
			}
			if ok, maxSize, err := c.account.CanAddMessageSize(tx, totalSize); err != nil {
				xcheckf(err, "checking quota")
			} else if !ok {
				// ../rfc/9051:5155
				xusercodeErrorf("OVERQUOTA", "account over maximum total message size %d", maxSize)
			}
			err = c.account.AddMessageSize(c.log, tx, totalSize)
			xcheckf(err, "updating disk usage")

			msgs := map[store.UID]store.Message{}
			for _, m := range xmsgs {
				msgs[m.UID] = m
			}
			nmsgs := make([]store.Message, len(xmsgs))

			conf, _ := c.account.Conf()

			mbKeywords := map[string]struct{}{}

			// Insert new messages into database.
			var origMsgIDs, newMsgIDs []int64
			for i, uid := range uids {
				m, ok := msgs[uid]
				if !ok {
					xuserErrorf("messages changed, could not fetch requested uid")
				}
				origID := m.ID
				origMsgIDs = append(origMsgIDs, origID)
				m.ID = 0
				m.UID = uidFirst + store.UID(i)
				m.CreateSeq = modseq
				m.ModSeq = modseq
				m.MailboxID = mbDst.ID
				if m.IsReject && m.MailboxDestinedID != 0 {
					// Incorrectly delivered to Rejects mailbox. Adjust MailboxOrigID so this message
					// is used for reputation calculation during future deliveries.
					m.MailboxOrigID = m.MailboxDestinedID
					m.IsReject = false
				}
				m.TrainedJunk = nil
				m.JunkFlagsForMailbox(mbDst, conf)
				err := tx.Insert(&m)
				xcheckf(err, "inserting message")
				msgs[uid] = m
				nmsgs[i] = m
				origUIDs = append(origUIDs, uid)
				newUIDs = append(newUIDs, m.UID)
				newMsgIDs = append(newMsgIDs, m.ID)
				flags = append(flags, m.Flags)
				keywords = append(keywords, m.Keywords)
				for _, kw := range m.Keywords {
					mbKeywords[kw] = struct{}{}
				}

				qmr := bstore.QueryTx[store.Recipient](tx)
				qmr.FilterNonzero(store.Recipient{MessageID: origID})
				mrs, err := qmr.List()
				xcheckf(err, "listing message recipients")
				for _, mr := range mrs {
					mr.ID = 0
					mr.MessageID = m.ID
					err := tx.Insert(&mr)
					xcheckf(err, "inserting message recipient")
				}

				mbDst.Add(m.MailboxCounts())
			}

			mbDst.Keywords, mbKwChanged = store.MergeKeywords(mbDst.Keywords, maps.Keys(mbKeywords))

			err = tx.Update(&mbDst)
			xcheckf(err, "updating destination mailbox for uids, keywords and counts")

			// Copy message files to new message ID's.
			syncDirs := map[string]struct{}{}
			for i := range origMsgIDs {
				src := c.account.MessagePath(origMsgIDs[i])
				dst := c.account.MessagePath(newMsgIDs[i])
				dstdir := filepath.Dir(dst)
				if _, ok := syncDirs[dstdir]; !ok {
					os.MkdirAll(dstdir, 0770)
					syncDirs[dstdir] = struct{}{}
				}
				err := moxio.LinkOrCopy(c.log, dst, src, nil, true)
				xcheckf(err, "link or copy file %q to %q", src, dst)
				createdIDs = append(createdIDs, newMsgIDs[i])
			}

			for dir := range syncDirs {
				err := moxio.SyncDir(c.log, dir)
				xcheckf(err, "sync directory")
			}

			err = c.account.RetrainMessages(context.TODO(), c.log, tx, nmsgs, false)
			xcheckf(err, "train copied messages")
		})

		// Broadcast changes to other connections.
		if len(newUIDs) > 0 {
			changes := make([]store.Change, 0, len(newUIDs)+2)
			for i, uid := range newUIDs {
				changes = append(changes, store.ChangeAddUID{MailboxID: mbDst.ID, UID: uid, ModSeq: modseq, Flags: flags[i], Keywords: keywords[i]})
			}
			changes = append(changes, mbDst.ChangeCounts())
			if mbKwChanged {
				changes = append(changes, mbDst.ChangeKeywords())
			}
			c.broadcast(changes)
		}
	})

	// All good, prevent defer above from cleaning up copied files.
	createdIDs = nil

	// ../rfc/9051:6881 ../rfc/4315:183
	c.writeresultf("%s OK [COPYUID %d %s %s] copied", tag, mbDst.UIDValidity, compactUIDSet(origUIDs).String(), compactUIDSet(newUIDs).String())
}

// Move moves messages from the currently selected/active mailbox to a named mailbox.
//
// State: Selected
func (c *conn) cmdxMove(isUID bool, tag, cmd string, p *parser) {
	// Command: ../rfc/9051:4650 ../rfc/6851:119 ../rfc/6851:265

	// Request syntax: ../rfc/6851:320
	p.xspace()
	nums := p.xnumSet()
	p.xspace()
	name := p.xmailbox()
	p.xempty()

	name = xcheckmailboxname(name, true)

	if c.readonly {
		xuserErrorf("mailbox open in read-only mode")
	}

	uids, uidargs := c.gatherCopyMoveUIDs(isUID, nums)

	var mbSrc, mbDst store.Mailbox
	var changes []store.Change
	var newUIDs []store.UID
	var modseq store.ModSeq

	c.account.WithWLock(func() {
		c.xdbwrite(func(tx *bstore.Tx) {
			mbSrc = c.xmailboxID(tx, c.mailboxID) // Validate.
			mbDst = c.xmailbox(tx, name, "TRYCREATE")
			if mbDst.ID == c.mailboxID {
				xuserErrorf("cannot move to currently selected mailbox")
			}

			if len(uidargs) == 0 {
				xuserErrorf("no matching messages to move")
			}

			// Reserve the uids in the destination mailbox.
			uidFirst := mbDst.UIDNext
			uidnext := uidFirst
			mbDst.UIDNext += store.UID(len(uids))

			// Assign a new modseq, for the new records and for the expunged records.
			var err error
			modseq, err = c.account.NextModSeq(tx)
			xcheckf(err, "assigning next modseq")

			// Update existing record with new UID and MailboxID in database for messages. We
			// add a new but expunged record again in the original/source mailbox, for qresync.
			// Keeping the original ID for the live message means we don't have to move the
			// on-disk message contents file.
			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: c.mailboxID})
			q.FilterEqual("UID", uidargs...)
			q.FilterEqual("Expunged", false)
			q.SortAsc("UID")
			msgs, err := q.List()
			xcheckf(err, "listing messages to move")

			if len(msgs) != len(uidargs) {
				xserverErrorf("uid and message mismatch")
			}

			keywords := map[string]struct{}{}

			conf, _ := c.account.Conf()
			for i := range msgs {
				m := &msgs[i]
				if m.UID != uids[i] {
					xserverErrorf("internal error: got uid %d, expected %d, for index %d", m.UID, uids[i], i)
				}

				mbSrc.Sub(m.MailboxCounts())

				// Copy of message record that we'll insert when UID is freed up.
				om := *m
				om.PrepareExpunge()
				om.ID = 0 // Assign new ID.
				om.ModSeq = modseq

				m.MailboxID = mbDst.ID
				if m.IsReject && m.MailboxDestinedID != 0 {
					// Incorrectly delivered to Rejects mailbox. Adjust MailboxOrigID so this message
					// is used for reputation calculation during future deliveries.
					m.MailboxOrigID = m.MailboxDestinedID
					m.IsReject = false
					m.Seen = false
				}
				mbDst.Add(m.MailboxCounts())
				m.UID = uidnext
				m.ModSeq = modseq
				m.JunkFlagsForMailbox(mbDst, conf)
				uidnext++
				err := tx.Update(m)
				xcheckf(err, "updating moved message in database")

				// Now that UID is unused, we can insert the old record again.
				err = tx.Insert(&om)
				xcheckf(err, "inserting record for expunge after moving message")

				for _, kw := range m.Keywords {
					keywords[kw] = struct{}{}
				}
			}

			// Ensure destination mailbox has keywords of the moved messages.
			var mbKwChanged bool
			mbDst.Keywords, mbKwChanged = store.MergeKeywords(mbDst.Keywords, maps.Keys(keywords))
			if mbKwChanged {
				changes = append(changes, mbDst.ChangeKeywords())
			}

			err = tx.Update(&mbSrc)
			xcheckf(err, "updating source mailbox counts")

			err = tx.Update(&mbDst)
			xcheckf(err, "updating destination mailbox for uids, keywords and counts")

			err = c.account.RetrainMessages(context.TODO(), c.log, tx, msgs, false)
			xcheckf(err, "retraining messages after move")

			// Prepare broadcast changes to other connections.
			changes = make([]store.Change, 0, 1+len(msgs)+2)
			changes = append(changes, store.ChangeRemoveUIDs{MailboxID: c.mailboxID, UIDs: uids, ModSeq: modseq})
			for _, m := range msgs {
				newUIDs = append(newUIDs, m.UID)
				changes = append(changes, m.ChangeAddUID())
			}
			changes = append(changes, mbSrc.ChangeCounts(), mbDst.ChangeCounts())
		})

		c.broadcast(changes)
	})

	// ../rfc/9051:4708 ../rfc/6851:254
	// ../rfc/9051:4713
	c.bwritelinef("* OK [COPYUID %d %s %s] moved", mbDst.UIDValidity, compactUIDSet(uids).String(), compactUIDSet(newUIDs).String())
	qresync := c.enabled[capQresync]
	var vanishedUIDs numSet
	for i := 0; i < len(uids); i++ {
		seq := c.xsequence(uids[i])
		c.sequenceRemove(seq, uids[i])
		if qresync {
			vanishedUIDs.append(uint32(uids[i]))
		} else {
			c.bwritelinef("* %d EXPUNGE", seq)
		}
	}
	if !vanishedUIDs.empty() {
		// VANISHED without EARLIER. ../rfc/7162:2004
		for _, s := range vanishedUIDs.Strings(4*1024 - 32) {
			c.bwritelinef("* VANISHED %s", s)
		}
	}

	if c.enabled[capQresync] {
		// ../rfc/9051:6744 ../rfc/7162:1334
		c.writeresultf("%s OK [HIGHESTMODSEQ %d] move", tag, modseq.Client())
	} else {
		c.ok(tag, cmd)
	}
}

// Store sets a full set of flags, or adds/removes specific flags.
//
// State: Selected
func (c *conn) cmdxStore(isUID bool, tag, cmd string, p *parser) {
	// Command: ../rfc/9051:4543 ../rfc/3501:3214

	// Request syntax: ../rfc/9051:7076 ../rfc/3501:5052 ../rfc/4466:691 ../rfc/7162:2471
	p.xspace()
	nums := p.xnumSet()
	p.xspace()
	var unchangedSince *int64
	if p.take("(") {
		// ../rfc/7162:2471
		p.xtake("UNCHANGEDSINCE")
		p.xspace()
		v := p.xnumber64()
		unchangedSince = &v
		p.xtake(")")
		p.xspace()
		// UNCHANGEDSINCE is a CONDSTORE-enabling parameter ../rfc/7162:382
		c.xensureCondstore(nil)
	}
	var plus, minus bool
	if p.take("+") {
		plus = true
	} else if p.take("-") {
		minus = true
	}
	p.xtake("FLAGS")
	silent := p.take(".SILENT")
	p.xspace()
	var flagstrs []string
	if p.hasPrefix("(") {
		flagstrs = p.xflagList()
	} else {
		flagstrs = append(flagstrs, p.xflag())
		for p.space() {
			flagstrs = append(flagstrs, p.xflag())
		}
	}
	p.xempty()

	if c.readonly {
		xuserErrorf("mailbox open in read-only mode")
	}

	flags, keywords, err := store.ParseFlagsKeywords(flagstrs)
	if err != nil {
		xuserErrorf("parsing flags: %v", err)
	}
	var mask store.Flags
	if plus {
		mask, flags = flags, store.FlagsAll
	} else if minus {
		mask, flags = flags, store.Flags{}
	} else {
		mask = store.FlagsAll
	}

	var mb, origmb store.Mailbox
	var updated []store.Message
	var changed []store.Message // ModSeq more recent than unchangedSince, will be in MODIFIED response code, and we will send untagged fetch responses so client is up to date.
	var modseq store.ModSeq     // Assigned when needed.
	modified := map[int64]bool{}

	c.account.WithWLock(func() {
		var mbKwChanged bool
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			mb = c.xmailboxID(tx, c.mailboxID) // Validate.
			origmb = mb

			uidargs := c.xnumSetCondition(isUID, nums)

			if len(uidargs) == 0 {
				return
			}

			// Ensure keywords are in mailbox.
			if !minus {
				mb.Keywords, mbKwChanged = store.MergeKeywords(mb.Keywords, keywords)
				if mbKwChanged {
					err := tx.Update(&mb)
					xcheckf(err, "updating mailbox with keywords")
				}
			}

			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: c.mailboxID})
			q.FilterEqual("UID", uidargs...)
			q.FilterEqual("Expunged", false)
			err := q.ForEach(func(m store.Message) error {
				// Client may specify a message multiple times, but we only process it once. ../rfc/7162:823
				if modified[m.ID] {
					return nil
				}

				mc := m.MailboxCounts()

				origFlags := m.Flags
				m.Flags = m.Flags.Set(mask, flags)
				oldKeywords := append([]string{}, m.Keywords...)
				if minus {
					m.Keywords, _ = store.RemoveKeywords(m.Keywords, keywords)
				} else if plus {
					m.Keywords, _ = store.MergeKeywords(m.Keywords, keywords)
				} else {
					m.Keywords = keywords
				}

				keywordsChanged := func() bool {
					sort.Strings(oldKeywords)
					n := append([]string{}, m.Keywords...)
					sort.Strings(n)
					return !slices.Equal(oldKeywords, n)
				}

				// If the message has a more recent modseq than the check requires, we won't modify
				// it and report in the final command response.
				// ../rfc/7162:555
				//
				// unchangedSince 0 always fails the check, we don't turn it into 1 like with our
				// internal modseqs. RFC implies that is not required for non-system flags, but we
				// don't have per-flag modseq and this seems reasonable. ../rfc/7162:640
				if unchangedSince != nil && m.ModSeq.Client() > *unchangedSince {
					changed = append(changed, m)
					return nil
				}

				// Note: we don't perform the optimization described in ../rfc/7162:1258
				// It requires that we keep track of the flags we think the client knows (but only
				// on this connection). We don't track that. It also isn't clear why this is
				// allowed because it is skipping the condstore conditional check, and the new
				// combination of flags could be unintended.

				// We do not assign a new modseq if nothing actually changed. ../rfc/7162:1246 ../rfc/7162:312
				if origFlags == m.Flags && !keywordsChanged() {
					// Note: since we didn't update the modseq, we are not adding m.ID to "modified",
					// it would skip the modseq check above. We still add m to list of updated, so we
					// send an untagged fetch response. But we don't broadcast it.
					updated = append(updated, m)
					return nil
				}

				mb.Sub(mc)
				mb.Add(m.MailboxCounts())

				// Assign new modseq for first actual change.
				if modseq == 0 {
					var err error
					modseq, err = c.account.NextModSeq(tx)
					xcheckf(err, "next modseq")
				}
				m.ModSeq = modseq
				modified[m.ID] = true
				updated = append(updated, m)

				changes = append(changes, m.ChangeFlags(origFlags))

				return tx.Update(&m)
			})
			xcheckf(err, "storing flags in messages")

			if mb.MailboxCounts != origmb.MailboxCounts {
				err := tx.Update(&mb)
				xcheckf(err, "updating mailbox counts")

				changes = append(changes, mb.ChangeCounts())
			}
			if mbKwChanged {
				changes = append(changes, mb.ChangeKeywords())
			}

			err = c.account.RetrainMessages(context.TODO(), c.log, tx, updated, false)
			xcheckf(err, "training messages")
		})

		c.broadcast(changes)
	})

	// In the RFC, the section about STORE/UID STORE says we must return MODSEQ when
	// UNCHANGEDSINCE was specified. It does not specify it in case UNCHANGEDSINCE
	// isn't specified. For that case it does say MODSEQ is needed in unsolicited
	// untagged fetch responses. Implying that solicited untagged fetch responses
	// should not include MODSEQ (why else mention unsolicited explicitly?). But, in
	// the introduction to CONDSTORE it does explicitly specify MODSEQ should be
	// included in untagged fetch responses at all times with CONDSTORE-enabled
	// connections. It would have been better if the command behaviour was specified in
	// the command section, not the introduction to the extension.
	// ../rfc/7162:388 ../rfc/7162:852
	// ../rfc/7162:549
	if !silent || c.enabled[capCondstore] {
		for _, m := range updated {
			var flags string
			if !silent {
				flags = fmt.Sprintf(" FLAGS %s", flaglist(m.Flags, m.Keywords).pack(c))
			}
			var modseqStr string
			if c.enabled[capCondstore] {
				modseqStr = fmt.Sprintf(" MODSEQ (%d)", m.ModSeq.Client())
			}
			// ../rfc/9051:6749 ../rfc/3501:4869 ../rfc/7162:2490
			c.bwritelinef("* %d FETCH (UID %d%s%s)", c.xsequence(m.UID), m.UID, flags, modseqStr)
		}
	}

	// We don't explicitly send flags for failed updated with silent set. The regular
	// notification will get the flags to the client.
	// ../rfc/7162:630 ../rfc/3501:3233

	if len(changed) == 0 {
		c.ok(tag, cmd)
		return
	}

	// Write unsolicited untagged fetch responses for messages that didn't pass the
	// unchangedsince check. ../rfc/7162:679
	// Also gather UIDs or sequences for the MODIFIED response below. ../rfc/7162:571
	var mnums []store.UID
	for _, m := range changed {
		c.bwritelinef("* %d FETCH (UID %d FLAGS %s MODSEQ (%d))", c.xsequence(m.UID), m.UID, flaglist(m.Flags, m.Keywords).pack(c), m.ModSeq.Client())
		if isUID {
			mnums = append(mnums, m.UID)
		} else {
			mnums = append(mnums, store.UID(c.xsequence(m.UID)))
		}
	}

	sort.Slice(mnums, func(i, j int) bool {
		return mnums[i] < mnums[j]
	})
	set := compactUIDSet(mnums)
	// ../rfc/7162:2506
	c.writeresultf("%s OK [MODIFIED %s] conditional store did not modify all", tag, set.String())
}
