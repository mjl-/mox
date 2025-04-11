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
- todo: try to recover from syntax errors when the last command line ends with a }, i.e. a literal. we currently abort the entire connection. we may want to read some amount of literal data and continue with a next command.
*/

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"maps"
	"math"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"
	"github.com/mjl-/flate"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/junk"
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

var unhandledPanics atomic.Int64 // For tests.

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

// Capabilities (extensions) the server supports. Connections will add a few more,
// e.g. STARTTLS, LOGINDISABLED, AUTH=PLAIN.
//
// We always announce support for SCRAM PLUS-variants, also on connections without
// TLS. The client should not be selecting PLUS variants on non-TLS connections,
// instead opting to do the bare SCRAM variant without indicating the server claims
// to support the PLUS variant (skipping the server downgrade detection check).
var serverCapabilities = strings.Join([]string{
	"IMAP4rev2",                       // ../rfc/9051
	"IMAP4rev1",                       // ../rfc/3501
	"ENABLE",                          // ../rfc/5161
	"LITERAL+",                        // ../rfc/7888
	"IDLE",                            // ../rfc/2177
	"SASL-IR",                         // ../rfc/4959
	"BINARY",                          // ../rfc/3516
	"UNSELECT",                        // ../rfc/3691
	"UIDPLUS",                         // ../rfc/4315
	"ESEARCH",                         // ../rfc/4731
	"SEARCHRES",                       // ../rfc/5182
	"MOVE",                            // ../rfc/6851
	"UTF8=ACCEPT",                     // ../rfc/6855
	"LIST-EXTENDED",                   // ../rfc/5258
	"SPECIAL-USE",                     // ../rfc/6154
	"CREATE-SPECIAL-USE",              //
	"LIST-STATUS",                     // ../rfc/5819
	"AUTH=SCRAM-SHA-256-PLUS",         // ../rfc/7677 ../rfc/5802
	"AUTH=SCRAM-SHA-256",              //
	"AUTH=SCRAM-SHA-1-PLUS",           // ../rfc/5802
	"AUTH=SCRAM-SHA-1",                //
	"AUTH=CRAM-MD5",                   // ../rfc/2195
	"ID",                              // ../rfc/2971
	"APPENDLIMIT=9223372036854775807", // ../rfc/7889:129, we support the max possible size, 1<<63 - 1
	"CONDSTORE",                       // ../rfc/7162:411
	"QRESYNC",                         // ../rfc/7162:1323
	"STATUS=SIZE",                     // ../rfc/8438 ../rfc/9051:8024
	"QUOTA",                           // ../rfc/9208:111
	"QUOTA=RES-STORAGE",               //
	"METADATA",                        // ../rfc/5464
	"SAVEDATE",                        // ../rfc/8514
	"WITHIN",                          // ../rfc/5032
	"NAMESPACE",                       // ../rfc/2342
	"LIST-METADATA",                   // ../rfc/9590
	"MULTIAPPEND",                     // ../rfc/3502
	"REPLACE",                         // ../rfc/8508
	"PREVIEW",                         // ../rfc/8970:114
	"INPROGRESS",                      // ../rfc/9585:101
	"MULTISEARCH",                     // ../rfc/7377:187
	"NOTIFY",                          // ../rfc/5465:195
	"UIDONLY",                         // ../rfc/9586:127
	// "COMPRESS=DEFLATE", // ../rfc/4978, disabled for interoperability issues: The flate reader (inflate) still blocks on partial flushes, preventing progress.
}, " ")

type conn struct {
	cid               int64
	state             state
	conn              net.Conn
	connBroken        bool               // Once broken, we won't flush any more data.
	tls               bool               // Whether TLS has been initialized.
	viaHTTPS          bool               // Whether this connection came in via HTTPS (using TLS ALPN).
	br                *bufio.Reader      // From remote, with TLS unwrapped in case of TLS, and possibly wrapping inflate.
	tr                *moxio.TraceReader // Kept to change trace level when reading/writing cmd/auth/data.
	line              chan lineErr       // If set, instead of reading from br, a line is read from this channel. For reading a line in IDLE while also waiting for mailbox/account updates.
	lastLine          string             // For detecting if syntax error is fatal, i.e. if this ends with a literal. Without crlf.
	xbw               *bufio.Writer      // To remote, with TLS added in case of TLS, and possibly wrapping deflate, see conn.xflateWriter. Writes go through xtw to conn.Write, which panics on errors, hence the "x".
	xtw               *moxio.TraceWriter
	xflateWriter      *moxio.FlateWriter // For flushing output after flushing conn.xbw, and for closing.
	xflateBW          *bufio.Writer      // Wraps raw connection writes, xflateWriter writes here, also needs flushing.
	slow              bool               // If set, reads are done with a 1 second sleep, and writes are done 1 byte at a time, to keep spammers busy.
	lastlog           time.Time          // For printing time since previous log line.
	baseTLSConfig     *tls.Config        // Base TLS config to use for handshake.
	remoteIP          net.IP
	noRequireSTARTTLS bool
	cmd               string // Currently executing, for deciding to xapplyChanges and logging.
	cmdMetric         string // Currently executing, for metrics.
	cmdStart          time.Time
	ncmds             int                 // Number of commands processed. Used to abort connection when first incoming command is unknown/invalid.
	log               mlog.Log            // Used for all synchronous logging on this connection, see logbg for logging in a separate goroutine.
	enabled           map[capability]bool // All upper-case.
	compress          bool                // Whether compression is enabled, via compress command.
	notify            *notify             // For the NOTIFY extension. Event/change filtering active if non-nil.

	// Set by SEARCH with SAVE. Can be used by commands accepting a sequence-set with
	// value "$". When used, UIDs must be verified to still exist, because they may
	// have been expunged. Cleared by a SELECT or EXAMINE.
	// Nil means no searchResult is present. An empty list is a valid searchResult,
	// just not matching any messages.
	// ../rfc/5182:13 ../rfc/9051:4040
	searchResult []store.UID

	// userAgent is set by the ID command, which can happen at any time (before or
	// after the authentication attempt we want to log it with).
	userAgent string
	// loginAttempt is set during authentication, typically picked up by the ID command
	// that soon follows, or it will be flushed within 1s, or on connection teardown.
	loginAttempt     *store.LoginAttempt
	loginAttemptTime time.Time

	// Only set when connection has been authenticated. These can be set even when
	// c.state is stateNotAuthenticated, for TLS client certificate authentication. In
	// that case, credentials aren't used until the authentication command with the
	// SASL "EXTERNAL" mechanism.
	authFailed int    // Number of failed auth attempts. For slowing down remote with many failures.
	noPreauth  bool   // If set, don't switch connection to "authenticated" after TLS handshake with client certificate authentication.
	username   string // Full username as used during login.
	account    *store.Account
	comm       *store.Comm // For sending/receiving changes on mailboxes in account, e.g. from messages incoming on smtp, or another imap client.

	mailboxID int64       // Only for StateSelected.
	readonly  bool        // If opened mailbox is readonly.
	uidonly   bool        // If uidonly is enabled, uids is empty and cannot be used.
	uidnext   store.UID   // We don't return search/fetch/etc results for uids >= uidnext, which is updated when applying changes.
	exists    uint32      // Needed for uidonly, equal to len(uids) for non-uidonly sessions.
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
	capMetadata   capability = "METADATA"
	capUIDOnly    capability = "UIDONLY"
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
	commandsStateAuthenticated    = stateCommands("enable", "select", "examine", "create", "delete", "rename", "subscribe", "unsubscribe", "list", "namespace", "status", "append", "idle", "lsub", "getquotaroot", "getquota", "getmetadata", "setmetadata", "compress", "esearch", "notify")
	commandsStateSelected         = stateCommands("close", "unselect", "expunge", "search", "fetch", "store", "copy", "move", "uid expunge", "uid search", "uid fetch", "uid store", "uid copy", "uid move", "replace", "uid replace", "esearch")
)

// Commands that use sequence numbers. Cannot be used when UIDONLY is enabled.
// Commands like UID SEARCH have additional checks for some parameters.
var commandsSequence = stateCommands("search", "fetch", "store", "copy", "move", "replace")

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
	"enable":       (*conn).cmdEnable,
	"select":       (*conn).cmdSelect,
	"examine":      (*conn).cmdExamine,
	"create":       (*conn).cmdCreate,
	"delete":       (*conn).cmdDelete,
	"rename":       (*conn).cmdRename,
	"subscribe":    (*conn).cmdSubscribe,
	"unsubscribe":  (*conn).cmdUnsubscribe,
	"list":         (*conn).cmdList,
	"lsub":         (*conn).cmdLsub,
	"namespace":    (*conn).cmdNamespace,
	"status":       (*conn).cmdStatus,
	"append":       (*conn).cmdAppend,
	"idle":         (*conn).cmdIdle,
	"getquotaroot": (*conn).cmdGetquotaroot,
	"getquota":     (*conn).cmdGetquota,
	"getmetadata":  (*conn).cmdGetmetadata,
	"setmetadata":  (*conn).cmdSetmetadata,
	"compress":     (*conn).cmdCompress,
	"esearch":      (*conn).cmdEsearch,
	"notify":       (*conn).cmdNotify, // Connection does not have to be in selected state. ../rfc/5465:792 ../rfc/5465:921

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
	// ../rfc/8508:289
	"replace":     (*conn).cmdReplace,
	"uid replace": (*conn).cmdUIDReplace,
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

func (c *conn) xbrokenf(format string, args ...any) {
	c.connBroken = true
	panic(fmt.Errorf(format, args...))
}

type msgseq uint32

// Listen initializes all imap listeners for the configuration, and stores them for Serve to start them.
func Listen() {
	names := slices.Sorted(maps.Keys(mox.Conf.Static.Listeners))
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

	// Each listener gets its own copy of the config, so session keys between different
	// ports on same listener aren't shared. We rotate session keys explicitly in this
	// base TLS config because each connection clones the TLS config before using. The
	// base TLS config would never get automatically managed/rotated session keys.
	if tlsConfig != nil {
		tlsConfig = tlsConfig.Clone()
		mox.StartTLSSessionTicketKeyRefresher(mox.Shutdown, log, tlsConfig)
	}

	serve := func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Infox("imap: accept", err, slog.String("protocol", protocol), slog.String("listener", listenerName))
				continue
			}

			metricIMAPConnection.WithLabelValues(protocol).Inc()
			go serve(listenerName, mox.Cid(), tlsConfig, conn, xtls, noRequireSTARTTLS, false, "")
		}
	}

	servers = append(servers, serve)
}

// ServeTLSConn serves IMAP on a TLS connection.
func ServeTLSConn(listenerName string, conn *tls.Conn, tlsConfig *tls.Config) {
	serve(listenerName, mox.Cid(), tlsConfig, conn, true, false, true, "")
}

func ServeConnPreauth(listenerName string, cid int64, conn net.Conn, preauthAddress string) {
	serve(listenerName, cid, nil, conn, false, true, false, preauthAddress)
}

// Serve starts serving on all listeners, launching a goroutine per listener.
func Serve() {
	for _, serve := range servers {
		go serve()
	}
	servers = nil
}

// Logbg returns a logger for logging in the background (in a goroutine), eg for
// logging LoginAttempts. The regular c.log has a handler that evaluates fields on
// the connection at time of logging, which may happen at the same time as
// modifications to those fields.
func (c *conn) logbg() mlog.Log {
	log := mlog.New("imapserver", nil).WithCid(c.cid)
	if c.username != "" {
		log = log.With(slog.String("username", c.username))
	}
	return log
}

// returns whether this connection accepts utf-8 in strings.
func (c *conn) utf8strings() bool {
	return c.enabled[capIMAP4rev2] || c.enabled[capUTF8Accept]
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
	// Flush any pending delayed changes as if the mailbox is still selected. Probably
	// better than causing STATUS responses for the mailbox being unselected but which
	// is still selected.
	c.flushNotifyDelayed()

	if c.state == stateSelected {
		c.state = stateAuthenticated
	}
	c.mailboxID = 0
	c.uidnext = 0
	c.exists = 0
	c.uids = nil
}

func (c *conn) flushNotifyDelayed() {
	if c.notify == nil {
		return
	}
	delayed := c.notify.Delayed
	c.notify.Delayed = nil
	c.flushChanges(delayed)
}

// flushChanges is called for NOTIFY changes we shouldn't send untagged messages
// about but must process for message removals. We don't update the selected
// mailbox message sequence numbers, since the client would have no idea we
// adjusted message sequence numbers. Combined with NOTIFY NONE, this means
// messages may be erased that the client thinks still exists in its session.
func (c *conn) flushChanges(changes []store.Change) {
	for _, change := range changes {
		switch ch := change.(type) {
		case store.ChangeRemoveUIDs:
			c.comm.RemovalSeen(ch)
		}
	}
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
			c.xbrokenf("write: %s (%w)", err, errIO)
		}
		n += nn
		buf = buf[chunk:]
		if len(buf) > 0 && badClientDelay > 0 {
			mox.Sleep(mox.Context, badClientDelay)
		}
	}
	return n, nil
}

func (c *conn) xtraceread(level slog.Level) func() {
	c.tr.SetTrace(level)
	return func() {
		c.tr.SetTrace(mlog.LevelTrace)
	}
}

func (c *conn) xtracewrite(level slog.Level) func() {
	c.xflush()
	c.xtw.SetTrace(level)
	return func() {
		c.xflush()
		c.xtw.SetTrace(mlog.LevelTrace)
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
func (c *conn) xreadline(readCmd bool) string {
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
			err := c.conn.SetDeadline(time.Now().Add(10 * time.Second))
			c.log.Check(err, "setting deadline")
			c.xwritelinef("* BYE inactive")
		}
		c.connBroken = true
		if !errors.Is(err, errIO) && !errors.Is(err, errProtocol) {
			c.xbrokenf("%s (%w)", err, errIO)
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
func (c *conn) xwriteresultf(format string, args ...any) {
	c.xbwriteresultf(format, args...)
	c.xflush()
}

// write buffered tagged command response, but first write pending changes.
func (c *conn) xbwriteresultf(format string, args ...any) {
	switch c.cmd {
	case "fetch", "store", "search":
		// ../rfc/9051:5862 ../rfc/7162:2033
	case "select", "examine":
		// We don't send changes before having confirmed opening the mailbox, to prevent
		// clients from trying to interpret changes when it considers there isn't a
		// selected mailbox yet.
	default:
		if c.comm != nil {
			overflow, changes := c.comm.Get()
			c.xapplyChanges(overflow, changes, true)
		}
	}
	c.xbwritelinef(format, args...)
}

func (c *conn) xwritelinef(format string, args ...any) {
	c.xbwritelinef(format, args...)
	c.xflush()
}

// Buffer line for write.
func (c *conn) xbwritelinef(format string, args ...any) {
	format += "\r\n"
	fmt.Fprintf(c.xbw, format, args...)
}

func (c *conn) xflush() {
	// If the connection is already broken, we're not going to write more.
	if c.connBroken {
		return
	}

	err := c.xbw.Flush()
	xcheckf(err, "flush") // Should never happen, the Write caused by the Flush should panic on i/o error.

	// If compression is enabled, we need to flush its stream.
	if c.compress {
		// Note: Flush writes a sync message if there is nothing to flush. Ideally we
		// wouldn't send that, but we would have to keep track of whether data needs to be
		// flushed.
		err := c.xflateWriter.Flush()
		xcheckf(err, "flush deflate")

		// The flate writer writes to a bufio.Writer, we must also flush that.
		err = c.xflateBW.Flush()
		xcheckf(err, "flush deflate writer")
	}
}

func (c *conn) parseCommand(tag *string, line string) (cmd string, p *parser) {
	p = newParser(line, c)
	p.context("tag")
	*tag = p.xtag()
	p.context("command")
	p.xspace()
	cmd = p.xcommand()
	return cmd, newParser(p.remainder(), c)
}

func (c *conn) xreadliteral(size int64, sync bool) []byte {
	if sync {
		c.xwritelinef("+ ")
	}
	buf := make([]byte, size)
	if size > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			c.log.Errorx("setting read deadline", err)
		}

		_, err := io.ReadFull(c.br, buf)
		if err != nil {
			c.xbrokenf("reading literal: %s (%w)", err, errIO)
		}
	}
	return buf
}

var cleanClose struct{} // Sentinel value for panic/recover indicating clean close of connection.

// serve handles a single IMAP connection on nc.
//
// If xtls is set, immediate TLS should be enabled on the connection, unless
// viaHTTP is set, which indicates TLS is already active with the connection coming
// from the webserver with IMAP chosen through ALPN. activated. If viaHTTP is set,
// the TLS config ddid not enable client certificate authentication. If xtls is
// false and tlsConfig is set, STARTTLS may enable TLS later on.
//
// If noRequireSTARTTLS is set, TLS is not required for authentication.
//
// If accountAddress is not empty, it is the email address of the account to open
// preauthenticated.
//
// The connection is closed before returning.
func serve(listenerName string, cid int64, tlsConfig *tls.Config, nc net.Conn, xtls, noRequireSTARTTLS, viaHTTPS bool, preauthAddress string) {
	var remoteIP net.IP
	if a, ok := nc.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = a.IP
	} else {
		// For tests and for imapserve.
		remoteIP = net.ParseIP("127.0.0.10")
	}

	c := &conn{
		cid:               cid,
		conn:              nc,
		tls:               xtls,
		viaHTTPS:          viaHTTPS,
		lastlog:           time.Now(),
		baseTLSConfig:     tlsConfig,
		remoteIP:          remoteIP,
		noRequireSTARTTLS: noRequireSTARTTLS,
		enabled:           map[capability]bool{},
		cmd:               "(greeting)",
		cmdStart:          time.Now(),
	}
	var logmutex sync.Mutex
	// Also see (and possibly update) c.logbg, for logging in a goroutine.
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
	// todo: tracing should be done on whatever comes out of c.br. the remote connection write a command plus data, and bufio can read it in one read, causing a command parser that sets the tracing level to data to have no effect. we are now typically logging sent messages, when mail clients append to the Sent mailbox.
	c.br = bufio.NewReader(c.tr)
	c.xtw = moxio.NewTraceWriter(c.log, "S: ", c)
	c.xbw = bufio.NewWriter(c.xtw)

	// Many IMAP connections use IDLE to wait for new incoming messages. We'll enable
	// keepalive to get a higher chance of the connection staying alive, or otherwise
	// detecting broken connections early.
	tcpconn := c.conn
	if viaHTTPS {
		tcpconn = nc.(*tls.Conn).NetConn()
	}
	if tc, ok := tcpconn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlivePeriod(5 * time.Minute); err != nil {
			c.log.Errorx("setting keepalive period", err)
		} else if err := tc.SetKeepAlive(true); err != nil {
			c.log.Errorx("enabling keepalive", err)
		}
	}

	c.log.Info("new connection",
		slog.Any("remote", c.conn.RemoteAddr()),
		slog.Any("local", c.conn.LocalAddr()),
		slog.Bool("tls", xtls),
		slog.Bool("viahttps", viaHTTPS),
		slog.String("listener", listenerName))

	defer func() {
		err := c.conn.Close()
		if err != nil {
			c.log.Debugx("closing connection", err)
		}

		// If changes for NOTIFY's SELECTED-DELAYED are still pending, we'll acknowledge
		// their message removals so the files can be erased.
		c.flushNotifyDelayed()

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
			unhandledPanics.Add(1) // For tests.
		}
	}()

	if xtls && !viaHTTPS {
		// Start TLS on connection. We perform the handshake explicitly, so we can set a
		// timeout, do client certificate authentication, log TLS details afterwards.
		c.xtlsHandshakeAndAuthenticate(c.conn)
	}

	select {
	case <-mox.Shutdown.Done():
		// ../rfc/9051:5381
		c.xwritelinef("* BYE mox shutting down")
		return
	default:
	}

	if !limiterConnectionrate.Add(c.remoteIP, time.Now(), 1) {
		c.xwritelinef("* BYE connection rate from your ip or network too high, slow down please")
		return
	}

	// If remote IP/network resulted in too many authentication failures, refuse to serve.
	if !mox.LimiterFailedAuth.CanAdd(c.remoteIP, time.Now(), 1) {
		metrics.AuthenticationRatelimitedInc("imap")
		c.log.Debug("refusing connection due to many auth failures", slog.Any("remoteip", c.remoteIP))
		c.xwritelinef("* BYE too many auth failures")
		return
	}

	if !limiterConnections.Add(c.remoteIP, time.Now(), 1) {
		c.log.Debug("refusing connection due to many open connections", slog.Any("remoteip", c.remoteIP))
		c.xwritelinef("* BYE too many open connections from your ip or network")
		return
	}
	defer limiterConnections.Add(c.remoteIP, time.Now(), -1)

	// We register and unregister the original connection, in case it c.conn is
	// replaced with a TLS connection later on.
	mox.Connections.Register(nc, "imap", listenerName)
	defer mox.Connections.Unregister(nc)

	if preauthAddress != "" {
		acc, _, _, err := store.OpenEmail(c.log, preauthAddress, false)
		if err != nil {
			c.log.Debugx("open account for preauth address", err, slog.String("address", preauthAddress))
			c.xwritelinef("* BYE open account for address: %s", err)
			return
		}
		c.username = preauthAddress
		c.account = acc
		c.comm = store.RegisterComm(c.account)
	}

	if c.account != nil && !c.noPreauth {
		c.state = stateAuthenticated
		c.xwritelinef("* PREAUTH [CAPABILITY %s] mox imap welcomes %s", c.capabilities(), c.username)
	} else {
		c.xwritelinef("* OK [CAPABILITY %s] mox imap", c.capabilities())
	}

	// Ensure any pending loginAttempt is written before we stop.
	defer func() {
		if c.loginAttempt != nil {
			store.LoginAttemptAdd(context.Background(), c.logbg(), *c.loginAttempt)
			c.loginAttempt = nil
			c.loginAttemptTime = time.Time{}
		}
	}()

	for {
		c.command()
		c.xflush() // For flushing errors, or commands that did not flush explicitly.

		// Flush login attempt if it hasn't already been flushed by an ID command within 1s
		// after authentication.
		if c.loginAttempt != nil && (c.loginAttempt.UserAgent != "" || time.Since(c.loginAttemptTime) >= time.Second) {
			store.LoginAttemptAdd(context.Background(), c.logbg(), *c.loginAttempt)
			c.loginAttempt = nil
			c.loginAttemptTime = time.Time{}
		}
	}
}

// isClosed returns whether i/o failed, typically because the connection is closed.
// For connection errors, we often want to generate fewer logs.
func isClosed(err error) bool {
	return errors.Is(err, errIO) || errors.Is(err, errProtocol) || mlog.IsClosed(err)
}

// newLoginAttempt initializes a c.loginAttempt, for adding to the store after
// filling in the results and other details.
func (c *conn) newLoginAttempt(useTLS bool, authMech string) {
	if c.loginAttempt != nil {
		store.LoginAttemptAdd(context.Background(), c.logbg(), *c.loginAttempt)
		c.loginAttempt = nil
	}
	c.loginAttemptTime = time.Now()

	var state *tls.ConnectionState
	if tc, ok := c.conn.(*tls.Conn); ok && useTLS {
		v := tc.ConnectionState()
		state = &v
	}

	localAddr := c.conn.LocalAddr().String()
	localIP, _, _ := net.SplitHostPort(localAddr)
	if localIP == "" {
		localIP = localAddr
	}

	c.loginAttempt = &store.LoginAttempt{
		RemoteIP:  c.remoteIP.String(),
		LocalIP:   localIP,
		TLS:       store.LoginAttemptTLS(state),
		Protocol:  "imap",
		UserAgent: c.userAgent, // May still be empty, to be filled in later.
		AuthMech:  authMech,
		Result:    store.AuthError, // Replaced by caller.
	}
}

// makeTLSConfig makes a new tls config that is bound to the connection for
// possible client certificate authentication.
func (c *conn) makeTLSConfig() *tls.Config {
	// We clone the config so we can set VerifyPeerCertificate below to a method bound
	// to this connection. Earlier, we set session keys explicitly on the base TLS
	// config, so they can be used for this connection too.
	tlsConf := c.baseTLSConfig.Clone()

	// Allow client certificate authentication, for use with the sasl "external"
	// authentication mechanism.
	tlsConf.ClientAuth = tls.RequestClientCert

	// We verify the client certificate during the handshake. The TLS handshake is
	// initiated explicitly for incoming connections and during starttls, so we can
	// immediately extract the account name and address used for authentication.
	tlsConf.VerifyPeerCertificate = c.tlsClientAuthVerifyPeerCert

	return tlsConf
}

// tlsClientAuthVerifyPeerCert can be used as tls.Config.VerifyPeerCertificate, and
// sets authentication-related fields on conn. This is not called on resumed TLS
// connections.
func (c *conn) tlsClientAuthVerifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil
	}

	// If we had too many authentication failures from this IP, don't attempt
	// authentication. If this is a new incoming connetion, it is closed after the TLS
	// handshake.
	if !mox.LimiterFailedAuth.CanAdd(c.remoteIP, time.Now(), 1) {
		return nil
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		c.log.Debugx("parsing tls client certificate", err)
		return err
	}
	if err := c.tlsClientAuthVerifyPeerCertParsed(cert); err != nil {
		c.log.Debugx("verifying tls client certificate", err)
		return fmt.Errorf("verifying client certificate: %w", err)
	}
	return nil
}

// tlsClientAuthVerifyPeerCertParsed verifies a client certificate. Called both for
// fresh and resumed TLS connections.
func (c *conn) tlsClientAuthVerifyPeerCertParsed(cert *x509.Certificate) error {
	if c.account != nil {
		return fmt.Errorf("cannot authenticate with tls client certificate after previous authentication")
	}

	// todo: it would be nice to postpone storing the loginattempt for tls pubkey auth until we have the ID command. but delaying is complicated because we can't get the tls information in this function. that's why we store the login attempt in a goroutine below, where it can can get a lock when accessing the tls connection only when this function has returned. we can't access c.loginAttempt (we would turn it into a slice) in a goroutine without adding more locking. for now we'll do without user-agent/id for tls pub key auth.
	c.newLoginAttempt(false, "tlsclientauth")
	defer func() {
		// Get TLS connection state in goroutine because we are called while performing the
		// TLS handshake, which already has the tls connection locked.
		conn := c.conn.(*tls.Conn)
		la := *c.loginAttempt
		c.loginAttempt = nil
		logbg := c.logbg() // Evaluate attributes now, can't do it in goroutine.
		go func() {
			defer func() {
				// In case of panic don't take the whole program down.
				x := recover()
				if x != nil {
					c.log.Error("recover from panic", slog.Any("panic", x))
					debug.PrintStack()
					metrics.PanicInc(metrics.Imapserver)
				}
			}()

			state := conn.ConnectionState()
			la.TLS = store.LoginAttemptTLS(&state)
			store.LoginAttemptAdd(context.Background(), logbg, la)
		}()

		if la.Result == store.AuthSuccess {
			mox.LimiterFailedAuth.Reset(c.remoteIP, time.Now())
		} else {
			mox.LimiterFailedAuth.Add(c.remoteIP, time.Now(), 1)
		}
	}()

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

	shabuf := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fp := base64.RawURLEncoding.EncodeToString(shabuf[:])
	c.loginAttempt.TLSPubKeyFingerprint = fp
	pubKey, err := store.TLSPublicKeyGet(context.TODO(), fp)
	if err != nil {
		if err == bstore.ErrAbsent {
			c.loginAttempt.Result = store.AuthBadCredentials
		}
		return fmt.Errorf("looking up tls public key with fingerprint %s: %v", fp, err)
	}
	c.loginAttempt.LoginAddress = pubKey.LoginAddress

	// Verify account exists and still matches address. We don't check for account
	// login being disabled if preauth is disabled. In that case, sasl external auth
	// will be done before credentials can be used, and login disabled will be checked
	// then, where it will result in a more helpful error message.
	checkLoginDisabled := !pubKey.NoIMAPPreauth
	acc, accName, _, err := store.OpenEmail(c.log, pubKey.LoginAddress, checkLoginDisabled)
	c.loginAttempt.AccountName = accName
	if err != nil {
		if errors.Is(err, store.ErrLoginDisabled) {
			c.loginAttempt.Result = store.AuthLoginDisabled
		}
		// note: we cannot send a more helpful error message to the client.
		return fmt.Errorf("opening account for address %s for public key %s: %w", pubKey.LoginAddress, fp, err)
	}
	defer func() {
		if acc != nil {
			err := acc.Close()
			c.xsanity(err, "close account")
		}
	}()
	c.loginAttempt.AccountName = acc.Name
	if acc.Name != pubKey.Account {
		return fmt.Errorf("tls client public key %s is for account %s, but email address %s is for account %s", fp, pubKey.Account, pubKey.LoginAddress, acc.Name)
	}

	c.loginAttempt.Result = store.AuthSuccess

	c.authFailed = 0
	c.noPreauth = pubKey.NoIMAPPreauth
	c.account = acc
	acc = nil // Prevent cleanup by defer.
	c.username = pubKey.LoginAddress
	c.comm = store.RegisterComm(c.account)
	c.log.Debug("tls client authenticated with client certificate",
		slog.String("fingerprint", fp),
		slog.String("username", c.username),
		slog.String("account", c.account.Name),
		slog.Any("remote", c.remoteIP))
	return nil
}

// xtlsHandshakeAndAuthenticate performs the TLS handshake, and verifies a client
// certificate if present.
func (c *conn) xtlsHandshakeAndAuthenticate(conn net.Conn) {
	tlsConn := tls.Server(conn, c.makeTLSConfig())
	c.conn = tlsConn
	c.tr = moxio.NewTraceReader(c.log, "C: ", c.conn)
	c.br = bufio.NewReader(c.tr)

	cidctx := context.WithValue(mox.Context, mlog.CidKey, c.cid)
	ctx, cancel := context.WithTimeout(cidctx, time.Minute)
	defer cancel()
	c.log.Debug("starting tls server handshake")
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		c.xbrokenf("tls handshake: %s (%w)", err, errIO)
	}
	cancel()

	cs := tlsConn.ConnectionState()
	if cs.DidResume && len(cs.PeerCertificates) > 0 {
		// Verify client after session resumption.
		err := c.tlsClientAuthVerifyPeerCertParsed(cs.PeerCertificates[0])
		if err != nil {
			c.xwritelinef("* BYE [ALERT] Error verifying client certificate after TLS session resumption: %s", err)
			c.xbrokenf("tls verify client certificate after resumption: %s (%w)", err, errIO)
		}
	}

	version, ciphersuite := moxio.TLSInfo(cs)
	attrs := []slog.Attr{
		slog.String("version", version),
		slog.String("ciphersuite", ciphersuite),
		slog.String("sni", cs.ServerName),
		slog.Bool("resumed", cs.DidResume),
		slog.Int("clientcerts", len(cs.PeerCertificates)),
	}
	if c.account != nil {
		attrs = append(attrs,
			slog.String("account", c.account.Name),
			slog.String("username", c.username),
		)
	}
	c.log.Debug("tls handshake completed", attrs...)
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
				// If compression was enabled, we flush & close the deflate stream.
				if c.compress {
					// Note: Close and flush can Write and may panic with an i/o error.
					if err := c.xflateWriter.Close(); err != nil {
						c.log.Debugx("close deflate writer", err)
					} else if err := c.xflateBW.Flush(); err != nil {
						c.log.Debugx("flush deflate buffer", err)
					}
				}

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
				c.xwritelinef("* BYE please try again speaking imap")
				c.xbrokenf("not speaking imap (%w)", errIO)
			}
			c.log.Debugx("imap command syntax error", sxerr.err, logFields...)
			c.log.Info("imap syntax error", slog.String("lastline", c.lastLine))
			fatal := strings.HasSuffix(c.lastLine, "+}")
			if fatal {
				err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				c.log.Check(err, "setting write deadline")
			}
			if sxerr.line != "" {
				c.xbwritelinef("%s", sxerr.line)
			}
			code := ""
			if sxerr.code != "" {
				code = "[" + sxerr.code + "] "
			}
			c.xbwriteresultf("%s BAD %s%s unrecognized syntax/command: %v", tag, code, cmd, sxerr.errmsg)
			if fatal {
				c.xflush()
				panic(fmt.Errorf("aborting connection after syntax error for command with non-sync literal: %w", errProtocol))
			}
		} else if errors.As(err, &serr) {
			result = "servererror"
			c.log.Errorx("imap command server error", err, logFields...)
			debug.PrintStack()
			c.xbwriteresultf("%s NO %s %v", tag, cmd, err)
		} else if errors.As(err, &uerr) {
			result = "usererror"
			c.log.Debugx("imap command user error", err, logFields...)
			if uerr.code != "" {
				c.xbwriteresultf("%s NO [%s] %s %v", tag, uerr.code, cmd, err)
			} else {
				c.xbwriteresultf("%s NO %s %v", tag, cmd, err)
			}
		} else {
			// Other type of panic, we pass it on, aborting the connection.
			result = "panic"
			c.log.Errorx("imap command panic", err, logFields...)
			panic(err)
		}
	}()

	tag = "*"

	// If NOTIFY is enabled, we wait for either a line (with a command) from the
	// client, or a change event. If we see a line, we continue below as for the
	// non-NOTIFY case, parsing the command.
	var line string
	if c.notify != nil {
	Wait:
		for {
			select {
			case le := <-c.lineChan():
				c.line = nil
				if err := le.err; err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						err := c.conn.SetDeadline(time.Now().Add(10 * time.Second))
						c.log.Check(err, "setting write deadline")
						c.xwritelinef("* BYE inactive")
					}
					c.connBroken = true
					if !errors.Is(err, errIO) && !errors.Is(err, errProtocol) {
						c.xbrokenf("%s (%w)", err, errIO)
					}
					panic(err)
				}
				line = le.line
				break Wait

			case <-c.comm.Pending:
				overflow, changes := c.comm.Get()
				c.xapplyChanges(overflow, changes, false)
				c.xflush()

			case <-mox.Shutdown.Done():
				// ../rfc/9051:5375
				c.xwritelinef("* BYE shutting down")
				c.xbrokenf("shutting down (%w)", errIO)
			}
		}

		// Reset the write deadline. In case of little activity, with a command timeout of
		// 30 minutes, we have likely passed it.
		err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
		c.log.Check(err, "setting write deadline")
	} else {
		// Without NOTIFY, we just read a line.
		line = c.xreadline(true)
	}
	cmd, p = c.parseCommand(&tag, line)
	cmdlow = strings.ToLower(cmd)
	c.cmd = cmdlow
	c.cmdStart = time.Now()
	c.cmdMetric = "(unrecognized)"

	select {
	case <-mox.Shutdown.Done():
		// ../rfc/9051:5375
		c.xwritelinef("* BYE shutting down")
		c.xbrokenf("shutting down (%w)", errIO)
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

	// ../rfc/9586:172
	if _, ok := commandsSequence[cmdlow]; ok && c.uidonly {
		xsyntaxCodeErrorf("UIDREQUIRED", "cannot use message sequence numbers with uidonly")
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
	if c.uidonly {
		panic("sequence with uidonly")
	}
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
	if c.uidonly {
		panic("xsequence with uidonly")
	}
	seq := c.sequence(uid)
	if seq <= 0 {
		xserverErrorf("unknown uid %d (%w)", uid, errProtocol)
	}
	return seq
}

func (c *conn) sequenceRemove(seq msgseq, uid store.UID) {
	if c.uidonly {
		panic("sequenceRemove with uidonly")
	}
	i := seq - 1
	if c.uids[i] != uid {
		xserverErrorf("got uid %d at msgseq %d, expected uid %d", uid, seq, c.uids[i])
	}
	copy(c.uids[i:], c.uids[i+1:])
	c.uids = c.uids[:c.exists-1]
	c.exists--
	c.checkUIDs(c.uids, true)
}

// add uid to session, through c.uidnext, and if uidonly isn't enabled to c.uids.
// care must be taken that pending changes are fetched while holding the account
// wlock, and applied before adding this uid, because those pending changes may
// contain another new uid that has to be added first.
func (c *conn) uidAppend(uid store.UID) {
	if c.uidonly {
		if uid < c.uidnext {
			panic(fmt.Sprintf("new uid %d < uidnext %d", uid, c.uidnext))
		}
		c.exists++
		c.uidnext = uid + 1
		return
	}

	if uidSearch(c.uids, uid) > 0 {
		xserverErrorf("uid already present (%w)", errProtocol)
	}
	if c.exists > 0 && uid < c.uids[c.exists-1] {
		xserverErrorf("new uid %d is smaller than last uid %d (%w)", uid, c.uids[c.exists-1], errProtocol)
	}
	c.exists++
	c.uidnext = uid + 1
	c.uids = append(c.uids, uid)
	c.checkUIDs(c.uids, true)
}

// sanity check that uids are in ascending order.
func (c *conn) checkUIDs(uids []store.UID, checkExists bool) {
	if !sanityChecks {
		return
	}

	if checkExists && uint32(len(uids)) != c.exists {
		panic(fmt.Sprintf("exists %d does not match len(uids) %d", c.exists, len(c.uids)))
	}

	for i, uid := range uids {
		if uid == 0 || i > 0 && uid <= uids[i-1] {
			xserverErrorf("bad uids %v", uids)
		}
	}
}

func slicesAny[T any](l []T) []any {
	r := make([]any, len(l))
	for i, v := range l {
		r[i] = v
	}
	return r
}

// newCachedLastUID returns a method that returns the highest uid for a mailbox,
// for interpretation of "*". If mailboxID is for the selected mailbox, the UIDs
// visible in the session are taken into account. If there is no UID, 0 is
// returned. If an error occurs, xerrfn is called, which should not return.
func (c *conn) newCachedLastUID(tx *bstore.Tx, mailboxID int64, xerrfn func(err error)) func() store.UID {
	var last store.UID
	var have bool
	return func() store.UID {
		if have {
			return last
		}
		if c.mailboxID == mailboxID {
			if c.exists == 0 {
				return 0
			}
			if !c.uidonly {
				return c.uids[c.exists-1]
			}
		}
		q := bstore.QueryTx[store.Message](tx)
		q.FilterNonzero(store.Message{MailboxID: mailboxID})
		q.FilterEqual("Expunged", false)
		if c.mailboxID == mailboxID {
			q.FilterLess("UID", c.uidnext)
		}
		q.SortDesc("UID")
		q.Limit(1)
		m, err := q.Get()
		if err == bstore.ErrAbsent {
			have = true
			return last
		}
		if err != nil {
			xerrfn(err)
			panic(err) // xerrfn should have called panic.
		}
		have = true
		last = m.UID
		return last
	}
}

// xnumSetEval evaluates nums to uids given the current session state and messages
// in the selected mailbox. The returned UIDs are sorted, without duplicates.
func (c *conn) xnumSetEval(tx *bstore.Tx, isUID bool, nums numSet) []store.UID {
	if nums.searchResult {
		// UIDs that do not exist can be ignored.
		if c.exists == 0 {
			return nil
		}

		// Update previously stored UIDs. Some may have been deleted.
		// Once deleted a UID will never come back, so we'll just remove those uids.
		if c.uidonly {
			var uids []store.UID
			if len(c.searchResult) > 0 {
				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: c.mailboxID})
				q.FilterEqual("Expunged", false)
				q.FilterEqual("UID", slicesAny(c.searchResult)...)
				q.SortAsc("UID")
				for m, err := range q.All() {
					xcheckf(err, "looking up messages from search result")
					uids = append(uids, m.UID)
				}
			}
			c.searchResult = uids
		} else {
			o := 0
			for _, uid := range c.searchResult {
				if uidSearch(c.uids, uid) > 0 {
					c.searchResult[o] = uid
					o++
				}
			}
			c.searchResult = c.searchResult[:o]
		}
		return c.searchResult
	}

	if !isUID {
		uids := map[store.UID]struct{}{}

		// Sequence numbers that don't exist, or * on an empty mailbox, should result in a BAD response. ../rfc/9051:7018
		for _, r := range nums.ranges {
			var ia, ib int
			if r.first.star {
				if c.exists == 0 {
					xsyntaxErrorf("invalid seqset * on empty mailbox")
				}
				ia = int(c.exists) - 1
			} else {
				ia = int(r.first.number - 1)
				if ia >= int(c.exists) {
					xsyntaxErrorf("msgseq %d not in mailbox", r.first.number)
				}
			}
			if r.last == nil {
				uids[c.uids[ia]] = struct{}{}
				continue
			}

			if r.last.star {
				ib = int(c.exists) - 1
			} else {
				ib = int(r.last.number - 1)
				if ib >= int(c.exists) {
					xsyntaxErrorf("msgseq %d not in mailbox", r.last.number)
				}
			}
			if ia > ib {
				ia, ib = ib, ia
			}
			for _, uid := range c.uids[ia : ib+1] {
				uids[uid] = struct{}{}
			}
		}
		return slices.Sorted(maps.Keys(uids))
	}

	// UIDs that do not exist can be ignored.
	if c.exists == 0 {
		return nil
	}

	uids := map[store.UID]struct{}{}

	if c.uidonly {
		xlastUID := c.newCachedLastUID(tx, c.mailboxID, func(xerr error) { xuserErrorf("%s", xerr) })
		for _, r := range nums.xinterpretStar(xlastUID).ranges {
			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: c.mailboxID})
			q.FilterEqual("Expunged", false)
			if r.last == nil {
				q.FilterEqual("UID", r.first.number)
			} else {
				q.FilterGreaterEqual("UID", r.first.number)
				q.FilterLessEqual("UID", r.last.number)
			}
			q.FilterLess("UID", c.uidnext)
			q.SortAsc("UID")
			for m, err := range q.All() {
				xcheckf(err, "enumerating uids")
				uids[m.UID] = struct{}{}
			}
		}
		return slices.Sorted(maps.Keys(uids))
	}

	for _, r := range nums.ranges {
		last := r.first
		if r.last != nil {
			last = *r.last
		}

		uida := store.UID(r.first.number)
		if r.first.star {
			uida = c.uids[c.exists-1]
		}

		uidb := store.UID(last.number)
		if last.star {
			uidb = c.uids[c.exists-1]
		}

		if uida > uidb {
			uida, uidb = uidb, uida
		}

		// Binary search for uida.
		s := 0
		e := int(c.exists)
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
				uids[uid] = struct{}{}
			} else if uid > uidb {
				break
			}
		}
	}
	return slices.Sorted(maps.Keys(uids))
}

func (c *conn) ok(tag, cmd string) {
	c.xbwriteresultf("%s OK %s done", tag, cmd)
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
	mb, err := store.MailboxID(tx, id)
	if err == bstore.ErrAbsent {
		xuserErrorf("%w", store.ErrUnknownMailbox)
	} else if err == store.ErrMailboxExpunged {
		// ../rfc/9051:5140
		xusercodeErrorf("NONEXISTENT", "mailbox has been deleted")
	}
	return mb
}

// Apply changes to our session state.
// Should not be called while holding locks, as changes are written to client connections, which can block.
// Does not flush output.
func (c *conn) xapplyChanges(overflow bool, changes []store.Change, sendDelayed bool) {
	// If more changes were generated than we can process, we send a
	// NOTIFICATIONOVERFLOW as defined in the NOTIFY extension. ../rfc/5465:712
	if overflow {
		if c.notify != nil && len(c.notify.Delayed) > 0 {
			changes = append(c.notify.Delayed, changes...)
		}
		c.flushChanges(changes)
		// We must not send any more unsolicited untagged responses to the client for
		// NOTIFY, but we also follow this for IDLE. ../rfc/5465:717
		c.notify = &notify{}
		c.xbwritelinef("* OK [NOTIFICATIONOVERFLOW] out of sync after too many pending changes")
		changes = nil
	}

	// applyChanges for IDLE and NOTIFY. When explicitly in IDLE while NOTIFY is
	// enabled, we still respond with messages as for NOTIFY. ../rfc/5465:406
	if c.notify != nil {
		c.xapplyChangesNotify(changes, sendDelayed)
		return
	}
	if len(changes) == 0 {
		return
	}

	// Even in the case of a panic (e.g. i/o errors), we must mark removals as seen.
	origChanges := changes
	defer func() {
		for _, change := range origChanges {
			if ch, ok := change.(store.ChangeRemoveUIDs); ok {
				c.comm.RemovalSeen(ch)
			}
		}
	}()

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
		case store.ChangeRemoveMailbox, store.ChangeAddMailbox, store.ChangeRenameMailbox, store.ChangeAddSubscription, store.ChangeRemoveSubscription:
			n = append(n, change)
			continue
		case store.ChangeAnnotation:
			// note: annotations may have a mailbox associated with them, but we pass all
			// changes on.
			// Only when the metadata capability was enabled. ../rfc/5464:660
			if c.enabled[capMetadata] {
				n = append(n, change)
				continue
			}
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
			c.uidAppend(ch.UID)
			adds = append(adds, ch)
		}
		if len(adds) > 0 {
			// Write the exists, and the UID and flags as well. Hopefully the client waits for
			// long enough after the EXISTS to see these messages, and doesn't request them
			// again with a FETCH.
			c.xbwritelinef("* %d EXISTS", c.exists)
			for _, add := range adds {
				var modseqStr string
				if condstore {
					modseqStr = fmt.Sprintf(" MODSEQ (%d)", add.ModSeq.Client())
				}
				// UIDFETCH in case of uidonly. ../rfc/9586:228
				if c.uidonly {
					c.xbwritelinef("* %d UIDFETCH (FLAGS %s%s)", add.UID, flaglist(add.Flags, add.Keywords).pack(c), modseqStr)
				} else {
					seq := c.xsequence(add.UID)
					c.xbwritelinef("* %d FETCH (UID %d FLAGS %s%s)", seq, add.UID, flaglist(add.Flags, add.Keywords).pack(c), modseqStr)
				}
			}
			continue
		}

		change := changes[i]
		i++

		switch ch := change.(type) {
		case store.ChangeRemoveUIDs:
			var vanishedUIDs numSet
			for _, uid := range ch.UIDs {
				// With uidonly, we must always return VANISHED. ../rfc/9586:232
				if c.uidonly {
					c.exists--
					vanishedUIDs.append(uint32(uid))
					continue
				}

				seq := c.xsequence(uid)
				c.sequenceRemove(seq, uid)
				if qresync {
					vanishedUIDs.append(uint32(uid))
				} else {
					c.xbwritelinef("* %d EXPUNGE", seq)
				}
			}
			if !vanishedUIDs.empty() {
				// VANISHED without EARLIER. ../rfc/7162:2004
				for _, s := range vanishedUIDs.Strings(4*1024 - 32) {
					c.xbwritelinef("* VANISHED %s", s)
				}
			}

		case store.ChangeFlags:
			var modseqStr string
			if condstore {
				modseqStr = fmt.Sprintf(" MODSEQ (%d)", ch.ModSeq.Client())
			}
			// UIDFETCH in case of uidonly. ../rfc/9586:228
			if c.uidonly {
				c.xbwritelinef("* %d UIDFETCH (FLAGS %s%s)", ch.UID, flaglist(ch.Flags, ch.Keywords).pack(c), modseqStr)
			} else {
				// The uid can be unknown if we just expunged it while another session marked it as deleted just before.
				seq := c.sequence(ch.UID)
				if seq <= 0 {
					continue
				}
				c.xbwritelinef("* %d FETCH (UID %d FLAGS %s%s)", seq, ch.UID, flaglist(ch.Flags, ch.Keywords).pack(c), modseqStr)
			}

		case store.ChangeRemoveMailbox:
			// Only announce \NonExistent to modern clients, otherwise they may ignore the
			// unrecognized \NonExistent and interpret this as a newly created mailbox, while
			// the goal was to remove it...
			if c.enabled[capIMAP4rev2] {
				c.xbwritelinef(`* LIST (\NonExistent) "/" %s`, mailboxt(ch.Name).pack(c))
			}

		case store.ChangeAddMailbox:
			c.xbwritelinef(`* LIST (%s) "/" %s`, strings.Join(ch.Flags, " "), mailboxt(ch.Mailbox.Name).pack(c))

		case store.ChangeRenameMailbox:
			// OLDNAME only with IMAP4rev2 or NOTIFY ../rfc/9051:2726 ../rfc/5465:628
			var oldname string
			if c.enabled[capIMAP4rev2] {
				oldname = fmt.Sprintf(` ("OLDNAME" (%s))`, mailboxt(ch.OldName).pack(c))
			}
			c.xbwritelinef(`* LIST (%s) "/" %s%s`, strings.Join(ch.Flags, " "), mailboxt(ch.NewName).pack(c), oldname)

		case store.ChangeAddSubscription:
			c.xbwritelinef(`* LIST (%s) "/" %s`, strings.Join(append([]string{`\Subscribed`}, ch.ListFlags...), " "), mailboxt(ch.MailboxName).pack(c))

		case store.ChangeRemoveSubscription:
			c.xbwritelinef(`* LIST (%s) "/" %s`, strings.Join(ch.ListFlags, " "), mailboxt(ch.MailboxName).pack(c))

		case store.ChangeAnnotation:
			// ../rfc/5464:807 ../rfc/5464:788
			c.xbwritelinef(`* METADATA %s %s`, mailboxt(ch.MailboxName).pack(c), astring(ch.Key).pack(c))

		default:
			panic(fmt.Sprintf("internal error, missing case for %#v", change))
		}
	}
}

// xapplyChangesNotify is like xapplyChanges, but for NOTIFY, with configurable
// mailboxes to notify about, and configurable events to send, including which
// fetch attributes to return. All calls must go through xapplyChanges, for overflow
// handling.
func (c *conn) xapplyChangesNotify(changes []store.Change, sendDelayed bool) {
	if sendDelayed && len(c.notify.Delayed) > 0 {
		changes = append(c.notify.Delayed, changes...)
		c.notify.Delayed = nil
	}

	if len(changes) == 0 {
		return
	}

	// Even in the case of a panic (e.g. i/o errors), we must mark removals as seen.
	// For selected-delayed, we may have postponed handling the message, so we call
	// RemovalSeen when handling a change, and mark how far we got, so we only process
	// changes that we haven't processed yet.
	unhandled := changes
	defer func() {
		for _, change := range unhandled {
			if ch, ok := change.(store.ChangeRemoveUIDs); ok {
				c.comm.RemovalSeen(ch)
			}
		}
	}()

	c.log.Debug("applying notify changes", slog.Any("changes", changes))

	err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	c.log.Check(err, "setting write deadline")

	qresync := c.enabled[capQresync]
	condstore := c.enabled[capCondstore]

	// Prepare for providing a read-only transaction on first-use, for MessageNew fetch
	// attributes.
	var tx *bstore.Tx
	defer func() {
		if tx != nil {
			err := tx.Rollback()
			c.log.Check(err, "rolling back tx")
		}
	}()
	xtx := func() *bstore.Tx {
		if tx != nil {
			return tx
		}

		var err error
		tx, err = c.account.DB.Begin(context.TODO(), false)
		xcheckf(err, "tx")
		return tx
	}

	// On-demand mailbox lookups, with cache.
	mailboxes := map[int64]store.Mailbox{}
	xmailbox := func(id int64) store.Mailbox {
		if mb, ok := mailboxes[id]; ok {
			return mb
		}
		mb := store.Mailbox{ID: id}
		err := xtx().Get(&mb)
		xcheckf(err, "get mailbox")
		mailboxes[id] = mb
		return mb
	}

	// Keep track of last command, to close any open message file (for fetching
	// attributes) in case of a panic.
	var cmd *fetchCmd
	defer func() {
		if cmd != nil {
			cmd.msgclose()
			cmd = nil
		}
	}()

	for index, change := range changes {
		switch ch := change.(type) {
		case store.ChangeAddUID:
			// ../rfc/5465:511
			// todo: ../rfc/5465:525 group ChangeAddUID for the same mailbox, so we can send a single EXISTS. useful for imports.

			mb := xmailbox(ch.MailboxID)
			ms, ev, ok := c.notify.match(c, xtx, mb.ID, mb.Name, eventMessageNew)
			if !ok {
				continue
			}

			// For non-selected mailbox, send STATUS with UIDNEXT, MESSAGES. And HIGESTMODSEQ
			// in case of condstore/qresync. ../rfc/5465:537
			// There is no mention of UNSEEN for MessageNew, but clients will want to show a
			// new "unread messages" count, and they will have to understand it since
			// FlagChange is specified as sending UNSEEN.
			if mb.ID != c.mailboxID {
				if condstore || qresync {
					c.xbwritelinef("* STATUS %s (UIDNEXT %d MESSAGES %d HIGHESTMODSEQ %d UNSEEN %d)", mailboxt(mb.Name).pack(c), ch.UID+1, ch.MessageCountIMAP, ch.ModSeq, ch.Unseen)
				} else {
					c.xbwritelinef("* STATUS %s (UIDNEXT %d MESSAGES %d UNSEEN %d)", mailboxt(mb.Name).pack(c), ch.UID+1, ch.MessageCountIMAP, ch.Unseen)
				}
				continue
			}

			// Delay sending all message events, we want to prevent synchronization issues
			// around UIDNEXT and MODSEQ. ../rfc/5465:808
			if ms.Kind == mbspecSelectedDelayed && !sendDelayed {
				c.notify.Delayed = append(c.notify.Delayed, change)
				continue
			}

			c.uidAppend(ch.UID)

			// ../rfc/5465:515
			c.xbwritelinef("* %d EXISTS", c.exists)

			// If client did not specify attributes, we'll send the defaults.
			if len(ev.FetchAtt) == 0 {
				var modseqStr string
				if condstore {
					modseqStr = fmt.Sprintf(" MODSEQ (%d)", ch.ModSeq.Client())
				}
				// NOTIFY does not specify the default fetch attributes to return, we send UID and
				// FLAGS.
				// UIDFETCH in case of uidonly. ../rfc/9586:228
				if c.uidonly {
					c.xbwritelinef("* %d UIDFETCH (FLAGS %s%s)", ch.UID, flaglist(ch.Flags, ch.Keywords).pack(c), modseqStr)
				} else {
					c.xbwritelinef("* %d FETCH (UID %d FLAGS %s%s)", c.xsequence(ch.UID), ch.UID, flaglist(ch.Flags, ch.Keywords).pack(c), modseqStr)
				}
				continue
			}

			// todo: ../rfc/5465:543 mark messages as \seen after processing if client didn't use the .PEEK-variants.
			cmd = &fetchCmd{conn: c, isUID: true, rtx: xtx(), mailboxID: ch.MailboxID, uid: ch.UID}
			data, err := cmd.process(ev.FetchAtt)
			if err != nil {
				// There is no good way to notify the client about errors. We continue below to
				// send a FETCH with just the UID. And we send an untagged NO in the hope a client
				// developer sees the message.
				c.log.Errorx("generating notify fetch response", err, slog.Int64("mailboxid", ch.MailboxID), slog.Any("uid", ch.UID))
				c.xbwritelinef("* NO generating notify fetch response: %s", err.Error())
				// Always add UID, also for uidonly, to ensure a non-empty list.
				data = listspace{bare("UID"), number(ch.UID)}
			}
			// UIDFETCH in case of uidonly. ../rfc/9586:228
			if c.uidonly {
				fmt.Fprintf(cmd.conn.xbw, "* %d UIDFETCH ", ch.UID)
			} else {
				fmt.Fprintf(cmd.conn.xbw, "* %d FETCH ", c.xsequence(ch.UID))
			}
			func() {
				defer c.xtracewrite(mlog.LevelTracedata)()
				data.xwriteTo(cmd.conn, cmd.conn.xbw)
				c.xtracewrite(mlog.LevelTrace) // Restore.
				cmd.conn.xbw.Write([]byte("\r\n"))
			}()

			cmd.msgclose()
			cmd = nil

		case store.ChangeRemoveUIDs:
			// ../rfc/5465:567
			mb := xmailbox(ch.MailboxID)
			ms, _, ok := c.notify.match(c, xtx, mb.ID, mb.Name, eventMessageExpunge)
			if !ok {
				unhandled = changes[index+1:]
				c.comm.RemovalSeen(ch)
				continue
			}

			// For non-selected mailboxes, we send STATUS with at least UIDNEXT and MESSAGES.
			// ../rfc/5465:576
			// In case of QRESYNC, we send HIGHESTMODSEQ. Also for CONDSTORE, which isn't
			// required like for MessageExpunge like it is for MessageNew.   ../rfc/5465:578
			// ../rfc/5465:539
			// There is no mention of UNSEEN, but clients will want to show a new "unread
			// messages" count, and they can parse it since FlagChange is specified as sending
			// UNSEEN.
			if mb.ID != c.mailboxID {
				unhandled = changes[index+1:]
				c.comm.RemovalSeen(ch)
				if condstore || qresync {
					c.xbwritelinef("* STATUS %s (UIDNEXT %d MESSAGES %d HIGHESTMODSEQ %d UNSEEN %d)", mailboxt(mb.Name).pack(c), ch.UIDNext, ch.MessageCountIMAP, ch.ModSeq, ch.Unseen)
				} else {
					c.xbwritelinef("* STATUS %s (UIDNEXT %d MESSAGES %d UNSEEN %d)", mailboxt(mb.Name).pack(c), ch.UIDNext, ch.MessageCountIMAP, ch.Unseen)
				}
				continue
			}

			// Delay sending all message events, we want to prevent synchronization issues
			// around UIDNEXT and MODSEQ. ../rfc/5465:808
			if ms.Kind == mbspecSelectedDelayed && !sendDelayed {
				unhandled = changes[index+1:] // We'll call RemovalSeen in the future.
				c.notify.Delayed = append(c.notify.Delayed, change)
				continue
			}

			unhandled = changes[index+1:]
			c.comm.RemovalSeen(ch)

			var vanishedUIDs numSet
			for _, uid := range ch.UIDs {
				// With uidonly, we must always return VANISHED. ../rfc/9586:232
				if c.uidonly {
					c.exists--
					vanishedUIDs.append(uint32(uid))
					continue
				}

				seq := c.xsequence(uid)
				c.sequenceRemove(seq, uid)
				if qresync {
					vanishedUIDs.append(uint32(uid))
				} else {
					c.xbwritelinef("* %d EXPUNGE", seq)
				}
			}
			if !vanishedUIDs.empty() {
				// VANISHED without EARLIER. ../rfc/7162:2004
				for _, s := range vanishedUIDs.Strings(4*1024 - 32) {
					c.xbwritelinef("* VANISHED %s", s)
				}
			}

		case store.ChangeFlags:
			// ../rfc/5465:461
			mb := xmailbox(ch.MailboxID)
			ms, _, ok := c.notify.match(c, xtx, mb.ID, mb.Name, eventFlagChange)
			if !ok {
				continue
			} else if mb.ID != c.mailboxID {
				// ../rfc/5465:474
				// For condstore/qresync, we include HIGHESTMODSEQ. ../rfc/5465:476
				// We include UNSEEN, so clients can update the number of unread messages. ../rfc/5465:479
				if condstore || qresync {
					c.xbwritelinef("* STATUS %s (HIGHESTMODSEQ %d UIDVALIDITY %d UNSEEN %d)", mailboxt(mb.Name).pack(c), ch.ModSeq, ch.UIDValidity, ch.Unseen)
				} else {
					c.xbwritelinef("* STATUS %s (UIDVALIDITY %d UNSEEN %d)", mailboxt(mb.Name).pack(c), ch.UIDValidity, ch.Unseen)
				}
				continue
			}

			// Delay sending all message events, we want to prevent synchronization issues
			// around UIDNEXT and MODSEQ. ../rfc/5465:808
			if ms.Kind == mbspecSelectedDelayed && !sendDelayed {
				c.notify.Delayed = append(c.notify.Delayed, change)
				continue
			}

			// The uid can be unknown if we just expunged it while another session marked it as deleted just before.
			var seq msgseq
			if !c.uidonly {
				seq = c.sequence(ch.UID)
				if seq <= 0 {
					continue
				}
			}

			var modseqStr string
			if condstore {
				modseqStr = fmt.Sprintf(" MODSEQ (%d)", ch.ModSeq.Client())
			}
			// UID and FLAGS are required. ../rfc/5465:463
			// UIDFETCH in case of uidonly. ../rfc/9586:228
			if c.uidonly {
				c.xbwritelinef("* %d UIDFETCH (FLAGS %s%s)", ch.UID, flaglist(ch.Flags, ch.Keywords).pack(c), modseqStr)
			} else {
				c.xbwritelinef("* %d FETCH (UID %d FLAGS %s%s)", seq, ch.UID, flaglist(ch.Flags, ch.Keywords).pack(c), modseqStr)
			}

		case store.ChangeThread:
			continue

		// ../rfc/5465:603
		case store.ChangeRemoveMailbox:
			mb := xmailbox(ch.MailboxID)
			_, _, ok := c.notify.match(c, xtx, mb.ID, mb.Name, eventMailboxName)
			if !ok {
				continue
			}

			// ../rfc/5465:624
			c.xbwritelinef(`* LIST (\NonExistent) "/" %s`, mailboxt(ch.Name).pack(c))

		case store.ChangeAddMailbox:
			mb := xmailbox(ch.Mailbox.ID)
			_, _, ok := c.notify.match(c, xtx, mb.ID, mb.Name, eventMailboxName)
			if !ok {
				continue
			}
			c.xbwritelinef(`* LIST (%s) "/" %s`, strings.Join(ch.Flags, " "), mailboxt(ch.Mailbox.Name).pack(c))

		case store.ChangeRenameMailbox:
			mb := xmailbox(ch.MailboxID)
			_, _, ok := c.notify.match(c, xtx, mb.ID, mb.Name, eventMailboxName)
			if !ok {
				continue
			}
			// ../rfc/5465:628
			oldname := fmt.Sprintf(` ("OLDNAME" (%s))`, mailboxt(ch.OldName).pack(c))
			c.xbwritelinef(`* LIST (%s) "/" %s%s`, strings.Join(ch.Flags, " "), mailboxt(ch.NewName).pack(c), oldname)

		// ../rfc/5465:653
		case store.ChangeAddSubscription:
			_, _, ok := c.notify.match(c, xtx, 0, ch.MailboxName, eventSubscriptionChange)
			if !ok {
				continue
			}
			c.xbwritelinef(`* LIST (%s) "/" %s`, strings.Join(append([]string{`\Subscribed`}, ch.ListFlags...), " "), mailboxt(ch.MailboxName).pack(c))

		case store.ChangeRemoveSubscription:
			_, _, ok := c.notify.match(c, xtx, 0, ch.MailboxName, eventSubscriptionChange)
			if !ok {
				continue
			}
			// ../rfc/5465:653
			c.xbwritelinef(`* LIST (%s) "/" %s`, strings.Join(ch.ListFlags, " "), mailboxt(ch.MailboxName).pack(c))

		case store.ChangeMailboxCounts:
			continue

		case store.ChangeMailboxSpecialUse:
			// todo: can we send special-use flags as part of an untagged LIST response?
			continue

		case store.ChangeMailboxKeywords:
			// ../rfc/5465:461
			mb := xmailbox(ch.MailboxID)
			ms, _, ok := c.notify.match(c, xtx, mb.ID, mb.Name, eventFlagChange)
			if !ok {
				continue
			} else if mb.ID != c.mailboxID {
				continue
			}

			// Delay sending all message events, we want to prevent synchronization issues
			// around UIDNEXT and MODSEQ.  ../rfc/5465:808
			// This change is about mailbox keywords, but it's specified under the FlagChange
			// message event. ../rfc/5465:466

			if ms.Kind == mbspecSelectedDelayed && !sendDelayed {
				c.notify.Delayed = append(c.notify.Delayed, change)
				continue
			}

			var keywords string
			if len(ch.Keywords) > 0 {
				keywords = " " + strings.Join(ch.Keywords, " ")
			}
			c.xbwritelinef(`* FLAGS (\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent%s)`, keywords)

		case store.ChangeAnnotation:
			// Client does not have to enable METADATA/METADATA-SERVER. Just asking for these
			// events is enough.
			// ../rfc/5465:679

			if ch.MailboxID == 0 {
				// ServerMetadataChange ../rfc/5465:695
				_, _, ok := c.notify.match(c, xtx, 0, "", eventServerMetadataChange)
				if !ok {
					continue
				}
			} else {
				// MailboxMetadataChange ../rfc/5465:665
				mb := xmailbox(ch.MailboxID)
				_, _, ok := c.notify.match(c, xtx, mb.ID, mb.Name, eventMailboxMetadataChange)
				if !ok {
					continue
				}
			}
			// We don't implement message annotations. ../rfc/5465:461

			// We must not include values. ../rfc/5465:683 ../rfc/5464:716
			// Syntax: ../rfc/5464:807
			c.xbwritelinef(`* METADATA %s %s`, mailboxt(ch.MailboxName).pack(c), astring(ch.Key).pack(c))

		default:
			panic(fmt.Sprintf("internal error, missing case for %#v", change))
		}
	}

	// If we have too many delayed changes, we will warn about notification overflow,
	// and not queue more changes until another NOTIFY command. ../rfc/5465:717
	if len(c.notify.Delayed) > selectedDelayedChangesMax {
		l := c.notify.Delayed
		c.notify.Delayed = nil
		c.flushChanges(l)

		c.notify = &notify{}
		c.xbwritelinef("* OK [NOTIFICATIONOVERFLOW] out of sync after too many pending changes for selected mailbox")
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
	c.xbwritelinef("* CAPABILITY %s", caps)
	c.ok(tag, cmd)
}

// capabilities returns non-empty string with available capabilities based on connection state.
// For use in cmdCapability and untagged OK responses on connection start, login and authenticate.
func (c *conn) capabilities() string {
	caps := serverCapabilities
	// ../rfc/9051:1238
	// We only allow starting without TLS when explicitly configured, in violation of RFC.
	if !c.tls && c.baseTLSConfig != nil {
		caps += " STARTTLS"
	}
	if c.tls || c.noRequireSTARTTLS {
		caps += " AUTH=PLAIN"
	} else {
		caps += " LOGINDISABLED"
	}
	if c.tls && len(c.conn.(*tls.Conn).ConnectionState().PeerCertificates) > 0 && !c.viaHTTPS {
		caps += " AUTH=EXTERNAL"
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
	c.xbwritelinef("* BYE thanks")
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
	var values []string
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
			values = append(values, fmt.Sprintf("%s=%q", k, v))
		}
	} else {
		p.xnil()
	}
	p.xempty()

	c.userAgent = strings.Join(values, " ")

	// The ID command is typically sent soon after authentication. So we've prepared
	// the LoginAttempt and write it now.
	if c.loginAttempt != nil {
		c.loginAttempt.UserAgent = c.userAgent
		store.LoginAttemptAdd(context.Background(), c.logbg(), *c.loginAttempt)
		c.loginAttempt = nil
		c.loginAttemptTime = time.Time{}
	}

	// We just log the client id.
	c.log.Info("client id", slog.Any("params", params))

	// Response syntax: ../rfc/2971:243
	// We send our name, and only the version for authenticated users. ../rfc/2971:193
	if c.state == stateAuthenticated || c.state == stateSelected {
		c.xbwritelinef(`* ID ("name" "mox" "version" %s)`, string0(moxvar.Version).pack(c))
	} else {
		c.xbwritelinef(`* ID ("name" "mox")`)
	}
	c.ok(tag, cmd)
}

// Compress enables compression on the connection. Deflate is the only algorithm
// specified. TLS doesn't do compression nowadays, so we don't have to check for that.
//
// Status: Authenticated. The RFC doesn't mention this in prose, but the command is
// added to ABNF production rule "command-auth".
func (c *conn) cmdCompress(tag, cmd string, p *parser) {
	// Command: ../rfc/4978:122

	// Request syntax: ../rfc/4978:310
	p.xspace()
	alg := p.xatom()
	p.xempty()

	// Will do compression only once.
	if c.compress {
		// ../rfc/4978:143
		xusercodeErrorf("COMPRESSIONACTIVE", "compression already active with previous compress command")
	}
	// ../rfc/4978:134
	if !strings.EqualFold(alg, "deflate") {
		xuserErrorf("compression algorithm not supported")
	}

	// We must flush now, before we initialize flate.
	c.log.Debug("compression enabled")
	c.ok(tag, cmd)

	c.xflateBW = bufio.NewWriter(c)
	fw0, err := flate.NewWriter(c.xflateBW, flate.DefaultCompression)
	xcheckf(err, "deflate") // Cannot happen.
	xfw := moxio.NewFlateWriter(fw0)

	c.compress = true
	c.xflateWriter = xfw
	c.xtw = moxio.NewTraceWriter(c.log, "S: ", c.xflateWriter)
	c.xbw = bufio.NewWriter(c.xtw) // The previous c.xbw will not have buffered data.

	rc := xprefixConn(c.conn, c.br) // c.br may contain buffered data.
	// We use the special partial reader. Some clients write commands and flush the
	// buffer in "partial flush" mode instead of "sync flush" mode. The "sync flush"
	// mode emits an explicit zero-length data block that triggers the Go stdlib flate
	// reader to return data to us. It wouldn't for blocks written in "partial flush"
	// mode, and it would block us indefinitely while trying to read another flate
	// block. The partial reader returns data earlier, but still eagerly consumes all
	// blocks in its buffer.
	// todo: also _write_ in partial mode since it uses fewer bytes than a sync flush (which needs an additional 4 bytes for the zero-length data block). we need a writer that can flush in partial mode first. writing with sync flush will work with clients that themselves write with partial flush.
	fr := flate.NewReaderPartial(rc)
	c.tr = moxio.NewTraceReader(c.log, "C: ", fr)
	c.br = bufio.NewReader(c.tr)
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
	if c.baseTLSConfig == nil {
		xsyntaxErrorf("starttls not announced")
	}

	conn := xprefixConn(c.conn, c.br)
	// We add the cid to facilitate debugging in case of TLS connection failure.
	c.ok(tag, cmd+" ("+mox.ReceivedID(c.cid)+")")

	c.xtlsHandshakeAndAuthenticate(conn)
	c.tls = true

	// We are not sending unsolicited CAPABILITIES for newly available authentication
	// mechanisms, clients can't depend on us sending it and should ask it themselves.
	// ../rfc/9051:1382
}

// Authenticate using SASL. Supports multiple back and forths between client and
// server to finish authentication, unlike LOGIN which is just a single
// username/password.
//
// We may already have ambient TLS credentials that have not been activated.
//
// Status: Not authenticated.
func (c *conn) cmdAuthenticate(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1403 ../rfc/3501:1519
	// Examples: ../rfc/9051:1520 ../rfc/3501:1631

	// For many failed auth attempts, slow down verification attempts.
	if c.authFailed > 3 && authFailDelay > 0 {
		mox.Sleep(mox.Context, time.Duration(c.authFailed-3)*authFailDelay)
	}

	// If authentication fails due to missing derived secrets, we don't hold it against
	// the connection. There is no way to indicate server support for an authentication
	// mechanism, but that a mechanism won't work for an account.
	var missingDerivedSecrets bool

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

	c.newLoginAttempt(true, "")
	defer func() {
		if c.loginAttempt.Result == store.AuthSuccess {
			mox.LimiterFailedAuth.Reset(c.remoteIP, time.Now())
		} else if !missingDerivedSecrets {
			mox.LimiterFailedAuth.Add(c.remoteIP, time.Now(), 1)
		}
	}()

	// Request syntax: ../rfc/9051:6341 ../rfc/3501:4561
	p.xspace()
	authType := p.xatom()

	xreadInitial := func() []byte {
		var line string
		if p.empty() {
			c.xwritelinef("+ ")
			line = c.xreadline(false)
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
			c.loginAttempt.Result = store.AuthAborted
			xsyntaxErrorf("authenticate aborted by client")
		}
		buf, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			xsyntaxErrorf("parsing base64: %v", err)
		}
		return buf
	}

	xreadContinuation := func() []byte {
		line := c.xreadline(false)
		if line == "*" {
			c.loginAttempt.Result = store.AuthAborted
			xsyntaxErrorf("authenticate aborted by client")
		}
		buf, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			xsyntaxErrorf("parsing base64: %v", err)
		}
		return buf
	}

	// The various authentication mechanisms set account and username. We may already
	// have an account and username from TLS client authentication. Afterwards, we
	// check that the account is the same.
	var account *store.Account
	var username string
	defer func() {
		if account != nil {
			err := account.Close()
			c.xsanity(err, "close account")
		}
	}()

	switch strings.ToUpper(authType) {
	case "PLAIN":
		c.loginAttempt.AuthMech = "plain"

		if !c.noRequireSTARTTLS && !c.tls {
			// ../rfc/9051:5194
			xusercodeErrorf("PRIVACYREQUIRED", "tls required for login")
		}

		// Plain text passwords, mark as traceauth.
		defer c.xtraceread(mlog.LevelTraceauth)()
		buf := xreadInitial()
		c.xtraceread(mlog.LevelTrace) // Restore.
		plain := bytes.Split(buf, []byte{0})
		if len(plain) != 3 {
			xsyntaxErrorf("bad plain auth data, expected 3 nul-separated tokens, got %d tokens", len(plain))
		}
		authz := norm.NFC.String(string(plain[0]))
		username = norm.NFC.String(string(plain[1]))
		password := string(plain[2])
		c.loginAttempt.LoginAddress = username

		if authz != "" && authz != username {
			xusercodeErrorf("AUTHORIZATIONFAILED", "cannot assume role")
		}

		var err error
		account, c.loginAttempt.AccountName, err = store.OpenEmailAuth(c.log, username, password, false)
		if err != nil {
			if errors.Is(err, store.ErrUnknownCredentials) {
				c.loginAttempt.Result = store.AuthBadCredentials
				c.log.Info("authentication failed", slog.String("username", username))
				xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
			}
			xusercodeErrorf("", "error")
		}

	case "CRAM-MD5":
		c.loginAttempt.AuthMech = strings.ToLower(authType)

		// ../rfc/9051:1462
		p.xempty()

		// ../rfc/2195:82
		chal := fmt.Sprintf("<%d.%d@%s>", uint64(mox.CryptoRandInt()), time.Now().UnixNano(), mox.Conf.Static.HostnameDomain.ASCII)
		c.xwritelinef("+ %s", base64.StdEncoding.EncodeToString([]byte(chal)))

		resp := xreadContinuation()
		t := strings.Split(string(resp), " ")
		if len(t) != 2 || len(t[1]) != 2*md5.Size {
			xsyntaxErrorf("malformed cram-md5 response")
		}
		username = norm.NFC.String(t[0])
		c.loginAttempt.LoginAddress = username
		c.log.Debug("cram-md5 auth", slog.String("address", username))
		var err error
		account, c.loginAttempt.AccountName, _, err = store.OpenEmail(c.log, username, false)
		if err != nil {
			if errors.Is(err, store.ErrUnknownCredentials) {
				c.loginAttempt.Result = store.AuthBadCredentials
				c.log.Info("failed authentication attempt", slog.String("username", username), slog.Any("remote", c.remoteIP))
				xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
			}
			xserverErrorf("looking up address: %v", err)
		}
		var ipadhash, opadhash hash.Hash
		account.WithRLock(func() {
			err := account.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
				password, err := bstore.QueryTx[store.Password](tx).Get()
				if err == bstore.ErrAbsent {
					c.log.Info("failed authentication attempt", slog.String("username", username), slog.Any("remote", c.remoteIP))
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
			c.log.Info("cram-md5 auth attempt without derived secrets set, save password again to store secrets", slog.String("username", username))
			c.log.Info("failed authentication attempt", slog.String("username", username), slog.Any("remote", c.remoteIP))
			missingDerivedSecrets = true
			xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
		}

		// ../rfc/2195:138 ../rfc/2104:142
		ipadhash.Write([]byte(chal))
		opadhash.Write(ipadhash.Sum(nil))
		digest := fmt.Sprintf("%x", opadhash.Sum(nil))
		if digest != t[1] {
			c.log.Info("failed authentication attempt", slog.String("username", username), slog.Any("remote", c.remoteIP))
			xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
		}

	case "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1":
		// todo: improve handling of errors during scram. e.g. invalid parameters. should we abort the imap command, or continue until the end and respond with a scram-level error?
		// todo: use single implementation between ../imapserver/server.go and ../smtpserver/server.go

		// No plaintext credentials, we can log these normally.

		c.loginAttempt.AuthMech = strings.ToLower(authType)
		var h func() hash.Hash
		switch c.loginAttempt.AuthMech {
		case "scram-sha-1", "scram-sha-1-plus":
			h = sha1.New
		case "scram-sha-256", "scram-sha-256-plus":
			h = sha256.New
		default:
			xserverErrorf("missing case for scram variant")
		}

		var cs *tls.ConnectionState
		requireChannelBinding := strings.HasSuffix(c.loginAttempt.AuthMech, "-plus")
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
			c.log.Infox("scram protocol error", err, slog.Any("remote", c.remoteIP))
			xuserErrorf("scram protocol error: %s", err)
		}
		username = ss.Authentication
		c.loginAttempt.LoginAddress = username
		c.log.Debug("scram auth", slog.String("authentication", username))
		// We check for login being disabled when finishing.
		account, c.loginAttempt.AccountName, _, err = store.OpenEmail(c.log, username, false)
		if err != nil {
			// todo: we could continue scram with a generated salt, deterministically generated
			// from the username. that way we don't have to store anything but attackers cannot
			// learn if an account exists. same for absent scram saltedpassword below.
			xuserErrorf("scram not possible")
		}
		if ss.Authorization != "" && ss.Authorization != username {
			xuserErrorf("authentication with authorization for different user not supported")
		}
		var xscram store.SCRAM
		account.WithRLock(func() {
			err := account.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
				password, err := bstore.QueryTx[store.Password](tx).Get()
				if err == bstore.ErrAbsent {
					c.log.Info("failed authentication attempt", slog.String("username", username), slog.Any("remote", c.remoteIP))
					xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
				}
				xcheckf(err, "fetching credentials")
				switch c.loginAttempt.AuthMech {
				case "scram-sha-1", "scram-sha-1-plus":
					xscram = password.SCRAMSHA1
				case "scram-sha-256", "scram-sha-256-plus":
					xscram = password.SCRAMSHA256
				default:
					xserverErrorf("missing case for scram credentials")
				}
				if len(xscram.Salt) == 0 || xscram.Iterations == 0 || len(xscram.SaltedPassword) == 0 {
					missingDerivedSecrets = true
					c.log.Info("scram auth attempt without derived secrets set, save password again to store secrets", slog.String("username", username))
					xuserErrorf("scram not possible")
				}
				return nil
			})
			xcheckf(err, "read tx")
		})
		s1, err := ss.ServerFirst(xscram.Iterations, xscram.Salt)
		xcheckf(err, "scram first server step")
		c.xwritelinef("+ %s", base64.StdEncoding.EncodeToString([]byte(s1)))
		c2 := xreadContinuation()
		s3, err := ss.Finish(c2, xscram.SaltedPassword)
		if len(s3) > 0 {
			c.xwritelinef("+ %s", base64.StdEncoding.EncodeToString([]byte(s3)))
		}
		if err != nil {
			c.xreadline(false) // Should be "*" for cancellation.
			if errors.Is(err, scram.ErrInvalidProof) {
				c.loginAttempt.Result = store.AuthBadCredentials
				c.log.Info("failed authentication attempt", slog.String("username", username), slog.Any("remote", c.remoteIP))
				xusercodeErrorf("AUTHENTICATIONFAILED", "bad credentials")
			} else if errors.Is(err, scram.ErrChannelBindingsDontMatch) {
				c.loginAttempt.Result = store.AuthBadChannelBinding
				c.log.Warn("bad channel binding during authentication, potential mitm", slog.String("username", username), slog.Any("remote", c.remoteIP))
				xusercodeErrorf("AUTHENTICATIONFAILED", "channel bindings do not match, potential mitm")
			} else if errors.Is(err, scram.ErrInvalidEncoding) {
				c.loginAttempt.Result = store.AuthBadProtocol
				c.log.Infox("bad scram protocol message", err, slog.String("username", username), slog.Any("remote", c.remoteIP))
				xuserErrorf("bad scram protocol message: %s", err)
			}
			xuserErrorf("server final: %w", err)
		}

		// Client must still respond, but there is nothing to say. See ../rfc/9051:6221
		// The message should be empty. todo: should we require it is empty?
		xreadContinuation()

	case "EXTERNAL":
		c.loginAttempt.AuthMech = "external"

		// ../rfc/4422:1618
		buf := xreadInitial()
		username = norm.NFC.String(string(buf))
		c.loginAttempt.LoginAddress = username

		if !c.tls {
			xusercodeErrorf("AUTHENTICATIONFAILED", "tls required for tls client certificate authentication")
		}
		if c.account == nil {
			xusercodeErrorf("AUTHENTICATIONFAILED", "missing client certificate, required for tls client certificate authentication")
		}

		if username == "" {
			username = c.username
			c.loginAttempt.LoginAddress = username
		}
		var err error
		account, c.loginAttempt.AccountName, _, err = store.OpenEmail(c.log, username, false)
		xcheckf(err, "looking up username from tls client authentication")

	default:
		c.loginAttempt.AuthMech = "(unrecognized)"
		xuserErrorf("method not supported")
	}

	if accConf, ok := account.Conf(); !ok {
		xserverErrorf("cannot get account config")
	} else if accConf.LoginDisabled != "" {
		c.loginAttempt.Result = store.AuthLoginDisabled
		c.log.Info("account login disabled", slog.String("username", username))
		// No AUTHENTICATIONFAILED code, clients could prompt users for different password.
		xuserErrorf("%w: %s", store.ErrLoginDisabled, accConf.LoginDisabled)
	}

	// We may already have TLS credentials. They won't have been enabled, or we could
	// get here due to the state machine that doesn't allow authentication while being
	// authenticated. But allow another SASL authentication, but it has to be for the
	// same account. It can be for a different username (email address) of the account.
	if c.account != nil {
		if account != c.account {
			c.log.Debug("sasl authentication for different account than tls client authentication, aborting connection",
				slog.String("saslmechanism", c.loginAttempt.AuthMech),
				slog.String("saslaccount", account.Name),
				slog.String("tlsaccount", c.account.Name),
				slog.String("saslusername", username),
				slog.String("tlsusername", c.username),
			)
			xusercodeErrorf("AUTHENTICATIONFAILED", "authentication failed, tls client certificate public key belongs to another account")
		} else if username != c.username {
			c.log.Debug("sasl authentication for different username than tls client certificate authentication, switching to sasl username",
				slog.String("saslmechanism", c.loginAttempt.AuthMech),
				slog.String("saslusername", username),
				slog.String("tlsusername", c.username),
				slog.String("account", c.account.Name),
			)
		}
	} else {
		c.account = account
		account = nil // Prevent cleanup.
	}
	c.username = username
	if c.comm == nil {
		c.comm = store.RegisterComm(c.account)
	}

	c.setSlow(false)
	c.loginAttempt.AccountName = c.account.Name
	c.loginAttempt.LoginAddress = c.username
	c.loginAttempt.Result = store.AuthSuccess
	c.authFailed = 0
	c.state = stateAuthenticated
	c.xwriteresultf("%s OK [CAPABILITY %s] authenticate done", tag, c.capabilities())
}

// Login logs in with username and password.
//
// Status: Not authenticated.
func (c *conn) cmdLogin(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:1597 ../rfc/3501:1663

	c.newLoginAttempt(true, "login")
	defer func() {
		if c.loginAttempt.Result == store.AuthSuccess {
			mox.LimiterFailedAuth.Reset(c.remoteIP, time.Now())
		} else {
			mox.LimiterFailedAuth.Add(c.remoteIP, time.Now(), 1)
		}
	}()

	// todo: get this line logged with traceauth. the plaintext password is included on the command line, which we've already read (before dispatching to this function).

	// Request syntax: ../rfc/9051:6667 ../rfc/3501:4804
	p.xspace()
	username := norm.NFC.String(p.xastring())
	c.loginAttempt.LoginAddress = username
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

	account, accName, err := store.OpenEmailAuth(c.log, username, password, true)
	c.loginAttempt.AccountName = accName
	if err != nil {
		var code string
		if errors.Is(err, store.ErrUnknownCredentials) {
			c.loginAttempt.Result = store.AuthBadCredentials
			code = "AUTHENTICATIONFAILED"
			c.log.Info("failed authentication attempt", slog.String("username", username), slog.Any("remote", c.remoteIP))
		} else if errors.Is(err, store.ErrLoginDisabled) {
			c.loginAttempt.Result = store.AuthLoginDisabled
			c.log.Info("account login disabled", slog.String("username", username))
			// There is no specific code for "account disabled" in IMAP. AUTHORIZATIONFAILED is
			// not a good idea, it will prompt users for a password. ALERT seems reasonable,
			// but may cause email clients to suppress the message since we are not yet
			// authenticated. So we don't send anything. ../rfc/9051:4940
			xuserErrorf("%s", err)
		}
		xusercodeErrorf(code, "login failed")
	}
	defer func() {
		if account != nil {
			err := account.Close()
			c.xsanity(err, "close account")
		}
	}()

	// We may already have TLS credentials. They won't have been enabled, or we could
	// get here due to the state machine that doesn't allow authentication while being
	// authenticated. But allow another SASL authentication, but it has to be for the
	// same account. It can be for a different username (email address) of the account.
	if c.account != nil {
		if account != c.account {
			c.log.Debug("sasl authentication for different account than tls client authentication, aborting connection",
				slog.String("saslmechanism", "login"),
				slog.String("saslaccount", account.Name),
				slog.String("tlsaccount", c.account.Name),
				slog.String("saslusername", username),
				slog.String("tlsusername", c.username),
			)
			xusercodeErrorf("AUTHENTICATIONFAILED", "authentication failed, tls client certificate public key belongs to another account")
		} else if username != c.username {
			c.log.Debug("sasl authentication for different username than tls client certificate authentication, switching to sasl username",
				slog.String("saslmechanism", "login"),
				slog.String("saslusername", username),
				slog.String("tlsusername", c.username),
				slog.String("account", c.account.Name),
			)
		}
	} else {
		c.account = account
		account = nil // Prevent cleanup.
	}
	c.username = username
	if c.comm == nil {
		c.comm = store.RegisterComm(c.account)
	}
	c.loginAttempt.LoginAddress = c.username
	c.loginAttempt.AccountName = c.account.Name
	c.loginAttempt.Result = store.AuthSuccess
	c.authFailed = 0
	c.setSlow(false)
	c.state = stateAuthenticated
	c.xwriteresultf("%s OK [CAPABILITY %s] login done", tag, c.capabilities())
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
		case capMetadata:
			c.enabled[cap] = true
			enabled += " " + s
		case capUIDOnly:
			c.enabled[cap] = true
			enabled += " " + s
			c.uidonly = true
			c.uids = nil
		}
	}
	// QRESYNC enabled CONDSTORE too ../rfc/7162:1391
	if qresync && !c.enabled[capCondstore] {
		c.xensureCondstore(nil)
		enabled += " CONDSTORE"
	}

	// Response syntax: ../rfc/9051:6520 ../rfc/5161:211
	c.xbwritelinef("* ENABLED%s", enabled)
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

		var mb store.Mailbox
		if tx == nil {
			c.xdbread(func(tx *bstore.Tx) {
				mb = c.xmailboxID(tx, c.mailboxID)
			})
		} else {
			mb = c.xmailboxID(tx, c.mailboxID)
		}
		c.xbwritelinef("* OK [HIGHESTMODSEQ %d] after condstore-enabling command", mb.ModSeq.Client())
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
		c.xbwritelinef("* OK [CLOSED] x")
		c.unselect()
	}

	if c.uidonly && qrknownSeqSet != nil {
		// ../rfc/9586:255
		xsyntaxCodeErrorf("UIDREQUIRED", "cannot use message sequence match data with uidonly enabled")
	}

	name = xcheckmailboxname(name, true)

	var mb store.Mailbox
	c.account.WithRLock(func() {
		c.xdbread(func(tx *bstore.Tx) {
			mb = c.xmailbox(tx, name, "")

			var firstUnseen msgseq = 0

			c.uidnext = mb.UIDNext
			if c.uidonly {
				c.exists = uint32(mb.MailboxCounts.Total + mb.MailboxCounts.Deleted)
			} else {
				c.uids = []store.UID{}

				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: mb.ID})
				q.FilterEqual("Expunged", false)
				q.SortAsc("UID")
				err := q.ForEach(func(m store.Message) error {
					c.uids = append(c.uids, m.UID)
					if firstUnseen == 0 && !m.Seen {
						firstUnseen = msgseq(len(c.uids))
					}
					return nil
				})
				xcheckf(err, "fetching uids")

				c.exists = uint32(len(c.uids))
			}

			var flags string
			if len(mb.Keywords) > 0 {
				flags = " " + strings.Join(mb.Keywords, " ")
			}
			c.xbwritelinef(`* FLAGS (\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent%s)`, flags)
			c.xbwritelinef(`* OK [PERMANENTFLAGS (\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent \*)] x`)
			if !c.enabled[capIMAP4rev2] {
				c.xbwritelinef(`* 0 RECENT`)
			}
			c.xbwritelinef(`* %d EXISTS`, c.exists)
			if !c.enabled[capIMAP4rev2] && firstUnseen > 0 {
				// ../rfc/9051:8051 ../rfc/3501:1774
				c.xbwritelinef(`* OK [UNSEEN %d] x`, firstUnseen)
			}
			c.xbwritelinef(`* OK [UIDVALIDITY %d] x`, mb.UIDValidity)
			c.xbwritelinef(`* OK [UIDNEXT %d] x`, mb.UIDNext)
			c.xbwritelinef(`* LIST () "/" %s`, mailboxt(mb.Name).pack(c))
			if c.enabled[capCondstore] {
				// ../rfc/7162:417
				// ../rfc/7162-eid5055 ../rfc/7162:484 ../rfc/7162:1167
				c.xbwritelinef(`* OK [HIGHESTMODSEQ %d] x`, mb.ModSeq.Client())
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
						// Access to c.uids is safe, qrknownSeqSet and uidonly cannot both be set.
						if i < 0 || i >= int(c.exists) || c.uids[i] != store.UID(uid) {
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
							c.xbwritelinef("* OK [ALERT] Synchronization inconsistency in client detected. Client tried to sync with a UID that was removed at or after the MODSEQ it sent in the request. Sending all historic message removals for selected mailbox. Full synchronization recommended.")
						}
					} else if err != bstore.ErrAbsent {
						xcheckf(err, "checking old client uid")
					}
				}

				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: mb.ID})
				// Note: we don't filter by Expunged.
				q.FilterGreater("ModSeq", store.ModSeqFromClient(qrmodseq))
				q.FilterLessEqual("ModSeq", mb.ModSeq)
				q.FilterLess("UID", c.uidnext)
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
					// UIDFETCH in case of uidonly. ../rfc/9586:228
					if c.uidonly {
						c.xbwritelinef("* %d UIDFETCH (FLAGS %s MODSEQ (%d))", m.UID, flaglist(m.Flags, m.Keywords).pack(c), m.ModSeq.Client())
					} else if msgseq := c.sequence(m.UID); msgseq > 0 {
						c.xbwritelinef("* %d FETCH (UID %d FLAGS %s MODSEQ (%d))", msgseq, m.UID, flaglist(m.Flags, m.Keywords).pack(c), m.ModSeq.Client())
					}
					return nil
				})
				xcheckf(err, "listing changed messages")

				highDeletedModSeq, err := c.account.HighestDeletedModSeq(tx)
				xcheckf(err, "getting highest deleted modseq")

				// If we don't have enough history, we go through all UIDs and look them up, and
				// add them to the vanished list if they have disappeared.
				if qrmodseq < highDeletedModSeq.Client() {
					// If no "known uid set" was in the request, we substitute 1:max or the empty set.
					// ../rfc/7162:1524
					if qrknownUIDs == nil {
						qrknownUIDs = &numSet{ranges: []numRange{{first: setNumber{number: 1}, last: &setNumber{number: uint32(c.uidnext - 1)}}}}
					}

					if c.uidonly {
						// note: qrknownUIDs will not contain "*".
						for _, r := range qrknownUIDs.xinterpretStar(func() store.UID { return 0 }).ranges {
							// Gather UIDs for this range.
							var uids []store.UID
							q := bstore.QueryTx[store.Message](tx)
							q.FilterNonzero(store.Message{MailboxID: mb.ID})
							q.FilterEqual("Expunged", false)
							if r.last == nil {
								q.FilterEqual("UID", r.first.number)
							} else {
								q.FilterGreaterEqual("UID", r.first.number)
								q.FilterLessEqual("UID", r.last.number)
							}
							q.SortAsc("UID")
							for m, err := range q.All() {
								xcheckf(err, "enumerating uids")
								uids = append(uids, m.UID)
							}

							// Find UIDs missing from the database.
							iter := r.newIter()
							for {
								uid, ok := iter.Next()
								if !ok {
									break
								}
								if uidSearch(uids, store.UID(uid)) <= 0 {
									vanishedUIDs[store.UID(uid)] = struct{}{}
								}
							}
						}
					} else {
						// Ensure it is in ascending order, no needless first/last ranges. qrknownUIDs cannot contain a star.
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
				}

				// Now that we have all vanished UIDs, send them over compactly.
				if len(vanishedUIDs) > 0 {
					l := slices.Sorted(maps.Keys(vanishedUIDs))
					// ../rfc/7162:1985
					for _, s := range compactUIDSet(l).Strings(4*1024 - 32) {
						c.xbwritelinef("* VANISHED (EARLIER) %s", s)
					}
				}
			}
		})
	})

	if isselect {
		c.xbwriteresultf("%s OK [READ-WRITE] x", tag)
		c.readonly = false
	} else {
		c.xbwriteresultf("%s OK [READ-ONLY] x", tag)
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
	// Optional parameters. ../rfc/4466:501 ../rfc/4466:511
	var useAttrs []string // Special-use attributes without leading \.
	if p.space() {
		p.xtake("(")
		// We only support "USE", and there don't appear to be more types of parameters.
		for {
			p.xtake("USE (")
			for {
				p.xtake(`\`)
				useAttrs = append(useAttrs, p.xatom())
				if !p.space() {
					break
				}
			}
			p.xtake(")")
			if !p.space() {
				break
			}
		}
		p.xtake(")")
	}
	p.xempty()

	origName := name
	name = strings.TrimRight(name, "/") // ../rfc/9051:1930
	name = xcheckmailboxname(name, false)

	var specialUse store.SpecialUse
	specialUseBools := map[string]*bool{
		"archive": &specialUse.Archive,
		"drafts":  &specialUse.Draft,
		"junk":    &specialUse.Junk,
		"sent":    &specialUse.Sent,
		"trash":   &specialUse.Trash,
	}
	for _, s := range useAttrs {
		p, ok := specialUseBools[strings.ToLower(s)]
		if !ok {
			// ../rfc/6154:287
			xusercodeErrorf("USEATTR", `cannot create mailbox with special-use attribute \%s`, s)
		}
		*p = true
	}

	var changes []store.Change
	var created []string // Created mailbox names.

	c.account.WithWLock(func() {
		c.xdbwrite(func(tx *bstore.Tx) {
			var exists bool
			var err error
			_, changes, created, exists, err = c.account.MailboxCreate(tx, name, specialUse)
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
			oldname = fmt.Sprintf(` ("OLDNAME" (%s))`, mailboxt(origName).pack(c))
		}
		c.xbwritelinef(`* LIST (\Subscribed) "/" %s%s`, mailboxt(n).pack(c), oldname)
	}
	c.ok(tag, cmd)
}

// Delete removes a mailbox and all its messages and annotations.
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

	c.account.WithWLock(func() {
		var mb store.Mailbox
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			mb = c.xmailbox(tx, name, "NONEXISTENT")

			var hasChildren bool
			var err error
			changes, hasChildren, err = c.account.MailboxDelete(context.TODO(), c.log, tx, &mb)
			if hasChildren {
				xusercodeErrorf("HASCHILDREN", "mailbox has a child, only leaf mailboxes can be deleted")
			}
			xcheckf(err, "deleting mailbox")
		})

		c.broadcast(changes)
	})

	c.ok(tag, cmd)
}

// Rename changes the name of a mailbox.
// Renaming INBOX is special, it moves the inbox messages to a new mailbox, leaving
// inbox empty, but copying metadata annotations.
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

	var cleanupIDs []int64
	defer func() {
		for _, id := range cleanupIDs {
			p := c.account.MessagePath(id)
			err := os.Remove(p)
			c.xsanity(err, "cleaning up message")
		}
	}()

	c.account.WithWLock(func() {
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			mbSrc := c.xmailbox(tx, src, "NONEXISTENT")

			// Handle common/simple case first.
			if src != "Inbox" {
				var modseq store.ModSeq
				var alreadyExists bool
				var err error
				changes, _, alreadyExists, err = c.account.MailboxRename(tx, &mbSrc, dst, &modseq)
				if alreadyExists {
					xusercodeErrorf("ALREADYEXISTS", "%s", err)
				}
				xcheckf(err, "renaming mailbox")
				return
			}

			// Inbox is very special. Unlike other mailboxes, its children are not moved. And
			// unlike a regular move, its messages are moved to a newly created mailbox. We do
			// indeed create a new destination mailbox and actually move the messages.
			// ../rfc/9051:2101
			exists, err := c.account.MailboxExists(tx, dst)
			xcheckf(err, "checking if destination mailbox exists")
			if exists {
				xusercodeErrorf("ALREADYEXISTS", "destination mailbox %q already exists", dst)
			}
			if dst == src {
				xuserErrorf("cannot move inbox to itself")
			}

			var modseq store.ModSeq
			mbDst, chl, err := c.account.MailboxEnsure(tx, dst, false, store.SpecialUse{}, &modseq)
			xcheckf(err, "creating destination mailbox")
			changes = chl

			// Copy mailbox annotations. ../rfc/5464:368
			qa := bstore.QueryTx[store.Annotation](tx)
			qa.FilterNonzero(store.Annotation{MailboxID: mbSrc.ID})
			qa.FilterEqual("Expunged", false)
			annotations, err := qa.List()
			xcheckf(err, "get annotations to copy for inbox")
			for _, a := range annotations {
				a.ID = 0
				a.MailboxID = mbDst.ID
				a.ModSeq = modseq
				a.CreateSeq = modseq
				err := tx.Insert(&a)
				xcheckf(err, "copy annotation to destination mailbox")
				changes = append(changes, a.Change(mbDst.Name))
			}
			c.xcheckMetadataSize(tx)

			// Build query that selects messages to move.
			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: mbSrc.ID})
			q.FilterEqual("Expunged", false)
			q.SortAsc("UID")

			newIDs, chl := c.xmoveMessages(tx, q, 0, modseq, &mbSrc, &mbDst)
			changes = append(changes, chl...)
			cleanupIDs = newIDs
		})

		cleanupIDs = nil

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
		var changes []store.Change

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

			var flags []string
			exists, err := c.account.MailboxExists(tx, name)
			xcheckf(err, "looking up mailbox existence")
			if !exists {
				flags = []string{`\NonExistent`}
			}

			changes = []store.Change{store.ChangeRemoveSubscription{MailboxName: name, ListFlags: flags}}
		})

		c.broadcast(changes)

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
				for p := mox.ParentMailboxName(name); p != ""; p = mox.ParentMailboxName(p) {
					subscribedKids[p] = true
				}
			}
			if !re.MatchString(name) {
				continue
			}
			have[name] = true
			line := fmt.Sprintf(`* LSUB () "/" %s`, mailboxt(name).pack(c))
			lines = append(lines, line)

		}

		// ../rfc/3501:2394
		if !ispercent {
			return
		}
		qmb := bstore.QueryTx[store.Mailbox](tx)
		qmb.FilterEqual("Expunged", false)
		qmb.SortAsc("Name")
		err = qmb.ForEach(func(mb store.Mailbox) error {
			if have[mb.Name] || !subscribedKids[mb.Name] || !re.MatchString(mb.Name) {
				return nil
			}
			line := fmt.Sprintf(`* LSUB (\NoSelect) "/" %s`, mailboxt(mb.Name).pack(c))
			lines = append(lines, line)
			return nil
		})
		xcheckf(err, "querying mailboxes")
	})

	// Response syntax: ../rfc/3501:4833 ../rfc/3501:4837
	for _, line := range lines {
		c.xbwritelinef("%s", line)
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
	c.xbwritelinef(`* NAMESPACE (("" "/")) NIL NIL`)
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

	c.xbwritelinef("%s", responseLine)
	c.ok(tag, cmd)
}

// Response syntax: ../rfc/9051:6681 ../rfc/9051:7070 ../rfc/9051:7059 ../rfc/3501:4834 ../rfc/9208:712
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
			status = append(status, A, fmt.Sprintf("%d", mb.ModSeq.Client()))
		case "DELETED-STORAGE":
			// ../rfc/9208:394
			// How much storage space could be reclaimed by expunging messages with the
			// \Deleted flag. We could keep track of this number and return it efficiently.
			// Calculating it each time can be slow, and we don't know if clients request it.
			// Clients are not likely to set the deleted flag without immediately expunging
			// nowadays. Let's wait for something to need it to go through the trouble, and
			// always return 0 for now.
			status = append(status, A, "0")
		default:
			xsyntaxErrorf("unknown attribute %q", a)
		}
	}
	return fmt.Sprintf("* STATUS %s (%s)", mailboxt(mb.Name).pack(c), strings.Join(status, " "))
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
// The MULTIAPPEND extension is implemented, allowing multiple flags/datetime/data
// sets.
//
// State: Authenticated and selected.
func (c *conn) cmdAppend(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3406 ../rfc/6855:204 ../rfc/4466:427 ../rfc/3501:2527 ../rfc/3502:95
	// Examples: ../rfc/9051:3482 ../rfc/3501:2589 ../rfc/3502:175

	// A message that we've (partially) read from the client, and will be delivering to
	// the mailbox once we have them all. ../rfc/3502:49
	type appendMsg struct {
		storeFlags store.Flags
		keywords   []string
		time       time.Time

		file *os.File // Message file we are appending. Can be nil if we are writing to a nopWriteCloser due to being over quota.

		mw *message.Writer
		m  store.Message // New message. Delivered file for m.ID is removed on error.
	}

	var appends []*appendMsg
	var commit bool
	defer func() {
		for _, a := range appends {
			if !commit && a.m.ID != 0 {
				p := c.account.MessagePath(a.m.ID)
				err := os.Remove(p)
				c.xsanity(err, "cleaning up temporary append file after error")
			}
		}
	}()

	// Request syntax: ../rfc/9051:6325 ../rfc/6855:219 ../rfc/3501:4547 ../rfc/3502:218
	p.xspace()
	name := p.xmailbox()
	p.xspace()

	// Check how much quota space is available. We'll keep track of remaining quota as
	// we accept multiple messages.
	quotaMsgMax := c.account.QuotaMessageSize()
	quotaUnlimited := quotaMsgMax == 0
	var quotaAvail int64
	var totalSize int64
	if !quotaUnlimited {
		c.account.WithRLock(func() {
			c.xdbread(func(tx *bstore.Tx) {
				du := store.DiskUsage{ID: 1}
				err := tx.Get(&du)
				xcheckf(err, "get quota disk usage")
				quotaAvail = quotaMsgMax - du.MessageSize
			})
		})
	}

	var overQuota bool // For response code.
	var cancel bool    // In case we've seen zero-sized message append.

	for {
		// Append msg early, for potential cleanup.
		var a appendMsg
		appends = append(appends, &a)

		if p.hasPrefix("(") {
			// Error must be a syntax error, to properly abort the connection due to literal.
			var err error
			a.storeFlags, a.keywords, err = store.ParseFlagsKeywords(p.xflagList())
			if err != nil {
				xsyntaxErrorf("parsing flags: %v", err)
			}
			p.xspace()
		}
		if p.hasPrefix(`"`) {
			a.time = p.xdateTime()
			p.xspace()
		} else {
			a.time = time.Now()
		}
		// todo: only with utf8 should we we accept message headers with utf-8. we currently always accept them.
		// todo: this is only relevant if we also support the CATENATE extension?
		// ../rfc/6855:204
		utf8 := p.take("UTF8 (")
		if utf8 {
			p.xtake("~")
		}
		// Always allow literal8, for binary extension. ../rfc/4466:486
		// For utf8, we already consumed the required ~ above.
		size, synclit := p.xliteralSize(!utf8, false)

		if !quotaUnlimited && !overQuota {
			quotaAvail -= size
			overQuota = quotaAvail < 0
		}
		if size == 0 {
			cancel = true
		}

		var f io.Writer
		if synclit {
			// Check for mailbox on first iteration.
			if len(appends) <= 1 {
				name = xcheckmailboxname(name, true)
				c.xdbread(func(tx *bstore.Tx) {
					c.xmailbox(tx, name, "TRYCREATE")
				})
			}

			if overQuota {
				// ../rfc/9051:5155 ../rfc/9208:472
				xusercodeErrorf("OVERQUOTA", "account over maximum total message size %d", quotaMsgMax)
			}

			// ../rfc/3502:140
			if cancel {
				xuserErrorf("empty message, cancelling append")
			}

			// Read the message into a temporary file.
			var err error
			a.file, err = store.CreateMessageTemp(c.log, "imap-append")
			xcheckf(err, "creating temp file for message")
			defer store.CloseRemoveTempFile(c.log, a.file, "temporary message file")
			f = a.file

			c.xwritelinef("+ ")
		} else {
			// We'll discard the message and return an error as soon as we can (possible
			// synchronizing literal of next message, or after we've seen all messages).
			if overQuota || cancel {
				f = io.Discard
			} else {
				var err error
				a.file, err = store.CreateMessageTemp(c.log, "imap-append")
				xcheckf(err, "creating temp file for message")
				defer store.CloseRemoveTempFile(c.log, a.file, "temporary message file")
				f = a.file
			}
		}

		defer c.xtracewrite(mlog.LevelTracedata)()
		a.mw = message.NewWriter(f)
		msize, err := io.Copy(a.mw, io.LimitReader(c.br, size))
		c.xtracewrite(mlog.LevelTrace) // Restore.
		if err != nil {
			// Cannot use xcheckf due to %w handling of errIO.
			c.xbrokenf("reading literal message: %s (%w)", err, errIO)
		}
		if msize != size {
			c.xbrokenf("read %d bytes for message, expected %d (%w)", msize, size, errIO)
		}
		totalSize += msize

		line := c.xreadline(false)
		p = newParser(line, c)
		if utf8 {
			p.xtake(")")
		}

		// The MULTIAPPEND extension allows more appends.
		if !p.space() {
			break
		}
	}
	p.xempty()

	name = xcheckmailboxname(name, true)

	if overQuota {
		// ../rfc/9208:472
		xusercodeErrorf("OVERQUOTA", "account over maximum total message size %d", quotaMsgMax)
	}

	// ../rfc/3502:140
	if cancel {
		xuserErrorf("empty message, cancelling append")
	}

	var mb store.Mailbox
	var overflow bool
	var pendingChanges []store.Change
	defer func() {
		// In case of panic.
		c.flushChanges(pendingChanges)
	}()

	// Append all messages in a single atomic transaction. ../rfc/3502:143

	c.account.WithWLock(func() {
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			mb = c.xmailbox(tx, name, "TRYCREATE")

			nkeywords := len(mb.Keywords)

			// Check quota for all messages at once.
			ok, maxSize, err := c.account.CanAddMessageSize(tx, totalSize)
			xcheckf(err, "checking quota")
			if !ok {
				// ../rfc/9208:472
				xusercodeErrorf("OVERQUOTA", "account over maximum total message size %d", maxSize)
			}

			modseq, err := c.account.NextModSeq(tx)
			xcheckf(err, "get next mod seq")

			mb.ModSeq = modseq

			msgDirs := map[string]struct{}{}
			for _, a := range appends {
				a.m = store.Message{
					MailboxID:     mb.ID,
					MailboxOrigID: mb.ID,
					Received:      a.time,
					Flags:         a.storeFlags,
					Keywords:      a.keywords,
					Size:          a.mw.Size,
					ModSeq:        modseq,
					CreateSeq:     modseq,
				}

				// todo: do a single junk training
				err = c.account.MessageAdd(c.log, tx, &mb, &a.m, a.file, store.AddOpts{SkipDirSync: true})
				xcheckf(err, "delivering message")

				changes = append(changes, a.m.ChangeAddUID(mb))

				msgDirs[filepath.Dir(c.account.MessagePath(a.m.ID))] = struct{}{}
			}

			changes = append(changes, mb.ChangeCounts())
			if nkeywords != len(mb.Keywords) {
				changes = append(changes, mb.ChangeKeywords())
			}

			err = tx.Update(&mb)
			xcheckf(err, "updating mailbox counts")

			for dir := range msgDirs {
				err := moxio.SyncDir(c.log, dir)
				xcheckf(err, "sync dir")
			}
		})

		commit = true

		// Fetch pending changes, possibly with new UIDs, so we can apply them before adding our own new UID.
		overflow, pendingChanges = c.comm.Get()

		// Broadcast the change to other connections.
		c.broadcast(changes)
	})

	if c.mailboxID == mb.ID {
		l := pendingChanges
		pendingChanges = nil
		c.xapplyChanges(overflow, l, true)
		for _, a := range appends {
			c.uidAppend(a.m.UID)
		}
		// todo spec: with condstore/qresync, is there a mechanism to let the client know the modseq for the appended uid? in theory an untagged fetch with the modseq after the OK APPENDUID could make sense, but this probably isn't allowed.
		c.xbwritelinef("* %d EXISTS", c.exists)
	}

	// ../rfc/4315:289 ../rfc/3502:236 APPENDUID
	// ../rfc/4315:276 ../rfc/4315:310 UID, and UID set for multiappend
	var uidset string
	if len(appends) == 1 {
		uidset = fmt.Sprintf("%d", appends[0].m.UID)
	} else {
		uidset = fmt.Sprintf("%d:%d", appends[0].m.UID, appends[len(appends)-1].m.UID)
	}
	c.xwriteresultf("%s OK [APPENDUID %d %s] appended", tag, mb.UIDValidity, uidset)
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

	c.xwritelinef("+ waiting")

	// With NOTIFY enabled, flush all pending changes.
	if c.notify != nil && len(c.notify.Delayed) > 0 {
		c.xapplyChanges(false, nil, true)
		c.xflush()
	}

	var line string
Wait:
	for {
		select {
		case le := <-c.lineChan():
			c.line = nil
			if err := le.err; err != nil {
				if errors.Is(le.err, os.ErrDeadlineExceeded) {
					err := c.conn.SetDeadline(time.Now().Add(10 * time.Second))
					c.log.Check(err, "setting deadline")
					c.xwritelinef("* BYE inactive")
				}
				c.connBroken = true
				if !errors.Is(err, errIO) && !errors.Is(err, errProtocol) {
					c.xbrokenf("%s (%w)", err, errIO)
				}
				panic(err)
			}
			line = le.line
			break Wait
		case <-c.comm.Pending:
			overflow, changes := c.comm.Get()
			c.xapplyChanges(overflow, changes, true)
			c.xflush()
		case <-mox.Shutdown.Done():
			// ../rfc/9051:5375
			c.xwritelinef("* BYE shutting down")
			c.xbrokenf("shutting down (%w)", errIO)
		}
	}

	// Reset the write deadline. In case of little activity, with a command timeout of
	// 30 minutes, we have likely passed it.
	err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	c.log.Check(err, "setting write deadline")

	if strings.ToUpper(line) != "DONE" {
		// We just close the connection because our protocols are out of sync.
		c.xbrokenf("%w: in IDLE, expected DONE", errIO)
	}

	c.ok(tag, cmd)
}

// Return the quota root for a mailbox name and any current quota's.
//
// State: Authenticated and selected.
func (c *conn) cmdGetquotaroot(tag, cmd string, p *parser) {
	// Command: ../rfc/9208:278 ../rfc/2087:141

	// Request syntax: ../rfc/9208:660 ../rfc/2087:233
	p.xspace()
	name := p.xmailbox()
	p.xempty()

	// This mailbox does not have to exist. Caller just wants to know which limits
	// would apply. We only have one limit, so we don't use the name otherwise.
	// ../rfc/9208:295
	name = xcheckmailboxname(name, true)

	// Get current usage for account.
	var quota, size int64 // Account only has a quota if > 0.
	c.account.WithRLock(func() {
		quota = c.account.QuotaMessageSize()
		if quota >= 0 {
			c.xdbread(func(tx *bstore.Tx) {
				du := store.DiskUsage{ID: 1}
				err := tx.Get(&du)
				xcheckf(err, "gather used quota")
				size = du.MessageSize
			})
		}
	})

	// We only have one per account quota, we name it "" like the examples in the RFC.
	// Response syntax: ../rfc/9208:668 ../rfc/2087:242
	c.xbwritelinef(`* QUOTAROOT %s ""`, astring(name).pack(c))

	// We only write the quota response if there is a limit. The syntax doesn't allow
	// an empty list, so we cannot send the current disk usage if there is no limit.
	if quota > 0 {
		// Response syntax: ../rfc/9208:666 ../rfc/2087:239
		c.xbwritelinef(`* QUOTA "" (STORAGE %d %d)`, (size+1024-1)/1024, (quota+1024-1)/1024)
	}
	c.ok(tag, cmd)
}

// Return the quota for a quota root.
//
// State: Authenticated and selected.
func (c *conn) cmdGetquota(tag, cmd string, p *parser) {
	// Command: ../rfc/9208:245 ../rfc/2087:123

	// Request syntax: ../rfc/9208:658 ../rfc/2087:231
	p.xspace()
	root := p.xastring()
	p.xempty()

	// We only have a per-account root called "".
	if root != "" {
		xuserErrorf("unknown quota root")
	}

	var quota, size int64
	c.account.WithRLock(func() {
		quota = c.account.QuotaMessageSize()
		if quota > 0 {
			c.xdbread(func(tx *bstore.Tx) {
				du := store.DiskUsage{ID: 1}
				err := tx.Get(&du)
				xcheckf(err, "gather used quota")
				size = du.MessageSize
			})
		}
	})

	// We only write the quota response if there is a limit. The syntax doesn't allow
	// an empty list, so we cannot send the current disk usage if there is no limit.
	if quota > 0 {
		// Response syntax: ../rfc/9208:666 ../rfc/2087:239
		c.xbwritelinef(`* QUOTA "" (STORAGE %d %d)`, (size+1024-1)/1024, (quota+1024-1)/1024)
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

	if !c.readonly {
		c.xexpunge(nil, true)
	}
	c.unselect()
	c.ok(tag, cmd)
}

// expunge messages marked for deletion in currently selected/active mailbox.
// if uidSet is not nil, only messages matching the set are expunged.
//
// Messages that have been marked expunged from the database are returned. While
// other sessions still reference the message, it is not cleared from the database
// yet, and the message file is not yet removed.
//
// The highest modseq in the mailbox is returned, typically associated with the
// removal of the messages, but if no messages were expunged the current latest max
// modseq for the mailbox is returned.
func (c *conn) xexpunge(uidSet *numSet, missingMailboxOK bool) (expunged []store.Message, highestModSeq store.ModSeq) {
	c.account.WithWLock(func() {
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			mb, err := store.MailboxID(tx, c.mailboxID)
			if err == bstore.ErrAbsent || err == store.ErrMailboxExpunged {
				if missingMailboxOK {
					return
				}
				// ../rfc/9051:5140
				xusercodeErrorf("NONEXISTENT", "%w", store.ErrUnknownMailbox)
			}
			xcheckf(err, "get mailbox")

			xlastUID := c.newCachedLastUID(tx, c.mailboxID, func(err error) { xuserErrorf("%s", err) })

			qm := bstore.QueryTx[store.Message](tx)
			qm.FilterNonzero(store.Message{MailboxID: c.mailboxID})
			qm.FilterEqual("Deleted", true)
			qm.FilterEqual("Expunged", false)
			qm.FilterLess("UID", c.uidnext)
			qm.FilterFn(func(m store.Message) bool {
				// Only remove if this session knows about the message and if present in optional
				// uidSet.
				return uidSet == nil || uidSet.xcontainsKnownUID(m.UID, c.searchResult, xlastUID)
			})
			qm.SortAsc("UID")
			expunged, err = qm.List()
			xcheckf(err, "listing messages to expunge")

			if len(expunged) == 0 {
				highestModSeq = mb.ModSeq
				return
			}

			// Assign new modseq.
			modseq, err := c.account.NextModSeq(tx)
			xcheckf(err, "assigning next modseq")
			highestModSeq = modseq
			mb.ModSeq = modseq

			chremuids, chmbcounts, err := c.account.MessageRemove(c.log, tx, modseq, &mb, store.RemoveOpts{}, expunged...)
			xcheckf(err, "expunging messages")
			changes = append(changes, chremuids, chmbcounts)

			err = tx.Update(&mb)
			xcheckf(err, "update mailbox")
		})

		c.broadcast(changes)
	})

	return expunged, highestModSeq
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
// is not nil, only those UIDs are expunged.
// State: Selected
func (c *conn) cmdxExpunge(tag, cmd string, uidSet *numSet) {
	// Command: ../rfc/9051:3687 ../rfc/3501:2695

	expunged, highestModSeq := c.xexpunge(uidSet, false)

	// Response syntax: ../rfc/9051:6742 ../rfc/3501:4864
	var vanishedUIDs numSet
	qresync := c.enabled[capQresync]
	for _, m := range expunged {
		// With uidonly, we must always return VANISHED. ../rfc/9586:210
		if c.uidonly {
			c.exists--
			vanishedUIDs.append(uint32(m.UID))
			continue
		}
		seq := c.xsequence(m.UID)
		c.sequenceRemove(seq, m.UID)
		if qresync {
			vanishedUIDs.append(uint32(m.UID))
		} else {
			c.xbwritelinef("* %d EXPUNGE", seq)
		}
	}
	if !vanishedUIDs.empty() {
		// VANISHED without EARLIER. ../rfc/7162:2004
		for _, s := range vanishedUIDs.Strings(4*1024 - 32) {
			c.xbwritelinef("* VANISHED %s", s)
		}
	}

	if c.enabled[capCondstore] {
		c.xwriteresultf("%s OK [HIGHESTMODSEQ %d] expunged", tag, highestModSeq.Client())
	} else {
		c.ok(tag, cmd)
	}
}

// State: Selected
func (c *conn) cmdSearch(tag, cmd string, p *parser) {
	c.cmdxSearch(false, false, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdUIDSearch(tag, cmd string, p *parser) {
	c.cmdxSearch(true, false, tag, cmd, p)
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

// State: Selected
func (c *conn) cmdReplace(tag, cmd string, p *parser) {
	c.cmdxReplace(false, tag, cmd, p)
}

// State: Selected
func (c *conn) cmdUIDReplace(tag, cmd string, p *parser) {
	c.cmdxReplace(true, tag, cmd, p)
}

func (c *conn) gatherCopyMoveUIDs(tx *bstore.Tx, isUID bool, nums numSet) []store.UID {
	// Gather uids, then sort so we can return a consistently simple and hard to
	// misinterpret COPYUID/MOVEUID response. It seems safer to have UIDs in ascending
	// order, because requested uid set of 12:10 is equal to 10:12, so if we would just
	// echo whatever the client sends us without reordering, the client can reorder our
	// response and interpret it differently than we intended.
	// ../rfc/9051:5072
	return c.xnumSetEval(tx, isUID, nums)
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

	// Files that were created during the copy. Remove them if the operation fails.
	var newIDs []int64
	defer func() {
		for _, id := range newIDs {
			p := c.account.MessagePath(id)
			err := os.Remove(p)
			c.xsanity(err, "cleaning up created file")
		}
	}()

	// UIDs to copy.
	var uids []store.UID

	var mbDst store.Mailbox
	var nkeywords int
	var newUIDs []store.UID
	var flags []store.Flags
	var keywords [][]string
	var modseq store.ModSeq // For messages in new mailbox, assigned when first message is copied.

	c.account.WithWLock(func() {

		c.xdbwrite(func(tx *bstore.Tx) {
			mbSrc := c.xmailboxID(tx, c.mailboxID) // Validate.

			mbDst = c.xmailbox(tx, name, "TRYCREATE")
			if mbDst.ID == mbSrc.ID {
				xuserErrorf("cannot copy to currently selected mailbox")
			}

			uids = c.gatherCopyMoveUIDs(tx, isUID, nums)

			if len(uids) == 0 {
				xuserErrorf("no matching messages to copy")
			}

			nkeywords = len(mbDst.Keywords)

			var err error
			modseq, err = c.account.NextModSeq(tx)
			xcheckf(err, "assigning next modseq")
			mbSrc.ModSeq = modseq
			mbDst.ModSeq = modseq

			err = tx.Update(&mbSrc)
			xcheckf(err, "updating source mailbox for modseq")

			// Reserve the uids in the destination mailbox.
			uidFirst := mbDst.UIDNext
			err = mbDst.UIDNextAdd(len(uids))
			xcheckf(err, "adding uid")

			// Fetch messages from database.
			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: c.mailboxID})
			q.FilterEqual("UID", slicesAny(uids)...)
			q.FilterEqual("Expunged", false)
			xmsgs, err := q.List()
			xcheckf(err, "fetching messages")

			if len(xmsgs) != len(uids) {
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
				// ../rfc/9051:5155 ../rfc/9208:472
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
			now := time.Now()

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
				m.SaveDate = &now
				err := tx.Insert(&m)
				xcheckf(err, "inserting message")
				msgs[uid] = m
				nmsgs[i] = m
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

			mbDst.Keywords, _ = store.MergeKeywords(mbDst.Keywords, slices.Sorted(maps.Keys(mbKeywords)))

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
				newIDs = append(newIDs, newMsgIDs[i])
			}

			for dir := range syncDirs {
				err := moxio.SyncDir(c.log, dir)
				xcheckf(err, "sync directory")
			}

			err = c.account.RetrainMessages(context.TODO(), c.log, tx, nmsgs)
			xcheckf(err, "train copied messages")
		})

		newIDs = nil

		// Broadcast changes to other connections.
		if len(newUIDs) > 0 {
			changes := make([]store.Change, 0, len(newUIDs)+2)
			for i, uid := range newUIDs {
				add := store.ChangeAddUID{
					MailboxID:        mbDst.ID,
					UID:              uid,
					ModSeq:           modseq,
					Flags:            flags[i],
					Keywords:         keywords[i],
					MessageCountIMAP: mbDst.MessageCountIMAP(),
					Unseen:           uint32(mbDst.MailboxCounts.Unseen),
				}
				changes = append(changes, add)
			}
			changes = append(changes, mbDst.ChangeCounts())
			if nkeywords != len(mbDst.Keywords) {
				changes = append(changes, mbDst.ChangeKeywords())
			}
			c.broadcast(changes)
		}
	})

	// ../rfc/9051:6881 ../rfc/4315:183
	c.xwriteresultf("%s OK [COPYUID %d %s %s] copied", tag, mbDst.UIDValidity, compactUIDSet(uids).String(), compactUIDSet(newUIDs).String())
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

	// UIDs to move.
	var uids []store.UID

	var mbDst store.Mailbox
	var uidFirst store.UID
	var modseq store.ModSeq

	var cleanupIDs []int64
	defer func() {
		for _, id := range cleanupIDs {
			p := c.account.MessagePath(id)
			err := os.Remove(p)
			c.xsanity(err, "removing destination message file %v", p)
		}
	}()

	c.account.WithWLock(func() {
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			mbSrc := c.xmailboxID(tx, c.mailboxID) // Validate.
			mbDst = c.xmailbox(tx, name, "TRYCREATE")
			if mbDst.ID == c.mailboxID {
				xuserErrorf("cannot move to currently selected mailbox")
			}

			uids = c.gatherCopyMoveUIDs(tx, isUID, nums)

			if len(uids) == 0 {
				xuserErrorf("no matching messages to move")
			}

			uidFirst = mbDst.UIDNext

			// Assign a new modseq, for the new records and for the expunged records.
			var err error
			modseq, err = c.account.NextModSeq(tx)
			xcheckf(err, "assigning next modseq")

			// Make query selecting messages to move.
			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: mbSrc.ID})
			q.FilterEqual("UID", slicesAny(uids)...)
			q.FilterEqual("Expunged", false)
			q.SortAsc("UID")

			newIDs, chl := c.xmoveMessages(tx, q, len(uids), modseq, &mbSrc, &mbDst)
			changes = append(changes, chl...)
			cleanupIDs = newIDs
		})

		cleanupIDs = nil

		c.broadcast(changes)
	})

	// ../rfc/9051:4708 ../rfc/6851:254
	// ../rfc/9051:4713
	newUIDs := numSet{ranges: []numRange{{setNumber{number: uint32(uidFirst)}, &setNumber{number: uint32(mbDst.UIDNext - 1)}}}}
	c.xbwritelinef("* OK [COPYUID %d %s %s] moved", mbDst.UIDValidity, compactUIDSet(uids).String(), newUIDs.String())
	qresync := c.enabled[capQresync]
	var vanishedUIDs numSet
	for i := range uids {
		// With uidonly, we must always return VANISHED. ../rfc/9586:232
		if c.uidonly {
			c.exists--
			vanishedUIDs.append(uint32(uids[i]))
			continue
		}

		seq := c.xsequence(uids[i])
		c.sequenceRemove(seq, uids[i])
		if qresync {
			vanishedUIDs.append(uint32(uids[i]))
		} else {
			c.xbwritelinef("* %d EXPUNGE", seq)
		}
	}
	if !vanishedUIDs.empty() {
		// VANISHED without EARLIER. ../rfc/7162:2004
		for _, s := range vanishedUIDs.Strings(4*1024 - 32) {
			c.xbwritelinef("* VANISHED %s", s)
		}
	}

	if qresync {
		// ../rfc/9051:6744 ../rfc/7162:1334
		c.xwriteresultf("%s OK [HIGHESTMODSEQ %d] move", tag, modseq.Client())
	} else {
		c.ok(tag, cmd)
	}
}

// q must yield messages from a single mailbox.
func (c *conn) xmoveMessages(tx *bstore.Tx, q *bstore.Query[store.Message], expectCount int, modseq store.ModSeq, mbSrc, mbDst *store.Mailbox) (newIDs []int64, changes []store.Change) {
	newIDs = make([]int64, 0, expectCount)
	var commit bool
	defer func() {
		if commit {
			return
		}
		for _, id := range newIDs {
			p := c.account.MessagePath(id)
			err := os.Remove(p)
			c.xsanity(err, "removing added message file %v", p)
		}
		newIDs = nil
	}()

	mbSrc.ModSeq = modseq
	mbDst.ModSeq = modseq

	var jf *junk.Filter
	defer func() {
		if jf != nil {
			err := jf.CloseDiscard()
			c.log.Check(err, "closing junk filter after error")
		}
	}()

	accConf, _ := c.account.Conf()

	changeRemoveUIDs := store.ChangeRemoveUIDs{
		MailboxID: mbSrc.ID,
		ModSeq:    modseq,
	}
	changes = make([]store.Change, 0, expectCount+4) // mbsrc removeuids, mbsrc counts, mbdst counts, mbdst keywords

	nkeywords := len(mbDst.Keywords)
	now := time.Now()

	l, err := q.List()
	xcheckf(err, "listing messages to move")

	if expectCount > 0 && len(l) != expectCount {
		xcheckf(fmt.Errorf("moved %d messages, expected %d", len(l), expectCount), "move messages")
	}

	// For newly created message directories that we sync after hardlinking/copying files.
	syncDirs := map[string]struct{}{}

	for _, om := range l {
		nm := om
		nm.MailboxID = mbDst.ID
		nm.UID = mbDst.UIDNext
		err := mbDst.UIDNextAdd(1)
		xcheckf(err, "adding uid")
		nm.ModSeq = modseq
		nm.CreateSeq = modseq
		nm.SaveDate = &now
		if nm.IsReject && nm.MailboxDestinedID != 0 {
			// Incorrectly delivered to Rejects mailbox. Adjust MailboxOrigID so this message
			// is used for reputation calculation during future deliveries.
			nm.MailboxOrigID = nm.MailboxDestinedID
			nm.IsReject = false
			nm.Seen = false
		}

		nm.JunkFlagsForMailbox(*mbDst, accConf)

		err = tx.Update(&nm)
		xcheckf(err, "updating message with new mailbox")

		mbDst.Add(nm.MailboxCounts())

		mbSrc.Sub(om.MailboxCounts())
		om.ID = 0
		om.Expunged = true
		om.ModSeq = modseq
		om.TrainedJunk = nil
		err = tx.Insert(&om)
		xcheckf(err, "inserting expunged message in old mailbox")

		dstPath := c.account.MessagePath(om.ID)
		dstDir := filepath.Dir(dstPath)
		if _, ok := syncDirs[dstDir]; !ok {
			os.MkdirAll(dstDir, 0770)
			syncDirs[dstDir] = struct{}{}
		}

		err = moxio.LinkOrCopy(c.log, dstPath, c.account.MessagePath(nm.ID), nil, false)
		xcheckf(err, "duplicating message in old mailbox for current sessions")
		newIDs = append(newIDs, nm.ID)
		// We don't sync the directory. In case of a crash and files disappearing, the
		// eraser will simply not find the file at next startup.

		err = tx.Insert(&store.MessageErase{ID: om.ID, SkipUpdateDiskUsage: true})
		xcheckf(err, "insert message erase")

		mbDst.Keywords, _ = store.MergeKeywords(mbDst.Keywords, nm.Keywords)

		if accConf.JunkFilter != nil && nm.NeedsTraining() {
			// Lazily open junk filter.
			if jf == nil {
				jf, _, err = c.account.OpenJunkFilter(context.TODO(), c.log)
				xcheckf(err, "open junk filter")
			}
			err := c.account.RetrainMessage(context.TODO(), c.log, tx, jf, &nm)
			xcheckf(err, "retrain message after moving")
		}

		changeRemoveUIDs.UIDs = append(changeRemoveUIDs.UIDs, om.UID)
		changeRemoveUIDs.MsgIDs = append(changeRemoveUIDs.MsgIDs, om.ID)
		changes = append(changes, nm.ChangeAddUID(*mbDst))
	}
	xcheckf(err, "move messages")

	for dir := range syncDirs {
		err := moxio.SyncDir(c.log, dir)
		xcheckf(err, "sync directory")
	}

	changeRemoveUIDs.UIDNext = mbDst.UIDNext
	changeRemoveUIDs.MessageCountIMAP = mbDst.MessageCountIMAP()
	changeRemoveUIDs.Unseen = uint32(mbDst.MailboxCounts.Unseen)
	changes = append(changes, changeRemoveUIDs, mbSrc.ChangeCounts())

	err = tx.Update(mbSrc)
	xcheckf(err, "updating counts for inbox")

	changes = append(changes, mbDst.ChangeCounts())
	if len(mbDst.Keywords) > nkeywords {
		changes = append(changes, mbDst.ChangeKeywords())
	}

	err = tx.Update(mbDst)
	xcheckf(err, "updating uidnext and counts in destination mailbox")

	if jf != nil {
		err := jf.Close()
		jf = nil
		xcheckf(err, "saving junk filter")
	}

	commit = true
	return
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

			uids := c.xnumSetEval(tx, isUID, nums)

			if len(uids) == 0 {
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
			q.FilterEqual("UID", slicesAny(uids)...)
			q.FilterEqual("Expunged", false)
			err := q.ForEach(func(m store.Message) error {
				// Client may specify a message multiple times, but we only process it once. ../rfc/7162:823
				if modified[m.ID] {
					return nil
				}

				mc := m.MailboxCounts()

				origFlags := m.Flags
				m.Flags = m.Flags.Set(mask, flags)
				oldKeywords := slices.Clone(m.Keywords)
				if minus {
					m.Keywords, _ = store.RemoveKeywords(m.Keywords, keywords)
				} else if plus {
					m.Keywords, _ = store.MergeKeywords(m.Keywords, keywords)
				} else {
					m.Keywords = keywords
				}

				keywordsChanged := func() bool {
					sort.Strings(oldKeywords)
					n := slices.Clone(m.Keywords)
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
					mb.ModSeq = modseq
				}
				m.ModSeq = modseq
				modified[m.ID] = true
				updated = append(updated, m)

				changes = append(changes, m.ChangeFlags(origFlags, mb))

				return tx.Update(&m)
			})
			xcheckf(err, "storing flags in messages")

			if mb.MailboxCounts != origmb.MailboxCounts || modseq != 0 {
				err := tx.Update(&mb)
				xcheckf(err, "updating mailbox counts")
			}
			if mb.MailboxCounts != origmb.MailboxCounts {
				changes = append(changes, mb.ChangeCounts())
			}
			if mbKwChanged {
				changes = append(changes, mb.ChangeKeywords())
			}

			err = c.account.RetrainMessages(context.TODO(), c.log, tx, updated)
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
			var args []string
			if !silent {
				args = append(args, fmt.Sprintf("FLAGS %s", flaglist(m.Flags, m.Keywords).pack(c)))
			}
			if c.enabled[capCondstore] {
				args = append(args, fmt.Sprintf("MODSEQ (%d)", m.ModSeq.Client()))
			}
			// ../rfc/9051:6749 ../rfc/3501:4869 ../rfc/7162:2490
			// UIDFETCH in case of uidonly. ../rfc/9586:228
			if c.uidonly {
				// Ensure list is non-empty.
				if len(args) == 0 {
					args = append(args, fmt.Sprintf("UID %d", m.UID))
				}
				c.xbwritelinef("* %d UIDFETCH (%s)", m.UID, strings.Join(args, " "))
			} else {
				args = append([]string{fmt.Sprintf("UID %d", m.UID)}, args...)
				c.xbwritelinef("* %d FETCH (%s)", c.xsequence(m.UID), strings.Join(args, " "))
			}
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
		// UIDFETCH in case of uidonly. ../rfc/9586:228
		if c.uidonly {
			c.xbwritelinef("* %d UIDFETCH (FLAGS %s MODSEQ (%d))", m.UID, flaglist(m.Flags, m.Keywords).pack(c), m.ModSeq.Client())
		} else {
			c.xbwritelinef("* %d FETCH (UID %d FLAGS %s MODSEQ (%d))", c.xsequence(m.UID), m.UID, flaglist(m.Flags, m.Keywords).pack(c), m.ModSeq.Client())
		}
		if isUID {
			mnums = append(mnums, m.UID)
		} else {
			mnums = append(mnums, store.UID(c.xsequence(m.UID)))
		}
	}

	slices.Sort(mnums)
	set := compactUIDSet(mnums)
	// ../rfc/7162:2506
	c.xwriteresultf("%s OK [MODIFIED %s] conditional store did not modify all", tag, set.String())
}
