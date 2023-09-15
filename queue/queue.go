// Package queue is in charge of outgoing messages, queueing them when submitted,
// attempting a first delivery over SMTP, retrying with backoff and sending DSNs
// for delayed or failed deliveries.
package queue

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

var xlog = mlog.New("queue")

var (
	metricConnection = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_queue_connection_total",
			Help: "Queue client connections, outgoing.",
		},
		[]string{
			"result", // "ok", "timeout", "canceled", "error"
		},
	)
	metricDelivery = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_queue_delivery_duration_seconds",
			Help:    "SMTP client delivery attempt to single host.",
			Buckets: []float64{0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30, 60, 120},
		},
		[]string{
			"attempt",   // Number of attempts.
			"transport", // empty for default direct delivery.
			"tlsmode",   // strict, opportunistic, skip
			"result",    // ok, timeout, canceled, temperror, permerror, error
		},
	)
)

type contextDialer interface {
	DialContext(ctx context.Context, network, addr string) (c net.Conn, err error)
}

// Used to dial remote SMTP servers.
// Overridden for tests.
var dial = func(ctx context.Context, dialer contextDialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
	// If this is a net.Dialer, use its settings and add the timeout and localaddr.
	// This is the typical case, but SOCKS5 support can use a different dialer.
	if d, ok := dialer.(*net.Dialer); ok {
		nd := *d
		nd.Timeout = timeout
		nd.LocalAddr = laddr
		return nd.DialContext(ctx, "tcp", addr)
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

var jitter = mox.NewRand()

var DBTypes = []any{Msg{}} // Types stored in DB.
var DB *bstore.DB          // Exported for making backups.

// Set for mox localserve, to prevent queueing.
var Localserve bool

// Msg is a message in the queue.
type Msg struct {
	ID                 int64
	Queued             time.Time      `bstore:"default now"`
	SenderAccount      string         // Failures are delivered back to this local account. Also used for routing.
	SenderLocalpart    smtp.Localpart // Should be a local user and domain.
	SenderDomain       dns.IPDomain
	RecipientLocalpart smtp.Localpart // Typically a remote user and domain.
	RecipientDomain    dns.IPDomain
	RecipientDomainStr string              // For filtering.
	Attempts           int                 // Next attempt is based on last attempt and exponential back off based on attempts.
	DialedIPs          map[string][]net.IP // For each host, the IPs that were dialed. Used for IP selection for later attempts.
	NextAttempt        time.Time           // For scheduling.
	LastAttempt        *time.Time
	LastError          string
	Has8bit            bool   // Whether message contains bytes with high bit set, determines whether 8BITMIME SMTP extension is needed.
	SMTPUTF8           bool   // Whether message requires use of SMTPUTF8.
	Size               int64  // Full size of message, combined MsgPrefix with contents of message file.
	MessageID          string // Used when composing a DSN, in its References header.
	MsgPrefix          []byte

	// If set, this message is a DSN and this is a version using utf-8, for the case
	// the remote MTA supports smtputf8. In this case, Size and MsgPrefix are not
	// relevant.
	DSNUTF8 []byte

	// If non-empty, the transport to use for this message. Can be set through cli or
	// admin interface. If empty (the default for a submitted message), regular routing
	// rules apply.
	Transport string
}

// Sender of message as used in MAIL FROM.
func (m Msg) Sender() smtp.Path {
	return smtp.Path{Localpart: m.SenderLocalpart, IPDomain: m.SenderDomain}
}

// Recipient of message as used in RCPT TO.
func (m Msg) Recipient() smtp.Path {
	return smtp.Path{Localpart: m.RecipientLocalpart, IPDomain: m.RecipientDomain}
}

// MessagePath returns the path where the message is stored.
func (m Msg) MessagePath() string {
	return mox.DataDirPath(filepath.Join("queue", store.MessagePath(m.ID)))
}

// Init opens the queue database without starting delivery.
func Init() error {
	qpath := mox.DataDirPath("queue/index.db")
	os.MkdirAll(filepath.Dir(qpath), 0770)
	isNew := false
	if _, err := os.Stat(qpath); err != nil && os.IsNotExist(err) {
		isNew = true
	}

	var err error
	DB, err = bstore.Open(mox.Shutdown, qpath, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, DBTypes...)
	if err != nil {
		if isNew {
			os.Remove(qpath)
		}
		return fmt.Errorf("open queue database: %s", err)
	}
	return nil
}

// Shutdown closes the queue database. The delivery process isn't stopped. For tests only.
func Shutdown() {
	err := DB.Close()
	xlog.Check(err, "closing queue db")
	DB = nil
}

// List returns all messages in the delivery queue.
// Ordered by earliest delivery attempt first.
func List(ctx context.Context) ([]Msg, error) {
	qmsgs, err := bstore.QueryDB[Msg](ctx, DB).List()
	if err != nil {
		return nil, err
	}
	sort.Slice(qmsgs, func(i, j int) bool {
		a := qmsgs[i]
		b := qmsgs[j]
		la := a.LastAttempt != nil
		lb := b.LastAttempt != nil
		if !la && lb {
			return true
		} else if la && !lb {
			return false
		}
		if !la && !lb || a.LastAttempt.Equal(*b.LastAttempt) {
			return a.ID < b.ID
		}
		return a.LastAttempt.Before(*b.LastAttempt)
	})
	return qmsgs, nil
}

// Count returns the number of messages in the delivery queue.
func Count(ctx context.Context) (int, error) {
	return bstore.QueryDB[Msg](ctx, DB).Count()
}

// Add a new message to the queue. The queue is kicked immediately to start a
// first delivery attempt.
//
// If consumeFile is true, it is removed as part of delivery (by rename or copy
// and remove). msgFile is never closed by Add.
//
// dnsutf8Opt is a utf8-version of the message, to be used only for DNSs. If set,
// this data is used as the message when delivering the DSN and the remote SMTP
// server supports SMTPUTF8. If the remote SMTP server does not support SMTPUTF8,
// the regular non-utf8 message is delivered.
func Add(ctx context.Context, log *mlog.Log, senderAccount string, mailFrom, rcptTo smtp.Path, has8bit, smtputf8 bool, size int64, messageID string, msgPrefix []byte, msgFile *os.File, dsnutf8Opt []byte, consumeFile bool) (int64, error) {
	// todo: Add should accept multiple rcptTo if they are for the same domain. so we can queue them for delivery in one (or just a few) session(s), transferring the data only once. ../rfc/5321:3759

	if Localserve {
		if senderAccount == "" {
			return 0, fmt.Errorf("cannot queue with localserve without local account")
		}
		acc, err := store.OpenAccount(senderAccount)
		if err != nil {
			return 0, fmt.Errorf("opening sender account for immediate delivery with localserve: %v", err)
		}
		defer func() {
			err := acc.Close()
			log.Check(err, "closing account")
		}()
		m := store.Message{Size: size, MsgPrefix: msgPrefix}
		conf, _ := acc.Conf()
		dest := conf.Destinations[mailFrom.String()]
		acc.WithWLock(func() {
			err = acc.DeliverDestination(log, dest, &m, msgFile, consumeFile)
		})
		if err != nil {
			return 0, fmt.Errorf("delivering message: %v", err)
		}
		log.Debug("immediately delivered from queue to sender")
		return 0, nil
	}

	tx, err := DB.Begin(ctx, true)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if tx != nil {
			if err := tx.Rollback(); err != nil {
				log.Errorx("rollback for queue", err)
			}
		}
	}()

	now := time.Now()
	qm := Msg{0, now, senderAccount, mailFrom.Localpart, mailFrom.IPDomain, rcptTo.Localpart, rcptTo.IPDomain, formatIPDomain(rcptTo.IPDomain), 0, nil, now, nil, "", has8bit, smtputf8, size, messageID, msgPrefix, dsnutf8Opt, ""}

	if err := tx.Insert(&qm); err != nil {
		return 0, err
	}

	dst := qm.MessagePath()
	defer func() {
		if dst != "" {
			err := os.Remove(dst)
			log.Check(err, "removing destination message file for queue", mlog.Field("path", dst))
		}
	}()
	dstDir := filepath.Dir(dst)
	os.MkdirAll(dstDir, 0770)
	if consumeFile {
		if err := os.Rename(msgFile.Name(), dst); err != nil {
			// Could be due to cross-filesystem rename. Users shouldn't configure their systems that way.
			return 0, fmt.Errorf("move message into queue dir: %w", err)
		}
	} else if err := moxio.LinkOrCopy(log, dst, msgFile.Name(), nil, true); err != nil {
		return 0, fmt.Errorf("linking/copying message to new file: %s", err)
	} else if err := moxio.SyncDir(dstDir); err != nil {
		return 0, fmt.Errorf("sync directory: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit transaction: %s", err)
	}
	tx = nil
	dst = ""

	queuekick()
	return qm.ID, nil
}

func formatIPDomain(d dns.IPDomain) string {
	if len(d.IP) > 0 {
		return "[" + d.IP.String() + "]"
	}
	return d.Domain.Name()
}

var (
	kick           = make(chan struct{}, 1)
	deliveryResult = make(chan string, 1)
)

func queuekick() {
	select {
	case kick <- struct{}{}:
	default:
	}
}

// Kick sets the NextAttempt for messages matching all filter parameters (ID,
// toDomain, recipient) that are nonzero, and kicks the queue, attempting delivery
// of those messages. If all parameters are zero, all messages are kicked. If
// transport is set, the delivery attempts for the matching messages will use the
// transport. An empty string is the default transport, i.e. direct delivery.
// Returns number of messages queued for immediate delivery.
func Kick(ctx context.Context, ID int64, toDomain, recipient string, transport *string) (int, error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if ID > 0 {
		q.FilterID(ID)
	}
	if toDomain != "" {
		q.FilterEqual("RecipientDomainStr", toDomain)
	}
	if recipient != "" {
		q.FilterFn(func(qm Msg) bool {
			return qm.Recipient().XString(true) == recipient
		})
	}
	up := map[string]any{"NextAttempt": time.Now()}
	if transport != nil {
		if *transport != "" {
			_, ok := mox.Conf.Static.Transports[*transport]
			if !ok {
				return 0, fmt.Errorf("unknown transport %q", *transport)
			}
		}
		up["Transport"] = *transport
	}
	n, err := q.UpdateFields(up)
	if err != nil {
		return 0, fmt.Errorf("selecting and updating messages in queue: %v", err)
	}
	queuekick()
	return n, nil
}

// Drop removes messages from the queue that match all nonzero parameters.
// If all parameters are zero, all messages are removed.
// Returns number of messages removed.
func Drop(ctx context.Context, ID int64, toDomain string, recipient string) (int, error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if ID > 0 {
		q.FilterID(ID)
	}
	if toDomain != "" {
		q.FilterEqual("RecipientDomainStr", toDomain)
	}
	if recipient != "" {
		q.FilterFn(func(qm Msg) bool {
			return qm.Recipient().XString(true) == recipient
		})
	}
	var msgs []Msg
	q.Gather(&msgs)
	n, err := q.Delete()
	if err != nil {
		return 0, fmt.Errorf("selecting and deleting messages from queue: %v", err)
	}
	for _, m := range msgs {
		p := m.MessagePath()
		if err := os.Remove(p); err != nil {
			xlog.WithContext(ctx).Errorx("removing queue message from file system", err, mlog.Field("queuemsgid", m.ID), mlog.Field("path", p))
		}
	}
	return n, nil
}

type ReadReaderAtCloser interface {
	io.ReadCloser
	io.ReaderAt
}

// OpenMessage opens a message present in the queue.
func OpenMessage(ctx context.Context, id int64) (ReadReaderAtCloser, error) {
	qm := Msg{ID: id}
	err := DB.Get(ctx, &qm)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(qm.MessagePath())
	if err != nil {
		return nil, fmt.Errorf("open message file: %s", err)
	}
	r := store.FileMsgReader(qm.MsgPrefix, f)
	return r, err
}

const maxConcurrentDeliveries = 10

// Start opens the database by calling Init, then starts the delivery process.
func Start(resolver dns.Resolver, done chan struct{}) error {
	if err := Init(); err != nil {
		return err
	}

	// High-level delivery strategy advice: ../rfc/5321:3685
	go func() {
		// Map keys are either dns.Domain.Name()'s, or string-formatted IP addresses.
		busyDomains := map[string]struct{}{}

		timer := time.NewTimer(0)

		for {
			select {
			case <-mox.Shutdown.Done():
				done <- struct{}{}
				return
			case <-kick:
			case <-timer.C:
			case domain := <-deliveryResult:
				delete(busyDomains, domain)
			}

			if len(busyDomains) >= maxConcurrentDeliveries {
				continue
			}

			launchWork(resolver, busyDomains)
			timer.Reset(nextWork(mox.Shutdown, busyDomains))
		}
	}()
	return nil
}

func nextWork(ctx context.Context, busyDomains map[string]struct{}) time.Duration {
	q := bstore.QueryDB[Msg](ctx, DB)
	if len(busyDomains) > 0 {
		var doms []any
		for d := range busyDomains {
			doms = append(doms, d)
		}
		q.FilterNotEqual("RecipientDomainStr", doms...)
	}
	q.SortAsc("NextAttempt")
	q.Limit(1)
	qm, err := q.Get()
	if err == bstore.ErrAbsent {
		return 24 * time.Hour
	} else if err != nil {
		xlog.Errorx("finding time for next delivery attempt", err)
		return 1 * time.Minute
	}
	return time.Until(qm.NextAttempt)
}

func launchWork(resolver dns.Resolver, busyDomains map[string]struct{}) int {
	q := bstore.QueryDB[Msg](mox.Shutdown, DB)
	q.FilterLessEqual("NextAttempt", time.Now())
	q.SortAsc("NextAttempt")
	q.Limit(maxConcurrentDeliveries)
	if len(busyDomains) > 0 {
		var doms []any
		for d := range busyDomains {
			doms = append(doms, d)
		}
		q.FilterNotEqual("RecipientDomainStr", doms...)
	}
	msgs, err := q.List()
	if err != nil {
		xlog.Errorx("querying for work in queue", err)
		mox.Sleep(mox.Shutdown, 1*time.Second)
		return -1
	}

	for _, m := range msgs {
		busyDomains[formatIPDomain(m.RecipientDomain)] = struct{}{}
		go deliver(resolver, m)
	}
	return len(msgs)
}

// Remove message from queue in database and file system.
func queueDelete(ctx context.Context, msgID int64) error {
	if err := DB.Delete(ctx, &Msg{ID: msgID}); err != nil {
		return err
	}
	// If removing from database fails, we'll also leave the file in the file system.

	p := mox.DataDirPath(filepath.Join("queue", store.MessagePath(msgID)))
	if err := os.Remove(p); err != nil {
		return fmt.Errorf("removing queue message from file system: %v", err)
	}

	return nil
}

// deliver attempts to deliver a message.
// The queue is updated, either by removing a delivered or permanently failed
// message, or updating the time for the next attempt. A DSN may be sent.
func deliver(resolver dns.Resolver, m Msg) {
	cid := mox.Cid()
	qlog := xlog.WithCid(cid).Fields(mlog.Field("from", m.Sender()), mlog.Field("recipient", m.Recipient()), mlog.Field("attempts", m.Attempts), mlog.Field("msgid", m.ID))

	defer func() {
		deliveryResult <- formatIPDomain(m.RecipientDomain)

		x := recover()
		if x != nil {
			qlog.Error("deliver panic", mlog.Field("panic", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Queue)
		}
	}()

	// We register this attempt by setting last_attempt, and already next_attempt time
	// in the future with exponential backoff. If we run into trouble delivery below,
	// at least we won't be bothering the receiving server with our problems.
	// Delivery attempts: immediately, 7.5m, 15m, 30m, 1h, 2h (send delayed DSN), 4h,
	// 8h, 16h (send permanent failure DSN).
	// ../rfc/5321:3703
	// todo future: make the back off times configurable. ../rfc/5321:3713
	backoff := time.Duration(7*60+30+jitter.Intn(10)-5) * time.Second
	for i := 0; i < m.Attempts; i++ {
		backoff *= time.Duration(2)
	}
	m.Attempts++
	now := time.Now()
	m.LastAttempt = &now
	m.NextAttempt = now.Add(backoff)
	qup := bstore.QueryDB[Msg](mox.Shutdown, DB)
	qup.FilterID(m.ID)
	update := Msg{Attempts: m.Attempts, NextAttempt: m.NextAttempt, LastAttempt: m.LastAttempt}
	if _, err := qup.UpdateNonzero(update); err != nil {
		qlog.Errorx("storing delivery attempt", err)
		return
	}

	// Find route for transport to use for delivery attempt.
	var transport config.Transport
	var transportName string
	if m.Transport != "" {
		var ok bool
		transport, ok = mox.Conf.Static.Transports[m.Transport]
		if !ok {
			var remoteMTA dsn.NameIP // Zero value, will not be included in DSN. ../rfc/3464:1027
			fail(qlog, m, backoff, false, remoteMTA, "", fmt.Sprintf("cannot find transport %q", m.Transport))
			return
		}
		transportName = m.Transport
	} else {
		route := findRoute(m.Attempts-1, m)
		transport = route.ResolvedTransport
		transportName = route.Transport
	}

	if transportName != "" {
		qlog = qlog.Fields(mlog.Field("transport", transportName))
		qlog.Debug("delivering with transport", mlog.Field("transport", transportName))
	}

	var dialer contextDialer = &net.Dialer{}
	if transport.Submissions != nil {
		deliverSubmit(cid, qlog, resolver, dialer, m, backoff, transportName, transport.Submissions, true, 465)
	} else if transport.Submission != nil {
		deliverSubmit(cid, qlog, resolver, dialer, m, backoff, transportName, transport.Submission, false, 587)
	} else if transport.SMTP != nil {
		deliverSubmit(cid, qlog, resolver, dialer, m, backoff, transportName, transport.SMTP, false, 25)
	} else {
		ourHostname := mox.Conf.Static.HostnameDomain
		if transport.Socks != nil {
			socksdialer, err := proxy.SOCKS5("tcp", transport.Socks.Address, nil, &net.Dialer{})
			if err != nil {
				fail(qlog, m, backoff, false, dsn.NameIP{}, "", fmt.Sprintf("socks dialer: %v", err))
				return
			} else if d, ok := socksdialer.(contextDialer); !ok {
				fail(qlog, m, backoff, false, dsn.NameIP{}, "", "socks dialer is not a contextdialer")
				return
			} else {
				dialer = d
			}
			ourHostname = transport.Socks.Hostname
		}
		deliverDirect(cid, qlog, resolver, dialer, ourHostname, transportName, m, backoff)
	}
}

func findRoute(attempt int, m Msg) config.Route {
	routesAccount, routesDomain, routesGlobal := mox.Conf.Routes(m.SenderAccount, m.SenderDomain.Domain)
	if r, ok := findRouteInList(attempt, m, routesAccount); ok {
		return r
	}
	if r, ok := findRouteInList(attempt, m, routesDomain); ok {
		return r
	}
	if r, ok := findRouteInList(attempt, m, routesGlobal); ok {
		return r
	}
	return config.Route{}
}

func findRouteInList(attempt int, m Msg, routes []config.Route) (config.Route, bool) {
	for _, r := range routes {
		if routeMatch(attempt, m, r) {
			return r, true
		}
	}
	return config.Route{}, false
}

func routeMatch(attempt int, m Msg, r config.Route) bool {
	return attempt >= r.MinimumAttempts && routeMatchDomain(r.FromDomainASCII, m.SenderDomain.Domain) && routeMatchDomain(r.ToDomainASCII, m.RecipientDomain.Domain)
}

func routeMatchDomain(l []string, d dns.Domain) bool {
	if len(l) == 0 {
		return true
	}
	for _, e := range l {
		if d.ASCII == e || strings.HasPrefix(e, ".") && (d.ASCII == e[1:] || strings.HasSuffix(d.ASCII, e)) {
			return true
		}
	}
	return false
}

// dialHost dials host for delivering Msg, taking previous attempts into accounts.
// If the previous attempt used IPv4, this attempt will use IPv6 (in case one of the IPs is in a DNSBL).
// The second attempt for an address family we prefer the same IP as earlier, to increase our chances if remote is doing greylisting.
// dialHost updates m with the dialed IP and m should be saved in case of failure.
// If we have fully specified local smtp listen IPs, we set those for the outgoing
// connection. The admin probably configured these same IPs in SPF, but others
// possibly not.
func dialHost(ctx context.Context, log *mlog.Log, resolver dns.Resolver, dialer contextDialer, host dns.IPDomain, port int, m *Msg) (conn net.Conn, ip net.IP, dualstack bool, rerr error) {
	var ips []net.IP
	if len(host.IP) > 0 {
		ips = []net.IP{host.IP}
	} else {
		// todo: The Go resolver automatically follows CNAMEs, which is not allowed for
		// host names in MX records. ../rfc/5321:3861 ../rfc/2181:661
		name := host.Domain.ASCII + "."
		ipaddrs, err := resolver.LookupIPAddr(ctx, name)
		if err != nil || len(ipaddrs) == 0 {
			return nil, nil, false, fmt.Errorf("looking up %q: %v", name, err)
		}
		var have4, have6 bool
		for _, ipaddr := range ipaddrs {
			ips = append(ips, ipaddr.IP)
			if ipaddr.IP.To4() == nil {
				have6 = true
			} else {
				have4 = true
			}
		}
		dualstack = have4 && have6
		prevIPs := m.DialedIPs[host.String()]
		if len(prevIPs) > 0 {
			prevIP := prevIPs[len(prevIPs)-1]
			prevIs4 := prevIP.To4() != nil
			sameFamily := 0
			for _, ip := range prevIPs {
				is4 := ip.To4() != nil
				if prevIs4 == is4 {
					sameFamily++
				}
			}
			preferPrev := sameFamily == 1
			// We use stable sort so any preferred/randomized listing from DNS is kept intact.
			sort.SliceStable(ips, func(i, j int) bool {
				aIs4 := ips[i].To4() != nil
				bIs4 := ips[j].To4() != nil
				if aIs4 != bIs4 {
					// Prefer "i" if it is not same address family.
					return aIs4 != prevIs4
				}
				// Prefer "i" if it is the same as last and we should be preferring it.
				return preferPrev && ips[i].Equal(prevIP)
			})
			log.Debug("ordered ips for dialing", mlog.Field("ips", ips))
		}
	}

	var timeout time.Duration
	deadline, ok := ctx.Deadline()
	if !ok {
		timeout = 30 * time.Second
	} else {
		timeout = time.Until(deadline) / time.Duration(len(ips))
	}

	var lastErr error
	var lastIP net.IP
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		log.Debug("dialing remote host for delivery", mlog.Field("addr", addr))
		var laddr net.Addr
		for _, lip := range mox.Conf.Static.SpecifiedSMTPListenIPs {
			ipIs4 := ip.To4() != nil
			lipIs4 := lip.To4() != nil
			if ipIs4 == lipIs4 {
				laddr = &net.TCPAddr{IP: lip}
				break
			}
		}
		conn, err := dial(ctx, dialer, timeout, addr, laddr)
		if err == nil {
			log.Debug("connected for smtp delivery", mlog.Field("host", host), mlog.Field("addr", addr), mlog.Field("laddr", laddr))
			if m.DialedIPs == nil {
				m.DialedIPs = map[string][]net.IP{}
			}
			name := host.String()
			m.DialedIPs[name] = append(m.DialedIPs[name], ip)
			return conn, ip, dualstack, nil
		}
		log.Debugx("connection attempt for smtp delivery", err, mlog.Field("host", host), mlog.Field("addr", addr), mlog.Field("laddr", laddr))
		lastErr = err
		lastIP = ip
	}
	return nil, lastIP, dualstack, lastErr
}
