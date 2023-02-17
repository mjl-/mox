// Package queue is in charge of outgoing messages, queueing them when submitted,
// attempting a first delivery over SMTP, retrying with backoff and sending DSNs
// for delayed or failed deliveries.
package queue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
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
	metricDeliveryHost = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_queue_delivery_duration_seconds",
			Help:    "SMTP client delivery attempt to single host.",
			Buckets: []float64{0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30, 60, 120},
		},
		[]string{
			"attempt", // Number of attempts.
			"tlsmode", // strict, opportunistic, skip
			"result",  // ok, timeout, canceled, temperror, permerror, error
		},
	)
)

// Used to dial remote SMTP servers.
// Overridden for tests.
var dial = func(ctx context.Context, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout, LocalAddr: laddr}
	return dialer.DialContext(ctx, "tcp", addr)
}

var jitter = mox.NewRand()

var queueDB *bstore.DB

// Msg is a message in the queue.
type Msg struct {
	ID                 int64
	Queued             time.Time      `bstore:"default now"`
	SenderAccount      string         // Failures are delivered back to this local account.
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
	Has8bit            bool  // Whether message contains bytes with high bit set, determines whether 8BITMIME SMTP extension is needed.
	SMTPUTF8           bool  // Whether message requires use of SMTPUTF8.
	Size               int64 // Full size of message, combined MsgPrefix with contents of message file.
	MsgPrefix          []byte
	DSNUTF8            []byte // If set, this message is a DSN and this is a version using utf-8, for the case the remote MTA supports smtputf8. In this case, Size and MsgPrefix are not relevant.
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
	queueDB, err = bstore.Open(qpath, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, Msg{})
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
	err := queueDB.Close()
	xlog.Check(err, "closing queue db")
	queueDB = nil
}

// List returns all messages in the delivery queue.
// Ordered by earliest delivery attempt first.
func List() ([]Msg, error) {
	qmsgs, err := bstore.QueryDB[Msg](queueDB).List()
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
func Count() (int, error) {
	return bstore.QueryDB[Msg](queueDB).Count()
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
func Add(log *mlog.Log, senderAccount string, mailFrom, rcptTo smtp.Path, has8bit, smtputf8 bool, size int64, msgPrefix []byte, msgFile *os.File, dsnutf8Opt []byte, consumeFile bool) error {
	// todo: Add should accept multiple rcptTo if they are for the same domain. so we can queue them for delivery in one (or just a few) session(s), transferring the data only once. ../rfc/5321:3759

	tx, err := queueDB.Begin(true)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if tx != nil {
			if err := tx.Rollback(); err != nil {
				log.Errorx("rollback for queue", err)
			}
		}
	}()

	now := time.Now()
	qm := Msg{0, now, senderAccount, mailFrom.Localpart, mailFrom.IPDomain, rcptTo.Localpart, rcptTo.IPDomain, formatIPDomain(rcptTo.IPDomain), 0, nil, now, nil, "", has8bit, smtputf8, size, msgPrefix, dsnutf8Opt}

	if err := tx.Insert(&qm); err != nil {
		return err
	}

	dst := mox.DataDirPath(filepath.Join("queue", store.MessagePath(qm.ID)))
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
			return fmt.Errorf("move message into queue dir: %w", err)
		}
	} else if err := os.Link(msgFile.Name(), dst); err != nil {
		// Assume file system does not support hardlinks. Copy it instead.
		if err := writeFile(dst, &moxio.AtReader{R: msgFile}); err != nil {
			return fmt.Errorf("copying message to new file: %s", err)
		}
	}

	if err := moxio.SyncDir(dstDir); err != nil {
		return fmt.Errorf("sync directory: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %s", err)
	}
	tx = nil
	dst = ""

	queuekick()
	return nil
}

// write contents of r to new file dst, for delivering a message.
func writeFile(dst string, r io.Reader) error {
	df, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0660)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer func() {
		if df != nil {
			err := df.Close()
			xlog.Check(err, "closing file after failed write")
		}
	}()
	if _, err := io.Copy(df, r); err != nil {
		return fmt.Errorf("copy: %s", err)
	} else if err := df.Sync(); err != nil {
		return fmt.Errorf("sync: %s", err)
	} else if err := df.Close(); err != nil {
		return fmt.Errorf("close: %s", err)
	}
	df = nil
	return nil
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

// Kick sets the NextAttempt for messages matching all parameters that are nonzero,
// and kicks the queue, attempting delivery of those messages. If all parameters
// are zero, all messages are kicked.
// Returns number of messages queued for immediate delivery.
func Kick(ID int64, toDomain string, recipient string) (int, error) {
	q := bstore.QueryDB[Msg](queueDB)
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
	n, err := q.UpdateNonzero(Msg{NextAttempt: time.Now()})
	if err != nil {
		return 0, fmt.Errorf("selecting and updating messages in queue: %v", err)
	}
	queuekick()
	return n, nil
}

// Drop removes messages from the queue that match all nonzero parameters.
// If all parameters are zero, all messages are removed.
// Returns number of messages removed.
func Drop(ID int64, toDomain string, recipient string) (int, error) {
	q := bstore.QueryDB[Msg](queueDB)
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
	n, err := q.Delete()
	if err != nil {
		return 0, fmt.Errorf("selecting and deleting messages from queue: %v", err)
	}
	return n, nil
}

// OpenMessage opens a message present in the queue.
func OpenMessage(id int64) (io.ReadCloser, error) {
	qm := Msg{ID: id}
	err := queueDB.Get(&qm)
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
			timer.Reset(nextWork(busyDomains))
		}
	}()
	return nil
}

func nextWork(busyDomains map[string]struct{}) time.Duration {
	q := bstore.QueryDB[Msg](queueDB)
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
	q := bstore.QueryDB[Msg](queueDB)
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
		mox.Sleep(mox.Context, 1*time.Second)
		return -1
	}

	for _, m := range msgs {
		busyDomains[formatIPDomain(m.RecipientDomain)] = struct{}{}
		go deliver(resolver, m)
	}
	return len(msgs)
}

// Remove message from queue in database and file system.
func queueDelete(msgID int64) error {
	if err := queueDB.Delete(&Msg{ID: msgID}); err != nil {
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
	qlog := xlog.WithCid(cid).Fields(mlog.Field("from", m.Sender()), mlog.Field("recipient", m.Recipient()), mlog.Field("attempts", m.Attempts), mlog.Field("msgID", m.ID))

	defer func() {
		deliveryResult <- formatIPDomain(m.RecipientDomain)

		x := recover()
		if x != nil {
			qlog.Error("deliver panic", mlog.Field("panic", x))
			debug.PrintStack()
			metrics.PanicInc("queue")
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
	qup := bstore.QueryDB[Msg](queueDB)
	qup.FilterID(m.ID)
	update := Msg{Attempts: m.Attempts, NextAttempt: m.NextAttempt, LastAttempt: m.LastAttempt}
	if _, err := qup.UpdateNonzero(update); err != nil {
		qlog.Errorx("storing delivery attempt", err)
		return
	}

	fail := func(permanent bool, remoteMTA dsn.NameIP, secodeOpt, errmsg string) {
		if permanent || m.Attempts >= 8 {
			qlog.Errorx("permanent failure delivering from queue", errors.New(errmsg))
			queueDSNFailure(qlog, m, remoteMTA, secodeOpt, errmsg)

			if err := queueDelete(m.ID); err != nil {
				qlog.Errorx("deleting message from queue after permanent failure", err)
			}
			return
		}

		qup := bstore.QueryDB[Msg](queueDB)
		qup.FilterID(m.ID)
		if _, err := qup.UpdateNonzero(Msg{LastError: errmsg, DialedIPs: m.DialedIPs}); err != nil {
			qlog.Errorx("storing delivery error", err, mlog.Field("deliveryError", errmsg))
		}

		if m.Attempts == 5 {
			// We've attempted deliveries at these intervals: 0, 7.5m, 15m, 30m, 1h, 2u.
			// Let sender know delivery is delayed.
			qlog.Errorx("temporary failure delivering from queue, sending delayed dsn", errors.New(errmsg), mlog.Field("backoff", backoff))

			retryUntil := m.LastAttempt.Add((4 + 8 + 16) * time.Hour)
			queueDSNDelay(qlog, m, remoteMTA, secodeOpt, errmsg, retryUntil)
		} else {
			qlog.Errorx("temporary failure delivering from queue", errors.New(errmsg), mlog.Field("backoff", backoff), mlog.Field("nextattempt", m.NextAttempt))
		}
	}

	hosts, effectiveDomain, permanent, err := gatherHosts(resolver, m, cid, qlog)
	if err != nil {
		fail(permanent, dsn.NameIP{}, "", err.Error())
		return
	}

	// Check for MTA-STS policy and enforce it if needed. We have to check the
	// effective domain (found after following CNAME record(s)): there will certainly
	// not be an mtasts record for the original recipient domain, because that is not
	// allowed when a CNAME record is present.
	var policyFresh bool
	var policy *mtasts.Policy
	tlsModeDefault := smtpclient.TLSOpportunistic
	if !effectiveDomain.IsZero() {
		cidctx := context.WithValue(mox.Context, mlog.CidKey, cid)
		policy, policyFresh, err = mtastsdb.Get(cidctx, resolver, effectiveDomain)
		if err != nil {
			// No need to refuse to deliver if we have some mtasts error.
			qlog.Infox("mtasts failed, continuing with strict tls requirement", err, mlog.Field("domain", effectiveDomain))
			tlsModeDefault = smtpclient.TLSStrict
			return
		}
		// note: policy can be nil, if a domain does not implement MTA-STS or its the first
		// time we fetch the policy and it we encountered an error.
	}

	// We try delivery to each record until we have success or a permanent failure. So
	// for transient errors, we'll try the next MX record. For MX records pointing to a
	// dual stack host, we turn a permanent failure due to policy on the first delivery
	// attempt into a temporary failure and make sure to try the other address family
	// the next attempt. This should reduce issues due to one of our IPs being on a
	// block list. We won't try multiple IPs of the same address family. Surprisingly,
	// RFC 5321 does not specify a clear algorithm, but common practicie is probably
	// ../rfc/3974:268.
	var remoteMTA dsn.NameIP
	var secodeOpt, errmsg string
	permanent = false
	mtastsFailure := true
	// todo: should make distinction between host permanently not accepting the message, and the message not being deliverable permanently. e.g. a mx host may have a size limit, or not accept 8bitmime, while another host in the list does accept the message. same for smtputf8, ../rfc/6531:555
	for _, h := range hosts {
		var badTLS, ok bool

		// ../rfc/8461:913
		if policy != nil && policy.Mode == mtasts.ModeEnforce && !policy.Matches(h.Domain) {
			errmsg = fmt.Sprintf("mx host %v does not match enforced mta-sts policy", h.Domain)
			qlog.Error("mx host does not match enforce mta-sts policy, skipping", mlog.Field("host", h.Domain))
			continue
		}

		qlog.Info("delivering to remote", mlog.Field("remote", h), mlog.Field("queuecid", cid))
		cid := mox.Cid()
		nqlog := qlog.WithCid(cid)
		var remoteIP net.IP
		tlsMode := tlsModeDefault
		if policy != nil && policy.Mode == mtasts.ModeEnforce {
			tlsMode = smtpclient.TLSStrict
		}
		permanent, badTLS, secodeOpt, remoteIP, errmsg, ok = deliverHost(nqlog, resolver, cid, h, &m, tlsMode)
		if !ok && badTLS && tlsMode == smtpclient.TLSOpportunistic {
			// In case of failure with opportunistic TLS, try again without TLS. ../rfc/7435:459
			// todo future: revisit this decision. perhaps it should be a configuration option that defaults to not doing this?
			nqlog.Info("connecting again for delivery attempt without tls")
			permanent, badTLS, secodeOpt, remoteIP, errmsg, ok = deliverHost(nqlog, resolver, cid, h, &m, smtpclient.TLSSkip)
		}
		if ok {
			nqlog.Info("delivered from queue")
			if err := queueDelete(m.ID); err != nil {
				nqlog.Errorx("deleting message from queue after delivery", err)
			}
			return
		}
		remoteMTA = dsn.NameIP{Name: h.XString(false), IP: remoteIP}
		if !badTLS {
			mtastsFailure = false
		}
		if permanent {
			break
		}
	}
	if mtastsFailure && policyFresh {
		permanent = true
	}

	fail(permanent, remoteMTA, secodeOpt, errmsg)
}

var (
	errCNAMELoop  = errors.New("cname loop")
	errCNAMELimit = errors.New("too many cname records")
	errNoRecord   = errors.New("no dns record")
	errDNS        = errors.New("dns lookup error")
	errNoMail     = errors.New("domain does not accept email as indicated with single dot for mx record")
)

// Gather hosts to try to deliver to. We start with the straight-forward MX record.
// If that does not exist, we'll look for CNAME of the entire domain (following
// chains if needed). If a CNAME does not exist, but the domain name has an A or
// AAAA record, we'll try delivery directly to that host.
// ../rfc/5321:3824
func gatherHosts(resolver dns.Resolver, m Msg, cid int64, qlog *mlog.Log) (hosts []dns.IPDomain, effectiveDomain dns.Domain, permanent bool, err error) {
	if len(m.RecipientDomain.IP) > 0 {
		return []dns.IPDomain{m.RecipientDomain}, effectiveDomain, false, nil
	}

	// We start out delivering to the recipient domain. We follow CNAMEs a few times.
	rcptDomain := m.RecipientDomain.Domain
	// Domain we are actually delivering to, after following CNAME record(s).
	effectiveDomain = rcptDomain
	domainsSeen := map[string]bool{}
	for i := 0; ; i++ {
		if domainsSeen[effectiveDomain.ASCII] {
			return nil, effectiveDomain, true, fmt.Errorf("%w: recipient domain %s: already saw %s", errCNAMELoop, rcptDomain, effectiveDomain)
		}
		domainsSeen[effectiveDomain.ASCII] = true

		// note: The Go resolver returns the requested name if the domain has no CNAME record but has a host record.
		if i == 16 {
			// We have a maximum number of CNAME records we follow. There is no hard limit for
			// DNS, and you might think folks wouldn't configure CNAME chains at all, but for
			// (non-mail) domains, CNAME chains of 10 records have been encountered according
			// to the internet.
			return nil, effectiveDomain, true, fmt.Errorf("%w: recipient domain %s, last resolved domain %s", errCNAMELimit, rcptDomain, effectiveDomain)
		}

		cidctx := context.WithValue(mox.Context, mlog.CidKey, cid)
		ctx, cancel := context.WithTimeout(cidctx, 30*time.Second)
		defer cancel()
		// Note: LookupMX can return an error and still return records: Invalid records are
		// filtered out and an error returned. We must process any records that are valid.
		// Only if all are unusable will we return an error. ../rfc/5321:3851
		mxl, err := resolver.LookupMX(ctx, effectiveDomain.ASCII+".")
		cancel()
		if err != nil && len(mxl) == 0 {
			if !dns.IsNotFound(err) {
				return nil, effectiveDomain, false, fmt.Errorf("%w: mx lookup for %s: %v", errDNS, effectiveDomain, err)
			}

			// No MX record. First attempt CNAME lookup. ../rfc/5321:3838 ../rfc/3974:197
			cname, err := resolver.LookupCNAME(ctx, effectiveDomain.ASCII+".")
			if err != nil && !dns.IsNotFound(err) {
				return nil, effectiveDomain, false, fmt.Errorf("%w: cname lookup for %s: %v", errDNS, effectiveDomain, err)
			}
			if err == nil && cname != effectiveDomain.ASCII+"." {
				d, err := dns.ParseDomain(strings.TrimSuffix(cname, "."))
				if err != nil {
					return nil, effectiveDomain, true, fmt.Errorf("%w: parsing cname domain %s: %v", errDNS, effectiveDomain, err)
				}
				effectiveDomain = d
				// Start again with new domain.
				continue
			}

			// See if the host exists. If so, attempt delivery directly to host. ../rfc/5321:3842
			ctx, cancel = context.WithTimeout(cidctx, 30*time.Second)
			defer cancel()
			_, err = resolver.LookupHost(ctx, effectiveDomain.ASCII+".")
			cancel()
			if dns.IsNotFound(err) {
				return nil, effectiveDomain, true, fmt.Errorf("%w: recipient domain/host %v", errNoRecord, effectiveDomain)
			} else if err != nil {
				return nil, effectiveDomain, false, fmt.Errorf("%w: looking up host %v because of no mx record: %v", errDNS, effectiveDomain, err)
			}
			hosts = []dns.IPDomain{{Domain: effectiveDomain}}
		} else if err != nil {
			qlog.Infox("partial mx failure, attempting delivery to valid mx records", err)
		}

		// ../rfc/7505:122
		if err == nil && len(mxl) == 1 && mxl[0].Host == "." {
			return nil, effectiveDomain, true, errNoMail
		}

		// The Go resolver already sorts by preference, randomizing records of same
		// preference. ../rfc/5321:3885
		for _, mx := range mxl {
			host, err := dns.ParseDomain(strings.TrimSuffix(mx.Host, "."))
			if err != nil {
				// note: should not happen because Go resolver already filters these out.
				return nil, effectiveDomain, true, fmt.Errorf("%w: invalid host name in mx record %q: %v", errDNS, mx.Host, err)
			}
			hosts = append(hosts, dns.IPDomain{Domain: host})
		}
		if len(hosts) > 0 {
			err = nil
		}
		return hosts, effectiveDomain, false, err
	}
}

// deliverHost attempts to deliver m to host.
// deliverHost updated m.DialedIPs, which must be saved in case of failure to deliver.
func deliverHost(log *mlog.Log, resolver dns.Resolver, cid int64, host dns.IPDomain, m *Msg, tlsMode smtpclient.TLSMode) (permanent, badTLS bool, secodeOpt string, remoteIP net.IP, errmsg string, ok bool) {
	// About attempting delivery to multiple addresses of a host: ../rfc/5321:3898

	start := time.Now()
	var deliveryResult string
	defer func() {
		metricDeliveryHost.WithLabelValues(fmt.Sprintf("%d", m.Attempts), string(tlsMode), deliveryResult).Observe(float64(time.Since(start)) / float64(time.Second))
		log.Debug("queue deliverhost result", mlog.Field("host", host), mlog.Field("attempt", m.Attempts), mlog.Field("tlsmode", tlsMode), mlog.Field("permanent", permanent), mlog.Field("badTLS", badTLS), mlog.Field("secodeOpt", secodeOpt), mlog.Field("errmsg", errmsg), mlog.Field("ok", ok), mlog.Field("duration", time.Since(start)))
	}()

	f, err := os.Open(m.MessagePath())
	if err != nil {
		return false, false, "", nil, fmt.Sprintf("open message file: %s", err), false
	}
	msgr := store.FileMsgReader(m.MsgPrefix, f)
	defer func() {
		err := msgr.Close()
		log.Check(err, "closing message after delivery attempt")
	}()

	cidctx := context.WithValue(mox.Context, mlog.CidKey, cid)
	ctx, cancel := context.WithTimeout(cidctx, 30*time.Second)
	defer cancel()

	conn, ip, dualstack, err := dialHost(ctx, log, resolver, host, m)
	remoteIP = ip
	cancel()
	var result string
	switch {
	case err == nil:
		result = "ok"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		result = "timeout"
	case errors.Is(err, context.Canceled):
		result = "canceled"
	default:
		result = "error"
	}
	metricConnection.WithLabelValues(result).Inc()
	if err != nil {
		log.Debugx("connecting to remote smtp", err, mlog.Field("host", host))
		return false, false, "", ip, fmt.Sprintf("dialing smtp server: %v", err), false
	}

	var mailFrom string
	if m.SenderLocalpart != "" || !m.SenderDomain.IsZero() {
		mailFrom = m.Sender().XString(m.SMTPUTF8)
	}
	rcptTo := m.Recipient().XString(m.SMTPUTF8)

	// todo future: get closer to timeouts specified in rfc? ../rfc/5321:3610
	log = log.Fields(mlog.Field("remoteip", ip))
	ctx, cancel = context.WithTimeout(cidctx, 30*time.Minute)
	defer cancel()
	mox.Connections.Register(conn, "smtpclient", "queue")
	sc, err := smtpclient.New(ctx, log, conn, tlsMode, host.String(), "")
	defer func() {
		if sc == nil {
			conn.Close()
		} else {
			sc.Close()
		}
		mox.Connections.Unregister(conn)
	}()
	if err == nil {
		has8bit := m.Has8bit
		smtputf8 := m.SMTPUTF8
		var msg io.Reader = msgr
		size := m.Size
		if m.DSNUTF8 != nil && sc.Supports8BITMIME() && sc.SupportsSMTPUTF8() {
			has8bit = true
			smtputf8 = true
			size = int64(len(m.DSNUTF8))
			msg = bytes.NewReader(m.DSNUTF8)
		}
		err = sc.Deliver(ctx, mailFrom, rcptTo, size, msg, has8bit, smtputf8)
	}
	if err != nil {
		log.Infox("delivery failed", err)
	}
	var cerr smtpclient.Error
	switch {
	case err == nil:
		deliveryResult = "ok"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		deliveryResult = "timeout"
	case errors.Is(err, context.Canceled):
		deliveryResult = "canceled"
	case errors.As(err, &cerr):
		deliveryResult = "temperror"
		if cerr.Permanent {
			deliveryResult = "permerror"
		}
	default:
		deliveryResult = "error"
	}
	if err == nil {
		return false, false, "", ip, "", true
	} else if cerr, ok := err.(smtpclient.Error); ok {
		// If we are being rejected due to policy reasons on the first
		// attempt and remote has both IPv4 and IPv6, we'll give it
		// another try. Our first IP may be in a block list, the address for
		// the other family perhaps is not.
		permanent := cerr.Permanent
		if permanent && m.Attempts == 1 && dualstack && strings.HasPrefix(cerr.Secode, "7.") {
			permanent = false
		}
		return permanent, errors.Is(cerr, smtpclient.ErrTLS), cerr.Secode, ip, cerr.Error(), false
	} else {
		return false, errors.Is(cerr, smtpclient.ErrTLS), "", ip, err.Error(), false
	}
}

// dialHost dials host for delivering Msg, taking previous attempts into accounts.
// If the previous attempt used IPv4, this attempt will use IPv6 (in case one of the IPs is in a DNSBL).
// The second attempt for an address family we prefer the same IP as earlier, to increase our chances if remote is doing greylisting.
// dialHost updates m with the dialed IP and m should be saved in case of failure.
// If we have fully specified local smtp listen IPs, we set those for the outgoing
// connection. The admin probably configured these same IPs in SPF, but others
// possibly not.
func dialHost(ctx context.Context, log *mlog.Log, resolver dns.Resolver, host dns.IPDomain, m *Msg) (conn net.Conn, ip net.IP, dualstack bool, rerr error) {
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
		addr := net.JoinHostPort(ip.String(), "25")
		log.Debug("dialing remote smtp", mlog.Field("addr", addr))
		var laddr net.Addr
		for _, lip := range mox.Conf.Static.SpecifiedSMTPListenIPs {
			ipIs4 := ip.To4() != nil
			lipIs4 := lip.To4() != nil
			if ipIs4 == lipIs4 {
				laddr = &net.TCPAddr{IP: lip}
				break
			}
		}
		conn, err := dial(ctx, timeout, addr, laddr)
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
