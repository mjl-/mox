// Package queue is in charge of outgoing messages, queueing them when submitted,
// attempting a first delivery over SMTP, retrying with backoff and sending DSNs
// for delayed or failed deliveries.
package queue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
)

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
			"tlsmode",   // immediate, requiredstarttls, opportunistic, skip (from smtpclient.TLSMode), with optional +mtasts and/or +dane.
			"result",    // ok, timeout, canceled, temperror, permerror, error
		},
	)
	metricHold = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "mox_queue_hold",
			Help: "Messages in queue that are on hold.",
		},
	)
)

var jitter = mox.NewPseudoRand()

var DBTypes = []any{Msg{}, HoldRule{}} // Types stored in DB.
var DB *bstore.DB                      // Exported for making backups.

// Allow requesting delivery starting from up to this interval from time of submission.
const FutureReleaseIntervalMax = 60 * 24 * time.Hour

// Set for mox localserve, to prevent queueing.
var Localserve bool

// HoldRule is a set of conditions that cause a matching message to be marked as on
// hold when it is queued. All-empty conditions matches all messages, effectively
// pausing the entire queue.
type HoldRule struct {
	ID                 int64
	Account            string
	SenderDomain       dns.Domain
	RecipientDomain    dns.Domain
	SenderDomainStr    string // Unicode.
	RecipientDomainStr string // Unicode.
}

func (pr HoldRule) All() bool {
	pr.ID = 0
	return pr == HoldRule{}
}

func (pr HoldRule) matches(m Msg) bool {
	return pr.All() || pr.Account == m.SenderAccount || pr.SenderDomainStr == m.SenderDomainStr || pr.RecipientDomainStr == m.RecipientDomainStr
}

// Msg is a message in the queue.
//
// Use MakeMsg to make a message with fields that Add needs. Add will further set
// queueing related fields.
type Msg struct {
	ID int64

	// A message for multiple recipients will get a BaseID that is identical to the
	// first Msg.ID queued. The message contents will be identical for each recipient,
	// including MsgPrefix. If other properties are identical too, including recipient
	// domain, multiple Msgs may be delivered in a single SMTP transaction. For
	// messages with a single recipient, this field will be 0.
	BaseID int64 `bstore:"index"`

	Queued             time.Time      `bstore:"default now"`
	Hold               bool           // If set, delivery won't be attempted.
	SenderAccount      string         // Failures are delivered back to this local account. Also used for routing.
	SenderLocalpart    smtp.Localpart // Should be a local user and domain.
	SenderDomain       dns.IPDomain
	SenderDomainStr    string         // For filtering, unicode.
	RecipientLocalpart smtp.Localpart // Typically a remote user and domain.
	RecipientDomain    dns.IPDomain
	RecipientDomainStr string              // For filtering, unicode.
	Attempts           int                 // Next attempt is based on last attempt and exponential back off based on attempts.
	MaxAttempts        int                 // Max number of attempts before giving up. If 0, then the default of 8 attempts is used instead.
	DialedIPs          map[string][]net.IP // For each host, the IPs that were dialed. Used for IP selection for later attempts.
	NextAttempt        time.Time           // For scheduling.
	LastAttempt        *time.Time
	LastError          string

	Has8bit       bool   // Whether message contains bytes with high bit set, determines whether 8BITMIME SMTP extension is needed.
	SMTPUTF8      bool   // Whether message requires use of SMTPUTF8.
	IsDMARCReport bool   // Delivery failures for DMARC reports are handled differently.
	IsTLSReport   bool   // Delivery failures for TLS reports are handled differently.
	Size          int64  // Full size of message, combined MsgPrefix with contents of message file.
	MessageID     string // Used when composing a DSN, in its References header.
	MsgPrefix     []byte

	// If set, this message is a DSN and this is a version using utf-8, for the case
	// the remote MTA supports smtputf8. In this case, Size and MsgPrefix are not
	// relevant.
	DSNUTF8 []byte

	// If non-empty, the transport to use for this message. Can be set through cli or
	// admin interface. If empty (the default for a submitted message), regular routing
	// rules apply.
	Transport string

	// RequireTLS influences TLS verification during delivery.
	//
	// If nil, the recipient domain policy is followed (MTA-STS and/or DANE), falling
	// back to optional opportunistic non-verified STARTTLS.
	//
	// If RequireTLS is true (through SMTP REQUIRETLS extension or webmail submit),
	// MTA-STS or DANE is required, as well as REQUIRETLS support by the next hop
	// server.
	//
	// If RequireTLS is false (through messag header "TLS-Required: No"), the recipient
	// domain's policy is ignored if it does not lead to a successful TLS connection,
	// i.e. falling back to SMTP delivery with unverified STARTTLS or plain text.
	RequireTLS *bool
	// ../rfc/8689:250

	// For DSNs, where the original FUTURERELEASE value must be included as per-message
	// field. This field should be of the form "for;" plus interval, or "until;" plus
	// utc date-time.
	FutureReleaseRequest string
	// ../rfc/4865:305
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
	qpath := mox.DataDirPath(filepath.FromSlash("queue/index.db"))
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
	metricHoldUpdate()
	return nil
}

// When we update the gauge, we just get the full current value, not try to account
// for adds/removes.
func metricHoldUpdate() {
	count, err := bstore.QueryDB[Msg](context.Background(), DB).FilterNonzero(Msg{Hold: true}).Count()
	if err != nil {
		mlog.New("queue", nil).Errorx("querying number of queued messages that are on hold", err)
	}
	metricHold.Set(float64(count))
}

// Shutdown closes the queue database. The delivery process isn't stopped. For tests only.
func Shutdown() {
	err := DB.Close()
	if err != nil {
		mlog.New("queue", nil).Errorx("closing queue db", err)
	}
	DB = nil
}

// Filter filters messages to list or operate on. Used by admin web interface
// and cli.
//
// Only non-empty/non-zero values are applied to the filter. Leaving all fields
// empty/zero matches all messages.
type Filter struct {
	IDs         []int64
	Account     string
	From        string
	To          string
	Hold        *bool
	Submitted   string // Whether submitted before/after a time relative to now. ">$duration" or "<$duration", also with "now" for duration.
	NextAttempt string // ">$duration" or "<$duration", also with "now" for duration.
	Transport   *string
}

func (f Filter) apply(q *bstore.Query[Msg]) error {
	if len(f.IDs) > 0 {
		q.FilterIDs(f.IDs)
	}
	applyTime := func(field string, s string) error {
		orig := s
		var before bool
		if strings.HasPrefix(s, "<") {
			before = true
		} else if !strings.HasPrefix(s, ">") {
			return fmt.Errorf(`must start with "<" for before or ">" for after a duration`)
		}
		s = s[1:]
		var t time.Time
		if s == "now" {
			t = time.Now()
		} else if d, err := time.ParseDuration(s); err != nil {
			return fmt.Errorf("parsing duration %q: %v", orig, err)
		} else {
			t = time.Now().Add(d)
		}
		if before {
			q.FilterLess(field, t)
		} else {
			q.FilterGreater(field, t)
		}
		return nil
	}
	if f.Hold != nil {
		q.FilterEqual("Hold", *f.Hold)
	}
	if f.Submitted != "" {
		if err := applyTime("Queued", f.Submitted); err != nil {
			return fmt.Errorf("applying filter for submitted: %v", err)
		}
	}
	if f.NextAttempt != "" {
		if err := applyTime("NextAttempt", f.NextAttempt); err != nil {
			return fmt.Errorf("applying filter for next attempt: %v", err)
		}
	}
	if f.Account != "" {
		q.FilterNonzero(Msg{SenderAccount: f.Account})
	}
	if f.Transport != nil {
		q.FilterEqual("Transport", *f.Transport)
	}
	if f.From != "" || f.To != "" {
		q.FilterFn(func(m Msg) bool {
			return f.From != "" && strings.Contains(m.Sender().XString(true), f.From) || f.To != "" && strings.Contains(m.Recipient().XString(true), f.To)
		})
	}
	return nil
}

// List returns all messages in the delivery queue.
// Ordered by earliest delivery attempt first.
func List(ctx context.Context, f Filter) ([]Msg, error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := f.apply(q); err != nil {
		return nil, err
	}
	qmsgs, err := q.List()
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

// HoldRuleList returns all hold rules.
func HoldRuleList(ctx context.Context) ([]HoldRule, error) {
	return bstore.QueryDB[HoldRule](ctx, DB).List()
}

// HoldRuleAdd adds a new hold rule causing newly submitted messages to be marked
// as "on hold", and existing matching messages too.
func HoldRuleAdd(ctx context.Context, log mlog.Log, hr HoldRule) (HoldRule, error) {
	err := DB.Write(ctx, func(tx *bstore.Tx) error {
		hr.ID = 0
		hr.SenderDomainStr = hr.SenderDomain.Name()
		hr.RecipientDomainStr = hr.RecipientDomain.Name()
		if err := tx.Insert(&hr); err != nil {
			return err
		}
		log.Info("adding hold rule", slog.Any("holdrule", hr))

		q := bstore.QueryTx[Msg](tx)
		if !hr.All() {
			q.FilterNonzero(Msg{
				SenderAccount:      hr.Account,
				SenderDomainStr:    hr.SenderDomainStr,
				RecipientDomainStr: hr.RecipientDomainStr,
			})
		}
		n, err := q.UpdateField("Hold", true)
		if err != nil {
			return fmt.Errorf("marking existing matching messages in queue on hold: %v", err)
		}
		log.Info("marked messages in queue as on hold", slog.Int("messages", n))
		return nil
	})
	if err != nil {
		return HoldRule{}, err
	}
	queuekick()
	metricHoldUpdate()
	return hr, nil
}

// HoldRuleRemove removes a hold rule. The Hold field of existing messages are not
// changed.
func HoldRuleRemove(ctx context.Context, log mlog.Log, holdRuleID int64) error {
	return DB.Write(ctx, func(tx *bstore.Tx) error {
		hr := HoldRule{ID: holdRuleID}
		if err := tx.Get(&hr); err != nil {
			return err
		}
		log.Info("removing hold rule", slog.Any("holdrule", hr))
		return tx.Delete(HoldRule{ID: holdRuleID})
	})
}

// MakeMsg is a convenience function that sets the commonly used fields for a Msg.
func MakeMsg(sender, recipient smtp.Path, has8bit, smtputf8 bool, size int64, messageID string, prefix []byte, requireTLS *bool, next time.Time) Msg {
	return Msg{
		SenderLocalpart:    sender.Localpart,
		SenderDomain:       sender.IPDomain,
		RecipientLocalpart: recipient.Localpart,
		RecipientDomain:    recipient.IPDomain,
		Has8bit:            has8bit,
		SMTPUTF8:           smtputf8,
		Size:               size,
		MessageID:          messageID,
		MsgPrefix:          prefix,
		RequireTLS:         requireTLS,
		Queued:             time.Now(),
		NextAttempt:        next,
	}
}

// Add one or more new messages to the queue. They'll get the same BaseID, so they
// can be delivered in a single SMTP transaction, with a single DATA command, but
// may be split into multiple transactions if errors/limits are encountered. The
// queue is kicked immediately to start a first delivery attempt.
//
// ID of the messagse must be 0 and will be set after inserting in the queue.
//
// Add sets derived fields like SenderDomainStr and RecipientDomainStr, and fields
// related to queueing, such as Queued, NextAttempt, LastAttempt, LastError.
func Add(ctx context.Context, log mlog.Log, senderAccount string, msgFile *os.File, qml ...Msg) error {
	if len(qml) == 0 {
		return fmt.Errorf("must queue at least one message")
	}

	for i, qm := range qml {
		if qm.ID != 0 {
			return fmt.Errorf("id of queued messages must be 0")
		}
		// Sanity check, internal consistency.
		qml[i].SenderDomainStr = formatIPDomain(qm.SenderDomain)
		qml[i].RecipientDomainStr = formatIPDomain(qm.RecipientDomain)
	}

	if Localserve {
		if senderAccount == "" {
			return fmt.Errorf("cannot queue with localserve without local account")
		}
		acc, err := store.OpenAccount(log, senderAccount)
		if err != nil {
			return fmt.Errorf("opening sender account for immediate delivery with localserve: %v", err)
		}
		defer func() {
			err := acc.Close()
			log.Check(err, "closing account")
		}()
		conf, _ := acc.Conf()
		err = nil
		acc.WithWLock(func() {
			for i, qm := range qml {
				qml[i].SenderAccount = senderAccount
				m := store.Message{Size: qm.Size, MsgPrefix: qm.MsgPrefix}
				dest := conf.Destinations[qm.Sender().String()]
				err = acc.DeliverDestination(log, dest, &m, msgFile)
				if err != nil {
					err = fmt.Errorf("delivering message: %v", err)
					return // Returned again outside WithWLock.
				}
			}
		})
		if err == nil {
			log.Debug("immediately delivered from queue to sender")
		}
		return err
	}

	tx, err := DB.Begin(ctx, true)
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

	// Mark messages Hold if they match a hold rule.
	holdRules, err := bstore.QueryTx[HoldRule](tx).List()
	if err != nil {
		return fmt.Errorf("getting queue hold rules")
	}

	// Insert messages into queue. If there are multiple messages, they all get a
	// non-zero BaseID that is the Msg.ID of the first message inserted.
	var baseID int64
	for i := range qml {
		qml[i].SenderAccount = senderAccount
		qml[i].BaseID = baseID
		for _, hr := range holdRules {
			if hr.matches(qml[i]) {
				qml[i].Hold = true
				break
			}
		}
		if err := tx.Insert(&qml[i]); err != nil {
			return err
		}
		if i == 0 && len(qml) > 1 {
			baseID = qml[i].ID
			qml[i].BaseID = baseID
			if err := tx.Update(&qml[i]); err != nil {
				return err
			}
		}
	}

	var paths []string
	defer func() {
		for _, p := range paths {
			err := os.Remove(p)
			log.Check(err, "removing destination message file for queue", slog.String("path", p))
		}
	}()

	for _, qm := range qml {
		dst := qm.MessagePath()
		paths = append(paths, dst)
		dstDir := filepath.Dir(dst)
		os.MkdirAll(dstDir, 0770)
		if err := moxio.LinkOrCopy(log, dst, msgFile.Name(), nil, true); err != nil {
			return fmt.Errorf("linking/copying message to new file: %s", err)
		} else if err := moxio.SyncDir(log, dstDir); err != nil {
			return fmt.Errorf("sync directory: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %s", err)
	}
	tx = nil
	paths = nil

	for _, m := range qml {
		if m.Hold {
			metricHoldUpdate()
			break
		}
	}

	queuekick()

	return nil
}

func formatIPDomain(d dns.IPDomain) string {
	if len(d.IP) > 0 {
		return "[" + d.IP.String() + "]"
	}
	return d.Domain.Name()
}

var (
	kick            = make(chan struct{}, 1)
	deliveryResults = make(chan string, 1)
)

func queuekick() {
	select {
	case kick <- struct{}{}:
	default:
	}
}

// NextAttemptAdd adds a duration to the NextAttempt for all matching messages, and
// kicks the queue.
func NextAttemptAdd(ctx context.Context, f Filter, d time.Duration) (affected int, err error) {
	err = DB.Write(ctx, func(tx *bstore.Tx) error {
		q := bstore.QueryDB[Msg](ctx, DB)
		if err := f.apply(q); err != nil {
			return err
		}
		var msgs []Msg
		msgs, err := q.List()
		if err != nil {
			return fmt.Errorf("listing matching messages: %v", err)
		}
		for _, m := range msgs {
			m.NextAttempt = m.NextAttempt.Add(d)
			if err := tx.Update(&m); err != nil {
				return err
			}
		}
		affected = len(msgs)
		return nil
	})
	if err != nil {
		return 0, err
	}
	queuekick()
	return affected, nil
}

// NextAttemptSet sets NextAttempt for all matching messages to a new time, and
// kicks the queue.
func NextAttemptSet(ctx context.Context, f Filter, t time.Time) (affected int, err error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := f.apply(q); err != nil {
		return 0, err
	}
	n, err := q.UpdateNonzero(Msg{NextAttempt: t})
	if err != nil {
		return 0, fmt.Errorf("selecting and updating messages in queue: %v", err)
	}
	queuekick()
	return n, nil
}

// HoldSet sets Hold for all matching messages and kicks the queue.
func HoldSet(ctx context.Context, f Filter, hold bool) (affected int, err error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := f.apply(q); err != nil {
		return 0, err
	}
	n, err := q.UpdateFields(map[string]any{"Hold": hold})
	if err != nil {
		return 0, fmt.Errorf("selecting and updating messages in queue: %v", err)
	}
	queuekick()
	metricHoldUpdate()
	return n, nil
}

// TransportSet changes the transport to use for the matching messages.
func TransportSet(ctx context.Context, f Filter, transport string) (affected int, err error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := f.apply(q); err != nil {
		return 0, err
	}
	n, err := q.UpdateFields(map[string]any{"Transport": transport})
	if err != nil {
		return 0, fmt.Errorf("selecting and updating messages in queue: %v", err)
	}
	queuekick()
	return n, nil
}

// Fail marks matching messages as failed for delivery and delivers DSNs to the sender.
func Fail(ctx context.Context, log mlog.Log, f Filter) (affected int, err error) {
	err = DB.Write(ctx, func(tx *bstore.Tx) error {
		q := bstore.QueryTx[Msg](tx)
		if err := f.apply(q); err != nil {
			return err
		}
		var msgs []Msg
		q.Gather(&msgs)
		n, err := q.Delete()
		if err != nil {
			return fmt.Errorf("selecting and deleting messages from queue: %v", err)
		}

		var remoteMTA dsn.NameIP
		for _, m := range msgs {
			if m.LastAttempt == nil {
				now := time.Now()
				m.LastAttempt = &now
			}
			deliverDSNFailure(ctx, log, m, remoteMTA, "", "delivery canceled by admin", nil)
		}
		affected = n
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("selecting and updating messages in queue: %v", err)
	}
	queuekick()
	metricHoldUpdate()
	return affected, nil
}

// Drop removes matching messages from the queue.
// Returns number of messages removed.
func Drop(ctx context.Context, log mlog.Log, f Filter) (affected int, err error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := f.apply(q); err != nil {
		return 0, err
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
			log.Errorx("removing queue message from file system", err, slog.Int64("queuemsgid", m.ID), slog.String("path", p))
		}
	}
	queuekick()
	metricHoldUpdate()
	return n, nil
}

// RequireTLSSet updates the RequireTLS field of matching messages.
func RequireTLSSet(ctx context.Context, f Filter, requireTLS *bool) (affected int, err error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := f.apply(q); err != nil {
		return 0, err
	}
	n, err := q.UpdateFields(map[string]any{"RequireTLS": requireTLS})
	queuekick()
	return n, err
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

	log := mlog.New("queue", nil)

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
			case domain := <-deliveryResults:
				delete(busyDomains, domain)
			}

			if len(busyDomains) >= maxConcurrentDeliveries {
				continue
			}

			launchWork(log, resolver, busyDomains)
			timer.Reset(nextWork(mox.Shutdown, log, busyDomains))
		}
	}()
	return nil
}

func nextWork(ctx context.Context, log mlog.Log, busyDomains map[string]struct{}) time.Duration {
	q := bstore.QueryDB[Msg](ctx, DB)
	if len(busyDomains) > 0 {
		var doms []any
		for d := range busyDomains {
			doms = append(doms, d)
		}
		q.FilterNotEqual("RecipientDomainStr", doms...)
	}
	q.FilterEqual("Hold", false)
	q.SortAsc("NextAttempt")
	q.Limit(1)
	qm, err := q.Get()
	if err == bstore.ErrAbsent {
		return 24 * time.Hour
	} else if err != nil {
		log.Errorx("finding time for next delivery attempt", err)
		return 1 * time.Minute
	}
	return time.Until(qm.NextAttempt)
}

func launchWork(log mlog.Log, resolver dns.Resolver, busyDomains map[string]struct{}) int {
	q := bstore.QueryDB[Msg](mox.Shutdown, DB)
	q.FilterLessEqual("NextAttempt", time.Now())
	q.FilterEqual("Hold", false)
	q.SortAsc("NextAttempt")
	q.Limit(maxConcurrentDeliveries)
	if len(busyDomains) > 0 {
		var doms []any
		for d := range busyDomains {
			doms = append(doms, d)
		}
		q.FilterNotEqual("RecipientDomainStr", doms...)
	}
	var msgs []Msg
	seen := map[string]bool{}
	err := q.ForEach(func(m Msg) error {
		dom := m.RecipientDomainStr
		if _, ok := busyDomains[dom]; !ok && !seen[dom] {
			seen[dom] = true
			msgs = append(msgs, m)
		}
		return nil
	})
	if err != nil {
		log.Errorx("querying for work in queue", err)
		mox.Sleep(mox.Shutdown, 1*time.Second)
		return -1
	}

	for _, m := range msgs {
		busyDomains[m.RecipientDomainStr] = struct{}{}
		go deliver(log, resolver, m)
	}
	return len(msgs)
}

// Remove message from queue in database and file system.
func queueDelete(ctx context.Context, msgIDs ...int64) error {
	err := DB.Write(ctx, func(tx *bstore.Tx) error {
		for _, id := range msgIDs {
			if err := tx.Delete(&Msg{ID: id}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// If removing from database fails, we'll also leave the file in the file system.

	var errs []string
	for _, id := range msgIDs {
		p := mox.DataDirPath(filepath.Join("queue", store.MessagePath(id)))
		if err := os.Remove(p); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", p, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("removing message files from queue: %s", strings.Join(errs, "; "))
	}
	return nil
}

// deliver attempts to deliver a message.
// The queue is updated, either by removing a delivered or permanently failed
// message, or updating the time for the next attempt. A DSN may be sent.
func deliver(log mlog.Log, resolver dns.Resolver, m Msg) {
	ctx := mox.Shutdown

	qlog := log.WithCid(mox.Cid()).With(
		slog.Any("from", m.Sender()),
		slog.Int("attempts", m.Attempts))

	defer func() {
		deliveryResults <- formatIPDomain(m.RecipientDomain)

		x := recover()
		if x != nil {
			qlog.Error("deliver panic", slog.Any("panic", x), slog.Int64("msgid", m.ID), slog.Any("recipient", m.Recipient()))
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
	origNextAttempt := m.NextAttempt
	now := time.Now()
	m.LastAttempt = &now
	m.NextAttempt = now.Add(backoff)
	qup := bstore.QueryDB[Msg](mox.Shutdown, DB)
	qup.FilterID(m.ID)
	update := Msg{Attempts: m.Attempts, NextAttempt: m.NextAttempt, LastAttempt: m.LastAttempt}
	if _, err := qup.UpdateNonzero(update); err != nil {
		qlog.Errorx("storing delivery attempt", err, slog.Int64("msgid", m.ID), slog.Any("recipient", m.Recipient()))
		return
	}

	resolveTransport := func(mm Msg) (string, config.Transport, bool) {
		if mm.Transport != "" {
			transport, ok := mox.Conf.Static.Transports[mm.Transport]
			if !ok {
				return "", config.Transport{}, false
			}
			return mm.Transport, transport, ok
		}
		route := findRoute(mm.Attempts, mm)
		return route.Transport, route.ResolvedTransport, true
	}

	// Find route for transport to use for delivery attempt.
	m.Attempts--
	transportName, transport, transportOK := resolveTransport(m)
	m.Attempts++
	if !transportOK {
		var remoteMTA dsn.NameIP // Zero value, will not be included in DSN. ../rfc/3464:1027
		fail(ctx, qlog, []*Msg{&m}, m.DialedIPs, backoff, remoteMTA, fmt.Errorf("cannot find transport %q", m.Transport))
		return
	}

	if transportName != "" {
		qlog = qlog.With(slog.String("transport", transportName))
		qlog.Debug("delivering with transport")
	}

	// Attempt to gather more recipients for this identical message, only with the same
	// recipient domain, and under the same conditions (recipientdomain, attempts,
	// requiretls, transport). ../rfc/5321:3759
	msgs := []*Msg{&m}
	if m.BaseID != 0 {
		err := DB.Write(mox.Shutdown, func(tx *bstore.Tx) error {
			q := bstore.QueryTx[Msg](tx)
			q.FilterNonzero(Msg{BaseID: m.BaseID, RecipientDomainStr: m.RecipientDomainStr, Attempts: m.Attempts - 1})
			q.FilterNotEqual("ID", m.ID)
			q.FilterLessEqual("NextAttempt", origNextAttempt)
			q.FilterEqual("Hold", false)
			err := q.ForEach(func(xm Msg) error {
				mrtls := m.RequireTLS != nil
				xmrtls := xm.RequireTLS != nil
				if mrtls != xmrtls || mrtls && *m.RequireTLS != *xm.RequireTLS {
					return nil
				}
				tn, _, ok := resolveTransport(xm)
				if ok && tn == transportName {
					msgs = append(msgs, &xm)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("looking up more recipients: %v", err)
			}

			// Mark these additional messages as attempted too.
			for _, mm := range msgs[1:] {
				mm.Attempts++
				mm.NextAttempt = m.NextAttempt
				mm.LastAttempt = m.LastAttempt
				if err := tx.Update(mm); err != nil {
					return fmt.Errorf("updating more message recipients for smtp transaction: %v", err)
				}
			}
			return nil
		})
		if err != nil {
			qlog.Errorx("error finding more recipients for message, will attempt to send to single recipient", err)
			msgs = msgs[:1]
		}
	}
	if len(msgs) > 1 {
		ids := make([]int64, len(msgs))
		rcpts := make([]smtp.Path, len(msgs))
		for i, m := range msgs {
			ids[i] = m.ID
			rcpts[i] = m.Recipient()
		}
		qlog.Debug("delivering to multiple recipients", slog.Any("msgids", ids), slog.Any("recipients", rcpts))
	} else {
		qlog.Debug("delivering to single recipient", slog.Any("msgid", m.ID), slog.Any("recipient", m.Recipient()))
	}

	// We gather TLS connection successes and failures during delivery, and we store
	// them in tlsrptdb. Every 24 hours we send an email with a report to the recipient
	// domains that opt in via a TLSRPT DNS record.  For us, the tricky part is
	// collecting all reporting information. We've got several TLS modes
	// (opportunistic, DANE and/or MTA-STS (PKIX), overrides due to Require TLS).
	// Failures can happen at various levels: MTA-STS policies (apply to whole delivery
	// attempt/domain), MX targets (possibly multiple per delivery attempt, both for
	// MTA-STS and DANE).
	//
	// Once the SMTP client has tried a TLS handshake, we register success/failure,
	// regardless of what happens next on the connection. We also register failures
	// when they happen before we get to the SMTP client, but only if they are related
	// to TLS (and some DNSSEC).
	var recipientDomainResult tlsrpt.Result
	var hostResults []tlsrpt.Result
	defer func() {
		if mox.Conf.Static.NoOutgoingTLSReports || m.RecipientDomain.IsIP() {
			return
		}

		now := time.Now()
		dayUTC := now.UTC().Format("20060102")

		// See if this contains a failure. If not, we'll mark TLS results for delivering
		// DMARC reports SendReport false, so we won't as easily get into a report sending
		// loop.
		var failure bool
		for _, result := range hostResults {
			if result.Summary.TotalFailureSessionCount > 0 {
				failure = true
				break
			}
		}
		if recipientDomainResult.Summary.TotalFailureSessionCount > 0 {
			failure = true
		}

		results := make([]tlsrptdb.TLSResult, 0, 1+len(hostResults))
		tlsaPolicyDomains := map[string]bool{}
		addResult := func(r tlsrpt.Result, isHost bool) {
			var zerotype tlsrpt.PolicyType
			if r.Policy.Type == zerotype {
				return
			}

			// Ensure we store policy domain in unicode in database.
			policyDomain, err := dns.ParseDomain(r.Policy.Domain)
			if err != nil {
				qlog.Errorx("parsing policy domain for tls result", err, slog.String("policydomain", r.Policy.Domain))
				return
			}

			if r.Policy.Type == tlsrpt.TLSA {
				tlsaPolicyDomains[policyDomain.ASCII] = true
			}

			tlsResult := tlsrptdb.TLSResult{
				PolicyDomain:    policyDomain.Name(),
				DayUTC:          dayUTC,
				RecipientDomain: m.RecipientDomain.Domain.Name(),
				IsHost:          isHost,
				SendReport:      !m.IsTLSReport && (!m.IsDMARCReport || failure),
				Results:         []tlsrpt.Result{r},
			}
			results = append(results, tlsResult)
		}
		for _, result := range hostResults {
			addResult(result, true)
		}
		// If we were delivering to a mail host directly (not a domain with MX records), we
		// are more likely to get a TLSA policy than an STS policy. Don't potentially
		// confuse operators with both a tlsa and no-policy-found result.
		// todo spec: ../rfc/8460:440 an explicit no-sts-policy result would be useful.
		if recipientDomainResult.Policy.Type != tlsrpt.NoPolicyFound || !tlsaPolicyDomains[recipientDomainResult.Policy.Domain] {
			addResult(recipientDomainResult, false)
		}

		if len(results) > 0 {
			err := tlsrptdb.AddTLSResults(context.Background(), results)
			qlog.Check(err, "adding tls results to database for upcoming tlsrpt report")
		}
	}()

	var dialer smtpclient.Dialer = &net.Dialer{}
	if transport.Submissions != nil {
		deliverSubmit(qlog, resolver, dialer, msgs, backoff, transportName, transport.Submissions, true, 465)
	} else if transport.Submission != nil {
		deliverSubmit(qlog, resolver, dialer, msgs, backoff, transportName, transport.Submission, false, 587)
	} else if transport.SMTP != nil {
		// todo future: perhaps also gather tlsrpt results for submissions.
		deliverSubmit(qlog, resolver, dialer, msgs, backoff, transportName, transport.SMTP, false, 25)
	} else {
		ourHostname := mox.Conf.Static.HostnameDomain
		if transport.Socks != nil {
			socksdialer, err := proxy.SOCKS5("tcp", transport.Socks.Address, nil, &net.Dialer{})
			if err != nil {
				fail(ctx, qlog, msgs, msgs[0].DialedIPs, backoff, dsn.NameIP{}, fmt.Errorf("socks dialer: %v", err))
				return
			} else if d, ok := socksdialer.(smtpclient.Dialer); !ok {
				fail(ctx, qlog, msgs, msgs[0].DialedIPs, backoff, dsn.NameIP{}, fmt.Errorf("socks dialer is not a contextdialer"))
				return
			} else {
				dialer = d
			}
			ourHostname = transport.Socks.Hostname
		}
		recipientDomainResult, hostResults = deliverDirect(qlog, resolver, dialer, ourHostname, transportName, msgs, backoff)
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

// Returns string representing delivery result for err, and number of delivered and
// failed messages.
//
// Values: ok, okpartial, timeout, canceled, temperror, permerror, error.
func deliveryResult(err error, delivered, failed int) string {
	var cerr smtpclient.Error
	switch {
	case err == nil:
		if delivered == 0 {
			return "error"
		} else if failed > 0 {
			return "okpartial"
		}
		return "ok"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &cerr):
		if cerr.Permanent {
			return "permerror"
		}
		return "temperror"
	}
	return "error"
}
