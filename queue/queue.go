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
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
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
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
	"github.com/mjl-/mox/webapi"
	"github.com/mjl-/mox/webhook"
)

// ErrFromID indicate a fromid was present when adding a message to the queue, but
// it wasn't unique.
var ErrFromID = errors.New("fromid not unique")

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

var DBTypes = []any{Msg{}, HoldRule{}, MsgRetired{}, webapi.Suppression{}, Hook{}, HookRetired{}} // Types stored in DB.
var DB *bstore.DB                                                                                 // Exported for making backups.

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
	FromID             string         // For transactional messages, used to match later DSNs.
	RecipientLocalpart smtp.Localpart // Typically a remote user and domain.
	RecipientDomain    dns.IPDomain
	RecipientDomainStr string              // For filtering, unicode domain. Can also contain ip enclosed in [].
	Attempts           int                 // Next attempt is based on last attempt and exponential back off based on attempts.
	MaxAttempts        int                 // Max number of attempts before giving up. If 0, then the default of 8 attempts is used instead.
	DialedIPs          map[string][]net.IP // For each host, the IPs that were dialed. Used for IP selection for later attempts.
	NextAttempt        time.Time           // For scheduling.
	LastAttempt        *time.Time
	Results            []MsgResult

	Has8bit       bool   // Whether message contains bytes with high bit set, determines whether 8BITMIME SMTP extension is needed.
	SMTPUTF8      bool   // Whether message requires use of SMTPUTF8.
	IsDMARCReport bool   // Delivery failures for DMARC reports are handled differently.
	IsTLSReport   bool   // Delivery failures for TLS reports are handled differently.
	Size          int64  // Full size of message, combined MsgPrefix with contents of message file.
	MessageID     string // Message-ID header, including <>. Used when composing a DSN, in its References header.
	MsgPrefix     []byte // Data to send before the contents from the file, typically with headers like DKIM-Signature.
	Subject       string // For context about delivery.

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

	Extra map[string]string // Extra information, for transactional email.
}

// MsgResult is the result (or work in progress) of a delivery attempt.
type MsgResult struct {
	Start    time.Time
	Duration time.Duration
	Success  bool
	Code     int
	Secode   string
	Error    string
	// todo: store smtp trace for failed deliveries for debugging, perhaps also for successful deliveries.
}

// Stored in MsgResult.Error while delivery is in progress. Replaced after success/error.
const resultErrorDelivering = "delivering..."

// markResult updates/adds a delivery result.
func (m *Msg) markResult(code int, secode string, errmsg string, success bool) {
	if len(m.Results) == 0 || m.Results[len(m.Results)-1].Error != resultErrorDelivering {
		m.Results = append(m.Results, MsgResult{Start: time.Now()})
	}
	result := &m.Results[len(m.Results)-1]
	result.Duration = time.Since(result.Start)
	result.Code = code
	result.Secode = secode
	result.Error = errmsg
	result.Success = success
}

// LastResult returns the last result entry, or an empty result.
func (m *Msg) LastResult() MsgResult {
	if len(m.Results) == 0 {
		return MsgResult{Start: time.Now()}
	}
	return m.Results[len(m.Results)-1]
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

// todo: store which transport (if any) was actually used in MsgResult, based on routes.

// Retired returns a MsgRetired for the message, for history of deliveries.
func (m Msg) Retired(success bool, t, keepUntil time.Time) MsgRetired {
	return MsgRetired{
		ID:                   m.ID,
		BaseID:               m.BaseID,
		Queued:               m.Queued,
		SenderAccount:        m.SenderAccount,
		SenderLocalpart:      m.SenderLocalpart,
		SenderDomainStr:      m.SenderDomainStr,
		FromID:               m.FromID,
		RecipientLocalpart:   m.RecipientLocalpart,
		RecipientDomain:      m.RecipientDomain,
		RecipientDomainStr:   m.RecipientDomainStr,
		Attempts:             m.Attempts,
		MaxAttempts:          m.MaxAttempts,
		DialedIPs:            m.DialedIPs,
		LastAttempt:          m.LastAttempt,
		Results:              m.Results,
		Has8bit:              m.Has8bit,
		SMTPUTF8:             m.SMTPUTF8,
		IsDMARCReport:        m.IsDMARCReport,
		IsTLSReport:          m.IsTLSReport,
		Size:                 m.Size,
		MessageID:            m.MessageID,
		Subject:              m.Subject,
		Transport:            m.Transport,
		RequireTLS:           m.RequireTLS,
		FutureReleaseRequest: m.FutureReleaseRequest,
		Extra:                m.Extra,

		RecipientAddress: smtp.Path{Localpart: m.RecipientLocalpart, IPDomain: m.RecipientDomain}.XString(true),
		Success:          success,
		LastActivity:     t,
		KeepUntil:        keepUntil,
	}
}

// MsgRetired is a message for which delivery completed, either successful,
// failed/canceled. Retired messages are only stored if so configured, and will be
// cleaned up after the configured period.
type MsgRetired struct {
	ID int64 // Same ID as it was as Msg.ID.

	BaseID             int64
	Queued             time.Time
	SenderAccount      string         // Failures are delivered back to this local account. Also used for routing.
	SenderLocalpart    smtp.Localpart // Should be a local user and domain.
	SenderDomainStr    string         // For filtering, unicode.
	FromID             string         `bstore:"index"` // Used to match DSNs.
	RecipientLocalpart smtp.Localpart // Typically a remote user and domain.
	RecipientDomain    dns.IPDomain
	RecipientDomainStr string              // For filtering, unicode.
	Attempts           int                 // Next attempt is based on last attempt and exponential back off based on attempts.
	MaxAttempts        int                 // Max number of attempts before giving up. If 0, then the default of 8 attempts is used instead.
	DialedIPs          map[string][]net.IP // For each host, the IPs that were dialed. Used for IP selection for later attempts.
	LastAttempt        *time.Time
	Results            []MsgResult

	Has8bit       bool   // Whether message contains bytes with high bit set, determines whether 8BITMIME SMTP extension is needed.
	SMTPUTF8      bool   // Whether message requires use of SMTPUTF8.
	IsDMARCReport bool   // Delivery failures for DMARC reports are handled differently.
	IsTLSReport   bool   // Delivery failures for TLS reports are handled differently.
	Size          int64  // Full size of message, combined MsgPrefix with contents of message file.
	MessageID     string // Used when composing a DSN, in its References header.
	Subject       string // For context about delivery.

	Transport            string
	RequireTLS           *bool
	FutureReleaseRequest string

	Extra map[string]string // Extra information, for transactional email.

	LastActivity     time.Time `bstore:"index"`
	RecipientAddress string    `bstore:"index RecipientAddress+LastActivity"`
	Success          bool      // Whether delivery to next hop succeeded.
	KeepUntil        time.Time `bstore:"index"`
}

// Sender of message as used in MAIL FROM.
func (m MsgRetired) Sender() (path smtp.Path, err error) {
	path.Localpart = m.RecipientLocalpart
	if strings.HasPrefix(m.SenderDomainStr, "[") && strings.HasSuffix(m.SenderDomainStr, "]") {
		s := m.SenderDomainStr[1 : len(m.SenderDomainStr)-1]
		path.IPDomain.IP = net.ParseIP(s)
		if path.IPDomain.IP == nil {
			err = fmt.Errorf("parsing ip address %q: %v", s, err)
		}
	} else {
		path.IPDomain.Domain, err = dns.ParseDomain(m.SenderDomainStr)
	}
	return
}

// Recipient of message as used in RCPT TO.
func (m MsgRetired) Recipient() smtp.Path {
	return smtp.Path{Localpart: m.RecipientLocalpart, IPDomain: m.RecipientDomain}
}

// LastResult returns the last result entry, or an empty result.
func (m MsgRetired) LastResult() MsgResult {
	if len(m.Results) == 0 {
		return MsgResult{}
	}
	return m.Results[len(m.Results)-1]
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
	log := mlog.New("queue", nil)
	opts := bstore.Options{Timeout: 5 * time.Second, Perm: 0660, RegisterLogger: moxvar.RegisterLogger(qpath, log.Logger)}
	DB, err = bstore.Open(mox.Shutdown, qpath, &opts, DBTypes...)
	if err == nil {
		err = DB.Read(mox.Shutdown, func(tx *bstore.Tx) error {
			return metricHoldUpdate(tx)
		})
	}
	if err != nil {
		if isNew {
			err := os.Remove(qpath)
			log.Check(err, "removing new queue database file after error")
		}
		return fmt.Errorf("open queue database: %s", err)
	}
	return nil
}

// When we update the gauge, we just get the full current value, not try to account
// for adds/removes.
func metricHoldUpdate(tx *bstore.Tx) error {
	count, err := bstore.QueryTx[Msg](tx).FilterNonzero(Msg{Hold: true}).Count()
	if err != nil {
		return fmt.Errorf("querying messages on hold for metric: %v", err)
	}
	metricHold.Set(float64(count))
	return nil
}

// Shutdown closes the queue database. The delivery process isn't stopped. For tests only.
func Shutdown() {
	err := DB.Close()
	if err != nil {
		mlog.New("queue", nil).Errorx("closing queue db", err)
	}
	DB = nil
}

// todo: the filtering & sorting can use improvements. too much duplicated code (variants between {Msg,Hook}{,Retired}. Sort has pagination fields, some untyped.

// Filter filters messages to list or operate on. Used by admin web interface
// and cli.
//
// Only non-empty/non-zero values are applied to the filter. Leaving all fields
// empty/zero matches all messages.
type Filter struct {
	Max         int
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
		s = strings.TrimSpace(s[1:])
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
	if f.Max != 0 {
		q.Limit(f.Max)
	}
	return nil
}

type Sort struct {
	Field  string // "Queued" or "NextAttempt"/"".
	LastID int64  // If > 0, we return objects beyond this, less/greater depending on Asc.
	Last   any    // Value of Field for last object. Must be set iff LastID is set.
	Asc    bool   // Ascending, or descending.
}

func (s Sort) apply(q *bstore.Query[Msg]) error {
	switch s.Field {
	case "", "NextAttempt":
		s.Field = "NextAttempt"
	case "Queued":
		s.Field = "Queued"
	default:
		return fmt.Errorf("unknown sort order field %q", s.Field)
	}

	if s.LastID > 0 {
		ls, ok := s.Last.(string)
		if !ok {
			return fmt.Errorf("last should be string with time, not %T %q", s.Last, s.Last)
		}
		last, err := time.Parse(time.RFC3339Nano, ls)
		if err != nil {
			last, err = time.Parse(time.RFC3339, ls)
		}
		if err != nil {
			return fmt.Errorf("parsing last %q as time: %v", s.Last, err)
		}
		q.FilterNotEqual("ID", s.LastID)
		var fieldEqual func(m Msg) bool
		if s.Field == "NextAttempt" {
			fieldEqual = func(m Msg) bool { return m.NextAttempt.Equal(last) }
		} else {
			fieldEqual = func(m Msg) bool { return m.Queued.Equal(last) }
		}
		if s.Asc {
			q.FilterGreaterEqual(s.Field, last)
			q.FilterFn(func(m Msg) bool {
				return !fieldEqual(m) || m.ID > s.LastID
			})
		} else {
			q.FilterLessEqual(s.Field, last)
			q.FilterFn(func(m Msg) bool {
				return !fieldEqual(m) || m.ID < s.LastID
			})
		}
	}
	if s.Asc {
		q.SortAsc(s.Field, "ID")
	} else {
		q.SortDesc(s.Field, "ID")
	}
	return nil
}

// List returns max 100 messages matching filter in the delivery queue.
// By default, orders by next delivery attempt.
func List(ctx context.Context, filter Filter, sort Sort) ([]Msg, error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := filter.apply(q); err != nil {
		return nil, err
	}
	if err := sort.apply(q); err != nil {
		return nil, err
	}
	qmsgs, err := q.List()
	if err != nil {
		return nil, err
	}
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
	var n int
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
		var err error
		n, err = q.UpdateField("Hold", true)
		if err != nil {
			return fmt.Errorf("marking existing matching messages in queue on hold: %v", err)
		}
		return metricHoldUpdate(tx)
	})
	if err != nil {
		return HoldRule{}, err
	}
	log.Info("marked messages in queue as on hold", slog.Int("messages", n))
	msgqueueKick()
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
// messageID should include <>.
func MakeMsg(sender, recipient smtp.Path, has8bit, smtputf8 bool, size int64, messageID string, prefix []byte, requireTLS *bool, next time.Time, subject string) Msg {
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
		Subject:            subject,
		RequireTLS:         requireTLS,
		Queued:             time.Now(),
		NextAttempt:        next,
	}
}

// Add one or more new messages to the queue. If the sender paths and MsgPrefix are
// identical, they'll get the same BaseID, so they can be delivered in a single
// SMTP transaction, with a single DATA command, but may be split into multiple
// transactions if errors/limits are encountered. The queue is kicked immediately
// to start a first delivery attempt.
//
// ID of the messagse must be 0 and will be set after inserting in the queue.
//
// Add sets derived fields like SenderDomainStr and RecipientDomainStr, and fields
// related to queueing, such as Queued, NextAttempt.
func Add(ctx context.Context, log mlog.Log, senderAccount string, msgFile *os.File, qml ...Msg) error {
	if len(qml) == 0 {
		return fmt.Errorf("must queue at least one message")
	}

	base := true

	for i, qm := range qml {
		if qm.ID != 0 {
			return fmt.Errorf("id of queued messages must be 0")
		}
		// Sanity check, internal consistency.
		qml[i].SenderDomainStr = formatIPDomain(qm.SenderDomain)
		qml[i].RecipientDomainStr = formatIPDomain(qm.RecipientDomain)
		if base && i > 0 && qm.Sender().String() != qml[0].Sender().String() || !bytes.Equal(qm.MsgPrefix, qml[0].MsgPrefix) {
			base = false
		}
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

	// Insert messages into queue. If multiple messages are to be delivered in a single
	// transaction, they all get a non-zero BaseID that is the Msg.ID of the first
	// message inserted.
	var baseID int64
	for i := range qml {
		// FromIDs must be unique if present. We don't have a unique index because values
		// can be the empty string. We check in both Msg and MsgRetired, both are relevant
		// for uniquely identifying a message sent in the past.
		if fromID := qml[i].FromID; fromID != "" {
			if exists, err := bstore.QueryTx[Msg](tx).FilterNonzero(Msg{FromID: fromID}).Exists(); err != nil {
				return fmt.Errorf("looking up fromid: %v", err)
			} else if exists {
				return fmt.Errorf("%w: fromid %q already present in message queue", ErrFromID, fromID)
			}
			if exists, err := bstore.QueryTx[MsgRetired](tx).FilterNonzero(MsgRetired{FromID: fromID}).Exists(); err != nil {
				return fmt.Errorf("looking up fromid: %v", err)
			} else if exists {
				return fmt.Errorf("%w: fromid %q already present in retired message queue", ErrFromID, fromID)
			}
		}

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
		if base && i == 0 && len(qml) > 1 {
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

	syncDirs := map[string]struct{}{}

	for _, qm := range qml {
		dst := qm.MessagePath()
		paths = append(paths, dst)

		dstDir := filepath.Dir(dst)
		if _, ok := syncDirs[dstDir]; !ok {
			os.MkdirAll(dstDir, 0770)
			syncDirs[dstDir] = struct{}{}
		}

		if err := moxio.LinkOrCopy(log, dst, msgFile.Name(), nil, true); err != nil {
			return fmt.Errorf("linking/copying message to new file: %s", err)
		}
	}

	for dir := range syncDirs {
		if err := moxio.SyncDir(log, dir); err != nil {
			return fmt.Errorf("sync directory: %v", err)
		}
	}

	for _, m := range qml {
		if m.Hold {
			if err := metricHoldUpdate(tx); err != nil {
				return err
			}
			break
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %s", err)
	}
	tx = nil
	paths = nil

	msgqueueKick()

	return nil
}

func formatIPDomain(d dns.IPDomain) string {
	if len(d.IP) > 0 {
		return "[" + d.IP.String() + "]"
	}
	return d.Domain.Name()
}

var (
	msgqueue        = make(chan struct{}, 1)
	deliveryResults = make(chan string, 1)
)

func kick() {
	msgqueueKick()
	hookqueueKick()
}

func msgqueueKick() {
	select {
	case msgqueue <- struct{}{}:
	default:
	}
}

// NextAttemptAdd adds a duration to the NextAttempt for all matching messages, and
// kicks the queue.
func NextAttemptAdd(ctx context.Context, filter Filter, d time.Duration) (affected int, err error) {
	err = DB.Write(ctx, func(tx *bstore.Tx) error {
		q := bstore.QueryTx[Msg](tx)
		if err := filter.apply(q); err != nil {
			return err
		}
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
	msgqueueKick()
	return affected, nil
}

// NextAttemptSet sets NextAttempt for all matching messages to a new time, and
// kicks the queue.
func NextAttemptSet(ctx context.Context, filter Filter, t time.Time) (affected int, err error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := filter.apply(q); err != nil {
		return 0, err
	}
	n, err := q.UpdateNonzero(Msg{NextAttempt: t})
	if err != nil {
		return 0, fmt.Errorf("selecting and updating messages in queue: %v", err)
	}
	msgqueueKick()
	return n, nil
}

// HoldSet sets Hold for all matching messages and kicks the queue.
func HoldSet(ctx context.Context, filter Filter, hold bool) (affected int, err error) {
	err = DB.Write(ctx, func(tx *bstore.Tx) error {
		q := bstore.QueryTx[Msg](tx)
		if err := filter.apply(q); err != nil {
			return err
		}
		n, err := q.UpdateFields(map[string]any{"Hold": hold})
		if err != nil {
			return fmt.Errorf("selecting and updating messages in queue: %v", err)
		}
		affected = n
		return metricHoldUpdate(tx)
	})
	if err != nil {
		return 0, err
	}
	msgqueueKick()
	return affected, nil
}

// TransportSet changes the transport to use for the matching messages.
func TransportSet(ctx context.Context, filter Filter, transport string) (affected int, err error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := filter.apply(q); err != nil {
		return 0, err
	}
	n, err := q.UpdateFields(map[string]any{"Transport": transport})
	if err != nil {
		return 0, fmt.Errorf("selecting and updating messages in queue: %v", err)
	}
	msgqueueKick()
	return n, nil
}

// Fail marks matching messages as failed for delivery, delivers a DSN to the
// sender, and sends a webhook.
//
// Returns number of messages removed, which can be non-zero even in case of an
// error.
func Fail(ctx context.Context, log mlog.Log, f Filter) (affected int, err error) {
	return failDrop(ctx, log, f, true)
}

// Drop removes matching messages from the queue. Messages are added as retired
// message, webhooks with the "canceled" event are queued.
//
// Returns number of messages removed, which can be non-zero even in case of an
// error.
func Drop(ctx context.Context, log mlog.Log, f Filter) (affected int, err error) {
	return failDrop(ctx, log, f, false)
}

func failDrop(ctx context.Context, log mlog.Log, filter Filter, fail bool) (affected int, err error) {
	var msgs []Msg
	err = DB.Write(ctx, func(tx *bstore.Tx) error {
		q := bstore.QueryTx[Msg](tx)
		if err := filter.apply(q); err != nil {
			return err
		}
		var err error
		msgs, err = q.List()
		if err != nil {
			return fmt.Errorf("getting messages to delete: %v", err)
		}

		if len(msgs) == 0 {
			return nil
		}

		now := time.Now()
		var remoteMTA dsn.NameIP
		for i := range msgs {
			result := MsgResult{
				Start: now,
				Error: "delivery canceled by admin",
			}
			msgs[i].Results = append(msgs[i].Results, result)
			if fail {
				if msgs[i].LastAttempt == nil {
					msgs[i].LastAttempt = &now
				}
				deliverDSNFailure(log, msgs[i], remoteMTA, "", result.Error, nil)
			}
		}
		event := webhook.EventCanceled
		if fail {
			event = webhook.EventFailed
		}
		if err := retireMsgs(log, tx, event, 0, "", nil, msgs...); err != nil {
			return fmt.Errorf("removing queue messages from database: %w", err)
		}
		return metricHoldUpdate(tx)
	})
	if err != nil {
		return 0, err
	}
	if len(msgs) > 0 {
		if err := removeMsgsFS(log, msgs...); err != nil {
			return len(msgs), fmt.Errorf("removing queue messages from file system: %w", err)
		}
	}
	kick()
	return len(msgs), nil
}

// RequireTLSSet updates the RequireTLS field of matching messages.
func RequireTLSSet(ctx context.Context, filter Filter, requireTLS *bool) (affected int, err error) {
	q := bstore.QueryDB[Msg](ctx, DB)
	if err := filter.apply(q); err != nil {
		return 0, err
	}
	n, err := q.UpdateFields(map[string]any{"RequireTLS": requireTLS})
	msgqueueKick()
	return n, err
}

// RetiredFilter filters messages to list or operate on. Used by admin web interface
// and cli.
//
// Only non-empty/non-zero values are applied to the filter. Leaving all fields
// empty/zero matches all messages.
type RetiredFilter struct {
	Max          int
	IDs          []int64
	Account      string
	From         string
	To           string
	Submitted    string // Whether submitted before/after a time relative to now. ">$duration" or "<$duration", also with "now" for duration.
	LastActivity string // ">$duration" or "<$duration", also with "now" for duration.
	Transport    *string
	Success      *bool
}

func (f RetiredFilter) apply(q *bstore.Query[MsgRetired]) error {
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
		s = strings.TrimSpace(s[1:])
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
	if f.Submitted != "" {
		if err := applyTime("Queued", f.Submitted); err != nil {
			return fmt.Errorf("applying filter for submitted: %v", err)
		}
	}
	if f.LastActivity != "" {
		if err := applyTime("LastActivity", f.LastActivity); err != nil {
			return fmt.Errorf("applying filter for last activity: %v", err)
		}
	}
	if f.Account != "" {
		q.FilterNonzero(MsgRetired{SenderAccount: f.Account})
	}
	if f.Transport != nil {
		q.FilterEqual("Transport", *f.Transport)
	}
	if f.From != "" || f.To != "" {
		q.FilterFn(func(m MsgRetired) bool {
			return f.From != "" && strings.Contains(m.SenderLocalpart.String()+"@"+m.SenderDomainStr, f.From) || f.To != "" && strings.Contains(m.Recipient().XString(true), f.To)
		})
	}
	if f.Success != nil {
		q.FilterEqual("Success", *f.Success)
	}
	if f.Max != 0 {
		q.Limit(f.Max)
	}
	return nil
}

type RetiredSort struct {
	Field  string // "Queued" or "LastActivity"/"".
	LastID int64  // If > 0, we return objects beyond this, less/greater depending on Asc.
	Last   any    // Value of Field for last object. Must be set iff LastID is set.
	Asc    bool   // Ascending, or descending.
}

func (s RetiredSort) apply(q *bstore.Query[MsgRetired]) error {
	switch s.Field {
	case "", "LastActivity":
		s.Field = "LastActivity"
	case "Queued":
		s.Field = "Queued"
	default:
		return fmt.Errorf("unknown sort order field %q", s.Field)
	}

	if s.LastID > 0 {
		ls, ok := s.Last.(string)
		if !ok {
			return fmt.Errorf("last should be string with time, not %T %q", s.Last, s.Last)
		}
		last, err := time.Parse(time.RFC3339Nano, ls)
		if err != nil {
			last, err = time.Parse(time.RFC3339, ls)
		}
		if err != nil {
			return fmt.Errorf("parsing last %q as time: %v", s.Last, err)
		}
		q.FilterNotEqual("ID", s.LastID)
		var fieldEqual func(m MsgRetired) bool
		if s.Field == "LastActivity" {
			fieldEqual = func(m MsgRetired) bool { return m.LastActivity.Equal(last) }
		} else {
			fieldEqual = func(m MsgRetired) bool { return m.Queued.Equal(last) }
		}
		if s.Asc {
			q.FilterGreaterEqual(s.Field, last)
			q.FilterFn(func(mr MsgRetired) bool {
				return !fieldEqual(mr) || mr.ID > s.LastID
			})
		} else {
			q.FilterLessEqual(s.Field, last)
			q.FilterFn(func(mr MsgRetired) bool {
				return !fieldEqual(mr) || mr.ID < s.LastID
			})
		}
	}
	if s.Asc {
		q.SortAsc(s.Field, "ID")
	} else {
		q.SortDesc(s.Field, "ID")
	}
	return nil
}

// RetiredList returns retired messages.
func RetiredList(ctx context.Context, filter RetiredFilter, sort RetiredSort) ([]MsgRetired, error) {
	q := bstore.QueryDB[MsgRetired](ctx, DB)
	if err := filter.apply(q); err != nil {
		return nil, err
	}
	if err := sort.apply(q); err != nil {
		return nil, err
	}
	return q.List()
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
const maxConcurrentHookDeliveries = 10

// Start opens the database by calling Init, then starts the delivery and cleanup
// processes.
func Start(resolver dns.Resolver, done chan struct{}) error {
	if err := Init(); err != nil {
		return err
	}

	go startQueue(resolver, done)
	go startHookQueue(done)

	go cleanupMsgRetired(done)
	go cleanupHookRetired(done)

	return nil
}

func cleanupMsgRetired(done chan struct{}) {
	log := mlog.New("queue", nil)

	defer func() {
		x := recover()
		if x != nil {
			log.Error("unhandled panic in cleanupMsgRetired", slog.Any("x", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Queue)
		}
	}()

	timer := time.NewTimer(3 * time.Second)
	for {
		select {
		case <-mox.Shutdown.Done():
			done <- struct{}{}
			return
		case <-timer.C:
		}

		cleanupMsgRetiredSingle(log)
		timer.Reset(time.Hour)
	}
}

func cleanupMsgRetiredSingle(log mlog.Log) {
	n, err := bstore.QueryDB[MsgRetired](mox.Shutdown, DB).FilterLess("KeepUntil", time.Now()).Delete()
	log.Check(err, "removing old retired messages")
	if n > 0 {
		log.Debug("cleaned up retired messages", slog.Int("count", n))
	}
}

func startQueue(resolver dns.Resolver, done chan struct{}) {
	// High-level delivery strategy advice: ../rfc/5321:3685
	log := mlog.New("queue", nil)

	// Map keys are either dns.Domain.Name()'s, or string-formatted IP addresses.
	busyDomains := map[string]struct{}{}

	timer := time.NewTimer(0)

	for {
		select {
		case <-mox.Shutdown.Done():
			for len(busyDomains) > 0 {
				domain := <-deliveryResults
				delete(busyDomains, domain)
			}
			done <- struct{}{}
			return
		case <-msgqueue:
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

// todo future: we may consider keeping message files around for a while after retiring. especially for failures to deliver. to inspect what exactly wasn't delivered.

func removeMsgsFS(log mlog.Log, msgs ...Msg) error {
	var errs []string
	for _, m := range msgs {
		p := mox.DataDirPath(filepath.Join("queue", store.MessagePath(m.ID)))
		if err := os.Remove(p); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", p, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("removing message files from queue: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Move one or more messages to retire list or remove it. Webhooks are scheduled.
// IDs of msgs in suppressedMsgIDs caused a suppression to be added.
//
// Callers should update Msg.Results before calling.
//
// Callers must remove the messages from the file system afterwards, see
// removeMsgsFS. Callers must also kick the message and webhook queues.
func retireMsgs(log mlog.Log, tx *bstore.Tx, event webhook.OutgoingEvent, code int, secode string, suppressedMsgIDs []int64, msgs ...Msg) error {
	now := time.Now()

	var hooks []Hook
	m0 := msgs[0]
	accConf, ok := mox.Conf.Account(m0.SenderAccount)
	var hookURL string
	if accConf.OutgoingWebhook != nil {
		hookURL = accConf.OutgoingWebhook.URL
	}
	log.Debug("retiring messages from queue", slog.Any("event", event), slog.String("account", m0.SenderAccount), slog.Bool("ok", ok), slog.String("webhookurl", hookURL))
	if hookURL != "" && (len(accConf.OutgoingWebhook.Events) == 0 || slices.Contains(accConf.OutgoingWebhook.Events, string(event))) {
		for _, m := range msgs {
			suppressing := slices.Contains(suppressedMsgIDs, m.ID)
			h, err := hookCompose(m, hookURL, accConf.OutgoingWebhook.Authorization, event, suppressing, code, secode)
			if err != nil {
				log.Errorx("composing webhooks while retiring messages from queue, not queueing hook for message", err, slog.Int64("msgid", m.ID), slog.Any("recipient", m.Recipient()))
			} else {
				hooks = append(hooks, h)
			}
		}
	}

	msgKeep := 24 * 7 * time.Hour
	hookKeep := 24 * 7 * time.Hour
	if ok {
		msgKeep = accConf.KeepRetiredMessagePeriod
		hookKeep = accConf.KeepRetiredWebhookPeriod
	}

	for _, m := range msgs {
		if err := tx.Delete(&m); err != nil {
			return err
		}
	}
	if msgKeep > 0 {
		for _, m := range msgs {
			rm := m.Retired(event == webhook.EventDelivered, now, now.Add(msgKeep))
			if err := tx.Insert(&rm); err != nil {
				return err
			}
		}
	}

	for i := range hooks {
		if err := hookInsert(tx, &hooks[i], now, hookKeep); err != nil {
			return fmt.Errorf("enqueueing webhooks while retiring messages from queue: %v", err)
		}
	}

	if len(hooks) > 0 {
		for _, h := range hooks {
			log.Debug("queued webhook while retiring message from queue", h.attrs()...)
		}
		hookqueueKick()
	}
	return nil
}

// deliver attempts to deliver a message.
// The queue is updated, either by removing a delivered or permanently failed
// message, or updating the time for the next attempt. A DSN may be sent.
func deliver(log mlog.Log, resolver dns.Resolver, m0 Msg) {
	ctx := mox.Shutdown

	qlog := log.WithCid(mox.Cid()).With(
		slog.Any("from", m0.Sender()),
		slog.Int("attempts", m0.Attempts+1))

	defer func() {
		deliveryResults <- formatIPDomain(m0.RecipientDomain)

		x := recover()
		if x != nil {
			qlog.Error("deliver panic", slog.Any("panic", x), slog.Int64("msgid", m0.ID), slog.Any("recipient", m0.Recipient()))
			debug.PrintStack()
			metrics.PanicInc(metrics.Queue)
		}
	}()

	// We'll use a single transaction for the various checks, committing as soon as
	// we're done with it.
	xtx, err := DB.Begin(mox.Shutdown, true)
	if err != nil {
		qlog.Errorx("transaction for gathering messages to deliver", err)
		return
	}
	defer func() {
		if xtx != nil {
			err := xtx.Rollback()
			qlog.Check(err, "rolling back transaction after error delivering")
		}
	}()

	// We register this attempt by setting LastAttempt, adding an empty Result, and
	// already setting NextAttempt in the future with exponential backoff. If we run
	// into trouble delivery below, at least we won't be bothering the receiving server
	// with our problems.
	// Delivery attempts: immediately, 7.5m, 15m, 30m, 1h, 2h (send delayed DSN), 4h,
	// 8h, 16h (send permanent failure DSN).
	// ../rfc/5321:3703
	// todo future: make the back off times configurable. ../rfc/5321:3713
	now := time.Now()
	var backoff time.Duration
	var origNextAttempt time.Time
	prepare := func() error {
		// Refresh message within transaction.
		m0 = Msg{ID: m0.ID}
		if err := xtx.Get(&m0); err != nil {
			return fmt.Errorf("get message to be delivered: %v", err)
		}

		backoff = time.Duration(7*60+30+jitter.IntN(10)-5) * time.Second
		for range m0.Attempts {
			backoff *= time.Duration(2)
		}
		m0.Attempts++
		origNextAttempt = m0.NextAttempt
		m0.LastAttempt = &now
		m0.NextAttempt = now.Add(backoff)
		m0.Results = append(m0.Results, MsgResult{Start: now, Error: resultErrorDelivering})
		if err := xtx.Update(&m0); err != nil {
			return fmt.Errorf("update message to be delivered: %v", err)
		}
		return nil
	}
	if err := prepare(); err != nil {
		qlog.Errorx("storing delivery attempt", err, slog.Int64("msgid", m0.ID), slog.Any("recipient", m0.Recipient()))
		return
	}

	var remoteMTA dsn.NameIP // Zero value, will not be included in DSN. ../rfc/3464:1027

	// If domain of sender is currently disabled, fail the delivery attempt.
	if domConf, _ := mox.Conf.Domain(m0.SenderDomain.Domain); domConf.Disabled {
		failMsgsTx(qlog, xtx, []*Msg{&m0}, m0.DialedIPs, backoff, remoteMTA, fmt.Errorf("domain of sender temporarily disabled"))
		err = xtx.Commit()
		qlog.Check(err, "commit processing failure to deliver messages")
		xtx = nil
		kick()
		return
	}

	// Check if recipient is on suppression list. If so, fail delivery.
	path := smtp.Path{Localpart: m0.RecipientLocalpart, IPDomain: m0.RecipientDomain}
	baseAddr := baseAddress(path).XString(true)
	qsup := bstore.QueryTx[webapi.Suppression](xtx)
	qsup.FilterNonzero(webapi.Suppression{Account: m0.SenderAccount, BaseAddress: baseAddr})
	exists, err := qsup.Exists()
	if err != nil || exists {
		if err != nil {
			qlog.Errorx("checking whether recipient address is in suppression list", err)
		} else {
			err := fmt.Errorf("not delivering to recipient address %s: %w", path.XString(true), errSuppressed)
			err = smtpclient.Error{Permanent: true, Err: err}
			failMsgsTx(qlog, xtx, []*Msg{&m0}, m0.DialedIPs, backoff, remoteMTA, err)
		}
		err = xtx.Commit()
		qlog.Check(err, "commit processing failure to deliver messages")
		xtx = nil
		kick()
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
	m0.Attempts--
	transportName, transport, transportOK := resolveTransport(m0)
	m0.Attempts++
	if !transportOK {
		failMsgsTx(qlog, xtx, []*Msg{&m0}, m0.DialedIPs, backoff, remoteMTA, fmt.Errorf("cannot find transport %q", m0.Transport))
		err = xtx.Commit()
		qlog.Check(err, "commit processing failure to deliver messages")
		xtx = nil
		kick()
		return
	}

	if transportName != "" {
		qlog = qlog.With(slog.String("transport", transportName))
		qlog.Debug("delivering with transport")
	}

	// Attempt to gather more recipients for this identical message, only with the same
	// recipient domain, and under the same conditions (recipientdomain, attempts,
	// requiretls, transport). ../rfc/5321:3759
	msgs := []*Msg{&m0}
	if m0.BaseID != 0 {
		gather := func() error {
			q := bstore.QueryTx[Msg](xtx)
			q.FilterNonzero(Msg{BaseID: m0.BaseID, RecipientDomainStr: m0.RecipientDomainStr, Attempts: m0.Attempts - 1})
			q.FilterNotEqual("ID", m0.ID)
			q.FilterLessEqual("NextAttempt", origNextAttempt)
			q.FilterEqual("Hold", false)
			err := q.ForEach(func(xm Msg) error {
				mrtls := m0.RequireTLS != nil
				xmrtls := xm.RequireTLS != nil
				if mrtls != xmrtls || mrtls && *m0.RequireTLS != *xm.RequireTLS {
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
				mm.NextAttempt = m0.NextAttempt
				mm.LastAttempt = m0.LastAttempt
				mm.Results = append(mm.Results, MsgResult{Start: now, Error: resultErrorDelivering})
				if err := xtx.Update(mm); err != nil {
					return fmt.Errorf("updating more message recipients for smtp transaction: %v", err)
				}
			}
			return nil
		}
		if err := gather(); err != nil {
			qlog.Errorx("error finding more recipients for message, will attempt to send to single recipient", err)
			msgs = msgs[:1]
		}
	}

	if err := xtx.Commit(); err != nil {
		qlog.Errorx("commit of preparation to deliver", err, slog.Any("msgid", m0.ID))
		return
	}
	xtx = nil

	if len(msgs) > 1 {
		ids := make([]int64, len(msgs))
		rcpts := make([]smtp.Path, len(msgs))
		for i, m := range msgs {
			ids[i] = m.ID
			rcpts[i] = m.Recipient()
		}
		qlog.Debug("delivering to multiple recipients", slog.Any("msgids", ids), slog.Any("recipients", rcpts))
	} else {
		qlog.Debug("delivering to single recipient", slog.Any("msgid", m0.ID), slog.Any("recipient", m0.Recipient()))
	}

	// Test for "Fail" transport before Localserve.
	if transport.Fail != nil {
		err := smtpclient.Error{
			Permanent: transport.Fail.Code/100 == 5,
			Code:      transport.Fail.Code,
			Secode:    smtp.SePol7Other0,
			Err:       fmt.Errorf("%s", transport.Fail.Message),
		}
		failMsgsDB(qlog, msgs, msgs[0].DialedIPs, backoff, dsn.NameIP{}, err)
		return
	}

	if Localserve {
		deliverLocalserve(ctx, qlog, msgs, backoff)
		return
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
		if mox.Conf.Static.NoOutgoingTLSReports || m0.RecipientDomain.IsIP() {
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
				RecipientDomain: m0.RecipientDomain.Domain.Name(),
				IsHost:          isHost,
				SendReport:      !m0.IsTLSReport && (!m0.IsDMARCReport || failure),
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
				failMsgsDB(qlog, msgs, msgs[0].DialedIPs, backoff, dsn.NameIP{}, fmt.Errorf("socks dialer: %v", err))
				return
			} else if d, ok := socksdialer.(smtpclient.Dialer); !ok {
				failMsgsDB(qlog, msgs, msgs[0].DialedIPs, backoff, dsn.NameIP{}, fmt.Errorf("socks dialer is not a contextdialer"))
				return
			} else {
				dialer = d
			}
			ourHostname = transport.Socks.Hostname
		}
		recipientDomainResult, hostResults = deliverDirect(qlog, resolver, dialer, ourHostname, transportName, transport.Direct, msgs, backoff)
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
