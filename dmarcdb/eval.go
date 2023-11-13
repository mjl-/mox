package dmarcdb

// Sending TLS reports and DMARC reports is very similar. See ../dmarcdb/eval.go:/similar and ../tlsrptsend/send.go:/similar.

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

var (
	metricReport = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_dmarcdb_report_queued_total",
			Help: "Total messages with DMARC aggregate/error reports queued.",
		},
	)
	metricReportError = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_dmarcdb_report_error_total",
			Help: "Total errors while composing or queueing DMARC aggregate/error reports.",
		},
	)
)

var (
	EvalDBTypes = []any{Evaluation{}, SuppressAddress{}} // Types stored in DB.
	// Exported for backups. For incoming deliveries the SMTP server adds evaluations
	// to the database. Every hour, a goroutine wakes up that gathers evaluations from
	// the last hour(s), sends a report, and removes the evaluations from the database.
	EvalDB    *bstore.DB
	evalMutex sync.Mutex
)

// Evaluation is the result of an evaluation of a DMARC policy, to be included
// in a DMARC report.
type Evaluation struct {
	ID int64

	// Domain where DMARC policy was found, could be the organizational domain while
	// evaluation was for a subdomain. Unicode. Same as domain found in
	// PolicyPublished. A separate field for its index.
	PolicyDomain string `bstore:"index"`

	// Time of evaluation, determines which report (covering whole hours) this
	// evaluation will be included in.
	Evaluated time.Time `bstore:"default now"`

	// If optional, this evaluation is not a reason to send a DMARC report, but it will
	// be included when a report is sent due to other non-optional evaluations. Set for
	// evaluations of incoming DMARC reports. We don't want such deliveries causing us to
	// send a report, or we would keep exchanging reporting messages forever. Also set
	// for when evaluation is a DMARC reject for domains we haven't positively
	// interacted with, to prevent being used to flood an unsuspecting domain with
	// reports.
	Optional bool

	// Effective aggregate reporting interval in hours. Between 1 and 24, rounded up
	// from seconds from policy to first number that can divide 24.
	IntervalHours int

	// "rua" in DMARC record, we only store evaluations for records with aggregate reporting addresses, so always non-empty.
	Addresses []string

	// Policy used for evaluation. We don't store the "fo" field for failure reporting
	// options, since we don't send failure reports for individual messages.
	PolicyPublished dmarcrpt.PolicyPublished

	// For "row" in a report record.
	SourceIP        string
	Disposition     dmarcrpt.Disposition
	AlignedDKIMPass bool
	AlignedSPFPass  bool
	OverrideReasons []dmarcrpt.PolicyOverrideReason

	// For "identifiers" in a report record.
	EnvelopeTo   string
	EnvelopeFrom string
	HeaderFrom   string

	// For "auth_results" in a report record.
	DKIMResults []dmarcrpt.DKIMAuthResult
	SPFResults  []dmarcrpt.SPFAuthResult
}

// SuppressAddress is a reporting address for which outgoing DMARC reports
// will be suppressed for a period.
type SuppressAddress struct {
	ID               int64
	Inserted         time.Time `bstore:"default now"`
	ReportingAddress string    `bstore:"unique"`
	Until            time.Time `bstore:"nonzero"`
	Comment          string
}

var dmarcResults = map[bool]dmarcrpt.DMARCResult{
	false: dmarcrpt.DMARCFail,
	true:  dmarcrpt.DMARCPass,
}

// ReportRecord turns an evaluation into a record that can be included in a
// report.
func (e Evaluation) ReportRecord(count int) dmarcrpt.ReportRecord {
	return dmarcrpt.ReportRecord{
		Row: dmarcrpt.Row{
			SourceIP: e.SourceIP,
			Count:    count,
			PolicyEvaluated: dmarcrpt.PolicyEvaluated{
				Disposition: e.Disposition,
				DKIM:        dmarcResults[e.AlignedDKIMPass],
				SPF:         dmarcResults[e.AlignedSPFPass],
				Reasons:     e.OverrideReasons,
			},
		},
		Identifiers: dmarcrpt.Identifiers{
			EnvelopeTo:   e.EnvelopeTo,
			EnvelopeFrom: e.EnvelopeFrom,
			HeaderFrom:   e.HeaderFrom,
		},
		AuthResults: dmarcrpt.AuthResults{
			DKIM: e.DKIMResults,
			SPF:  e.SPFResults,
		},
	}
}

func evalDB(ctx context.Context) (rdb *bstore.DB, rerr error) {
	evalMutex.Lock()
	defer evalMutex.Unlock()
	if EvalDB == nil {
		p := mox.DataDirPath("dmarceval.db")
		os.MkdirAll(filepath.Dir(p), 0770)
		db, err := bstore.Open(ctx, p, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, EvalDBTypes...)
		if err != nil {
			return nil, err
		}
		EvalDB = db
	}
	return EvalDB, nil
}

var intervalOpts = []int{24, 12, 8, 6, 4, 3, 2}

func intervalHours(seconds int) int {
	hours := (seconds + 3600 - 1) / 3600
	for _, opt := range intervalOpts {
		if hours >= opt {
			return opt
		}
	}
	return 1
}

// AddEvaluation adds the result of a DMARC evaluation for an incoming message
// to the database.
//
// AddEvaluation sets Evaluation.IntervalHours based on
// aggregateReportingIntervalSeconds.
func AddEvaluation(ctx context.Context, aggregateReportingIntervalSeconds int, e *Evaluation) error {
	e.IntervalHours = intervalHours(aggregateReportingIntervalSeconds)

	db, err := evalDB(ctx)
	if err != nil {
		return err
	}

	e.ID = 0
	return db.Insert(ctx, e)
}

// Evaluations returns all evaluations in the database.
func Evaluations(ctx context.Context) ([]Evaluation, error) {
	db, err := evalDB(ctx)
	if err != nil {
		return nil, err
	}

	q := bstore.QueryDB[Evaluation](ctx, db)
	q.SortAsc("Evaluated")
	return q.List()
}

// EvaluationStat summarizes stored evaluations, for inclusion in an upcoming
// aggregate report, for a domain.
type EvaluationStat struct {
	Domain       dns.Domain
	Dispositions []string
	Count        int
	SendReport   bool
}

// EvaluationStats returns evaluation counts and report-sending status per domain.
func EvaluationStats(ctx context.Context) (map[string]EvaluationStat, error) {
	db, err := evalDB(ctx)
	if err != nil {
		return nil, err
	}

	r := map[string]EvaluationStat{}

	err = bstore.QueryDB[Evaluation](ctx, db).ForEach(func(e Evaluation) error {
		if stat, ok := r[e.PolicyDomain]; ok {
			if !slices.Contains(stat.Dispositions, string(e.Disposition)) {
				stat.Dispositions = append(stat.Dispositions, string(e.Disposition))
			}
			stat.Count++
			stat.SendReport = stat.SendReport || !e.Optional
			r[e.PolicyDomain] = stat
		} else {
			dom, err := dns.ParseDomain(e.PolicyDomain)
			if err != nil {
				return fmt.Errorf("parsing domain %q: %v", e.PolicyDomain, err)
			}
			r[e.PolicyDomain] = EvaluationStat{
				Domain:       dom,
				Dispositions: []string{string(e.Disposition)},
				Count:        1,
				SendReport:   !e.Optional,
			}
		}
		return nil
	})
	return r, err
}

// EvaluationsDomain returns all evaluations for a domain.
func EvaluationsDomain(ctx context.Context, domain dns.Domain) ([]Evaluation, error) {
	db, err := evalDB(ctx)
	if err != nil {
		return nil, err
	}

	q := bstore.QueryDB[Evaluation](ctx, db)
	q.FilterNonzero(Evaluation{PolicyDomain: domain.Name()})
	q.SortAsc("Evaluated")
	return q.List()
}

// RemoveEvaluationsDomain removes evaluations for domain so they won't be sent in
// an aggregate report.
func RemoveEvaluationsDomain(ctx context.Context, domain dns.Domain) error {
	db, err := evalDB(ctx)
	if err != nil {
		return err
	}

	q := bstore.QueryDB[Evaluation](ctx, db)
	q.FilterNonzero(Evaluation{PolicyDomain: domain.Name()})
	_, err = q.Delete()
	return err
}

var jitterRand = mox.NewPseudoRand()

// time to sleep until next whole hour t, replaced by tests.
// Jitter so we don't cause load at exactly whole hours, other processes may
// already be doing that.
var jitteredTimeUntil = func(t time.Time) time.Duration {
	return time.Until(t.Add(time.Duration(30+jitterRand.Intn(60)) * time.Second))
}

// Start launches a goroutine that wakes up at each whole hour (plus jitter) and
// sends DMARC reports to domains that requested them.
func Start(resolver dns.Resolver) {
	go func() {
		log := mlog.New("dmarcdb")

		defer func() {
			// In case of panic don't take the whole program down.
			x := recover()
			if x != nil {
				log.Error("recover from panic", mlog.Field("panic", x))
				debug.PrintStack()
				metrics.PanicInc(metrics.Dmarcdb)
			}
		}()

		timer := time.NewTimer(time.Hour)
		defer timer.Stop()

		ctx := mox.Shutdown

		db, err := evalDB(ctx)
		if err != nil {
			log.Errorx("opening dmarc evaluations database for sending dmarc aggregate reports, not sending reports", err)
			return
		}

		for {
			now := time.Now()
			nextEnd := nextWholeHour(now)
			timer.Reset(jitteredTimeUntil(nextEnd))

			select {
			case <-ctx.Done():
				log.Info("dmarc aggregate report sender shutting down")
				return
			case <-timer.C:
			}

			// Gather report intervals we want to process now. Multiples of hours that can
			// divide 24, starting from UTC.
			// ../rfc/7489:1750
			utchour := nextEnd.UTC().Hour()
			if utchour == 0 {
				utchour = 24
			}
			intervals := []int{}
			for _, ival := range intervalOpts {
				if ival*(utchour/ival) == utchour {
					intervals = append(intervals, ival)
				}
			}
			intervals = append(intervals, 1)

			// Remove evaluations older than 48 hours (2 reports with the default and maximum
			// 24 hour interval). They should have been processed by now. We may have kept them
			// during temporary errors, but persistent temporary errors shouldn't fill up our
			// database. This also cleans up evaluations that were all optional for a domain.
			_, err := bstore.QueryDB[Evaluation](ctx, db).FilterLess("Evaluated", nextEnd.Add(-48*time.Hour)).Delete()
			log.Check(err, "removing stale dmarc evaluations from database")

			clog := log.WithCid(mox.Cid())
			clog.Info("sending dmarc aggregate reports", mlog.Field("end", nextEnd.UTC()), mlog.Field("intervals", intervals))
			if err := sendReports(ctx, clog, resolver, db, nextEnd, intervals); err != nil {
				clog.Errorx("sending dmarc aggregate reports", err)
				metricReportError.Inc()
			} else {
				clog.Info("finished sending dmarc aggregate reports")
			}
		}
	}()
}

func nextWholeHour(now time.Time) time.Time {
	t := now
	t = t.Add(time.Hour)
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
}

// We don't send reports at full speed. In the future, we could try to stretch out
// reports a bit smarter. E.g. over 5 minutes with some minimum interval, and
// perhaps faster and in parallel when there are lots of reports. Perhaps also
// depending on reporting interval (faster for 1h, slower for 24h).
// Replaced by tests.
var sleepBetween = func(ctx context.Context, between time.Duration) (ok bool) {
	t := time.NewTimer(between)
	select {
	case <-ctx.Done():
		t.Stop()
		return false
	case <-t.C:
		return true
	}
}

// sendReports gathers all policy domains that have evaluations that should
// receive a DMARC report and sends a report to each.
func sendReports(ctx context.Context, log *mlog.Log, resolver dns.Resolver, db *bstore.DB, endTime time.Time, intervals []int) error {
	ivals := make([]any, len(intervals))
	for i, v := range intervals {
		ivals[i] = v
	}

	destDomains := map[string]bool{}

	// Gather all domains that we plan to send to.
	nsend := 0
	q := bstore.QueryDB[Evaluation](ctx, db)
	q.FilterLess("Evaluated", endTime)
	q.FilterEqual("IntervalHours", ivals...)
	err := q.ForEach(func(e Evaluation) error {
		if !e.Optional && !destDomains[e.PolicyPublished.Domain] {
			nsend++
		}
		destDomains[e.PolicyPublished.Domain] = destDomains[e.PolicyPublished.Domain] || !e.Optional
		return nil
	})
	if err != nil {
		return fmt.Errorf("looking for domains to send reports to: %v", err)
	}

	var wg sync.WaitGroup

	// Sleep in between sending reports. We process hourly, and spread the reports over
	// the hour, but with max 5 minute interval.
	between := 45 * time.Minute
	if nsend > 0 {
		between /= time.Duration(nsend)
	}
	if between > 5*time.Minute {
		between = 5 * time.Minute
	}

	// Attempt to send report to each domain.
	n := 0
	for d, send := range destDomains {
		// Cleanup evaluations for domain with only optionals.
		if !send {
			removeEvaluations(ctx, log, db, endTime, d)
			continue
		}

		if n > 0 {
			if ok := sleepBetween(ctx, between); !ok {
				return nil
			}
		}
		n++

		// Send in goroutine, so a slow process doesn't block progress.
		wg.Add(1)
		go func(domain string) {
			defer func() {
				// In case of panic don't take the whole program down.
				x := recover()
				if x != nil {
					log.Error("unhandled panic in dmarcdb sendReports", mlog.Field("panic", x))
					debug.PrintStack()
					metrics.PanicInc(metrics.Dmarcdb)
				}
			}()
			defer wg.Done()

			rlog := log.WithCid(mox.Cid()).Fields(mlog.Field("domain", domain))
			rlog.Info("sending dmarc report")
			if _, err := sendReportDomain(ctx, rlog, resolver, db, endTime, domain); err != nil {
				rlog.Errorx("sending dmarc aggregate report to domain", err)
				metricReportError.Inc()
			}
		}(d)
	}

	wg.Wait()

	return nil
}

type recipient struct {
	address smtp.Address
	maxSize uint64
}

func parseRecipient(log *mlog.Log, uri dmarc.URI) (r recipient, ok bool) {
	log = log.Fields(mlog.Field("uri", uri.Address))

	u, err := url.Parse(uri.Address)
	if err != nil {
		log.Debugx("parsing uri in dmarc record rua value", err)
		return r, false
	}
	if !strings.EqualFold(u.Scheme, "mailto") {
		log.Debug("skipping unrecognized scheme in dmarc record rua value")
		return r, false
	}
	addr, err := smtp.ParseAddress(u.Opaque)
	if err != nil {
		log.Debugx("parsing mailto uri in dmarc record rua value", err)
		return r, false
	}

	r = recipient{addr, uri.MaxSize}
	// ../rfc/7489:1197
	switch uri.Unit {
	case "k", "K":
		r.maxSize *= 1024
	case "m", "M":
		r.maxSize *= 1024 * 1024
	case "g", "G":
		r.maxSize *= 1024 * 1024 * 1024
	case "t", "T":
		// Oh yeah, terabyte-sized reports!
		r.maxSize *= 1024 * 1024 * 1024 * 1024
	case "":
	default:
		log.Debug("unrecognized max size unit in dmarc record rua value", mlog.Field("unit", uri.Unit))
		return r, false
	}

	return r, true
}

func removeEvaluations(ctx context.Context, log *mlog.Log, db *bstore.DB, endTime time.Time, domain string) {
	q := bstore.QueryDB[Evaluation](ctx, db)
	q.FilterLess("Evaluated", endTime)
	q.FilterNonzero(Evaluation{PolicyDomain: domain})
	_, err := q.Delete()
	log.Check(err, "removing evaluations after processing for dmarc aggregate report")
}

// replaceable for testing.
var queueAdd = queue.Add

func sendReportDomain(ctx context.Context, log *mlog.Log, resolver dns.Resolver, db *bstore.DB, endTime time.Time, domain string) (cleanup bool, rerr error) {
	dom, err := dns.ParseDomain(domain)
	if err != nil {
		return false, fmt.Errorf("parsing domain for sending reports: %v", err)
	}

	// We'll cleanup records by default.
	cleanup = true
	// If we encounter a temporary error we cancel cleanup of evaluations on error.
	tempError := false

	defer func() {
		if !cleanup || tempError {
			log.Debug("not cleaning up evaluations after attempting to send dmarc aggregate report")
		} else {
			removeEvaluations(ctx, log, db, endTime, domain)
		}
	}()

	// We're going to build up this report.
	report := dmarcrpt.Feedback{
		Version: "1.0",
		ReportMetadata: dmarcrpt.ReportMetadata{
			OrgName: mox.Conf.Static.HostnameDomain.ASCII,
			Email:   "postmaster@" + mox.Conf.Static.HostnameDomain.ASCII,
			// ReportID and DateRange are set after we've seen evaluations.
			// Errors is filled below when we encounter problems.
		},
		// We'll fill the records below.
		Records: []dmarcrpt.ReportRecord{},
	}

	var errors []string // For report.ReportMetaData.Errors

	// Check if we should be sending a report at all: if there are rua URIs in the
	// current DMARC record. The interval may have changed too, but we'll flush out our
	// evaluations regardless. We always use the latest DMARC record when sending, but
	// we'll lump all policies of the last interval into one report.
	// ../rfc/7489:1714
	status, _, record, _, _, err := dmarc.Lookup(ctx, resolver, dom)
	if err != nil {
		// todo future: we could perhaps still send this report, assuming the values we know. in case of temporary error, we could also schedule again regardless of next interval hour (we would now only retry a 24h-interval report after 24h passed).
		// Remove records unless it was a temporary error. We'll try again next round.
		cleanup = status != dmarc.StatusTemperror
		return cleanup, fmt.Errorf("looking up current dmarc record for reporting address: %v", err)
	}

	var recipients []recipient

	// Gather all aggregate reporting addresses to try to send to. We'll start with
	// those in the initial DMARC record, but will follow external reporting addresses
	// and possibly update the list.
	for _, uri := range record.AggregateReportAddresses {
		r, ok := parseRecipient(log, uri)
		if !ok {
			continue
		}

		// Check if domain of rua recipient has the same organizational domain as for the
		// evaluations. If not, we need to verify we are allowed to send.
		ruaOrgDom := publicsuffix.Lookup(ctx, r.address.Domain)
		evalOrgDom := publicsuffix.Lookup(ctx, dom)

		if ruaOrgDom == evalOrgDom {
			recipients = append(recipients, r)
			continue
		}

		// Verify and follow addresses in other organizational domain through
		// <policydomain>._report._dmarc.<host> lookup.
		// ../rfc/7489:1556
		accepts, status, records, _, _, err := dmarc.LookupExternalReportsAccepted(ctx, resolver, evalOrgDom, r.address.Domain)
		log.Debugx("checking if rua address with different organization domain has opted into receiving dmarc reports", err,
			mlog.Field("policydomain", evalOrgDom),
			mlog.Field("destinationdomain", r.address.Domain),
			mlog.Field("accepts", accepts),
			mlog.Field("status", status))
		if status == dmarc.StatusTemperror {
			// With a temporary error, we'll try to get the report the delivered anyway,
			// perhaps there are multiple recipients.
			// ../rfc/7489:1578
			tempError = true
			errors = append(errors, "temporary error checking authorization for report delegation to external address")
		}
		if !accepts {
			errors = append(errors, fmt.Sprintf("rua %s is external domain that does not opt-in to receiving dmarc records through _report dmarc record", r.address))
			continue
		}

		// We can follow a _report DMARC DNS record once. In that record, a domain may
		// specify alternative addresses that we should send reports to instead. Such
		// alternative address(es) must have the same host. If not, we ignore the new
		// value. Behaviour for multiple records and/or multiple new addresses is
		// underspecified. We'll replace an address with one or more new addresses, and
		// keep the original if there was no candidate (which covers the case of invalid
		// alternative addresses and no new address specified).
		// ../rfc/7489:1600
		foundReplacement := false
		rlog := log.Fields(mlog.Field("followedaddress", uri.Address))
		for _, record := range records {
			for _, exturi := range record.AggregateReportAddresses {
				extr, ok := parseRecipient(rlog, exturi)
				if !ok {
					continue
				}
				if extr.address.Domain != r.address.Domain {
					rlog.Debug("rua address in external _report dmarc record has different host than initial dmarc record, ignoring new name", mlog.Field("externaladdress", extr.address))
					errors = append(errors, fmt.Sprintf("rua %s is external domain with a replacement address %s with different host", r.address, extr.address))
				} else {
					rlog.Debug("using replacement rua address from external _report dmarc record", mlog.Field("externaladdress", extr.address))
					foundReplacement = true
					recipients = append(recipients, extr)
				}
			}
		}
		if !foundReplacement {
			recipients = append(recipients, r)
		}
	}

	if len(recipients) == 0 {
		// No reports requested, perfectly fine, no work to do for us.
		log.Debug("no aggregate reporting addresses configured")
		return true, nil
	}

	// We count idential records. Can be common with a domain sending quite some email.
	// Though less if the sending domain has many IPs. In the future, we may want to
	// remove some details from records so we can aggregate them into fewer rows.
	type recordCount struct {
		dmarcrpt.ReportRecord
		count int
	}
	counts := map[string]recordCount{}

	var first, last Evaluation // For daterange.
	var sendReport bool

	q := bstore.QueryDB[Evaluation](ctx, db)
	q.FilterLess("Evaluated", endTime)
	q.FilterNonzero(Evaluation{PolicyDomain: domain})
	q.SortAsc("Evaluated")
	err = q.ForEach(func(e Evaluation) error {
		if first.ID == 0 {
			first = e
		}
		last = e

		record := e.ReportRecord(0)

		// todo future: if we see many unique records from a single ip (exact ipv4 or ipv6 subnet), we may want to coalesce them into a single record, leaving out the fields that make them: a single ip could cause a report to contain many records with many unique domains, selectors, etc. it may compress relatively well, but the reports could still be huge.

		// Simple but inefficient way to aggregate identical records. We may want to turn
		// records into smaller representation in the future.
		recbuf, err := xml.Marshal(record)
		if err != nil {
			return fmt.Errorf("xml marshal of report record: %v", err)
		}
		recstr := string(recbuf)
		counts[recstr] = recordCount{record, counts[recstr].count + 1}
		if !e.Optional {
			sendReport = true
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("gathering evaluations for report: %v", err)
	}

	if !sendReport {
		log.Debug("no non-optional evaluations for domain, not sending dmarc aggregate report")
		return true, nil
	}

	// Set begin and end date range. We try to set it to whole intervals as requested
	// by the domain owner. The typical, default and maximum interval is 24 hours. But
	// we allow any whole number of hours that can divide 24 hours. If we have an
	// evaluation that is older, we may have had a failure to send earlier. We include
	// those earlier intervals in this report as well.
	//
	// Although "end" could be interpreted as exclusive, to be on the safe side
	// regarding client behaviour, and (related) to mimic large existing DMARC report
	// senders, we set it to the last second of the period this report covers.
	report.ReportMetadata.DateRange.End = endTime.Add(-time.Second).Unix()
	interval := time.Duration(first.IntervalHours) * time.Hour
	beginTime := endTime.Add(-interval)
	for first.Evaluated.Before(beginTime) {
		beginTime = beginTime.Add(-interval)
	}
	report.ReportMetadata.DateRange.Begin = beginTime.Unix()

	// yyyymmddHH, we only send one report per hour, so should be unique per policy
	// domain. We also add a truly unique id based on first evaluation id used without
	// revealing the number of evaluations we have. Reuse of ReceivedID is not great,
	// but shouldn't hurt.
	report.ReportMetadata.ReportID = endTime.UTC().Format("20060102.15") + "." + mox.ReceivedID(first.ID)

	// We may include errors we encountered when composing the report. We
	// don't currently include errors about dmarc evaluations, e.g. DNS
	// lookup errors during incoming deliveries.
	report.ReportMetadata.Errors = errors

	// We'll fill this with the last-used record, not the one we fetch fresh from DSN.
	// They will almost always be the same, but if not, the fresh record was never
	// actually used for evaluations, so no point in reporting it.
	report.PolicyPublished = last.PolicyPublished

	// Process records in-order for testable results.
	recstrs := maps.Keys(counts)
	sort.Strings(recstrs)
	for _, recstr := range recstrs {
		rc := counts[recstr]
		rc.ReportRecord.Row.Count = rc.count
		report.Records = append(report.Records, rc.ReportRecord)
	}

	reportFile, err := store.CreateMessageTemp("dmarcreportout")
	if err != nil {
		return false, fmt.Errorf("creating temporary file for outgoing dmarc aggregate report: %v", err)
	}
	defer store.CloseRemoveTempFile(log, reportFile, "generated dmarc aggregate report")

	gzw := gzip.NewWriter(reportFile)
	_, err = fmt.Fprint(gzw, xml.Header)
	enc := xml.NewEncoder(gzw)
	enc.Indent("", "\t") // Keep up pretention that xml is human-readable.
	if err == nil {
		err = enc.Encode(report)
	}
	if err == nil {
		err = enc.Close()
	}
	if err == nil {
		err = gzw.Close()
	}
	if err != nil {
		return true, fmt.Errorf("writing dmarc aggregate report as xml with gzip: %v", err)
	}

	msgf, err := store.CreateMessageTemp("dmarcreportmsgout")
	if err != nil {
		return false, fmt.Errorf("creating temporary message file with outgoing dmarc aggregate report: %v", err)
	}
	defer store.CloseRemoveTempFile(log, msgf, "message with generated dmarc aggregate report")

	// We are sending reports from our host's postmaster address. In a
	// typical setup the host is a subdomain of a configured domain with
	// DKIM keys, so we can DKIM-sign our reports. SPF should pass anyway.
	// A single report can contain deliveries from a single policy domain
	// to multiple of our configured domains.
	from := smtp.Address{Localpart: "postmaster", Domain: mox.Conf.Static.HostnameDomain}

	// Subject follows the form in RFC. ../rfc/7489:1871
	subject := fmt.Sprintf("Report Domain: %s Submitter: %s Report-ID: <%s>", dom.ASCII, mox.Conf.Static.HostnameDomain.ASCII, report.ReportMetadata.ReportID)

	// Human-readable part for convenience. ../rfc/7489:1803
	text := fmt.Sprintf(`Attached is an aggregate DMARC report with results of evaluations of the DMARC
policy of your domain for messages received by us that have your domain in the
message From header. You are receiving this message because your address is
specified in the "rua" field of the DMARC record for your domain.

Report domain: %s
Submitter: %s
Report-ID: %s
Period: %s - %s UTC
`, dom, mox.Conf.Static.HostnameDomain, report.ReportMetadata.ReportID, beginTime.UTC().Format(time.DateTime), endTime.UTC().Format(time.DateTime))

	// The attached file follows the naming convention from the RFC. ../rfc/7489:1812
	reportFilename := fmt.Sprintf("%s!%s!%d!%d.xml.gz", mox.Conf.Static.HostnameDomain.ASCII, dom.ASCII, beginTime.Unix(), endTime.Add(-time.Second).Unix())

	var addrs []message.NameAddress
	for _, rcpt := range recipients {
		addrs = append(addrs, message.NameAddress{Address: rcpt.address})
	}

	// Compose the message.
	msgPrefix, has8bit, smtputf8, messageID, err := composeAggregateReport(ctx, log, msgf, from, addrs, subject, text, reportFilename, reportFile)
	if err != nil {
		return false, fmt.Errorf("composing message with outgoing dmarc aggregate report: %v", err)
	}

	// Get size of message after all compression and encodings (base64 makes it big
	// again), and go through potentials recipients (rua). If they are willing to
	// accept the report, queue it.
	msgInfo, err := msgf.Stat()
	if err != nil {
		return false, fmt.Errorf("stat message with outgoing dmarc aggregate report: %v", err)
	}
	msgSize := int64(len(msgPrefix)) + msgInfo.Size()
	var queued bool
	for _, rcpt := range recipients {
		// If recipient is on suppression list, we won't queue the reporting message.
		q := bstore.QueryDB[SuppressAddress](ctx, db)
		q.FilterNonzero(SuppressAddress{ReportingAddress: rcpt.address.Path().String()})
		q.FilterGreater("Until", time.Now())
		exists, err := q.Exists()
		if err != nil {
			return false, fmt.Errorf("querying suppress list: %v", err)
		}
		if exists {
			log.Info("suppressing outgoing dmarc aggregate report", mlog.Field("reportingaddress", rcpt.address))
			continue
		}

		// Only send to addresses where we don't exceed their size limit. The RFC mentions
		// the size of the report, but then continues about the size after compression and
		// transport encodings (i.e. gzip and the mime base64 attachment, so the intention
		// is probably to compare against the size of the message that contains the report.
		// ../rfc/7489:1773
		if rcpt.maxSize > 0 && msgSize > int64(rcpt.maxSize) {
			continue
		}

		qm := queue.MakeMsg(mox.Conf.Static.Postmaster.Account, from.Path(), rcpt.address.Path(), has8bit, smtputf8, msgSize, messageID, []byte(msgPrefix), nil)
		// Don't try as long as regular deliveries, and stop before we would send the
		// delayed DSN. Though we also won't send that due to IsDMARCReport.
		qm.MaxAttempts = 5
		qm.IsDMARCReport = true

		err = queueAdd(ctx, log, &qm, msgf)
		if err != nil {
			tempError = true
			log.Errorx("queueing message with dmarc aggregate report", err)
			metricReportError.Inc()
		} else {
			log.Debug("dmarc aggregate report queued", mlog.Field("recipient", rcpt.address))
			queued = true
			metricReport.Inc()
		}
	}

	if !queued {
		if err := sendErrorReport(ctx, log, db, from, addrs, dom, report.ReportMetadata.ReportID, msgSize); err != nil {
			log.Errorx("sending dmarc error reports", err)
			metricReportError.Inc()
		}
	}

	// Regardless of whether we queued a report, we are not going to keep the
	// evaluations around. Though this can be overridden if tempError is set.
	// ../rfc/7489:1785

	return true, nil
}

func composeAggregateReport(ctx context.Context, log *mlog.Log, mf *os.File, fromAddr smtp.Address, recipients []message.NameAddress, subject, text, filename string, reportXMLGzipFile *os.File) (msgPrefix string, has8bit, smtputf8 bool, messageID string, rerr error) {
	xc := message.NewComposer(mf, 100*1024*1024)
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(error); ok && errors.Is(err, message.ErrCompose) {
			rerr = err
			return
		}
		panic(x)
	}()

	// We only use smtputf8 if we have to, with a utf-8 localpart. For IDNA, we use ASCII domains.
	for _, a := range recipients {
		if a.Address.Localpart.IsInternational() {
			xc.SMTPUTF8 = true
			break
		}
	}

	xc.HeaderAddrs("From", []message.NameAddress{{Address: fromAddr}})
	xc.HeaderAddrs("To", recipients)
	xc.Subject(subject)
	messageID = fmt.Sprintf("<%s>", mox.MessageIDGen(xc.SMTPUTF8))
	xc.Header("Message-Id", messageID)
	xc.Header("Date", time.Now().Format(message.RFC5322Z))
	xc.Header("User-Agent", "mox/"+moxvar.Version)
	xc.Header("MIME-Version", "1.0")

	// Multipart message, with a text/plain and the report attached.
	mp := multipart.NewWriter(xc)
	xc.Header("Content-Type", fmt.Sprintf(`multipart/mixed; boundary="%s"`, mp.Boundary()))
	xc.Line()

	// Textual part, just mentioning this is a DMARC report.
	textBody, ct, cte := xc.TextPart(text)
	textHdr := textproto.MIMEHeader{}
	textHdr.Set("Content-Type", ct)
	textHdr.Set("Content-Transfer-Encoding", cte)
	textp, err := mp.CreatePart(textHdr)
	xc.Checkf(err, "adding text part to message")
	_, err = textp.Write(textBody)
	xc.Checkf(err, "writing text part")

	// DMARC report as attachment.
	ahdr := textproto.MIMEHeader{}
	ahdr.Set("Content-Type", "application/gzip")
	ahdr.Set("Content-Transfer-Encoding", "base64")
	cd := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
	ahdr.Set("Content-Disposition", cd)
	ap, err := mp.CreatePart(ahdr)
	xc.Checkf(err, "adding dmarc aggregate report to message")
	wc := moxio.Base64Writer(ap)
	_, err = io.Copy(wc, &moxio.AtReader{R: reportXMLGzipFile})
	xc.Checkf(err, "adding attachment")
	err = wc.Close()
	xc.Checkf(err, "flushing attachment")

	err = mp.Close()
	xc.Checkf(err, "closing multipart")

	xc.Flush()

	msgPrefix = dkimSign(ctx, log, fromAddr, xc.SMTPUTF8, mf)

	return msgPrefix, xc.Has8bit, xc.SMTPUTF8, messageID, nil
}

// Though this functionality is quite underspecified, we'll do our best to send our
// an error report in case our report is too large for all recipients.
// ../rfc/7489:1918
func sendErrorReport(ctx context.Context, log *mlog.Log, db *bstore.DB, fromAddr smtp.Address, recipients []message.NameAddress, reportDomain dns.Domain, reportID string, reportMsgSize int64) error {
	log.Debug("no reporting addresses willing to accept report given size, queuing short error message")

	msgf, err := store.CreateMessageTemp("dmarcreportmsg-out")
	if err != nil {
		return fmt.Errorf("creating temporary message file for outgoing dmarc error report: %v", err)
	}
	defer store.CloseRemoveTempFile(log, msgf, "outgoing dmarc error report message")

	var recipientStrs []string
	for _, rcpt := range recipients {
		recipientStrs = append(recipientStrs, rcpt.Address.String())
	}

	subject := fmt.Sprintf("DMARC aggregate reporting error report for %s", reportDomain.ASCII)
	// ../rfc/7489:1926
	text := fmt.Sprintf(`Report-Date: %s
Report-Domain: %s
Report-ID: %s
Report-Size: %d
Submitter: %s
Submitting-URI: %s
`, time.Now().Format(message.RFC5322Z), reportDomain.ASCII, reportID, reportMsgSize, mox.Conf.Static.HostnameDomain.ASCII, strings.Join(recipientStrs, ","))
	text = strings.ReplaceAll(text, "\n", "\r\n")

	msgPrefix, has8bit, smtputf8, messageID, err := composeErrorReport(ctx, log, msgf, fromAddr, recipients, subject, text)
	if err != nil {
		return err
	}

	msgInfo, err := msgf.Stat()
	if err != nil {
		return fmt.Errorf("stat message with outgoing dmarc error report: %v", err)
	}
	msgSize := int64(len(msgPrefix)) + msgInfo.Size()

	for _, rcpt := range recipients {
		// If recipient is on suppression list, we won't queue the reporting message.
		q := bstore.QueryDB[SuppressAddress](ctx, db)
		q.FilterNonzero(SuppressAddress{ReportingAddress: rcpt.Address.Path().String()})
		q.FilterGreater("Until", time.Now())
		exists, err := q.Exists()
		if err != nil {
			return fmt.Errorf("querying suppress list: %v", err)
		}
		if exists {
			log.Info("suppressing outgoing dmarc error report", mlog.Field("reportingaddress", rcpt.Address))
			continue
		}

		qm := queue.MakeMsg(mox.Conf.Static.Postmaster.Account, fromAddr.Path(), rcpt.Address.Path(), has8bit, smtputf8, msgSize, messageID, []byte(msgPrefix), nil)
		// Don't try as long as regular deliveries, and stop before we would send the
		// delayed DSN. Though we also won't send that due to IsDMARCReport.
		qm.MaxAttempts = 5
		qm.IsDMARCReport = true

		if err := queueAdd(ctx, log, &qm, msgf); err != nil {
			log.Errorx("queueing message with dmarc error report", err)
			metricReportError.Inc()
		} else {
			log.Debug("dmarc error report queued", mlog.Field("recipient", rcpt))
			metricReport.Inc()
		}
	}
	return nil
}

func composeErrorReport(ctx context.Context, log *mlog.Log, mf *os.File, fromAddr smtp.Address, recipients []message.NameAddress, subject, text string) (msgPrefix string, has8bit, smtputf8 bool, messageID string, rerr error) {
	xc := message.NewComposer(mf, 100*1024*1024)
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(error); ok && errors.Is(err, message.ErrCompose) {
			rerr = err
			return
		}
		panic(x)
	}()

	// We only use smtputf8 if we have to, with a utf-8 localpart. For IDNA, we use ASCII domains.
	for _, a := range recipients {
		if a.Address.Localpart.IsInternational() {
			xc.SMTPUTF8 = true
			break
		}
	}

	xc.HeaderAddrs("From", []message.NameAddress{{Address: fromAddr}})
	xc.HeaderAddrs("To", recipients)
	xc.Header("Subject", subject)
	messageID = fmt.Sprintf("<%s>", mox.MessageIDGen(xc.SMTPUTF8))
	xc.Header("Message-Id", messageID)
	xc.Header("Date", time.Now().Format(message.RFC5322Z))
	xc.Header("User-Agent", "mox/"+moxvar.Version)
	xc.Header("MIME-Version", "1.0")

	textBody, ct, cte := xc.TextPart(text)
	xc.Header("Content-Type", ct)
	xc.Header("Content-Transfer-Encoding", cte)
	xc.Line()
	_, err := xc.Write(textBody)
	xc.Checkf(err, "writing text")

	xc.Flush()

	msgPrefix = dkimSign(ctx, log, fromAddr, smtputf8, mf)

	return msgPrefix, xc.Has8bit, xc.SMTPUTF8, messageID, nil
}

func dkimSign(ctx context.Context, log *mlog.Log, fromAddr smtp.Address, smtputf8 bool, mf *os.File) string {
	// Add DKIM-Signature headers if we have a key for (a higher) domain than the from
	// address, which is a host name. A signature will only be useful with higher-level
	// domains if they have a relaxed dkim check (which is the default). If the dkim
	// check is strict, there is no harm, there will simply not be a dkim pass.
	fd := fromAddr.Domain
	var zerodom dns.Domain
	for fd != zerodom {
		confDom, ok := mox.Conf.Domain(fd)
		if len(confDom.DKIM.Sign) > 0 {
			dkimHeaders, err := dkim.Sign(ctx, fromAddr.Localpart, fd, confDom.DKIM, smtputf8, mf)
			if err != nil {
				log.Errorx("dkim-signing dmarc report, continuing without signature", err)
				metricReportError.Inc()
				return ""
			}
			return dkimHeaders
		} else if ok {
			return ""
		}

		var nfd dns.Domain
		_, nfd.ASCII, _ = strings.Cut(fd.ASCII, ".")
		_, nfd.Unicode, _ = strings.Cut(fd.Unicode, ".")
		fd = nfd
	}
	return ""
}

// SuppressAdd adds an address to the suppress list.
func SuppressAdd(ctx context.Context, ba *SuppressAddress) error {
	db, err := evalDB(ctx)
	if err != nil {
		return err
	}

	return db.Insert(ctx, ba)
}

// SuppressList returns all reporting addresses on the suppress list.
func SuppressList(ctx context.Context) ([]SuppressAddress, error) {
	db, err := evalDB(ctx)
	if err != nil {
		return nil, err
	}

	return bstore.QueryDB[SuppressAddress](ctx, db).SortDesc("ID").List()
}

// SuppressRemove removes a reporting address record from the suppress list.
func SuppressRemove(ctx context.Context, id int64) error {
	db, err := evalDB(ctx)
	if err != nil {
		return err
	}

	return db.Delete(ctx, &SuppressAddress{ID: id})
}

// SuppressUpdate updates the until field of a reporting address record.
func SuppressUpdate(ctx context.Context, id int64, until time.Time) error {
	db, err := evalDB(ctx)
	if err != nil {
		return err
	}

	ba := SuppressAddress{ID: id}
	err = db.Get(ctx, &ba)
	if err != nil {
		return err
	}
	ba.Until = until
	return db.Update(ctx, &ba)
}
