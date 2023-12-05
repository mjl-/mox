// Package mtastsdb stores MTA-STS policies for later use.
//
// An MTA-STS policy can specify how long it may be cached. By storing a
// policy, it does not have to be fetched again during email delivery, which
// makes it harder for attackers to intervene.
package mtastsdb

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/tlsrpt"
)

var (
	metricGet = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_mtastsdb_get_total",
			Help: "Number of Get by result.",
		},
		[]string{"result"},
	)
)

var timeNow = time.Now // Tests override this.

// PolicyRecord is a cached policy or absence of a policy.
type PolicyRecord struct {
	Domain        string    // Domain name, with unicode characters.
	Inserted      time.Time `bstore:"default now"`
	ValidEnd      time.Time
	LastUpdate    time.Time // Policies are refreshed on use and periodically.
	LastUse       time.Time `bstore:"index"`
	Backoff       bool
	RecordID      string // As retrieved from DNS.
	mtasts.Policy        // As retrieved from the well-known HTTPS url.

	// Text that make up the policy, as retrieved. We didn't store this in the past. If
	// empty, policy can be reconstructed from Policy field. Needed by TLSRPT.
	PolicyText string
}

var (
	// No valid non-expired policy in database.
	ErrNotFound = errors.New("mtastsdb: policy not found")

	// Indicates an MTA-STS TXT record was fetched recently, but fetching the policy
	// failed and should not yet be retried.
	ErrBackoff = errors.New("mtastsdb: policy fetch failed recently")
)

var DBTypes = []any{PolicyRecord{}} // Types stored in DB.
var DB *bstore.DB                   // Exported for backups.
var mutex sync.Mutex

func database(ctx context.Context) (rdb *bstore.DB, rerr error) {
	mutex.Lock()
	defer mutex.Unlock()
	if DB == nil {
		p := mox.DataDirPath("mtasts.db")
		os.MkdirAll(filepath.Dir(p), 0770)
		db, err := bstore.Open(ctx, p, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, DBTypes...)
		if err != nil {
			return nil, err
		}
		DB = db
	}
	return DB, nil
}

// Init opens the database and starts a goroutine that refreshes policies in
// the database, and keeps doing so periodically.
func Init(refresher bool) error {
	_, err := database(mox.Shutdown)
	if err != nil {
		return err
	}

	if refresher {
		// todo: allow us to shut down cleanly?
		go refresh()
	}

	return nil
}

// Close closes the database.
func Close() {
	mutex.Lock()
	defer mutex.Unlock()
	if DB != nil {
		err := DB.Close()
		mlog.New("mtastsdb", nil).Check(err, "closing database")
		DB = nil
	}
}

// lookup looks up a policy for the domain in the database.
//
// Only non-expired records are returned.
//
// Returns ErrNotFound if record is not present.
// Returns ErrBackoff if a recent attempt to fetch a record failed.
func lookup(ctx context.Context, log mlog.Log, domain dns.Domain) (*PolicyRecord, error) {
	db, err := database(ctx)
	if err != nil {
		return nil, err
	}

	if domain.IsZero() {
		return nil, fmt.Errorf("empty domain")
	}
	now := timeNow()
	q := bstore.QueryDB[PolicyRecord](ctx, db)
	q.FilterNonzero(PolicyRecord{Domain: domain.Name()})
	q.FilterGreater("ValidEnd", now)
	pr, err := q.Get()
	if err == bstore.ErrAbsent {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	pr.LastUse = now
	if err := db.Update(ctx, &pr); err != nil {
		log.Errorx("marking cached mta-sts policy as used in database", err)
	}
	if pr.Backoff {
		return nil, ErrBackoff
	}
	return &pr, nil
}

// Upsert adds the policy to the database, overwriting an existing policy for the domain.
// Policy can be nil, indicating a failure to fetch the policy.
func Upsert(ctx context.Context, domain dns.Domain, recordID string, policy *mtasts.Policy, policyText string) error {
	db, err := database(ctx)
	if err != nil {
		return err
	}

	return db.Write(ctx, func(tx *bstore.Tx) error {
		pr := PolicyRecord{Domain: domain.Name()}
		err := tx.Get(&pr)
		if err != nil && err != bstore.ErrAbsent {
			return err
		}

		now := timeNow()

		var p mtasts.Policy
		if policy != nil {
			p = *policy
		} else {
			// ../rfc/8461:552
			p.Mode = mtasts.ModeNone
			p.MaxAgeSeconds = 5 * 60
		}
		backoff := policy == nil
		validEnd := now.Add(time.Duration(p.MaxAgeSeconds) * time.Second)

		if err == bstore.ErrAbsent {
			pr = PolicyRecord{domain.Name(), now, validEnd, now, now, backoff, recordID, p, policyText}
			return tx.Insert(&pr)
		}

		pr.ValidEnd = validEnd
		pr.LastUpdate = now
		pr.LastUse = now
		pr.Backoff = backoff
		pr.RecordID = recordID
		pr.Policy = p
		pr.PolicyText = policyText
		return tx.Update(&pr)
	})
}

// PolicyRecords returns all policies in the database, sorted descending by last
// use, domain.
func PolicyRecords(ctx context.Context) ([]PolicyRecord, error) {
	db, err := database(ctx)
	if err != nil {
		return nil, err
	}
	return bstore.QueryDB[PolicyRecord](ctx, db).SortDesc("LastUse", "Domain").List()
}

// Get retrieves an MTA-STS policy for domain and whether it is fresh.
//
// If an error is returned, it should be considered a transient error, e.g. a
// temporary DNS lookup failure.
//
// The returned policy can be nil also when there is no error. In this case, the
// domain does not implement MTA-STS.
//
// If a policy is present in the local database, it is refreshed if needed. If no
// policy is present for the domain, an attempt is made to fetch the policy and
// store it in the local database.
//
// Some errors are logged but not otherwise returned, e.g. if a new policy is
// supposedly published but could not be retrieved.
//
// Get returns an "sts" or "no-policy-found" in reportResult in most cases (when
// not a local/internal error). It may add an "sts" result without policy contents
// ("policy-string") in case of errors while fetching the policy.
func Get(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, domain dns.Domain) (policy *mtasts.Policy, reportResult tlsrpt.Result, fresh bool, err error) {
	log := mlog.New("mtastsdb", elog)
	defer func() {
		result := "ok"
		if err != nil && errors.Is(err, ErrBackoff) {
			result = "backoff"
		} else if err != nil && errors.Is(err, ErrNotFound) {
			result = "notfound"
		} else if err != nil {
			result = "error"
		}
		metricGet.WithLabelValues(result).Inc()
		log.Debugx("mtastsdb get result", err, slog.Any("domain", domain), slog.Bool("fresh", fresh))
	}()

	cachedPolicy, err := lookup(ctx, log, domain)
	if err != nil && errors.Is(err, ErrNotFound) {
		// We don't have a policy for this domain, not even a record that we tried recently
		// and should backoff. So attempt to fetch policy.
		nctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		record, p, ptext, err := mtasts.Get(nctx, log.Logger, resolver, domain)
		if err != nil {
			switch {
			case errors.Is(err, mtasts.ErrNoRecord) || errors.Is(err, mtasts.ErrMultipleRecords) || errors.Is(err, mtasts.ErrRecordSyntax) || errors.Is(err, mtasts.ErrNoPolicy) || errors.Is(err, mtasts.ErrPolicyFetch) || errors.Is(err, mtasts.ErrPolicySyntax):
				// Remote is not doing MTA-STS, continue below. ../rfc/8461:333 ../rfc/8461:574
				log.Debugx("interpreting mtasts error to mean remote is not doing mta-sts", err)

				if errors.Is(err, mtasts.ErrNoRecord) {
					reportResult = tlsrpt.MakeResult(tlsrpt.NoPolicyFound, domain)
				} else {
					fd := policyFetchFailureDetails(err)
					reportResult = tlsrpt.MakeResult(tlsrpt.STS, domain, fd)
				}

			default:
				// Interpret as temporary error, e.g. mtasts.ErrDNS, try again later.

				// Temporary DNS error could be an operational issue on our side, but we can still
				// report it.
				// Result: ../rfc/8460:594
				fd := tlsrpt.Details(tlsrpt.ResultSTSPolicyFetch, mtasts.TLSReportFailureReason(err))
				reportResult = tlsrpt.MakeResult(tlsrpt.STS, domain, fd)

				return nil, reportResult, false, fmt.Errorf("lookup up mta-sts policy: %w", err)
			}
		} else if p.Mode == mtasts.ModeNone {
			reportResult = tlsrpt.MakeResult(tlsrpt.NoPolicyFound, domain)
		} else {
			reportResult = tlsrpt.Result{Policy: tlsrptPolicy(p, ptext, domain)}
		}

		// Insert policy into database. If we could not fetch the policy itself, we back
		// off for 5 minutes. ../rfc/8461:555
		if err == nil || errors.Is(err, mtasts.ErrNoPolicy) || errors.Is(err, mtasts.ErrPolicyFetch) || errors.Is(err, mtasts.ErrPolicySyntax) {
			var recordID string
			if record != nil {
				recordID = record.ID
			}
			if err := Upsert(ctx, domain, recordID, p, ptext); err != nil {
				log.Errorx("inserting policy into cache, continuing", err)
			}
		}

		return p, reportResult, true, nil
	} else if err != nil && errors.Is(err, ErrBackoff) {
		// ../rfc/8461:552
		// We recently failed to fetch a policy, act as if MTA-STS is not implemented.
		// Result: ../rfc/8460:594
		fd := tlsrpt.Details(tlsrpt.ResultSTSPolicyFetch, "back-off-after-recent-fetch-error")
		reportResult = tlsrpt.MakeResult(tlsrpt.STS, domain, fd)
		return nil, reportResult, false, nil
	} else if err != nil {
		// We don't add the result to the report, this is an internal error.
		return nil, reportResult, false, fmt.Errorf("looking up mta-sts policy in cache: %w", err)
	}

	// Policy was found in database. Check in DNS it is still fresh.
	policy = &cachedPolicy.Policy
	nctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	record, _, err := mtasts.LookupRecord(nctx, log.Logger, resolver, domain)
	if err != nil {
		if errors.Is(err, mtasts.ErrNoRecord) {
			if policy.Mode != mtasts.ModeNone {
				log.Errorx("no mtasts dns record while checking non-none policy for freshness, either domain owner removed mta-sts without phasing out policy with a none-policy for period of previous max-age, or this could be an attempt to downgrade to connection without mtasts, continuing with previous policy", err)
			}
			// else, policy will be removed by periodic refresher in the near future.
		} else {
			// Could be a temporary DNS or configuration error.
			log.Errorx("checking for freshness of cached mta-sts dns txt record for domain, continuing with previously cached policy", err)
		}

		// Result: ../rfc/8460:594
		fd := tlsrpt.Details(tlsrpt.ResultSTSPolicyFetch, mtasts.TLSReportFailureReason(err))
		if policy.Mode != mtasts.ModeNone {
			fd.FailureReasonCode += "+fallback-to-cached-policy"
		}
		reportResult = tlsrpt.Result{
			Policy:         tlsrptPolicy(policy, cachedPolicy.PolicyText, domain),
			FailureDetails: []tlsrpt.FailureDetails{fd},
		}
		return policy, reportResult, false, nil
	} else if record.ID == cachedPolicy.RecordID && cachedPolicy.PolicyText != "" {
		// In the past, we didn't store the raw policy lines in cachedPolicy.Lines. We only
		// stop now if we do have policy lines in the cache.
		reportResult = tlsrpt.Result{Policy: tlsrptPolicy(policy, cachedPolicy.PolicyText, domain)}
		return policy, reportResult, true, nil
	}

	// New policy should be available, or we are fetching the policy again because we
	// didn't store the raw policy lines in the past.
	nctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p, ptext, err := mtasts.FetchPolicy(nctx, log.Logger, domain)
	if err != nil {
		log.Errorx("fetching updated policy for domain, continuing with previously cached policy", err)

		fd := policyFetchFailureDetails(err)
		fd.FailureReasonCode += "+fallback-to-cached-policy"
		reportResult = tlsrpt.Result{
			Policy:         tlsrptPolicy(policy, cachedPolicy.PolicyText, domain),
			FailureDetails: []tlsrpt.FailureDetails{fd},
		}
		return policy, reportResult, false, nil
	}
	if err := Upsert(ctx, domain, record.ID, p, ptext); err != nil {
		log.Errorx("inserting refreshed policy into cache, continuing with fresh policy", err)
	}
	reportResult = tlsrpt.Result{Policy: tlsrptPolicy(p, ptext, domain)}
	return p, reportResult, true, nil
}

func policyFetchFailureDetails(err error) tlsrpt.FailureDetails {
	var verificationErr *tls.CertificateVerificationError
	if errors.As(err, &verificationErr) {
		resultType, reasonCode := tlsrpt.TLSFailureDetails(verificationErr)
		// Result: ../rfc/8460:601
		reason := string(resultType)
		if reasonCode != "" {
			reason += "+" + reasonCode
		}
		return tlsrpt.Details(tlsrpt.ResultSTSWebPKIInvalid, reason)
	} else if errors.Is(err, mtasts.ErrPolicySyntax) {
		// Result: ../rfc/8460:598
		return tlsrpt.Details(tlsrpt.ResultSTSPolicyInvalid, mtasts.TLSReportFailureReason(err))
	}
	// Result: ../rfc/8460:594
	return tlsrpt.Details(tlsrpt.ResultSTSPolicyFetch, mtasts.TLSReportFailureReason(err))
}

func tlsrptPolicy(p *mtasts.Policy, policyText string, domain dns.Domain) tlsrpt.ResultPolicy {
	if policyText == "" {
		// We didn't always store original policy lines. Reconstruct.
		policyText = p.String()
	}
	lines := strings.Split(strings.TrimSuffix(policyText, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}

	rp := tlsrpt.ResultPolicy{
		Type:   tlsrpt.STS,
		Domain: domain.ASCII,
		String: lines,
	}
	rp.MXHost = make([]string, len(p.MX))
	for i, mx := range p.MX {
		s := mx.Domain.ASCII
		if mx.Wildcard {
			s = "*." + s
		}
		rp.MXHost[i] = s
	}
	return rp
}
