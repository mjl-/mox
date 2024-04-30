package tlsrptdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/tlsrpt"
)

// TLSResult is stored in the database to track TLS results per policy domain, day
// and recipient domain. These records will be included in TLS reports.
type TLSResult struct {
	ID int64

	// Domain potentially with TLSRPT DNS record, with addresses that will receive
	// reports. Either a recipient domain (for MTA-STS policies) or an (MX) host (for
	// DANE policies). Unicode.
	PolicyDomain string `bstore:"unique PolicyDomain+DayUTC+RecipientDomain,nonzero"`

	// DayUTC is of the form yyyymmdd.
	DayUTC string `bstore:"nonzero"`
	// We send per 24h UTC-aligned days. ../rfc/8460:474

	// Reports are sent per recipient domain and per MX host. For reports to a
	// recipient domain, we type send a result for MTA-STS and one or more MX host
	// (DANE) results. Unicode.
	RecipientDomain string `bstore:"index,nonzero"`

	Created time.Time `bstore:"default now"`
	Updated time.Time `bstore:"default now"`

	IsHost bool // Result is for MX host (DANE), not recipient domain (MTA-STS).

	// Whether to send a report. TLS results for delivering messages with TLS reports
	// will be recorded, but will not cause a report to be sent.
	SendReport bool
	// ../rfc/8460:318 says we should not include TLS results for sending a TLS report,
	// but presumably that's to prevent mail servers sending a report every day once
	// they start.

	// Set after sending to recipient domain, before sending results to policy domain
	// (after which the record is removed).
	SentToRecipientDomain bool
	// Reporting addresses from the recipient domain TLSRPT record, not necessarily
	// those we sent to (e.g. due to failure). Used to leave results to MX target
	// (DANE) policy domains out that were already sent in the report to the recipient
	// domain, so we don't report twice.
	RecipientDomainReportingAddresses []string
	// Set after sending report to policy domain.
	SentToPolicyDomain bool

	// Results is updated for each TLS attempt.
	Results []tlsrpt.Result
}

// SuppressAddress is a reporting address for which outgoing TLS reports
// will be suppressed for a period.
type SuppressAddress struct {
	ID               int64     `bstore:"typename TLSRPTSuppressAddress"`
	Inserted         time.Time `bstore:"default now"`
	ReportingAddress string    `bstore:"unique"`
	Until            time.Time `bstore:"nonzero"`
	Comment          string
}

func resultDB(ctx context.Context) (rdb *bstore.DB, rerr error) {
	mutex.Lock()
	defer mutex.Unlock()
	if ResultDB == nil {
		p := mox.DataDirPath("tlsrptresult.db")
		os.MkdirAll(filepath.Dir(p), 0770)
		db, err := bstore.Open(ctx, p, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, ResultDBTypes...)
		if err != nil {
			return nil, err
		}
		ResultDB = db
	}
	return ResultDB, nil
}

// AddTLSResults adds or merges all tls results for delivering to a policy domain,
// on its UTC day to a recipient domain to the database. Results may cause multiple
// separate reports to be sent.
func AddTLSResults(ctx context.Context, results []TLSResult) error {
	db, err := resultDB(ctx)
	if err != nil {
		return err
	}

	now := time.Now()

	err = db.Write(ctx, func(tx *bstore.Tx) error {
		for _, result := range results {
			// Ensure all slices are non-nil. We do this now so all readers will marshal to
			// compliant with the JSON schema. And also for consistent equality checks when
			// merging policies created in different places.
			for i, r := range result.Results {
				if r.Policy.String == nil {
					r.Policy.String = []string{}
				}
				if r.Policy.MXHost == nil {
					r.Policy.MXHost = []string{}
				}
				if r.FailureDetails == nil {
					r.FailureDetails = []tlsrpt.FailureDetails{}
				}
				result.Results[i] = r
			}

			q := bstore.QueryTx[TLSResult](tx)
			q.FilterNonzero(TLSResult{PolicyDomain: result.PolicyDomain, DayUTC: result.DayUTC, RecipientDomain: result.RecipientDomain})
			r, err := q.Get()
			if err == bstore.ErrAbsent {
				result.ID = 0
				if err := tx.Insert(&result); err != nil {
					return fmt.Errorf("insert: %w", err)
				}
				continue
			} else if err != nil {
				return err
			}

			report := tlsrpt.Report{Policies: r.Results}
			report.Merge(result.Results...)
			r.Results = report.Policies

			r.IsHost = result.IsHost
			if result.SendReport {
				r.SendReport = true
			}
			r.Updated = now
			if err := tx.Update(&r); err != nil {
				return fmt.Errorf("update: %w", err)
			}
		}
		return nil
	})
	return err
}

// Results returns all TLS results in the database, for all policy domains each
// with potentially multiple days. Sorted by RecipientDomain and day.
func Results(ctx context.Context) ([]TLSResult, error) {
	db, err := resultDB(ctx)
	if err != nil {
		return nil, err
	}

	return bstore.QueryDB[TLSResult](ctx, db).SortAsc("PolicyDomain", "DayUTC", "RecipientDomain").List()
}

// ResultsDomain returns all TLSResults for a policy domain, potentially for
// multiple days.
func ResultsPolicyDomain(ctx context.Context, policyDomain dns.Domain) ([]TLSResult, error) {
	db, err := resultDB(ctx)
	if err != nil {
		return nil, err
	}

	return bstore.QueryDB[TLSResult](ctx, db).FilterNonzero(TLSResult{PolicyDomain: policyDomain.Name()}).SortAsc("DayUTC", "RecipientDomain").List()
}

// ResultsRecipientDomain returns all TLSResults for a recipient domain,
// potentially for multiple days.
func ResultsRecipientDomain(ctx context.Context, recipientDomain dns.Domain) ([]TLSResult, error) {
	db, err := resultDB(ctx)
	if err != nil {
		return nil, err
	}

	return bstore.QueryDB[TLSResult](ctx, db).FilterNonzero(TLSResult{RecipientDomain: recipientDomain.Name()}).SortAsc("DayUTC", "PolicyDomain").List()
}

// RemoveResultsPolicyDomain removes all TLSResults for the policy domain on the
// day from the database.
func RemoveResultsPolicyDomain(ctx context.Context, policyDomain dns.Domain, dayUTC string) error {
	db, err := resultDB(ctx)
	if err != nil {
		return err
	}

	_, err = bstore.QueryDB[TLSResult](ctx, db).FilterNonzero(TLSResult{PolicyDomain: policyDomain.Name(), DayUTC: dayUTC}).Delete()
	return err
}

// RemoveResultsRecipientDomain removes all TLSResults for the recipient domain on
// the day from the database.
func RemoveResultsRecipientDomain(ctx context.Context, recipientDomain dns.Domain, dayUTC string) error {
	db, err := resultDB(ctx)
	if err != nil {
		return err
	}

	_, err = bstore.QueryDB[TLSResult](ctx, db).FilterNonzero(TLSResult{RecipientDomain: recipientDomain.Name(), DayUTC: dayUTC}).Delete()
	return err
}

// SuppressAdd adds an address to the suppress list.
func SuppressAdd(ctx context.Context, ba *SuppressAddress) error {
	db, err := resultDB(ctx)
	if err != nil {
		return err
	}

	return db.Insert(ctx, ba)
}

// SuppressList returns all reporting addresses on the suppress list.
func SuppressList(ctx context.Context) ([]SuppressAddress, error) {
	db, err := resultDB(ctx)
	if err != nil {
		return nil, err
	}

	return bstore.QueryDB[SuppressAddress](ctx, db).SortDesc("ID").List()
}

// SuppressRemove removes a reporting address record from the suppress list.
func SuppressRemove(ctx context.Context, id int64) error {
	db, err := resultDB(ctx)
	if err != nil {
		return err
	}

	return db.Delete(ctx, &SuppressAddress{ID: id})
}

// SuppressUpdate updates the until field of a reporting address record.
func SuppressUpdate(ctx context.Context, id int64, until time.Time) error {
	db, err := resultDB(ctx)
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
