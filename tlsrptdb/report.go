// Package tlsrptdb stores reports from "SMTP TLS Reporting" in its database.
package tlsrptdb

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/tlsrpt"
)

var (
	metricSession = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_tlsrptdb_session_total",
			Help: "Number of sessions, both success and known result types.",
		},
		[]string{"type"}, // Known result types, and "success"
	)

	knownResultTypes = map[tlsrpt.ResultType]struct{}{
		tlsrpt.ResultSTARTTLSNotSupported:    {},
		tlsrpt.ResultCertificateHostMismatch: {},
		tlsrpt.ResultCertificateExpired:      {},
		tlsrpt.ResultTLSAInvalid:             {},
		tlsrpt.ResultDNSSECInvalid:           {},
		tlsrpt.ResultDANERequired:            {},
		tlsrpt.ResultCertificateNotTrusted:   {},
		tlsrpt.ResultSTSPolicyInvalid:        {},
		tlsrpt.ResultSTSWebPKIInvalid:        {},
		tlsrpt.ResultValidationFailure:       {},
		tlsrpt.ResultSTSPolicyFetch:          {},
	}
)

// Record is a TLS report as a database record, including information
// about the sender.
type Record struct {
	ID         int64
	Domain     string `bstore:"index"` // Policy domain to which the TLS report applies. Unicode.
	FromDomain string
	MailFrom   string
	HostReport bool // Report for host TLSRPT record, as opposed to domain TLSRPT record.
	Report     tlsrpt.Report
}

func reportDB(ctx context.Context) (rdb *bstore.DB, rerr error) {
	mutex.Lock()
	defer mutex.Unlock()
	if ReportDB == nil {
		p := mox.DataDirPath("tlsrpt.db")
		os.MkdirAll(filepath.Dir(p), 0770)
		db, err := bstore.Open(ctx, p, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, ReportDBTypes...)
		if err != nil {
			return nil, err
		}
		ReportDB = db
	}
	return ReportDB, nil
}

// AddReport adds a TLS report to the database.
//
// The report should have come in over SMTP, with a DKIM-validated
// verifiedFromDomain. Using HTTPS for reports is not recommended as there is no
// authentication on the reports origin.
//
// Only reports for known domains are added to the database. Unknown domains are
// ignored without causing an error, unless no known domain was found in the report
// at all.
//
// Prometheus metrics are updated only for configured domains.
func AddReport(ctx context.Context, log mlog.Log, verifiedFromDomain dns.Domain, mailFrom string, hostReport bool, r *tlsrpt.Report) error {
	db, err := reportDB(ctx)
	if err != nil {
		return err
	}

	if len(r.Policies) == 0 {
		return fmt.Errorf("no policies in report")
	}

	var inserted int
	return db.Write(ctx, func(tx *bstore.Tx) error {
		for _, p := range r.Policies {
			pp := p.Policy

			d, err := dns.ParseDomain(pp.Domain)
			if err != nil {
				return fmt.Errorf("invalid domain %v in tls report: %v", d, err)
			}

			if _, ok := mox.Conf.Domain(d); !ok && d != mox.Conf.Static.HostnameDomain {
				log.Info("unknown host/recipient policy domain in tls report, not storing", slog.Any("domain", d), slog.String("mailfrom", mailFrom))
				continue
			}

			metricSession.WithLabelValues("success").Add(float64(p.Summary.TotalSuccessfulSessionCount))
			for _, f := range p.FailureDetails {
				var result string
				if _, ok := knownResultTypes[f.ResultType]; ok {
					result = string(f.ResultType)
				} else {
					result = "other"
				}
				metricSession.WithLabelValues(result).Add(float64(f.FailedSessionCount))
			}

			record := Record{0, d.Name(), verifiedFromDomain.Name(), mailFrom, d == mox.Conf.Static.HostnameDomain, *r}
			if err := tx.Insert(&record); err != nil {
				return fmt.Errorf("inserting report for domain: %w", err)
			}
			inserted++
		}
		if inserted == 0 {
			return fmt.Errorf("no domains in report recognized")
		}
		return nil
	})
}

// Records returns all TLS reports in the database.
func Records(ctx context.Context) ([]Record, error) {
	db, err := reportDB(ctx)
	if err != nil {
		return nil, err
	}
	return bstore.QueryDB[Record](ctx, db).List()
}

// RecordID returns the report for the ID.
func RecordID(ctx context.Context, id int64) (Record, error) {
	db, err := reportDB(ctx)
	if err != nil {
		return Record{}, err
	}

	e := Record{ID: id}
	err = db.Get(ctx, &e)
	return e, err
}

// RecordsPeriodPolicyDomain returns the reports overlapping start and end, for the
// given policy domain. If policy domain is empty, records for all domains are
// returned.
func RecordsPeriodDomain(ctx context.Context, start, end time.Time, policyDomain dns.Domain) ([]Record, error) {
	db, err := reportDB(ctx)
	if err != nil {
		return nil, err
	}

	q := bstore.QueryDB[Record](ctx, db)
	var zerodom dns.Domain
	if policyDomain != zerodom {
		q.FilterNonzero(Record{Domain: policyDomain.Name()})
	}
	q.FilterFn(func(r Record) bool {
		dr := r.Report.DateRange
		return !dr.Start.Before(start) && dr.Start.Before(end) || dr.End.After(start) && !dr.End.After(end)
	})
	return q.List()
}
