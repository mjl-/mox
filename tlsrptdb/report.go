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

// TLSReportRecord is a TLS report as a database record, including information
// about the sender.
//
// todo: should be named just Record, but it would cause a sherpa type name conflict.
type TLSReportRecord struct {
	ID         int64  `bstore:"typename Record"`
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
// The report is currently required to only cover a single domain in its policy
// domain. Only reports for known domains are added to the database.
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

	var reportdom, zerodom dns.Domain
	record := TLSReportRecord{0, "", verifiedFromDomain.Name(), mailFrom, hostReport, *r}

	for _, p := range r.Policies {
		pp := p.Policy

		// Check domain, they must all be the same for now. We are not expecting senders to
		// coalesce TLS results for different policy domains in a single report.
		d, err := dns.ParseDomain(pp.Domain)
		if err != nil {
			log.Errorx("invalid domain in tls report", err, slog.Any("domain", pp.Domain), slog.String("mailfrom", mailFrom))
			continue
		}
		if hostReport && d != mox.Conf.Static.HostnameDomain {
			log.Info("unknown mail host policy domain in tls report, not storing", slog.Any("domain", d), slog.String("mailfrom", mailFrom))
			return fmt.Errorf("unknown mail host policy domain")
		} else if _, ok := mox.Conf.Domain(d); !hostReport && !ok {
			log.Info("unknown recipient policy domain in tls report, not storing", slog.Any("domain", d), slog.String("mailfrom", mailFrom))
			return fmt.Errorf("unknown recipient policy domain")
		}
		if reportdom != zerodom && d != reportdom {
			return fmt.Errorf("multiple domains in report %s and %s", reportdom, d)
		}
		reportdom = d

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
	}
	record.Domain = reportdom.Name()
	return db.Insert(ctx, &record)
}

// Records returns all TLS reports in the database.
func Records(ctx context.Context) ([]TLSReportRecord, error) {
	db, err := reportDB(ctx)
	if err != nil {
		return nil, err
	}
	return bstore.QueryDB[TLSReportRecord](ctx, db).List()
}

// RecordID returns the report for the ID.
func RecordID(ctx context.Context, id int64) (TLSReportRecord, error) {
	db, err := reportDB(ctx)
	if err != nil {
		return TLSReportRecord{}, err
	}

	e := TLSReportRecord{ID: id}
	err = db.Get(ctx, &e)
	return e, err
}

// RecordsPeriodPolicyDomain returns the reports overlapping start and end, for the
// given policy domain. If policy domain is empty, records for all domains are
// returned.
func RecordsPeriodDomain(ctx context.Context, start, end time.Time, policyDomain dns.Domain) ([]TLSReportRecord, error) {
	db, err := reportDB(ctx)
	if err != nil {
		return nil, err
	}

	q := bstore.QueryDB[TLSReportRecord](ctx, db)
	var zerodom dns.Domain
	if policyDomain != zerodom {
		q.FilterNonzero(TLSReportRecord{Domain: policyDomain.Name()})
	}
	q.FilterFn(func(r TLSReportRecord) bool {
		dr := r.Report.DateRange
		return !dr.Start.Before(start) && dr.Start.Before(end) || dr.End.After(start) && !dr.End.After(end)
	})
	return q.List()
}
