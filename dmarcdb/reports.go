package dmarcdb

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
)

var (
	ReportsDBTypes = []any{DomainFeedback{}} // Types stored in DB.
	ReportsDB      *bstore.DB                // Exported for backups.
)

var (
	metricEvaluated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_dmarcdb_policy_evaluated_total",
			Help: "Number of policy evaluations.",
		},
		// We only register validated domains for which we have a config.
		[]string{"domain", "disposition", "dkim", "spf"},
	)
	metricDKIM = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_dmarcdb_dkim_result_total",
			Help: "Number of DKIM results.",
		},
		[]string{"result"},
	)
	metricSPF = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_dmarcdb_spf_result_total",
			Help: "Number of SPF results.",
		},
		[]string{"result"},
	)
)

// DomainFeedback is a single report stored in the database.
type DomainFeedback struct {
	ID int64
	// Domain where DMARC DNS record was found, could be organizational domain.
	Domain string `bstore:"index"`
	// Domain in From-header.
	FromDomain string `bstore:"index"`
	dmarcrpt.Feedback
}

// AddReport adds a DMARC aggregate feedback report from an email to the database,
// and updates prometheus metrics.
//
// fromDomain is the domain in the report message From header.
func AddReport(ctx context.Context, f *dmarcrpt.Feedback, fromDomain dns.Domain) error {
	d, err := dns.ParseDomain(f.PolicyPublished.Domain)
	if err != nil {
		return fmt.Errorf("parsing domain in report: %v", err)
	}

	df := DomainFeedback{0, d.Name(), fromDomain.Name(), *f}
	if err := ReportsDB.Insert(ctx, &df); err != nil {
		return err
	}

	for _, r := range f.Records {
		for _, dkim := range r.AuthResults.DKIM {
			count := r.Row.Count
			if count > 0 {
				metricDKIM.With(prometheus.Labels{
					"result": string(dkim.Result),
				}).Add(float64(count))
			}
		}

		for _, spf := range r.AuthResults.SPF {
			count := r.Row.Count
			if count > 0 {
				metricSPF.With(prometheus.Labels{
					"result": string(spf.Result),
				}).Add(float64(count))
			}
		}

		count := r.Row.Count
		if count > 0 {
			pe := r.Row.PolicyEvaluated
			metricEvaluated.With(prometheus.Labels{
				"domain":      f.PolicyPublished.Domain,
				"disposition": string(pe.Disposition),
				"dkim":        string(pe.DKIM),
				"spf":         string(pe.SPF),
			}).Add(float64(count))
		}
	}
	return nil
}

// Records returns all reports in the database.
func Records(ctx context.Context) ([]DomainFeedback, error) {
	return bstore.QueryDB[DomainFeedback](ctx, ReportsDB).List()
}

// RecordID returns the report for the ID.
func RecordID(ctx context.Context, id int64) (DomainFeedback, error) {
	e := DomainFeedback{ID: id}
	err := ReportsDB.Get(ctx, &e)
	return e, err
}

// RecordsPeriodDomain returns the reports overlapping start and end, for the given
// domain. If domain is empty, all records match for domain.
func RecordsPeriodDomain(ctx context.Context, start, end time.Time, domain string) ([]DomainFeedback, error) {
	s := start.Unix()
	e := end.Unix()

	q := bstore.QueryDB[DomainFeedback](ctx, ReportsDB)
	if domain != "" {
		q.FilterNonzero(DomainFeedback{Domain: domain})
	}
	q.FilterFn(func(d DomainFeedback) bool {
		m := d.Feedback.ReportMetadata.DateRange
		return m.Begin >= s && m.Begin < e || m.End > s && m.End <= e
	})
	return q.List()
}
