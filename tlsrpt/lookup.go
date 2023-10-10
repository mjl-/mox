package tlsrpt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

var xlog = mlog.New("tlsrpt")

var (
	metricLookup = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_tlsrpt_lookup_duration_seconds",
			Help:    "TLSRPT lookups with result.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30},
		},
		[]string{"result"},
	)
)

var (
	ErrNoRecord        = errors.New("tlsrpt: no tlsrpt dns txt record")
	ErrMultipleRecords = errors.New("tlsrpt: multiple tlsrpt records") // Must be treated as if domain does not implement TLSRPT.
	ErrDNS             = errors.New("tlsrpt: temporary error")
	ErrRecordSyntax    = errors.New("tlsrpt: record syntax error")
)

// Lookup looks up a TLSRPT DNS TXT record for domain at "_smtp._tls.<domain>" and
// parses it.
func Lookup(ctx context.Context, resolver dns.Resolver, domain dns.Domain) (rrecord *Record, rtxt string, rerr error) {
	log := xlog.WithContext(ctx)
	start := time.Now()
	defer func() {
		result := "ok"
		if rerr != nil {
			if errors.Is(rerr, ErrNoRecord) {
				result = "notfound"
			} else if errors.Is(rerr, ErrMultipleRecords) {
				result = "multiple"
			} else if errors.Is(rerr, ErrDNS) {
				result = "temperror"
			} else if errors.Is(rerr, ErrRecordSyntax) {
				result = "malformed"
			} else {
				result = "error"
			}
		}
		metricLookup.WithLabelValues(result).Observe(float64(time.Since(start)) / float64(time.Second))
		log.Debugx("tlsrpt lookup result", rerr, mlog.Field("domain", domain), mlog.Field("record", rrecord), mlog.Field("duration", time.Since(start)))
	}()

	name := "_smtp._tls." + domain.ASCII + "."
	txts, _, err := dns.WithPackage(resolver, "tlsrpt").LookupTXT(ctx, name)
	if dns.IsNotFound(err) {
		return nil, "", ErrNoRecord
	} else if err != nil {
		return nil, "", fmt.Errorf("%w: %s", ErrDNS, err)
	}

	var text string
	var record *Record
	for _, txt := range txts {
		r, istlsrpt, err := ParseRecord(txt)
		if !istlsrpt {
			// This is a loose but probably reasonable interpretation of ../rfc/8460:375 which
			// wants us to discard otherwise valid records that start with e.g. "v=TLSRPTv1 ;"
			// (note the space before the ";") when multiple TXT records were returned.
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("parsing record: %w", err)
		}
		if record != nil {
			return nil, "", ErrMultipleRecords
		}
		record = r
		text = txt
	}
	if record == nil {
		return nil, "", ErrNoRecord
	}
	return record, text, nil
}
