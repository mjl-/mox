// Package iprev checks if an IP has a reverse DNS name configured and that the
// reverse DNS name resolves back to the IP (RFC 8601, Section 3).
package iprev

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

var xlog = mlog.New("iprev")

var (
	metricIPRev = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_iprev_lookup_total",
			Help:    "Number of iprev lookups.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30},
		},
		[]string{"status"},
	)
)

// Lookup errors.
var (
	ErrNoRecord = errors.New("iprev: no reverse dns record")
	ErrDNS      = errors.New("iprev: dns lookup")
)

// ../rfc/8601:1082

// Status is the result of a lookup.
type Status string

const (
	StatusPass      Status = "pass"      // Reverse and forward lookup results were in agreement.
	StatusFail      Status = "fail"      // Reverse and forward lookup results were not in agreement, but at least the reverse name does exist.
	StatusTemperror Status = "temperror" // Temporary error, e.g. DNS timeout.
	StatusPermerror Status = "permerror" // Permanent error and later retry is unlikely to succeed. E.g. no PTR record.
)

// Lookup checks whether an IP has a proper reverse & forward
// DNS configuration. I.e. that it is explicitly associated with its domain name.
//
// A PTR lookup is done on the IP, resulting in zero or more names. These names are
// forward resolved (A or AAAA) until the original IP address is found. The first
// matching name is returned as "name". All names, matching or not, are returned as
// "names".
//
// If a temporary error occurred, rerr is set.
func Lookup(ctx context.Context, resolver dns.Resolver, ip net.IP) (rstatus Status, name string, names []string, authentic bool, rerr error) {
	log := xlog.WithContext(ctx)
	start := time.Now()
	defer func() {
		metricIPRev.WithLabelValues(string(rstatus)).Observe(float64(time.Since(start)) / float64(time.Second))
		log.Debugx("iprev lookup result", rerr, mlog.Field("ip", ip), mlog.Field("status", rstatus), mlog.Field("duration", time.Since(start)))
	}()

	revNames, result, revErr := dns.WithPackage(resolver, "iprev").LookupAddr(ctx, ip.String())
	if dns.IsNotFound(revErr) {
		return StatusPermerror, "", nil, result.Authentic, ErrNoRecord
	} else if revErr != nil {
		return StatusTemperror, "", nil, result.Authentic, fmt.Errorf("%w: %s", ErrDNS, revErr)
	}

	var lastErr error
	authentic = result.Authentic
	for _, rname := range revNames {
		ips, result, err := dns.WithPackage(resolver, "iprev").LookupIP(ctx, "ip", rname)
		authentic = authentic && result.Authentic
		for _, fwdIP := range ips {
			if ip.Equal(fwdIP) {
				return StatusPass, rname, revNames, authentic, nil
			}
		}
		if err != nil && !dns.IsNotFound(err) {
			lastErr = err
		}
	}
	if lastErr != nil {
		return StatusTemperror, "", revNames, authentic, fmt.Errorf("%w: %s", ErrDNS, lastErr)
	}
	return StatusFail, "", revNames, authentic, nil
}
