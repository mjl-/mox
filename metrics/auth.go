package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricAuth = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_authentication_total",
			Help: "Authentication attempts and results.",
		},
		[]string{
			"kind",    // submission, imap, webmail, webaccount, webadmin (formerly httpaccount, httpadmin)
			"variant", // login, plain, scram-sha-256, scram-sha-1, cram-md5, weblogin, websessionuse. formerly: httpbasic.
			// todo: we currently only use badcreds, but known baduser can be helpful
			"result", // ok, baduser, badpassword, badcreds, error, aborted
		},
	)

	metricAuthRatelimited = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_authentication_ratelimited_total",
			Help: "Authentication attempts that were refused due to rate limiting.",
		},
		[]string{
			"kind", // submission, imap, httpaccount, httpadmin
		},
	)
)

func AuthenticationInc(kind, variant, result string) {
	metricAuth.WithLabelValues(kind, variant, result).Inc()
}

func AuthenticationRatelimitedInc(kind string) {
	metricAuthRatelimited.WithLabelValues(kind).Inc()
}
