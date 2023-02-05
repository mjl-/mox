package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricAuthentication = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_authentication_total",
			Help: "Authentication attempts and results.",
		},
		[]string{
			"kind",    // submission, imap, httpaccount, httpadmin
			"variant", // login, plain, scram-sha-256, scram-sha-1, cram-md5, httpbasic
			// todo: we currently only use badcreds, but known baduser can be helpful
			"result", // ok, baduser, badpassword, badcreds, error, aborted
		},
	)
)

func AuthenticationInc(kind, variant, result string) {
	metricAuthentication.WithLabelValues(kind, variant, result).Inc()
}
