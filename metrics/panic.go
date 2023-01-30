package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var metricPanic = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mox_panic_total",
		Help: "Number of unhandled panics, by package.",
	},
	[]string{
		"pkg",
	},
)

func PanicInc(pkg string) {
	metricPanic.WithLabelValues(pkg).Inc()
}
