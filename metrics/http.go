// Package metrics has prometheus metric variables/functions.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/exp/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/mlog"
)

var (
	metricHTTPClient = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_httpclient_request_duration_seconds",
			Help:    "HTTP requests lookups.",
			Buckets: []float64{0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30},
		},
		[]string{
			"pkg",
			"method",
			"code",
			"result",
		},
	)
)

// HTTPClientObserve tracks the result of an HTTP transaction in a metric, and
// logs the result.
func HTTPClientObserve(ctx context.Context, log mlog.Log, pkg, method string, statusCode int, err error, start time.Time) {
	log = log.WithPkg("metrics")
	var result string
	switch {
	case err == nil:
		switch statusCode / 100 {
		case 2:
			result = "ok"
		case 4:
			result = "usererror"
		case 5:
			result = "servererror"
		default:
			result = "other"
		}
	case errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		result = "timeout"
	case errors.Is(err, context.Canceled):
		result = "canceled"
	default:
		result = "error"
	}
	metricHTTPClient.WithLabelValues(pkg, method, result, fmt.Sprintf("%d", statusCode)).Observe(float64(time.Since(start)) / float64(time.Second))
	log.Debugx("httpclient result", err, slog.String("pkg", pkg), slog.String("method", method), slog.Int("code", statusCode), slog.Duration("duration", time.Since(start)))
}
