package stub

import (
	"context"
	"time"

	"golang.org/x/exp/slog"
)

func HTTPClientObserveIgnore(ctx context.Context, log *slog.Logger, pkg, method string, statusCode int, err error, start time.Time) {
}

type Counter interface {
	Inc()
}

type CounterIgnore struct{}

func (CounterIgnore) Inc() {}

type CounterVec interface {
	IncLabels(labels ...string)
}

type CounterVecIgnore struct{}

func (CounterVecIgnore) IncLabels(labels ...string) {}

type Histogram interface {
	Observe(float64)
}

type HistogramIgnore struct{}

func (HistogramIgnore) Observe(float64) {}

type HistogramVec interface {
	ObserveLabels(v float64, labels ...string)
}

type HistogramVecIgnore struct{}

func (HistogramVecIgnore) ObserveLabels(v float64, labels ...string) {}
