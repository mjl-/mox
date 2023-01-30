package mox

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLifecycle(t *testing.T) {
	c := &connections{
		conns:  map[net.Conn]connKind{},
		gauges: map[connKind]prometheus.GaugeFunc{},
		active: map[connKind]int64{},
	}
	nc0, nc1 := net.Pipe()
	defer nc0.Close()
	defer nc1.Close()
	c.Register(nc0, "proto", "listener")
	c.Shutdown()

	done := c.Done()
	select {
	case <-done:
		t.Fatalf("already done, but still a connection open")
	default:
	}

	_, err := nc0.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("expected i/o deadline exceeded, got no error")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v, expected os.ErrDeadlineExceeded", err)
	}
	c.Unregister(nc0)
	select {
	case <-done:
	default:
		t.Fatalf("unregistered connection, but not yet done")
	}
}
