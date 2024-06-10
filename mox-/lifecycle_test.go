package mox

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
)

func TestLifecycle(t *testing.T) {
	Shutdown, ShutdownCancel = context.WithCancel(context.Background())
	nc0, nc1 := net.Pipe()
	defer nc0.Close()
	defer nc1.Close()
	Connections.Register(nc0, "proto", "listener")
	Connections.Shutdown()

	done := Connections.Done()
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
	Connections.Unregister(nc0)
	select {
	case <-done:
	default:
		t.Fatalf("unregistered connection, but not yet done")
	}
}
