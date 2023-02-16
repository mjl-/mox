package mox

import (
	"context"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Shutdown is canceled when a graceful shutdown is initiated. SMTP, IMAP, periodic
// processes should check this before starting a new operation. If true, the
// operation should be aborted, and new connections should receive a message that
// the service is currently not available.
var Shutdown context.Context
var ShutdownCancel func()

// Context should be used as parent by all operations. It is canceled when mox is
// shutdown, aborting all pending operations.
//
// Operations typically have context timeouts, 30s for single i/o like DNS queries,
// and 1 minute for operations with more back and forth. These are set through a
// context.WithTimeout based on this context, so those contexts are still canceled
// when shutting down.
//
// HTTP servers don't get graceful shutdown, their connections are just aborted.
var Context context.Context
var ContextCancel func()

// Connections holds all active protocol sockets (smtp, imap). They will be given
// an immediate read/write deadline shortly after initiating mox shutdown, after
// which the connections get 1 more second for error handling before actual
// shutdown.
var Connections = &connections{
	conns:  map[net.Conn]connKind{},
	gauges: map[connKind]prometheus.GaugeFunc{},
	active: map[connKind]int64{},
}

type connKind struct {
	protocol string
	listener string
}

type connections struct {
	sync.Mutex
	conns  map[net.Conn]connKind
	dones  []chan struct{}
	gauges map[connKind]prometheus.GaugeFunc

	activeMutex sync.Mutex
	active      map[connKind]int64
}

// Register adds a connection for receiving an immediate i/o deadline on shutdown.
// When the connection is closed, Remove must be called to cancel the registration.
func (c *connections) Register(nc net.Conn, protocol, listener string) {
	// This can happen, when a connection was initiated before a shutdown, but it
	// doesn't hurt to log it.
	select {
	case <-Shutdown.Done():
		xlog.Error("new connection added while shutting down")
		debug.PrintStack()
	default:
	}

	ck := connKind{protocol, listener}

	c.activeMutex.Lock()
	c.active[ck]++
	c.activeMutex.Unlock()

	c.Lock()
	defer c.Unlock()
	c.conns[nc] = ck
	if _, ok := c.gauges[ck]; !ok {
		c.gauges[ck] = promauto.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "mox_connections_count",
				Help: "Open connections, per protocol/listener.",
				ConstLabels: prometheus.Labels{
					"protocol": protocol,
					"listener": listener,
				},
			},
			func() float64 {
				c.activeMutex.Lock()
				defer c.activeMutex.Unlock()
				return float64(c.active[ck])
			},
		)
	}
}

// Unregister removes a connection for shutdown.
func (c *connections) Unregister(nc net.Conn) {
	c.Lock()
	defer c.Unlock()
	ck := c.conns[nc]

	defer func() {
		c.activeMutex.Lock()
		c.active[ck]--
		c.activeMutex.Unlock()
	}()

	delete(c.conns, nc)
	if len(c.conns) > 0 {
		return
	}
	for _, done := range c.dones {
		done <- struct{}{}
	}
	c.dones = nil
}

// Shutdown sets an immediate i/o deadline on all open registered sockets. Called
// some time after mox shutdown is initiated.
// The deadline will cause i/o's to be aborted, which should result in the
// connection being unregistered.
func (c *connections) Shutdown() {
	now := time.Now()
	c.Lock()
	defer c.Unlock()
	for nc := range c.conns {
		if err := nc.SetDeadline(now); err != nil {
			xlog.Errorx("setting immediate read/write deadline for shutdown", err)
		}
	}
}

// Done returns a new channel on which a value is sent when no more sockets are
// open, which could be immediate.
func (c *connections) Done() chan struct{} {
	c.Lock()
	defer c.Unlock()
	done := make(chan struct{}, 1)
	if len(c.conns) == 0 {
		done <- struct{}{}
		return done
	}
	c.dones = append(c.dones, done)
	return done
}
