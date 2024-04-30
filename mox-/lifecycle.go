package mox

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// We start up as root, bind to sockets, open private key/cert files and fork and
// exec as unprivileged user. During startup as root, we gather the fd's for the
// listen addresses in passedListeners and files in passedFiles, and pass their
// addresses and paths in environment variables to the new process.
var passedListeners = map[string]*os.File{} // Listen address to file descriptor.
var passedFiles = map[string][]*os.File{}   // Path to file descriptors.

// RestorePassedFiles reads addresses from $MOX_SOCKETS and paths from $MOX_FILES
// and prepares an os.File for each file descriptor, which are used by later calls
// of Listen or opening files.
func RestorePassedFiles() {
	s := os.Getenv("MOX_SOCKETS")
	if s == "" {
		var linuxhint string
		if runtime.GOOS == "linux" {
			linuxhint = " If you updated from v0.0.1, update the mox.service file to start as root (privileges are dropped): ./mox config printservice >mox.service && sudo systemctl daemon-reload && sudo systemctl restart mox."
		}
		pkglog.Fatal("mox must be started as root, and will drop privileges after binding required sockets (missing environment variable MOX_SOCKETS)." + linuxhint)
	}

	// 0,1,2 are stdin,stdout,stderr, 3 is the first passed fd (first listeners, then files).
	var o uintptr = 3
	for _, addr := range strings.Split(s, ",") {
		passedListeners[addr] = os.NewFile(o, addr)
		o++
	}

	files := os.Getenv("MOX_FILES")
	if files == "" {
		return
	}
	for _, path := range strings.Split(files, ",") {
		passedFiles[path] = append(passedFiles[path], os.NewFile(o, path))
		o++
	}
}

// CleanupPassedFiles closes the listening socket file descriptors and files passed
// in by the parent process. To be called by the unprivileged child after listeners
// have been recreated (they dup the file descriptor), and by the privileged
// process after starting its child.
func CleanupPassedFiles() {
	for _, f := range passedListeners {
		err := f.Close()
		pkglog.Check(err, "closing listener socket file descriptor")
	}
	for _, fl := range passedFiles {
		for _, f := range fl {
			err := f.Close()
			pkglog.Check(err, "closing path file descriptor")
		}
	}
}

// For privileged file descriptor operations (listen and opening privileged files),
// perform them immediately, regardless of running as root or other user, in case
// ForkExecUnprivileged is not used.
var FilesImmediate bool

// Listen returns a newly created network listener when starting as root, and
// otherwise (not root) returns a network listener from a file descriptor that was
// passed by the parent root process.
func Listen(network, addr string) (net.Listener, error) {
	if os.Getuid() != 0 && !FilesImmediate {
		f, ok := passedListeners[addr]
		if !ok {
			return nil, fmt.Errorf("no file descriptor for listener %s", addr)
		}
		ln, err := net.FileListener(f)
		if err != nil {
			return nil, fmt.Errorf("making network listener from file descriptor for address %s: %v", addr, err)
		}
		return ln, nil
	}

	if _, ok := passedListeners[addr]; ok {
		return nil, fmt.Errorf("duplicate listener: %s", addr)
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	// On windows, we cannot duplicate a socket. We don't need to for mox localserve
	// with FilesImmediate.
	if !FilesImmediate {
		tcpln, ok := ln.(*net.TCPListener)
		if !ok {
			return nil, fmt.Errorf("listener not a tcp listener, but %T, for network %s, address %s", ln, network, addr)
		}
		f, err := tcpln.File()
		if err != nil {
			return nil, fmt.Errorf("dup listener: %v", err)
		}
		passedListeners[addr] = f
	}
	return ln, err
}

// Open a privileged file, such as a TLS private key. When running as root
// (during startup), the file is opened and the file descriptor is stored.
// These file descriptors are passed to the unprivileged process. When in the
// unprivileged processed, we lookup a passed file descriptor.
// The same calls should be made in the privileged and unprivileged process.
func OpenPrivileged(path string) (*os.File, error) {
	if os.Getuid() != 0 && !FilesImmediate {
		fl := passedFiles[path]
		if len(fl) == 0 {
			return nil, fmt.Errorf("no file descriptor for file %s", path)
		}
		f := fl[0]
		passedFiles[path] = fl[1:]
		return f, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	passedFiles[path] = append(passedFiles[path], f)

	// Open again, the caller will be closing this file.
	return os.Open(path)
}

// Shutdown is canceled when a graceful shutdown is initiated. SMTP, IMAP, periodic
// processes should check this before starting a new operation. If this context is
// canaceled, the operation should not be started, and new connections/commands should
// receive a message that the service is currently not available.
var Shutdown context.Context
var ShutdownCancel func()

// This context should be used as parent by most operations. It is canceled 1
// second after graceful shutdown was initiated with the cancelation of the
// Shutdown context. This should abort active operations.
//
// Operations typically have context timeouts, 30s for single i/o like DNS queries,
// and 1 minute for operations with more back and forth. These are set through a
// context.WithTimeout based on this context, so those contexts are still canceled
// when shutting down.
//
// HTTP servers don't get graceful shutdown, their connections are just aborted.
// todo: should shut down http connections as well, and shut down the listener and/or return 503 for new requests.
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
		pkglog.Error("new connection added while shutting down")
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
			pkglog.Errorx("setting immediate read/write deadline for shutdown", err)
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
