package proxyprotocol

import (
	"net"
	"sync"
)

// Listener wraps a TCP listener and only returns connections after a valid
// PROXY protocol header has been read. Connections with an invalid header are
// closed and skipped, so a client cannot make users of net.Listener stop
// accepting connections by sending a malformed header.
//
// Header processing happens in separate goroutines. This keeps Accept
// available for other connections while a proxy is slow to send its header.
// Close also closes connections whose headers are still being processed.
type Listener struct {
	net.Listener
	trustedProxies []*net.IPNet

	startOnce sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup

	mu          sync.Mutex
	closed      bool
	handshakes  map[net.Conn]struct{}
	closeErr    error
	terminalErr error

	done     chan struct{}
	loopDone chan struct{}
	results  chan listenerResult
}

type listenerResult struct {
	conn net.Conn
	raw  net.Conn
	err  error
}

// NewListener wraps listener with strict PROXY protocol handling. The caller
// retains ownership of listener and should use the returned listener from then
// on, including for Close.
func NewListener(listener net.Listener, trustedProxies []*net.IPNet) *Listener {
	return &Listener{
		Listener:       listener,
		trustedProxies: trustedProxies,
		handshakes:     map[net.Conn]struct{}{},
		done:           make(chan struct{}),
		loopDone:       make(chan struct{}),
		results:        make(chan listenerResult, 64),
	}
}

func (l *Listener) start() {
	l.startOnce.Do(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.closed {
			return
		}
		l.wg.Add(1)
		go l.acceptLoop()
	})
}

func (l *Listener) acceptLoop() {
	defer l.wg.Done()
	defer close(l.loopDone)

	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if !closed {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					select {
					case l.results <- listenerResult{err: err}:
					case <-l.done:
						return
					}
					continue
				}
				l.mu.Lock()
				l.terminalErr = err
				l.mu.Unlock()
			}
			return
		}

		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			_ = conn.Close()
			return
		}
		l.handshakes[conn] = struct{}{}
		l.wg.Add(1)
		l.mu.Unlock()
		go l.handshake(conn)
	}
}

func (l *Listener) handshake(raw net.Conn) {
	defer l.wg.Done()

	conn, err := NewConn(raw, l.trustedProxies)
	if err != nil {
		l.removeHandshake(raw)
		_ = raw.Close()
		return
	}

	// Keep the raw connection in handshakes until Accept claims it. This lets
	// Close reliably close a connection that has finished parsing but has not
	// yet been handed to the caller.
	select {
	case l.results <- listenerResult{conn: conn, raw: raw}:
	case <-l.done:
		l.removeHandshake(raw)
		_ = raw.Close()
	}
}

func (l *Listener) removeHandshake(conn net.Conn) {
	l.mu.Lock()
	delete(l.handshakes, conn)
	l.mu.Unlock()
}

// Accept waits for a connection whose PROXY header has been fully processed.
// Connections with malformed headers are closed and ignored.
func (l *Listener) Accept() (net.Conn, error) {
	l.start()

	select {
	case result := <-l.results:
		if result.err != nil {
			select {
			case <-l.done:
				return nil, net.ErrClosed
			default:
			}
			return nil, result.err
		}
		l.mu.Lock()
		delete(l.handshakes, result.raw)
		closed := l.closed
		l.mu.Unlock()
		if closed {
			if result.conn != nil {
				_ = result.conn.Close()
			}
			return nil, net.ErrClosed
		}
		return result.conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.loopDone:
		l.mu.Lock()
		err := l.terminalErr
		l.mu.Unlock()
		if err == nil {
			return nil, net.ErrClosed
		}
		return nil, err
	}
}

// Close closes the underlying listener and all connections still waiting for
// their PROXY headers to be parsed.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		close(l.done)
		conns := make([]net.Conn, 0, len(l.handshakes))
		for conn := range l.handshakes {
			conns = append(conns, conn)
		}
		l.mu.Unlock()

		l.closeErr = l.Listener.Close()
		for _, conn := range conns {
			_ = conn.Close()
		}
		l.wg.Wait()
		for {
			select {
			case result := <-l.results:
				if result.conn != nil {
					_ = result.conn.Close()
				}
			default:
				return
			}
		}
	})
	return l.closeErr
}
