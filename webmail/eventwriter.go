package webmail

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/store"
)

type eventWriter struct {
	out              writeFlusher
	waitMin, waitMax time.Duration

	// If connection is closed, the goroutine doing delayed writes must abort.
	sync.Mutex
	closed bool

	// Before writing an event, we check if session is still valid. If not, we send a
	// fatal error instead.
	accountName  string
	sessionToken store.SessionToken

	wrote  bool // To be reset by user, set on write.
	events chan struct {
		name string    // E.g. "start" for EventStart.
		v    any       // Written as JSON.
		when time.Time // For delaying.
	} // Will only be set when waitMin or waitMax is > 0. Closed on connection shutdown.
	errors chan error // If we have an events channel, we read errors and abort for them.
}

func newEventWriter(out writeFlusher, waitMin, waitMax time.Duration, accountName string, sessionToken store.SessionToken) *eventWriter {
	return &eventWriter{out: out, waitMin: waitMin, waitMax: waitMax, accountName: accountName, sessionToken: sessionToken}
}

// close shuts down the events channel, causing the goroutine (if created) to
// stop.
func (ew *eventWriter) close() {
	if ew.events != nil {
		close(ew.events)
	}
	ew.Lock()
	defer ew.Unlock()
	ew.closed = true
}

// Write an event to the connection, e.g. "start" with value v, written as
// JSON. This directly writes the event, no more delay.
func (ew *eventWriter) write(name string, v any) error {
	bw := bufio.NewWriter(ew.out)
	if _, err := fmt.Fprintf(bw, "event: %s\ndata: ", name); err != nil {
		return err
	} else if err := json.NewEncoder(bw).Encode(v); err != nil {
		return err
	} else if _, err := fmt.Fprint(bw, "\n"); err != nil {
		return err
	} else if err := bw.Flush(); err != nil {
		return err
	}
	return ew.out.Flush()
}

// For random wait between min and max delay.
var waitGen = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

// Schedule an event for writing to the connection. If events get a delay, this
// function still returns immediately.
func (ew *eventWriter) xsendEvent(ctx context.Context, log mlog.Log, name string, v any) {
	if name != "fatalErr" {
		if _, err := store.SessionUse(ctx, log, ew.accountName, ew.sessionToken, ""); err != nil {
			ew.xsendEvent(ctx, log, "fatalErr", "session no longer valid")
			return
		}
	}

	if (ew.waitMin > 0 || ew.waitMax > 0) && ew.events == nil {
		// First write on a connection with delay.
		ew.events = make(chan struct {
			name string
			v    any
			when time.Time
		}, 100)
		ew.errors = make(chan error)
		go func() {
			defer func() {
				x := recover() // Should not happen, but don't take program down if it does.
				if x != nil {
					log.WithContext(ctx).Error("writeEvent panic", slog.Any("err", x))
					debug.PrintStack()
					metrics.PanicInc(metrics.Webmailsendevent)
				}
			}()

			for {
				ev, ok := <-ew.events
				if !ok {
					return
				}
				d := time.Until(ev.when)
				if d > 0 {
					time.Sleep(d)
				}
				ew.Lock()
				if ew.closed {
					ew.Unlock()
					return
				}
				err := ew.write(ev.name, ev.v)
				ew.Unlock()
				if err != nil {
					ew.errors <- err
					return
				}
			}
		}()
	}
	// Check for previous write error before continuing.
	if ew.errors != nil {
		select {
		case err := <-ew.errors:
			panic(ioErr{err})
		default:
			break
		}
	}
	// If we have an events channel, we have a goroutine that write the events, delayed.
	if ew.events != nil {
		wait := ew.waitMin + time.Duration(waitGen.Intn(1000))*(ew.waitMax-ew.waitMin)/1000
		when := time.Now().Add(wait)
		ew.events <- struct {
			name string
			v    any
			when time.Time
		}{name, v, when}
	} else {
		err := ew.write(name, v)
		if err != nil {
			panic(ioErr{err})
		}
	}
	ew.wrote = true
}

// writeFlusher is a writer and flusher. We need to flush after writing an
// Event. Both to flush pending gzip data to the http response, and the http
// response to the client.
type writeFlusher interface {
	io.Writer
	Flush() error
}

// nopFlusher is a standin for writeFlusher if gzip is not used.
type nopFlusher struct {
	io.Writer
}

func (f nopFlusher) Flush() error {
	return nil
}

// httpFlusher wraps Flush for a writeFlusher with a call to an http.Flusher.
type httpFlusher struct {
	writeFlusher
	f http.Flusher
}

// Flush flushes the underlying writeFlusher, and calls Flush on the http.Flusher
// (which doesn't return an error).
func (f httpFlusher) Flush() error {
	err := f.writeFlusher.Flush()
	f.f.Flush()
	return err
}
