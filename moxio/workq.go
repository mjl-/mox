package moxio

import (
	"sync"
)

// Work is a slot for work that needs to be done.
type Work[T, R any] struct {
	In  T
	Err error
	Out R

	i    int
	done bool
}

// WorkQueue can be used to execute a work load where many items are processed
// with a slow step and where a pool of workers goroutines to execute the slow
// step helps. Reading messages from the database file is fast and cannot be
// easily done concurrently, but reading the message file from disk and parsing
// the headers is the bottleneck. The workqueue can manage the goroutines that
// read the message file from disk and parse.
type WorkQueue[T, R any] struct {
	max   int
	ring  []Work[T, R]
	start int
	n     int

	wg   sync.WaitGroup // For waiting for workers to stop.
	work chan Work[T, R]
	done chan Work[T, R]

	process func(T, R) error
}

// NewWorkQueue creates a new work queue with "procs" goroutines, and a total work
// queue size of "size" (e.g. 2*procs). The worker goroutines run "preparer", which
// should be a loop receiving work from "in" and sending the work result (with Err
// or Out set) on "out". The preparer function should return when the "in" channel
// is closed, the signal to stop. WorkQueue processes the results in the order they
// went in, so prepared work that was scheduled after earlier work that is not yet
// prepared will wait and be queued.
func NewWorkQueue[T, R any](procs, size int, preparer func(in, out chan Work[T, R]), process func(T, R) error) *WorkQueue[T, R] {
	wq := &WorkQueue[T, R]{
		max:     size,
		ring:    make([]Work[T, R], size),
		work:    make(chan Work[T, R], size), // Ensure scheduling never blocks for main goroutine.
		done:    make(chan Work[T, R], size), // Ensure sending result never blocks for worker goroutine.
		process: process,
	}

	wq.wg.Add(procs)
	for i := 0; i < procs; i++ {
		go func() {
			defer wq.wg.Done()
			preparer(wq.work, wq.done)
		}()
	}

	return wq
}

// Add adds new work to be prepared to the queue. If the queue is full, it
// waits until space becomes available, i.e. when the head of the queue has
// work that becomes prepared. Add processes the prepared items to make space
// available.
func (wq *WorkQueue[T, R]) Add(in T) error {
	// Schedule the new work if we can.
	if wq.n < wq.max {
		wq.work <- Work[T, R]{i: (wq.start + wq.n) % wq.max, done: true, In: in}
		wq.n++
		return nil
	}

	// We cannot schedule new work. Wait for finished work until start is done.
	for {
		w := <-wq.done
		wq.ring[w.i] = w
		if w.i == wq.start {
			break
		}
	}

	// Process as much finished work as possible. Will be at least 1.
	if err := wq.processHead(); err != nil {
		return err
	}

	// Schedule this message as new work.
	wq.work <- Work[T, R]{i: (wq.start + wq.n) % wq.max, done: true, In: in}
	wq.n++
	return nil
}

// processHead processes the work at the head of the queue by calling process
// on the work.
func (wq *WorkQueue[T, R]) processHead() error {
	for wq.n > 0 && wq.ring[wq.start].done {
		wq.ring[wq.start].done = false
		w := wq.ring[wq.start]
		wq.start = (wq.start + 1) % len(wq.ring)
		wq.n -= 1

		if w.Err != nil {
			return w.Err
		}
		if err := wq.process(w.In, w.Out); err != nil {
			return err
		}
	}
	return nil
}

// Finish waits for the remaining work to be prepared and processes the work.
func (wq *WorkQueue[T, R]) Finish() error {
	var err error
	for wq.n > 0 && err == nil {
		w := <-wq.done
		wq.ring[w.i] = w

		err = wq.processHead()
	}
	return err
}

// Stop shuts down the worker goroutines and waits until they have returned.
// Stop must always be called on a WorkQueue, otherwise the goroutines never stop.
func (wq *WorkQueue[T, R]) Stop() {
	close(wq.work)
	wq.wg.Wait()
}
