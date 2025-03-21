// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package adns

import (
	"context"
	"errors"
	"net"
)

// Various errors contained in OpError.
var (
	// For connection setup operations.
	errNoSuitableAddress = errors.New("no suitable address found")

	// For both read and write operations.
	errCanceled = canceledError{}
)

// canceledError lets us return the same error string we have always
// returned, while still being Is context.Canceled.
type canceledError struct{}

func (canceledError) Error() string { return "operation was canceled" }

func (canceledError) Is(err error) bool { return err == context.Canceled }

// mapErr maps from the context errors to the historical internal net
// error values.
func mapErr(err error) error {
	switch err {
	case context.Canceled:
		return errCanceled
	case context.DeadlineExceeded:
		return errTimeout
	default:
		return err
	}
}

// Various errors contained in DNSError.
var (
	errNoSuchHost  = &notFoundError{"no such host"}
	errUnknownPort = &notFoundError{"unknown port"}
)

// notFoundError is a special error understood by the newDNSError function,
// which causes a creation of a DNSError with IsNotFound field set to true.
type notFoundError struct{ s string }

func (e *notFoundError) Error() string { return e.s }

// temporaryError is an error type that implements the [Error] interface.
// It returns true from the Temporary method.
type temporaryError struct{ s string }

func (e *temporaryError) Error() string   { return e.s }
func (e *temporaryError) Temporary() bool { return true }
func (e *temporaryError) Timeout() bool   { return false }

// errTimeout exists to return the historical "i/o timeout" string
// for context.DeadlineExceeded. See mapErr.
// It is also used when Dialer.Deadline is exceeded.
// error.Is(errTimeout, context.DeadlineExceeded) returns true.
//
// TODO(iant): We could consider changing this to os.ErrDeadlineExceeded
// in the future, if we make
//
//	errors.Is(os.ErrDeadlineExceeded, context.DeadlineExceeded)
//
// return true.
var errTimeout error = &timeoutError{}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func (e *timeoutError) Is(err error) bool {
	return err == context.DeadlineExceeded
}

// DNSError represents a DNS lookup error.
type DNSError struct {
	UnwrapErr   error  // error returned by the [DNSError.Unwrap] method, might be nil
	Err         string // description of the error
	Name        string // name looked for
	Server      string // server used
	IsTimeout   bool   // if true, timed out; not all timeouts set this
	IsTemporary bool   // if true, error is temporary; not all errors set this

	// IsNotFound is set to true when the requested name does not
	// contain any records of the requested type (data not found),
	// or the name itself was not found (NXDOMAIN).
	IsNotFound bool
}

// newDNSError creates a new *DNSError.
// Based on the err, it sets the UnwrapErr, IsTimeout, IsTemporary, IsNotFound fields.
func newDNSError(err error, name, server string) *DNSError {
	var (
		isTimeout   bool
		isTemporary bool
		unwrapErr   error
	)

	if err, ok := err.(net.Error); ok {
		isTimeout = err.Timeout()
		isTemporary = err.Temporary()
	}

	// At this time, the only errors we wrap are context errors, to allow
	// users to check for canceled/timed out requests.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		unwrapErr = err
	} else if edeErr, ok := err.(ExtendedError); ok {
		unwrapErr = edeErr
		if edeErr.IsTemporary() {
			isTemporary = true
		}
	}

	_, isNotFound := err.(*notFoundError)
	return &DNSError{
		UnwrapErr:   unwrapErr,
		Err:         err.Error(),
		Name:        name,
		Server:      server,
		IsTimeout:   isTimeout,
		IsTemporary: isTemporary,
		IsNotFound:  isNotFound,
	}
}

// Unwrap returns e.UnwrapErr.
func (e *DNSError) Unwrap() error { return e.UnwrapErr }

func (e *DNSError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := "lookup " + e.Name
	if e.Server != "" {
		s += " on " + e.Server
	}
	s += ": " + e.Err
	return s
}

// Timeout reports whether the DNS lookup is known to have timed out.
// This is not always known; a DNS lookup may fail due to a timeout
// and return a DNSError for which Timeout returns false.
func (e *DNSError) Timeout() bool { return e.IsTimeout }

// Temporary reports whether the DNS error is known to be temporary.
// This is not always known; a DNS lookup may fail due to a temporary
// error and return a DNSError for which Temporary returns false.
func (e *DNSError) Temporary() bool { return e.IsTimeout || e.IsTemporary }
