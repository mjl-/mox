// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package adns

import (
	"context"
	"errors"
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

type timeout interface {
	Timeout() bool
}

// Various errors contained in DNSError.
var (
	errNoSuchHost = errors.New("no such host")
)

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
	Underlying  error  // Underlying error, could be an ExtendedError.
	Err         string // description of the error
	Name        string // name looked for
	Server      string // server used
	IsTimeout   bool   // if true, timed out; not all timeouts set this
	IsTemporary bool   // if true, error is temporary; not all errors set this
	IsNotFound  bool   // if true, host could not be found
}

// Unwrap returns the underlying error, which could be an ExtendedError.
func (e *DNSError) Unwrap() error {
	return e.Underlying
}

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
