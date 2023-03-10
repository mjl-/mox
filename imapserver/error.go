package imapserver

import (
	"errors"
	"fmt"
)

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		xserverErrorf("%s: %w", fmt.Sprintf(format, args...), err)
	}
}

type userError struct {
	code string // Optional response code in brackets.
	err  error
}

func (e userError) Error() string { return e.err.Error() }
func (e userError) Unwrap() error { return e.err }

func xuserErrorf(format string, args ...any) {
	panic(userError{err: fmt.Errorf(format, args...)})
}

func xusercodeErrorf(code, format string, args ...any) {
	panic(userError{code: code, err: fmt.Errorf(format, args...)})
}

type serverError struct{ err error }

func (e serverError) Error() string { return e.err.Error() }
func (e serverError) Unwrap() error { return e.err }

func xserverErrorf(format string, args ...any) {
	panic(serverError{fmt.Errorf(format, args...)})
}

type syntaxError struct {
	line   string // Optional line to write before BAD result. For untagged response. CRLF will be added.
	code   string // Optional result code (between []) to write in BAD result.
	errmsg string // BAD response message.
	err    error  // Typically with same info as errmsg, but sometimes more.
}

func (e syntaxError) Error() string {
	s := "bad syntax: " + e.errmsg
	if e.code != "" {
		s += " [" + e.code + "]"
	}
	return s
}
func (e syntaxError) Unwrap() error { return e.err }

func xsyntaxErrorf(format string, args ...any) {
	errmsg := fmt.Sprintf(format, args...)
	err := errors.New(errmsg)
	panic(syntaxError{"", "", errmsg, err})
}
