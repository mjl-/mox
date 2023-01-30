package smtpserver

import (
	"fmt"

	"github.com/mjl-/mox/smtp"
)

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		panic(smtpError{smtp.C451LocalErr, smtp.SeSys3Other0, fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err), true, false})
	}
}

type smtpError struct {
	code       int
	secode     string
	err        error
	printStack bool
	userError  bool // If this is an error on the user side, which causes logging at a lower level.
}

func (e smtpError) Error() string { return e.err.Error() }
func (e smtpError) Unwrap() error { return e.err }

func xsmtpErrorf(code int, secode string, userError bool, format string, args ...any) {
	panic(smtpError{code, secode, fmt.Errorf(format, args...), false, userError})
}

func xsmtpServerErrorf(codes codes, format string, args ...any) {
	xsmtpErrorf(codes.code, codes.secode, false, format, args...)
}

func xsmtpUserErrorf(code int, secode string, format string, args ...any) {
	xsmtpErrorf(code, secode, true, format, args...)
}
