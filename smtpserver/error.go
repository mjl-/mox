package smtpserver

import (
	"fmt"

	"github.com/mjl-/mox/smtp"
)

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		err := fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err)
		panic(smtpError{smtp.C451LocalErr, smtp.SeSys3Other0, err.Error(), err, true, false})
	}
}

type smtpError struct {
	code       int
	secode     string
	errmsg     string // Sent in response.
	err        error  // If set, used in logging. Typically has same information as errmsg.
	printStack bool
	userError  bool // If this is an error on the user side, which causes logging at a lower level.
}

func (e smtpError) Error() string { return e.errmsg }
func (e smtpError) Unwrap() error { return e.err }

func xsmtpErrorf(code int, secode string, userError bool, format string, args ...any) {
	err := fmt.Errorf(format, args...)
	panic(smtpError{code, secode, err.Error(), err, false, userError})
}

func xsmtpServerErrorf(codes codes, format string, args ...any) {
	xsmtpErrorf(codes.code, codes.secode, false, format, args...)
}

func xsmtpUserErrorf(code int, secode string, format string, args ...any) {
	xsmtpErrorf(code, secode, true, format, args...)
}
