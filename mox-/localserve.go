package mox

import (
	"strconv"
	"strings"

	"github.com/mjl-/mox/smtp"
)

func LocalserveNeedsError(lp smtp.Localpart) (code int, timeout bool) {
	s := string(lp)
	if strings.HasSuffix(s, "temperror") {
		return smtp.C451LocalErr, false
	} else if strings.HasSuffix(s, "permerror") {
		return smtp.C550MailboxUnavail, false
	} else if strings.HasSuffix(s, "timeout") {
		return 0, true
	}
	if len(s) < 3 {
		return 0, false
	}
	s = s[len(s)-3:]
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, false
	}
	if v < 400 || v > 600 {
		return 0, false
	}
	return int(v), false
}
