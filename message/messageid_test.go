package message

import (
	"errors"
	"testing"
)

func TestMessageIDCanonical(t *testing.T) {
	check := func(s string, expID string, expRaw bool, expErr error) {
		t.Helper()

		id, raw, err := MessageIDCanonical(s)
		if id != expID || raw != expRaw || (expErr == nil) != (err == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got message-id %q, raw %v, err %v, expected %q %v %v, for message-id %q", id, raw, err, expID, expRaw, expErr, s)
		}
	}

	check("bogus", "", false, errBadMessageID)
	check("<bogus@host", "", false, errBadMessageID)
	check("bogus@host>", "", false, errBadMessageID)
	check("<>", "", false, errBadMessageID)
	check("<user@domain>", "user@domain", false, nil)
	check("<USER@DOMAIN>", "user@domain", false, nil)
	check("<user@[10.0.0.1]>", "user@[10.0.0.1]", true, nil)
	check("<user@domain> (added by postmaster@isp.example)", "user@domain", false, nil)
	check("<user@domain> other", "user@domain", false, nil)
	check("<User@Domain@Time>", "user@domain@time", true, nil)
	check("<User>", "user", true, nil)
}
