package imapserver

import (
	"errors"
	"testing"
)

func TestUTF7(t *testing.T) {
	check := func(input string, output string, expErr error) {
		t.Helper()

		r, err := utf7decode(input)
		if r != output {
			t.Fatalf("got %q, expected %q (err %v), for input %q", r, output, err, input)
		}
		if (expErr == nil) != (err == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got err %v, expected %v", err, expErr)
		}
	}

	check("plain", "plain", nil)
	check("&Jjo-", "☺", nil)
	check("test&Jjo-", "test☺", nil)
	check("&Jjo-test&Jjo-", "☺test☺", nil)
	check("&Jjo-test", "☺test", nil)
	check("&-", "&", nil)
	check("&-", "&", nil)
	check("&Jjo", "", errUTF7UnfinishedShift)     // missing closing -
	check("&Jjo-&-", "", errUTF7SuperfluousShift) // shift just after unshift not allowed, should have been a single shift.
	check("&AGE-", "", errUTF7UnneededShift)      // Just 'a', does not need utf7.
	check("&☺-", "", errUTF7Base64)
	check("&YQ-", "", errUTF7OddSized) // Just a single byte 'a'
}
