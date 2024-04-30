package message

import (
	"strings"
	"testing"
)

func TestMsgWriter(t *testing.T) {
	check := func(data string, want bool) {
		t.Helper()

		b := &strings.Builder{}
		mw := NewWriter(b)
		if _, err := mw.Write([]byte(data)); err != nil {
			t.Fatalf("write for message %q: %s", data, err)
		}
		if mw.HaveBody != want {
			t.Fatalf("got %v, expected %v, for message %q", mw.HaveBody, want, data)
		}

		b = &strings.Builder{}
		mw = NewWriter(b)
		for i := range data {
			if _, err := mw.Write([]byte(data[i : i+1])); err != nil {
				t.Fatalf("write for message %q: %s", data, err)
			}
		}
		if mw.HaveBody != want {
			t.Fatalf("got %v, expected %v, for message %q", mw.HaveBody, want, data)
		}
	}

	check("no header", false)
	check("no header\r\n", false)
	check("key: value\r\n\r\n", true)
	check("key: value\r\n\r\nbody", true)
	check("key: value\n\nbody", true)
	check("key: value\n\r\nbody", true)
	check("key: value\r\rbody", false)
	check("\r\n\r\n", true)
	check("\r\n\r\nbody", true)
	check("\r\nbody", true)

	// Check \n is replaced with \r\n.
	var b strings.Builder
	mw := NewWriter(&b)
	msg := "key: value\n\nline1\r\nline2\nx\n.\n"
	_, err := mw.Write([]byte(msg))
	tcheck(t, err, "write")
	got := b.String()
	exp := "key: value\r\n\r\nline1\r\nline2\r\nx\r\n.\r\n"
	if got != exp {
		t.Fatalf("got %q, expected %q", got, exp)
	}
}

func TestMsgWriterIssue117(t *testing.T) {
	var b strings.Builder
	mw := NewWriter(&b)

	// Write header and header/body separator, but with CR missing.
	_, err := mw.Write([]byte("a: b\n\n"))
	tcheck(t, err, "write")

	// Write start of a line. The newline follows in a second write. Just because of buffering.
	_, err = mw.Write([]byte("body\r"))
	tcheck(t, err, "write")

	// Finish the line. The bug is that w.tail was only updated while writing headers,
	// not while writing message data for the body. That makes the code think this \n
	// wasn't preceded by a \r, causing it to add a \r. And we end up with \r\r\n in
	// the file.
	_, err = mw.Write([]byte("\n"))
	tcheck(t, err, "write")

	got := b.String()
	exp := "a: b\r\n\r\nbody\r\n"
	if got != exp {
		t.Fatalf("got %q, expected %q", got, exp)
	}
}
