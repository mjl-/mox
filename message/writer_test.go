package message

import (
	"strings"
	"testing"
)

func TestMsgWriter(t *testing.T) {
	check := func(data string, want bool) {
		t.Helper()

		b := &strings.Builder{}
		mw := &Writer{Writer: b}
		if _, err := mw.Write([]byte(data)); err != nil {
			t.Fatalf("write for message %q: %s", data, err)
		}
		if mw.HaveHeaders != want {
			t.Fatalf("got %v, expected %v, for message %q", mw.HaveHeaders, want, data)
		}

		b = &strings.Builder{}
		mw = &Writer{Writer: b}
		for i := range data {
			if _, err := mw.Write([]byte(data[i : i+1])); err != nil {
				t.Fatalf("write for message %q: %s", data, err)
			}
		}
		if mw.HaveHeaders != want {
			t.Fatalf("got %v, expected %v, for message %q", mw.HaveHeaders, want, data)
		}
	}

	check("no header", false)
	check("no header\r\n", false)
	check("key: value\r\n\r\n", true)
	check("key: value\r\n\r\nbody", true)
	check("key: value\n\nbody", false)
	check("key: value\r\rbody", false)
	check("\r\n\r\n", true)
	check("\r\n\r\nbody", true)
}
