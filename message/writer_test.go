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
	check("key: value\n\nbody", false)
	check("key: value\r\rbody", false)
	check("\r\n\r\n", true)
	check("\r\n\r\nbody", true)
	check("\r\nbody", true)
}
