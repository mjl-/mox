package webmail

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/mjl-/mox/message"
)

func TestWriteAltBody(t *testing.T) {
	var buf bytes.Buffer
	xc := message.NewComposer(io.Discard, 1024*1024, false)
	boundary := "BOUNDARYTEST123"
	if err := writeAltBody(&buf, boundary, "hello text", "<p>hello html</p>", xc); err != nil {
		t.Fatalf("writeAltBody: %v", err)
	}
	s := buf.String()
	for _, want := range []string{
		"--" + boundary,
		"Content-Type: text/plain",
		"Content-Type: text/html",
		"hello text",
		"hello html",
		"--" + boundary + "--",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("output missing %q\n---\n%s", want, s)
		}
	}
}
