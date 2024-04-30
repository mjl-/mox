package message

import (
	"io"
	"strings"
	"testing"
)

func TestDecodeReader(t *testing.T) {
	check := func(charset, input, output string) {
		t.Helper()
		buf, err := io.ReadAll(DecodeReader(charset, strings.NewReader(input)))
		tcheck(t, err, "decode")
		if string(buf) != output {
			t.Fatalf("decoding %q with charset %q, got %q, expected %q", input, charset, buf, output)
		}
	}

	check("", "☺", "☺")         // No decoding.
	check("us-ascii", "☺", "☺") // No decoding.
	check("utf-8", "☺", "☺")
	check("iso-8859-1", string([]byte{0xa9}), "©")
	check("iso-8859-5", string([]byte{0xd0}), "а")
}
