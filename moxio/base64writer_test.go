package moxio

import (
	"strings"
	"testing"
)

func TestBase64Writer(t *testing.T) {
	var sb strings.Builder
	bw := Base64Writer(&sb)
	_, err := bw.Write([]byte("0123456789012345678901234567890123456789012345678901234567890123456789"))
	tcheckf(t, err, "write")
	err = bw.Close()
	tcheckf(t, err, "close")
	s := sb.String()
	exp := "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nz\r\ng5MDEyMzQ1Njc4OQ==\r\n"
	if s != exp {
		t.Fatalf("base64writer, got %q, expected %q", s, exp)
	}
}
