package chatmail

import (
	"bytes"
	"io"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzEncryptedPayload(f *testing.F) {
	// Seed with the payloads used by the unit tests, in CRLF form.
	for _, seed := range []string{validPayload, gnupgPayload, commentPayload, cleartextPayload} {
		f.Add(strings.ReplaceAll(seed, "\n", "\r\n"))
	}
	f.Fuzz(func(t *testing.T, payload string) {
		encryptedPayload(payload, true)
		encryptedPayload(payload, false)
	})
}

// FuzzEncrypted fuzzes the MIME structure handling with the testdata messages as
// seed corpus.
func FuzzEncrypted(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("reading testdata: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".eml") {
			continue
		}
		buf, err := os.ReadFile(filepath.Join("testdata", e.Name()))
		if err != nil {
			f.Fatalf("reading testdata %s: %v", e.Name(), err)
		}
		f.Add(buf)
	}
	f.Fuzz(func(t *testing.T, buf []byte) {
		m, err := mail.ReadMessage(bytes.NewReader(buf))
		if err != nil {
			return
		}
		body, err := io.ReadAll(m.Body)
		if err != nil {
			return
		}
		h := textproto.MIMEHeader(m.Header)
		Encrypted(h, bytes.NewReader(body), true)
		Encrypted(h, bytes.NewReader(body), false)
		SecureJoin(h, bytes.NewReader(body))
		AutocryptSetupMessage(h)
	})
}
