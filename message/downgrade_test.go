package message

import (
	"bytes"
	"io"
	"log/slog"
	"mime"
	"net/mail"
	"strings"
	"testing"
)

func TestDowngradeSMTPUTF8(t *testing.T) {
	tests := []struct {
		name       string
		msg        string
		absent     []string // substrings that must NOT appear in the result
		present    []string // substrings that MUST appear in the result
		unchanged  bool     // if true, result must equal input exactly
	}{
		{
			name:      "ascii-only passthrough",
			msg:       "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Hello\r\n\r\nBody text.\r\n",
			unchanged: true,
		},
		{
			name:    "utf8 subject q-encoded",
			msg:     "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Héllo wörld\r\n\r\nBody.\r\n",
			absent:  []string{"Héllo", "wörld"},
			present: []string{"=?utf-8?q?", "\r\n\r\nBody.\r\n"},
		},
		{
			name:    "utf8 display name mime-encoded",
			msg:     "From: Ünïcödé Üser <sender@example.com>\r\nTo: rcpt@example.com\r\nSubject: Test\r\n\r\nBody.\r\n",
			absent:  []string{"Ünïcödé"},
			present: []string{"sender@example.com", "\r\n\r\nBody.\r\n"},
		},
		{
			name:    "utf8 body unchanged",
			msg:     "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\n\r\nBödy with ünïcödé.\r\n",
			present: []string{"Bödy with ünïcödé."},
		},
		{
			name:    "utf8 generic header q-encoded",
			msg:     "From: sender@example.com\r\nTo: rcpt@example.com\r\nX-Custom: café résumé\r\nSubject: Test\r\n\r\nBody.\r\n",
			absent:  []string{"café", "résumé"},
		},
		{
			name:    "no body",
			msg:     "From: Ünïcödé <sender@example.com>\r\nTo: rcpt@example.com\r\nSubject: Test\r\n",
			absent:  []string{"Ünïcödé"},
		},
		{
			name:    "multiple utf8 addresses",
			msg:     "From: sender@example.com\r\nTo: Àlice <alice@example.com>, Böb <bob@example.com>\r\nSubject: Test\r\n\r\nBody.\r\n",
			absent:  []string{"Àlice", "Böb"},
			present: []string{"alice@example.com", "bob@example.com"},
		},
		{
			name:    "folded header",
			msg:     "From: sender@example.com\r\nSubject: Héllo\r\n wörld continüed\r\nTo: rcpt@example.com\r\n\r\nBody.\r\n",
			absent:  []string{"Héllo", "wörld", "continüed"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := DowngradeSMTPUTF8([]byte(tc.msg))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			s := string(result)

			if tc.unchanged && s != tc.msg {
				t.Fatalf("expected unchanged message, got:\n%s", s)
			}
			for _, sub := range tc.absent {
				if strings.Contains(s, sub) {
					t.Fatalf("result should not contain %q, got:\n%s", sub, s)
				}
			}
			for _, sub := range tc.present {
				if !strings.Contains(s, sub) {
					t.Fatalf("result should contain %q, got:\n%s", sub, s)
				}
			}
		})
	}
}

func TestSplitHeaderFields(t *testing.T) {
	input := []byte("From: a@b.com\r\nSubject: test\r\n with fold\r\nTo: c@d.com\r\n")
	fields := splitHeaderFields(input)
	want := []string{
		"From: a@b.com\r\n",
		"Subject: test\r\n with fold\r\n",
		"To: c@d.com\r\n",
	}
	if len(fields) != len(want) {
		t.Fatalf("got %d fields, want %d", len(fields), len(want))
	}
	for i, w := range want {
		if string(fields[i]) != w {
			t.Fatalf("field %d: got %q, want %q", i, string(fields[i]), w)
		}
	}
}

// TestDowngradeMIMERoundTrip takes full MIME messages with UTF-8 headers,
// downgrades them, then parses the result with both message.Parse (mox's own
// parser) and net/mail.ReadMessage to verify that the MIME-encoded headers
// decode back to the original values and that the body is preserved.
func TestDowngradeMIMERoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		msg         string
		wantSubject string
		wantFrom    string // Expected decoded display name of From address.
		wantFromAddr string // Expected email in From.
		wantTo      []string // Expected decoded display names of To addresses.
		wantToAddrs []string // Expected emails in To.
		wantCc      string // Expected decoded display name of Cc address.
		wantBody    string
	}{
		{
			name: "multipart mixed with utf8 headers",
			msg: "From: Öliver Müller <oliver@example.com>\r\n" +
				"To: Ñoño García <nono@example.com>\r\n" +
				"Cc: Ünsal Çelik <unsal@example.com>\r\n" +
				"Subject: Ré: café résumé\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: multipart/mixed; boundary=\"boundary42\"\r\n" +
				"\r\n" +
				"--boundary42\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"\r\n" +
				"Héllo, this is the bödy.\r\n" +
				"--boundary42\r\n" +
				"Content-Type: text/plain; charset=us-ascii\r\n" +
				"Content-Disposition: attachment; filename=\"notes.txt\"\r\n" +
				"\r\n" +
				"Attachment content.\r\n" +
				"--boundary42--\r\n",
			wantSubject:  "Ré: café résumé",
			wantFrom:     "Öliver Müller",
			wantFromAddr: "oliver@example.com",
			wantTo:       []string{"Ñoño García"},
			wantToAddrs:  []string{"nono@example.com"},
			wantCc:       "Ünsal Çelik",
			wantBody:     "Héllo, this is the bödy.",
		},
		{
			name: "multipart alternative with multiple To",
			msg: "From: Ségolène <segolene@example.com>\r\n" +
				"To: Ärthur <arthur@example.com>, Björk <bjork@example.com>\r\n" +
				"Subject: Dëjà vu\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: multipart/alternative; boundary=\"altbound\"\r\n" +
				"\r\n" +
				"--altbound\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"\r\n" +
				"Plain text version.\r\n" +
				"--altbound\r\n" +
				"Content-Type: text/html; charset=utf-8\r\n" +
				"\r\n" +
				"<p>HTML version.</p>\r\n" +
				"--altbound--\r\n",
			wantSubject:  "Dëjà vu",
			wantFrom:     "Ségolène",
			wantFromAddr: "segolene@example.com",
			wantTo:       []string{"Ärthur", "Björk"},
			wantToAddrs:  []string{"arthur@example.com", "bjork@example.com"},
			wantBody:     "Plain text version.",
		},
		{
			name: "simple message with custom header",
			msg: "From: Ïda <ida@example.com>\r\n" +
				"To: recipient@example.com\r\n" +
				"Subject: Ünïcödé everywhere\r\n" +
				"X-Greeting: Cześć świecie\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"\r\n" +
				"Bödÿ text wïth ünïcödé.\r\n",
			wantSubject:  "Ünïcödé everywhere",
			wantFrom:     "Ïda",
			wantFromAddr: "ida@example.com",
			wantTo:       []string{""},
			wantToAddrs:  []string{"recipient@example.com"},
			wantBody:     "Bödÿ text wïth ünïcödé.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := DowngradeSMTPUTF8([]byte(tc.msg))
			if err != nil {
				t.Fatalf("downgrade: %v", err)
			}

			// Headers must be pure ASCII after downgrade.
			headerEnd := bytes.Index(result, []byte("\r\n\r\n"))
			if headerEnd < 0 {
				t.Fatal("no header/body separator in downgraded message")
			}
			for i, b := range result[:headerEnd] {
				if b > 127 {
					t.Fatalf("non-ASCII byte %02x at header offset %d in downgraded message", b, i)
				}
			}

			// --- Parse with message.Parse (mox parser) ---
			part, err := Parse(slog.Default(), false, bytes.NewReader(result))
			if err != nil {
				t.Fatalf("message.Parse: %v", err)
			}
			if err := part.Walk(slog.Default(), nil); err != nil {
				t.Fatalf("part.Walk: %v", err)
			}

			// After downgrade, NeedsSMTPUTF8 should be false for the headers.
			// (Body may still contain non-ASCII, but NeedsSMTPUTF8 only checks headers.)
			needsUTF8, err := part.NeedsSMTPUTF8()
			if err != nil {
				t.Fatalf("NeedsSMTPUTF8: %v", err)
			}
			if needsUTF8 {
				t.Fatalf("downgraded message still reports NeedsSMTPUTF8=true")
			}

			env := part.Envelope
			if env == nil {
				t.Fatal("no envelope from message.Parse")
			}
			if env.Subject != tc.wantSubject {
				t.Fatalf("subject: got %q, want %q", env.Subject, tc.wantSubject)
			}
			if len(env.From) == 0 {
				t.Fatal("no From addresses parsed")
			}
			if env.From[0].Name != tc.wantFrom {
				t.Fatalf("from name: got %q, want %q", env.From[0].Name, tc.wantFrom)
			}
			if len(env.To) != len(tc.wantTo) {
				t.Fatalf("to count: got %d, want %d", len(env.To), len(tc.wantTo))
			}
			for i, wantName := range tc.wantTo {
				if env.To[i].Name != wantName {
					t.Fatalf("to[%d] name: got %q, want %q", i, env.To[i].Name, wantName)
				}
			}
			if tc.wantCc != "" {
				if len(env.CC) == 0 {
					t.Fatal("no Cc addresses parsed")
				}
				if env.CC[0].Name != tc.wantCc {
					t.Fatalf("cc name: got %q, want %q", env.CC[0].Name, tc.wantCc)
				}
			}

			// --- Parse with net/mail (stdlib parser) ---
			mailMsg, err := mail.ReadMessage(bytes.NewReader(result))
			if err != nil {
				t.Fatalf("mail.ReadMessage: %v", err)
			}

			// net/mail decodes RFC 2047 in Subject.
			dec := new(mime.WordDecoder)
			gotSubject, err := dec.DecodeHeader(mailMsg.Header.Get("Subject"))
			if err != nil {
				t.Fatalf("decoding subject: %v", err)
			}
			if gotSubject != tc.wantSubject {
				t.Fatalf("net/mail subject: got %q, want %q", gotSubject, tc.wantSubject)
			}

			// Check From address.
			fromAddrs, err := mailMsg.Header.AddressList("From")
			if err != nil {
				t.Fatalf("net/mail from: %v", err)
			}
			if len(fromAddrs) == 0 {
				t.Fatal("net/mail: no From addresses")
			}
			if fromAddrs[0].Name != tc.wantFrom {
				t.Fatalf("net/mail from name: got %q, want %q", fromAddrs[0].Name, tc.wantFrom)
			}
			if fromAddrs[0].Address != tc.wantFromAddr {
				t.Fatalf("net/mail from addr: got %q, want %q", fromAddrs[0].Address, tc.wantFromAddr)
			}

			// Check To addresses.
			toAddrs, err := mailMsg.Header.AddressList("To")
			if err != nil {
				t.Fatalf("net/mail to: %v", err)
			}
			if len(toAddrs) != len(tc.wantToAddrs) {
				t.Fatalf("net/mail to count: got %d, want %d", len(toAddrs), len(tc.wantToAddrs))
			}
			for i := range toAddrs {
				if toAddrs[i].Address != tc.wantToAddrs[i] {
					t.Fatalf("net/mail to[%d] addr: got %q, want %q", i, toAddrs[i].Address, tc.wantToAddrs[i])
				}
			}

			// Check body is preserved.
			body, err := io.ReadAll(mailMsg.Body)
			if err != nil {
				t.Fatalf("reading body: %v", err)
			}
			if !strings.Contains(string(body), tc.wantBody) {
				t.Fatalf("body should contain %q, got:\n%s", tc.wantBody, body)
			}
		})
	}
}

// TestComposeSubjectRoundTrip verifies that Composer.Subject() produces
// subjects that decode correctly via net/mail and message.Parse, especially
// for multi-word non-ASCII subjects (e.g. CJK) where RFC 2047 §6.2
// whitespace-between-encoded-words stripping would otherwise lose spaces.
func TestComposeSubjectRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		subject string
	}{
		{"korean spaces", "가장 높은 산, 가장 긴 강"},
		{"japanese spaces", "東京 タワー スカイツリー"},
		{"chinese spaces", "你好 世界 欢迎"},
		{"mixed ascii and utf8", "Hello 世界 from Go"},
		{"single utf8 word", "café"},
		{"ascii only", "Hello World"},
		{"emoji spaces", "Hello 🌍 World 🎉 Party"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			xc := NewComposer(&buf, 10*1024*1024, false)
			xc.Header("From", "sender@example.com")
			xc.Header("To", "rcpt@example.com")
			xc.Subject(tc.subject)
			xc.Header("MIME-Version", "1.0")
			xc.Header("Content-Type", "text/plain; charset=utf-8")
			xc.Line()
			xc.Write([]byte("body\r\n"))
			xc.Flush()

			msg := buf.Bytes()

			// Verify the raw Subject header is pure ASCII.
			headerEnd := bytes.Index(msg, []byte("\r\n\r\n"))
			if headerEnd < 0 {
				t.Fatal("no header/body separator")
			}
			fields := splitHeaderFields(msg[:headerEnd])
			for _, f := range fields {
				if bytes.HasPrefix(f, []byte("Subject:")) {
					for i, b := range f {
						if b > 127 {
							t.Fatalf("non-ASCII byte %02x at offset %d in Subject header: %q", b, i, f)
						}
					}
				}
			}

			// Parse with net/mail and verify subject decodes to original.
			mailMsg, err := mail.ReadMessage(bytes.NewReader(msg))
			if err != nil {
				t.Fatalf("mail.ReadMessage: %v", err)
			}
			dec := new(mime.WordDecoder)
			got, err := dec.DecodeHeader(mailMsg.Header.Get("Subject"))
			if err != nil {
				t.Fatalf("decoding subject: %v", err)
			}
			if got != tc.subject {
				t.Fatalf("net/mail subject: got %q, want %q", got, tc.subject)
			}

			// Parse with message.Parse and verify subject decodes to original.
			part, err := Parse(slog.Default(), false, bytes.NewReader(msg))
			if err != nil {
				t.Fatalf("message.Parse: %v", err)
			}
			if part.Envelope == nil {
				t.Fatal("no envelope")
			}
			if part.Envelope.Subject != tc.subject {
				t.Fatalf("message.Parse subject: got %q, want %q", part.Envelope.Subject, tc.subject)
			}
		})
	}
}
