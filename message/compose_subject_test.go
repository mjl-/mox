package message

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func composeSubjectValue(t *testing.T, subject string, smtpUTF8 bool) string {
	t.Helper()
	var buf bytes.Buffer
	xc := NewComposer(&buf, 0, smtpUTF8)
	xc.Subject(subject)
	xc.Flush()
	return buf.String()
}

func TestSubjectStripsControlCharacters(t *testing.T) {
	got := composeSubjectValue(t, "hello\r\nBcc: bob@example.com", false)
	want := "Subject: hello Bcc: bob@example.com\r\n"
	if got != want {
		t.Fatalf("unexpected header:\n%s", got)
	}
}

func TestSubjectEncodesNonASCII(t *testing.T) {
	got := composeSubjectValue(t, "hello ☺ world", false)
	if !strings.Contains(strings.ToLower(got), "=?utf-8?b?4pi6?=") {
		t.Fatalf("expected encoded word in %q", got)
	}
	if !strings.HasPrefix(got, "Subject: hello ") || !strings.HasSuffix(got, " world\r\n") {
		t.Fatalf("unexpected folding around encoded word: %q", got)
	}
}

func TestSubjectFoldsLongLines(t *testing.T) {
	var words []string
	for i := 0; i < 20; i++ {
		words = append(words, fmt.Sprintf("word%02d", i))
	}
	got := composeSubjectValue(t, strings.Join(words, " "), false)
	if !strings.Contains(got, "\r\n\t") {
		t.Fatalf("expected folded header, got %q", got)
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\r\n"), "\r\n") {
		if len(line) > 78 {
			t.Fatalf("line %q exceeds 78 characters", line)
		}
	}
}

func TestSubjectChunksNonASCIIWithoutSpaces(t *testing.T) {
	input := strings.Repeat("こんにちは", 10)
	got := composeSubjectValue(t, input, false)
	if strings.Count(strings.ToLower(got), "=?utf-8?b?") < 2 {
		t.Fatalf("expected multiple encoded words for long utf-8 subject: %q", got)
	}
	if !strings.Contains(got, "\r\n\t") {
		t.Fatalf("expected folded header for long utf-8 subject: %q", got)
	}
}

func TestSubjectSMTPUTF8KeepsUTF8(t *testing.T) {
	got := composeSubjectValue(t, "mañana reunión", true)
	if strings.Contains(strings.ToLower(got), "=?utf-8?b?") {
		t.Fatalf("did not expect encoded words when SMTPUTF8 is set: %q", got)
	}
	if !strings.Contains(got, "mañana") {
		t.Fatalf("expected utf-8 runes to remain: %q", got)
	}
}
