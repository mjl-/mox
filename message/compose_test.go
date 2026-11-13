package message

import (
	"bytes"
	"mime"
	"strings"
	"testing"
)

// unfold removes every CRLF that is immediately followed by whitespace, which
// is exactly what RFC 5322 section 2.2.3 prescribes. The whitespace itself is
// kept, so a fold is NOT free: it injects a space or tab into the logical
// header value.
func unfold(s string) string {
	s = strings.ReplaceAll(s, "\r\n\t", "\t")
	s = strings.ReplaceAll(s, "\r\n ", " ")
	return s
}

// TestSubjectRoundTrip verifies that Composer.Subject survives a real
// encode -> transmit -> unfold -> decode cycle for subjects that mix Cyrillic,
// latin, punctuation, repeated spaces and tabs.
func TestSubjectRoundTrip(t *testing.T) {
	cases := []string{
		"Техническая документация",
		"Отчёт за январь",
		"Hello world",
		"Смешанный mixed текст",
		"Однослово",
		"Тема письма - дальше   по  два  пробела",
		"Ведущий и завершающий пробел ",
		"Табы\tи\tпробелы  смешанные",
		"Длинная кириллическая тема письма, которая заведомо превышает семьдесят семь символов и должна быть свёрнута",
		"Счёт №42 от 13.11.2026 на сумму 1 234,56 руб.",
		"Re: Ответ на очень длинное письмо с множеством деталей и номером 12345",
		strings.Repeat("очень длинное слово ", 60), // стресс: >998 байт в закодированном виде
		"",
		"Plain ASCII only",
		strings.Repeat("x", 400),
	}
	dec := new(mime.WordDecoder)

	for _, subj := range cases {
		var b bytes.Buffer
		xc := NewComposer(&b, 0, false)
		xc.Subject(subj)
		xc.Flush()

		raw := strings.TrimSuffix(b.String(), "\r\n")
		if !strings.HasPrefix(raw, "Subject: ") {
			t.Fatalf("нет префикса Subject: %q", raw)
		}
		folded := strings.TrimPrefix(raw, "Subject: ")

		// Ни одна физическая строка не должна превышать лимит RFC 5322.
		for _, line := range strings.Split(b.String(), "\r\n") {
			if len(line) > 998 {
				t.Errorf("строка заголовка длиннее 998 октетов (%d) для %q", len(line), subj)
			}
		}

		got, err := dec.DecodeHeader(unfold(folded))
		if err != nil {
			t.Errorf("декодирование %q: %v", subj, err)
			continue
		}
		if got != subj {
			t.Errorf("round-trip не сошёлся\n  вход : %q\n  выход: %q\n  raw  : %q", subj, got, folded)
			continue
		}
		t.Logf("ok  (%3d октет в заголовке) %q", len(folded), subj)
	}
}
