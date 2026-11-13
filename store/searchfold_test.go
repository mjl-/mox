package store

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
)

func TestSearchText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Příliš žluťoučký kůň úpěl ďábelské ódy", "prilis zlutoucky kun upel dabelske ody"},
		{"ÄÖÜ Straße STRAẞE", "aou strasse strasse"},
		{"Zażółć gęślą jaźń", "zazolc gesla jazn"},
		{"Ľúbim mäkký kŕdeľ šťastných žriebät", "lubim makky krdel stastnych zriebat"},
		{"Crème brûlée São Tomé Șț ạệ Øresund Đ Ħ Ŧ ı", "creme brulee sao tome st ae oresund d h t i"},
		{"C\u030c a\u0301\u0328 Straße", "c a strasse"},
		{"Й Ё И\u0306 Е\u0308 ά α\u0301 עִ 中文", "й ё и\u0306 е\u0308 ά α\u0301 עִ 中文"},
		{"\u0301a -\u0301 !\u0301", "\u0301a -\u0301 !\u0301"},
		{"", ""},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := SearchText(tc.in, true); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if got := SearchText(tc.in, false); got != strings.ToLower(tc.in) {
				t.Fatalf("disabled folding changed text: %q", got)
			}
			r := transform.NewReader(iotest.OneByteReader(strings.NewReader(tc.in)), &latinSearchFold{})
			b, err := io.ReadAll(r)
			if err != nil || strings.ToLower(string(b)) != tc.want {
				t.Fatalf("one-byte reader: %q, %v", b, err)
			}
		})
	}
}

func TestLatinSearchFoldBuffers(t *testing.T) {
	var tr latinSearchFold
	// A short destination must not consume a rune or change the preceding script.
	tr.latin = true
	nd, ns, err := tr.Transform(nil, []byte("я"), false)
	if nd != 0 || ns != 0 || err != transform.ErrShortDst || !tr.latin {
		t.Fatalf("short destination: %d %d %v %#v", nd, ns, err, tr)
	}
	tr.Reset()
	if tr.latin {
		t.Fatal("reset retained preceding Latin character")
	}
	b, err := io.ReadAll(transform.NewReader(strings.NewReader("a\xff\u0301\xc3"), &tr))
	if err != nil || string(b) != "a\xff\u0301\xc3" {
		t.Fatalf("invalid UTF-8: %q, %v", b, err)
	}
}

func TestWordSearchFoldLatin(t *testing.T) {
	log := mlog.New("search", nil)
	for _, tc := range []struct {
		text, word string
		match      bool
	}{
		{"Příliš Straße Łódź", "prilis strasse lodz", true},
		{"prilis strasse lodz", "PŘÍLIŠ STRAẞE ŁÓDŹ", true},
		{"c\u030caj", "čaj", true},
		{"й ё", "и е", false},
		{"Müller", "Mueller", false},
		{strings.Repeat("x", 8190) + "Příliš Straße Łódź", "prilis strasse lodz", true},
		{strings.Repeat("x", 4095) + "c\u030caj", "čaj", true},
		{"c" + strings.Repeat("\u030c", 10000) + "aj", "čaj", true},
		{"a" + strings.Repeat("\u0301", 10000) + "я\u0301", "aя\u0301", true},
	} {
		for _, negate := range []bool{false, true} {
			ws := PrepareWordSearch([]string{tc.word}, nil, true)
			if negate {
				ws = PrepareWordSearch(nil, []string{tc.word}, true)
			}
			seen := map[int]bool{}
			miss, err := ws.searchReader(log, iotest.OneByteReader(strings.NewReader(tc.text)), seen)
			got := !miss && len(seen) == len(ws.words)
			if err != nil || got != (tc.match != negate) {
				t.Fatalf("word %q, negate %v: match %v, error %v", tc.word, negate, got, err)
			}
		}
	}
	// Folding must not mask source read errors.
	want := errors.New("read failed")
	ws := PrepareWordSearch([]string{"x"}, nil, true)
	if _, err := ws.searchReader(log, iotest.ErrReader(want), map[int]bool{}); !errors.Is(err, want) {
		t.Fatalf("got %v, want read error", err)
	}
}

func BenchmarkWordSearchFoldLatin(b *testing.B) {
	log := mlog.New("search", nil)
	for _, text := range []string{"Mostly ASCII text in a message. ", "Příliš žluťoučký kůň Straße Łódź. "} {
		for _, fold := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/fold=%v", text, fold), func(b *testing.B) {
				body := strings.Repeat(text, 1000)
				ws := PrepareWordSearch([]string{"absent"}, nil, fold)
				b.SetBytes(int64(len(body)))
				b.ReportAllocs()
				for b.Loop() {
					_, err := ws.searchReader(log, strings.NewReader(body), map[int]bool{})
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestWordSearchFoldLatinMIME(t *testing.T) {
	log := mlog.New("search", nil)
	text := "Příliš žluťoučký kůň"
	latin2, err := charmap.ISO8859_2.NewEncoder().String(text)
	if err != nil {
		t.Fatal(err)
	}
	for _, charset := range []string{"utf-8", "iso-8859-2"} {
		body := text
		if charset == "iso-8859-2" {
			body = latin2
		}
		raw := fmt.Sprintf("Subject: %s\r\nContent-Type: text/plain; charset=%s\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", mime.QEncoding.Encode(charset, body), charset, base64.StdEncoding.EncodeToString([]byte(body)))
		p, err := message.EnsurePart(log.Logger, true, strings.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		for _, fold := range []bool{false, true} {
			for _, header := range []bool{false, true} {
				ws := PrepareWordSearch([]string{"prilis zlutoucky kun"}, nil, fold)
				got, err := ws.MatchPart(log, &p, header)
				if err != nil || got != fold {
					t.Fatalf("charset %s, fold %v, headers %v: %v, %v", charset, fold, header, got, err)
				}
			}
		}
	}
}
