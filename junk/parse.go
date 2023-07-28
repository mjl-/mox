package junk

// see https://en.wikipedia.org/wiki/Naive_Bayes_spam_filtering
// - todo: better html parsing?
// - todo: try reading text in pdf?
// - todo: try to detect language, have words per language? can be in the same dictionary. currently my dictionary is biased towards treating english as spam.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"golang.org/x/net/html"

	"github.com/mjl-/mox/message"
)

func (f *Filter) tokenizeMail(path string) (bool, map[string]struct{}, error) {
	mf, err := os.Open(path)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		err := mf.Close()
		f.log.Check(err, "closing message file")
	}()
	fi, err := mf.Stat()
	if err != nil {
		return false, nil, err
	}
	p, _ := message.EnsurePart(mf, fi.Size())
	words, err := f.ParseMessage(p)
	return true, words, err
}

// ParseMessage reads a mail and returns a map with words.
func (f *Filter) ParseMessage(p message.Part) (map[string]struct{}, error) {
	metaWords := map[string]struct{}{}
	textWords := map[string]struct{}{}
	htmlWords := map[string]struct{}{}

	hdrs, err := p.Header()
	if err != nil {
		return nil, fmt.Errorf("parsing headers: %v", err)
	}

	// Add words from the header, annotated with <field>+":".
	// todo: add whether header is dkim-verified?
	for k, l := range hdrs {
		for _, h := range l {
			switch k {
			case "From", "To", "Cc", "Bcc", "Reply-To", "Subject", "Sender", "Return-Path":
			// case "Subject", "To":
			default:
				continue
			}
			words := map[string]struct{}{}
			f.tokenizeText(strings.NewReader(h), words)
			for w := range words {
				if len(w) <= 3 {
					continue
				}
				metaWords[k+":"+w] = struct{}{}
			}
		}
	}

	if err := f.mailParse(p, metaWords, textWords, htmlWords); err != nil {
		return nil, fmt.Errorf("parsing message: %w", err)
	}

	for w := range metaWords {
		textWords[w] = struct{}{}
	}
	for w := range htmlWords {
		textWords[w] = struct{}{}
	}

	return textWords, nil
}

// mailParse looks through the mail for the first text and html parts, and tokenizes their words.
func (f *Filter) mailParse(p message.Part, metaWords, textWords, htmlWords map[string]struct{}) error {
	ct := p.MediaType + "/" + p.MediaSubType

	if ct == "TEXT/HTML" {
		err := f.tokenizeHTML(p.ReaderUTF8OrBinary(), metaWords, htmlWords)
		// log.Printf("html parsed, words %v", htmlWords)
		return err
	}
	if ct == "" || strings.HasPrefix(ct, "TEXT/") {
		err := f.tokenizeText(p.ReaderUTF8OrBinary(), textWords)
		// log.Printf("text parsed, words %v", textWords)
		return err
	}
	if p.Message != nil {
		// Nested message, happens for forwarding.
		if err := p.SetMessageReaderAt(); err != nil {
			return fmt.Errorf("setting reader on nested message: %w", err)
		}
		return f.mailParse(*p.Message, metaWords, textWords, htmlWords)
	}
	for _, sp := range p.Parts {
		if err := f.mailParse(sp, metaWords, textWords, htmlWords); err != nil {
			return err
		}
	}
	return nil
}

func looksRandom(s string) bool {
	// Random strings, eg 2fvu9stm9yxhnlu. ASCII only and a many consonants in a stretch.
	stretch := 0
	const consonants = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ23456789" // 0 and 1 may be used as o and l/i
	stretches := 0
	for _, c := range s {
		if c >= 0x80 {
			return false
		}
		if strings.ContainsRune(consonants, c) {
			stretch++
			continue
		}
		if stretch >= 6 {
			stretches++
		}
		stretch = 0
	}
	if stretch >= 6 {
		stretches++
	}
	return stretches > 0
}

func looksNumeric(s string) bool {
	s = strings.TrimPrefix(s, "0x") // Hexadecimal.
	var digits, hex, other, digitstretch, maxdigitstretch int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits++
			digitstretch++
			continue
		} else if c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			hex++
		} else {
			other++
		}
		if digitstretch > maxdigitstretch {
			maxdigitstretch = digitstretch
		}
	}
	if digitstretch > maxdigitstretch {
		maxdigitstretch = digitstretch
	}
	return maxdigitstretch >= 4 || other == 0 && maxdigitstretch >= 3
}

func (f *Filter) tokenizeText(r io.Reader, words map[string]struct{}) error {
	b := &strings.Builder{}
	var prev string
	var prev2 string

	add := func() {
		defer b.Reset()
		if b.Len() <= 2 {
			return
		}

		s := b.String()
		s = strings.Trim(s, "'")
		var nondigit bool
		for _, c := range s {
			if !unicode.IsDigit(c) {
				nondigit = true
				break
			}
		}

		if !(nondigit && len(s) > 2) {
			return
		}

		if looksRandom(s) {
			return
		}
		if looksNumeric(s) {
			return
		}

		// todo: do something for URLs, parse them? keep their domain only?

		if f.Threegrams && prev2 != "" && prev != "" {
			words[prev2+" "+prev+" "+s] = struct{}{}
		}
		if f.Twograms && prev != "" {
			words[prev+" "+s] = struct{}{}
		}
		if f.Onegrams {
			words[s] = struct{}{}
		}
		prev2 = prev
		prev = s
	}

	br := bufio.NewReader(r)

	peekLetter := func() bool {
		c, _, err := br.ReadRune()
		br.UnreadRune()
		return err == nil && unicode.IsLetter(c)
	}

	for {
		c, _, err := br.ReadRune()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && (c != '\'' || b.Len() > 0 && peekLetter()) {
			add()
		} else {
			b.WriteRune(unicode.ToLower(c))
		}
	}
	add()
	return nil
}

// tokenizeHTML parses html, and tokenizes its text into words.
func (f *Filter) tokenizeHTML(r io.Reader, meta, words map[string]struct{}) error {
	htmlReader := &htmlTextReader{
		t:    html.NewTokenizer(r),
		meta: map[string]struct{}{},
	}
	return f.tokenizeText(htmlReader, words)
}

type htmlTextReader struct {
	t        *html.Tokenizer
	meta     map[string]struct{}
	tagStack []string
	buf      []byte
	err      error
}

func (r *htmlTextReader) Read(buf []byte) (n int, err error) {
	// todo: deal with invalid html better. the tokenizer is just tokenizing, we need to fix up the nesting etc. eg, rules say some elements close certain open elements.
	// todo: deal with inline elements? they shouldn't cause a word break.

	give := func(nbuf []byte) (int, error) {
		n := len(buf)
		if n > len(nbuf) {
			n = len(nbuf)
		}
		copy(buf, nbuf[:n])
		nbuf = nbuf[n:]
		if len(nbuf) < cap(r.buf) {
			r.buf = r.buf[:len(nbuf)]
		} else {
			r.buf = make([]byte, len(nbuf), 3*len(nbuf)/2)
		}
		copy(r.buf, nbuf)
		return n, nil
	}

	if len(r.buf) > 0 {
		return give(r.buf)
	}
	if r.err != nil {
		return 0, r.err
	}

	for {
		switch r.t.Next() {
		case html.ErrorToken:
			r.err = r.t.Err()
			return 0, r.err
		case html.TextToken:
			if len(r.tagStack) > 0 {
				switch r.tagStack[len(r.tagStack)-1] {
				case "script", "style", "svg":
					continue
				}
			}
			buf := r.t.Text()
			if len(buf) > 0 {
				return give(buf)
			}
		case html.StartTagToken:
			tagBuf, moreAttr := r.t.TagName()
			tag := string(tagBuf)
			//log.Printf("tag %q %v", tag, r.tagStack)

			if tag == "img" && moreAttr {
				var key, val []byte
				for moreAttr {
					key, val, moreAttr = r.t.TagAttr()
					if string(key) == "alt" && len(val) > 0 {
						return give(val)
					}
				}
			}

			// Empty elements, https://developer.mozilla.org/en-US/docs/Glossary/Empty_element
			switch tag {
			case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
				continue
			}

			r.tagStack = append(r.tagStack, tag)
		case html.EndTagToken:
			// log.Printf("tag pop %v", r.tagStack)
			if len(r.tagStack) > 0 {
				r.tagStack = r.tagStack[:len(r.tagStack)-1]
			}
		case html.SelfClosingTagToken:
		case html.CommentToken:
		case html.DoctypeToken:
		}
	}
}
