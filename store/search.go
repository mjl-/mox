package store

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	encUnicode "golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// WordSearch holds context for a search, with scratch buffers to prevent
// allocations for each message.
type WordSearch struct {
	words, notWords    [][]byte
	searchBuf, keepBuf []byte
}

// PrepareWordSearch returns a search context that can be used to match multiple
// messages (after each other, not concurrently).
func PrepareWordSearch(words, notWords []string) WordSearch {
	var wl, nwl [][]byte
	for _, w := range words {
		wl = append(wl, []byte(strings.ToLower(w)))
	}
	for _, w := range notWords {
		nwl = append(nwl, []byte(strings.ToLower(w)))
	}

	keep := 0
	for _, w := range words {
		if len(w) > keep {
			keep = len(w)
		}
	}
	for _, w := range notWords {
		if len(w) > keep {
			keep = len(w)
		}
	}
	keep += 6 // Max utf-8 character size.

	bufSize := 8 * 1024
	for bufSize/keep < 8 {
		bufSize *= 2
	}

	keepBuf := make([]byte, keep)
	searchBuf := make([]byte, bufSize)

	return WordSearch{wl, nwl, searchBuf, keepBuf}
}

// MatchPart returns whether the part/mail message p matches the search.
// The search terms are matched against content-transfer-decoded and
// charset-decoded bodies and optionally headers.
// HTML parts are currently treated as regular text, without parsing HTML.
func (ws WordSearch) MatchPart(log mlog.Log, p *message.Part, headerToo bool) (bool, error) {
	seen := map[int]bool{}
	miss, err := ws.matchPart(log, p, headerToo, seen)
	match := err == nil && !miss && len(seen) == len(ws.words)
	return match, err
}

// If all words are seen, and we there are no not-words that force us to search
// till the end, we know we have a match.
func (ws WordSearch) isQuickHit(seen map[int]bool) bool {
	return len(seen) == len(ws.words) && len(ws.notWords) == 0
}

// search a part as text and/or its subparts, recursively. Once we know we have
// a miss, we stop (either due to not-word match or error). In case of
// non-miss, the caller checks if there was a hit.
func (ws WordSearch) matchPart(log mlog.Log, p *message.Part, headerToo bool, seen map[int]bool) (miss bool, rerr error) {
	if headerToo {
		miss, err := ws.searchReader(log, p.HeaderReader(), seen)
		if miss || err != nil || ws.isQuickHit(seen) {
			return miss, err
		}
	}

	if len(p.Parts) == 0 {
		if p.MediaType != "TEXT" {
			// todo: for other types we could try to find a library for parsing and search in there too.
			return false, nil
		}
		tp := p.ReaderUTF8OrBinary()
		// todo: for html and perhaps other types, we could try to parse as text and filter on the text.
		miss, err := ws.searchReader(log, tp, seen)
		if miss || err != nil || ws.isQuickHit(seen) {
			return miss, err
		}
	}
	for _, pp := range p.Parts {
		if pp.Message != nil {
			if err := pp.SetMessageReaderAt(); err != nil {
				return false, err
			}
			pp = *pp.Message
		}
		miss, err := ws.matchPart(log, &pp, headerToo, seen)
		if miss || err != nil || ws.isQuickHit(seen) {
			return miss, err
		}
	}
	return false, nil
}

func (ws WordSearch) searchReader(log mlog.Log, r io.Reader, seen map[int]bool) (miss bool, rerr error) {
	// We will be reading through the content, stopping as soon as we known an answer:
	// when all words have been seen and there are no "not words" (true), or one "not
	// word" has been seen (false). We use bytes.Contains to look for the words. We
	// advance our buffer in largish chunks, keeping the end of the buffer the size of
	// the largest word plus the max of an utf-8 character to account for words
	// spanning chunks.

	have := 0
	for {
		n, err := io.ReadFull(r, ws.searchBuf[have:])
		if n > 0 {
			have += n
		}
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return true, err
		}
		if err == nil {
			copy(ws.keepBuf, ws.searchBuf[have-len(ws.keepBuf):])
		}

		lower := toLower(ws.searchBuf[:have])

		for i, w := range ws.words {
			if !seen[i] && bytes.Contains(lower, w) {
				seen[i] = true
				if len(seen) == len(ws.words) && len(ws.notWords) == 0 {
					return false, nil
				}
			}
		}
		for _, w := range ws.notWords {
			if bytes.Contains(lower, w) {
				return true, nil
			}
		}
		if err != nil {
			// Must be EOF or UnexpectedEOF now.
			break
		}
		copy(ws.searchBuf, ws.keepBuf)
		have = len(ws.keepBuf)
	}
	return false, nil
}

// in-place lower-casing, only allocating a new slice when lower-case would become
// larger. we replace RuneError (0xfffd) by byte value 0, because it would often
// increase size, but we assume no one wants to match it.
func toLower(buf []byte) []byte {
	r := buf[:0]
	copied := false
	for i := 0; i < len(buf); {
		if buf[i] < 0x80 {
			b := buf[i]
			if b >= 'A' && b <= 'Z' {
				b += 0x20
			}
			r = append(r, b)
			i++
			continue
		}
		c, size := utf8.DecodeRune(buf[i:])
		i += size
		nc := unicode.ToLower(c)
		if nc < 0 {
			continue
		}
		if c == utf8.RuneError {
			r = append(r, 0)
			continue
		}
		nsize := utf8.RuneLen(nc)
		// Take care not to overwrite the part of the buffer we still have to process.
		if !copied && len(r)+nsize > i {
			// eg Ⱥ 0x23a (2 bytes) to ⱥ 0x2c65 (3 bytes)
			copied = true
			nr := make([]byte, len(r), len(r)+nsize+len(buf)-i)
			copy(nr, r)
			nr = r
		}
		r = utf8.AppendRune(r, nc)
	}
	return r
}

func decodeRFC2047(encoded string) (string, error) {
	// match e.g. =?(iso-2022-jp)?(B)?(Rnc6...)?=
	r := regexp.MustCompile(`(?i)=\?([^?]+)\?([BQ])\?([^?]+)\?=`)
	matches := r.FindAllStringSubmatch(encoded, -1)

	if len(matches) == 0 { // no match. Looks ASCII.
		return encoded, nil
	}

	var decodedStrings []string
	for _, match := range matches {
		charset := match[1]
		encodingName := match[2]
		encodedText := match[3]

		reader, err := decodeTransferEncodeAndCharset(encodingName, charset, encodedText)
		if err != nil {
			return encoded, err
		}

		decodedText, err := io.ReadAll(reader)
		if err != nil {
			return encoded, err
		}

		decodedStrings = append(decodedStrings, string(decodedText))
	}

	// Concat multiple strings
	return strings.Join(decodedStrings, ""), nil
}

func decodeTransferEncodeAndCharset(encodingName string, charset string, encodedText string) (io.Reader, error) {
	decodedString, err := decodeTransferEncode(encodingName, encodedText)
	if len(decodedString) == 0 && err != nil {
		return nil, err
	}

	// try to decode even if unknown encoding
	reader, err := decodeCharset(charset, decodedString)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

// Decode Base64 or Quoted Printable
func decodeTransferEncode(encodingName string, encodedText string) (string, error) {
	// Decode Base64 or Quoted-Printable
	var decodedBytes []byte
	var err error
	switch strings.ToUpper(encodingName) {
	case "B": // Base64
		decodedBytes, err = base64.StdEncoding.DecodeString(encodedText)
		if err != nil {
			return string(decodedBytes), fmt.Errorf("Base64 decode error: %w", err)
		}
	case "Q": // Quoted-Printable
		decodedBytes, err = io.ReadAll(quotedprintable.NewReader(strings.NewReader(encodedText)))
		if err != nil {
			return string(decodedBytes), fmt.Errorf("Quoted-Printable decode error: %w", err)
		}
	default:
		return encodedText, fmt.Errorf("not supported encoding: %s", encodingName)
	}
	return string(decodedBytes), nil
}

func decodeCharset(charset string, decodedString string) (io.Reader, error) {
	// Select charset
	var enc encoding.Encoding
	switch strings.ToLower(charset) {
	case "iso-2022-jp":
		enc = japanese.ISO2022JP
	case "utf-8":
		enc = encUnicode.UTF8
	case "us-ascii":
		return strings.NewReader(decodedString), nil
	default:
		return nil, fmt.Errorf("not supported charset: %s", charset)
	}

	// Decode with charset
	reader := transform.NewReader(strings.NewReader(decodedString), enc.NewDecoder())
	return reader, nil
}

func decodeMultiPart(body string, boundary string) (io.Reader, error) {
	encPattern := `Content-Transfer-Encoding:\s+(\w+)`
	charsetPattern := `charset="((?:\w|-)+)"`

	// Regexp for MIME encode type & Charset match
	encRe, err := regexp.Compile(encPattern)
	if err != nil {
		return nil, fmt.Errorf("error compiling regex:%v", err)
	}
	charsetRe, err := regexp.Compile(charsetPattern)
	if err != nil {
		return nil, fmt.Errorf("error compiling regex:%v", err)
	}

	// Split by boundary
	parts := strings.Split(body, boundary)
	var readers []io.Reader

	// Make decoded io.Readers for each part
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) == 0 {
			continue
		}

		// Extract MIME header and body
		headerBody := strings.SplitN(part, "\r\n\r\n", 2)
		if len(headerBody) < 2 {
			// retry
			headerBody = strings.SplitN(part, "\n\n", 2)
			if len(headerBody) < 2 {
				continue
			}
		}

		mimeHeader := headerBody[0]
		encodedBody := headerBody[1]

		// Find encode types
		encMatches := encRe.FindStringSubmatch(mimeHeader)
		charsetMatches := charsetRe.FindStringSubmatch(mimeHeader)

		// Decode
		if len(encMatches) > 1 && len(charsetMatches) > 1 {
			reader, err := decodeTransferEncodeAndCharset(encMatches[1][0:1], charsetMatches[1], encodedBody)
			if err != nil {
				return nil, err
			}
			readers = append(readers, reader)

		} else {
			return nil, fmt.Errorf("failed to match encoding and charset in:\n%s", mimeHeader)
		}
	}

	return io.MultiReader(readers...), nil
}
