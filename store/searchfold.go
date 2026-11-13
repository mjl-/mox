package store

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// SearchText returns the case-insensitive search representation of s. With
// foldLatin, Latin accents are removed and sharp s is expanded to ss.
// Other scripts are only lower-cased, as in ordinary searches.
func SearchText(s string, foldLatin bool) string {
	if foldLatin {
		// latinSearchFold accepts all input, including malformed UTF-8.
		s, _, _ = transform.String(&latinSearchFold{}, s)
	}
	return strings.ToLower(s)
}

// latinSearchFold keeps track of the preceding base character so combining marks
// are removed only from Latin letters, including across reader boundaries.
type latinSearchFold struct {
	latin bool
}

func (t *latinSearchFold) Reset() { t.latin = false }

func (t *latinSearchFold) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	var buf [norm.MaxSegmentSize]byte
	for nSrc < len(src) {
		if b := src[nSrc]; b < utf8.RuneSelf {
			if nDst == len(dst) {
				return nDst, nSrc, transform.ErrShortDst
			}
			dst[nDst] = b
			nDst++
			nSrc++
			t.latin = b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
			continue
		}
		if !atEOF && !utf8.FullRune(src[nSrc:]) {
			return nDst, nSrc, transform.ErrShortSrc
		}
		r, size := utf8.DecodeRune(src[nSrc:])
		mark := unicode.Is(unicode.M, r)
		if mark && t.latin {
			nSrc += size
			continue
		}
		latin := unicode.Is(unicode.Latin, r)
		out := src[nSrc : nSrc+size]
		if latin {
			// Read the canonical decomposition directly to avoid allocating per rune.
			decomp := norm.NFD.Properties(out).Decomposition()
			if decomp == nil {
				decomp = out
			}
			out = buf[:0]
			for len(decomp) > 0 {
				base, n := utf8.DecodeRune(decomp)
				decomp = decomp[n:]
				if unicode.Is(unicode.M, base) {
					continue
				}
				// Strokes and sharp s have no canonical decomposition.
				switch base {
				case 'ß', 'ẞ':
					out = append(out, 's', 's')
					continue
				case 'Ł', 'ł':
					base = 'l'
				case 'Ø', 'ø':
					base = 'o'
				case 'Đ', 'đ':
					base = 'd'
				case 'Ħ', 'ħ':
					base = 'h'
				case 'Ŧ', 'ŧ':
					base = 't'
				case 'ı':
					base = 'i'
				}
				out = utf8.AppendRune(out, base)
			}
		}
		if len(dst)-nDst < len(out) {
			return nDst, nSrc, transform.ErrShortDst
		}
		nDst += copy(dst[nDst:], out)
		nSrc += size
		if !mark {
			t.latin = latin
		}
	}
	return nDst, nSrc, nil
}
