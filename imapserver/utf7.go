package imapserver

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf16"
)

// IMAP4rev1 uses a modified version of UTF-7.
// ../rfc/3501:1050
// ../rfc/2152:69

const utf7chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,"

var utf7encoding = base64.NewEncoding(utf7chars).WithPadding(base64.NoPadding)

var (
	errUTF7SuperfluousShift = errors.New("utf7: superfluous unshift+shift")
	errUTF7Base64           = errors.New("utf7: bad base64")
	errUTF7OddSized         = errors.New("utf7: odd-sized data")
	errUTF7UnneededShift    = errors.New("utf7: unneeded shift")
	errUTF7UnfinishedShift  = errors.New("utf7: unfinished shift")
	errUTF7BadSurrogate     = errors.New("utf7: bad utf16 surrogates")
)

func utf7decode(s string) (string, error) {
	var r string
	var shifted bool
	var b string
	lastunshift := -2

	for i, c := range s {
		if !shifted {
			if c == '&' {
				if lastunshift == i-1 {
					return "", errUTF7SuperfluousShift
				}
				shifted = true
			} else {
				r += string(c)
			}
			continue
		}

		if c != '-' {
			b += string(c)
			continue
		}

		shifted = false
		lastunshift = i
		if b == "" {
			r += "&"
			continue
		}
		buf, err := utf7encoding.DecodeString(b)
		if err != nil {
			return "", fmt.Errorf("%w: %q: %v", errUTF7Base64, b, err)
		}
		b = ""

		if len(buf)%2 != 0 {
			return "", errUTF7OddSized
		}

		x := make([]rune, len(buf)/2)
		j := 0
		trymerge := false
		for i := 0; i < len(buf); i += 2 {
			x[j] = rune(buf[i])<<8 | rune(buf[i+1])
			if trymerge {
				s0 := utf16.IsSurrogate(x[j-1])
				s1 := utf16.IsSurrogate(x[j])
				if s0 && s1 {
					c := utf16.DecodeRune(x[j-1], x[j])
					if c == 0xfffd {
						return "", fmt.Errorf("%w: decoding %x %x", errUTF7BadSurrogate, x[j-1], x[j])
					}
					x[j-1] = c
					trymerge = false
					continue
				} else if s0 != s1 {
					return "", fmt.Errorf("%w: not both surrogate: %x %x", errUTF7BadSurrogate, x[j-1], x[j])
				}
			}
			j++
			trymerge = true
		}
		x = x[:j]

		for _, c := range x {
			if c < 0x20 || c > 0x7e || c == '&' {
				r += string(c)
			} else {
				// ../rfc/3501:1057
				return "", errUTF7UnneededShift
			}
		}
	}
	if shifted {
		return "", errUTF7UnfinishedShift
	}
	return r, nil
}

func utf7encode(s string) string {
	var r string
	var code string

	flushcode := func() {
		if code == "" {
			return
		}
		var b bytes.Buffer
		for _, c := range code {
			high, low := utf16.EncodeRune(c)
			if high == 0xfffd && low == 0xfffd {
				b.WriteByte(byte(c >> 8))
				b.WriteByte(byte(c >> 0))
			} else {
				b.WriteByte(byte(high >> 8))
				b.WriteByte(byte(high >> 0))
				b.WriteByte(byte(low >> 8))
				b.WriteByte(byte(low >> 0))
			}
		}
		r += "&" + utf7encoding.EncodeToString(b.Bytes()) + "-"
		code = ""
	}

	for _, c := range s {
		if c == '&' {
			flushcode()
			r += "&-"
		} else if c >= ' ' && c < 0x7f {
			flushcode()
			r += string(c)
		} else {
			code += string(c)
		}
	}
	flushcode()
	return r
}
