package imapserver

import (
	"encoding/base64"
	"errors"
	"fmt"
)

const utf7chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,"

var utf7encoding = base64.NewEncoding(utf7chars).WithPadding(base64.NoPadding)

var (
	errUTF7SuperfluousShift = errors.New("utf7: superfluous unshift+shift")
	errUTF7Base64           = errors.New("utf7: bad base64")
	errUTF7OddSized         = errors.New("utf7: odd-sized data")
	errUTF7UnneededShift    = errors.New("utf7: unneeded shift")
	errUTF7UnfinishedShift  = errors.New("utf7: unfinished shift")
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
		for i := 0; i < len(buf); i += 2 {
			x[j] = rune(buf[i])<<8 | rune(buf[i+1])
			j++
		}

		need := false
		for _, c := range x {
			if c < 0x20 || c > 0x7e || c == '&' {
				need = true
			}
			r += string(c)
		}
		if !need {
			return "", errUTF7UnneededShift
		}
	}
	if shifted {
		return "", errUTF7UnfinishedShift
	}
	return r, nil
}
