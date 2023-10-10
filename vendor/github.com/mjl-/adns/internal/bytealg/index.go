package bytealg

import (
	"strings"
)

func IndexByteString(s string, b byte) int {
	return strings.IndexByte(s, b)
}
