package message

import (
	"testing"
)

func TestThreadSubject(t *testing.T) {
	check := func(s, expBase string, expResp bool) {
		t.Helper()

		base, isResp := ThreadSubject(s, false)
		if base != expBase || isResp != expResp {
			t.Fatalf("got base %q, resp %v, expected %q %v for subject %q", base, isResp, expBase, expResp, s)
		}
	}

	check("test", "test", false)
	check(" a  b\tc\r\n d\t", "a b c d", false)
	check("test (fwd) (fwd) ", "test", true)
	check("re: test", "test", true)
	check("fw: test", "test", true)
	check("fwd: test", "test", true)
	check("fwd [tag] Test", "fwd [tag] test", false)
	check("[list] re: a b c\t", "a b c", true)
	check("[list] fw: a b c", "a b c", true)
	check("[tag1][tag2] [tag3]\t re: a b c", "a b c", true)
	check("[tag1][tag2] [tag3]\t re: a \u0000b c", "", true)
	check("[list] fw:[tag] a b c", "a b c", true)
	check("[list] re: [list] fwd: a b c\t", "a b c", true)
	check("[fwd: a b c]", "a b c", true)
	check("[fwd: [fwd: a b c]]", "a b c", true)
	check("[fwd: [list] re: a b c]", "a b c", true)
	check("[nonlist]", "[nonlist]", false)
	check("fwd [list]:", "", true)
}
