package main

import (
	"strings"
	"testing"

	"github.com/mjl-/mox/mlog"
)

func TestParseDovecotKeywords(t *testing.T) {
	const data = `0 Old
1 Junk
2 NonJunk
3 $Forwarded
4 $Junk
`
	keywords := tryParseDovecotKeywords(strings.NewReader(data), mlog.New("dovecotkeywords"))
	got := strings.Join(keywords, ",")
	want := "Old,Junk,NonJunk,$Forwarded,$Junk"
	if got != want {
		t.Fatalf("parsing dovecot keywords, got %q, want %q", got, want)

	}
}
