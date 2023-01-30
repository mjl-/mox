package junk

import (
	"os"
	"testing"
)

func FuzzParseMessage(f *testing.F) {
	f.Add("")
	add := func(p string) {
		buf, err := os.ReadFile(p)
		if err != nil {
			f.Fatalf("reading file %q: %v", p, err)
		}
		f.Add(string(buf))
	}
	add("../testdata/junk/parse.eml")
	add("../testdata/junk/parse2.eml")
	add("../testdata/junk/parse3.eml")

	dbPath := "../testdata/junk/parse.db"
	bloomPath := "../testdata/junk/parse.bloom"
	os.Remove(dbPath)
	os.Remove(bloomPath)
	params := Params{Twograms: true}
	jf, err := NewFilter(xlog, params, dbPath, bloomPath)
	if err != nil {
		f.Fatalf("new filter: %v", err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		jf.tokenizeMail(s)
	})
}
