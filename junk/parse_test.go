package junk

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mjl-/mox/mlog"
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
	add(filepath.FromSlash("../testdata/junk/parse.eml"))
	add(filepath.FromSlash("../testdata/junk/parse2.eml"))
	add(filepath.FromSlash("../testdata/junk/parse3.eml"))

	dbPath := filepath.FromSlash("../testdata/junk/parse.db")
	bloomPath := filepath.FromSlash("../testdata/junk/parse.bloom")
	os.Remove(dbPath)
	os.Remove(bloomPath)
	params := Params{Twograms: true}
	log := mlog.New("junk", nil)
	jf, err := NewFilter(ctxbg, log, params, dbPath, bloomPath)
	if err != nil {
		f.Fatalf("new filter: %v", err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		jf.tokenizeMail(s)
	})
}
