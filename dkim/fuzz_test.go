package dkim

import (
	"testing"
)

func FuzzParseSignature(f *testing.F) {
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, buf []byte) {
		parseSignature(buf, false)
	})
}

func FuzzParseRecord(f *testing.F) {
	f.Add("")
	f.Add("v=DKIM1; p=bad")
	f.Fuzz(func(t *testing.T, s string) {
		r, _, err := ParseRecord(s)
		if err == nil {
			if _, err := r.Record(); err != nil {
				t.Errorf("r.Record() for parsed record %s, %#v: %s", s, r, err)
			}
		}
	})
}
