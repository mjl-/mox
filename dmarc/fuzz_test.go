package dmarc

import (
	"testing"
)

func FuzzParseRecord(f *testing.F) {
	f.Add("")
	f.Add("V = DMARC1; P = reject ;\tSP=none; unknown \t=\t ignored-future-value \t ; adkim=s; aspf=s; rua=mailto:dmarc-feedback@example.com  ,\t\tmailto:tld-test@thirdparty.example.net!10m; RUF=mailto:auth-reports@example.com  ,\t\tmailto:tld-test@thirdparty.example.net!0G; RI = 123; FO = 0:1:d:s ; RF= afrf : other; Pct = 0")
	f.Add("v=DMARC1; rua=mailto:dmarc-feedback@example.com!99999999999999999999999999999999999999999999999")
	f.Fuzz(func(t *testing.T, s string) {
		r, _, err := ParseRecord(s)
		if err == nil {
			_ = r.String()
		}
	})
}
