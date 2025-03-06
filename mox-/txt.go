package mox

// TXTStrings returns a TXT record value as one or more quoted strings, each max
// 100 characters. In case of multiple strings, a multi-line record is returned.
func TXTStrings(s string) string {
	if len(s) <= 100 {
		return `"` + s + `"`
	}

	r := "(\n"
	for len(s) > 0 {
		n := min(len(s), 100)
		if r != "" {
			r += " "
		}
		r += "\t\t\"" + s[:n] + "\"\n"
		s = s[n:]
	}
	r += "\t)"
	return r
}
