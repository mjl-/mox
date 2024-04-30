package mox

import (
	cryptorand "crypto/rand"
	"encoding/base64"
)

// MessageIDGen returns a generated unique random Message-Id value, excluding <>.
func MessageIDGen(smtputf8 bool) string {
	buf := make([]byte, 16)
	cryptorand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf) + "@" + Conf.Static.HostnameDomain.XName(smtputf8)
}
