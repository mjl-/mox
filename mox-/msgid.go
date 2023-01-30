package mox

import (
	"encoding/base64"
)

var messageIDRand = NewRand()

// MessageIDGen returns a generated unique random Message-Id value, excluding <>.
func MessageIDGen(smtputf8 bool) string {
	buf := make([]byte, 16)
	messageIDRand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf) + "@" + Conf.Static.HostnameDomain.XName(smtputf8)
}
