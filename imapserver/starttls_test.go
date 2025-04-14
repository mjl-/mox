package imapserver

import (
	"crypto/tls"
	"encoding/base64"
	"testing"
)

func TestStarttls(t *testing.T) {
	tc := start(t, false)
	tc.client.StartTLS(&tls.Config{InsecureSkipVerify: true})
	tc.transactf("bad", "starttls") // TLS already active.
	tc.login("mjl@mox.example", password0)
	tc.close()

	tc = startArgs(t, false, true, true, false, true, "mjl")
	tc.transactf("bad", "starttls") // TLS already active.
	tc.close()

	tc = startArgs(t, false, true, false, false, true, "mjl")
	tc.transactf("no", `login "mjl@mox.example" "%s"`, password0)
	tc.xcodeWord("PRIVACYREQUIRED")
	tc.transactf("no", "authenticate PLAIN %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000"+password0)))
	tc.xcodeWord("PRIVACYREQUIRED")
	tc.client.StartTLS(&tls.Config{InsecureSkipVerify: true})
	tc.login("mjl@mox.example", password0)
	tc.close()
}
