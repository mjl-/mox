package imapserver

import (
	"crypto/tls"
	"encoding/base64"
	"testing"
)

func TestStarttls(t *testing.T) {
	tc := start(t)
	tc.client.Starttls(&tls.Config{InsecureSkipVerify: true})
	tc.transactf("bad", "starttls") // TLS already active.
	tc.client.Login("mjl@mox.example", "testtest")
	tc.close()

	tc = startArgs(t, true, true, false, true, "mjl")
	tc.transactf("bad", "starttls") // TLS already active.
	tc.close()

	tc = startArgs(t, true, false, false, true, "mjl")
	tc.transactf("no", `login "mjl@mox.example" "testtest"`)
	tc.xcode("PRIVACYREQUIRED")
	tc.transactf("no", "authenticate PLAIN %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000testtest")))
	tc.xcode("PRIVACYREQUIRED")
	tc.client.Starttls(&tls.Config{InsecureSkipVerify: true})
	tc.client.Login("mjl@mox.example", "testtest")
	tc.close()
}
