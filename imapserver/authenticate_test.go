package imapserver

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/mjl-/mox/scram"
)

func TestAuthenticatePlain(t *testing.T) {
	tc := start(t)

	tc.transactf("no", "authenticate bogus ")
	tc.transactf("bad", "authenticate plain not base64...")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000baduser\u0000badpass")))
	tc.xcode("AUTHENTICATIONFAILED")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000badpass")))
	tc.xcode("AUTHENTICATIONFAILED")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl\u0000badpass"))) // Need email, not account.
	tc.xcode("AUTHENTICATIONFAILED")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000test")))
	tc.xcode("AUTHENTICATIONFAILED")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000testtesttest")))
	tc.xcode("AUTHENTICATIONFAILED")
	tc.transactf("bad", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000")))
	tc.xcode("")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("other\u0000mjl@mox.example\u0000testtest")))
	tc.xcode("AUTHORIZATIONFAILED")
	tc.transactf("ok", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000testtest")))
	tc.close()

	tc = start(t)
	tc.transactf("ok", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("mjl@mox.example\u0000mjl@mox.example\u0000testtest")))
	tc.close()

	tc = start(t)
	tc.client.AuthenticatePlain("mjl@mox.example", "testtest")
	tc.close()

	tc = start(t)
	defer tc.close()

	tc.cmdf("", "authenticate plain")
	tc.readprefixline("+ ")
	tc.writelinef("*") // Aborts.
	tc.readstatus("bad")

	tc.cmdf("", "authenticate plain")
	tc.readprefixline("+")
	tc.writelinef("%s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000testtest")))
	tc.readstatus("ok")
}

func TestAuthenticateSCRAMSHA256(t *testing.T) {
	tc := start(t)
	tc.client.AuthenticateSCRAMSHA256("mjl@mox.example", "testtest")
	tc.close()

	auth := func(status string, serverFinalError error, username, password string) {
		t.Helper()

		sc := scram.NewClient(username, "")
		clientFirst, err := sc.ClientFirst()
		tc.check(err, "scram clientFirst")
		tc.client.LastTag = "x001"
		tc.writelinef("%s authenticate scram-sha-256 %s", tc.client.LastTag, base64.StdEncoding.EncodeToString([]byte(clientFirst)))

		xreadContinuation := func() []byte {
			line, _, result, rerr := tc.client.ReadContinuation()
			tc.check(rerr, "read continuation")
			if result.Status != "" {
				tc.t.Fatalf("expected continuation")
			}
			buf, err := base64.StdEncoding.DecodeString(line)
			tc.check(err, "parsing base64 from remote")
			return buf
		}

		serverFirst := xreadContinuation()
		clientFinal, err := sc.ServerFirst(serverFirst, password)
		tc.check(err, "scram clientFinal")
		tc.writelinef("%s", base64.StdEncoding.EncodeToString([]byte(clientFinal)))

		serverFinal := xreadContinuation()
		err = sc.ServerFinal(serverFinal)
		if serverFinalError == nil {
			tc.check(err, "scram serverFinal")
		} else if err == nil || !errors.Is(err, serverFinalError) {
			t.Fatalf("server final, got err %#v, expected %#v", err, serverFinalError)
		}
		if serverFinalError != nil {
			tc.writelinef("*")
		} else {
			tc.writelinef("")
		}
		_, result, err := tc.client.Response()
		tc.check(err, "read response")
		if string(result.Status) != strings.ToUpper(status) {
			tc.t.Fatalf("got status %q, expected %q", result.Status, strings.ToUpper(status))
		}
	}

	tc = start(t)
	auth("no", scram.ErrInvalidProof, "mjl@mox.example", "badpass")
	auth("no", scram.ErrInvalidProof, "mjl@mox.example", "")
	// todo: server aborts due to invalid username. we should probably make client continue with fake determinisitically generated salt and result in error in the end.
	// auth("no", nil, "other@mox.example", "testtest")

	tc.transactf("no", "authenticate bogus ")
	tc.transactf("bad", "authenticate scram-sha-256 not base64...")
	tc.transactf("bad", "authenticate scram-sha-256 %s", base64.StdEncoding.EncodeToString([]byte("bad data")))
	tc.close()
}
