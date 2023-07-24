package imapserver

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
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
	tc.readprefixline("+ ")
	tc.writelinef("%s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000testtest")))
	tc.readstatus("ok")
}

func TestAuthenticateSCRAMSHA1(t *testing.T) {
	testAuthenticateSCRAM(t, "SCRAM-SHA-1", sha1.New)
}

func TestAuthenticateSCRAMSHA256(t *testing.T) {
	testAuthenticateSCRAM(t, "SCRAM-SHA-256", sha256.New)
}

func testAuthenticateSCRAM(t *testing.T, method string, h func() hash.Hash) {
	tc := start(t)
	tc.client.AuthenticateSCRAM(method, h, "mjl@mox.example", "testtest")
	tc.close()

	auth := func(status string, serverFinalError error, username, password string) {
		t.Helper()

		sc := scram.NewClient(h, username, "")
		clientFirst, err := sc.ClientFirst()
		tc.check(err, "scram clientFirst")
		tc.client.LastTag = "x001"
		tc.writelinef("%s authenticate %s %s", tc.client.LastTag, method, base64.StdEncoding.EncodeToString([]byte(clientFirst)))

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
	tc.transactf("bad", "authenticate %s not base64...", method)
	tc.transactf("bad", "authenticate %s %s", method, base64.StdEncoding.EncodeToString([]byte("bad data")))
	tc.close()
}

func TestAuthenticateCRAMMD5(t *testing.T) {
	tc := start(t)

	tc.transactf("no", "authenticate bogus ")
	tc.transactf("bad", "authenticate CRAM-MD5 not base64...")
	tc.transactf("bad", "authenticate CRAM-MD5 %s", base64.StdEncoding.EncodeToString([]byte("baddata")))
	tc.transactf("bad", "authenticate CRAM-MD5 %s", base64.StdEncoding.EncodeToString([]byte("bad data")))

	auth := func(status string, username, password string) {
		t.Helper()

		tc.client.LastTag = "x001"
		tc.writelinef("%s authenticate CRAM-MD5", tc.client.LastTag)

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

		chal := xreadContinuation()
		h := hmac.New(md5.New, []byte(password))
		h.Write([]byte(chal))
		resp := fmt.Sprintf("%s %x", username, h.Sum(nil))
		tc.writelinef("%s", base64.StdEncoding.EncodeToString([]byte(resp)))

		_, result, err := tc.client.Response()
		tc.check(err, "read response")
		if string(result.Status) != strings.ToUpper(status) {
			tc.t.Fatalf("got status %q, expected %q", result.Status, strings.ToUpper(status))
		}
	}

	auth("no", "mjl@mox.example", "badpass")
	auth("no", "mjl@mox.example", "")
	auth("no", "other@mox.example", "testtest")

	auth("ok", "mjl@mox.example", "testtest")

	tc.close()
}
