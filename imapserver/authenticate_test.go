package imapserver

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/secure/precis"

	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/store"
)

func TestAuthenticateLogin(t *testing.T) {
	// NFD username and PRECIS-cleaned password.
	tc := start(t, false)
	tc.client.Login("mo\u0301x@mox.example", password1)
	tc.close()
}

func TestAuthenticatePlain(t *testing.T) {
	tc := start(t, false)

	tc.transactf("no", "authenticate bogus ")
	tc.transactf("bad", "authenticate plain not base64...")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000baduser\u0000badpass")))
	tc.xcodeWord("AUTHENTICATIONFAILED")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000badpass")))
	tc.xcodeWord("AUTHENTICATIONFAILED")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl\u0000badpass"))) // Need email, not account.
	tc.xcodeWord("AUTHENTICATIONFAILED")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000test")))
	tc.xcodeWord("AUTHENTICATIONFAILED")
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000test"+password0)))
	tc.xcodeWord("AUTHENTICATIONFAILED")
	tc.transactf("bad", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000")))
	tc.xcode(nil)
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("other\u0000mjl@mox.example\u0000"+password0)))
	tc.xcodeWord("AUTHORIZATIONFAILED")
	tc.transactf("ok", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000"+password0)))
	tc.close()

	tc = start(t, false)
	tc.transactf("ok", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("mjl@mox.example\u0000mjl@mox.example\u0000"+password0)))
	tc.close()

	// NFD username and PRECIS-cleaned password.
	tc = start(t, false)
	tc.transactf("ok", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("mo\u0301x@mox.example\u0000mo\u0301x@mox.example\u0000"+password1)))
	tc.close()

	tc = start(t, false)
	tc.client.AuthenticatePlain("mjl@mox.example", password0)
	tc.close()

	tc = start(t, false)
	defer tc.close()

	tc.cmdf("", "authenticate plain")
	tc.readprefixline("+ ")
	tc.writelinef("*") // Aborts.
	tc.readstatus("bad")

	tc.cmdf("", "authenticate plain")
	tc.readprefixline("+ ")
	tc.writelinef("%s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000"+password0)))
	tc.readstatus("ok")
}

func TestLoginDisabled(t *testing.T) {
	tc := start(t, false)
	defer tc.close()

	acc, err := store.OpenAccount(pkglog, "disabled", false)
	tcheck(t, err, "open account")
	err = acc.SetPassword(pkglog, "test1234")
	tcheck(t, err, "set password")
	err = acc.Close()
	tcheck(t, err, "close account")

	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000disabled@mox.example\u0000test1234")))
	tc.xcode(nil)
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000disabled@mox.example\u0000bogus")))
	tc.xcodeWord("AUTHENTICATIONFAILED")

	tc.transactf("no", "login disabled@mox.example test1234")
	tc.xcode(nil)
	tc.transactf("no", "login disabled@mox.example bogus")
	tc.xcodeWord("AUTHENTICATIONFAILED")
}

func TestAuthenticateSCRAMSHA1(t *testing.T) {
	testAuthenticateSCRAM(t, false, "SCRAM-SHA-1", sha1.New)
}

func TestAuthenticateSCRAMSHA256(t *testing.T) {
	testAuthenticateSCRAM(t, false, "SCRAM-SHA-256", sha256.New)
}

func TestAuthenticateSCRAMSHA1PLUS(t *testing.T) {
	testAuthenticateSCRAM(t, true, "SCRAM-SHA-1-PLUS", sha1.New)
}

func TestAuthenticateSCRAMSHA256PLUS(t *testing.T) {
	testAuthenticateSCRAM(t, true, "SCRAM-SHA-256-PLUS", sha256.New)
}

func testAuthenticateSCRAM(t *testing.T, tls bool, method string, h func() hash.Hash) {
	tc := startArgs(t, false, true, tls, true, true, "mjl")
	tc.client.AuthenticateSCRAM(method, h, "mjl@mox.example", password0)
	tc.close()

	auth := func(status string, serverFinalError error, username, password string) {
		t.Helper()

		noServerPlus := false
		sc := scram.NewClient(h, username, "", noServerPlus, tc.client.TLSConnectionState())
		clientFirst, err := sc.ClientFirst()
		tc.check(err, "scram clientFirst")
		tc.client.WriteCommandf("", "authenticate %s %s", method, base64.StdEncoding.EncodeToString([]byte(clientFirst)))

		xreadContinuation := func() []byte {
			line, err := tc.client.ReadContinuation()
			tcheck(t, err, "read continuation")
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
		resp, err := tc.client.ReadResponse()
		tc.check(err, "read response")
		if string(resp.Status) != strings.ToUpper(status) {
			tc.t.Fatalf("got status %q, expected %q", resp.Status, strings.ToUpper(status))
		}
	}

	tc = startArgs(t, false, true, tls, true, true, "mjl")
	auth("no", scram.ErrInvalidProof, "mjl@mox.example", "badpass")
	auth("no", scram.ErrInvalidProof, "mjl@mox.example", "")
	// todo: server aborts due to invalid username. we should probably make client continue with fake determinisitically generated salt and result in error in the end.
	// auth("no", nil, "other@mox.example", password0)

	tc.transactf("no", "authenticate bogus ")
	tc.transactf("bad", "authenticate %s not base64...", method)
	tc.transactf("no", "authenticate %s %s", method, base64.StdEncoding.EncodeToString([]byte("bad data")))

	// NFD username, with PRECIS-cleaned password.
	auth("ok", nil, "mo\u0301x@mox.example", password1)

	tc.close()
}

func TestAuthenticateCRAMMD5(t *testing.T) {
	tc := start(t, false)

	tc.transactf("no", "authenticate bogus ")
	tc.transactf("bad", "authenticate CRAM-MD5 not base64...")
	tc.transactf("bad", "authenticate CRAM-MD5 %s", base64.StdEncoding.EncodeToString([]byte("baddata")))
	tc.transactf("bad", "authenticate CRAM-MD5 %s", base64.StdEncoding.EncodeToString([]byte("bad data")))

	auth := func(status string, username, password string) {
		t.Helper()

		tc.client.WriteCommandf("", "authenticate CRAM-MD5")

		xreadContinuation := func() []byte {
			line, err := tc.client.ReadContinuation()
			tcheck(t, err, "read continuation")
			buf, err := base64.StdEncoding.DecodeString(line)
			tc.check(err, "parsing base64 from remote")
			return buf
		}

		chal := xreadContinuation()
		pw, err := precis.OpaqueString.String(password)
		if err == nil {
			password = pw
		}
		h := hmac.New(md5.New, []byte(password))
		h.Write([]byte(chal))
		data := fmt.Sprintf("%s %x", username, h.Sum(nil))
		tc.writelinef("%s", base64.StdEncoding.EncodeToString([]byte(data)))

		resp, err := tc.client.ReadResponse()
		tc.check(err, "read response")
		if string(resp.Status) != strings.ToUpper(status) {
			tc.t.Fatalf("got status %q, expected %q", resp.Status, strings.ToUpper(status))
		}
	}

	auth("no", "mjl@mox.example", "badpass")
	auth("no", "mjl@mox.example", "")
	auth("no", "other@mox.example", password0)

	auth("ok", "mjl@mox.example", password0)

	tc.close()

	// NFD username, with PRECIS-cleaned password.
	tc = start(t, false)
	auth("ok", "mo\u0301x@mox.example", password1)
	tc.close()
}

func TestAuthenticateTLSClientCert(t *testing.T) {
	tc := startArgsMore(t, false, true, true, nil, nil, true, true, "mjl", nil)
	tc.transactf("no", "authenticate external ") // No TLS auth.
	tc.close()

	// Create a certificate, register its public key with account, and make a tls
	// client config that sends the certificate.
	clientCert0 := fakeCert(t, true)
	clientConfig := tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{clientCert0},
	}

	tlspubkey, err := store.ParseTLSPublicKeyCert(clientCert0.Certificate[0])
	tcheck(t, err, "parse certificate")
	tlspubkey.Account = "mjl"
	tlspubkey.LoginAddress = "mjl@mox.example"
	tlspubkey.NoIMAPPreauth = true

	addClientCert := func() error {
		return store.TLSPublicKeyAdd(ctxbg, &tlspubkey)
	}

	// No preauth, explicit authenticate with TLS.
	tc = startArgsMore(t, false, true, true, nil, &clientConfig, false, true, "mjl", addClientCert)
	if tc.client.Preauth {
		t.Fatalf("preauthentication while not configured for tls public key")
	}
	tc.transactf("ok", "authenticate external ")
	tc.close()

	// External with explicit username.
	tc = startArgsMore(t, false, true, true, nil, &clientConfig, false, true, "mjl", addClientCert)
	if tc.client.Preauth {
		t.Fatalf("preauthentication while not configured for tls public key")
	}
	tc.transactf("ok", "authenticate external %s", base64.StdEncoding.EncodeToString([]byte("mjl@mox.example")))
	tc.close()

	// No preauth, also allow other mechanisms.
	tc = startArgsMore(t, false, true, true, nil, &clientConfig, false, true, "mjl", addClientCert)
	tc.transactf("ok", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000"+password0)))
	tc.close()

	// No preauth, also allow other username for same account.
	tc = startArgsMore(t, false, true, true, nil, &clientConfig, false, true, "mjl", addClientCert)
	tc.transactf("ok", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000móx@mox.example\u0000"+password0)))
	tc.close()

	// No preauth, other mechanism must be for same account.
	acc, err := store.OpenAccount(pkglog, "other", false)
	tcheck(t, err, "open account")
	err = acc.SetPassword(pkglog, "test1234")
	tcheck(t, err, "set password")
	err = acc.Close()
	tcheck(t, err, "close account")
	tc = startArgsMore(t, false, true, true, nil, &clientConfig, false, true, "mjl", addClientCert)
	tc.transactf("no", "authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000other@mox.example\u0000test1234")))
	tc.close()

	// Starttls and external auth.
	tc = startArgsMore(t, false, true, false, nil, &clientConfig, false, true, "mjl", addClientCert)
	tc.client.StartTLS(&clientConfig)
	tc.transactf("ok", "authenticate external =")
	tc.close()

	tlspubkey.NoIMAPPreauth = false
	err = store.TLSPublicKeyUpdate(ctxbg, &tlspubkey)
	tcheck(t, err, "update tls public key")

	// With preauth, no authenticate command needed/allowed.
	// Already set up tls session ticket cache, for next test.
	serverConfig := tls.Config{
		Certificates: []tls.Certificate{fakeCert(t, false)},
	}
	ctx, cancel := context.WithCancel(ctxbg)
	defer cancel()
	mox.StartTLSSessionTicketKeyRefresher(ctx, pkglog, &serverConfig)
	clientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	tc = startArgsMore(t, false, true, true, &serverConfig, &clientConfig, false, true, "mjl", addClientCert)
	if !tc.client.Preauth {
		t.Fatalf("not preauthentication while configured for tls public key")
	}
	cs := tc.conn.(*tls.Conn).ConnectionState()
	if cs.DidResume {
		t.Fatalf("tls connection was resumed")
	}
	tc.transactf("no", "authenticate external ") // Not allowed, already in authenticated state.
	tc.close()

	// Authentication works with TLS resumption.
	tc = startArgsMore(t, false, true, true, &serverConfig, &clientConfig, false, true, "mjl", addClientCert)
	if !tc.client.Preauth {
		t.Fatalf("not preauthentication while configured for tls public key")
	}
	cs = tc.conn.(*tls.Conn).ConnectionState()
	if !cs.DidResume {
		t.Fatalf("tls connection was not resumed")
	}
	// Check that operations that require an account work.
	tc.client.Enable(imapclient.CapIMAP4rev2)
	received, err := time.Parse(time.RFC3339, "2022-11-16T10:01:00+01:00")
	tc.check(err, "parse time")
	tc.client.Append("inbox", makeAppendTime(exampleMsg, received))
	tc.client.Select("inbox")
	tc.close()

	// Authentication with unknown key should fail.
	// todo: less duplication, change startArgs so this can be merged into it.
	err = store.Close()
	tcheck(t, err, "store close")
	os.RemoveAll("../testdata/imap/data")
	err = store.Init(ctxbg)
	tcheck(t, err, "store init")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/imap/mox.conf")
	mox.MustLoadConfig(true, false)
	switchStop := store.Switchboard()
	defer switchStop()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	defer func() { <-done }()
	connCounter++
	cid := connCounter
	go func() {
		defer serverConn.Close()
		serve("test", cid, &serverConfig, serverConn, true, false, false, "")
		close(done)
	}()

	clientConfig.ClientSessionCache = nil
	clientConn = tls.Client(clientConn, &clientConfig)
	// note: It's not enough to do a handshake and check if that was successful. If the
	// client cert is not acceptable, we only learn after the handshake, when the first
	// data messages are exchanged.
	buf := make([]byte, 100)
	_, err = clientConn.Read(buf)
	if err == nil {
		t.Fatalf("tls handshake with unknown client certificate succeeded")
	}
	if alert, ok := mox.AsTLSAlert(err); !ok || alert != 42 {
		t.Fatalf("got err %#v, expected tls 'bad certificate' alert", err)
	}
}
