package imapserver

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/store"
)

var ctxbg = context.Background()

func init() {
	sanityChecks = true

	// Don't slow down tests.
	badClientDelay = 0
	authFailDelay = 0
}

func tocrlf(s string) string {
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// From ../rfc/3501:2589
var exampleMsg = tocrlf(`Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)
From: Fred Foobar <foobar@Blurdybloop.example>
Subject: afternoon meeting
To: mooch@owatagu.siam.edu.example
Message-Id: <B27397-0100000@Blurdybloop.example>
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; CHARSET=US-ASCII

Hello Joe, do you think we can meet at 3:30 tomorrow?

`)

/*
From ../rfc/2049:801

Message structure:

Message - multipart/mixed
Part 1 - no content-type
Part 2 - text/plain
Part 3 - multipart/parallel
Part 3.1 - audio/basic (base64)
Part 3.2 - image/jpeg (base64, empty)
Part 4 - text/enriched
Part 5 - message/rfc822
Part 5.1 - text/plain (quoted-printable)
*/
var nestedMessage = tocrlf(`MIME-Version: 1.0
From: Nathaniel Borenstein <nsb@nsb.fv.com>
To: Ned Freed <ned@innosoft.com>
Date: Fri, 07 Oct 1994 16:15:05 -0700 (PDT)
Subject: A multipart example
Content-Type: multipart/mixed;
              boundary=unique-boundary-1

This is the preamble area of a multipart message.
Mail readers that understand multipart format
should ignore this preamble.

If you are reading this text, you might want to
consider changing to a mail reader that understands
how to properly display multipart messages.

--unique-boundary-1

  ... Some text appears here ...

[Note that the blank between the boundary and the start
 of the text in this part means no header fields were
 given and this is text in the US-ASCII character set.
 It could have been done with explicit typing as in the
 next part.]

--unique-boundary-1
Content-type: text/plain; charset=US-ASCII

This could have been part of the previous part, but
illustrates explicit versus implicit typing of body
parts.

--unique-boundary-1
Content-Type: multipart/parallel; boundary=unique-boundary-2

--unique-boundary-2
Content-Type: audio/basic
Content-Transfer-Encoding: base64

aGVsbG8NCndvcmxkDQo=

--unique-boundary-2
Content-Type: image/jpeg
Content-Transfer-Encoding: base64


--unique-boundary-2--

--unique-boundary-1
Content-type: text/enriched

This is <bold><italic>enriched.</italic></bold>
<smaller>as defined in RFC 1896</smaller>

Isn't it
<bigger><bigger>cool?</bigger></bigger>

--unique-boundary-1
Content-Type: message/rfc822

From: info@mox.example
To: mox <info@mox.example>
Subject: (subject in US-ASCII)
Content-Type: Text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: Quoted-printable

  ... Additional text in ISO-8859-1 goes here ...

--unique-boundary-1--
`)

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func mockUIDValidity() func() {
	orig := store.InitialUIDValidity
	store.InitialUIDValidity = func() uint32 {
		return 1
	}
	return func() {
		store.InitialUIDValidity = orig
	}
}

type testconn struct {
	t          *testing.T
	conn       net.Conn
	client     *imapclient.Conn
	done       chan struct{}
	serverConn net.Conn
	account    *store.Account

	// Result of last command.
	lastUntagged []imapclient.Untagged
	lastResult   imapclient.Result
	lastErr      error
}

func (tc *testconn) check(err error, msg string) {
	tc.t.Helper()
	if err != nil {
		tc.t.Fatalf("%s: %s", msg, err)
	}
}

func (tc *testconn) last(l []imapclient.Untagged, r imapclient.Result, err error) {
	tc.lastUntagged = l
	tc.lastResult = r
	tc.lastErr = err
}

func (tc *testconn) xcode(s string) {
	tc.t.Helper()
	if tc.lastResult.Code != s {
		tc.t.Fatalf("got last code %q, expected %q", tc.lastResult.Code, s)
	}
}

func (tc *testconn) xcodeArg(v any) {
	tc.t.Helper()
	if !reflect.DeepEqual(tc.lastResult.CodeArg, v) {
		tc.t.Fatalf("got last code argument %v, expected %v", tc.lastResult.CodeArg, v)
	}
}

func (tc *testconn) xuntagged(exps ...imapclient.Untagged) {
	tc.t.Helper()
	tc.xuntaggedOpt(true, exps...)
}

func (tc *testconn) xuntaggedOpt(all bool, exps ...imapclient.Untagged) {
	tc.t.Helper()
	last := append([]imapclient.Untagged{}, tc.lastUntagged...)
	var mismatch any
next:
	for ei, exp := range exps {
		for i, l := range last {
			if reflect.TypeOf(l) != reflect.TypeOf(exp) {
				continue
			}
			if !reflect.DeepEqual(l, exp) {
				mismatch = l
				continue
			}
			copy(last[i:], last[i+1:])
			last = last[:len(last)-1]
			continue next
		}
		if mismatch != nil {
			tc.t.Fatalf("untagged data mismatch, got:\n\t%T %#v\nexpected:\n\t%T %#v", mismatch, mismatch, exp, exp)
		}
		var next string
		if len(tc.lastUntagged) > 0 {
			next = fmt.Sprintf(", next %#v", tc.lastUntagged[0])
		}
		tc.t.Fatalf("did not find untagged response %#v %T (%d) in %v%s", exp, exp, ei, tc.lastUntagged, next)
	}
	if len(last) > 0 && all {
		tc.t.Fatalf("leftover untagged responses %v", last)
	}
}

func tuntagged(t *testing.T, got imapclient.Untagged, dst any) {
	t.Helper()
	gotv := reflect.ValueOf(got)
	dstv := reflect.ValueOf(dst)
	if gotv.Type() != dstv.Type().Elem() {
		t.Fatalf("got %v, expected %v", gotv.Type(), dstv.Type().Elem())
	}
	dstv.Elem().Set(gotv)
}

func (tc *testconn) xnountagged() {
	tc.t.Helper()
	if len(tc.lastUntagged) != 0 {
		tc.t.Fatalf("got %v untagged, expected 0", tc.lastUntagged)
	}
}

func (tc *testconn) transactf(status, format string, args ...any) {
	tc.t.Helper()
	tc.cmdf("", format, args...)
	tc.response(status)
}

func (tc *testconn) response(status string) {
	tc.t.Helper()
	tc.lastUntagged, tc.lastResult, tc.lastErr = tc.client.Response()
	tcheck(tc.t, tc.lastErr, "read imap response")
	if strings.ToUpper(status) != string(tc.lastResult.Status) {
		tc.t.Fatalf("got status %q, expected %q", tc.lastResult.Status, status)
	}
}

func (tc *testconn) cmdf(tag, format string, args ...any) {
	tc.t.Helper()
	err := tc.client.Commandf(tag, format, args...)
	tcheck(tc.t, err, "writing imap command")
}

func (tc *testconn) readstatus(status string) {
	tc.t.Helper()
	tc.response(status)
}

func (tc *testconn) readprefixline(pre string) {
	tc.t.Helper()
	line, err := tc.client.Readline()
	tcheck(tc.t, err, "read line")
	if !strings.HasPrefix(line, pre) {
		tc.t.Fatalf("expected prefix %q, got %q", pre, line)
	}
}

func (tc *testconn) writelinef(format string, args ...any) {
	tc.t.Helper()
	err := tc.client.Writelinef(format, args...)
	tcheck(tc.t, err, "write line")
}

// wait at most 1 second for server to quit.
func (tc *testconn) waitDone() {
	tc.t.Helper()
	t := time.NewTimer(time.Second)
	select {
	case <-tc.done:
		t.Stop()
	case <-t.C:
		tc.t.Fatalf("server not done within 1s")
	}
}

func (tc *testconn) close() {
	if tc.account == nil {
		// Already closed, we are not strict about closing multiple times.
		return
	}
	err := tc.account.Close()
	tc.check(err, "close account")
	tc.account = nil
	tc.client.Close()
	tc.serverConn.Close()
	tc.waitDone()
}

func xparseNumSet(s string) imapclient.NumSet {
	ns, err := imapclient.ParseNumSet(s)
	if err != nil {
		panic(fmt.Sprintf("parsing numset %s: %s", s, err))
	}
	return ns
}

var connCounter int64

func start(t *testing.T) *testconn {
	return startArgs(t, true, false, true)
}

func startNoSwitchboard(t *testing.T) *testconn {
	return startArgs(t, false, false, true)
}

func startArgs(t *testing.T, first, isTLS, allowLoginWithoutTLS bool) *testconn {
	limitersInit() // Reset rate limiters.

	if first {
		os.RemoveAll("../testdata/imap/data")
	}
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/imap/mox.conf")
	mox.MustLoadConfig(true, false)
	acc, err := store.OpenAccount("mjl")
	tcheck(t, err, "open account")
	if first {
		err = acc.SetPassword("testtest")
		tcheck(t, err, "set password")
	}
	switchStop := func() {}
	if first {
		switchStop = store.Switchboard()
	}

	serverConn, clientConn := net.Pipe()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{fakeCert(t)},
	}
	if isTLS {
		serverConn = tls.Server(serverConn, tlsConfig)
		clientConn = tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
	}

	done := make(chan struct{})
	connCounter++
	cid := connCounter
	go func() {
		serve("test", cid, tlsConfig, serverConn, isTLS, allowLoginWithoutTLS)
		switchStop()
		close(done)
	}()
	client, err := imapclient.New(clientConn, true)
	tcheck(t, err, "new client")
	return &testconn{t: t, conn: clientConn, client: client, done: done, serverConn: serverConn, account: acc}
}

func fakeCert(t *testing.T) tls.Certificate {
	privKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
	}
	localCertBuf, err := x509.CreateCertificate(cryptorand.Reader, template, template, privKey.Public(), privKey)
	if err != nil {
		t.Fatalf("making certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(localCertBuf)
	if err != nil {
		t.Fatalf("parsing generated certificate: %s", err)
	}
	c := tls.Certificate{
		Certificate: [][]byte{localCertBuf},
		PrivateKey:  privKey,
		Leaf:        cert,
	}
	return c
}

func TestLogin(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.transactf("bad", "login too many args")
	tc.transactf("bad", "login") // no args
	tc.transactf("no", "login mjl@mox.example badpass")
	tc.transactf("no", "login mjl testtest") // must use email, not account
	tc.transactf("no", "login mjl@mox.example test")
	tc.transactf("no", "login mjl@mox.example testtesttest")
	tc.transactf("no", `login "mjl@mox.example" "testtesttest"`)
	tc.transactf("no", "login \"m\xf8x@mox.example\" \"testtesttest\"")
	tc.transactf("ok", "login mjl@mox.example testtest")
	tc.close()

	tc = start(t)
	tc.transactf("ok", `login "mjl@mox.example" "testtest"`)
	tc.close()

	tc = start(t)
	tc.transactf("ok", `login "\"\"@mox.example" "testtest"`)
	defer tc.close()

	tc.transactf("bad", "logout badarg")
	tc.transactf("ok", "logout")
}

// Test that commands don't work in the states they are not supposed to.
func TestState(t *testing.T) {
	tc := start(t)

	notAuthenticated := []string{"starttls", "authenticate", "login"}
	authenticatedOrSelected := []string{"enable", "select", "examine", "create", "delete", "rename", "subscribe", "unsubscribe", "list", "namespace", "status", "append", "idle", "lsub"}
	selected := []string{"close", "unselect", "expunge", "search", "fetch", "store", "copy", "move", "uid expunge"}

	// Always allowed.
	tc.transactf("ok", "capability")
	tc.transactf("ok", "noop")
	tc.transactf("ok", "logout")
	tc.close()
	tc = start(t)
	defer tc.close()

	// Not authenticated, lots of commands not allowed.
	for _, cmd := range append(append([]string{}, authenticatedOrSelected...), selected...) {
		tc.transactf("no", "%s", cmd)
	}

	// Some commands not allowed when authenticated.
	tc.transactf("ok", "login mjl@mox.example testtest")
	for _, cmd := range append(append([]string{}, notAuthenticated...), selected...) {
		tc.transactf("no", "%s", cmd)
	}

	tc.transactf("bad", "boguscommand")
}

func TestNonIMAP(t *testing.T) {
	tc := start(t)
	defer tc.close()

	// imap greeting has already been read, we sidestep the imapclient.
	_, err := fmt.Fprintf(tc.conn, "bogus\r\n")
	tc.check(err, "write bogus command")
	tc.readprefixline("* BYE ")
	if _, err := tc.conn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("connection not closed after initial bad command")
	}
}

func TestLiterals(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", "testtest")
	tc.client.Create("tmpbox")

	tc.transactf("ok", "rename {6+}\r\ntmpbox {7+}\r\nntmpbox")

	from := "ntmpbox"
	to := "tmpbox"
	fmt.Fprint(tc.client, "xtag rename ")
	tc.client.WriteSyncLiteral(from)
	fmt.Fprint(tc.client, " ")
	tc.client.WriteSyncLiteral(to)
	fmt.Fprint(tc.client, "\r\n")
	tc.client.LastTag = "xtag"
	tc.last(tc.client.Response())
	if tc.lastResult.Status != "OK" {
		tc.t.Fatalf(`got %q, expected "OK"`, tc.lastResult.Status)
	}
}

// Test longer scenario with login, lists, subscribes, status, selects, etc.
func TestScenario(t *testing.T) {
	tc := start(t)
	defer tc.close()
	tc.transactf("ok", "login mjl@mox.example testtest")

	tc.transactf("bad", " missingcommand")

	tc.transactf("ok", "examine inbox")
	tc.transactf("ok", "unselect")

	tc.transactf("ok", "examine inbox")
	tc.transactf("ok", "close")

	tc.transactf("ok", "select inbox")
	tc.transactf("ok", "close")

	tc.transactf("ok", "select inbox")
	tc.transactf("ok", "expunge")
	tc.transactf("ok", "check")

	tc.transactf("ok", "subscribe inbox")
	tc.transactf("ok", "unsubscribe inbox")
	tc.transactf("ok", "subscribe inbox")

	tc.transactf("ok", `lsub "" "*"`)

	tc.transactf("ok", `list "" ""`)
	tc.transactf("ok", `namespace`)

	tc.transactf("ok", "enable utf8=accept")
	tc.transactf("ok", "enable imap4rev2 utf8=accept")

	tc.transactf("no", "create inbox")
	tc.transactf("ok", "create tmpbox")
	tc.transactf("ok", "rename tmpbox ntmpbox")
	tc.transactf("ok", "delete ntmpbox")

	tc.transactf("ok", "status inbox (uidnext messages uidvalidity deleted size unseen recent)")

	tc.transactf("ok", "append inbox (\\seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	tc.transactf("no", "append bogus () {%d}", len(exampleMsg))
	tc.cmdf("", "append inbox () {%d}", len(exampleMsg))
	tc.readprefixline("+ ")
	_, err := tc.conn.Write([]byte(exampleMsg + "\r\n"))
	tc.check(err, "write message")
	tc.response("ok")

	tc.transactf("ok", "fetch 1 all")
	tc.transactf("ok", "fetch 1 body")
	tc.transactf("ok", "fetch 1 binary[]")

	tc.transactf("ok", `store 1 flags (\seen \answered)`)
	tc.transactf("ok", `store 1 +flags ($junk)`) // should train as junk.
	tc.transactf("ok", `store 1 -flags ($junk)`) // should retrain as non-junk.
	tc.transactf("ok", `store 1 -flags (\seen)`) // should untrain completely.
	tc.transactf("ok", `store 1 -flags (\answered)`)
	tc.transactf("ok", `store 1 +flags (\answered)`)
	tc.transactf("ok", `store 1 flags.silent (\seen \answered)`)
	tc.transactf("ok", `store 1 -flags.silent (\answered)`)
	tc.transactf("ok", `store 1 +flags.silent (\answered)`)
	tc.transactf("bad", `store 1 flags (\badflag)`)
	tc.transactf("ok", "noop")

	tc.transactf("ok", "copy 1 Trash")
	tc.transactf("ok", "copy 1 Trash")
	tc.transactf("ok", "move 1 Trash")

	tc.transactf("ok", "close")
	tc.transactf("ok", "select Trash")
	tc.transactf("ok", `store 1 flags (\deleted)`)
	tc.transactf("ok", "expunge")
	tc.transactf("ok", "noop")

	tc.transactf("ok", `store 1 flags (\deleted)`)
	tc.transactf("ok", "close")
	tc.transactf("ok", "delete Trash")
}

func TestMailbox(t *testing.T) {
	tc := start(t)
	defer tc.close()
	tc.client.Login("mjl@mox.example", "testtest")

	invalid := []string{
		"e\u0301", // é but as e + acute, not unicode-normalized
		"/leadingslash",
		"a//b",
		"Inbox/",
		"\x01",
		" ",
		"\x7f",
		"\x80",
		"\u2028",
		"\u2029",
	}
	for _, bad := range invalid {
		tc.transactf("no", "select {%d+}\r\n%s", len(bad), bad)
	}
}

func TestMailboxDeleted(t *testing.T) {
	tc := start(t)
	defer tc.close()
	tc.client.Login("mjl@mox.example", "testtest")

	tc2 := startNoSwitchboard(t)
	defer tc2.close()
	tc2.client.Login("mjl@mox.example", "testtest")

	tc.client.Create("testbox")
	tc2.client.Select("testbox")
	tc.client.Delete("testbox")

	// Now try to operate on testbox while it has been removed.
	tc2.transactf("no", "check")
	tc2.transactf("no", "expunge")
	tc2.transactf("no", "uid expunge 1")
	tc2.transactf("no", "search all")
	tc2.transactf("no", "uid search all")
	tc2.transactf("no", "fetch 1:* all")
	tc2.transactf("no", "uid fetch 1 all")
	tc2.transactf("no", "store 1 flags ()")
	tc2.transactf("no", "uid store 1 flags ()")
	tc2.transactf("bad", "copy 1 inbox") // msgseq 1 not available.
	tc2.transactf("no", "uid copy 1 inbox")
	tc2.transactf("bad", "move 1 inbox") // msgseq 1 not available.
	tc2.transactf("no", "uid move 1 inbox")

	tc2.transactf("ok", "unselect")

	tc.client.Create("testbox")
	tc2.client.Select("testbox")
	tc.client.Delete("testbox")
	tc2.transactf("ok", "close")
}

func TestID(t *testing.T) {
	tc := start(t)
	defer tc.close()
	tc.client.Login("mjl@mox.example", "testtest")

	tc.transactf("ok", "id nil")
	tc.xuntagged(imapclient.UntaggedID{"name": "mox", "version": moxvar.Version})

	tc.transactf("ok", `id ("name" "mox" "version" "1.2.3" "other" "test" "test" nil)`)
	tc.xuntagged(imapclient.UntaggedID{"name": "mox", "version": moxvar.Version})

	tc.transactf("bad", `id ("name" "mox" "name" "mox")`) // Duplicate field.
}

func TestSequence(t *testing.T) {
	tc := start(t)
	defer tc.close()
	tc.client.Login("mjl@mox.example", "testtest")
	tc.client.Select("inbox")

	tc.transactf("bad", "fetch * all") // ../rfc/9051:7018
	tc.transactf("bad", "fetch 1 all") // ../rfc/9051:7018

	tc.transactf("ok", "uid fetch 1 all") // non-existing messages are OK for uids.
	tc.transactf("ok", "uid fetch * all") // * is like uidnext, a non-existing message.

	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.transactf("ok", "fetch 2:1,1 uid") // We reorder 2:1 to 1:2, but we don't deduplicate numbers.
	tc.xuntagged(
		imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(1)}},
		imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(2)}},
		imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(1)}},
	)

	tc.transactf("ok", "uid fetch 3:* uid") // Because * is the last message, which is 2, the range becomes 3:2, which matches the last message.
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(2)}})
}

// Test that a message that is expunged by another session can be read as long as a
// reference is held by a session. New sessions do not see the expunged message.
// todo: possibly implement the additional reference counting. so far it hasn't been worth the trouble.
func DisabledTestReference(t *testing.T) {
	tc := start(t)
	defer tc.close()
	tc.client.Login("mjl@mox.example", "testtest")
	tc.client.Select("inbox")
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))

	tc2 := startNoSwitchboard(t)
	defer tc2.close()
	tc2.client.Login("mjl@mox.example", "testtest")
	tc2.client.Select("inbox")

	tc.client.StoreFlagsSet("1", true, `\Deleted`)
	tc.client.Expunge()

	tc3 := startNoSwitchboard(t)
	defer tc3.close()
	tc3.client.Login("mjl@mox.example", "testtest")
	tc3.transactf("ok", `list "" "inbox" return (status (messages))`)
	tc3.xuntagged(imapclient.UntaggedList{Separator: '/', Mailbox: "Inbox"}, imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[string]int64{"MESSAGES": 0}})

	tc2.transactf("ok", "fetch 1 rfc822.size")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{imapclient.FetchRFC822Size(len(exampleMsg))}})
}
