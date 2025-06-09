package imapserver

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/store"
	"slices"
)

var ctxbg = context.Background()
var pkglog = mlog.New("imapserver", nil)

func init() {
	sanityChecks = true

	// Don't slow down tests.
	badClientDelay = 0
	authFailDelay = 0

	mox.Context = ctxbg
}

func ptr[T any](v T) *T {
	return &v
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
Content-Disposition: inline; filename=image.jpg


--unique-boundary-2--

--unique-boundary-1
Content-type: text/enriched

This is <bold><italic>enriched.</italic></bold>
<smaller>as defined in RFC 1896</smaller>

Isn't it
<bigger><bigger>cool?</bigger></bigger>

--unique-boundary-1
Content-Type: message/rfc822
Content-MD5: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
Content-Language: en,de
Content-Location: http://localhost

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

func mustParseUntagged(s string) imapclient.Untagged {
	r, err := imapclient.ParseUntagged(s + "\r\n")
	if err != nil {
		panic(err)
	}
	return r
}

func mustParseCode(s string) imapclient.Code {
	r, err := imapclient.ParseCode(s)
	if err != nil {
		panic(err)
	}
	return r
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
	t           *testing.T
	conn        net.Conn
	client      *imapclient.Conn
	uidonly     bool
	done        chan struct{}
	serverConn  net.Conn
	account     *store.Account
	switchStop  func()
	clientPanic bool

	// Result of last command.
	lastResponse imapclient.Response
	lastErr      error
}

func (tc *testconn) check(err error, msg string) {
	tc.t.Helper()
	if err != nil {
		tc.t.Fatalf("%s: %s", msg, err)
	}
}

func (tc *testconn) last(resp imapclient.Response, err error) {
	tc.lastResponse = resp
	tc.lastErr = err
}

func (tc *testconn) xcode(c imapclient.Code) {
	tc.t.Helper()
	if !reflect.DeepEqual(tc.lastResponse.Code, c) {
		tc.t.Fatalf("got last code %#v, expected %#v", tc.lastResponse.Code, c)
	}
}

func (tc *testconn) xcodeWord(s string) {
	tc.t.Helper()
	tc.xcode(imapclient.CodeWord(s))
}

func (tc *testconn) xuntagged(exps ...imapclient.Untagged) {
	tc.t.Helper()
	tc.xuntaggedOpt(true, exps...)
}

func (tc *testconn) xuntaggedOpt(all bool, exps ...imapclient.Untagged) {
	tc.t.Helper()
	last := slices.Clone(tc.lastResponse.Untagged)
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
		if len(tc.lastResponse.Untagged) > 0 {
			next = fmt.Sprintf(", next:\n%#v", tc.lastResponse.Untagged[0])
		}
		tc.t.Fatalf("did not find untagged response:\n%#v %T (%d)\nin %v%s", exp, exp, ei, tc.lastResponse.Untagged, next)
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
		t.Fatalf("got %#v, expected %#v", got, dstv.Elem().Interface())
	}
	dstv.Elem().Set(gotv)
}

func (tc *testconn) xnountagged() {
	tc.t.Helper()
	if len(tc.lastResponse.Untagged) != 0 {
		tc.t.Fatalf("got %v untagged, expected 0", tc.lastResponse.Untagged)
	}
}

func (tc *testconn) readuntagged(exps ...imapclient.Untagged) {
	tc.t.Helper()
	for i, exp := range exps {
		tc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		v, err := tc.client.ReadUntagged()
		tcheck(tc.t, err, "reading untagged")
		if !reflect.DeepEqual(v, exp) {
			tc.t.Fatalf("got %#v, expected %#v, response %d/%d", v, exp, i+1, len(exps))
		}
	}
}

func (tc *testconn) transactf(status, format string, args ...any) {
	tc.t.Helper()
	tc.cmdf("", format, args...)
	tc.response(status)
}

func (tc *testconn) response(status string) {
	tc.t.Helper()
	tc.lastResponse, tc.lastErr = tc.client.ReadResponse()
	if tc.lastErr != nil {
		if resp, ok := tc.lastErr.(imapclient.Response); ok {
			if !reflect.DeepEqual(resp, tc.lastResponse) {
				tc.t.Fatalf("response error %#v != returned response %#v", tc.lastErr, tc.lastResponse)
			}
		} else {
			tcheck(tc.t, tc.lastErr, "read imap response")
		}
	}
	if strings.ToUpper(status) != string(tc.lastResponse.Status) {
		tc.t.Fatalf("got status %q, expected %q", tc.lastResponse.Status, status)
	}
}

func (tc *testconn) cmdf(tag, format string, args ...any) {
	tc.t.Helper()
	err := tc.client.WriteCommandf(tag, format, args...)
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

func (tc *testconn) login(username, password string) {
	tc.client.Login(username, password)
	if tc.uidonly {
		tc.transactf("ok", "enable uidonly")
	}
}

// untaggedFetch returns an imapclient.UntaggedFetch or
// imapclient.UntaggedUIDFetch, depending on whether uidonly is enabled for the
// connection.
func (tc *testconn) untaggedFetch(seq, uid uint32, attrs ...imapclient.FetchAttr) any {
	if tc.uidonly {
		return imapclient.UntaggedUIDFetch{UID: uid, Attrs: attrs}
	}
	attrs = append([]imapclient.FetchAttr{imapclient.FetchUID(uid)}, attrs...)
	return imapclient.UntaggedFetch{Seq: seq, Attrs: attrs}
}

// like untaggedFetch, but with explicit UID fetch attribute in case of uidonly.
func (tc *testconn) untaggedFetchUID(seq, uid uint32, attrs ...imapclient.FetchAttr) any {
	attrs = append([]imapclient.FetchAttr{imapclient.FetchUID(uid)}, attrs...)
	if tc.uidonly {
		return imapclient.UntaggedUIDFetch{UID: uid, Attrs: attrs}
	}
	return imapclient.UntaggedFetch{Seq: seq, Attrs: attrs}
}

func (tc *testconn) close() {
	tc.close0(true)
}

func (tc *testconn) closeNoWait() {
	tc.close0(false)
}

func (tc *testconn) close0(waitclose bool) {
	defer func() {
		if unhandledPanics.Swap(0) > 0 {
			tc.t.Fatalf("unhandled panic in server")
		}
	}()

	if tc.account == nil {
		// Already closed, we are not strict about closing multiple times.
		return
	}
	if tc.client != nil {
		tc.clientPanic = false // Ignore errors writing to TLS connection the server also closed.
		tc.client.Close()
	}
	err := tc.account.Close()
	tc.check(err, "close account")
	if waitclose {
		tc.account.WaitClosed()
	}
	tc.account = nil
	tc.serverConn.Close()
	tc.waitDone()
	if tc.switchStop != nil {
		tc.switchStop()
	}
}

func xparseNumSet(s string) imapclient.NumSet {
	ns, err := imapclient.ParseNumSet(s)
	if err != nil {
		panic(fmt.Sprintf("parsing numset %s: %s", s, err))
	}
	return ns
}

func xparseUIDRange(s string) imapclient.NumRange {
	nr, err := imapclient.ParseUIDRange(s)
	if err != nil {
		panic(fmt.Sprintf("parsing uid range %s: %s", s, err))
	}
	return nr
}

func makeAppend(msg string) imapclient.Append {
	return imapclient.Append{Size: int64(len(msg)), Data: strings.NewReader(msg)}
}

func makeAppendTime(msg string, tm time.Time) imapclient.Append {
	return imapclient.Append{Received: &tm, Size: int64(len(msg)), Data: strings.NewReader(msg)}
}

var connCounter int64

func start(t *testing.T, uidonly bool) *testconn {
	return startArgs(t, uidonly, true, false, true, true, "mjl")
}

func startNoSwitchboard(t *testing.T, uidonly bool) *testconn {
	return startArgs(t, uidonly, false, false, true, false, "mjl")
}

const password0 = "te\u0301st \u00a0\u2002\u200a" // NFD and various unicode spaces.
const password1 = "tést    "                      // PRECIS normalized, with NFC.

func startArgs(t *testing.T, uidonly, first, immediateTLS bool, allowLoginWithoutTLS, setPassword bool, accname string) *testconn {
	return startArgsMore(t, uidonly, first, immediateTLS, nil, nil, allowLoginWithoutTLS, setPassword, accname, nil)
}

// namedConn wraps a conn so it can return a RemoteAddr with a non-empty name.
// The TLS resumption test needs a non-empty name, but on BSDs, the unix domain
// socket pair has an empty peer name.
type namedConn struct {
	net.Conn
}

func (c namedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.10"), Port: 1234}
}

// todo: the parameters and usage are too much now. change to scheme similar to smtpserver, with params in a struct, and a separate method for init and making a connection.
func startArgsMore(t *testing.T, uidonly, first, immediateTLS bool, serverConfig, clientConfig *tls.Config, allowLoginWithoutTLS, setPassword bool, accname string, afterInit func() error) *testconn {
	limitersInit() // Reset rate limiters.

	switchStop := func() {}
	if first {
		mox.ConfigStaticPath = filepath.FromSlash("../testdata/imap/mox.conf")
		mox.MustLoadConfig(true, false)
		store.Close() // May not be open, we ignore error.
		os.RemoveAll("../testdata/imap/data")
		err := store.Init(ctxbg)
		tcheck(t, err, "store init")
		switchStop = store.Switchboard()
	}

	acc, err := store.OpenAccount(pkglog, accname, false)
	tcheck(t, err, "open account")
	if setPassword {
		err = acc.SetPassword(pkglog, password0)
		tcheck(t, err, "set password")
	}
	if first {
		// Add a deleted mailbox, may excercise some code paths.
		err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			// todo: add a message to inbox and remove it again. need to change all uids in the tests.
			// todo: add tests for operating on an expunged mailbox. it should say it doesn't exist.

			mb, _, _, _, err := acc.MailboxCreate(tx, "expungebox", store.SpecialUse{})
			if err != nil {
				return fmt.Errorf("create mailbox: %v", err)
			}
			if _, _, err := acc.MailboxDelete(ctxbg, pkglog, tx, &mb); err != nil {
				return fmt.Errorf("delete mailbox: %v", err)
			}
			return nil
		})
		tcheck(t, err, "add expunged mailbox")
	}

	if afterInit != nil {
		err := afterInit()
		tcheck(t, err, "after init")
	}

	// We get actual sockets for their buffering behaviour. net.Pipe is synchronous,
	// and the implementation of the compress extension can write a sync message to an
	// imap client when that client isn't reading but is trying to write. In the real
	// world, network buffer will take up those few bytes, so assume the buffer in the
	// test too.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	tcheck(t, err, "socketpair")
	xfdconn := func(fd int, name string) net.Conn {
		f := os.NewFile(uintptr(fd), name)
		fc, err := net.FileConn(f)
		tcheck(t, err, "fileconn")
		err = f.Close()
		tcheck(t, err, "close file for conn")

		// Small read/write buffers, for detecting closed/broken connections quickly.
		uc := fc.(*net.UnixConn)
		err = uc.SetReadBuffer(512)
		tcheck(t, err, "set read buffer")
		uc.SetWriteBuffer(512)
		tcheck(t, err, "set write buffer")

		return namedConn{uc}
	}
	serverConn := xfdconn(fds[0], "server")
	clientConn := xfdconn(fds[1], "client")

	if serverConfig == nil {
		serverConfig = &tls.Config{
			Certificates: []tls.Certificate{fakeCert(t, false)},
		}
	}
	if immediateTLS {
		if clientConfig == nil {
			clientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		clientConn = tls.Client(clientConn, clientConfig)
	}

	done := make(chan struct{})
	connCounter += 2
	cid := connCounter - 1
	go func() {
		const viaHTTPS = false
		serve("test", cid, serverConfig, serverConn, immediateTLS, false, allowLoginWithoutTLS, viaHTTPS, "")
		close(done)
	}()
	var tc *testconn
	var opts imapclient.Opts
	opts = imapclient.Opts{
		Logger: slog.Default().With("cid", connCounter),
		Error: func(err error) {
			if tc.clientPanic {
				panic(err)
			} else {
				opts.Logger.Error("imapclient error", "err", err)
			}
		},
	}
	client, _ := imapclient.New(clientConn, &opts)
	tc = &testconn{t: t, conn: clientConn, client: client, uidonly: uidonly, done: done, serverConn: serverConn, account: acc, clientPanic: true}
	if first {
		tc.switchStop = switchStop
	}
	return tc
}

func fakeCert(t *testing.T, randomkey bool) tls.Certificate {
	seed := make([]byte, ed25519.SeedSize)
	if randomkey {
		cryptorand.Read(seed)
	}
	privKey := ed25519.NewKeyFromSeed(seed) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
		// Valid period is needed to get session resumption enabled.
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
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
	tc := start(t, false)
	defer tc.close()

	tc.transactf("bad", "login too many args")
	tc.transactf("bad", "login") // no args
	tc.transactf("no", "login mjl@mox.example badpass")
	tc.transactf("no", `login mjl "%s"`, password0) // must use email, not account
	tc.transactf("no", "login mjl@mox.example test")
	tc.transactf("no", "login mjl@mox.example testtesttest")
	tc.transactf("no", `login "mjl@mox.example" "testtesttest"`)
	tc.transactf("no", "login \"m\xf8x@mox.example\" \"testtesttest\"")
	tc.transactf("ok", `login mjl@mox.example "%s"`, password0)
	tc.close()

	tc = start(t, false)
	tc.transactf("ok", `login "mjl@mox.example" "%s"`, password0)
	tc.close()

	tc = start(t, false)
	tc.transactf("ok", `login "\"\"@mox.example" "%s"`, password0)
	defer tc.close()

	tc.transactf("bad", "logout badarg")
	tc.transactf("ok", "logout")
}

// Test that commands don't work in the states they are not supposed to.
func TestState(t *testing.T) {
	tc := start(t, false)

	notAuthenticated := []string{"starttls", "authenticate", "login"}
	authenticatedOrSelected := []string{"enable", "select", "examine", "create", "delete", "rename", "subscribe", "unsubscribe", "list", "namespace", "status", "append", "idle", "lsub"}
	selected := []string{"close", "unselect", "expunge", "search", "fetch", "store", "copy", "move", "uid expunge"}

	// Always allowed.
	tc.transactf("ok", "capability")
	tc.transactf("ok", "noop")
	tc.transactf("ok", "logout")
	tc.close()
	tc = start(t, false)
	defer tc.close()

	// Not authenticated, lots of commands not allowed.
	for _, cmd := range slices.Concat(authenticatedOrSelected, selected) {
		tc.transactf("no", "%s", cmd)
	}

	// Some commands not allowed when authenticated.
	tc.transactf("ok", `login mjl@mox.example "%s"`, password0)
	for _, cmd := range slices.Concat(notAuthenticated, selected) {
		tc.transactf("no", "%s", cmd)
	}

	tc.transactf("bad", "boguscommand")
}

func TestNonIMAP(t *testing.T) {
	tc := start(t, false)
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
	tc := start(t, false)
	defer tc.close()

	tc.login("mjl@mox.example", password0)
	tc.client.Create("tmpbox", nil)

	tc.transactf("ok", "rename {6+}\r\ntmpbox {7+}\r\nntmpbox")

	from := "ntmpbox"
	to := "tmpbox"
	tc.client.LastTagSet("xtag")
	fmt.Fprint(tc.client, "xtag rename ")
	tc.client.WriteSyncLiteral(from)
	fmt.Fprint(tc.client, " ")
	tc.client.WriteSyncLiteral(to)
	fmt.Fprint(tc.client, "\r\n")
	tc.lastResponse, tc.lastErr = tc.client.ReadResponse()
	if tc.lastResponse.Status != "OK" {
		tc.t.Fatalf(`got %q, expected "OK"`, tc.lastResponse.Status)
	}
}

// Test longer scenario with login, lists, subscribes, status, selects, etc.
func TestScenario(t *testing.T) {
	testScenario(t, false)
}

func TestScenarioUIDOnly(t *testing.T) {
	testScenario(t, true)
}

func testScenario(t *testing.T, uidonly bool) {
	tc := start(t, uidonly)
	defer tc.close()
	tc.login("mjl@mox.example", password0)

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

	tc.transactf("ok", "uid fetch 1 all")
	tc.transactf("ok", "uid fetch 1 body")
	tc.transactf("ok", "uid fetch 1 binary[]")

	tc.transactf("ok", `uid store 1 flags (\seen \answered)`)
	tc.transactf("ok", `uid store 1 +flags ($junk)`) // should train as junk.
	tc.transactf("ok", `uid store 1 -flags ($junk)`) // should retrain as non-junk.
	tc.transactf("ok", `uid store 1 -flags (\seen)`) // should untrain completely.
	tc.transactf("ok", `uid store 1 -flags (\answered)`)
	tc.transactf("ok", `uid store 1 +flags (\answered)`)
	tc.transactf("ok", `uid store 1 flags.silent (\seen \answered)`)
	tc.transactf("ok", `uid store 1 -flags.silent (\answered)`)
	tc.transactf("ok", `uid store 1 +flags.silent (\answered)`)
	tc.transactf("bad", `uid store 1 flags (\badflag)`)
	tc.transactf("ok", "noop")

	tc.transactf("ok", "uid copy 1 Trash")
	tc.transactf("ok", "uid copy 1 Trash")
	tc.transactf("ok", "uid move 1 Trash")

	tc.transactf("ok", "close")
	tc.transactf("ok", "select Trash")
	tc.transactf("ok", `uid store 1 flags (\deleted)`)
	tc.transactf("ok", "expunge")
	tc.transactf("ok", "noop")

	tc.transactf("ok", `uid store 1 flags (\deleted)`)
	tc.transactf("ok", "close")
	tc.transactf("ok", "delete Trash")

	if uidonly {
		return
	}

	tc.transactf("ok", "create Trash")
	tc.transactf("ok", "append inbox (\\seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	tc.transactf("ok", "select inbox")

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
	tc := start(t, false)
	defer tc.close()
	tc.login("mjl@mox.example", password0)

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
	tc := start(t, false)
	defer tc.close()

	tc2 := startNoSwitchboard(t, false)
	defer tc2.closeNoWait()

	tc.login("mjl@mox.example", password0)
	tc2.login("mjl@mox.example", password0)

	tc.client.Create("testbox", nil)
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
	tc2.transactf("no", "copy 1 inbox")
	tc2.transactf("no", "uid copy 1 inbox")
	tc2.transactf("no", "move 1 inbox")
	tc2.transactf("no", "uid move 1 inbox")

	tc2.transactf("ok", "unselect")

	tc.client.Create("testbox", nil)
	tc2.client.Select("testbox")
	tc.client.Delete("testbox")
	tc2.transactf("ok", "close")
}

func TestID(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	tc.login("mjl@mox.example", password0)

	tc.transactf("ok", "id nil")
	tc.xuntagged(imapclient.UntaggedID{"name": "mox", "version": moxvar.Version})

	tc.transactf("ok", `id ("name" "mox" "version" "1.2.3" "other" "test" "test" nil)`)
	tc.xuntagged(imapclient.UntaggedID{"name": "mox", "version": moxvar.Version})

	tc.transactf("bad", `id ("name" "mox" "name" "mox")`) // Duplicate field.
}

func TestSequence(t *testing.T) {
	testSequence(t, false)
}

func TestSequenceUIDOnly(t *testing.T) {
	testSequence(t, true)
}

func testSequence(t *testing.T, uidonly bool) {
	tc := start(t, uidonly)
	defer tc.close()
	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	tc.transactf("bad", "fetch * all") // ../rfc/9051:7018
	tc.transactf("bad", "fetch 1:* all")
	tc.transactf("bad", "fetch 1:2 all")
	tc.transactf("bad", "fetch 1 all") // ../rfc/9051:7018

	tc.transactf("ok", "uid fetch 1 all") // non-existing messages are OK for uids.
	tc.transactf("ok", "uid fetch * all") // * is like uidnext, a non-existing message.

	tc.transactf("ok", "uid search return (save) all") // Empty result.
	tc.transactf("ok", "uid fetch $ uid")
	tc.xuntagged()

	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	if !uidonly {
		tc.transactf("ok", "fetch 2:1,1 uid") // We reorder 2:1 to 1:2, and we deduplicate numbers.
		tc.xuntagged(
			tc.untaggedFetch(1, 1),
			tc.untaggedFetch(2, 2),
		)

		tc.transactf("bad", "fetch 1:3 all")
	}

	tc.transactf("ok", "uid fetch * flags")
	tc.xuntagged(tc.untaggedFetch(2, 2, imapclient.FetchFlags(nil)))

	tc.transactf("ok", "uid fetch 3:* flags") // Because * is the last message, which is 2, the range becomes 3:2, which matches the last message.
	tc.xuntagged(tc.untaggedFetch(2, 2, imapclient.FetchFlags(nil)))

	tc.transactf("ok", "uid fetch *:3 flags")
	tc.xuntagged(tc.untaggedFetch(2, 2, imapclient.FetchFlags(nil)))

	tc.transactf("ok", "uid search return (save) all") // Empty result.
	tc.transactf("ok", "uid fetch $ flags")
	tc.xuntagged(
		tc.untaggedFetch(1, 1, imapclient.FetchFlags(nil)),
		tc.untaggedFetch(2, 2, imapclient.FetchFlags(nil)),
	)
}

// Test that a message that is expunged by another session can be read as long as a
// reference is held by a session. New sessions do not see the expunged message.
func TestReference(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")
	tc.client.Append("inbox", makeAppend(exampleMsg))

	tc2 := startNoSwitchboard(t, false)
	defer tc2.closeNoWait()
	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	tc.client.MSNStoreFlagsSet("1", true, `\Deleted`)
	tc.client.Expunge()

	tc3 := startNoSwitchboard(t, false)
	defer tc3.closeNoWait()
	tc3.login("mjl@mox.example", password0)
	tc3.transactf("ok", `list "" "inbox" return (status (messages))`)
	tc3.xuntagged(
		mustParseUntagged(`* LIST () "/" Inbox`),
		imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 0}},
	)

	tc2.transactf("ok", "fetch 1 rfc822.size")
	tc2.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchRFC822Size(len(exampleMsg))))
}
