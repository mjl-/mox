package webmail

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/store"
)

var ctxbg = context.Background()

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func tcompare(t *testing.T, got, exp any) {
	t.Helper()
	if !reflect.DeepEqual(got, exp) {
		t.Fatalf("got %v, expected %v", got, exp)
	}
}

type Message struct {
	From, To, Cc, Bcc, Subject, MessageID string
	Headers                               [][2]string
	Date                                  time.Time
	References                            string
	Part                                  Part
}

type Part struct {
	Type             string
	ID               string
	Disposition      string
	TransferEncoding string

	Content string
	Parts   []Part

	boundary string
}

func (m Message) Marshal(t *testing.T) []byte {
	if m.Date.IsZero() {
		m.Date = time.Now()
	}
	if m.MessageID == "" {
		m.MessageID = "<" + mox.MessageIDGen(false) + ">"
	}

	var b bytes.Buffer
	header := func(k, v string) {
		if v == "" {
			return
		}
		_, err := fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		tcheck(t, err, "write header")
	}

	header("From", m.From)
	header("To", m.To)
	header("Cc", m.Cc)
	header("Bcc", m.Bcc)
	header("Subject", m.Subject)
	header("Message-Id", m.MessageID)
	header("Date", m.Date.Format(message.RFC5322Z))
	header("References", m.References)
	for _, t := range m.Headers {
		header(t[0], t[1])
	}
	header("Mime-Version", "1.0")
	if len(m.Part.Parts) > 0 {
		m.Part.boundary = multipart.NewWriter(io.Discard).Boundary()
	}
	m.Part.WriteHeader(t, &b)
	m.Part.WriteBody(t, &b)
	return b.Bytes()
}

func (p Part) Header() textproto.MIMEHeader {
	h := textproto.MIMEHeader{}
	add := func(k, v string) {
		if v != "" {
			h.Add(k, v)
		}
	}
	ct := p.Type
	if p.boundary != "" {
		ct += fmt.Sprintf(`; boundary="%s"`, p.boundary)
	}
	add("Content-Type", ct)
	add("Content-Id", p.ID)
	add("Content-Disposition", p.Disposition)
	add("Content-Transfer-Encoding", p.TransferEncoding) // todo: ensure if not multipart? probably ensure before calling headre
	return h
}

func (p Part) WriteHeader(t *testing.T, w io.Writer) {
	for k, vl := range p.Header() {
		for _, v := range vl {
			_, err := fmt.Fprintf(w, "%s: %s\r\n", k, v)
			tcheck(t, err, "write header")
		}
	}
	_, err := fmt.Fprint(w, "\r\n")
	tcheck(t, err, "write line")
}

func (p Part) WriteBody(t *testing.T, w io.Writer) {
	if len(p.Parts) == 0 {
		switch p.TransferEncoding {
		case "base64":
			bw := moxio.Base64Writer(w)
			_, err := bw.Write([]byte(p.Content))
			tcheck(t, err, "writing base64")
			err = bw.Close()
			tcheck(t, err, "closing base64 part")
		case "":
			if p.Content == "" {
				t.Fatalf("cannot write empty part")
			}
			if !strings.HasSuffix(p.Content, "\n") {
				p.Content += "\n"
			}
			p.Content = strings.ReplaceAll(p.Content, "\n", "\r\n")
			_, err := w.Write([]byte(p.Content))
			tcheck(t, err, "write content")
		default:
			t.Fatalf("unknown transfer-encoding %q", p.TransferEncoding)
		}
		return
	}

	mp := multipart.NewWriter(w)
	mp.SetBoundary(p.boundary)
	for _, sp := range p.Parts {
		if len(sp.Parts) > 0 {
			sp.boundary = multipart.NewWriter(io.Discard).Boundary()
		}
		pw, err := mp.CreatePart(sp.Header())
		tcheck(t, err, "create part")
		sp.WriteBody(t, pw)
	}
	err := mp.Close()
	tcheck(t, err, "close multipart")
}

var (
	msgMinimal = Message{
		Part: Part{Type: "text/plain", Content: "the body"},
	}
	msgText = Message{
		From:    "mjl <mjl@mox.example>",
		To:      "mox <mox@other.example>",
		Subject: "text message",
		Part:    Part{Type: "text/plain; charset=utf-8", Content: "the body"},
	}
	msgHTML = Message{
		From:    "mjl <mjl@mox.example>",
		To:      "mox <mox@other.example>",
		Subject: "html message",
		Part:    Part{Type: "text/html", Content: `<html>the body <img src="cid:img1@mox.example" /></html>`},
	}
	msgAlt = Message{
		From:      "mjl <mjl@mox.example>",
		To:        "mox <mox@other.example>",
		Subject:   "test",
		MessageID: "<alt@localhost>",
		Headers:   [][2]string{{"In-Reply-To", "<previous@host.example>"}},
		Part: Part{
			Type: "multipart/alternative",
			Parts: []Part{
				{Type: "text/plain", Content: "the body"},
				{Type: "text/html; charset=utf-8", Content: `<html>the body <img src="cid:img1@mox.example" /></html>`},
			},
		},
	}
	msgAltReply = Message{
		Subject:    "Re: test",
		References: "<alt@localhost>",
		Part:       Part{Type: "text/plain", Content: "reply to alt"},
	}
	msgAltRel = Message{
		From:    "mjl <mjl+altrel@mox.example>",
		To:      "mox <mox+altrel@other.example>",
		Subject: "test with alt and rel",
		Headers: [][2]string{{"X-Special", "testing"}},
		Part: Part{
			Type: "multipart/alternative",
			Parts: []Part{
				{Type: "text/plain", Content: "the text body"},
				{
					Type: "multipart/related",
					Parts: []Part{
						{
							Type:    "text/html; charset=utf-8",
							Content: `<html>the body <img src="cid:img1@mox.example" /></html>`,
						},
						{Type: `image/png`, Disposition: `inline; filename="test1.png"`, ID: "<img1@mox.example>", Content: `PNG...`, TransferEncoding: "base64"},
					},
				},
			},
		},
	}
	msgAttachments = Message{
		From:    "mjl <mjl@mox.example>",
		To:      "mox <mox@other.example>",
		Subject: "test",
		Part: Part{
			Type: "multipart/mixed",
			Parts: []Part{
				{Type: "text/plain", Content: "the body"},
				{Type: "image/png", TransferEncoding: "base64", Content: `PNG...`},
				{Type: "image/png", TransferEncoding: "base64", Content: `PNG...`},
				{Type: `image/jpg; name="test.jpg"`, TransferEncoding: "base64", Content: `JPG...`},
				{Type: `image/jpg`, Disposition: `attachment; filename="test.jpg"`, TransferEncoding: "base64", Content: `JPG...`},
			},
		},
	}
)

// Import test messages messages.
type testmsg struct {
	Mailbox  string
	Flags    store.Flags
	Keywords []string
	msg      Message
	m        store.Message // As delivered.
	ID       int64         // Shortcut for m.ID
}

func tdeliver(t *testing.T, acc *store.Account, tm *testmsg) {
	msgFile, err := store.CreateMessageTemp("webmail-test")
	tcheck(t, err, "create message temp")
	size, err := msgFile.Write(tm.msg.Marshal(t))
	tcheck(t, err, "write message temp")
	m := store.Message{Flags: tm.Flags, Keywords: tm.Keywords, Size: int64(size)}
	err = acc.DeliverMailbox(xlog, tm.Mailbox, &m, msgFile, true)
	tcheck(t, err, "deliver test message")
	err = msgFile.Close()
	tcheck(t, err, "closing test message")
	tm.m = m
	tm.ID = m.ID
}

// Test scenario with an account with some mailboxes, messages, then make all
// kinds of changes and we check if we get the right events.
// todo: check more of the results, we currently mostly check http statuses,
// not the returned content.
func TestWebmail(t *testing.T) {
	mox.LimitersInit()
	os.RemoveAll("../testdata/webmail/data")
	mox.Context = ctxbg
	mox.ConfigStaticPath = "../testdata/webmail/mox.conf"
	mox.MustLoadConfig(true, false)
	defer store.Switchboard()()

	acc, err := store.OpenAccount("mjl")
	tcheck(t, err, "open account")
	err = acc.SetPassword("test1234")
	tcheck(t, err, "set password")
	defer func() {
		err := acc.Close()
		xlog.Check(err, "closing account")
	}()

	api := Webmail{maxMessageSize: 1024 * 1024}
	apiHandler, err := makeSherpaHandler(api.maxMessageSize)
	tcheck(t, err, "sherpa handler")

	reqInfo := requestInfo{"mjl@mox.example", "mjl", &http.Request{}}
	ctx := context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	tneedError(t, func() { api.MailboxCreate(ctx, "Inbox") })   // Cannot create inbox.
	tneedError(t, func() { api.MailboxCreate(ctx, "Archive") }) // Already exists.
	api.MailboxCreate(ctx, "Testbox1")
	api.MailboxCreate(ctx, "Lists/Go/Nuts") // Creates hierarchy.

	var zerom store.Message
	var (
		inboxMinimal     = &testmsg{"Inbox", store.Flags{}, nil, msgMinimal, zerom, 0}
		inboxText        = &testmsg{"Inbox", store.Flags{}, nil, msgText, zerom, 0}
		inboxHTML        = &testmsg{"Inbox", store.Flags{}, nil, msgHTML, zerom, 0}
		inboxAlt         = &testmsg{"Inbox", store.Flags{}, nil, msgAlt, zerom, 0}
		inboxAltRel      = &testmsg{"Inbox", store.Flags{}, nil, msgAltRel, zerom, 0}
		inboxAttachments = &testmsg{"Inbox", store.Flags{}, nil, msgAttachments, zerom, 0}
		testbox1Alt      = &testmsg{"Testbox1", store.Flags{}, nil, msgAlt, zerom, 0}
		rejectsMinimal   = &testmsg{"Rejects", store.Flags{Junk: true}, nil, msgMinimal, zerom, 0}
	)
	var testmsgs = []*testmsg{inboxMinimal, inboxText, inboxHTML, inboxAlt, inboxAltRel, inboxAttachments, testbox1Alt, rejectsMinimal}

	for _, tm := range testmsgs {
		tdeliver(t, acc, tm)
	}

	type httpHeaders [][2]string
	ctHTML := [2]string{"Content-Type", "text/html; charset=utf-8"}
	ctText := [2]string{"Content-Type", "text/plain; charset=utf-8"}
	ctTextNoCharset := [2]string{"Content-Type", "text/plain"}
	ctJS := [2]string{"Content-Type", "application/javascript; charset=utf-8"}
	ctJSON := [2]string{"Content-Type", "application/json; charset=utf-8"}

	const authOK = "mjl@mox.example:test1234"
	const authBad = "mjl@mox.example:badpassword"
	hdrAuthOK := [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(authOK))}
	hdrAuthBad := [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(authBad))}

	testHTTP := func(method, path string, headers httpHeaders, expStatusCode int, expHeaders httpHeaders, check func(resp *http.Response)) {
		t.Helper()

		req := httptest.NewRequest(method, path, nil)
		for _, kv := range headers {
			req.Header.Add(kv[0], kv[1])
		}
		rr := httptest.NewRecorder()
		handle(apiHandler, rr, req)
		if rr.Code != expStatusCode {
			t.Fatalf("got status %d, expected %d", rr.Code, expStatusCode)
		}

		resp := rr.Result()
		for _, h := range expHeaders {
			if resp.Header.Get(h[0]) != h[1] {
				t.Fatalf("for header %q got value %q, expected %q", h[0], resp.Header.Get(h[0]), h[1])
			}
		}

		if check != nil {
			check(resp)
		}
	}
	testHTTPAuth := func(method, path string, expStatusCode int, expHeaders httpHeaders, check func(resp *http.Response)) {
		t.Helper()
		testHTTP(method, path, httpHeaders{hdrAuthOK}, expStatusCode, expHeaders, check)
	}

	// HTTP webmail
	testHTTP("GET", "/", httpHeaders{}, http.StatusUnauthorized, nil, nil)
	testHTTP("GET", "/", httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
	testHTTPAuth("GET", "/", http.StatusOK, httpHeaders{ctHTML}, nil)
	testHTTPAuth("POST", "/", http.StatusMethodNotAllowed, nil, nil)
	testHTTP("GET", "/", httpHeaders{hdrAuthOK, [2]string{"Accept-Encoding", "gzip"}}, http.StatusOK, httpHeaders{ctHTML, [2]string{"Content-Encoding", "gzip"}}, nil)
	testHTTP("GET", "/msg.js", httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
	testHTTPAuth("POST", "/msg.js", http.StatusMethodNotAllowed, nil, nil)
	testHTTPAuth("GET", "/msg.js", http.StatusOK, httpHeaders{ctJS}, nil)
	testHTTP("GET", "/text.js", httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
	testHTTPAuth("GET", "/text.js", http.StatusOK, httpHeaders{ctJS}, nil)

	testHTTP("GET", "/api/Bogus", httpHeaders{}, http.StatusUnauthorized, nil, nil)
	testHTTP("GET", "/api/Bogus", httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
	testHTTPAuth("GET", "/api/Bogus", http.StatusNotFound, nil, nil)
	testHTTPAuth("GET", "/api/SSETypes", http.StatusOK, httpHeaders{ctJSON}, nil)

	// Unknown.
	testHTTPAuth("GET", "/other", http.StatusNotFound, nil, nil)

	// HTTP message, generic
	testHTTP("GET", fmt.Sprintf("/msg/%v/attachments.zip", inboxMinimal.ID), nil, http.StatusUnauthorized, nil, nil)
	testHTTP("GET", fmt.Sprintf("/msg/%v/attachments.zip", inboxMinimal.ID), httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
	testHTTPAuth("GET", fmt.Sprintf("/msg/%v/attachments.zip", 0), http.StatusNotFound, nil, nil)
	testHTTPAuth("GET", fmt.Sprintf("/msg/%v/attachments.zip", testmsgs[len(testmsgs)-1].ID+1), http.StatusNotFound, nil, nil)
	testHTTPAuth("GET", fmt.Sprintf("/msg/%v/bogus", inboxMinimal.ID), http.StatusNotFound, nil, nil)
	testHTTPAuth("GET", fmt.Sprintf("/msg/%v/view/bogus", inboxMinimal.ID), http.StatusNotFound, nil, nil)
	testHTTPAuth("GET", fmt.Sprintf("/msg/%v/bogus/0", inboxMinimal.ID), http.StatusNotFound, nil, nil)
	testHTTPAuth("GET", "/msg/", http.StatusNotFound, nil, nil)
	testHTTPAuth("POST", fmt.Sprintf("/msg/%v/attachments.zip", inboxMinimal.ID), http.StatusMethodNotAllowed, nil, nil)

	// HTTP message: attachments.zip
	ctZip := [2]string{"Content-Type", "application/zip"}
	checkZip := func(resp *http.Response, fileContents [][2]string) {
		t.Helper()
		zipbuf, err := io.ReadAll(resp.Body)
		tcheck(t, err, "reading response")
		zr, err := zip.NewReader(bytes.NewReader(zipbuf), int64(len(zipbuf)))
		tcheck(t, err, "open zip")
		if len(fileContents) != len(zr.File) {
			t.Fatalf("zip file has %d files, expected %d", len(fileContents), len(zr.File))
		}
		for i, fc := range fileContents {
			if zr.File[i].Name != fc[0] {
				t.Fatalf("zip, file at index %d is named %q, expected %q", i, zr.File[i].Name, fc[0])
			}
			f, err := zr.File[i].Open()
			tcheck(t, err, "open file in zip")
			buf, err := io.ReadAll(f)
			tcheck(t, err, "read file in zip")
			tcompare(t, string(buf), fc[1])
			err = f.Close()
			tcheck(t, err, "closing file")
		}
	}

	pathInboxMinimal := fmt.Sprintf("/msg/%d", inboxMinimal.ID)
	testHTTP("GET", pathInboxMinimal+"/attachments.zip", httpHeaders{}, http.StatusUnauthorized, nil, nil)
	testHTTP("GET", pathInboxMinimal+"/attachments.zip", httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)

	testHTTPAuth("GET", pathInboxMinimal+"/attachments.zip", http.StatusOK, httpHeaders{ctZip}, func(resp *http.Response) {
		checkZip(resp, nil)
	})
	pathInboxRelAlt := fmt.Sprintf("/msg/%d", inboxAltRel.ID)
	testHTTPAuth("GET", pathInboxRelAlt+"/attachments.zip", http.StatusOK, httpHeaders{ctZip}, func(resp *http.Response) {
		checkZip(resp, [][2]string{{"test1.png", "PNG..."}})
	})
	pathInboxAttachments := fmt.Sprintf("/msg/%d", inboxAttachments.ID)
	testHTTPAuth("GET", pathInboxAttachments+"/attachments.zip", http.StatusOK, httpHeaders{ctZip}, func(resp *http.Response) {
		checkZip(resp, [][2]string{{"attachment-1.png", "PNG..."}, {"attachment-2.png", "PNG..."}, {"test.jpg", "JPG..."}, {"test-1.jpg", "JPG..."}})
	})

	// HTTP message: raw
	pathInboxAltRel := fmt.Sprintf("/msg/%d", inboxAltRel.ID)
	pathInboxText := fmt.Sprintf("/msg/%d", inboxText.ID)
	testHTTP("GET", pathInboxAltRel+"/raw", httpHeaders{}, http.StatusUnauthorized, nil, nil)
	testHTTP("GET", pathInboxAltRel+"/raw", httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
	testHTTPAuth("GET", pathInboxAltRel+"/raw", http.StatusOK, httpHeaders{ctTextNoCharset}, nil)
	testHTTPAuth("GET", pathInboxText+"/raw", http.StatusOK, httpHeaders{ctText}, nil)

	// HTTP message: parsedmessage.js
	testHTTP("GET", pathInboxMinimal+"/parsedmessage.js", httpHeaders{}, http.StatusUnauthorized, nil, nil)
	testHTTP("GET", pathInboxMinimal+"/parsedmessage.js", httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
	testHTTPAuth("GET", pathInboxMinimal+"/parsedmessage.js", http.StatusOK, httpHeaders{ctJS}, nil)

	mox.LimitersInit()
	// HTTP message: text,html,htmlexternal and msgtext,msghtml,msghtmlexternal
	for _, elem := range []string{"text", "html", "htmlexternal", "msgtext", "msghtml", "msghtmlexternal"} {
		testHTTP("GET", pathInboxAltRel+"/"+elem, httpHeaders{}, http.StatusUnauthorized, nil, nil)
		testHTTP("GET", pathInboxAltRel+"/"+elem, httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
		mox.LimitersInit() // Reset, for too many failures.
	}

	// The text endpoint serves JS that we generated, so should be safe, but still doesn't hurt to have a CSP.
	cspText := [2]string{
		"Content-Security-Policy",
		"frame-ancestors 'self'; default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline' 'self'; frame-src 'self'; connect-src 'self'",
	}
	// HTML as viewed in the regular viewer, not in a new tab.
	cspHTML := [2]string{
		"Content-Security-Policy",
		"sandbox allow-popups allow-popups-to-escape-sandbox; frame-ancestors 'self'; default-src 'none'; img-src data:; style-src 'unsafe-inline'",
	}
	// HTML when in separate message tab, needs allow-same-origin for iframe inner height.
	cspHTMLSameOrigin := [2]string{
		"Content-Security-Policy",
		"sandbox allow-popups allow-popups-to-escape-sandbox allow-same-origin; frame-ancestors 'self'; default-src 'none'; img-src data:; style-src 'unsafe-inline'",
	}
	// Like cspHTML, but allows http and https resources.
	cspHTMLExternal := [2]string{
		"Content-Security-Policy",
		"sandbox allow-popups allow-popups-to-escape-sandbox; frame-ancestors 'self'; default-src 'none'; img-src data: http: https: 'unsafe-inline'; style-src 'unsafe-inline' data: http: https:; font-src data: http: https: 'unsafe-inline'; media-src 'unsafe-inline' data: http: https:",
	}
	// HTML with external resources when opened in separate tab, with allow-same-origin for iframe inner height.
	cspHTMLExternalSameOrigin := [2]string{
		"Content-Security-Policy",
		"sandbox allow-popups allow-popups-to-escape-sandbox allow-same-origin; frame-ancestors 'self'; default-src 'none'; img-src data: http: https: 'unsafe-inline'; style-src 'unsafe-inline' data: http: https:; font-src data: http: https: 'unsafe-inline'; media-src 'unsafe-inline' data: http: https:",
	}
	// Msg page, our JS, that loads an html iframe, already blocks access for the iframe.
	cspMsgHTML := [2]string{
		"Content-Security-Policy",
		"frame-ancestors 'self'; default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline' 'self'; frame-src 'self'; connect-src 'self'",
	}
	// Msg page that already allows external resources for the iframe.
	cspMsgHTMLExternal := [2]string{
		"Content-Security-Policy",
		"frame-ancestors 'self'; default-src 'none'; img-src data: http: https: 'unsafe-inline'; style-src 'unsafe-inline' data: http: https:; font-src data: http: https: 'unsafe-inline'; media-src 'unsafe-inline' data: http: https:; script-src 'unsafe-inline' 'self'; frame-src 'self'; connect-src 'self'",
	}
	testHTTPAuth("GET", pathInboxAltRel+"/text", http.StatusOK, httpHeaders{ctHTML, cspText}, nil)
	testHTTPAuth("GET", pathInboxAltRel+"/html", http.StatusOK, httpHeaders{ctHTML, cspHTML}, nil)
	testHTTPAuth("GET", pathInboxAltRel+"/htmlexternal", http.StatusOK, httpHeaders{ctHTML, cspHTMLExternal}, nil)
	testHTTPAuth("GET", pathInboxAltRel+"/msgtext", http.StatusOK, httpHeaders{ctHTML, cspText}, nil)
	testHTTPAuth("GET", pathInboxAltRel+"/msghtml", http.StatusOK, httpHeaders{ctHTML, cspMsgHTML}, nil)
	testHTTPAuth("GET", pathInboxAltRel+"/msghtmlexternal", http.StatusOK, httpHeaders{ctHTML, cspMsgHTMLExternal}, nil)

	testHTTPAuth("GET", pathInboxAltRel+"/html?sameorigin=true", http.StatusOK, httpHeaders{ctHTML, cspHTMLSameOrigin}, nil)
	testHTTPAuth("GET", pathInboxAltRel+"/htmlexternal?sameorigin=true", http.StatusOK, httpHeaders{ctHTML, cspHTMLExternalSameOrigin}, nil)

	// No HTML part.
	for _, elem := range []string{"html", "htmlexternal", "msghtml", "msghtmlexternal"} {
		testHTTPAuth("GET", pathInboxText+"/"+elem, http.StatusBadRequest, nil, nil)

	}
	// No text part.
	pathInboxHTML := fmt.Sprintf("/msg/%d", inboxHTML.ID)
	for _, elem := range []string{"text", "msgtext"} {
		testHTTPAuth("GET", pathInboxHTML+"/"+elem, http.StatusBadRequest, nil, nil)
	}

	// HTTP message part: view,viewtext,download
	for _, elem := range []string{"view", "viewtext", "download"} {
		testHTTP("GET", pathInboxAltRel+"/"+elem+"/0", httpHeaders{}, http.StatusUnauthorized, nil, nil)
		testHTTP("GET", pathInboxAltRel+"/"+elem+"/0", httpHeaders{hdrAuthBad}, http.StatusUnauthorized, nil, nil)
		testHTTPAuth("GET", pathInboxAltRel+"/"+elem+"/0", http.StatusOK, nil, nil)
		testHTTPAuth("GET", pathInboxAltRel+"/"+elem+"/0.0", http.StatusOK, nil, nil)
		testHTTPAuth("GET", pathInboxAltRel+"/"+elem+"/0.1", http.StatusOK, nil, nil)
		testHTTPAuth("GET", pathInboxAltRel+"/"+elem+"/0.2", http.StatusNotFound, nil, nil)
		testHTTPAuth("GET", pathInboxAltRel+"/"+elem+"/1", http.StatusNotFound, nil, nil)
	}
}

func TestSanitize(t *testing.T) {
	check := func(s string, exp string) {
		t.Helper()
		n, err := html.Parse(strings.NewReader(s))
		tcheck(t, err, "parsing html")
		sanitizeNode(n)
		var sb strings.Builder
		err = html.Render(&sb, n)
		tcheck(t, err, "writing html")
		if sb.String() != exp {
			t.Fatalf("sanitizing html: %s\ngot: %s\nexpected: %s", s, sb.String(), exp)
		}
	}

	check(``,
		`<html><head><base target="_blank" rel="noopener noreferrer"/></head><body></body></html>`)
	check(`<script>read localstorage</script>`,
		`<html><head><base target="_blank" rel="noopener noreferrer"/></head><body></body></html>`)
	check(`<a href="javascript:evil">click me</a>`,
		`<html><head><base target="_blank" rel="noopener noreferrer"/></head><body><a target="_blank" rel="noopener noreferrer">click me</a></body></html>`)
	check(`<a href="https://badsite" target="top">click me</a>`,
		`<html><head><base target="_blank" rel="noopener noreferrer"/></head><body><a href="https://badsite" target="_blank" rel="noopener noreferrer">click me</a></body></html>`)
	check(`<a xlink:href="https://badsite">click me</a>`,
		`<html><head><base target="_blank" rel="noopener noreferrer"/></head><body><a xlink:href="https://badsite" target="_blank" rel="noopener noreferrer">click me</a></body></html>`)
	check(`<a onclick="evil">click me</a>`,
		`<html><head><base target="_blank" rel="noopener noreferrer"/></head><body><a target="_blank" rel="noopener noreferrer">click me</a></body></html>`)
	check(`<iframe src="data:text/html;base64,evilhtml"></iframe>`,
		`<html><head><base target="_blank" rel="noopener noreferrer"/></head><body><iframe></iframe></body></html>`)
}
