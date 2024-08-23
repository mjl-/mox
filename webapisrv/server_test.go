package webapisrv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webapi"
	"github.com/mjl-/mox/webhook"
)

var ctxbg = context.Background()

func tcheckf(t *testing.T, err error, format string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func tcompare(t *testing.T, got, expect any) {
	t.Helper()
	if !reflect.DeepEqual(got, expect) {
		t.Fatalf("got:\n%#v\nexpected:\n%#v", got, expect)
	}
}

func terrcode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, expected error with code %q", code)
	}
	if xerr, ok := err.(webapi.Error); !ok {
		t.Fatalf("got %v, expected webapi error with code %q", err, code)
	} else if xerr.Code != code {
		t.Fatalf("got error code %q, expected %q", xerr.Code, code)
	}
}

func TestServer(t *testing.T) {
	mox.LimitersInit()
	os.RemoveAll("../testdata/webapisrv/data")
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/webapisrv/mox.conf")
	mox.MustLoadConfig(true, false)
	defer store.Switchboard()()
	err := queue.Init()
	tcheckf(t, err, "queue init")
	defer queue.Shutdown()

	log := mlog.New("webapisrv", nil)
	acc, err := store.OpenAccount(log, "mjl")
	tcheckf(t, err, "open account")
	const pw0 = "te\u0301st \u00a0\u2002\u200a" // NFD and various unicode spaces.
	const pw1 = "tést    "                      // PRECIS normalized, with NFC.
	err = acc.SetPassword(log, pw0)
	tcheckf(t, err, "set password")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
		acc.CheckClosed()
	}()

	s := NewServer(100*1024, "/webapi/", false).(server)
	hs := httptest.NewServer(s)
	defer hs.Close()

	// server expects the mount path to be stripped already.
	client := webapi.Client{BaseURL: hs.URL + "/v0/", Username: "mjl@mox.example", Password: pw0}

	testHTTPHdrsBody := func(s server, method, path string, headers map[string]string, body string, expCode int, expTooMany bool, expCT, expErrCode string) {
		t.Helper()

		r := httptest.NewRequest(method, path, strings.NewReader(body))
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		res := w.Result()
		if res.StatusCode != http.StatusTooManyRequests || !expTooMany {
			tcompare(t, res.StatusCode, expCode)
		}
		if expCT != "" {
			tcompare(t, res.Header.Get("Content-Type"), expCT)
		}
		if expErrCode != "" {
			dec := json.NewDecoder(res.Body)
			dec.DisallowUnknownFields()
			var apierr webapi.Error
			err := dec.Decode(&apierr)
			tcheckf(t, err, "decoding json error")
			tcompare(t, apierr.Code, expErrCode)
		}
	}
	testHTTP := func(method, path string, expCode int, expCT string) {
		t.Helper()
		testHTTPHdrsBody(s, method, path, nil, "", expCode, false, expCT, "")
	}

	testHTTP("GET", "/", http.StatusSeeOther, "")
	testHTTP("POST", "/", http.StatusMethodNotAllowed, "")
	testHTTP("GET", "/v0/", http.StatusOK, "text/html; charset=utf-8")
	testHTTP("GET", "/other/", http.StatusNotFound, "")
	testHTTP("GET", "/v0/Send", http.StatusOK, "text/html; charset=utf-8")
	testHTTP("GET", "/v0/MessageRawGet", http.StatusOK, "text/html; charset=utf-8")
	testHTTP("GET", "/v0/Bogus", http.StatusNotFound, "")
	testHTTP("PUT", "/v0/Send", http.StatusMethodNotAllowed, "")
	testHTTP("POST", "/v0/Send", http.StatusUnauthorized, "")

	for i := 0; i < 11; i++ {
		// Missing auth doesn't trigger auth rate limiter.
		testHTTP("POST", "/v0/Send", http.StatusUnauthorized, "")
	}
	for i := 0; i < 21; i++ {
		// Bad auth does.
		expCode := http.StatusUnauthorized
		tooMany := i >= 10
		if i == 20 {
			expCode = http.StatusTooManyRequests
		}
		testHTTPHdrsBody(s, "POST", "/v0/Send", map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("mjl@mox.example:badpassword"))}, "", expCode, tooMany, "", "")
	}
	mox.LimitersInit()

	// Request with missing X-Forwarded-For.
	sfwd := NewServer(100*1024, "/webapi/", true).(server)
	testHTTPHdrsBody(sfwd, "POST", "/v0/Send", map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("mjl@mox.example:badpassword"))}, "", http.StatusInternalServerError, false, "", "")

	// Body must be form, not JSON.
	authz := "Basic " + base64.StdEncoding.EncodeToString([]byte("mjl@mox.example:"+pw1))
	testHTTPHdrsBody(s, "POST", "/v0/Send", map[string]string{"Content-Type": "application/json", "Authorization": authz}, "{}", http.StatusBadRequest, false, "application/json; charset=utf-8", "protocol")
	testHTTPHdrsBody(s, "POST", "/v0/Send", map[string]string{"Content-Type": "multipart/form-data", "Authorization": authz}, "not formdata", http.StatusBadRequest, false, "application/json; charset=utf-8", "protocol")
	formAuth := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": authz,
	}
	testHTTPHdrsBody(s, "POST", "/v0/Send", formAuth, "not encoded\n\n", http.StatusBadRequest, false, "application/json; charset=utf-8", "protocol")
	// Missing "request".
	testHTTPHdrsBody(s, "POST", "/v0/Send", formAuth, "", http.StatusBadRequest, false, "application/json; charset=utf-8", "protocol")
	// "request" must be JSON.
	testHTTPHdrsBody(s, "POST", "/v0/Send", formAuth, "request=notjson", http.StatusBadRequest, false, "application/json; charset=utf-8", "protocol")
	// "request" must be JSON object.
	testHTTPHdrsBody(s, "POST", "/v0/Send", formAuth, "request=[]", http.StatusBadRequest, false, "application/json; charset=utf-8", "protocol")

	// Send message. Look for the message in the queue.
	now := time.Now()
	yes := true
	sendReq := webapi.SendRequest{
		Message: webapi.Message{
			From:       []webapi.NameAddress{{Name: "møx", Address: "mjl@mox.example"}},
			To:         []webapi.NameAddress{{Name: "móx", Address: "mjl+to@mox.example"}, {Address: "mjl+to2@mox.example"}},
			CC:         []webapi.NameAddress{{Name: "möx", Address: "mjl+cc@mox.example"}},
			BCC:        []webapi.NameAddress{{Name: "møx", Address: "mjl+bcc@mox.example"}},
			ReplyTo:    []webapi.NameAddress{{Name: "reply1", Address: "mox+reply1@mox.example"}, {Name: "reply2", Address: "mox+reply2@mox.example"}},
			MessageID:  "<random@localhost>",
			References: []string{"<messageid0@localhost>", "<messageid1@localhost>"},
			Date:       &now,
			Subject:    "¡hello world!",
			Text:       "hi ☺\n",
			HTML:       `<html><img src="cid:x" /></html>`, // Newline will be added.
		},
		Extra:   map[string]string{"a": "123"},
		Headers: [][2]string{{"x-custom", "header"}},
		AlternativeFiles: []webapi.File{
			{
				Name:        "x.ics",
				ContentType: "text/calendar",
				Data:        base64.StdEncoding.EncodeToString([]byte("ics data...")),
			},
		},
		InlineFiles: []webapi.File{
			{
				Name:        "x.png",
				ContentType: "image/png",
				ContentID:   "<x>",
				Data:        base64.StdEncoding.EncodeToString([]byte("png data")),
			},
		},
		AttachedFiles: []webapi.File{
			{
				Data: base64.StdEncoding.EncodeToString([]byte("%PDF-")), // Should be detected as PDF.
			},
		},
		RequireTLS:    &yes,
		FutureRelease: &now,
		SaveSent:      true,
	}
	sendResp, err := client.Send(ctxbg, sendReq)
	tcheckf(t, err, "send message")
	tcompare(t, sendResp.MessageID, sendReq.Message.MessageID)
	tcompare(t, len(sendResp.Submissions), 2+1+1) // 2 to, 1 cc, 1 bcc
	subs := sendResp.Submissions
	tcompare(t, subs[0].Address, "mjl+to@mox.example")
	tcompare(t, subs[1].Address, "mjl+to2@mox.example")
	tcompare(t, subs[2].Address, "mjl+cc@mox.example")
	tcompare(t, subs[3].Address, "mjl+bcc@mox.example")
	tcompare(t, subs[3].QueueMsgID, subs[0].QueueMsgID+3)
	tcompare(t, subs[0].FromID, "")
	// todo: look in queue for parameters. parse the message.

	// Send a custom multipart/form-data POST, with different request parameters, and
	// additional files.
	var sb strings.Builder
	mp := multipart.NewWriter(&sb)
	fdSendReq := webapi.SendRequest{
		Message: webapi.Message{
			To: []webapi.NameAddress{{Address: "møx@mox.example"}},
			// Let server assign date, message-id.
			Subject: "test",
			Text:    "hi",
		},
		// Don't let server add its own user-agent.
		Headers: [][2]string{{"User-Agent", "test"}},
	}
	sendReqBuf, err := json.Marshal(fdSendReq)
	tcheckf(t, err, "send request")
	mp.WriteField("request", string(sendReqBuf))

	// One alternative file.
	pw, err := mp.CreateFormFile("alternativefile", "test.ics")
	tcheckf(t, err, "create alternative ics file")
	_, err = fmt.Fprint(pw, "ICS...")
	tcheckf(t, err, "write ics")

	// Two inline PDFs.
	pw, err = mp.CreateFormFile("inlinefile", "test.pdf")
	tcheckf(t, err, "create inline pdf file")
	_, err = fmt.Fprint(pw, "%PDF-")
	tcheckf(t, err, "write pdf")
	pw, err = mp.CreateFormFile("inlinefile", "test.pdf")
	tcheckf(t, err, "create second inline pdf file")
	_, err = fmt.Fprint(pw, "%PDF-")
	tcheckf(t, err, "write second pdf")

	// One attached PDF.
	fh := textproto.MIMEHeader{}
	fh.Set("Content-Disposition", `form-data; name="attachedfile"; filename="test.pdf"`)
	fh.Set("Content-ID", "<testpdf>")
	pw, err = mp.CreatePart(fh)
	tcheckf(t, err, "create attached pdf file")
	_, err = fmt.Fprint(pw, "%PDF-")
	tcheckf(t, err, "write attached pdf")
	fdct := mp.FormDataContentType()
	err = mp.Close()
	tcheckf(t, err, "close multipart")

	// Perform custom POST.
	req, err := http.NewRequest("POST", hs.URL+"/v0/Send", strings.NewReader(sb.String()))
	tcheckf(t, err, "new request")
	req.Header.Set("Content-Type", fdct)
	// Use a unique MAIL FROM id when delivering.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("mjl+fromid@mox.example:"+pw1)))
	resp, err := http.DefaultClient.Do(req)
	tcheckf(t, err, "request multipart/form-data")
	tcompare(t, resp.StatusCode, http.StatusOK)
	var sendRes webapi.SendResult
	err = json.NewDecoder(resp.Body).Decode(&sendRes)
	tcheckf(t, err, "parse send response")
	tcompare(t, sendRes.MessageID != "", true)
	tcompare(t, len(sendRes.Submissions), 1)
	tcompare(t, sendRes.Submissions[0].FromID != "", true)

	// Trigger various error conditions.
	_, err = client.Send(ctxbg, webapi.SendRequest{
		Message: webapi.Message{
			To:      []webapi.NameAddress{{Address: "mjl@mox.example"}},
			Subject: "test",
		},
	})
	terrcode(t, err, "missingBody")

	_, err = client.Send(ctxbg, webapi.SendRequest{
		Message: webapi.Message{
			From:    []webapi.NameAddress{{Address: "other@mox.example"}},
			To:      []webapi.NameAddress{{Address: "mjl@mox.example"}},
			Subject: "test",
			Text:    "hi",
		},
	})
	terrcode(t, err, "badFrom")

	_, err = client.Send(ctxbg, webapi.SendRequest{
		Message: webapi.Message{
			From:    []webapi.NameAddress{{Address: "mox@mox.example"}, {Address: "mox@mox.example"}},
			To:      []webapi.NameAddress{{Address: "mjl@mox.example"}},
			Subject: "test",
			Text:    "hi",
		},
	})
	terrcode(t, err, "multipleFrom")

	_, err = client.Send(ctxbg, webapi.SendRequest{Message: webapi.Message{Subject: "test", Text: "hi"}})
	terrcode(t, err, "noRecipients")

	_, err = client.Send(ctxbg, webapi.SendRequest{
		Message: webapi.Message{
			MessageID: "missingltgt@localhost",
			To:        []webapi.NameAddress{{Address: "møx@mox.example"}},
			Subject:   "test",
			Text:      "hi",
		},
	})
	terrcode(t, err, "malformedMessageID")

	_, err = client.Send(ctxbg, webapi.SendRequest{
		Message: webapi.Message{
			MessageID: "missingltgt@localhost",
			To:        []webapi.NameAddress{{Address: "møx@mox.example"}},
			Subject:   "test",
			Text:      "hi",
		},
	})
	terrcode(t, err, "malformedMessageID")

	// todo: messageLimitReached, recipientLimitReached

	// SuppressionList
	supListRes, err := client.SuppressionList(ctxbg, webapi.SuppressionListRequest{})
	tcheckf(t, err, "listing suppressions")
	tcompare(t, len(supListRes.Suppressions), 0)

	// SuppressionAdd
	supAddReq := webapi.SuppressionAddRequest{EmailAddress: "Remote.Last-catchall@xn--74h.localhost", Manual: true, Reason: "tests"}
	_, err = client.SuppressionAdd(ctxbg, supAddReq)
	tcheckf(t, err, "add address to suppression list")
	_, err = client.SuppressionAdd(ctxbg, supAddReq)
	terrcode(t, err, "error") // Already present.
	supAddReq2 := webapi.SuppressionAddRequest{EmailAddress: "remotelast@☺.localhost", Manual: false, Reason: "tests"}
	_, err = client.SuppressionAdd(ctxbg, supAddReq2)
	terrcode(t, err, "error") // Already present, same base address.
	supAddReq3 := webapi.SuppressionAddRequest{EmailAddress: "not an address"}
	_, err = client.SuppressionAdd(ctxbg, supAddReq3)
	terrcode(t, err, "badAddress")

	supListRes, err = client.SuppressionList(ctxbg, webapi.SuppressionListRequest{})
	tcheckf(t, err, "listing suppressions")
	tcompare(t, len(supListRes.Suppressions), 1)
	supListRes.Suppressions[0].Created = now
	tcompare(t, supListRes.Suppressions, []webapi.Suppression{
		{
			ID:              1,
			Created:         now,
			Account:         "mjl",
			BaseAddress:     "remotelast@☺.localhost",
			OriginalAddress: "Remote.Last-catchall@☺.localhost",
			Manual:          true,
			Reason:          "tests",
		},
	})

	// SuppressionPresent
	supPresRes, err := client.SuppressionPresent(ctxbg, webapi.SuppressionPresentRequest{EmailAddress: "not@localhost"})
	tcheckf(t, err, "address present")
	tcompare(t, supPresRes.Present, false)
	supPresRes, err = client.SuppressionPresent(ctxbg, webapi.SuppressionPresentRequest{EmailAddress: "remotelast@xn--74h.localhost"})
	tcheckf(t, err, "address present")
	tcompare(t, supPresRes.Present, true)
	supPresRes, err = client.SuppressionPresent(ctxbg, webapi.SuppressionPresentRequest{EmailAddress: "Remote.Last-catchall@☺.localhost"})
	tcheckf(t, err, "address present")
	tcompare(t, supPresRes.Present, true)
	supPresRes, err = client.SuppressionPresent(ctxbg, webapi.SuppressionPresentRequest{EmailAddress: "not an address"})
	terrcode(t, err, "badAddress")

	// SuppressionRemove
	_, err = client.SuppressionRemove(ctxbg, webapi.SuppressionRemoveRequest{EmailAddress: "remote.LAST+more@☺.LocalHost"})
	tcheckf(t, err, "remove suppressed address")
	_, err = client.SuppressionRemove(ctxbg, webapi.SuppressionRemoveRequest{EmailAddress: "remote.LAST+more@☺.LocalHost"})
	terrcode(t, err, "error") // Absent.
	_, err = client.SuppressionRemove(ctxbg, webapi.SuppressionRemoveRequest{EmailAddress: "not an address"})
	terrcode(t, err, "badAddress")

	supListRes, err = client.SuppressionList(ctxbg, webapi.SuppressionListRequest{})
	tcheckf(t, err, "listing suppressions")
	tcompare(t, len(supListRes.Suppressions), 0)

	// MessageGet, we retrieve the message we sent first.
	msgRes, err := client.MessageGet(ctxbg, webapi.MessageGetRequest{MsgID: 1})
	tcheckf(t, err, "remove suppressed address")
	sentMsg := sendReq.Message
	sentMsg.Date = msgRes.Message.Date
	sentMsg.HTML += "\n"
	tcompare(t, msgRes.Message, sentMsg)
	// The structure is: mixed (related (alternative text html) inline-png) attached-pdf).
	pdfpart := msgRes.Structure.Parts[1]
	tcompare(t, pdfpart.ContentType, "application/pdf")
	// structure compared below, parsed again from raw message.
	// todo: compare Meta

	_, err = client.MessageGet(ctxbg, webapi.MessageGetRequest{MsgID: 1 + 999})
	terrcode(t, err, "messageNotFound")

	// MessageRawGet
	r, err := client.MessageRawGet(ctxbg, webapi.MessageRawGetRequest{MsgID: 1})
	tcheckf(t, err, "get raw message")
	var b bytes.Buffer
	_, err = io.Copy(&b, r)
	r.Close()
	tcheckf(t, err, "reading raw message")
	part, err := message.EnsurePart(log.Logger, true, bytes.NewReader(b.Bytes()), int64(b.Len()))
	tcheckf(t, err, "parsing raw message")
	tcompare(t, webhook.PartStructure(&part), msgRes.Structure)

	_, err = client.MessageRawGet(ctxbg, webapi.MessageRawGetRequest{MsgID: 1 + 999})
	terrcode(t, err, "messageNotFound")

	// MessagePartGet
	// The structure is: mixed (related (alternative text html) inline-png) attached-pdf).
	r, err = client.MessagePartGet(ctxbg, webapi.MessagePartGetRequest{MsgID: 1, PartPath: []int{0, 0, 1}})
	tcheckf(t, err, "get message part")
	tdata(t, r, sendReq.HTML+"\r\n") // Part returns the raw data with \r\n line endings.
	r.Close()

	r, err = client.MessagePartGet(ctxbg, webapi.MessagePartGetRequest{MsgID: 1, PartPath: []int{}})
	tcheckf(t, err, "get message part")
	r.Close()

	_, err = client.MessagePartGet(ctxbg, webapi.MessagePartGetRequest{MsgID: 1, PartPath: []int{2}})
	terrcode(t, err, "partNotFound")

	_, err = client.MessagePartGet(ctxbg, webapi.MessagePartGetRequest{MsgID: 1 + 999, PartPath: []int{}})
	terrcode(t, err, "messageNotFound")

	_, err = client.MessageFlagsAdd(ctxbg, webapi.MessageFlagsAddRequest{MsgID: 1, Flags: []string{`\answered`, "$Forwarded", "custom"}})
	tcheckf(t, err, "add flags")

	msgRes, err = client.MessageGet(ctxbg, webapi.MessageGetRequest{MsgID: 1})
	tcheckf(t, err, "get message")
	tcompare(t, slices.Contains(msgRes.Meta.Flags, `\answered`), true)
	tcompare(t, slices.Contains(msgRes.Meta.Flags, "$forwarded"), true)
	tcompare(t, slices.Contains(msgRes.Meta.Flags, "custom"), true)

	// Setting duplicate flags doesn't make a change.
	_, err = client.MessageFlagsAdd(ctxbg, webapi.MessageFlagsAddRequest{MsgID: 1, Flags: []string{`\Answered`, "$forwarded", "custom"}})
	tcheckf(t, err, "add flags")
	msgRes2, err := client.MessageGet(ctxbg, webapi.MessageGetRequest{MsgID: 1})
	tcheckf(t, err, "get message")
	tcompare(t, msgRes.Meta.Flags, msgRes2.Meta.Flags)

	// Non-existing message gives generic user error.
	_, err = client.MessageFlagsAdd(ctxbg, webapi.MessageFlagsAddRequest{MsgID: 1 + 999, Flags: []string{`\answered`, "$Forwarded", "custom"}})
	terrcode(t, err, "messageNotFound")

	// MessageFlagsRemove
	_, err = client.MessageFlagsRemove(ctxbg, webapi.MessageFlagsRemoveRequest{MsgID: 1, Flags: []string{`\Answered`, "$forwarded", "custom"}})
	tcheckf(t, err, "remove")
	msgRes, err = client.MessageGet(ctxbg, webapi.MessageGetRequest{MsgID: 1})
	tcheckf(t, err, "get message")
	tcompare(t, slices.Contains(msgRes.Meta.Flags, `\answered`), false)
	tcompare(t, slices.Contains(msgRes.Meta.Flags, "$forwarded"), false)
	tcompare(t, slices.Contains(msgRes.Meta.Flags, "custom"), false)
	// Can try removing again, no change.
	_, err = client.MessageFlagsRemove(ctxbg, webapi.MessageFlagsRemoveRequest{MsgID: 1, Flags: []string{`\Answered`, "$forwarded", "custom"}})
	tcheckf(t, err, "remove")

	_, err = client.MessageFlagsRemove(ctxbg, webapi.MessageFlagsRemoveRequest{MsgID: 1 + 999, Flags: []string{`\Answered`, "$forwarded", "custom"}})
	terrcode(t, err, "messageNotFound")

	// MessageMove
	tcompare(t, msgRes.Meta.MailboxName, "Sent")
	_, err = client.MessageMove(ctxbg, webapi.MessageMoveRequest{MsgID: 1, DestMailboxName: "Inbox"})
	tcheckf(t, err, "move to inbox")
	msgRes, err = client.MessageGet(ctxbg, webapi.MessageGetRequest{MsgID: 1})
	tcheckf(t, err, "get message")
	tcompare(t, msgRes.Meta.MailboxName, "Inbox")
	_, err = client.MessageMove(ctxbg, webapi.MessageMoveRequest{MsgID: 1, DestMailboxName: "Bogus"})
	terrcode(t, err, "user")
	_, err = client.MessageMove(ctxbg, webapi.MessageMoveRequest{MsgID: 1 + 999, DestMailboxName: "Inbox"})
	terrcode(t, err, "messageNotFound")

	// MessageDelete
	_, err = client.MessageDelete(ctxbg, webapi.MessageDeleteRequest{MsgID: 1})
	tcheckf(t, err, "delete message")
	_, err = client.MessageDelete(ctxbg, webapi.MessageDeleteRequest{MsgID: 1})
	terrcode(t, err, "user") // No longer.
	_, err = client.MessageGet(ctxbg, webapi.MessageGetRequest{MsgID: 1})
	terrcode(t, err, "messageNotFound") // No longer.
	_, err = client.MessageDelete(ctxbg, webapi.MessageDeleteRequest{MsgID: 1 + 999})
	terrcode(t, err, "messageNotFound")
}

func tdata(t *testing.T, r io.Reader, exp string) {
	t.Helper()
	buf, err := io.ReadAll(r)
	tcheckf(t, err, "reading body")
	tcompare(t, string(buf), exp)
}
