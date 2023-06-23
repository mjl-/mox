package imapserver

import (
	"strings"
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestSelect(t *testing.T) {
	testSelectExamine(t, false)
}

func TestExamine(t *testing.T) {
	testSelectExamine(t, true)
}

// select and examine are pretty much the same. but examine opens readonly instead of readwrite.
func testSelectExamine(t *testing.T, examine bool) {
	defer mockUIDValidity()()
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", "testtest")

	cmd := "select"
	okcode := "READ-WRITE"
	if examine {
		cmd = "examine"
		okcode = "READ-ONLY"
	}

	uclosed := imapclient.UntaggedResult{Status: imapclient.OK, RespText: imapclient.RespText{Code: "CLOSED", More: "x"}}
	flags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent`, " ")
	permflags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent \*`, " ")
	uflags := imapclient.UntaggedFlags(flags)
	upermflags := imapclient.UntaggedResult{Status: imapclient.OK, RespText: imapclient.RespText{Code: "PERMANENTFLAGS", CodeArg: imapclient.CodeList{Code: "PERMANENTFLAGS", Args: permflags}, More: "x"}}
	urecent := imapclient.UntaggedRecent(0)
	uexists0 := imapclient.UntaggedExists(0)
	uexists1 := imapclient.UntaggedExists(1)
	uuidval1 := imapclient.UntaggedResult{Status: imapclient.OK, RespText: imapclient.RespText{Code: "UIDVALIDITY", CodeArg: imapclient.CodeUint{Code: "UIDVALIDITY", Num: 1}, More: "x"}}
	uuidnext1 := imapclient.UntaggedResult{Status: imapclient.OK, RespText: imapclient.RespText{Code: "UIDNEXT", CodeArg: imapclient.CodeUint{Code: "UIDNEXT", Num: 1}, More: "x"}}
	ulist := imapclient.UntaggedList{Separator: '/', Mailbox: "Inbox"}
	uunseen := imapclient.UntaggedResult{Status: imapclient.OK, RespText: imapclient.RespText{Code: "UNSEEN", CodeArg: imapclient.CodeUint{Code: "UNSEEN", Num: 1}, More: "x"}}
	uuidnext2 := imapclient.UntaggedResult{Status: imapclient.OK, RespText: imapclient.RespText{Code: "UIDNEXT", CodeArg: imapclient.CodeUint{Code: "UIDNEXT", Num: 2}, More: "x"}}

	// Parameter required.
	tc.transactf("bad", cmd)

	// Mailbox does not exist.
	tc.transactf("no", cmd+" bogus")

	tc.transactf("ok", cmd+" inbox")
	tc.xuntagged(uflags, upermflags, urecent, uexists0, uuidval1, uuidnext1, ulist)
	tc.xcode(okcode)

	tc.transactf("ok", cmd+` "inbox"`)
	tc.xuntagged(uclosed, uflags, upermflags, urecent, uexists0, uuidval1, uuidnext1, ulist)
	tc.xcode(okcode)

	// Append a message. It will be reported as UNSEEN.
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.transactf("ok", cmd+" inbox")
	tc.xuntagged(uclosed, uflags, upermflags, urecent, uunseen, uexists1, uuidval1, uuidnext2, ulist)
	tc.xcode(okcode)

	// With imap4rev2, we no longer get untagged RECENT or untagged UNSEEN.
	tc.client.Enable("imap4rev2")
	tc.transactf("ok", cmd+" inbox")
	tc.xuntagged(uclosed, uflags, upermflags, uexists1, uuidval1, uuidnext2, ulist)
	tc.xcode(okcode)
}
