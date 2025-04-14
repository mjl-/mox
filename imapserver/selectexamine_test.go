package imapserver

import (
	"strings"
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestSelect(t *testing.T) {
	testSelectExamine(t, false, false)
}

func TestExamine(t *testing.T) {
	testSelectExamine(t, true, false)
}

func TestSelectUIDOnly(t *testing.T) {
	testSelectExamine(t, false, true)
}

func TestExamineUIDOnly(t *testing.T) {
	testSelectExamine(t, true, true)
}

// select and examine are pretty much the same. but examine opens readonly instead of readwrite.
func testSelectExamine(t *testing.T, examine, uidonly bool) {
	defer mockUIDValidity()()
	tc := start(t, uidonly)
	defer tc.close()

	tc.login("mjl@mox.example", password0)

	cmd := "select"
	okcode := "READ-WRITE"
	if examine {
		cmd = "examine"
		okcode = "READ-ONLY"
	}

	uclosed := imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeWord("CLOSED"), Text: "x"}
	flags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent`, " ")
	permflags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent \*`, " ")
	uflags := imapclient.UntaggedFlags(flags)
	upermflags := imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodePermanentFlags(permflags), Text: "x"}
	urecent := imapclient.UntaggedRecent(0)
	uexists0 := imapclient.UntaggedExists(0)
	uexists1 := imapclient.UntaggedExists(1)
	uuidval1 := imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUIDValidity(1), Text: "x"}
	uuidnext1 := imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUIDNext(1), Text: "x"}
	ulist := imapclient.UntaggedList{Separator: '/', Mailbox: "Inbox"}
	uunseen := imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUnseen(1), Text: "x"}
	uuidnext2 := imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUIDNext(2), Text: "x"}

	// Parameter required.
	tc.transactf("bad", "%s", cmd)

	// Mailbox does not exist.
	tc.transactf("no", "%s bogus", cmd)
	tc.transactf("no", "%s expungebox", cmd)

	tc.transactf("ok", "%s inbox", cmd)
	tc.xuntagged(uflags, upermflags, urecent, uexists0, uuidval1, uuidnext1, ulist)
	tc.xcodeWord(okcode)

	tc.transactf("ok", `%s "inbox"`, cmd)
	tc.xuntagged(uclosed, uflags, upermflags, urecent, uexists0, uuidval1, uuidnext1, ulist)
	tc.xcodeWord(okcode)

	// Append a message. It will be reported as UNSEEN.
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.transactf("ok", "%s inbox", cmd)
	if uidonly {
		tc.xuntagged(uclosed, uflags, upermflags, urecent, uexists1, uuidval1, uuidnext2, ulist)
	} else {
		tc.xuntagged(uclosed, uflags, upermflags, urecent, uunseen, uexists1, uuidval1, uuidnext2, ulist)
	}
	tc.xcodeWord(okcode)

	// With imap4rev2, we no longer get untagged RECENT or untagged UNSEEN.
	tc.client.Enable(imapclient.CapIMAP4rev2)
	tc.transactf("ok", "%s inbox", cmd)
	tc.xuntagged(uclosed, uflags, upermflags, uexists1, uuidval1, uuidnext2, ulist)
	tc.xcodeWord(okcode)
}
