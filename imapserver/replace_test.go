package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestReplace(t *testing.T) {
	defer mockUIDValidity()()

	tc := start(t)
	defer tc.close()

	tc2 := startNoSwitchboard(t)
	defer tc2.closeNoWait()

	tc.client.Login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	// Append 3 messages, remove first. Leaves msgseq 1,2 with uid 2,3.
	tc.client.Append("inbox", makeAppend(exampleMsg), makeAppend(exampleMsg), makeAppend(exampleMsg))
	tc.client.StoreFlagsSet("1", true, `\deleted`)
	tc.client.Expunge()

	tc.transactf("no", "replace 2 expungebox {1}") // Mailbox no longer exists.
	tc.xcode("TRYCREATE")

	tc2.client.Login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	// Replace last message (msgseq 2, uid 3) in same mailbox.
	tc.lastUntagged, tc.lastResult, tc.lastErr = tc.client.Replace("2", "INBOX", makeAppend(searchMsg))
	tcheck(tc.t, tc.lastErr, "read imap response")
	tc.xuntagged(
		imapclient.UntaggedResult{Status: "OK", RespText: imapclient.RespText{Code: "APPENDUID", CodeArg: imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("4")}, More: ""}},
		imapclient.UntaggedExists(3),
		imapclient.UntaggedExpunge(2),
	)
	tc.xcodeArg(imapclient.CodeHighestModSeq(8))

	// Check that other client sees Exists and Expunge.
	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedExpunge(2),
		imapclient.UntaggedExists(2),
		imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(4), imapclient.FetchFlags(nil)}},
	)

	// Enable qresync, replace uid 2 (msgseq 1) to different mailbox, see that we get vanished instead of expunged.
	tc.transactf("ok", "enable qresync")
	tc.lastUntagged, tc.lastResult, tc.lastErr = tc.client.UIDReplace("2", "INBOX", makeAppend(searchMsg))
	tcheck(tc.t, tc.lastErr, "read imap response")
	tc.xuntagged(
		imapclient.UntaggedResult{Status: "OK", RespText: imapclient.RespText{Code: "APPENDUID", CodeArg: imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("5")}, More: ""}},
		imapclient.UntaggedExists(3),
		imapclient.UntaggedVanished{UIDs: xparseNumSet("2")},
	)
	tc.xcodeArg(imapclient.CodeHighestModSeq(9))

	// Non-existent mailbox with non-synchronizing literal should consume the literal.
	tc.transactf("no", "replace 1 bogusbox {1+}\r\nx")

	// Leftover data.
	tc.transactf("bad", "replace 1 inbox () {6+}\r\ntest\r\n ")
}

func TestReplaceBigNonsyncLit(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	// Adding a message >1mb with non-sync literal to non-existent mailbox should abort entire connection.
	tc.transactf("bad", "replace 12345 inbox {2000000+}")
	tc.xuntagged(
		imapclient.UntaggedBye{Code: "ALERT", More: "error condition and non-synchronizing literal too big"},
	)
	tc.xcode("TOOBIG")
}

func TestReplaceQuota(t *testing.T) {
	// with quota limit
	tc := startArgs(t, true, false, true, true, "limit")
	defer tc.close()

	tc.client.Login("limit@mox.example", password0)
	tc.client.Select("inbox")
	tc.client.Append("inbox", makeAppend("x"))

	// Synchronizing literal, we get failure immediately.
	tc.transactf("no", "replace 1 inbox {6}\r\n")
	tc.xcode("OVERQUOTA")

	// Synchronizing literal to non-existent mailbox, we get failure immediately.
	tc.transactf("no", "replace 1 badbox {6}\r\n")
	tc.xcode("TRYCREATE")

	buf := make([]byte, 4000, 4002)
	for i := range buf {
		buf[i] = 'x'
	}
	buf = append(buf, "\r\n"...)

	// Non-synchronizing literal. We get to write our data.
	tc.client.Commandf("", "replace 1 inbox ~{4000+}")
	_, err := tc.client.Write(buf)
	tc.check(err, "write replace message")
	tc.response("no")
	tc.xcode("OVERQUOTA")

	// Non-synchronizing literal to bad mailbox.
	tc.client.Commandf("", "replace 1 badbox {4000+}")
	_, err = tc.client.Write(buf)
	tc.check(err, "write replace message")
	tc.response("no")
	tc.xcode("TRYCREATE")
}

func TestReplaceExpunged(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)
	tc.client.Select("inbox")
	tc.client.Append("inbox", makeAppend(exampleMsg))

	// We start the command, but don't write data yet.
	tc.client.Commandf("", "replace 1 inbox {4000}")

	// Get in with second client and remove the message we are replacing.
	tc2 := startNoSwitchboard(t)
	defer tc2.closeNoWait()
	tc2.client.Login("mjl@mox.example", password0)
	tc2.client.Select("inbox")
	tc2.client.StoreFlagsSet("1", true, `\Deleted`)
	tc2.client.Expunge()
	tc2.client.Unselect()
	tc2.client.Close()

	// Now continue trying to replace the message. We should get an error and an expunge.
	tc.readprefixline("+ ")
	buf := make([]byte, 4000, 4002)
	for i := range buf {
		buf[i] = 'x'
	}
	buf = append(buf, "\r\n"...)
	_, err := tc.client.Write(buf)
	tc.check(err, "write replace message")
	tc.response("no")
	tc.xuntagged(
		imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(1), imapclient.FetchFlags{`\Deleted`}}},
		imapclient.UntaggedExpunge(1),
	)
}
