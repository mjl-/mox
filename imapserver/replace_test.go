package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestReplace(t *testing.T) {
	testReplace(t, false)
}

func TestReplaceUIDOnly(t *testing.T) {
	testReplace(t, true)
}

func testReplace(t *testing.T, uidonly bool) {
	defer mockUIDValidity()()

	tc := start(t, uidonly)
	defer tc.close()

	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()

	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	// Star not allowed on empty mailbox.
	tc.transactf("bad", "uid replace * inbox {1}")
	if !uidonly {
		tc.transactf("bad", "replace * inbox {1}")
	}

	// Append 3 messages, remove first. Leaves msgseq 1,2 with uid 2,3.
	tc.client.MultiAppend("inbox", makeAppend(exampleMsg), makeAppend(exampleMsg), makeAppend(exampleMsg))
	tc.client.UIDStoreFlagsSet("1", true, `\deleted`)
	tc.client.Expunge()

	tc.transactf("no", "uid replace 1 expungebox {1}") // Mailbox no longer exists.
	tc.xcodeWord("TRYCREATE")

	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	// Replace last message (msgseq 2, uid 3) in same mailbox.
	if uidonly {
		tc.lastResponse, tc.lastErr = tc.client.UIDReplace("3", "INBOX", makeAppend(searchMsg))
	} else {
		tc.lastResponse, tc.lastErr = tc.client.MSNReplace("2", "INBOX", makeAppend(searchMsg))
	}
	tcheck(tc.t, tc.lastErr, "read imap response")
	if uidonly {
		tc.xuntagged(
			imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("4")}, Text: ""},
			imapclient.UntaggedExists(3),
			imapclient.UntaggedVanished{UIDs: xparseNumSet("3")},
		)
	} else {
		tc.xuntagged(
			imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("4")}, Text: ""},
			imapclient.UntaggedExists(3),
			imapclient.UntaggedExpunge(2),
		)
	}
	tc.xcode(imapclient.CodeHighestModSeq(8))

	// Check that other client sees Exists and Expunge.
	tc2.transactf("ok", "noop")
	if uidonly {
		tc2.xuntagged(
			imapclient.UntaggedVanished{UIDs: xparseNumSet("3")},
			imapclient.UntaggedExists(2),
			tc.untaggedFetch(2, 4, imapclient.FetchFlags(nil)),
		)
	} else {
		tc2.xuntagged(
			imapclient.UntaggedExpunge(2),
			imapclient.UntaggedExists(2),
			tc.untaggedFetch(2, 4, imapclient.FetchFlags(nil)),
		)
	}

	// Enable qresync, replace uid 2 (msgseq 1) to different mailbox, see that we get vanished instead of expunged.
	tc.transactf("ok", "enable qresync")
	tc.lastResponse, tc.lastErr = tc.client.UIDReplace("2", "INBOX", makeAppend(searchMsg))
	tcheck(tc.t, tc.lastErr, "read imap response")
	tc.xuntagged(
		imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("5")}, Text: ""},
		imapclient.UntaggedExists(3),
		imapclient.UntaggedVanished{UIDs: xparseNumSet("2")},
	)
	tc.xcode(imapclient.CodeHighestModSeq(9))

	// Use "*" for replacing.
	tc.transactf("ok", "uid replace * inbox {1+}\r\nx")
	tc.xuntagged(
		imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("6")}, Text: ""},
		imapclient.UntaggedExists(3),
		imapclient.UntaggedVanished{UIDs: xparseNumSet("5")},
	)
	if !uidonly {
		tc.transactf("ok", "replace * inbox {1+}\r\ny")
		tc.xuntagged(
			imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("7")}, Text: ""},
			imapclient.UntaggedExists(3),
			imapclient.UntaggedVanished{UIDs: xparseNumSet("6")},
		)
	}

	// Non-existent mailbox with non-synchronizing literal should consume the literal.
	if uidonly {
		tc.transactf("no", "uid replace 1 bogusbox {1+}\r\nx")
	} else {
		tc.transactf("no", "replace 1 bogusbox {1+}\r\nx")
	}

	// Leftover data.
	tc.transactf("bad", "replace 1 inbox () {6+}\r\ntest\r\n ")
}

func TestReplaceBigNonsyncLit(t *testing.T) {
	tc := start(t, false)
	defer tc.close()

	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	// Adding a message >1mb with non-sync literal to non-existent mailbox should abort entire connection.
	tc.transactf("bad", "replace 12345 inbox {2000000+}")
	tc.xuntagged(
		imapclient.UntaggedBye{Code: imapclient.CodeWord("ALERT"), Text: "error condition and non-synchronizing literal too big"},
	)
	tc.xcodeWord("TOOBIG")
}

func TestReplaceQuota(t *testing.T) {
	testReplaceQuota(t, false)
}

func TestReplaceQuotaUIDOnly(t *testing.T) {
	testReplaceQuota(t, true)
}

func testReplaceQuota(t *testing.T, uidonly bool) {
	// with quota limit
	tc := startArgs(t, uidonly, true, false, true, true, "limit")
	defer tc.close()

	tc.login("limit@mox.example", password0)
	tc.client.Select("inbox")
	tc.client.Append("inbox", makeAppend("x"))

	// Synchronizing literal, we get failure immediately.
	tc.transactf("no", "uid replace 1 inbox {6}\r\n")
	tc.xcodeWord("OVERQUOTA")

	// Synchronizing literal to non-existent mailbox, we get failure immediately.
	tc.transactf("no", "uid replace 1 badbox {6}\r\n")
	tc.xcodeWord("TRYCREATE")

	buf := make([]byte, 4000, 4002)
	for i := range buf {
		buf[i] = 'x'
	}
	buf = append(buf, "\r\n"...)

	// Non-synchronizing literal. We get to write our data.
	tc.client.WriteCommandf("", "uid replace 1 inbox ~{4000+}")
	_, err := tc.client.Write(buf)
	tc.check(err, "write replace message")
	tc.response("no")
	tc.xcodeWord("OVERQUOTA")

	// Non-synchronizing literal to bad mailbox.
	tc.client.WriteCommandf("", "uid replace 1 badbox {4000+}")
	_, err = tc.client.Write(buf)
	tc.check(err, "write replace message")
	tc.response("no")
	tc.xcodeWord("TRYCREATE")
}

func TestReplaceExpunged(t *testing.T) {
	testReplaceExpunged(t, false)
}

func TestReplaceExpungedUIDOnly(t *testing.T) {
	testReplaceExpunged(t, true)
}

func testReplaceExpunged(t *testing.T, uidonly bool) {
	tc := start(t, uidonly)
	defer tc.close()

	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")
	tc.client.Append("inbox", makeAppend(exampleMsg))

	// We start the command, but don't write data yet.
	tc.client.WriteCommandf("", "uid replace 1 inbox {4000}")

	// Get in with second client and remove the message we are replacing.
	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()
	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("inbox")
	tc2.client.UIDStoreFlagsSet("1", true, `\Deleted`)
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
	if uidonly {
		tc.xuntagged(
			tc.untaggedFetch(1, 1, imapclient.FetchFlags{`\Deleted`}),
			imapclient.UntaggedVanished{UIDs: xparseNumSet("1")},
		)
	} else {
		tc.xuntagged(
			tc.untaggedFetch(1, 1, imapclient.FetchFlags{`\Deleted`}),
			imapclient.UntaggedExpunge(1),
		)
	}
}
