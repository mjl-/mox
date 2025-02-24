package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestAppend(t *testing.T) {
	defer mockUIDValidity()()

	tc := start(t) // note: with switchboard because this connection stays alive unlike tc2.
	defer tc.close()

	tc2 := startNoSwitchboard(t) // note: without switchboard because this connection will break during tests.
	defer tc2.close()

	tc3 := startNoSwitchboard(t)
	defer tc3.close()

	tc2.client.Login("mjl@mox.example", password0)
	tc2.client.Select("inbox")
	tc.client.Login("mjl@mox.example", password0)
	tc.client.Select("inbox")
	tc3.client.Login("mjl@mox.example", password0)

	tc2.transactf("bad", "append")              // Missing params.
	tc2.transactf("bad", `append inbox`)        // Missing message.
	tc2.transactf("bad", `append inbox "test"`) // Message must be literal.

	// Syntax error for line ending in literal causes connection abort.
	tc2.transactf("bad", "append inbox (\\Badflag) {1+}\r\nx") // Unknown flag.
	tc2 = startNoSwitchboard(t)
	defer tc2.close()
	tc2.client.Login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	tc2.transactf("bad", "append inbox () \"bad time\" {1+}\r\nx") // Bad time.
	tc2 = startNoSwitchboard(t)
	defer tc2.close()
	tc2.client.Login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	tc2.transactf("no", "append nobox (\\Seen) \" 1-Jan-2022 10:10:00 +0100\" {1}")
	tc2.xcode("TRYCREATE")

	tc2.transactf("ok", "append inbox (\\Seen Label1 $label2) \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc2.xuntagged(imapclient.UntaggedExists(1))
	tc2.xcodeArg(imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("1")})

	tc.transactf("ok", "noop")
	uid1 := imapclient.FetchUID(1)
	flags := imapclient.FetchFlags{`\Seen`, "$label2", "label1"}
	tc.xuntagged(imapclient.UntaggedExists(1), imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, flags}})
	tc3.transactf("ok", "noop")
	tc3.xuntagged() // Inbox is not selected, nothing to report.

	tc2.transactf("ok", "append inbox (\\Seen) \" 1-Jan-2022 10:10:00 +0100\" UTF8 ({47+}\r\ncontent-type: just completely invalid;;\r\n\r\ntest)")
	tc2.xuntagged(imapclient.UntaggedExists(2))
	tc2.xcodeArg(imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("2")})

	tc2.transactf("ok", "append inbox (\\Seen) \" 1-Jan-2022 10:10:00 +0100\" UTF8 ({31+}\r\ncontent-type: text/plain;\n\ntest)")
	tc2.xuntagged(imapclient.UntaggedExists(3))
	tc2.xcodeArg(imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("3")})

	// Messages that we cannot parse are marked as application/octet-stream. Perhaps
	// the imap client knows how to deal with them.
	tc2.transactf("ok", "uid fetch 2 body")
	uid2 := imapclient.FetchUID(2)
	xbs := imapclient.FetchBodystructure{
		RespAttr: "BODY",
		Body: imapclient.BodyTypeBasic{
			MediaType:    "APPLICATION",
			MediaSubtype: "OCTET-STREAM",
			BodyFields: imapclient.BodyFields{
				Octets: 4,
			},
		},
	}
	tc2.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, xbs}})

	// Multiappend with two messages.
	tc.transactf("ok", "noop") // Flush pending untagged responses.
	tc.transactf("ok", "append inbox {6+}\r\ntest\r\n {6+}\r\ntost\r\n")
	tc.xuntagged(imapclient.UntaggedExists(5))
	tc.xcodeArg(imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("4:5")})

	// Cancelled with zero-length message.
	tc.transactf("no", "append inbox {6+}\r\ntest\r\n {0+}\r\n")

	tclimit := startArgs(t, false, false, true, true, "limit")
	defer tclimit.close()
	tclimit.client.Login("limit@mox.example", password0)
	tclimit.client.Select("inbox")
	// First message of 1 byte is within limits.
	tclimit.transactf("ok", "append inbox (\\Seen Label1 $label2) \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tclimit.xuntagged(imapclient.UntaggedExists(1))
	// Second message would take account past limit.
	tclimit.transactf("no", "append inbox (\\Seen Label1 $label2) \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tclimit.xcode("OVERQUOTA")

	// Empty mailbox.
	tclimit.transactf("ok", `store 1 flags (\deleted)`)
	tclimit.transactf("ok", "expunge")

	// Multiappend with first message within quota, and second message with sync
	// literal causing quota error. Request should get error response immediately.
	tclimit.transactf("no", "append inbox {1+}\r\nx {100000}")
	tclimit.xcode("OVERQUOTA")

	// Again, but second message now with non-sync literal, which is fully consumed by server.
	tclimit.client.Commandf("", "append inbox {1+}\r\nx {4000+}")
	buf := make([]byte, 4000, 4002)
	for i := range buf {
		buf[i] = 'x'
	}
	buf = append(buf, "\r\n"...)
	_, err := tclimit.client.Write(buf)
	tclimit.check(err, "write append message")
	tclimit.response("no")
	tclimit.xcode("OVERQUOTA")
}
