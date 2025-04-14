package imapserver

import (
	"testing"
)

func TestUIDOnly(t *testing.T) {
	tc := start(t, true)
	defer tc.close()
	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	tc.transactf("bad", "Fetch 1")
	tc.xcodeWord("UIDREQUIRED")
	tc.transactf("bad", "Fetch 1")
	tc.xcodeWord("UIDREQUIRED")
	tc.transactf("bad", "Search 1")
	tc.xcodeWord("UIDREQUIRED")
	tc.transactf("bad", "Store 1 Flags ()")
	tc.xcodeWord("UIDREQUIRED")
	tc.transactf("bad", "Copy 1 Archive")
	tc.xcodeWord("UIDREQUIRED")
	tc.transactf("bad", "Move 1 Archive")
	tc.xcodeWord("UIDREQUIRED")

	// Sequence numbers in search program.
	tc.transactf("bad", "Uid Search 1")
	tc.xcodeWord("UIDREQUIRED")

	// Sequence number in last qresync parameter.
	tc.transactf("ok", "Enable Qresync")
	tc.transactf("bad", "Select inbox (Qresync (1 5 (1,3,6 1,3,6)))")
	tc.xcodeWord("UIDREQUIRED")
	tc.client.Select("inbox") // Select again.

	// Breaks connection.
	tc.transactf("bad", "replace 1 inbox {1+}\r\nx")
	tc.xcodeWord("UIDREQUIRED")
}
