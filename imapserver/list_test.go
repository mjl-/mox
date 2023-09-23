package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/store"
)

func TestListBasic(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", "testtest")

	ulist := func(name string, flags ...string) imapclient.UntaggedList {
		if len(flags) == 0 {
			flags = nil
		}
		return imapclient.UntaggedList{Flags: flags, Separator: '/', Mailbox: name}
	}

	tc.last(tc.client.List("INBOX"))
	tc.xuntagged(ulist("Inbox"))

	tc.last(tc.client.List("Inbox"))
	tc.xuntagged(ulist("Inbox"))

	tc.last(tc.client.List("%"))
	tc.xuntagged(ulist("Archive", `\Archive`), ulist("Drafts", `\Drafts`), ulist("Inbox"), ulist("Junk", `\Junk`), ulist("Sent", `\Sent`), ulist("Trash", `\Trash`))

	tc.last(tc.client.List("*"))
	tc.xuntagged(ulist("Archive", `\Archive`), ulist("Drafts", `\Drafts`), ulist("Inbox"), ulist("Junk", `\Junk`), ulist("Sent", `\Sent`), ulist("Trash", `\Trash`))

	tc.last(tc.client.List("A*"))
	tc.xuntagged(ulist("Archive", `\Archive`))

	tc.client.Create("Inbox/todo")

	tc.last(tc.client.List("Inbox*"))
	tc.xuntagged(ulist("Inbox"), ulist("Inbox/todo"))

	tc.last(tc.client.List("Inbox/%"))
	tc.xuntagged(ulist("Inbox/todo"))

	tc.last(tc.client.List("Inbox/*"))
	tc.xuntagged(ulist("Inbox/todo"))

	// Leading full INBOX is turned into Inbox, so mailbox matches.
	tc.last(tc.client.List("INBOX/*"))
	tc.xuntagged(ulist("Inbox/todo"))

	// No match because we are only touching various casings of the full "INBOX".
	tc.last(tc.client.List("INBO*"))
	tc.xuntagged()
}

func TestListExtended(t *testing.T) {
	defer mockUIDValidity()()

	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", "testtest")

	ulist := func(name string, flags ...string) imapclient.UntaggedList {
		if len(flags) == 0 {
			flags = nil
		}
		return imapclient.UntaggedList{Flags: flags, Separator: '/', Mailbox: name}
	}

	uidvals := map[string]uint32{}
	use := store.DefaultInitialMailboxes.SpecialUse
	for _, name := range []string{"Inbox", use.Archive, use.Draft, use.Junk, use.Sent, use.Trash} {
		uidvals[name] = 1
	}
	for _, name := range store.DefaultInitialMailboxes.Regular {
		uidvals[name] = 1
	}
	var uidvalnext uint32 = 2
	uidval := func(name string) uint32 {
		v, ok := uidvals[name]
		if !ok {
			v = uidvalnext
			uidvals[name] = v
			uidvalnext++
		}
		return v
	}

	ustatus := func(name string) imapclient.UntaggedStatus {
		attrs := map[string]int64{
			"MESSAGES":    0,
			"UIDNEXT":     1,
			"UIDVALIDITY": int64(uidval(name)),
			"UNSEEN":      0,
			"DELETED":     0,
			"SIZE":        0,
			"RECENT":      0,
			"APPENDLIMIT": 0,
		}
		return imapclient.UntaggedStatus{Mailbox: name, Attrs: attrs}
	}

	const (
		Fsubscribed    = `\Subscribed`
		Fhaschildren   = `\HasChildren`
		Fhasnochildren = `\HasNoChildren`
		Fnonexistent   = `\NonExistent`
		Farchive       = `\Archive`
		Fdraft         = `\Drafts`
		Fjunk          = `\Junk`
		Fsent          = `\Sent`
		Ftrash         = `\Trash`
	)

	// untaggedlist with flags subscribed and hasnochildren
	xlist := func(name string, flags ...string) imapclient.UntaggedList {
		flags = append([]string{Fhasnochildren, Fsubscribed}, flags...)
		return ulist(name, flags...)
	}

	xchildlist := func(name string, flags ...string) imapclient.UntaggedList {
		u := ulist(name, flags...)
		comp := imapclient.TaggedExtComp{String: "SUBSCRIBED"}
		u.Extended = []imapclient.MboxListExtendedItem{{Tag: "CHILDINFO", Val: imapclient.TaggedExtVal{Comp: &comp}}}
		return u
	}

	tc.last(tc.client.ListFull(false, "INBOX"))
	tc.xuntagged(xlist("Inbox"), ustatus("Inbox"))

	tc.last(tc.client.ListFull(false, "Inbox"))
	tc.xuntagged(xlist("Inbox"), ustatus("Inbox"))

	tc.last(tc.client.ListFull(false, "%"))
	tc.xuntagged(xlist("Archive", Farchive), ustatus("Archive"), xlist("Drafts", Fdraft), ustatus("Drafts"), xlist("Inbox"), ustatus("Inbox"), xlist("Junk", Fjunk), ustatus("Junk"), xlist("Sent", Fsent), ustatus("Sent"), xlist("Trash", Ftrash), ustatus("Trash"))

	tc.last(tc.client.ListFull(false, "*"))
	tc.xuntagged(xlist("Archive", Farchive), ustatus("Archive"), xlist("Drafts", Fdraft), ustatus("Drafts"), xlist("Inbox"), ustatus("Inbox"), xlist("Junk", Fjunk), ustatus("Junk"), xlist("Sent", Fsent), ustatus("Sent"), xlist("Trash", Ftrash), ustatus("Trash"))

	tc.last(tc.client.ListFull(false, "A*"))
	tc.xuntagged(xlist("Archive", Farchive), ustatus("Archive"))

	tc.last(tc.client.ListFull(false, "A*", "Junk"))
	tc.xuntagged(xlist("Archive", Farchive), ustatus("Archive"), xlist("Junk", Fjunk), ustatus("Junk"))

	tc.client.Create("Inbox/todo")

	tc.last(tc.client.ListFull(false, "Inbox*"))
	tc.xuntagged(ulist("Inbox", Fhaschildren, Fsubscribed), ustatus("Inbox"), xlist("Inbox/todo"), ustatus("Inbox/todo"))

	tc.last(tc.client.ListFull(false, "Inbox/%"))
	tc.xuntagged(xlist("Inbox/todo"), ustatus("Inbox/todo"))

	tc.last(tc.client.ListFull(false, "Inbox/*"))
	tc.xuntagged(xlist("Inbox/todo"), ustatus("Inbox/todo"))

	// Leading full INBOX is turned into Inbox, so mailbox matches.
	tc.last(tc.client.ListFull(false, "INBOX/*"))
	tc.xuntagged(xlist("Inbox/todo"), ustatus("Inbox/todo"))

	// No match because we are only touching various casings of the full "INBOX".
	tc.last(tc.client.ListFull(false, "INBO*"))
	tc.xuntagged()

	tc.last(tc.client.ListFull(true, "Inbox"))
	tc.xuntagged(xchildlist("Inbox", Fsubscribed, Fhaschildren), ustatus("Inbox"))

	tc.client.Unsubscribe("Inbox")
	tc.last(tc.client.ListFull(true, "Inbox"))
	tc.xuntagged(xchildlist("Inbox", Fhaschildren), ustatus("Inbox"))

	tc.client.Delete("Inbox/todo") // Still subscribed.
	tc.last(tc.client.ListFull(true, "Inbox"))
	tc.xuntagged(xchildlist("Inbox", Fhasnochildren), ustatus("Inbox"))

	// Simple extended list without RETURN options.
	tc.transactf("ok", `list "" ("inbox")`)
	tc.xuntagged(ulist("Inbox"))

	tc.transactf("ok", `list () "" ("inbox") return ()`)
	tc.xuntagged(ulist("Inbox"))

	tc.transactf("ok", `list "" ("inbox") return ()`)
	tc.xuntagged(ulist("Inbox"))

	tc.transactf("ok", `list () "" ("inbox")`)
	tc.xuntagged(ulist("Inbox"))

	tc.transactf("ok", `list (remote) "" ("inbox")`)
	tc.xuntagged(ulist("Inbox"))

	tc.transactf("ok", `list (remote) "" "/inbox"`)
	tc.xuntagged()

	tc.transactf("ok", `list (remote) "/inbox" ""`)
	tc.xuntagged()

	tc.transactf("ok", `list (remote) "inbox" ""`)
	tc.xuntagged()

	tc.transactf("ok", `list (remote) "inbox" "a"`)
	tc.xuntagged()

	tc.client.Create("inbox/a")
	tc.transactf("ok", `list (remote) "inbox" "a"`)
	tc.xuntagged(ulist("Inbox/a"))

	tc.client.Subscribe("x")
	tc.transactf("ok", `list (subscribed) "" x return (subscribed)`)
	tc.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`, `\NonExistent`}, Separator: '/', Mailbox: "x"})

	tc.transactf("bad", `list (recursivematch) "" "*"`)        // Cannot have recursivematch without a base selection option like subscribed.
	tc.transactf("bad", `list (recursivematch remote) "" "*"`) // "remote" is not a base selection option.
	tc.transactf("bad", `list (unknown) "" "*"`)               // Unknown selection options must result in BAD.
	tc.transactf("bad", `list () "" "*" return (unknown)`)     // Unknown return options must result in BAD.
}
