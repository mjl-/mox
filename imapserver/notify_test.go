package imapserver

import (
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/store"
)

func TestNotify(t *testing.T) {
	testNotify(t, false)
}

func TestNotifyUIDOnly(t *testing.T) {
	testNotify(t, true)
}

func testNotify(t *testing.T, uidonly bool) {
	defer mockUIDValidity()()
	tc := start(t, uidonly)
	defer tc.close()
	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	// Check for some invalid syntax.
	tc.transactf("bad", "Notify")
	tc.transactf("bad", "Notify bogus")
	tc.transactf("bad", "Notify None ") // Trailing space.
	tc.transactf("bad", "Notify Set")
	tc.transactf("bad", "Notify Set ")
	tc.transactf("bad", "Notify Set Status")
	tc.transactf("bad", "Notify Set Status ()") // Empty list.
	tc.transactf("bad", "Notify Set Status (UnknownSpecifier (messageNew))")
	tc.transactf("bad", "Notify Set Status (Personal messageNew)")    // Missing list around events.
	tc.transactf("bad", "Notify Set Status (Personal (messageNew) )") // Trailing space.
	tc.transactf("bad", "Notify Set Status (Personal (messageNew)) ") // Trailing space.

	tc.transactf("bad", "Notify Set Status (Selected (mailboxName))")                                  // MailboxName not allowed on Selected.
	tc.transactf("bad", "Notify Set Status (Selected (messageNew))")                                   // MessageNew must come with MessageExpunge.
	tc.transactf("bad", "Notify Set Status (Selected (flagChange))")                                   // flagChange must come with MessageNew and MessageExpunge.
	tc.transactf("bad", "Notify Set Status (Selected (mailboxName)) (Selected-Delayed (mailboxName))") // Duplicate selected.
	tc.transactf("no", "Notify Set Status (Selected (annotationChange))")                              // We don't implement annotation change.
	tc.xcode(imapclient.CodeBadEvent{"MessageNew", "MessageExpunge", "FlagChange", "MailboxName", "SubscriptionChange", "MailboxMetadataChange", "ServerMetadataChange"})
	tc.transactf("no", "Notify Set Status (Personal (unknownEvent))")
	tc.xcode(imapclient.CodeBadEvent{"MessageNew", "MessageExpunge", "FlagChange", "MailboxName", "SubscriptionChange", "MailboxMetadataChange", "ServerMetadataChange"})

	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()
	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	var modseq uint32 = 4

	// Check that we don't get pending changes when we set "notify none". We first make
	// changes that we drain with noop. Then add new pending changes and execute
	// "notify none". Server should still process changes to the message sequence
	// numbers of the selected mailbox.
	tc2.client.Append("inbox", makeAppend(searchMsg)) // Results in exists and fetch.
	modseq++
	tc2.client.Append("Junk", makeAppend(searchMsg)) // Not selected, not mentioned.
	modseq++
	tc.transactf("ok", "noop")
	tc.xuntagged(
		imapclient.UntaggedExists(1),
		tc.untaggedFetch(1, 1, imapclient.FetchFlags(nil)),
	)
	tc2.client.UIDStoreFlagsAdd("1:*", true, `\Deleted`)
	modseq++
	tc2.client.Expunge()
	modseq++
	tc.transactf("ok", "Notify None")
	tc.xuntagged() // No untagged responses for delete/expunge.

	// Enable notify, will first result in a the pending changes, then status.
	tc.transactf("ok", "Notify Set Status (Selected (messageNew (Uid Modseq Bodystructure Preview) messageExpunge flagChange)) (personal (messageNew messageExpunge flagChange mailboxName subscriptionChange mailboxMetadataChange serverMetadataChange))")
	tc.xuntagged(
		imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeHighestModSeq(modseq), Text: "after condstore-enabling command"},
		// note: no status for Inbox since it is selected.
		imapclient.UntaggedStatus{Mailbox: "Drafts", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 0, imapclient.StatusUIDNext: 1, imapclient.StatusUIDValidity: 1, imapclient.StatusUnseen: 0, imapclient.StatusHighestModSeq: 2}},
		imapclient.UntaggedStatus{Mailbox: "Sent", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 0, imapclient.StatusUIDNext: 1, imapclient.StatusUIDValidity: 1, imapclient.StatusUnseen: 0, imapclient.StatusHighestModSeq: 2}},
		imapclient.UntaggedStatus{Mailbox: "Archive", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 0, imapclient.StatusUIDNext: 1, imapclient.StatusUIDValidity: 1, imapclient.StatusUnseen: 0, imapclient.StatusHighestModSeq: 2}},
		imapclient.UntaggedStatus{Mailbox: "Trash", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 0, imapclient.StatusUIDNext: 1, imapclient.StatusUIDValidity: 1, imapclient.StatusUnseen: 0, imapclient.StatusHighestModSeq: 2}},
		imapclient.UntaggedStatus{Mailbox: "Junk", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1, imapclient.StatusUIDNext: 2, imapclient.StatusUIDValidity: 1, imapclient.StatusUnseen: 1, imapclient.StatusHighestModSeq: int64(modseq - 2)}},
	)

	// Selecting the mailbox again results in a refresh of the message sequence
	// numbers, with the deleted message gone (it wasn't acknowledged yet due to
	// "notify none").
	tc.client.Select("inbox")

	// Add message, should result in EXISTS and FETCH with the configured attributes.
	tc2.client.Append("inbox", makeAppend(searchMsg))
	modseq++
	tc.readuntagged(
		imapclient.UntaggedExists(1),
		tc.untaggedFetchUID(1, 2,
			imapclient.FetchBodystructure{
				RespAttr: "BODYSTRUCTURE",
				Body: imapclient.BodyTypeMpart{
					Bodies: []any{
						imapclient.BodyTypeText{
							MediaType:    "TEXT",
							MediaSubtype: "PLAIN",
							BodyFields: imapclient.BodyFields{
								Params: [][2]string{[...]string{"CHARSET", "utf-8"}},
								Octets: 21,
							},
							Lines: 1,
							Ext: &imapclient.BodyExtension1Part{
								Disposition:       ptr((*string)(nil)),
								DispositionParams: ptr([][2]string(nil)),
								Language:          ptr([]string(nil)),
								Location:          ptr((*string)(nil)),
							},
						},
						imapclient.BodyTypeText{
							MediaType:    "TEXT",
							MediaSubtype: "HTML",
							BodyFields: imapclient.BodyFields{
								Params: [][2]string{[...]string{"CHARSET", "utf-8"}},
								Octets: 15,
							},
							Lines: 1,
							Ext: &imapclient.BodyExtension1Part{
								Disposition:       ptr((*string)(nil)),
								DispositionParams: ptr([][2]string(nil)),
								Language:          ptr([]string(nil)),
								Location:          ptr((*string)(nil)),
							},
						},
					},
					MediaSubtype: "ALTERNATIVE",
					Ext: &imapclient.BodyExtensionMpart{
						Params:            [][2]string{{"BOUNDARY", "x"}},
						Disposition:       ptr((*string)(nil)), // Present but nil.
						DispositionParams: ptr([][2]string(nil)),
						Language:          ptr([]string(nil)),
						Location:          ptr((*string)(nil)),
					},
				},
			},
			imapclient.FetchPreview{Preview: ptr("this is plain text.")},
			imapclient.FetchModSeq(modseq),
		),
	)

	// Change flags.
	tc2.client.UIDStoreFlagsAdd("1:*", true, `\Deleted`)
	modseq++
	tc.readuntagged(tc.untaggedFetch(1, 2, imapclient.FetchFlags{`\Deleted`}, imapclient.FetchModSeq(modseq)))

	// Remove message.
	tc2.client.Expunge()
	modseq++
	if uidonly {
		tc.readuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("2")})
	} else {
		tc.readuntagged(imapclient.UntaggedExpunge(1))
	}

	// MailboxMetadataChange for mailbox annotation.
	tc2.transactf("ok", `setmetadata Archive (/private/comment "test")`)
	modseq++
	tc.readuntagged(
		imapclient.UntaggedMetadataKeys{Mailbox: "Archive", Keys: []string{"/private/comment"}},
	)

	// MailboxMetadataChange also for the selected Inbox.
	tc2.transactf("ok", `setmetadata Inbox (/private/comment "test")`)
	modseq++
	tc.readuntagged(
		imapclient.UntaggedMetadataKeys{Mailbox: "Inbox", Keys: []string{"/private/comment"}},
	)

	// ServerMetadataChange for server annotation.
	tc2.transactf("ok", `setmetadata "" (/private/vendor/other/x "test")`)
	modseq++
	tc.readuntagged(
		imapclient.UntaggedMetadataKeys{Mailbox: "", Keys: []string{"/private/vendor/other/x"}},
	)

	// SubscriptionChange for new subscription.
	tc2.client.Subscribe("doesnotexist")
	tc.readuntagged(
		imapclient.UntaggedList{Mailbox: "doesnotexist", Separator: '/', Flags: []string{`\Subscribed`, `\NonExistent`}},
	)

	// SubscriptionChange for removed subscription.
	tc2.client.Unsubscribe("doesnotexist")
	tc.readuntagged(
		imapclient.UntaggedList{Mailbox: "doesnotexist", Separator: '/', Flags: []string{`\NonExistent`}},
	)

	// SubscriptionChange for selected mailbox.
	tc2.client.Unsubscribe("Inbox")
	tc2.client.Subscribe("Inbox")
	tc.readuntagged(
		imapclient.UntaggedList{Mailbox: "Inbox", Separator: '/'},
		imapclient.UntaggedList{Mailbox: "Inbox", Separator: '/', Flags: []string{`\Subscribed`}},
	)

	// MailboxName for creating mailbox.
	tc2.client.Create("newbox", nil)
	modseq++
	tc.readuntagged(
		imapclient.UntaggedList{Mailbox: "newbox", Separator: '/', Flags: []string{`\Subscribed`}},
	)

	// MailboxName for renaming mailbox.
	tc2.client.Rename("newbox", "oldbox")
	modseq++
	tc.readuntagged(
		imapclient.UntaggedList{Mailbox: "oldbox", Separator: '/', OldName: "newbox"},
	)

	// MailboxName for deleting mailbox.
	tc2.client.Delete("oldbox")
	modseq++
	tc.readuntagged(
		imapclient.UntaggedList{Mailbox: "oldbox", Separator: '/', Flags: []string{`\NonExistent`}},
	)

	// Add message again to check for modseq. First set notify again with fewer fetch
	// attributes for simpler checking.
	tc.transactf("ok", "Notify Set (personal (messageNew messageExpunge flagChange mailboxName subscriptionChange mailboxMetadataChange serverMetadataChange)) (Selected (messageNew (Uid Modseq) messageExpunge flagChange))")
	tc2.client.Append("inbox", makeAppend(searchMsg))
	modseq++
	tc.readuntagged(
		imapclient.UntaggedExists(1),
		tc.untaggedFetchUID(1, 3, imapclient.FetchModSeq(modseq)),
	)

	// Next round of events must be ignored. We shouldn't get anything until we add a
	// message to "testbox".
	tc.transactf("ok", "Notify Set (Selected None) (mailboxes testbox (messageNew messageExpunge)) (personal None)")
	tc2.client.Append("inbox", makeAppend(searchMsg)) // MessageNew
	modseq++
	tc2.client.UIDStoreFlagsAdd("1:*", true, `\Deleted`) // FlagChange
	modseq++
	tc2.client.Expunge() // MessageExpunge
	modseq++
	tc2.transactf("ok", `setmetadata Archive (/private/comment "test2")`) // MailboxMetadataChange
	modseq++
	tc2.transactf("ok", `setmetadata "" (/private/vendor/other/x "test2")`) // ServerMetadataChange
	modseq++
	tc2.client.Subscribe("doesnotexist2")   // SubscriptionChange
	tc2.client.Unsubscribe("doesnotexist2") // SubscriptionChange
	tc2.client.Create("newbox2", nil)       // MailboxName
	modseq++
	tc2.client.Rename("newbox2", "oldbox2") // MailboxName
	modseq++
	tc2.client.Delete("oldbox2") // MailboxName
	modseq++
	// Now trigger receiving a notification.
	tc2.client.Create("testbox", nil) // MailboxName
	modseq++
	tc2.client.Append("testbox", makeAppend(searchMsg)) // MessageNew
	modseq++
	tc.readuntagged(
		imapclient.UntaggedStatus{Mailbox: "testbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1, imapclient.StatusUIDNext: 2, imapclient.StatusUnseen: 1, imapclient.StatusHighestModSeq: int64(modseq)}},
	)

	// Test filtering per mailbox specifier. We create two mailboxes.
	tc.client.Create("inbox/a/b", nil)
	modseq++
	tc.client.Create("other/a/b", nil)
	modseq++
	tc.client.Unsubscribe("other/a/b")

	// Inboxes
	tc3 := startNoSwitchboard(t, uidonly)
	defer tc3.closeNoWait()
	tc3.login("mjl@mox.example", password0)
	tc3.transactf("ok", "Notify Set (Inboxes (messageNew messageExpunge))")

	// Subscribed
	tc4 := startNoSwitchboard(t, uidonly)
	defer tc4.closeNoWait()
	tc4.login("mjl@mox.example", password0)
	tc4.transactf("ok", "Notify Set (Subscribed (messageNew messageExpunge))")

	// Subtree
	tc5 := startNoSwitchboard(t, uidonly)
	defer tc5.closeNoWait()
	tc5.login("mjl@mox.example", password0)
	tc5.transactf("ok", "Notify Set (Subtree (Nonexistent inbox) (messageNew messageExpunge))")

	// Subtree-One
	tc6 := startNoSwitchboard(t, uidonly)
	defer tc6.closeNoWait()
	tc6.login("mjl@mox.example", password0)
	tc6.transactf("ok", "Notify Set (Subtree-One (Nonexistent Inbox/a other) (messageNew messageExpunge))")

	// We append to other/a/b first. It would normally come first in the notifications,
	// but we check we only get the second event.
	tc2.client.Append("other/a/b", makeAppend(searchMsg))
	modseq++
	tc2.client.Append("inbox/a/b", makeAppend(searchMsg))
	modseq++

	// No highestmodseq, these connections don't have CONDSTORE enabled.
	tc3.readuntagged(
		imapclient.UntaggedStatus{Mailbox: "Inbox/a/b", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1, imapclient.StatusUIDNext: 2, imapclient.StatusUnseen: 1}},
	)
	tc4.readuntagged(
		imapclient.UntaggedStatus{Mailbox: "Inbox/a/b", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1, imapclient.StatusUIDNext: 2, imapclient.StatusUnseen: 1}},
	)
	tc5.readuntagged(
		imapclient.UntaggedStatus{Mailbox: "Inbox/a/b", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1, imapclient.StatusUIDNext: 2, imapclient.StatusUnseen: 1}},
	)
	tc6.readuntagged(
		imapclient.UntaggedStatus{Mailbox: "Inbox/a/b", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1, imapclient.StatusUIDNext: 2, imapclient.StatusUnseen: 1}},
	)

	// Test for STATUS events on non-selected mailbox for message events.
	tc.transactf("ok", "notify set (personal (messageNew messageExpunge flagChange))")
	tc.client.Unselect()
	tc2.client.Create("statusbox", nil)
	modseq++
	tc2.client.Append("statusbox", makeAppend(searchMsg))
	modseq++
	tc.readuntagged(
		imapclient.UntaggedStatus{Mailbox: "statusbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1, imapclient.StatusUIDNext: 2, imapclient.StatusUnseen: 1, imapclient.StatusHighestModSeq: int64(modseq)}},
	)

	// With Selected-Delayed, we only get the events for the selected mailbox for
	// explicit commands. We still get other events.
	tc.transactf("ok", "notify set (selected-delayed (messageNew messageExpunge flagChange)) (personal (messageNew messageExpunge flagChange))")
	tc.client.Select("statusbox")
	tc2.client.Append("inbox", makeAppend(searchMsg))
	modseq++
	tc2.client.UIDStoreFlagsSet("*", true, `\Seen`)
	modseq++
	tc2.client.Append("statusbox", imapclient.Append{Flags: []string{"newflag"}, Size: int64(len(searchMsg)), Data: strings.NewReader(searchMsg)})
	modseq++
	tc2.client.Select("statusbox")

	tc.readuntagged(
		imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1, imapclient.StatusUIDNext: 6, imapclient.StatusUnseen: 1, imapclient.StatusHighestModSeq: int64(modseq - 2)}},
		imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusUIDValidity: 1, imapclient.StatusUnseen: 0, imapclient.StatusHighestModSeq: int64(modseq - 1)}},
	)

	tc.transactf("ok", "noop")
	tc.xuntagged(
		imapclient.UntaggedExists(2),
		tc.untaggedFetch(2, 2, imapclient.FetchFlags{"newflag"}, imapclient.FetchModSeq(modseq)),
		imapclient.UntaggedFlags{`\Seen`, `\Answered`, `\Flagged`, `\Deleted`, `\Draft`, `$Forwarded`, `$Junk`, `$NotJunk`, `$Phishing`, `$MDNSent`, `newflag`},
	)

	tc2.client.UIDStoreFlagsSet("2", true, `\Deleted`)
	modseq++
	tc2.client.Expunge()
	modseq++
	tc.transactf("ok", "noop")
	if uidonly {
		tc.xuntagged(
			tc.untaggedFetch(2, 2, imapclient.FetchFlags{`\Deleted`}, imapclient.FetchModSeq(modseq-1)),
			imapclient.UntaggedVanished{UIDs: xparseNumSet("2")},
		)
	} else {
		tc.xuntagged(
			tc.untaggedFetch(2, 2, imapclient.FetchFlags{`\Deleted`}, imapclient.FetchModSeq(modseq-1)),
			imapclient.UntaggedExpunge(2),
		)
	}

	// With Selected-Delayed, we should get events for selected mailboxes immediately when using IDLE.
	tc2.client.UIDStoreFlagsSet("*", true, `\Answered`)
	modseq++
	tc2.client.Select("inbox")
	tc2.client.UIDStoreFlagsClear("*", true, `\Seen`)
	modseq++
	tc2.client.Select("statusbox")

	tc.readuntagged(
		imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusUIDValidity: 1, imapclient.StatusUnseen: 1, imapclient.StatusHighestModSeq: int64(modseq)}},
	)

	tc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	tc.cmdf("", "idle")
	tc.readprefixline("+ ")
	tc.readuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{`\Answered`}, imapclient.FetchModSeq(modseq-1)))
	tc.writelinef("done")
	tc.response("ok")
	tc.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// If any event matches, we normally return it. But NONE prevents looking further.
	tc.client.Unselect()
	tc.transactf("ok", "notify set (mailboxes statusbox NONE) (personal (mailboxName))")
	tc2.client.UIDStoreFlagsSet("*", true, `\Answered`) // Matches NONE, ignored.
	//modseq++
	tc2.client.Create("eventbox", nil)
	//modseq++
	tc.readuntagged(
		imapclient.UntaggedList{Mailbox: "eventbox", Separator: '/', Flags: []string{`\Subscribed`}},
	)

	// Check we can return message contents.
	tc.transactf("ok", "notify set (selected (messageNew (body[header] body[text]) messageExpunge))")
	tc.client.Select("statusbox")
	tc2.client.Append("statusbox", makeAppend(searchMsg))
	// modseq++
	offset := strings.Index(searchMsg, "\r\n\r\n")
	tc.readuntagged(
		imapclient.UntaggedExists(2),
		tc.untaggedFetch(2, 3,
			imapclient.FetchBody{
				RespAttr: "BODY[HEADER]",
				Section:  "HEADER",
				Body:     searchMsg[:offset+4],
			},
			imapclient.FetchBody{
				RespAttr: "BODY[TEXT]",
				Section:  "TEXT",
				Body:     searchMsg[offset+4:],
			},
			imapclient.FetchFlags(nil),
		),
	)

	// If we encounter an error during fetch, an untagged NO is returned.
	// We ask for the 2nd part of a message, and we add a message with just 1 part.
	tc.transactf("ok", "notify set (selected (messageNew (body[2]) messageExpunge))")
	tc2.client.Append("statusbox", makeAppend(exampleMsg))
	// modseq++
	tc.readuntagged(
		imapclient.UntaggedExists(3),
		imapclient.UntaggedResult{Status: "NO", Text: "generating notify fetch response: requested part does not exist"},
		tc.untaggedFetchUID(3, 4),
	)

	// When adding new tests, uncomment modseq++ lines above.
}

func TestNotifyOverflow(t *testing.T) {
	testNotifyOverflow(t, false)
}

func TestNotifyOverflowUIDOnly(t *testing.T) {
	testNotifyOverflow(t, true)
}

func testNotifyOverflow(t *testing.T, uidonly bool) {
	orig := store.CommPendingChangesMax
	store.CommPendingChangesMax = 3
	defer func() {
		store.CommPendingChangesMax = orig
	}()

	defer mockUIDValidity()()
	tc := start(t, uidonly)
	defer tc.close()
	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")
	tc.transactf("ok", "noop")

	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()
	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	// Generates 4 changes, crossing max 3.
	tc2.client.Append("inbox", makeAppend(searchMsg))
	tc2.client.Append("inbox", makeAppend(searchMsg))

	tc.transactf("ok", "noop")
	tc.xuntagged(imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeWord("NOTIFICATIONOVERFLOW"), Text: "out of sync after too many pending changes"})

	// Won't be getting any more notifications until we enable them again with NOTIFY.
	tc2.client.Append("inbox", makeAppend(searchMsg))
	tc.transactf("ok", "noop")
	tc.xuntagged()

	// Enable notify again. Without uidonly, we won't get a notification because the
	// message isn't known in the session.
	tc.transactf("ok", "notify set (selected (messageNew messageExpunge flagChange))")
	tc2.client.UIDStoreFlagsAdd("1", true, `\Seen`)
	if uidonly {
		tc.readuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{`\Seen`}))
	} else {
		tc.transactf("ok", "noop")
		tc.xuntagged()
	}

	// Reselect to get the message visible in the session.
	tc.client.Select("inbox")
	tc2.client.UIDStoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "noop")
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags(nil)))

	// Trigger overflow for changes for "selected-delayed".
	store.CommPendingChangesMax = 10
	delayedMax := selectedDelayedChangesMax
	selectedDelayedChangesMax = 1
	defer func() {
		selectedDelayedChangesMax = delayedMax
	}()
	tc.transactf("ok", "notify set (selected-delayed (messageNew messageExpunge flagChange))")
	tc2.client.UIDStoreFlagsAdd("1", true, `\Seen`)
	tc2.client.UIDStoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "noop")
	tc.xuntagged(imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeWord("NOTIFICATIONOVERFLOW"), Text: "out of sync after too many pending changes for selected mailbox"})

	// Again, no new notifications until we select and enable again.
	tc2.client.UIDStoreFlagsAdd("1", true, `\Seen`)
	tc.transactf("ok", "noop")
	tc.xuntagged()

	tc.client.Select("inbox")
	tc.transactf("ok", "notify set (selected-delayed (messageNew messageExpunge flagChange))")
	tc2.client.UIDStoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "noop")
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags(nil)))
}
