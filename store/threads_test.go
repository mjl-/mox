package store

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

func TestThreadingUpgrade(t *testing.T) {
	log := mlog.New("store", nil)
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	acc, err := OpenAccount(log, "mjl")
	tcheck(t, err, "open account")
	defer func() {
		err = acc.Close()
		tcheck(t, err, "closing account")
	}()
	defer Switchboard()()

	// New account already has threading. Add some messages, check the threading.
	deliver := func(recv time.Time, s string, expThreadID int64) Message {
		t.Helper()
		f, err := CreateMessageTemp(log, "account-test")
		tcheck(t, err, "temp file")
		defer os.Remove(f.Name())
		defer f.Close()

		s = strings.ReplaceAll(s, "\n", "\r\n")
		m := Message{
			Size:      int64(len(s)),
			MsgPrefix: []byte(s),
			Received:  recv,
		}
		err = acc.DeliverMailbox(log, "Inbox", &m, f)
		tcheck(t, err, "deliver")
		if expThreadID == 0 {
			expThreadID = m.ID
		}
		if m.ThreadID != expThreadID {
			t.Fatalf("got threadid %d, expected %d", m.ThreadID, expThreadID)
		}
		return m
	}

	now := time.Now()

	m0 := deliver(now, "Message-ID: <m0@localhost>\nSubject: test1\n\ntest\n", 0)
	m1 := deliver(now, "Message-ID: <m1@localhost>\nReferences: <m0@localhost>\nSubject: test1\n\ntest\n", m0.ID)  // References.
	m2 := deliver(now, "Message-ID: <m2@localhost>\nReferences: <m0@localhost>\nSubject: other\n\ntest\n", 0)      // References, but different subject.
	m3 := deliver(now, "Message-ID: <m3@localhost>\nIn-Reply-To: <m0@localhost>\nSubject: test1\n\ntest\n", m0.ID) // In-Reply-To.
	m4 := deliver(now, "Message-ID: <m4@localhost>\nSubject: re: test1\n\ntest\n", m0.ID)                          // Subject.
	m5 := deliver(now, "Message-ID: <m5@localhost>\nSubject: test1 (fwd)\n\ntest\n", m0.ID)                        // Subject.
	m6 := deliver(now, "Message-ID: <m6@localhost>\nSubject: [fwd: test1]\n\ntest\n", m0.ID)                       // Subject.
	m7 := deliver(now, "Message-ID: <m7@localhost>\nSubject: test1\n\ntest\n", 0)                                  // Only subject, but not a response.

	// Thread with a cyclic head, a self-referencing message.
	c1 := deliver(now, "Message-ID: <c1@localhost>\nReferences: <c2@localhost>\nSubject: cycle0\n\ntest\n", 0)     // Head cycle with m8.
	c2 := deliver(now, "Message-ID: <c2@localhost>\nReferences: <c1@localhost>\nSubject: cycle0\n\ntest\n", c1.ID) // Head cycle with c1.
	c3 := deliver(now, "Message-ID: <c3@localhost>\nReferences: <c1@localhost>\nSubject: cycle0\n\ntest\n", c1.ID) // Connected to one of the cycle elements.
	c4 := deliver(now, "Message-ID: <c4@localhost>\nReferences: <c2@localhost>\nSubject: cycle0\n\ntest\n", c1.ID) // Connected to other cycle element.
	c5 := deliver(now, "Message-ID: <c5@localhost>\nReferences: <c4@localhost>\nSubject: cycle0\n\ntest\n", c1.ID)
	c5b := deliver(now, "Message-ID: <c5@localhost>\nReferences: <c4@localhost>\nSubject: cycle0\n\ntest\n", c1.ID) // Duplicate, e.g. Sent item, internal cycle during upgrade.
	c6 := deliver(now, "Message-ID: <c6@localhost>\nReferences: <c5@localhost>\nSubject: cycle0\n\ntest\n", c1.ID)
	c7 := deliver(now, "Message-ID: <c7@localhost>\nReferences: <c5@localhost> <c7@localhost>\nSubject: cycle0\n\ntest\n", c1.ID) // Self-referencing message that also points to actual parent.

	// More than 2 messages to make a cycle.
	d0 := deliver(now, "Message-ID: <d0@localhost>\nReferences: <d2@localhost>\nSubject: cycle1\n\ntest\n", 0)
	d1 := deliver(now, "Message-ID: <d1@localhost>\nReferences: <d0@localhost>\nSubject: cycle1\n\ntest\n", d0.ID)
	d2 := deliver(now, "Message-ID: <d2@localhost>\nReferences: <d1@localhost>\nSubject: cycle1\n\ntest\n", d0.ID)

	// Cycle with messages delivered later. During import/upgrade, they will all be one thread.
	e0 := deliver(now, "Message-ID: <e0@localhost>\nReferences: <e1@localhost>\nSubject: cycle2\n\ntest\n", 0)
	e1 := deliver(now, "Message-ID: <e1@localhost>\nReferences: <e2@localhost>\nSubject: cycle2\n\ntest\n", 0)
	e2 := deliver(now, "Message-ID: <e2@localhost>\nReferences: <e0@localhost>\nSubject: cycle2\n\ntest\n", e0.ID)

	// Three messages in a cycle (f1, f2, f3), with one with an additional ancestor (f4) which is ignored due to the cycle. Has different threads during import.
	f0 := deliver(now, "Message-ID: <f0@localhost>\nSubject: cycle3\n\ntest\n", 0)
	f1 := deliver(now, "Message-ID: <f1@localhost>\nReferences: <f0@localhost> <f2@localhost>\nSubject: cycle3\n\ntest\n", f0.ID)
	f2 := deliver(now, "Message-ID: <f2@localhost>\nReferences: <f3@localhost>\nSubject: cycle3\n\ntest\n", 0)
	f3 := deliver(now, "Message-ID: <f3@localhost>\nReferences: <f1@localhost>\nSubject: cycle3\n\ntest\n", f0.ID)

	// Duplicate single message (no larger thread).
	g0 := deliver(now, "Message-ID: <g0@localhost>\nSubject: dup\n\ntest\n", 0)
	g0b := deliver(now, "Message-ID: <g0@localhost>\nSubject: dup\n\ntest\n", g0.ID)

	// Duplicate message with a child message.
	h0 := deliver(now, "Message-ID: <h0@localhost>\nSubject: dup2\n\ntest\n", 0)
	h0b := deliver(now, "Message-ID: <h0@localhost>\nSubject: dup2\n\ntest\n", h0.ID)
	h1 := deliver(now, "Message-ID: <h1@localhost>\nReferences: <h0@localhost>\nSubject: dup2\n\ntest\n", h0.ID)

	// Message has itself as reference.
	s0 := deliver(now, "Message-ID: <s0@localhost>\nReferences: <s0@localhost>\nSubject: self-referencing message\n\ntest\n", 0)

	// Message with \0 in subject, should get an empty base subject.
	b0 := deliver(now, "Message-ID: <b0@localhost>\nSubject: bad\u0000subject\n\ntest\n", 0)
	b1 := deliver(now, "Message-ID: <b1@localhost>\nSubject: bad\u0000subject\n\ntest\n", 0) // Not matched.

	// Interleaved duplicate threaded messages. First child, then parent, then duplicate parent, then duplicat child again.
	i0 := deliver(now, "Message-ID: <i0@localhost>\nReferences: <i1@localhost>\nSubject: interleaved duplicate\n\ntest\n", 0)
	i1 := deliver(now, "Message-ID: <i1@localhost>\nSubject: interleaved duplicate\n\ntest\n", 0)
	i2 := deliver(now, "Message-ID: <i1@localhost>\nSubject: interleaved duplicate\n\ntest\n", i1.ID)
	i3 := deliver(now, "Message-ID: <i0@localhost>\nReferences: <i1@localhost>\nSubject: interleaved duplicate\n\ntest\n", i0.ID)

	j0 := deliver(now, "Message-ID: <j0@localhost>\nReferences: <>\nSubject: empty id in references\n\ntest\n", 0)

	dbpath := acc.DBPath
	err = acc.Close()
	tcheck(t, err, "close account")

	// Now clear the threading upgrade, and the threading fields and close the account.
	// We open the database file directly, so we don't trigger the consistency checker.
	db, err := bstore.Open(ctxbg, dbpath, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, DBTypes...)
	err = db.Write(ctxbg, func(tx *bstore.Tx) error {
		up := Upgrade{ID: 1}
		err := tx.Delete(&up)
		tcheck(t, err, "delete upgrade")

		q := bstore.QueryTx[Message](tx)
		_, err = q.UpdateFields(map[string]any{
			"MessageID":         "",
			"SubjectBase":       "",
			"ThreadID":          int64(0),
			"ThreadParentIDs":   []int64(nil),
			"ThreadMissingLink": false,
		})
		return err
	})
	tcheck(t, err, "reset threading fields")
	err = db.Close()
	tcheck(t, err, "closing db")

	// Open the account again, that should get the account upgraded. Wait for upgrade to finish.
	acc, err = OpenAccount(log, "mjl")
	tcheck(t, err, "open account")
	err = acc.ThreadingWait(log)
	tcheck(t, err, "wait for threading")

	check := func(id int64, expThreadID int64, expParentIDs []int64, expMissingLink bool) {
		t.Helper()

		m := Message{ID: id}
		err := acc.DB.Get(ctxbg, &m)
		tcheck(t, err, "get message")
		if m.ThreadID != expThreadID || !reflect.DeepEqual(m.ThreadParentIDs, expParentIDs) || m.ThreadMissingLink != expMissingLink {
			t.Fatalf("got thread id %d, parent ids %v, missing link %v, expected %d %v %v", m.ThreadID, m.ThreadParentIDs, m.ThreadMissingLink, expThreadID, expParentIDs, expMissingLink)
		}
	}

	parents0 := []int64{m0.ID}
	check(m0.ID, m0.ID, nil, false)
	check(m1.ID, m0.ID, parents0, false)
	check(m2.ID, m2.ID, nil, true)
	check(m3.ID, m0.ID, parents0, false)
	check(m4.ID, m0.ID, parents0, true)
	check(m5.ID, m0.ID, parents0, true)
	check(m6.ID, m0.ID, parents0, true)
	check(m7.ID, m7.ID, nil, false)

	check(c1.ID, c1.ID, nil, true) // Head of cycle, hence missing link
	check(c2.ID, c1.ID, []int64{c1.ID}, false)
	check(c3.ID, c1.ID, []int64{c1.ID}, false)
	check(c4.ID, c1.ID, []int64{c2.ID, c1.ID}, false)
	check(c5.ID, c1.ID, []int64{c4.ID, c2.ID, c1.ID}, false)
	check(c5b.ID, c1.ID, []int64{c5.ID, c4.ID, c2.ID, c1.ID}, true)
	check(c6.ID, c1.ID, []int64{c5.ID, c4.ID, c2.ID, c1.ID}, false)
	check(c7.ID, c1.ID, []int64{c5.ID, c4.ID, c2.ID, c1.ID}, true)

	check(d0.ID, d0.ID, nil, true)
	check(d1.ID, d0.ID, []int64{d0.ID}, false)
	check(d2.ID, d0.ID, []int64{d1.ID, d0.ID}, false)

	check(e0.ID, e0.ID, nil, true)
	check(e1.ID, e0.ID, []int64{e2.ID, e0.ID}, false)
	check(e2.ID, e0.ID, []int64{e0.ID}, false)

	check(f0.ID, f0.ID, nil, false)
	check(f1.ID, f1.ID, nil, true)
	check(f2.ID, f1.ID, []int64{f3.ID, f1.ID}, false)
	check(f3.ID, f1.ID, []int64{f1.ID}, false)

	check(g0.ID, g0.ID, nil, false)
	check(g0b.ID, g0.ID, []int64{g0.ID}, true)

	check(h0.ID, h0.ID, nil, false)
	check(h0b.ID, h0.ID, []int64{h0.ID}, true)
	check(h1.ID, h0.ID, []int64{h0.ID}, false)

	check(s0.ID, s0.ID, nil, true)

	check(b0.ID, b0.ID, nil, false)
	check(b1.ID, b1.ID, nil, false)

	check(i0.ID, i1.ID, []int64{i1.ID}, false)
	check(i1.ID, i1.ID, nil, false)
	check(i2.ID, i1.ID, []int64{i1.ID}, true)
	check(i3.ID, i1.ID, []int64{i0.ID, i1.ID}, true)

	check(j0.ID, j0.ID, nil, false)
}
