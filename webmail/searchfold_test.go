package webmail

import (
	"mime"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

func TestSearchFoldLatin(t *testing.T) {
	os.RemoveAll("../testdata/webmail/data")
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/webmail/mox.conf")
	mox.MustLoadConfig(true, false)
	tcheck(t, store.Init(ctxbg), "store init")
	defer func() { tcheck(t, store.Close(), "store close") }()
	defer store.Switchboard()()
	acc, err := store.OpenAccount(pkglog, "mjl", false)
	tcheck(t, err, "open account")
	defer func() {
		tcheck(t, acc.Close(), "close account")
		acc.WaitClosed()
	}()

	texts := []string{"Příliš Straße Łódź Ľúbim", "Prilis Strasse Lodz Lubim", "Pr\u030ci\u0301lis\u030c Straße Ło\u0301dz\u0301 L\u030cu\u0301bim"}
	var msgs []*testmsg
	for _, text := range texts {
		hdr := mime.QEncoding.Encode("utf-8", text)
		tm := &testmsg{Mailbox: "Inbox", msg: Message{
			From: hdr + " <sender@mox.example>", To: hdr + " <to@mox.example>",
			Subject: hdr, Headers: [][2]string{{"X-Name", hdr}},
			Part: Part{Type: "text/plain; charset=utf-8", Content: text + " й ё"},
		}}
		tdeliver(t, acc, tm)
		msgs = append(msgs, tm)
	}
	conf, _ := acc.Conf()
	if conf.SearchFoldLatin {
		t.Fatal("folding enabled by default")
	}

	check := func(q Query, expected []int64) {
		t.Helper()
		q.Threading = ThreadOff
		q.OrderAsc = true
		v := view{Request: Request{Query: q, Page: Page{Count: 10}}}
		responses := make(chan msgResp, 10)
		err := acc.DB.Read(ctxbg, func(tx *bstore.Tx) error {
			queryMessages(ctxbg, pkglog, acc, tx, v, responses, nil)
			return nil
		})
		tcheck(t, err, "query messages")
		var ids []int64
		for r := range responses {
			tcheck(t, r.err, "query result")
			for _, mi := range r.mil {
				ids = append(ids, mi.Message.ID)
			}
		}
		if !slices.Equal(ids, expected) {
			t.Fatalf("query %+v: got %v, want %v", q, ids, expected)
		}
		// Live view updates must use the same account setting and matching rules.
		for _, tm := range msgs {
			m := tm.m
			got, err := v.matches(pkglog, acc, false, m.ID, m.MailboxID, m.UID, m.Flags, m.Keywords, func(int64, int64, store.UID) (store.Message, error) { return m, nil })
			tcheck(t, err, "live view match")
			if got != slices.Contains(expected, m.ID) {
				t.Fatalf("live view query %+v, message %d: got %v", q, m.ID, got)
			}
		}
	}

	for _, enabled := range []bool{false, true, false} {
		unlock := mox.Conf.DynamicLockUnlock()
		conf.SearchFoldLatin = enabled
		mox.Conf.Dynamic.Accounts["mjl"] = conf
		unlock()
		for i, text := range texts {
			var expected, excluded []int64
			for j, tm := range msgs {
				if enabled || i == j {
					expected = append(expected, tm.ID)
				} else {
					excluded = append(excluded, tm.ID)
				}
			}
			for _, f := range []Filter{
				{Words: []string{text}}, {Subject: []string{text}}, {From: []string{text}},
				{To: []string{text}}, {Headers: [][2]string{{"X-Name", text}}},
			} {
				check(Query{Filter: f}, expected)
			}
			for _, nf := range []NotFilter{
				{Words: []string{text}}, {Subject: []string{text}}, {From: []string{text}}, {To: []string{text}},
			} {
				check(Query{NotFilter: nf}, excluded)
			}
		}
		check(Query{Filter: Filter{Words: []string{"и е"}}}, nil)
	}
}
