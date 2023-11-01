package webaccount

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	cryptrand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/text/unicode/norm"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

type importListener struct {
	Token    string
	Events   chan importEvent
	Register chan bool // Whether register is successful.
}

type importEvent struct {
	Token  string
	SSEMsg []byte // Full SSE message, including event: ... and data: ... \n\n
	Event  any    // nil, importCount, importProblem, importDone, importAborted
	Cancel func() // For cancelling the context causing abort of the import. Set in first, import-registering, event.
}

type importAbortRequest struct {
	Token    string
	Response chan error
}

var importers = struct {
	Register   chan *importListener
	Unregister chan *importListener
	Events     chan importEvent
	Abort      chan importAbortRequest
}{
	make(chan *importListener, 1),
	make(chan *importListener, 1),
	make(chan importEvent),
	make(chan importAbortRequest),
}

// ImportManage should be run as a goroutine, it manages imports of mboxes/maildirs, propagating progress over SSE connections.
func ImportManage() {
	log := mlog.New("httpimport")
	defer func() {
		if x := recover(); x != nil {
			log.Error("import manage panic", mlog.Field("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Importmanage)
		}
	}()

	type state struct {
		MailboxCounts map[string]int
		Problems      []string
		Done          *time.Time
		Aborted       *time.Time
		Listeners     map[*importListener]struct{}
		Cancel        func()
	}

	imports := map[string]state{} // Token to state.
	for {
		select {
		case l := <-importers.Register:
			// If we have state, send it so the client is up to date.
			if s, ok := imports[l.Token]; ok {
				l.Register <- true
				s.Listeners[l] = struct{}{}

				sendEvent := func(kind string, v any) {
					buf, err := json.Marshal(v)
					if err != nil {
						log.Errorx("marshal event", err, mlog.Field("kind", kind), mlog.Field("event", v))
						return
					}
					ssemsg := fmt.Sprintf("event: %s\ndata: %s\n\n", kind, buf)

					select {
					case l.Events <- importEvent{kind, []byte(ssemsg), nil, nil}:
					default:
						log.Debug("dropped initial import event to slow consumer")
					}
				}

				for m, c := range s.MailboxCounts {
					sendEvent("count", importCount{m, c})
				}
				for _, p := range s.Problems {
					sendEvent("problem", importProblem{p})
				}
				if s.Done != nil {
					sendEvent("done", importDone{})
				} else if s.Aborted != nil {
					sendEvent("aborted", importAborted{})
				}
			} else {
				l.Register <- false
			}

		case l := <-importers.Unregister:
			delete(imports[l.Token].Listeners, l)

		case e := <-importers.Events:
			s, ok := imports[e.Token]
			if !ok {
				s = state{
					MailboxCounts: map[string]int{},
					Listeners:     map[*importListener]struct{}{},
					Cancel:        e.Cancel,
				}
				imports[e.Token] = s
			}
			for l := range s.Listeners {
				select {
				case l.Events <- e:
				default:
					log.Debug("dropped import event to slow consumer")
				}
			}
			if e.Event != nil {
				s := imports[e.Token]
				switch x := e.Event.(type) {
				case importCount:
					s.MailboxCounts[x.Mailbox] = x.Count
				case importProblem:
					s.Problems = append(s.Problems, x.Message)
				case importDone:
					now := time.Now()
					s.Done = &now
				case importAborted:
					now := time.Now()
					s.Aborted = &now
				}
				imports[e.Token] = s
			}

		case a := <-importers.Abort:
			s, ok := imports[a.Token]
			if !ok {
				a.Response <- errors.New("import not found")
				return
			}
			if s.Done != nil {
				a.Response <- errors.New("import already finished")
				return
			}
			s.Cancel()
			a.Response <- nil
		}

		// Cleanup old state.
		for t, s := range imports {
			if len(s.Listeners) > 0 {
				continue
			}
			if s.Done != nil && time.Since(*s.Done) > time.Minute || s.Aborted != nil && time.Since(*s.Aborted) > time.Minute {
				delete(imports, t)
			}
		}
	}
}

type importCount struct {
	Mailbox string
	Count   int
}
type importProblem struct {
	Message string
}
type importDone struct{}
type importAborted struct{}
type importStep struct {
	Title string
}

// importStart prepare the import and launches the goroutine to actually import.
// importStart is responsible for closing f and removing f.
func importStart(log *mlog.Log, accName string, f *os.File, skipMailboxPrefix string) (string, error) {
	defer func() {
		if f != nil {
			store.CloseRemoveTempFile(log, f, "upload for import")
		}
	}()

	buf := make([]byte, 16)
	if _, err := cryptrand.Read(buf); err != nil {
		return "", err
	}
	token := fmt.Sprintf("%x", buf)

	if _, err := f.Seek(0, 0); err != nil {
		return "", fmt.Errorf("seek to start of file: %v", err)
	}

	// Recognize file format.
	var iszip bool
	magicZip := []byte{0x50, 0x4b, 0x03, 0x04}
	magicGzip := []byte{0x1f, 0x8b}
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil {
		return "", fmt.Errorf("detecting file format: %v", err)
	}
	if bytes.Equal(magic, magicZip) {
		iszip = true
	} else if !bytes.Equal(magic[:2], magicGzip) {
		return "", fmt.Errorf("file is not a zip or gzip file")
	}

	var zr *zip.Reader
	var tr *tar.Reader
	if iszip {
		fi, err := f.Stat()
		if err != nil {
			return "", fmt.Errorf("stat temporary import zip file: %v", err)
		}
		zr, err = zip.NewReader(f, fi.Size())
		if err != nil {
			return "", fmt.Errorf("opening zip file: %v", err)
		}
	} else {
		gzr, err := gzip.NewReader(f)
		if err != nil {
			return "", fmt.Errorf("gunzip: %v", err)
		}
		tr = tar.NewReader(gzr)
	}

	acc, err := store.OpenAccount(accName)
	if err != nil {
		return "", fmt.Errorf("open acount: %v", err)
	}
	acc.Lock() // Not using WithWLock because importMessage is responsible for unlocking.

	tx, err := acc.DB.Begin(context.Background(), true)
	if err != nil {
		acc.Unlock()
		xerr := acc.Close()
		log.Check(xerr, "closing account")
		return "", fmt.Errorf("start transaction: %v", err)
	}

	// Ensure token is registered before returning, with context that can be canceled.
	ctx, cancel := context.WithCancel(mox.Shutdown)
	importers.Events <- importEvent{token, []byte(": keepalive\n\n"), nil, cancel}

	log.Info("starting import")
	go importMessages(ctx, log.WithCid(mox.Cid()), token, acc, tx, zr, tr, f, skipMailboxPrefix)
	f = nil // importMessages is now responsible for closing and removing.

	return token, nil
}

// importMessages imports the messages from zip/tgz file f.
// importMessages is responsible for unlocking and closing acc, and closing tx and f.
func importMessages(ctx context.Context, log *mlog.Log, token string, acc *store.Account, tx *bstore.Tx, zr *zip.Reader, tr *tar.Reader, f *os.File, skipMailboxPrefix string) {
	// If a fatal processing error occurs, we panic with this type.
	type importError struct{ Err error }

	// During import we collect all changes and broadcast them at the end, when successful.
	var changes []store.Change

	// ID's of delivered messages. If we have to rollback, we have to remove this files.
	var deliveredIDs []int64

	sendEvent := func(kind string, v any) {
		buf, err := json.Marshal(v)
		if err != nil {
			log.Errorx("marshal event", err, mlog.Field("kind", kind), mlog.Field("event", v))
			return
		}
		ssemsg := fmt.Sprintf("event: %s\ndata: %s\n\n", kind, buf)
		importers.Events <- importEvent{token, []byte(ssemsg), v, nil}
	}

	canceled := func() bool {
		select {
		case <-ctx.Done():
			sendEvent("aborted", importAborted{})
			return true
		default:
			return false
		}
	}

	problemf := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		sendEvent("problem", importProblem{Message: msg})
	}

	defer func() {
		store.CloseRemoveTempFile(log, f, "uploaded messages")

		for _, id := range deliveredIDs {
			p := acc.MessagePath(id)
			err := os.Remove(p)
			log.Check(err, "closing message file after import error", mlog.Field("path", p))
		}
		if tx != nil {
			err := tx.Rollback()
			log.Check(err, "rolling back transaction")
		}
		if acc != nil {
			acc.Unlock()
			err := acc.Close()
			log.Check(err, "closing account")
		}

		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(importError); ok {
			log.Errorx("import error", err.Err)
			problemf("%s (aborting)", err.Err)
			sendEvent("aborted", importAborted{})
		} else {
			log.Error("import panic", mlog.Field("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Importmessages)
		}
	}()

	ximportcheckf := func(err error, format string, args ...any) {
		if err != nil {
			panic(importError{fmt.Errorf("%s: %s", fmt.Sprintf(format, args...), err)})
		}
	}

	err := acc.ThreadingWait(log)
	ximportcheckf(err, "waiting for account thread upgrade")

	conf, _ := acc.Conf()

	jf, _, err := acc.OpenJunkFilter(ctx, log)
	if err != nil && !errors.Is(err, store.ErrNoJunkFilter) {
		ximportcheckf(err, "open junk filter")
	}
	defer func() {
		if jf != nil {
			err := jf.CloseDiscard()
			log.Check(err, "closing junk filter")
		}
	}()

	// Mailboxes we imported, and message counts.
	mailboxes := map[string]store.Mailbox{}
	messages := map[string]int{}

	// For maildirs, we are likely to get a possible dovecot-keywords file after having
	// imported the messages. Once we see the keywords, we use them. But before that
	// time we remember which messages miss a keywords. Once the keywords become
	// available, we'll fix up the flags for the unknown messages
	mailboxKeywords := map[string]map[rune]string{}                // Mailbox to 'a'-'z' to flag name.
	mailboxMissingKeywordMessages := map[string]map[int64]string{} // Mailbox to message id to string consisting of the unrecognized flags.

	// We keep the mailboxes we deliver to up to date with count and keywords (non-system flags).
	destMailboxCounts := map[int64]store.MailboxCounts{}
	destMailboxKeywords := map[int64]map[string]bool{}

	// Previous mailbox an event was sent for. We send an event for new mailboxes, when
	// another 100 messages were added, when adding a message to another mailbox, and
	// finally at the end as a closing statement.
	var prevMailbox string

	var modseq store.ModSeq // Assigned on first message, used for all messages.

	trainMessage := func(m *store.Message, p message.Part, pos string) {
		words, err := jf.ParseMessage(p)
		if err != nil {
			problemf("parsing message %s for updating junk filter: %v (continuing)", pos, err)
			return
		}
		err = jf.Train(ctx, !m.Junk, words)
		if err != nil {
			problemf("training junk filter for message %s: %v (continuing)", pos, err)
			return
		}
		m.TrainedJunk = &m.Junk
	}

	openTrainMessage := func(m *store.Message) {
		path := acc.MessagePath(m.ID)
		f, err := os.Open(path)
		if err != nil {
			problemf("opening message again for training junk filter: %v (continuing)", err)
			return
		}
		defer func() {
			err := f.Close()
			log.Check(err, "closing file after training junkfilter")
		}()
		p, err := m.LoadPart(f)
		if err != nil {
			problemf("loading parsed message again for training junk filter: %v (continuing)", err)
			return
		}
		trainMessage(m, p, fmt.Sprintf("message id %d", m.ID))
	}

	xensureMailbox := func(name string) store.Mailbox {
		name = norm.NFC.String(name)
		if strings.ToLower(name) == "inbox" {
			name = "Inbox"
		}

		if mb, ok := mailboxes[name]; ok {
			return mb
		}

		var p string
		var mb store.Mailbox
		for i, e := range strings.Split(name, "/") {
			if i == 0 {
				p = e
			} else {
				p = path.Join(p, e)
			}
			if _, ok := mailboxes[p]; ok {
				continue
			}

			q := bstore.QueryTx[store.Mailbox](tx)
			q.FilterNonzero(store.Mailbox{Name: p})
			var err error
			mb, err = q.Get()
			if err == bstore.ErrAbsent {
				uidvalidity, err := acc.NextUIDValidity(tx)
				ximportcheckf(err, "finding next uid validity")
				mb = store.Mailbox{
					Name:        p,
					UIDValidity: uidvalidity,
					UIDNext:     1,
					HaveCounts:  true,
					// Do not assign special-use flags. This existing account probably already has such mailboxes.
				}
				err = tx.Insert(&mb)
				ximportcheckf(err, "inserting mailbox in database")

				if tx.Get(&store.Subscription{Name: p}) != nil {
					err := tx.Insert(&store.Subscription{Name: p})
					ximportcheckf(err, "subscribing to imported mailbox")
				}
				changes = append(changes, store.ChangeAddMailbox{Mailbox: mb, Flags: []string{`\Subscribed`}})
			} else if err != nil {
				ximportcheckf(err, "creating mailbox %s (aborting)", p)
			}
			if prevMailbox != "" && mb.Name != prevMailbox {
				sendEvent("count", importCount{prevMailbox, messages[prevMailbox]})
			}
			mailboxes[mb.Name] = mb
			sendEvent("count", importCount{mb.Name, 0})
			prevMailbox = mb.Name
		}
		return mb
	}

	xdeliver := func(mb store.Mailbox, m *store.Message, f *os.File, pos string) {
		defer func() {
			name := f.Name()
			err = f.Close()
			log.Check(err, "closing temporary message file for delivery")
			err := os.Remove(name)
			log.Check(err, "removing temporary message file for delivery")
		}()
		m.MailboxID = mb.ID
		m.MailboxOrigID = mb.ID

		if modseq == 0 {
			var err error
			modseq, err = acc.NextModSeq(tx)
			ximportcheckf(err, "assigning next modseq")
		}
		m.CreateSeq = modseq
		m.ModSeq = modseq

		mc := destMailboxCounts[mb.ID]
		mc.Add(m.MailboxCounts())
		destMailboxCounts[mb.ID] = mc

		if len(m.Keywords) > 0 {
			if destMailboxKeywords[mb.ID] == nil {
				destMailboxKeywords[mb.ID] = map[string]bool{}
			}
			for _, k := range m.Keywords {
				destMailboxKeywords[mb.ID][k] = true
			}
		}

		// Parse message and store parsed information for later fast retrieval.
		p, err := message.EnsurePart(log, false, f, m.Size)
		if err != nil {
			problemf("parsing message %s: %s (continuing)", pos, err)
		}
		m.ParsedBuf, err = json.Marshal(p)
		ximportcheckf(err, "marshal parsed message structure")

		// Set fields needed for future threading. By doing it now, DeliverMessage won't
		// have to parse the Part again.
		p.SetReaderAt(store.FileMsgReader(m.MsgPrefix, f))
		m.PrepareThreading(log, &p)

		if m.Received.IsZero() {
			if p.Envelope != nil && !p.Envelope.Date.IsZero() {
				m.Received = p.Envelope.Date
			} else {
				m.Received = time.Now()
			}
		}

		// We set the flags that Deliver would set now and train ourselves. This prevents
		// Deliver from training, which would open the junk filter, change it, and write it
		// back to disk, for each message (slow).
		m.JunkFlagsForMailbox(mb, conf)
		if jf != nil && m.NeedsTraining() {
			trainMessage(m, p, pos)
		}

		const sync = false
		const notrain = true
		const nothreads = true
		if err := acc.DeliverMessage(log, tx, m, f, sync, notrain, nothreads); err != nil {
			problemf("delivering message %s: %s (continuing)", pos, err)
			return
		}
		deliveredIDs = append(deliveredIDs, m.ID)
		changes = append(changes, m.ChangeAddUID())
		messages[mb.Name]++
		if messages[mb.Name]%100 == 0 || prevMailbox != mb.Name {
			prevMailbox = mb.Name
			sendEvent("count", importCount{mb.Name, messages[mb.Name]})
		}
	}

	ximportMbox := func(mailbox, filename string, r io.Reader) {
		if mailbox == "" {
			problemf("empty mailbox name for mbox file %s (skipping)", filename)
			return
		}
		mb := xensureMailbox(mailbox)

		mr := store.NewMboxReader(store.CreateMessageTemp, filename, r, log)
		for {
			m, mf, pos, err := mr.Next()
			if err == io.EOF {
				break
			} else if err != nil {
				ximportcheckf(err, "next message in mbox file")
			}

			xdeliver(mb, m, mf, pos)
		}
	}

	ximportMaildir := func(mailbox, filename string, r io.Reader) {
		if mailbox == "" {
			problemf("empty mailbox name for maildir file %s (skipping)", filename)
			return
		}
		mb := xensureMailbox(mailbox)

		f, err := store.CreateMessageTemp("import")
		ximportcheckf(err, "creating temp message")
		defer func() {
			if f != nil {
				store.CloseRemoveTempFile(log, f, "message to import")
			}
		}()

		// Copy data, changing bare \n into \r\n.
		br := bufio.NewReader(r)
		w := bufio.NewWriter(f)
		var size int64
		for {
			line, err := br.ReadBytes('\n')
			if err != nil && err != io.EOF {
				ximportcheckf(err, "reading message")
			}
			if len(line) > 0 {
				if !bytes.HasSuffix(line, []byte("\r\n")) {
					line = append(line[:len(line)-1], "\r\n"...)
				}

				n, err := w.Write(line)
				ximportcheckf(err, "writing message")
				size += int64(n)
			}
			if err == io.EOF {
				break
			}
		}
		err = w.Flush()
		ximportcheckf(err, "writing message")

		var received time.Time
		t := strings.SplitN(path.Base(filename), ".", 2)
		if v, err := strconv.ParseInt(t[0], 10, 64); err == nil {
			received = time.Unix(v, 0)
		}

		// Parse flags. See https://cr.yp.to/proto/maildir.html.
		var keepFlags string
		var flags store.Flags
		keywords := map[string]bool{}
		t = strings.SplitN(path.Base(filename), ":2,", 2)
		if len(t) == 2 {
			for _, c := range t[1] {
				switch c {
				case 'P':
					// Passed, doesn't map to a common IMAP flag.
				case 'R':
					flags.Answered = true
				case 'S':
					flags.Seen = true
				case 'T':
					flags.Deleted = true
				case 'D':
					flags.Draft = true
				case 'F':
					flags.Flagged = true
				default:
					if c >= 'a' && c <= 'z' {
						dovecotKeywords, ok := mailboxKeywords[mailbox]
						if !ok {
							// No keywords file seen yet, we'll try later if it comes in.
							keepFlags += string(c)
						} else if kw, ok := dovecotKeywords[c]; ok {
							flagSet(&flags, keywords, kw)
						}
					}
				}
			}
		}

		m := store.Message{
			Received: received,
			Flags:    flags,
			Keywords: maps.Keys(keywords),
			Size:     size,
		}
		xdeliver(mb, &m, f, filename)
		f = nil
		if keepFlags != "" {
			if _, ok := mailboxMissingKeywordMessages[mailbox]; !ok {
				mailboxMissingKeywordMessages[mailbox] = map[int64]string{}
			}
			mailboxMissingKeywordMessages[mailbox][m.ID] = keepFlags
		}
	}

	importFile := func(name string, r io.Reader) {
		origName := name

		if strings.HasPrefix(name, skipMailboxPrefix) {
			name = strings.TrimPrefix(name[len(skipMailboxPrefix):], "/")
		}

		if strings.HasSuffix(name, "/") {
			name = strings.TrimSuffix(name, "/")
			dir := path.Dir(name)
			switch path.Base(dir) {
			case "new", "cur", "tmp":
				// Maildir, ensure it exists.
				mailbox := path.Dir(dir)
				xensureMailbox(mailbox)
			}
			// Otherwise, this is just a directory that probably holds mbox files and maildirs.
			return
		}

		if strings.HasSuffix(path.Base(name), ".mbox") {
			mailbox := name[:len(name)-len(".mbox")]
			ximportMbox(mailbox, origName, r)
			return
		}
		dir := path.Dir(name)
		dirbase := path.Base(dir)
		switch dirbase {
		case "new", "cur", "tmp":
			mailbox := path.Dir(dir)
			ximportMaildir(mailbox, origName, r)
		default:
			if path.Base(name) == "dovecot-keywords" {
				mailbox := path.Dir(name)
				dovecotKeywords := map[rune]string{}
				words, err := store.ParseDovecotKeywordsFlags(r, log)
				log.Check(err, "parsing dovecot keywords for mailbox", mlog.Field("mailbox", mailbox))
				for i, kw := range words {
					dovecotKeywords['a'+rune(i)] = kw
				}
				mailboxKeywords[mailbox] = dovecotKeywords

				for id, chars := range mailboxMissingKeywordMessages[mailbox] {
					var flags, zeroflags store.Flags
					keywords := map[string]bool{}
					for _, c := range chars {
						kw, ok := dovecotKeywords[c]
						if !ok {
							problemf("unspecified dovecot message flag %c for message id %d (continuing)", c, id)
							continue
						}
						flagSet(&flags, keywords, kw)
					}
					if flags == zeroflags && len(keywords) == 0 {
						continue
					}

					m := store.Message{ID: id}
					err := tx.Get(&m)
					ximportcheckf(err, "get imported message for flag update")

					mc := destMailboxCounts[m.MailboxID]
					mc.Sub(m.MailboxCounts())

					oflags := m.Flags
					m.Flags = m.Flags.Set(flags, flags)
					m.Keywords = maps.Keys(keywords)
					sort.Strings(m.Keywords)

					mc.Add(m.MailboxCounts())
					destMailboxCounts[m.MailboxID] = mc

					if len(m.Keywords) > 0 {
						if destMailboxKeywords[m.MailboxID] == nil {
							destMailboxKeywords[m.MailboxID] = map[string]bool{}
						}
						for _, k := range m.Keywords {
							destMailboxKeywords[m.MailboxID][k] = true
						}
					}

					// We train before updating, training may set m.TrainedJunk.
					if jf != nil && m.NeedsTraining() {
						openTrainMessage(&m)
					}
					err = tx.Update(&m)
					ximportcheckf(err, "updating message after flag update")
					changes = append(changes, m.ChangeFlags(oflags))
				}
				delete(mailboxMissingKeywordMessages, mailbox)
			} else {
				problemf("unrecognized file %s (skipping)", origName)
			}
		}
	}

	if zr != nil {
		for _, f := range zr.File {
			if canceled() {
				return
			}
			zf, err := f.Open()
			if err != nil {
				problemf("opening file %s in zip: %v", f.Name, err)
				continue
			}
			importFile(f.Name, zf)
			err = zf.Close()
			log.Check(err, "closing file from zip")
		}
	} else {
		for {
			if canceled() {
				return
			}
			h, err := tr.Next()
			if err == io.EOF {
				break
			} else if err != nil {
				problemf("reading next tar header: %v (aborting)", err)
				return
			}
			importFile(h.Name, tr)
		}
	}

	total := 0
	for _, count := range messages {
		total += count
	}
	log.Debug("messages imported", mlog.Field("total", total))

	// Send final update for count of last-imported mailbox.
	if prevMailbox != "" {
		sendEvent("count", importCount{prevMailbox, messages[prevMailbox]})
	}

	// Match threads.
	if len(deliveredIDs) > 0 {
		sendEvent("step", importStep{"matching messages with threads"})
		err = acc.AssignThreads(ctx, log, tx, deliveredIDs[0], 0, io.Discard)
		ximportcheckf(err, "assigning messages to threads")
	}

	// Update mailboxes with counts and keywords.
	for mbID, mc := range destMailboxCounts {
		mb := store.Mailbox{ID: mbID}
		err := tx.Get(&mb)
		ximportcheckf(err, "loading mailbox for counts and keywords")

		if mb.MailboxCounts != mc {
			mb.MailboxCounts = mc
			changes = append(changes, mb.ChangeCounts())
		}

		keywords := destMailboxKeywords[mb.ID]
		var mbKwChanged bool
		mb.Keywords, mbKwChanged = store.MergeKeywords(mb.Keywords, maps.Keys(keywords))

		err = tx.Update(&mb)
		ximportcheckf(err, "updating mailbox count and keywords")
		if mbKwChanged {
			changes = append(changes, mb.ChangeKeywords())
		}
	}

	err = tx.Commit()
	tx = nil
	ximportcheckf(err, "commit")
	deliveredIDs = nil

	if jf != nil {
		if err := jf.Close(); err != nil {
			problemf("saving changes of training junk filter: %v (continuing)", err)
			log.Errorx("saving changes of training junk filter", err)
		}
		jf = nil
	}

	store.BroadcastChanges(acc, changes)
	acc.Unlock()
	err = acc.Close()
	log.Check(err, "closing account after import")
	acc = nil

	sendEvent("done", importDone{})
}

func flagSet(flags *store.Flags, keywords map[string]bool, word string) {
	switch word {
	case "forwarded", "$forwarded":
		flags.Forwarded = true
	case "junk", "$junk":
		flags.Junk = true
	case "notjunk", "$notjunk", "nonjunk", "$nonjunk":
		flags.Notjunk = true
	case "phishing", "$phishing":
		flags.Phishing = true
	case "mdnsent", "$mdnsent":
		flags.MDNSent = true
	default:
		if err := store.CheckKeyword(word); err == nil {
			keywords[word] = true
		}
	}
}
