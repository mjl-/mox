package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

// todo: implement export of all maildirs to a zip file and also import of such a zip file.
// todo: add option to trust imported messages, causing us to look at Authentication-Results and Received-SPF headers and add eg verified spf/dkim/dmarc domains to our store, to jumpstart reputation.

const importCommonHelp = `By default, messages will train the junk filter based on their flags and
mailbox naming. If the destination mailbox name starts with "junk" or "spam"
(case insensitive), messages are imported and trained as junk regardless of
pre-existing flags. Use the -train=false flag to prevent training the filter.

If the destination mailbox is "Sent", the recipients of the messages are added
to the message metadata, causing later incoming messages from these recipients
to be accepted, unless other reputation signals prevent that.

The message "read"/"seen" flag can be overridden during import with the
-markread flag.
`

func cmdImportMaildir(c *cmd) {
	c.params = "accountname mailboxname maildir"
	c.help = `Import a maildir into an account.

` + importCommonHelp + `
Mailbox flags, like "seen", "answered", "forwarded", will be imported. An
attempt is made to parse dovecot keyword files.

The maildir files/directories are read by the mox process, so make sure it has
access to the maildir directories/files.
`

	var train bool
	var markRead bool
	c.flag.BoolVar(&train, "train", true, "train junkfilter with messages")
	c.flag.BoolVar(&markRead, "markread", false, "mark all imported messages as read")

	args := c.Parse()
	xcmdImport(false, train, markRead, args, c)
}

func cmdImportMbox(c *cmd) {
	c.params = "accountname mailboxname mbox"
	c.help = `Import an mbox into an account.

Using mbox is not recommended, maildir is a better format.

` + importCommonHelp + `

The mailbox is read by the mox process, so make sure it has access to the
maildir directories/files.
`

	var train bool
	var markRead bool
	c.flag.BoolVar(&train, "train", true, "train junkfilter with messages")
	c.flag.BoolVar(&markRead, "markread", false, "mark all imported messages as read")

	args := c.Parse()
	xcmdImport(true, train, markRead, args, c)
}

func xcmdImport(mbox, train, markRead bool, args []string, c *cmd) {
	if len(args) != 3 {
		c.Usage()
	}

	mox.MustLoadConfig()

	account := args[0]
	mailbox := args[1]
	if strings.EqualFold(mailbox, "inbox") {
		mailbox = "Inbox"
	}
	src := args[2]

	var ctlcmd string
	if mbox {
		ctlcmd = "importmbox"
	} else {
		ctlcmd = "importmaildir"
	}

	ctl := xctl()
	ctl.xwrite(ctlcmd)
	ctl.xwrite(account)
	ctl.xwrite(mailbox)
	ctl.xwrite(src)
	if train {
		ctl.xwrite("train")
	} else {
		ctl.xwrite("notrain")
	}
	if markRead {
		ctl.xwrite("markread")
	} else {
		ctl.xwrite("nomarkread")
	}
	ctl.xreadok()
	fmt.Fprintln(os.Stderr, "importing...")
	for {
		line := ctl.xread()
		if strings.HasPrefix(line, "progress ") {
			n := line[len("progress "):]
			fmt.Fprintf(os.Stderr, "%s...\n", n)
			continue
		}
		if line != "ok" {
			log.Fatalf("import, expected ok, got %q", line)
		}
		break
	}
	count := ctl.xread()
	fmt.Fprintf(os.Stderr, "%s imported\n", count)
}

func importctl(ctl *ctl, mbox bool) {
	/* protocol:
	> "importmaildir" or "importmbox"
	> account
	> mailbox
	> src (mbox file or maildir directory)
	> "train" or "notrain"
	> "markread" or "nomarkread"
	< "ok" or error
	< "progress" count (zero or more times, once for every 1000 messages)
	< "ok" when done, or error
	< count (of total imported messages, only if not error)
	*/
	account := ctl.xread()
	mailbox := ctl.xread()
	src := ctl.xread()
	xtrain := ctl.xread()
	xmarkread := ctl.xread()

	var train bool
	switch xtrain {
	case "train":
		train = true
	case "notrain":
		train = false
	default:
		ctl.xerror("bad value for train: " + xtrain)
	}

	var markRead bool
	switch xmarkread {
	case "markread":
		markRead = true
	case "nomarkread":
		markRead = false
	default:
		ctl.xerror("bad value for markread: " + xmarkread)
	}

	kind := "maildir"
	if mbox {
		kind = "mbox"
	}
	ctl.log.Info("importing messages", mlog.Field("kind", kind), mlog.Field("account", account), mlog.Field("mailbox", mailbox), mlog.Field("source", src))

	var err error
	var mboxf *os.File
	var mdnewf, mdcurf *os.File
	var msgreader msgReader

	defer func() {
		if mboxf != nil {
			if err := mboxf.Close(); err != nil {
				ctl.log.Infox("closing mbox file after import", err)
			}
		}
		if mdnewf != nil {
			if err := mdnewf.Close(); err != nil {
				ctl.log.Infox("closing maildir new after import", err)
			}
		}
		if mdcurf != nil {
			if err := mdcurf.Close(); err != nil {
				ctl.log.Infox("closing maildir cur after import", err)
			}
		}
	}()

	// Open account, creating a database file if it doesn't exist yet. It must be known
	// in the configuration file.
	a, err := store.OpenAccount(account)
	ctl.xcheck(err, "opening account")
	defer func() {
		if a != nil {
			if err := a.Close(); err != nil {
				ctl.log.Errorx("closing account after import", err)
			}
		}
	}()

	// Messages don't always have a junk flag set. We'll assume anything in a mailbox
	// starting with junk or spam is junk mail.
	isjunk := strings.HasPrefix(strings.ToLower(mailbox), "junk") || strings.HasPrefix(strings.ToLower(mailbox), "spam")

	// First check if we can access the mbox/maildir.
	// Mox needs to be able to access those files, the user running the import command
	// may be a different user who can access the files.
	if mbox {
		mboxf, err = os.Open(src)
		ctl.xcheck(err, "open mbox file")
		msgreader = newMboxReader(isjunk, store.CreateMessageTemp, mboxf, ctl.log)
	} else {
		mdnewf, err = os.Open(filepath.Join(src, "new"))
		ctl.xcheck(err, "open subdir new of maildir")
		mdcurf, err = os.Open(filepath.Join(src, "cur"))
		ctl.xcheck(err, "open subdir cur of maildir")
		msgreader = newMaildirReader(isjunk, store.CreateMessageTemp, mdnewf, mdcurf, ctl.log)
	}

	tx, err := a.DB.Begin(true)
	ctl.xcheck(err, "begin transaction")
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()

	// All preparations done. Good to go.
	ctl.xwriteok()

	// We will be delivering messages. If we fail halfway, we need to remove the created msg files.
	var deliveredIDs []int64

	// Handle errors from store.*X calls.
	defer func() {
		x := recover()
		if x == nil {
			return
		}

		ctl.log.Error("store error", mlog.Field("panic", x))
		debug.PrintStack()
		metrics.PanicInc("import")

		for _, id := range deliveredIDs {
			p := a.MessagePath(id)
			if err := os.Remove(p); err != nil {
				ctl.log.Errorx("closing message file after import error", err, mlog.Field("path", p))
			}
		}

		ctl.xerror(fmt.Sprintf("%v", x))
	}()

	var changes []store.Change

	xdeliver := func(m *store.Message, mf *os.File) {
		// todo: possibly set dmarcdomain to the domain of the from address? at least for non-spams that have been seen. otherwise user would start without any reputations. the assumption would be that the user has accepted email and deemed it legit, coming from the indicated sender.

		const consumeFile = true
		isSent := mailbox == "Sent"
		const sync = false
		const train = false
		a.DeliverX(ctl.log, tx, m, mf, consumeFile, isSent, sync, train)
		deliveredIDs = append(deliveredIDs, m.ID)
		ctl.log.Debug("delivered message", mlog.Field("id", m.ID))
		changes = append(changes, store.ChangeAddUID{MailboxID: m.MailboxID, UID: m.UID, Flags: m.Flags})
	}

	// todo: one goroutine for reading messages, one for parsing the message, one adding to database, one for junk filter training.
	n := 0
	a.WithWLock(func() {
		// Ensure mailbox exists.
		var mb store.Mailbox
		mb, changes = a.MailboxEnsureX(tx, mailbox, true)

		var jf *junk.Filter
		if train {
			jf, _, err = a.OpenJunkFilter(ctl.log)
			if err != nil && !errors.Is(err, store.ErrNoJunkFilter) {
				ctl.xcheck(err, "open junk filter")
			}
			defer func() {
				if jf != nil {
					err = jf.Close()
					ctl.xcheck(err, "close junk filter")
				}
			}()
		}

		process := func(m *store.Message, msgf *os.File, origPath string) {
			defer func() {
				if msgf == nil {
					return
				}
				if err := os.Remove(msgf.Name()); err != nil {
					ctl.log.Errorx("removing temporary message after failing to import", err)
				}
				msgf.Close()
			}()

			if markRead {
				m.Seen = true
			}

			// todo: if message does not contain a date header, but this was a maildir file, add a Date header based on the time in the filename?

			// Parse message and store parsed information for later fast retrieval.
			p, err := message.EnsurePart(msgf, m.Size)
			if err != nil {
				ctl.log.Infox("parsing message, continuing", err, mlog.Field("path", origPath))
			}
			m.ParsedBuf, err = json.Marshal(p)
			ctl.xcheck(err, "marshal parsed message structure")

			if m.Received.IsZero() {
				if p.Envelope != nil && !p.Envelope.Date.IsZero() {
					m.Received = p.Envelope.Date
				} else {
					m.Received = time.Now()
				}
			}

			if jf != nil && (m.Seen || m.Junk) {
				if words, err := jf.ParseMessage(p); err != nil {
					ctl.log.Infox("parsing message for updating junk filter", err, mlog.Field("parse", ""), mlog.Field("path", origPath))
				} else {
					err = jf.Train(!m.Junk, words)
					ctl.xcheck(err, "training junk filter")
				}
			}

			m.MailboxID = mb.ID
			m.MailboxOrigID = mb.ID
			xdeliver(m, msgf)
			msgf.Close()
			msgf = nil

			n++
			if n%1000 == 0 {
				ctl.xwrite(fmt.Sprintf("progress %d", n))
			}
		}

		for {
			m, msgf, origPath, err := msgreader.Next()
			if err == io.EOF {
				break
			}
			ctl.xcheck(err, "reading next message")

			process(m, msgf, origPath)
		}

		err = tx.Commit()
		ctl.xcheck(err, "commit")
		tx = nil
		ctl.log.Info("delivered messages through import", mlog.Field("count", len(deliveredIDs)))
		deliveredIDs = nil

		comm := store.RegisterComm(a)
		defer comm.Unregister()
		comm.Broadcast(changes)
	})

	err = a.Close()
	ctl.xcheck(err, "closing account")
	a = nil

	ctl.xwriteok()
	ctl.xwrite(fmt.Sprintf("%d", n))
}

type msgReader interface {
	// Return next message, or io.EOF when there are no more.
	Next() (*store.Message, *os.File, string, error)
}

type mboxReader struct {
	createTemp func(pattern string) (*os.File, error)
	path       string
	line       int
	r          *bufio.Reader
	prevempty  bool
	nonfirst   bool
	log        *mlog.Log
	eof        bool
	junk       bool
}

func newMboxReader(isjunk bool, createTemp func(pattern string) (*os.File, error), f *os.File, log *mlog.Log) *mboxReader {
	return &mboxReader{createTemp: createTemp, path: f.Name(), line: 1, r: bufio.NewReader(f), log: log, junk: isjunk}
}

func (mr *mboxReader) position() string {
	return fmt.Sprintf("%s:%d", mr.path, mr.line)
}

func (mr *mboxReader) Next() (*store.Message, *os.File, string, error) {
	if mr.eof {
		return nil, nil, "", io.EOF
	}

	from := []byte("From ")

	if !mr.nonfirst {
		// First read, we're at the beginning of the file.
		line, err := mr.r.ReadBytes('\n')
		if err == io.EOF {
			return nil, nil, "", io.EOF
		}
		mr.line++

		if !bytes.HasPrefix(line, from) {
			return nil, nil, mr.position(), fmt.Errorf(`first line does not start with "From "`)
		}
		mr.nonfirst = true
	}

	f, err := mr.createTemp("mboxreader")
	if err != nil {
		return nil, nil, mr.position(), err
	}
	defer func() {
		if f != nil {
			f.Close()
			if err := os.Remove(f.Name()); err != nil {
				mr.log.Errorx("removing temporary message file after mbox read error", err, mlog.Field("path", f.Name()))
			}
		}
	}()

	bf := bufio.NewWriter(f)

	var size int64
	for {
		line, err := mr.r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, nil, mr.position(), fmt.Errorf("reading from mbox: %v", err)
		}
		if len(line) > 0 {
			mr.line++
			// We store data with crlf, adjust any imported messages with bare newlines.
			if !bytes.HasSuffix(line, []byte("\r\n")) {
				line = append(line[:len(line)-1], "\r\n"...)
			}

			// Next mail message starts at bare From word.
			if mr.prevempty && bytes.HasPrefix(line, from) {
				break
			}
			if bytes.HasPrefix(line, []byte(">")) && bytes.HasPrefix(bytes.TrimLeft(line, ">"), []byte("From ")) {
				line = line[1:]
			}
			n, err := bf.Write(line)
			if err != nil {
				return nil, nil, mr.position(), fmt.Errorf("writing message to file: %v", err)
			}
			size += int64(n)
			mr.prevempty = bytes.Equal(line, []byte("\r\n"))
		}
		if err == io.EOF {
			mr.eof = true
			break
		}
	}
	if err := bf.Flush(); err != nil {
		return nil, nil, mr.position(), fmt.Errorf("flush: %v", err)
	}

	// todo: look at Status or X-Status header in message?
	// todo: take Received from the "From " line if present?
	flags := store.Flags{Seen: true, Junk: mr.junk}
	m := &store.Message{Flags: flags, Size: size}

	// Prevent cleanup by defer.
	mf := f
	f = nil

	return m, mf, mr.position(), nil
}

type maildirReader struct {
	createTemp      func(pattern string) (*os.File, error)
	newf, curf      *os.File
	f               *os.File // File we are currently reading from. We first read newf, then curf.
	dir             string   // Name of directory for f. Can be empty on first call.
	entries         []os.DirEntry
	dovecotKeywords []string
	log             *mlog.Log
	junk            bool
}

func newMaildirReader(isjunk bool, createTemp func(pattern string) (*os.File, error), newf, curf *os.File, log *mlog.Log) *maildirReader {
	mr := &maildirReader{createTemp: createTemp, newf: newf, curf: curf, f: newf, log: log, junk: isjunk}

	// Best-effort parsing of dovecot keywords.
	kf, err := os.Open(filepath.Join(filepath.Dir(newf.Name()), "dovecot-keywords"))
	if err == nil {
		mr.dovecotKeywords = tryParseDovecotKeywords(kf, log)
		kf.Close()
	}

	return mr
}

func (mr *maildirReader) Next() (*store.Message, *os.File, string, error) {
	if mr.dir == "" {
		mr.dir = mr.f.Name()
	}

	if len(mr.entries) == 0 {
		var err error
		mr.entries, err = mr.f.ReadDir(100)
		if err != nil && err != io.EOF {
			return nil, nil, "", err
		}
		if len(mr.entries) == 0 {
			if mr.f == mr.curf {
				return nil, nil, "", io.EOF
			}
			mr.f = mr.curf
			mr.dir = ""
			return mr.Next()
		}
	}

	p := filepath.Join(mr.dir, mr.entries[0].Name())
	mr.entries = mr.entries[1:]
	sf, err := os.Open(p)
	if err != nil {
		return nil, nil, p, fmt.Errorf("open message in maildir: %s", err)
	}
	defer sf.Close()
	f, err := mr.createTemp("maildirreader")
	if err != nil {
		return nil, nil, p, err
	}
	defer func() {
		if f != nil {
			f.Close()
			if err := os.Remove(f.Name()); err != nil {
				mr.log.Errorx("removing temporary message file after maildir read error", err, mlog.Field("path", f.Name()))
			}
		}
	}()

	// Copy data, changing bare \n into \r\n.
	r := bufio.NewReader(sf)
	w := bufio.NewWriter(f)
	var size int64
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, nil, p, fmt.Errorf("reading message: %v", err)
		}
		if len(line) > 0 {
			if !bytes.HasSuffix(line, []byte("\r\n")) {
				line = append(line[:len(line)-1], "\r\n"...)
			}

			if n, err := w.Write(line); err != nil {
				return nil, nil, p, fmt.Errorf("writing message: %v", err)
			} else {
				size += int64(n)
			}
		}
		if err == io.EOF {
			break
		}
	}
	if err := w.Flush(); err != nil {
		return nil, nil, p, fmt.Errorf("writing message: %v", err)
	}

	// Take received time from filename.
	var received time.Time
	t := strings.SplitN(filepath.Base(sf.Name()), ".", 2)
	if v, err := strconv.ParseInt(t[0], 10, 64); err == nil {
		received = time.Unix(v, 0)
	}

	// Parse flags. See https://cr.yp.to/proto/maildir.html.
	flags := store.Flags{}
	t = strings.SplitN(filepath.Base(sf.Name()), ":2,", 2)
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
					index := int(c - 'a')
					if index >= len(mr.dovecotKeywords) {
						continue
					}
					kw := mr.dovecotKeywords[index]
					switch kw {
					case "$Forwarded", "Forwarded":
						flags.Forwarded = true
					case "$Junk", "Junk":
						flags.Junk = true
					case "$NotJunk", "NotJunk", "NonJunk":
						flags.Notjunk = true
					case "$MDNSent":
						flags.MDNSent = true
					case "$Phishing", "Phishing":
						flags.Phishing = true
					}
					// todo: custom labels, e.g. $label1, JunkRecorded?
				}
			}
		}
	}

	if mr.junk {
		flags.Junk = true
	}

	m := &store.Message{Received: received, Flags: flags, Size: size}

	// Prevent cleanup by defer.
	mf := f
	f = nil

	return m, mf, p, nil
}

func tryParseDovecotKeywords(r io.Reader, log *mlog.Log) []string {
	/*
		  If the dovecot-keywords file is present, we parse its additional flags, see
		  https://doc.dovecot.org/admin_manual/mailbox_formats/maildir/

		0 Old
		1 Junk
		2 NonJunk
		3 $Forwarded
		4 $Junk
	*/
	keywords := make([]string, 26)
	end := 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s := scanner.Text()
		t := strings.SplitN(s, " ", 2)
		if len(t) != 2 {
			log.Info("unexpected dovecot keyword line", mlog.Field("line", s))
			continue
		}
		v, err := strconv.ParseInt(t[0], 10, 32)
		if err != nil {
			log.Infox("unexpected dovecot keyword index", err, mlog.Field("line", s))
			continue
		}
		if v < 0 || v >= int64(len(keywords)) {
			log.Info("dovecot keyword index too big", mlog.Field("line", s))
			continue
		}
		index := int(v)
		if keywords[index] != "" {
			log.Info("duplicate dovecot keyword", mlog.Field("line", s))
			continue
		}
		keywords[index] = t[1]
		if index >= end {
			end = index + 1
		}
	}
	if err := scanner.Err(); err != nil {
		log.Infox("reading dovecot keywords file", err)
	}
	return keywords[:end]
}
