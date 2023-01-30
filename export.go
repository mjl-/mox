package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/store"
)

func cmdExportMaildir(c *cmd) {
	c.params = "dst-path account-path [mailbox]"
	c.help = `Export one or all mailboxes from an account in maildir format.

Export bypasses a running mox instance. It opens the account mailbox/message
database file directly. This may block if a running mox instance also has the
database open, e.g. for IMAP connections.
`
	args := c.Parse()
	xcmdExport(false, args, c)
}

func cmdExportMbox(c *cmd) {
	c.params = "dst-path account-path [mailbox]"
	c.help = `Export messages from one or all mailboxes in an account in mbox format.

Using mbox is not recommended. Maildir is a better format.

Export bypasses a running mox instance. It opens the account mailbox/message
database file directly. This may block if a running mox instance also has the
database open, e.g. for IMAP connections.

For mbox export, we use "mboxrd" where message lines starting with the magic
"From " string are escaped by prepending a >. We escape all ">*From ",
otherwise reconstructing the original could lose a ">".
`
	args := c.Parse()
	xcmdExport(true, args, c)
}

func xcmdExport(mbox bool, args []string, c *cmd) {
	if len(args) != 2 && len(args) != 3 {
		c.Usage()
	}

	dst := args[0]
	accountDir := args[1]
	var mailbox string
	if len(args) == 3 {
		mailbox = args[2]
	}

	dbpath := filepath.Join(accountDir, "index.db")
	db, err := bstore.Open(dbpath, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, store.Message{}, store.Recipient{}, store.Mailbox{})
	xcheckf(err, "open database %q", dbpath)

	err = db.Read(func(tx *bstore.Tx) error {
		exporttx(tx, mbox, dst, accountDir, mailbox)
		return nil
	})
	xcheckf(err, "transaction")
}

func exporttx(tx *bstore.Tx, mbox bool, dst, accountDir, mailbox string) {
	id2name := map[int64]string{}
	name2id := map[string]int64{}

	mailboxes, err := bstore.QueryTx[store.Mailbox](tx).List()
	xcheckf(err, "query mailboxes")
	for _, mb := range mailboxes {
		id2name[mb.ID] = mb.Name
		name2id[mb.Name] = mb.ID
	}

	var mailboxID int64
	if mailbox != "" {
		var ok bool
		mailboxID, ok = name2id[mailbox]
		if !ok {
			log.Fatalf("mailbox %q not found", mailbox)
		}
	}

	mboxes := map[string]*os.File{}

	// Open mbox files or create dirs.
	var names []string
	for _, name := range id2name {
		if mailbox != "" && name != mailbox {
			continue
		}
		names = append(names, name)
	}
	// We need to sort the names because maildirs can create subdirs. Ranging over
	// id2name directly would randomize the directory names, we would create a sub
	// maildir before the parent, and fail with "dir exists" when creating the parent
	// dir.
	sort.Slice(names, func(i, j int) bool {
		return names[i] < names[j]
	})
	for _, name := range names {
		p := dst
		if mailbox == "" {
			p = filepath.Join(p, name)
		}

		os.MkdirAll(filepath.Dir(p), 0770)
		if mbox {
			mbp := p
			if mailbox == "" {
				mbp += ".mbox"
			}
			f, err := os.OpenFile(mbp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
			xcheckf(err, "creating mbox file")
			log.Printf("creating mbox file %s", mbp)
			mboxes[name] = f
		} else {
			err = os.Mkdir(p, 0770)
			xcheckf(err, "making maildir")
			log.Printf("creating maildir %s", p)
			subdirs := []string{"new", "cur", "tmp"}
			for _, subdir := range subdirs {
				err = os.Mkdir(filepath.Join(p, subdir), 0770)
				xcheckf(err, "making maildir subdir")
			}
		}
	}

	q := bstore.QueryTx[store.Message](tx)
	if mailboxID > 0 {
		q.FilterNonzero(store.Message{MailboxID: mailboxID})
	}
	defer q.Close()
	for {
		m, err := q.Next()
		if err == bstore.ErrAbsent {
			break
		}
		xcheckf(err, "next message")

		mbname := id2name[m.MailboxID]

		p := dst
		if mailbox == "" {
			p = filepath.Join(p, mbname)
		}

		mp := filepath.Join(accountDir, "msg", store.MessagePath(m.ID))
		var mr io.ReadCloser
		if m.Size == int64(len(m.MsgPrefix)) {
			log.Printf("message size is prefix size for m id %d", m.ID)
			mr = io.NopCloser(bytes.NewReader(m.MsgPrefix))
		} else {
			mpf, err := os.Open(mp)
			xcheckf(err, "open message file")
			st, err := mpf.Stat()
			xcheckf(err, "stat message file")
			size := st.Size() + int64(len(m.MsgPrefix))
			if size != m.Size {
				log.Fatalf("message size mismatch, database has %d, size is %d+%d=%d", m.Size, len(m.MsgPrefix), st.Size(), size)
			}
			mr = store.FileMsgReader(m.MsgPrefix, mpf)
		}

		if mbox {
			// todo: should we put status flags in Status or X-Status header inside the message?
			// todo: should we do anything with Content-Length headers? changing the escaping could invalidate those. is anything checking that field?

			f := mboxes[mbname]
			mailfrom := "mox"
			if m.MailFrom != "" {
				mailfrom = m.MailFrom
			}
			_, err := fmt.Fprintf(f, "From %s %s\n", mailfrom, m.Received.Format(time.ANSIC))
			xcheckf(err, "writing from header")
			r := bufio.NewReader(mr)
			for {
				line, rerr := r.ReadBytes('\n')
				if rerr != io.EOF {
					xcheckf(rerr, "reading from message")
				}
				if len(line) > 0 {
					if bytes.HasSuffix(line, []byte("\r\n")) {
						line = line[:len(line)-1]
						line[len(line)-1] = '\n'
					}
					if bytes.HasPrefix(bytes.TrimLeft(line, ">"), []byte("From ")) {
						_, err = fmt.Fprint(f, ">")
						xcheckf(err, "writing escaping >")
					}
					_, err = f.Write(line)
					xcheckf(err, "writing line")
				}
				if rerr == io.EOF {
					break
				}
			}
			_, err = fmt.Fprint(f, "\n")
			xcheckf(err, "writing end of message newline")
		} else {
			if m.Flags.Seen {
				p = filepath.Join(p, "cur")
			} else {
				p = filepath.Join(p, "new")
			}
			name := fmt.Sprintf("%d.%d.mox:2,", m.Received.Unix(), m.ID)
			// todo: more flags? forwarded, (non)junk, phishing, mdnsent would be nice. but what is the convention. dovecot-keywords sounds non-standard.
			if m.Flags.Seen {
				name += "S"
			}
			if m.Flags.Answered {
				name += "R"
			}
			if m.Flags.Flagged {
				name += "F"
			}
			if m.Flags.Draft {
				name += "D"
			}
			p = filepath.Join(p, name)
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
			xcheckf(err, "creating message file in maildir")

			r := bufio.NewReader(mr)
			for {
				line, rerr := r.ReadBytes('\n')
				if rerr != io.EOF {
					xcheckf(rerr, "reading from message")
				}
				if len(line) > 0 {
					if bytes.HasSuffix(line, []byte("\r\n")) {
						line = line[:len(line)-1]
						line[len(line)-1] = '\n'
					}
					_, err = f.Write(line)
					xcheckf(err, "writing line")
				}
				if rerr == io.EOF {
					break
				}
			}
			mr.Close()
			err = f.Close()
			xcheckf(err, "closing new file in maildir")
		}

		mr.Close()
	}

	if mbox {
		for _, f := range mboxes {
			err = f.Close()
			xcheckf(err, "closing mbox file")
		}
	}
}
