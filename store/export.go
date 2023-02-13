package store

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
)

// Archiver can archive multiple mailboxes and their messages.
type Archiver interface {
	Create(name string, size int64, mtime time.Time) (io.Writer, error)
	Close() error
}

// TarArchiver is an Archiver that writes to a tar ifle.
type TarArchiver struct {
	*tar.Writer
}

// Create adds a file header to the tar file.
func (a TarArchiver) Create(name string, size int64, mtime time.Time) (io.Writer, error) {
	hdr := tar.Header{
		Name:    name,
		Size:    size,
		Mode:    0600,
		ModTime: mtime,
		Format:  tar.FormatPAX,
	}
	if err := a.WriteHeader(&hdr); err != nil {
		return nil, err
	}
	return a, nil
}

// ZipArchiver is an Archiver that writes to a zip file.
type ZipArchiver struct {
	*zip.Writer
}

// Create adds a file header to the zip file.
func (a ZipArchiver) Create(name string, size int64, mtime time.Time) (io.Writer, error) {
	hdr := zip.FileHeader{
		Name:               name,
		Method:             zip.Deflate,
		Modified:           mtime,
		UncompressedSize64: uint64(size),
	}
	return a.CreateHeader(&hdr)
}

// ExportMessages writes messages to archiver. Either in maildir format, or otherwise in
// mbox. If mailboxOpt is empty, all mailboxes are exported, otherwise only the
// named mailbox.
//
// Some errors are not fatal and result in skipped messages. In that happens, a
// file "errors.txt" is added to the archive describing the errors. The goal is to
// let users export (hopefully) most messages even in the face of errors.
func (a *Account) ExportMessages(log *mlog.Log, archiver Archiver, maildir bool, mailboxOpt string) error {
	// Start transaction without closure, we are going to close it early, but don't
	// want to deal with declaring many variables now to be able to assign them in a
	// closure and use them afterwards.
	tx, err := a.DB.Begin(false)
	if err != nil {
		return fmt.Errorf("transaction: %v", err)
	}
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()

	start := time.Now()

	// Set up mailbox names and ids.
	id2name := map[int64]string{}
	name2id := map[string]int64{}

	mailboxes, err := bstore.QueryTx[Mailbox](tx).List()
	xcheckf(err, "query mailboxes")
	for _, mb := range mailboxes {
		id2name[mb.ID] = mb.Name
		name2id[mb.Name] = mb.ID
	}

	var mailboxID int64
	if mailboxOpt != "" {
		var ok bool
		mailboxID, ok = name2id[mailboxOpt]
		if !ok {
			return fmt.Errorf("mailbox not found")
		}
	}

	var names []string
	for _, name := range id2name {
		if mailboxOpt != "" && name != mailboxOpt {
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

	mailboxOrder := map[int64]int{}
	for i, name := range names {
		mbID := name2id[name]
		mailboxOrder[mbID] = i
	}

	// Fetch all messages. This can take quite a bit of memory if the mailbox is large.
	q := bstore.QueryTx[Message](tx)
	if mailboxID > 0 {
		q.FilterNonzero(Message{MailboxID: mailboxID})
	}
	msgs, err := q.List()
	if err != nil {
		return fmt.Errorf("listing messages: %v", err)
	}

	// Close transaction. We don't want to hold it for too long. We are now at risk
	// that a message is be removed while we export, or flags changed. At least the
	// size won't change. If we cannot open the message later on, we'll skip it and add
	// an error message to an errors.txt file in the output archive.
	if err := tx.Rollback(); err != nil {
		return fmt.Errorf("closing transaction: %v", err)
	}
	tx = nil

	// Order the messages by mailbox, received time and finally message ID.
	sort.Slice(msgs, func(i, j int) bool {
		iid := msgs[i].MailboxID
		jid := msgs[j].MailboxID
		if iid != jid {
			return mailboxOrder[iid] < mailboxOrder[jid]
		}
		if !msgs[i].Received.Equal(msgs[j].Received) {
			return msgs[i].Received.Before(msgs[j].Received)
		}
		return msgs[i].ID < msgs[j].ID
	})

	// We keep track of errors reading message files. We continue exporting and add an
	// errors.txt file to the archive. In case of errors, the user can get (hopefully)
	// most of their emails, and see something went wrong. For other errors, like
	// writing to the archiver (e.g. a browser), we abort, because we don't want to
	// continue with useless work.
	var errors string

	var curMailboxID int64 // Used to set curMailbox and finish a previous mbox file.
	var curMailbox string

	var mboxtmp *os.File
	var mboxwriter *bufio.Writer
	defer func() {
		if mboxtmp != nil {
			mboxtmp.Close()
		}
	}()

	finishMbox := func() error {
		if mboxtmp == nil {
			return nil
		}

		if err := mboxwriter.Flush(); err != nil {
			return fmt.Errorf("flush mbox writer: %v", err)
		}
		fi, err := mboxtmp.Stat()
		if err != nil {
			return fmt.Errorf("stat temporary mbox file: %v", err)
		}
		if _, err := mboxtmp.Seek(0, 0); err != nil {
			return fmt.Errorf("seek to start of temporary mbox file")
		}
		w, err := archiver.Create(curMailbox+".mbox", fi.Size(), fi.ModTime())
		if err != nil {
			return fmt.Errorf("add mbox to archive: %v", err)
		}
		if _, err := io.Copy(w, mboxtmp); err != nil {
			return fmt.Errorf("copying temp mbox file to archive: %v", err)
		}
		if err := mboxtmp.Close(); err != nil {
			log.Errorx("closing temporary mbox file", err)
			// Continue, not fatal.
		}
		mboxwriter = nil
		mboxtmp = nil
		return nil
	}

	exportMessage := func(m Message) error {
		mp := a.MessagePath(m.ID)
		var mr io.ReadCloser
		if m.Size == int64(len(m.MsgPrefix)) {
			mr = io.NopCloser(bytes.NewReader(m.MsgPrefix))
		} else {
			mpf, err := os.Open(mp)
			if err != nil {
				errors += fmt.Sprintf("open message file for id %d, path %s: %v (message skipped)\n", m.ID, mp, err)
				return nil
			}
			defer mpf.Close()
			st, err := mpf.Stat()
			if err != nil {
				errors += fmt.Sprintf("stat message file for id %d, path %s: %v (message skipped)\n", m.ID, mp, err)
				return nil
			}
			size := st.Size() + int64(len(m.MsgPrefix))
			if size != m.Size {
				errors += fmt.Sprintf("message size mismatch for message id %d, database has %d, size is %d+%d=%d, using calculated size\n", m.ID, m.Size, len(m.MsgPrefix), st.Size(), size)
			}
			mr = FileMsgReader(m.MsgPrefix, mpf)
		}

		if maildir {
			p := curMailbox
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

			// We store messages with \r\n, maildir needs without. But we need to know the
			// final size. So first convert, then create file with size, and write from buffer.
			// todo: for large messages, we should go through a temporary file instead of memory.
			var dst bytes.Buffer
			r := bufio.NewReader(mr)
			for {
				line, rerr := r.ReadBytes('\n')
				if rerr != io.EOF && rerr != nil {
					errors += fmt.Sprintf("reading from message for id %d: %v (message skipped)\n", m.ID, err)
					return nil
				}
				if len(line) > 0 {
					if bytes.HasSuffix(line, []byte("\r\n")) {
						line = line[:len(line)-1]
						line[len(line)-1] = '\n'
					}
					if _, err = dst.Write(line); err != nil {
						return fmt.Errorf("writing message: %v", err)
					}
				}
				if rerr == io.EOF {
					break
				}
			}
			size := int64(dst.Len())
			w, err := archiver.Create(p, size, m.Received)
			if err != nil {
				return fmt.Errorf("adding message to archive: %v", err)
			}
			if _, err := io.Copy(w, &dst); err != nil {
				return fmt.Errorf("copying message to archive: %v", err)
			}
			return nil
		}

		// todo: should we put status flags in Status or X-Status header inside the message?
		// todo: should we do anything with Content-Length headers? changing the escaping could invalidate those. is anything checking that field?
		mailfrom := "mox"
		if m.MailFrom != "" {
			mailfrom = m.MailFrom
		}
		if _, err := fmt.Fprintf(mboxwriter, "From %s %s\n", mailfrom, m.Received.Format(time.ANSIC)); err != nil {
			return fmt.Errorf("write message line to mbox temp file: %v", err)
		}
		r := bufio.NewReader(mr)
		for {
			line, rerr := r.ReadBytes('\n')
			if rerr != io.EOF && rerr != nil {
				return fmt.Errorf("reading message: %v", err)
			}
			if len(line) > 0 {
				if bytes.HasSuffix(line, []byte("\r\n")) {
					line = line[:len(line)-1]
					line[len(line)-1] = '\n'
				}
				if bytes.HasPrefix(bytes.TrimLeft(line, ">"), []byte("From ")) {
					if _, err := fmt.Fprint(mboxwriter, ">"); err != nil {
						return fmt.Errorf("writing escaping >: %v", err)
					}
				}
				if _, err := mboxwriter.Write(line); err != nil {
					return fmt.Errorf("writing line: %v", err)
				}
			}
			if rerr == io.EOF {
				break
			}
		}
		if _, err := fmt.Fprint(mboxwriter, "\n"); err != nil {
			return fmt.Errorf("writing end of message newline: %v", err)
		}
		return nil
	}

	for _, m := range msgs {
		if m.MailboxID != curMailboxID {
			if err := finishMbox(); err != nil {
				return err
			}

			curMailbox = id2name[m.MailboxID]
			curMailboxID = m.MailboxID
			if maildir {
				// Create the directories that show this is a maildir.
				if _, err := archiver.Create(curMailbox+"/new/", 0, start); err != nil {
					return fmt.Errorf("adding maildir new directory: %v", err)
				}
				if _, err := archiver.Create(curMailbox+"/cur/", 0, start); err != nil {
					return fmt.Errorf("adding maildir cur directory: %v", err)
				}
				if _, err := archiver.Create(curMailbox+"/tmp/", 0, start); err != nil {
					return fmt.Errorf("adding maildir tmp directory: %v", err)
				}
			} else {

				mboxtmp, err = os.CreateTemp("", "mox-mail-export-mbox")
				if err != nil {
					return fmt.Errorf("creating temp mbox file: %v", err)
				}
				// Remove file immediately, so we are sure we don't leave it around.
				if err := os.Remove(mboxtmp.Name()); err != nil {
					return fmt.Errorf("removing temp file just created: %v", err)
				}
				mboxwriter = bufio.NewWriter(mboxtmp)
			}
		}

		if err := exportMessage(m); err != nil {
			return err
		}
	}
	if err := finishMbox(); err != nil {
		return err
	}

	if errors != "" {
		w, err := archiver.Create("errors.txt", int64(len(errors)), time.Now())
		if err != nil {
			log.Errorx("adding errors.txt to archive", err)
			return err
		}
		if _, err := w.Write([]byte(errors)); err != nil {
			log.Errorx("writing errors.txt to archive", err)
			return err
		}
	}

	return nil
}
