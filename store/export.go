package store

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
)

// Archiver can archive multiple mailboxes and their messages.
type Archiver interface {
	// Add file to archive. If name ends with a slash, it is created as a directory and
	// the returned io.WriteCloser can be ignored.
	Create(name string, size int64, mtime time.Time) (io.WriteCloser, error)
	Close() error
}

// TarArchiver is an Archiver that writes to a tar ifle.
type TarArchiver struct {
	*tar.Writer
}

// Create adds a file header to the tar file.
func (a TarArchiver) Create(name string, size int64, mtime time.Time) (io.WriteCloser, error) {
	hdr := tar.Header{
		Name:    name,
		Size:    size,
		Mode:    0660,
		ModTime: mtime,
		Format:  tar.FormatPAX,
	}
	if err := a.WriteHeader(&hdr); err != nil {
		return nil, err
	}
	return nopCloser{a}, nil
}

// ZipArchiver is an Archiver that writes to a zip file.
type ZipArchiver struct {
	*zip.Writer
}

// Create adds a file header to the zip file.
func (a ZipArchiver) Create(name string, size int64, mtime time.Time) (io.WriteCloser, error) {
	hdr := zip.FileHeader{
		Name:               name,
		Method:             zip.Deflate,
		Modified:           mtime,
		UncompressedSize64: uint64(size),
	}
	w, err := a.CreateHeader(&hdr)
	if err != nil {
		return nil, err
	}
	return nopCloser{w}, nil
}

type nopCloser struct {
	io.Writer
}

// Close does nothing.
func (nopCloser) Close() error {
	return nil
}

// DirArchiver is an Archiver that writes to a directory.
type DirArchiver struct {
	Dir string
}

// Create create name in the file system, in dir.
// name must always use forwarded slashes.
func (a DirArchiver) Create(name string, size int64, mtime time.Time) (io.WriteCloser, error) {
	isdir := strings.HasSuffix(name, "/")
	name = strings.TrimSuffix(name, "/")
	p := filepath.Join(a.Dir, filepath.FromSlash(name))
	os.MkdirAll(filepath.Dir(p), 0770)
	if isdir {
		return nil, os.Mkdir(p, 0770)
	}
	return os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0660)
}

// Close on a dir does nothing.
func (a DirArchiver) Close() error {
	return nil
}

// ExportMessages writes messages to archiver. Either in maildir format, or otherwise in
// mbox. If mailboxOpt is empty, all mailboxes are exported, otherwise only the
// named mailbox.
//
// Some errors are not fatal and result in skipped messages. In that happens, a
// file "errors.txt" is added to the archive describing the errors. The goal is to
// let users export (hopefully) most messages even in the face of errors.
func ExportMessages(ctx context.Context, log *mlog.Log, db *bstore.DB, accountDir string, archiver Archiver, maildir bool, mailboxOpt string) error {
	// todo optimize: should prepare next file to add to archive (can be an mbox with many messages) while writing a file to the archive (which typically compresses, which takes time).

	// Start transaction without closure, we are going to close it early, but don't
	// want to deal with declaring many variables now to be able to assign them in a
	// closure and use them afterwards.
	tx, err := db.Begin(ctx, false)
	if err != nil {
		return fmt.Errorf("transaction: %v", err)
	}
	defer func() {
		if tx != nil {
			err := tx.Rollback()
			log.Check(err, "transaction rollback after export error")
		}
	}()

	start := time.Now()

	// Set up mailbox names and ids.
	id2name := map[int64]string{}
	name2id := map[string]int64{}

	mailboxes, err := bstore.QueryTx[Mailbox](tx).List()
	if err != nil {
		return fmt.Errorf("query mailboxes: %w", err)
	}
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
			CloseRemoveTempFile(log, mboxtmp, "mbox")
		}
	}()

	// For dovecot-keyword-style flags not in standard maildir.
	maildirFlags := map[string]int{}
	var maildirFlaglist []string
	maildirFlag := func(flag string) string {
		i, ok := maildirFlags[flag]
		if !ok {
			if len(maildirFlags) >= 26 {
				// Max 26 flag characters.
				return ""
			}
			i = len(maildirFlags)
			maildirFlags[flag] = i
			maildirFlaglist = append(maildirFlaglist, flag)
		}
		return string(rune('a' + i))
	}

	finishMailbox := func() error {
		if maildir {
			if len(maildirFlags) == 0 {
				return nil
			}

			var b bytes.Buffer
			for i, flag := range maildirFlaglist {
				if _, err := fmt.Fprintf(&b, "%d %s\n", i, flag); err != nil {
					return err
				}
			}
			w, err := archiver.Create(curMailbox+"/dovecot-keywords", int64(b.Len()), start)
			if err != nil {
				return fmt.Errorf("adding dovecot-keywords: %v", err)
			}
			if _, err := w.Write(b.Bytes()); err != nil {
				xerr := w.Close()
				log.Check(xerr, "closing dovecot-keywords file after closing")
				return fmt.Errorf("writing dovecot-keywords: %v", err)
			}
			maildirFlags = map[string]int{}
			maildirFlaglist = nil
			return w.Close()
		}

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
			xerr := w.Close()
			log.Check(xerr, "closing mbox message file after error")
			return fmt.Errorf("copying temp mbox file to archive: %v", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("closing message file: %v", err)
		}
		name := mboxtmp.Name()
		err = mboxtmp.Close()
		log.Check(err, "closing temporary mbox file")
		err = os.Remove(name)
		log.Check(err, "removing temporary mbox file", mlog.Field("path", name))
		mboxwriter = nil
		mboxtmp = nil
		return nil
	}

	exportMessage := func(m Message) error {
		mp := filepath.Join(accountDir, "msg", MessagePath(m.ID))
		var mr io.ReadCloser
		if m.Size == int64(len(m.MsgPrefix)) {
			mr = io.NopCloser(bytes.NewReader(m.MsgPrefix))
		} else {
			mf, err := os.Open(mp)
			if err != nil {
				errors += fmt.Sprintf("open message file for id %d, path %s: %v (message skipped)\n", m.ID, mp, err)
				return nil
			}
			defer func() {
				err := mf.Close()
				log.Check(err, "closing message file after export")
			}()
			st, err := mf.Stat()
			if err != nil {
				errors += fmt.Sprintf("stat message file for id %d, path %s: %v (message skipped)\n", m.ID, mp, err)
				return nil
			}
			size := st.Size() + int64(len(m.MsgPrefix))
			if size != m.Size {
				errors += fmt.Sprintf("message size mismatch for message id %d, database has %d, size is %d+%d=%d, using calculated size\n", m.ID, m.Size, len(m.MsgPrefix), st.Size(), size)
			}
			mr = FileMsgReader(m.MsgPrefix, mf)
		}

		if maildir {
			p := curMailbox
			if m.Flags.Seen {
				p = filepath.Join(p, "cur")
			} else {
				p = filepath.Join(p, "new")
			}
			name := fmt.Sprintf("%d.%d.mox:2,", m.Received.Unix(), m.ID)

			// Standard flags. May need to be sorted.
			if m.Flags.Draft {
				name += "D"
			}
			if m.Flags.Flagged {
				name += "F"
			}
			if m.Flags.Answered {
				name += "R"
			}
			if m.Flags.Seen {
				name += "S"
			}
			if m.Flags.Deleted {
				name += "T"
			}

			// Non-standard flag. We set them with a dovecot-keywords file.
			if m.Flags.Forwarded {
				name += maildirFlag("$Forwarded")
			}
			if m.Flags.Junk {
				name += maildirFlag("$Junk")
			}
			if m.Flags.Notjunk {
				name += maildirFlag("$NotJunk")
			}
			if m.Flags.Phishing {
				name += maildirFlag("$Phishing")
			}
			if m.Flags.MDNSent {
				name += maildirFlag("$MDNSent")
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
				xerr := w.Close()
				log.Check(xerr, "closing message")
				return fmt.Errorf("copying message to archive: %v", err)
			}
			return w.Close()
		}

		mailfrom := "mox"
		if m.MailFrom != "" {
			mailfrom = m.MailFrom
		}
		if _, err := fmt.Fprintf(mboxwriter, "From %s %s\n", mailfrom, m.Received.Format(time.ANSIC)); err != nil {
			return fmt.Errorf("write message line to mbox temp file: %v", err)
		}

		// Write message flags in the three headers that mbox consumers may (or may not) understand.
		if m.Seen {
			if _, err := fmt.Fprintf(mboxwriter, "Status: R\n"); err != nil {
				return fmt.Errorf("writing status header: %v", err)
			}
		}
		xstatus := ""
		if m.Answered {
			xstatus += "A"
		}
		if m.Flagged {
			xstatus += "F"
		}
		if m.Draft {
			xstatus += "T"
		}
		if m.Deleted {
			xstatus += "D"
		}
		if xstatus != "" {
			if _, err := fmt.Fprintf(mboxwriter, "X-Status: %s\n", xstatus); err != nil {
				return fmt.Errorf("writing x-status header: %v", err)
			}
		}
		var xkeywords []string
		if m.Forwarded {
			xkeywords = append(xkeywords, "$Forwarded")
		}
		if m.Junk && !m.Notjunk {
			xkeywords = append(xkeywords, "$Junk")
		}
		if m.Notjunk && !m.Junk {
			xkeywords = append(xkeywords, "$NotJunk")
		}
		if m.Phishing {
			xkeywords = append(xkeywords, "$Phishing")
		}
		if m.MDNSent {
			xkeywords = append(xkeywords, "$MDNSent")
		}
		if len(xkeywords) > 0 {
			if _, err := fmt.Fprintf(mboxwriter, "X-Keywords: %s\n", strings.Join(xkeywords, ",")); err != nil {
				return fmt.Errorf("writing x-keywords header: %v", err)
			}
		}

		header := true
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
				if header && len(line) == 1 {
					header = false
				}
				if header {
					// Skip any previously stored flag-holding or now incorrect content-length headers.
					// This assumes these headers are just a single line.
					switch strings.ToLower(string(bytes.SplitN(line, []byte(":"), 2)[0])) {
					case "status", "x-status", "x-keywords", "content-length":
						continue
					}
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
			if err := finishMailbox(); err != nil {
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
				mboxwriter = bufio.NewWriter(mboxtmp)
			}
		}

		if err := exportMessage(m); err != nil {
			return err
		}
	}
	if err := finishMailbox(); err != nil {
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
			xerr := w.Close()
			log.Check(xerr, "closing errors.txt after error")
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
	}

	return nil
}
