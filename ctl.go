package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

// ctl represents a connection to the ctl unix domain socket of a running mox instance.
// ctl provides functions to read/write commands/responses/data streams.
type ctl struct {
	cmd  string // Set for server-side of commands.
	conn net.Conn
	r    *bufio.Reader // Set for first reader.
	x    any           // If set, errors are handled by calling panic(x) instead of log.Fatal.
	log  *mlog.Log     // If set, along with x, logging is done here.
}

// xctl opens a ctl connection.
func xctl() *ctl {
	p := mox.DataDirPath("ctl")
	conn, err := net.Dial("unix", p)
	if err != nil {
		log.Fatalf("connecting to control socket at %q: %v", p, err)
	}
	ctl := &ctl{conn: conn}
	version := ctl.xread()
	if version != "ctlv0" {
		log.Fatalf("ctl protocol mismatch, got %q, expected ctlv0", version)
	}
	return ctl
}

// Interpret msg as an error.
// If ctl.x is set, the string is also written to the ctl to be interpreted as error by the other party.
func (c *ctl) xerror(msg string) {
	if c.x == nil {
		log.Fatalln(msg)
	}
	c.log.Debugx("ctl error", fmt.Errorf("%s", msg), mlog.Field("cmd", c.cmd))
	c.xwrite(msg)
	panic(c.x)
}

// Check if err is not nil. If so, handle error through ctl.x or log.Fatal. If
// ctl.x is set, the error string is written to ctl, to be interpreted as an error
// by the command reading from ctl.
func (c *ctl) xcheck(err error, msg string) {
	if err == nil {
		return
	}
	if c.x == nil {
		log.Fatalf("%s: %s", msg, err)
	}
	c.log.Debugx(msg, err, mlog.Field("cmd", c.cmd))
	fmt.Fprintf(c.conn, "%s: %s\n", msg, err)
	panic(c.x)
}

// Read a line and return it without trailing newline.
func (c *ctl) xread() string {
	if c.r == nil {
		c.r = bufio.NewReader(c.conn)
	}
	line, err := c.r.ReadString('\n')
	c.xcheck(err, "read from ctl")
	return strings.TrimSuffix(line, "\n")
}

// Read a line. If not "ok", the string is interpreted as an error.
func (c *ctl) xreadok() {
	line := c.xread()
	if line != "ok" {
		c.xerror(line)
	}
}

// Write a string, typically a command or parameter.
func (c *ctl) xwrite(text string) {
	_, err := fmt.Fprintln(c.conn, text)
	c.xcheck(err, "write")
}

// Write "ok" to indicate success.
func (c *ctl) xwriteok() {
	c.xwrite("ok")
}

// Copy data from a stream from ctl to dst.
func (c *ctl) xstreamto(dst io.Writer) {
	_, err := io.Copy(dst, c.reader())
	c.xcheck(err, "reading message")
}

// Copy data from src to a stream to ctl.
func (c *ctl) xstreamfrom(src io.Reader) {
	w := c.writer()
	_, err := io.Copy(w, src)
	c.xcheck(err, "copying")
	w.xclose()
}

// Writer returns an io.Writer for a data stream to ctl.
// When done writing, caller must call xclose to signal the end of the stream.
// Behaviour of "x" is copied from ctl.
func (c *ctl) writer() *ctlwriter {
	return &ctlwriter{cmd: c.cmd, conn: c.conn, x: c.x, log: c.log}
}

// Reader returns an io.Reader for a data stream from ctl.
// Behaviour of "x" is copied from ctl.
func (c *ctl) reader() *ctlreader {
	if c.r == nil {
		c.r = bufio.NewReader(c.conn)
	}
	return &ctlreader{cmd: c.cmd, conn: c.conn, r: c.r, x: c.x, log: c.log}
}

/*
Ctlwriter and ctlreader implement the writing and reading a data stream. They
implement the io.Writer and io.Reader interface. In the protocol below each
non-data message ends with a newline that is typically stripped when
interpreting.

Zero or more data transactions:

	> "123" (for data size) or an error message
	> data, 123 bytes
	< "ok" or an error message

Followed by a end of stream indicated by zero data bytes message:

	> "0"
*/

type ctlwriter struct {
	cmd  string   // Set for server-side of commands.
	conn net.Conn // Ctl socket from which messages are read.
	buf  []byte   // Scratch buffer, for reading response.
	x    any      // If not nil, errors in Write and xcheckf are handled with panic(x), otherwise with a log.Fatal.
	log  *mlog.Log
}

func (s *ctlwriter) Write(buf []byte) (int, error) {
	_, err := fmt.Fprintf(s.conn, "%d\n", len(buf))
	s.xcheck(err, "write count")
	_, err = s.conn.Write(buf)
	s.xcheck(err, "write data")
	if s.buf == nil {
		s.buf = make([]byte, 512)
	}
	n, err := s.conn.Read(s.buf)
	s.xcheck(err, "reading response to write")
	line := strings.TrimSuffix(string(s.buf[:n]), "\n")
	if line != "ok" {
		s.xerror(line)
	}
	return len(buf), nil
}

func (s *ctlwriter) xerror(msg string) {
	if s.x == nil {
		log.Fatalln(msg)
	} else {
		s.log.Debugx("error", fmt.Errorf("%s", msg), mlog.Field("cmd", s.cmd))
		panic(s.x)
	}
}

func (s *ctlwriter) xcheck(err error, msg string) {
	if err == nil {
		return
	}
	if s.x == nil {
		log.Fatalf("%s: %s", msg, err)
	} else {
		s.log.Debugx(msg, err, mlog.Field("cmd", s.cmd))
		panic(s.x)
	}
}

func (s *ctlwriter) xclose() {
	_, err := fmt.Fprintf(s.conn, "0\n")
	s.xcheck(err, "write eof")
}

type ctlreader struct {
	cmd      string        // Set for server-side of command.
	conn     net.Conn      // For writing "ok" after reading.
	r        *bufio.Reader // Buffered ctl socket.
	err      error         // If set, returned for each read. can also be io.EOF.
	npending int           // Number of bytes that can still be read until a new count line must be read.
	x        any           // If set, errors are handled with panic(x) instead of log.Fatal.
	log      *mlog.Log     // If x is set, logging goes to log.
}

func (s *ctlreader) Read(buf []byte) (N int, Err error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.npending == 0 {
		line, err := s.r.ReadString('\n')
		s.xcheck(err, "reading count")
		line = strings.TrimSuffix(line, "\n")
		n, err := strconv.ParseInt(line, 10, 32)
		if err != nil {
			s.xerror(line)
		}
		if n == 0 {
			s.err = io.EOF
			return 0, s.err
		}
		s.npending = int(n)
	}
	rn := len(buf)
	if rn > s.npending {
		rn = s.npending
	}
	n, err := s.r.Read(buf[:rn])
	s.xcheck(err, "read from ctl")
	s.npending -= n
	if s.npending == 0 {
		_, err = fmt.Fprintln(s.conn, "ok")
		s.xcheck(err, "writing ok after reading")
	}
	return n, err
}

func (s *ctlreader) xerror(msg string) {
	if s.x == nil {
		log.Fatalln(msg)
	} else {
		s.log.Debugx("error", fmt.Errorf("%s", msg), mlog.Field("cmd", s.cmd))
		panic(s.x)
	}
}

func (s *ctlreader) xcheck(err error, msg string) {
	if err == nil {
		return
	}
	if s.x == nil {
		log.Fatalf("%s: %s", msg, err)
	} else {
		s.log.Debugx(msg, err, mlog.Field("cmd", s.cmd))
		panic(s.x)
	}
}

// servectl handles requests on the unix domain socket "ctl", e.g. for graceful shutdown, local mail delivery.
func servectl(ctx context.Context, log *mlog.Log, conn net.Conn, shutdown func()) {
	log.Debug("ctl connection")

	var stop = struct{}{} // Sentinel value for panic and recover.
	ctl := &ctl{conn: conn, x: stop, log: log}
	defer func() {
		x := recover()
		if x == nil || x == stop {
			return
		}
		log.Error("servectl panic", mlog.Field("err", x), mlog.Field("cmd", ctl.cmd))
		debug.PrintStack()
		metrics.PanicInc(metrics.Ctl)
	}()

	defer conn.Close()

	ctl.xwrite("ctlv0")
	for {
		servectlcmd(ctx, ctl, shutdown)
	}
}

func servectlcmd(ctx context.Context, ctl *ctl, shutdown func()) {
	log := ctl.log
	cmd := ctl.xread()
	ctl.cmd = cmd
	log.Info("ctl command", mlog.Field("cmd", cmd))
	switch cmd {
	case "stop":
		shutdown()
		os.Exit(0)

	case "deliver":
		/* The protocol, double quoted are literals.

		> "deliver"
		> address
		< "ok"
		> stream
		< "ok"
		*/

		to := ctl.xread()
		a, addr, err := store.OpenEmail(to)
		ctl.xcheck(err, "lookup destination address")

		msgFile, err := store.CreateMessageTemp("ctl-deliver")
		ctl.xcheck(err, "creating temporary message file")
		defer store.CloseRemoveTempFile(log, msgFile, "deliver message")
		mw := message.NewWriter(msgFile)
		ctl.xwriteok()

		ctl.xstreamto(mw)
		err = msgFile.Sync()
		ctl.xcheck(err, "syncing message to storage")

		m := &store.Message{
			Received: time.Now(),
			Size:     mw.Size,
		}

		a.WithWLock(func() {
			err := a.DeliverDestination(log, addr, m, msgFile)
			ctl.xcheck(err, "delivering message")
			log.Info("message delivered through ctl", mlog.Field("to", to))
		})

		err = a.Close()
		ctl.xcheck(err, "closing account")
		ctl.xwriteok()

	case "setaccountpassword":
		/* protocol:
		> "setaccountpassword"
		> account
		> password
		< "ok" or error
		*/

		account := ctl.xread()
		pw := ctl.xread()

		acc, err := store.OpenAccount(account)
		ctl.xcheck(err, "open account")
		defer func() {
			if acc != nil {
				err := acc.Close()
				log.Check(err, "closing account after setting password")
			}
		}()

		err = acc.SetPassword(pw)
		ctl.xcheck(err, "setting password")
		err = acc.Close()
		ctl.xcheck(err, "closing account")
		acc = nil
		ctl.xwriteok()

	case "queue":
		/* protocol:
		> "queue"
		< "ok"
		< stream
		*/
		qmsgs, err := queue.List(ctx)
		ctl.xcheck(err, "listing queue")
		ctl.xwriteok()

		xw := ctl.writer()
		fmt.Fprintln(xw, "queue:")
		for _, qm := range qmsgs {
			var lastAttempt string
			if qm.LastAttempt != nil {
				lastAttempt = time.Since(*qm.LastAttempt).Round(time.Second).String()
			}
			fmt.Fprintf(xw, "%5d %s from:%s to:%s next %s last %s error %q\n", qm.ID, qm.Queued.Format(time.RFC3339), qm.Sender().LogString(), qm.Recipient().LogString(), -time.Since(qm.NextAttempt).Round(time.Second), lastAttempt, qm.LastError)
		}
		if len(qmsgs) == 0 {
			fmt.Fprint(xw, "(empty)\n")
		}
		xw.xclose()

	case "queuekick":
		/* protocol:
		> "queuekick"
		> id
		> todomain
		> recipient
		> transport // if empty, transport is left unchanged; in future, we may want to differtiate between "leave unchanged" and "set to empty string".
		< count
		< "ok" or error
		*/

		idstr := ctl.xread()
		todomain := ctl.xread()
		recipient := ctl.xread()
		transport := ctl.xread()
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			ctl.xwrite("0")
			ctl.xcheck(err, "parsing id")
		}

		var xtransport *string
		if transport != "" {
			xtransport = &transport
		}
		count, err := queue.Kick(ctx, id, todomain, recipient, xtransport)
		ctl.xcheck(err, "kicking queue")
		ctl.xwrite(fmt.Sprintf("%d", count))
		ctl.xwriteok()

	case "queuedrop":
		/* protocol:
		> "queuedrop"
		> id
		> todomain
		> recipient
		< count
		< "ok" or error
		*/

		idstr := ctl.xread()
		todomain := ctl.xread()
		recipient := ctl.xread()
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			ctl.xwrite("0")
			ctl.xcheck(err, "parsing id")
		}

		count, err := queue.Drop(ctx, id, todomain, recipient)
		ctl.xcheck(err, "dropping messages from queue")
		ctl.xwrite(fmt.Sprintf("%d", count))
		ctl.xwriteok()

	case "queuedump":
		/* protocol:
		> "queuedump"
		> id
		< "ok" or error
		< stream
		*/

		idstr := ctl.xread()
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			ctl.xcheck(err, "parsing id")
		}
		mr, err := queue.OpenMessage(ctx, id)
		ctl.xcheck(err, "opening message")
		defer func() {
			err := mr.Close()
			log.Check(err, "closing message from queue")
		}()
		ctl.xwriteok()
		ctl.xstreamfrom(mr)

	case "importmaildir", "importmbox":
		mbox := cmd == "importmbox"
		importctl(ctx, ctl, mbox)

	case "domainadd":
		/* protocol:
		> "domainadd"
		> domain
		> account
		> localpart
		< "ok" or error
		*/
		domain := ctl.xread()
		account := ctl.xread()
		localpart := ctl.xread()
		d, err := dns.ParseDomain(domain)
		ctl.xcheck(err, "parsing domain")
		err = mox.DomainAdd(ctx, d, account, smtp.Localpart(localpart))
		ctl.xcheck(err, "adding domain")
		ctl.xwriteok()

	case "domainrm":
		/* protocol:
		> "domainrm"
		> domain
		< "ok" or error
		*/
		domain := ctl.xread()
		d, err := dns.ParseDomain(domain)
		ctl.xcheck(err, "parsing domain")
		err = mox.DomainRemove(ctx, d)
		ctl.xcheck(err, "removing domain")
		ctl.xwriteok()

	case "accountadd":
		/* protocol:
		> "accountadd"
		> account
		> address
		< "ok" or error
		*/
		account := ctl.xread()
		address := ctl.xread()
		err := mox.AccountAdd(ctx, account, address)
		ctl.xcheck(err, "adding account")
		ctl.xwriteok()

	case "accountrm":
		/* protocol:
		> "accountrm"
		> account
		< "ok" or error
		*/
		account := ctl.xread()
		err := mox.AccountRemove(ctx, account)
		ctl.xcheck(err, "removing account")
		ctl.xwriteok()

	case "addressadd":
		/* protocol:
		> "addressadd"
		> address
		> account
		< "ok" or error
		*/
		address := ctl.xread()
		account := ctl.xread()
		err := mox.AddressAdd(ctx, address, account)
		ctl.xcheck(err, "adding address")
		ctl.xwriteok()

	case "addressrm":
		/* protocol:
		> "addressrm"
		> address
		< "ok" or error
		*/
		address := ctl.xread()
		err := mox.AddressRemove(ctx, address)
		ctl.xcheck(err, "removing address")
		ctl.xwriteok()

	case "loglevels":
		/* protocol:
		> "loglevels"
		< "ok"
		< stream
		*/
		ctl.xwriteok()
		l := mox.Conf.LogLevels()
		keys := []string{}
		for k := range l {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i] < keys[j]
		})
		s := ""
		for _, k := range keys {
			ks := k
			if ks == "" {
				ks = "(default)"
			}
			s += ks + ": " + mlog.LevelStrings[l[k]] + "\n"
		}
		ctl.xstreamfrom(strings.NewReader(s))

	case "setloglevels":
		/* protocol:
		> "setloglevels"
		> pkg
		> level (if empty, log level for pkg will be unset)
		< "ok" or error
		*/
		pkg := ctl.xread()
		levelstr := ctl.xread()
		if levelstr == "" {
			mox.Conf.LogLevelRemove(pkg)
		} else {
			level, ok := mlog.Levels[levelstr]
			if !ok {
				ctl.xerror("bad level")
			}
			mox.Conf.LogLevelSet(pkg, level)
		}
		ctl.xwriteok()

	case "retrain":
		/* protocol:
		> "retrain"
		> account
		< "ok" or error
		*/
		account := ctl.xread()
		acc, err := store.OpenAccount(account)
		ctl.xcheck(err, "open account")
		defer func() {
			if acc != nil {
				err := acc.Close()
				log.Check(err, "closing account after retraining")
			}
		}()

		acc.WithWLock(func() {
			conf, _ := acc.Conf()
			if conf.JunkFilter == nil {
				ctl.xcheck(store.ErrNoJunkFilter, "looking for junk filter")
			}

			// Remove existing junk filter files.
			basePath := mox.DataDirPath("accounts")
			dbPath := filepath.Join(basePath, acc.Name, "junkfilter.db")
			bloomPath := filepath.Join(basePath, acc.Name, "junkfilter.bloom")
			err := os.Remove(dbPath)
			log.Check(err, "removing old junkfilter database file", mlog.Field("path", dbPath))
			err = os.Remove(bloomPath)
			log.Check(err, "removing old junkfilter bloom filter file", mlog.Field("path", bloomPath))

			// Open junk filter, this creates new files.
			jf, _, err := acc.OpenJunkFilter(ctx, ctl.log)
			ctl.xcheck(err, "open new junk filter")
			defer func() {
				if jf == nil {
					return
				}
				err := jf.Close()
				log.Check(err, "closing junk filter during cleanup")
			}()

			// Read through messages with junk or nonjunk flag set, and train them.
			var total, trained int
			q := bstore.QueryDB[store.Message](ctx, acc.DB)
			q.FilterEqual("Expunged", false)
			err = q.ForEach(func(m store.Message) error {
				total++
				ok, err := acc.TrainMessage(ctx, ctl.log, jf, m)
				if ok {
					trained++
				}
				return err
			})
			ctl.xcheck(err, "training messages")
			ctl.log.Info("retrained messages", mlog.Field("total", total), mlog.Field("trained", trained))

			// Close junk filter, marking success.
			err = jf.Close()
			jf = nil
			ctl.xcheck(err, "closing junk filter")
		})
		ctl.xwriteok()

	case "recalculatemailboxcounts":
		/* protocol:
		> "recalculatemailboxcounts"
		> account
		< "ok" or error
		< stream
		*/
		account := ctl.xread()
		acc, err := store.OpenAccount(account)
		ctl.xcheck(err, "open account")
		defer func() {
			if acc != nil {
				err := acc.Close()
				log.Check(err, "closing account after recalculating mailbox counts")
			}
		}()
		ctl.xwriteok()

		w := ctl.writer()

		acc.WithWLock(func() {
			var changes []store.Change
			err = acc.DB.Write(ctx, func(tx *bstore.Tx) error {
				return bstore.QueryTx[store.Mailbox](tx).ForEach(func(mb store.Mailbox) error {
					mc, err := mb.CalculateCounts(tx)
					if err != nil {
						return fmt.Errorf("calculating counts for mailbox %q: %w", mb.Name, err)
					}

					if !mb.HaveCounts || mc != mb.MailboxCounts {
						_, err := fmt.Fprintf(w, "for %s setting new counts %s (was %s)\n", mb.Name, mc, mb.MailboxCounts)
						ctl.xcheck(err, "write")
						mb.HaveCounts = true
						mb.MailboxCounts = mc
						if err := tx.Update(&mb); err != nil {
							return fmt.Errorf("storing new counts for %q: %v", mb.Name, err)
						}
						changes = append(changes, mb.ChangeCounts())
					}
					return nil
				})
			})
			ctl.xcheck(err, "write transaction for mailbox counts")

			store.BroadcastChanges(acc, changes)
		})
		w.xclose()

	case "fixmsgsize":
		/* protocol:
		> "fixmsgsize"
		> account or empty
		< "ok" or error
		< stream
		*/

		accountOpt := ctl.xread()
		ctl.xwriteok()
		w := ctl.writer()

		var foundProblem bool
		const batchSize = 10000

		xfixmsgsize := func(accName string) {
			acc, err := store.OpenAccount(accName)
			ctl.xcheck(err, "open account")
			defer func() {
				err := acc.Close()
				log.Check(err, "closing account after fixing message sizes")
			}()

			total := 0
			var lastID int64
			for {
				var n int

				acc.WithRLock(func() {
					mailboxCounts := map[int64]store.Mailbox{} // For broadcasting.

					// Don't process all message in one transaction, we could block the account for too long.
					err := acc.DB.Write(ctx, func(tx *bstore.Tx) error {
						q := bstore.QueryTx[store.Message](tx)
						q.FilterEqual("Expunged", false)
						q.FilterGreater("ID", lastID)
						q.Limit(batchSize)
						q.SortAsc("ID")
						return q.ForEach(func(m store.Message) error {
							lastID = m.ID
							n++

							p := acc.MessagePath(m.ID)
							st, err := os.Stat(p)
							if err != nil {
								mb := store.Mailbox{ID: m.MailboxID}
								if xerr := tx.Get(&mb); xerr != nil {
									_, werr := fmt.Fprintf(w, "get mailbox id %d for message with file error: %v\n", mb.ID, xerr)
									ctl.xcheck(werr, "write")
								}
								_, werr := fmt.Fprintf(w, "checking file %s for message %d in mailbox %q (id %d): %v (continuing)\n", p, m.ID, mb.Name, mb.ID, err)
								ctl.xcheck(werr, "write")
								return nil
							}
							filesize := st.Size()
							correctSize := int64(len(m.MsgPrefix)) + filesize
							if m.Size == correctSize {
								return nil
							}

							foundProblem = true

							mb := store.Mailbox{ID: m.MailboxID}
							if err := tx.Get(&mb); err != nil {
								_, werr := fmt.Fprintf(w, "get mailbox id %d for message with file size mismatch: %v\n", mb.ID, err)
								ctl.xcheck(werr, "write")
							}
							_, err = fmt.Fprintf(w, "fixing message %d in mailbox %q (id %d) with incorrect size %d, should be %d (len msg prefix %d + on-disk file %s size %d)\n", m.ID, mb.Name, mb.ID, m.Size, correctSize, len(m.MsgPrefix), p, filesize)
							ctl.xcheck(err, "write")

							// We assume that the original message size was accounted as stored in the mailbox
							// total size. If this isn't correct, the user can always run
							// recalculatemailboxcounts.
							mb.Size -= m.Size
							mb.Size += correctSize
							if err := tx.Update(&mb); err != nil {
								return fmt.Errorf("update mailbox counts: %v", err)
							}
							mailboxCounts[mb.ID] = mb

							m.Size = correctSize

							mr := acc.MessageReader(m)
							part, err := message.EnsurePart(log, false, mr, m.Size)
							if err != nil {
								_, werr := fmt.Fprintf(w, "parsing message %d again: %v (continuing)\n", m.ID, err)
								ctl.xcheck(werr, "write")
							}
							m.ParsedBuf, err = json.Marshal(part)
							if err != nil {
								return fmt.Errorf("marshal parsed message: %v", err)
							}
							total++
							if err := tx.Update(&m); err != nil {
								return fmt.Errorf("update message: %v", err)
							}
							return nil
						})

					})
					ctl.xcheck(err, "find and fix wrong message sizes")

					var changes []store.Change
					for _, mb := range mailboxCounts {
						changes = append(changes, mb.ChangeCounts())
					}
					store.BroadcastChanges(acc, changes)
				})
				if n < batchSize {
					break
				}
			}
			_, err = fmt.Fprintf(w, "%d message size(s) fixed for account %s\n", total, accName)
			ctl.xcheck(err, "write")
		}

		if accountOpt != "" {
			xfixmsgsize(accountOpt)
		} else {
			for i, accName := range mox.Conf.Accounts() {
				var line string
				if i > 0 {
					line = "\n"
				}
				_, err := fmt.Fprintf(w, "%sFixing message sizes in account %s...\n", line, accName)
				ctl.xcheck(err, "write")
				xfixmsgsize(accName)
			}
		}
		if foundProblem {
			_, err := fmt.Fprintf(w, "\nProblems were found and fixed. You should invalidate messages stored at imap clients with the \"mox bumpuidvalidity account [mailbox]\" command.\n")
			ctl.xcheck(err, "write")
		}

		w.xclose()

	case "reparse":
		/* protocol:
		> "reparse"
		> account or empty
		< "ok" or error
		< stream
		*/

		accountOpt := ctl.xread()
		ctl.xwriteok()
		w := ctl.writer()

		const batchSize = 100

		xreparseAccount := func(accName string) {
			acc, err := store.OpenAccount(accName)
			ctl.xcheck(err, "open account")
			defer func() {
				err := acc.Close()
				log.Check(err, "closing account after reparsing messages")
			}()

			total := 0
			var lastID int64
			for {
				var n int
				// Don't process all message in one transaction, we could block the account for too long.
				err := acc.DB.Write(ctx, func(tx *bstore.Tx) error {
					q := bstore.QueryTx[store.Message](tx)
					q.FilterEqual("Expunged", false)
					q.FilterGreater("ID", lastID)
					q.Limit(batchSize)
					q.SortAsc("ID")
					return q.ForEach(func(m store.Message) error {
						lastID = m.ID
						mr := acc.MessageReader(m)
						p, err := message.EnsurePart(log, false, mr, m.Size)
						if err != nil {
							_, err := fmt.Fprintf(w, "parsing message %d: %v (continuing)\n", m.ID, err)
							ctl.xcheck(err, "write")
						}
						m.ParsedBuf, err = json.Marshal(p)
						if err != nil {
							return fmt.Errorf("marshal parsed message: %v", err)
						}
						total++
						n++
						if err := tx.Update(&m); err != nil {
							return fmt.Errorf("update message: %v", err)
						}
						return nil
					})

				})
				ctl.xcheck(err, "update messages with parsed mime structure")
				if n < batchSize {
					break
				}
			}
			_, err = fmt.Fprintf(w, "%d message(s) reparsed for account %s\n", total, accName)
			ctl.xcheck(err, "write")
		}

		if accountOpt != "" {
			xreparseAccount(accountOpt)
		} else {
			for i, accName := range mox.Conf.Accounts() {
				var line string
				if i > 0 {
					line = "\n"
				}
				_, err := fmt.Fprintf(w, "%sReparsing account %s...\n", line, accName)
				ctl.xcheck(err, "write")
				xreparseAccount(accName)
			}
		}
		w.xclose()

	case "reassignthreads":
		/* protocol:
		> "reassignthreads"
		> account or empty
		< "ok" or error
		< stream
		*/

		accountOpt := ctl.xread()
		ctl.xwriteok()
		w := ctl.writer()

		xreassignThreads := func(accName string) {
			acc, err := store.OpenAccount(accName)
			ctl.xcheck(err, "open account")
			defer func() {
				err := acc.Close()
				log.Check(err, "closing account after reassigning threads")
			}()

			// We don't want to step on an existing upgrade process.
			err = acc.ThreadingWait(ctl.log)
			ctl.xcheck(err, "waiting for threading upgrade to finish")
			// todo: should we try to continue if the threading upgrade failed? only if there is a chance it will succeed this time...

			// todo: reassigning isn't atomic (in a single transaction), ideally it would be (bstore would need to be able to handle large updates).
			const batchSize = 50000
			total, err := acc.ResetThreading(ctx, ctl.log, batchSize, true)
			ctl.xcheck(err, "resetting threading fields")
			_, err = fmt.Fprintf(w, "New thread base subject assigned to %d message(s), starting to reassign threads...\n", total)
			ctl.xcheck(err, "write")

			// Assign threads again. Ideally we would do this in a single transaction, but
			// bstore/boltdb cannot handle so many pending changes, so we set a high batchsize.
			err = acc.AssignThreads(ctx, ctl.log, nil, 0, 50000, w)
			ctl.xcheck(err, "reassign threads")

			_, err = fmt.Fprintf(w, "Threads reassigned. You should invalidate messages stored at imap clients with the \"mox bumpuidvalidity account [mailbox]\" command.\n")
			ctl.xcheck(err, "write")
		}

		if accountOpt != "" {
			xreassignThreads(accountOpt)
		} else {
			for i, accName := range mox.Conf.Accounts() {
				var line string
				if i > 0 {
					line = "\n"
				}
				_, err := fmt.Fprintf(w, "%sReassigning threads for account %s...\n", line, accName)
				ctl.xcheck(err, "write")
				xreassignThreads(accName)
			}
		}
		w.xclose()

	case "backup":
		backupctl(ctx, ctl)

	default:
		log.Info("unrecognized command", mlog.Field("cmd", cmd))
		ctl.xwrite("unrecognized command")
		return
	}
}
