package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/admin"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/imapserver"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webapi"
)

// ctl represents a connection to the ctl unix domain socket of a running mox instance.
// ctl provides functions to read/write commands/responses/data streams.
type ctl struct {
	cmd  string // Set for server-side of commands.
	conn net.Conn
	r    *bufio.Reader // Set for first reader.
	x    any           // If set, errors are handled by calling panic(x) instead of log.Fatal.
	log  mlog.Log      // If set, along with x, logging is done here.
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
	c.log.Debugx("ctl error", fmt.Errorf("%s", msg), slog.String("cmd", c.cmd))
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
	c.log.Debugx(msg, err, slog.String("cmd", c.cmd))
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
	xw := c.writer()
	_, err := io.Copy(xw, src)
	c.xcheck(err, "copying")
	xw.xclose()
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
	log  mlog.Log
}

// Write implements io.Writer. Errors other than EOF are handled through behaviour
// for s.x, either a panic or log.Fatal.
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
		s.log.Debugx("error", fmt.Errorf("%s", msg), slog.String("cmd", s.cmd))
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
		s.log.Debugx(msg, err, slog.String("cmd", s.cmd))
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
	log      mlog.Log      // If x is set, logging goes to log.
}

// Read implements io.Reader. Errors other than EOF are handled through behaviour
// for s.x, either a panic or log.Fatal.
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
	rn := min(len(buf), s.npending)
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
		s.log.Debugx("error", fmt.Errorf("%s", msg), slog.String("cmd", s.cmd))
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
		s.log.Debugx(msg, err, slog.String("cmd", s.cmd))
		panic(s.x)
	}
}

// servectl handles requests on the unix domain socket "ctl", e.g. for graceful shutdown, local mail delivery.
func servectl(ctx context.Context, cid int64, log mlog.Log, conn net.Conn, shutdown func()) {
	log.Debug("ctl connection")

	var stop = struct{}{} // Sentinel value for panic and recover.
	xctl := &ctl{conn: conn, x: stop, log: log}
	defer func() {
		x := recover()
		if x == nil || x == stop {
			return
		}
		log.Error("servectl panic", slog.Any("err", x), slog.String("cmd", xctl.cmd))
		debug.PrintStack()
		metrics.PanicInc(metrics.Ctl)
	}()

	defer func() {
		err := conn.Close()
		log.Check(err, "close ctl connection")
	}()

	xctl.xwrite("ctlv0")
	for {
		servectlcmd(ctx, xctl, cid, shutdown)
	}
}

func xparseJSON(xctl *ctl, s string, v any) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	xctl.xcheck(err, "parsing from ctl as json")
}

func servectlcmd(ctx context.Context, xctl *ctl, cid int64, shutdown func()) {
	log := xctl.log
	cmd := xctl.xread()
	xctl.cmd = cmd
	log.Info("ctl command", slog.String("cmd", cmd))
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

		to := xctl.xread()
		a, _, addr, err := store.OpenEmail(log, to, false)
		xctl.xcheck(err, "lookup destination address")

		msgFile, err := store.CreateMessageTemp(log, "ctl-deliver")
		xctl.xcheck(err, "creating temporary message file")
		defer store.CloseRemoveTempFile(log, msgFile, "deliver message")
		mw := message.NewWriter(msgFile)
		xctl.xwriteok()

		xctl.xstreamto(mw)
		err = msgFile.Sync()
		xctl.xcheck(err, "syncing message to storage")

		m := store.Message{
			Received: time.Now(),
			Size:     mw.Size,
		}

		a.WithWLock(func() {
			err := a.DeliverDestination(log, addr, &m, msgFile)
			xctl.xcheck(err, "delivering message")
			log.Info("message delivered through ctl", slog.Any("to", to))
		})

		err = a.Close()
		xctl.xcheck(err, "closing account")
		xctl.xwriteok()

	case "setaccountpassword":
		/* protocol:
		> "setaccountpassword"
		> account
		> password
		< "ok" or error
		*/

		account := xctl.xread()
		pw := xctl.xread()

		acc, err := store.OpenAccount(log, account, false)
		xctl.xcheck(err, "open account")
		defer func() {
			if acc != nil {
				err := acc.Close()
				log.Check(err, "closing account after setting password")
			}
		}()

		err = acc.SetPassword(log, pw)
		xctl.xcheck(err, "setting password")
		err = acc.Close()
		xctl.xcheck(err, "closing account")
		acc = nil
		xctl.xwriteok()

	case "queueholdruleslist":
		/* protocol:
		> "queueholdruleslist"
		< "ok"
		< stream
		*/
		l, err := queue.HoldRuleList(ctx)
		xctl.xcheck(err, "listing hold rules")
		xctl.xwriteok()
		xw := xctl.writer()
		fmt.Fprintln(xw, "hold rules:")
		for _, hr := range l {
			var elems []string
			if hr.Account != "" {
				elems = append(elems, fmt.Sprintf("account %q", hr.Account))
			}
			var zerodom dns.Domain
			if hr.SenderDomain != zerodom {
				elems = append(elems, fmt.Sprintf("sender domain %q", hr.SenderDomain.Name()))
			}
			if hr.RecipientDomain != zerodom {
				elems = append(elems, fmt.Sprintf("sender domain %q", hr.RecipientDomain.Name()))
			}
			if len(elems) == 0 {
				fmt.Fprintf(xw, "id %d: all messages\n", hr.ID)
			} else {
				fmt.Fprintf(xw, "id %d: %s\n", hr.ID, strings.Join(elems, ", "))
			}
		}
		if len(l) == 0 {
			fmt.Fprint(xw, "(none)\n")
		}
		xw.xclose()

	case "queueholdrulesadd":
		/* protocol:
		> "queueholdrulesadd"
		> account
		> senderdomainstr
		> recipientdomainstr
		< "ok" or error
		*/
		var hr queue.HoldRule
		hr.Account = xctl.xread()
		senderdomstr := xctl.xread()
		rcptdomstr := xctl.xread()
		var err error
		hr.SenderDomain, err = dns.ParseDomain(senderdomstr)
		xctl.xcheck(err, "parsing sender domain")
		hr.RecipientDomain, err = dns.ParseDomain(rcptdomstr)
		xctl.xcheck(err, "parsing recipient domain")
		hr, err = queue.HoldRuleAdd(ctx, log, hr)
		xctl.xcheck(err, "add hold rule")
		xctl.xwriteok()

	case "queueholdrulesremove":
		/* protocol:
		> "queueholdrulesremove"
		> id
		< "ok" or error
		*/
		idstr := xctl.xread()
		id, err := strconv.ParseInt(idstr, 10, 64)
		xctl.xcheck(err, "parsing id")
		err = queue.HoldRuleRemove(ctx, log, id)
		xctl.xcheck(err, "remove hold rule")
		xctl.xwriteok()

	case "queuelist":
		/* protocol:
		> "queuelist"
		> filters as json
		> sort as json
		< "ok"
		< stream
		*/
		filterline := xctl.xread()
		sortline := xctl.xread()
		var f queue.Filter
		xparseJSON(xctl, filterline, &f)
		var s queue.Sort
		xparseJSON(xctl, sortline, &s)
		qmsgs, err := queue.List(ctx, f, s)
		xctl.xcheck(err, "listing queue")
		xctl.xwriteok()

		xw := xctl.writer()
		fmt.Fprintln(xw, "messages:")
		for _, qm := range qmsgs {
			var lastAttempt string
			if qm.LastAttempt != nil {
				lastAttempt = time.Since(*qm.LastAttempt).Round(time.Second).String()
			}
			fmt.Fprintf(xw, "%5d %s from:%s to:%s next %s last %s error %q\n", qm.ID, qm.Queued.Format(time.RFC3339), qm.Sender().LogString(), qm.Recipient().LogString(), -time.Since(qm.NextAttempt).Round(time.Second), lastAttempt, qm.LastResult().Error)
		}
		if len(qmsgs) == 0 {
			fmt.Fprint(xw, "(none)\n")
		}
		xw.xclose()

	case "queueholdset":
		/* protocol:
		> "queueholdset"
		> queuefilters as json
		> "true" or "false"
		< "ok" or error
		< count
		*/

		filterline := xctl.xread()
		hold := xctl.xread() == "true"
		var f queue.Filter
		xparseJSON(xctl, filterline, &f)
		count, err := queue.HoldSet(ctx, f, hold)
		xctl.xcheck(err, "setting on hold status for messages")
		xctl.xwriteok()
		xctl.xwrite(fmt.Sprintf("%d", count))

	case "queueschedule":
		/* protocol:
		> "queueschedule"
		> queuefilters as json
		> relative to now
		> duration
		< "ok" or error
		< count
		*/

		filterline := xctl.xread()
		relnow := xctl.xread()
		duration := xctl.xread()
		var f queue.Filter
		xparseJSON(xctl, filterline, &f)
		d, err := time.ParseDuration(duration)
		xctl.xcheck(err, "parsing duration for next delivery attempt")
		var count int
		if relnow == "" {
			count, err = queue.NextAttemptAdd(ctx, f, d)
		} else {
			count, err = queue.NextAttemptSet(ctx, f, time.Now().Add(d))
		}
		xctl.xcheck(err, "setting next delivery attempts in queue")
		xctl.xwriteok()
		xctl.xwrite(fmt.Sprintf("%d", count))

	case "queuetransport":
		/* protocol:
		> "queuetransport"
		> queuefilters as json
		> transport
		< "ok" or error
		< count
		*/

		filterline := xctl.xread()
		transport := xctl.xread()
		var f queue.Filter
		xparseJSON(xctl, filterline, &f)
		count, err := queue.TransportSet(ctx, f, transport)
		xctl.xcheck(err, "adding to next delivery attempts in queue")
		xctl.xwriteok()
		xctl.xwrite(fmt.Sprintf("%d", count))

	case "queuerequiretls":
		/* protocol:
		> "queuerequiretls"
		> queuefilters as json
		> reqtls (empty string, "true" or "false")
		< "ok" or error
		< count
		*/

		filterline := xctl.xread()
		reqtls := xctl.xread()
		var req *bool
		switch reqtls {
		case "":
		case "true":
			v := true
			req = &v
		case "false":
			v := false
			req = &v
		default:
			xctl.xcheck(fmt.Errorf("unknown value %q", reqtls), "parsing value")
		}
		var f queue.Filter
		xparseJSON(xctl, filterline, &f)
		count, err := queue.RequireTLSSet(ctx, f, req)
		xctl.xcheck(err, "setting tls requirements on messages in queue")
		xctl.xwriteok()
		xctl.xwrite(fmt.Sprintf("%d", count))

	case "queuefail":
		/* protocol:
		> "queuefail"
		> queuefilters as json
		< "ok" or error
		< count
		*/

		filterline := xctl.xread()
		var f queue.Filter
		xparseJSON(xctl, filterline, &f)
		count, err := queue.Fail(ctx, log, f)
		xctl.xcheck(err, "marking messages from queue as failed")
		xctl.xwriteok()
		xctl.xwrite(fmt.Sprintf("%d", count))

	case "queuedrop":
		/* protocol:
		> "queuedrop"
		> queuefilters as json
		< "ok" or error
		< count
		*/

		filterline := xctl.xread()
		var f queue.Filter
		xparseJSON(xctl, filterline, &f)
		count, err := queue.Drop(ctx, log, f)
		xctl.xcheck(err, "dropping messages from queue")
		xctl.xwriteok()
		xctl.xwrite(fmt.Sprintf("%d", count))

	case "queuedump":
		/* protocol:
		> "queuedump"
		> id
		< "ok" or error
		< stream
		*/

		idstr := xctl.xread()
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			xctl.xcheck(err, "parsing id")
		}
		mr, err := queue.OpenMessage(ctx, id)
		xctl.xcheck(err, "opening message")
		defer func() {
			err := mr.Close()
			log.Check(err, "closing message from queue")
		}()
		xctl.xwriteok()
		xctl.xstreamfrom(mr)

	case "queueretiredlist":
		/* protocol:
		> "queueretiredlist"
		> filters as json
		> sort as json
		< "ok"
		< stream
		*/
		filterline := xctl.xread()
		sortline := xctl.xread()
		var f queue.RetiredFilter
		xparseJSON(xctl, filterline, &f)
		var s queue.RetiredSort
		xparseJSON(xctl, sortline, &s)
		qmsgs, err := queue.RetiredList(ctx, f, s)
		xctl.xcheck(err, "listing retired queue")
		xctl.xwriteok()

		xw := xctl.writer()
		fmt.Fprintln(xw, "retired messages:")
		for _, qm := range qmsgs {
			var lastAttempt string
			if qm.LastAttempt != nil {
				lastAttempt = time.Since(*qm.LastAttempt).Round(time.Second).String()
			}
			result := "failure"
			if qm.Success {
				result = "success"
			}
			sender, err := qm.Sender()
			xcheckf(err, "parsing sender")
			fmt.Fprintf(xw, "%5d %s %s from:%s to:%s last %s error %q\n", qm.ID, qm.Queued.Format(time.RFC3339), result, sender.LogString(), qm.Recipient().LogString(), lastAttempt, qm.LastResult().Error)
		}
		if len(qmsgs) == 0 {
			fmt.Fprint(xw, "(none)\n")
		}
		xw.xclose()

	case "queueretiredprint":
		/* protocol:
		> "queueretiredprint"
		> id
		< "ok"
		< stream
		*/
		idstr := xctl.xread()
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			xctl.xcheck(err, "parsing id")
		}
		l, err := queue.RetiredList(ctx, queue.RetiredFilter{IDs: []int64{id}}, queue.RetiredSort{})
		xctl.xcheck(err, "getting retired messages")
		if len(l) == 0 {
			xctl.xcheck(errors.New("not found"), "getting retired message")
		}
		m := l[0]
		xctl.xwriteok()
		xw := xctl.writer()
		enc := json.NewEncoder(xw)
		enc.SetIndent("", "\t")
		err = enc.Encode(m)
		xctl.xcheck(err, "encode retired message")
		xw.xclose()

	case "queuehooklist":
		/* protocol:
		> "queuehooklist"
		> filters as json
		> sort as json
		< "ok"
		< stream
		*/
		filterline := xctl.xread()
		sortline := xctl.xread()
		var f queue.HookFilter
		xparseJSON(xctl, filterline, &f)
		var s queue.HookSort
		xparseJSON(xctl, sortline, &s)
		hooks, err := queue.HookList(ctx, f, s)
		xctl.xcheck(err, "listing webhooks")
		xctl.xwriteok()

		xw := xctl.writer()
		fmt.Fprintln(xw, "webhooks:")
		for _, h := range hooks {
			var lastAttempt string
			if len(h.Results) > 0 {
				lastAttempt = time.Since(h.LastResult().Start).Round(time.Second).String()
			}
			fmt.Fprintf(xw, "%5d %s account:%s next %s last %s error %q url %s\n", h.ID, h.Submitted.Format(time.RFC3339), h.Account, time.Until(h.NextAttempt).Round(time.Second), lastAttempt, h.LastResult().Error, h.URL)
		}
		if len(hooks) == 0 {
			fmt.Fprint(xw, "(none)\n")
		}
		xw.xclose()

	case "queuehookschedule":
		/* protocol:
		> "queuehookschedule"
		> hookfilters as json
		> relative to now
		> duration
		< "ok" or error
		< count
		*/

		filterline := xctl.xread()
		relnow := xctl.xread()
		duration := xctl.xread()
		var f queue.HookFilter
		xparseJSON(xctl, filterline, &f)
		d, err := time.ParseDuration(duration)
		xctl.xcheck(err, "parsing duration for next delivery attempt")
		var count int
		if relnow == "" {
			count, err = queue.HookNextAttemptAdd(ctx, f, d)
		} else {
			count, err = queue.HookNextAttemptSet(ctx, f, time.Now().Add(d))
		}
		xctl.xcheck(err, "setting next delivery attempts in queue")
		xctl.xwriteok()
		xctl.xwrite(fmt.Sprintf("%d", count))

	case "queuehookcancel":
		/* protocol:
		> "queuehookcancel"
		> hookfilters as json
		< "ok" or error
		< count
		*/

		filterline := xctl.xread()
		var f queue.HookFilter
		xparseJSON(xctl, filterline, &f)
		count, err := queue.HookCancel(ctx, log, f)
		xctl.xcheck(err, "canceling webhooks in queue")
		xctl.xwriteok()
		xctl.xwrite(fmt.Sprintf("%d", count))

	case "queuehookprint":
		/* protocol:
		> "queuehookprint"
		> id
		< "ok"
		< stream
		*/
		idstr := xctl.xread()
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			xctl.xcheck(err, "parsing id")
		}
		l, err := queue.HookList(ctx, queue.HookFilter{IDs: []int64{id}}, queue.HookSort{})
		xctl.xcheck(err, "getting webhooks")
		if len(l) == 0 {
			xctl.xcheck(errors.New("not found"), "getting webhook")
		}
		h := l[0]
		xctl.xwriteok()
		xw := xctl.writer()
		enc := json.NewEncoder(xw)
		enc.SetIndent("", "\t")
		err = enc.Encode(h)
		xctl.xcheck(err, "encode webhook")
		xw.xclose()

	case "queuehookretiredlist":
		/* protocol:
		> "queuehookretiredlist"
		> filters as json
		> sort as json
		< "ok"
		< stream
		*/
		filterline := xctl.xread()
		sortline := xctl.xread()
		var f queue.HookRetiredFilter
		xparseJSON(xctl, filterline, &f)
		var s queue.HookRetiredSort
		xparseJSON(xctl, sortline, &s)
		l, err := queue.HookRetiredList(ctx, f, s)
		xctl.xcheck(err, "listing retired webhooks")
		xctl.xwriteok()

		xw := xctl.writer()
		fmt.Fprintln(xw, "retired webhooks:")
		for _, h := range l {
			var lastAttempt string
			if len(h.Results) > 0 {
				lastAttempt = time.Since(h.LastResult().Start).Round(time.Second).String()
			}
			result := "success"
			if !h.Success {
				result = "failure"
			}
			fmt.Fprintf(xw, "%5d %s %s account:%s last %s error %q url %s\n", h.ID, h.Submitted.Format(time.RFC3339), result, h.Account, lastAttempt, h.LastResult().Error, h.URL)
		}
		if len(l) == 0 {
			fmt.Fprint(xw, "(none)\n")
		}
		xw.xclose()

	case "queuehookretiredprint":
		/* protocol:
		> "queuehookretiredprint"
		> id
		< "ok"
		< stream
		*/
		idstr := xctl.xread()
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			xctl.xcheck(err, "parsing id")
		}
		l, err := queue.HookRetiredList(ctx, queue.HookRetiredFilter{IDs: []int64{id}}, queue.HookRetiredSort{})
		xctl.xcheck(err, "getting retired webhooks")
		if len(l) == 0 {
			xctl.xcheck(errors.New("not found"), "getting retired webhook")
		}
		h := l[0]
		xctl.xwriteok()
		xw := xctl.writer()
		enc := json.NewEncoder(xw)
		enc.SetIndent("", "\t")
		err = enc.Encode(h)
		xctl.xcheck(err, "encode retired webhook")
		xw.xclose()

	case "queuesuppresslist":
		/* protocol:
		> "queuesuppresslist"
		> account (or empty)
		< "ok" or error
		< stream
		*/

		account := xctl.xread()
		l, err := queue.SuppressionList(ctx, account)
		xctl.xcheck(err, "listing suppressions")
		xctl.xwriteok()
		xw := xctl.writer()
		fmt.Fprintln(xw, "suppressions (account, address, manual, time added, base adddress, reason):")
		for _, sup := range l {
			manual := "No"
			if sup.Manual {
				manual = "Yes"
			}
			fmt.Fprintf(xw, "%q\t%q\t%s\t%s\t%q\t%q\n", sup.Account, sup.OriginalAddress, manual, sup.Created.Round(time.Second), sup.BaseAddress, sup.Reason)
		}
		if len(l) == 0 {
			fmt.Fprintln(xw, "(none)")
		}
		xw.xclose()

	case "queuesuppressadd":
		/* protocol:
		> "queuesuppressadd"
		> account
		> address
		< "ok" or error
		*/

		account := xctl.xread()
		address := xctl.xread()
		_, ok := mox.Conf.Account(account)
		if !ok {
			xctl.xcheck(errors.New("unknown account"), "looking up account")
		}
		addr, err := smtp.ParseAddress(address)
		xctl.xcheck(err, "parsing address")
		sup := webapi.Suppression{
			Account: account,
			Manual:  true,
			Reason:  "added through mox cli",
		}
		err = queue.SuppressionAdd(ctx, addr.Path(), &sup)
		xctl.xcheck(err, "adding suppression")
		xctl.xwriteok()

	case "queuesuppressremove":
		/* protocol:
		> "queuesuppressremove"
		> account
		> address
		< "ok" or error
		*/

		account := xctl.xread()
		address := xctl.xread()
		addr, err := smtp.ParseAddress(address)
		xctl.xcheck(err, "parsing address")
		err = queue.SuppressionRemove(ctx, account, addr.Path())
		xctl.xcheck(err, "removing suppression")
		xctl.xwriteok()

	case "queuesuppresslookup":
		/* protocol:
		> "queuesuppresslookup"
		> account or empty
		> address
		< "ok" or error
		< stream
		*/

		account := xctl.xread()
		address := xctl.xread()
		if account != "" {
			_, ok := mox.Conf.Account(account)
			if !ok {
				xctl.xcheck(errors.New("unknown account"), "looking up account")
			}
		}
		addr, err := smtp.ParseAddress(address)
		xctl.xcheck(err, "parsing address")
		sup, err := queue.SuppressionLookup(ctx, account, addr.Path())
		xctl.xcheck(err, "looking up suppression")
		xctl.xwriteok()
		xw := xctl.writer()
		if sup == nil {
			fmt.Fprintln(xw, "not present")
		} else {
			manual := "no"
			if sup.Manual {
				manual = "yes"
			}
			fmt.Fprintf(xw, "present\nadded: %s\nmanual: %s\nbase address: %s\nreason: %q\n", sup.Created.Round(time.Second), manual, sup.BaseAddress, sup.Reason)
		}
		xw.xclose()

	case "importmaildir", "importmbox":
		mbox := cmd == "importmbox"
		ximportctl(ctx, xctl, mbox)

	case "domainadd":
		/* protocol:
		> "domainadd"
		> disabled as "true" or "false"
		> domain
		> account
		> localpart
		< "ok" or error
		*/
		var disabled bool
		switch s := xctl.xread(); s {
		case "true":
			disabled = true
		case "false":
			disabled = false
		default:
			xctl.xcheck(fmt.Errorf("invalid value %q", s), "parsing disabled boolean")
		}

		domain := xctl.xread()
		account := xctl.xread()
		localpart := xctl.xread()
		d, err := dns.ParseDomain(domain)
		xctl.xcheck(err, "parsing domain")
		err = admin.DomainAdd(ctx, disabled, d, account, smtp.Localpart(localpart))
		xctl.xcheck(err, "adding domain")
		xctl.xwriteok()

	case "domainrm":
		/* protocol:
		> "domainrm"
		> domain
		< "ok" or error
		*/
		domain := xctl.xread()
		d, err := dns.ParseDomain(domain)
		xctl.xcheck(err, "parsing domain")
		err = admin.DomainRemove(ctx, d)
		xctl.xcheck(err, "removing domain")
		xctl.xwriteok()

	case "domaindisabled":
		/* protocol:
		> "domaindisabled"
		> "true" or "false"
		> domain
		< "ok" or error
		*/
		domain := xctl.xread()
		var disabled bool
		switch s := xctl.xread(); s {
		case "true":
			disabled = true
		case "false":
			disabled = false
		default:
			xctl.xerror("bad boolean value")
		}
		err := admin.DomainSave(ctx, domain, func(d *config.Domain) error {
			d.Disabled = disabled
			return nil
		})
		xctl.xcheck(err, "saving domain")
		xctl.xwriteok()

	case "accountadd":
		/* protocol:
		> "accountadd"
		> account
		> address
		< "ok" or error
		*/
		account := xctl.xread()
		address := xctl.xread()
		err := admin.AccountAdd(ctx, account, address)
		xctl.xcheck(err, "adding account")
		xctl.xwriteok()

	case "accountrm":
		/* protocol:
		> "accountrm"
		> account
		< "ok" or error
		*/
		account := xctl.xread()
		err := admin.AccountRemove(ctx, account)
		xctl.xcheck(err, "removing account")
		xctl.xwriteok()

	case "accountlist":
		/* protocol:
		> "accountlist"
		< "ok" or error
		< stream
		*/
		xctl.xwriteok()
		xw := xctl.writer()
		all, disabled := mox.Conf.AccountsDisabled()
		slices.Sort(all)
		for _, account := range all {
			var extra string
			if slices.Contains(disabled, account) {
				extra += "\t(disabled)"
			}
			fmt.Fprintf(xw, "%s%s\n", account, extra)
		}
		xw.xclose()

	case "accountdisabled":
		/* protocol:
		> "accountdisabled"
		> account
		> message (if empty, then enabled)
		< "ok" or error
		*/
		account := xctl.xread()
		message := xctl.xread()

		acc, err := store.OpenAccount(log, account, false)
		xctl.xcheck(err, "open account")
		defer func() {
			err := acc.Close()
			log.Check(err, "closing account")
		}()

		err = admin.AccountSave(ctx, account, func(acc *config.Account) {
			acc.LoginDisabled = message
		})
		xctl.xcheck(err, "saving account")

		err = acc.SessionsClear(ctx, xctl.log)
		xctl.xcheck(err, "clearing active web sessions")

		xctl.xwriteok()

	case "accountenable":
		/* protocol:
		> "accountenable"
		> account
		< "ok" or error
		*/
		account := xctl.xread()
		err := admin.AccountSave(ctx, account, func(acc *config.Account) {
			acc.LoginDisabled = ""
		})
		xctl.xcheck(err, "enabling account")
		xctl.xwriteok()

	case "tlspubkeylist":
		/* protocol:
		> "tlspubkeylist"
		> account (or empty)
		< "ok" or error
		< stream
		*/
		accountOpt := xctl.xread()
		tlspubkeys, err := store.TLSPublicKeyList(ctx, accountOpt)
		xctl.xcheck(err, "list tls public keys")
		xctl.xwriteok()
		xw := xctl.writer()
		fmt.Fprintf(xw, "# fingerprint, type, name, account, login address, no imap preauth (%d)\n", len(tlspubkeys))
		for _, k := range tlspubkeys {
			fmt.Fprintf(xw, "%s\t%s\t%q\t%s\t%s\t%v\n", k.Fingerprint, k.Type, k.Name, k.Account, k.LoginAddress, k.NoIMAPPreauth)
		}
		xw.xclose()

	case "tlspubkeyget":
		/* protocol:
		> "tlspubkeyget"
		> fingerprint
		< "ok" or error
		< type
		< name
		< account
		< address
		< noimappreauth (true/false)
		< stream (certder)
		*/
		fp := xctl.xread()
		tlspubkey, err := store.TLSPublicKeyGet(ctx, fp)
		xctl.xcheck(err, "looking tls public key")
		xctl.xwriteok()
		xctl.xwrite(tlspubkey.Type)
		xctl.xwrite(tlspubkey.Name)
		xctl.xwrite(tlspubkey.Account)
		xctl.xwrite(tlspubkey.LoginAddress)
		xctl.xwrite(fmt.Sprintf("%v", tlspubkey.NoIMAPPreauth))
		xctl.xstreamfrom(bytes.NewReader(tlspubkey.CertDER))

	case "tlspubkeyadd":
		/* protocol:
		> "tlspubkeyadd"
		> loginaddress
		> name (or empty)
		> noimappreauth (true/false)
		> stream (certder)
		< "ok" or error
		*/
		loginAddress := xctl.xread()
		name := xctl.xread()
		noimappreauth := xctl.xread()
		if noimappreauth != "true" && noimappreauth != "false" {
			xctl.xcheck(fmt.Errorf("bad value %q", noimappreauth), "parsing noimappreauth")
		}
		var b bytes.Buffer
		xctl.xstreamto(&b)
		tlspubkey, err := store.ParseTLSPublicKeyCert(b.Bytes())
		xctl.xcheck(err, "parsing certificate")
		if name != "" {
			tlspubkey.Name = name
		}
		acc, _, _, err := store.OpenEmail(xctl.log, loginAddress, false)
		xctl.xcheck(err, "open account for address")
		defer func() {
			err := acc.Close()
			xctl.log.Check(err, "close account")
		}()
		tlspubkey.Account = acc.Name
		tlspubkey.LoginAddress = loginAddress
		tlspubkey.NoIMAPPreauth = noimappreauth == "true"

		err = store.TLSPublicKeyAdd(ctx, &tlspubkey)
		xctl.xcheck(err, "adding tls public key")
		xctl.xwriteok()

	case "tlspubkeyrm":
		/* protocol:
		> "tlspubkeyadd"
		> fingerprint
		< "ok" or error
		*/
		fp := xctl.xread()
		err := store.TLSPublicKeyRemove(ctx, fp)
		xctl.xcheck(err, "removing tls public key")
		xctl.xwriteok()

	case "addressadd":
		/* protocol:
		> "addressadd"
		> address
		> account
		< "ok" or error
		*/
		address := xctl.xread()
		account := xctl.xread()
		err := admin.AddressAdd(ctx, address, account)
		xctl.xcheck(err, "adding address")
		xctl.xwriteok()

	case "addressrm":
		/* protocol:
		> "addressrm"
		> address
		< "ok" or error
		*/
		address := xctl.xread()
		err := admin.AddressRemove(ctx, address)
		xctl.xcheck(err, "removing address")
		xctl.xwriteok()

	case "aliaslist":
		/* protocol:
		> "aliaslist"
		> domain
		< "ok" or error
		< stream
		*/
		domain := xctl.xread()
		d, err := dns.ParseDomain(domain)
		xctl.xcheck(err, "parsing domain")
		dc, ok := mox.Conf.Domain(d)
		if !ok {
			xctl.xcheck(errors.New("no such domain"), "listing aliases")
		}
		xctl.xwriteok()
		xw := xctl.writer()
		for _, a := range dc.Aliases {
			lp, err := smtp.ParseLocalpart(a.LocalpartStr)
			xctl.xcheck(err, "parsing alias localpart")
			fmt.Fprintln(xw, smtp.NewAddress(lp, a.Domain).Pack(true))
		}
		xw.xclose()

	case "aliasprint":
		/* protocol:
		> "aliasprint"
		> address
		< "ok" or error
		< stream
		*/
		address := xctl.xread()
		_, alias, ok := mox.Conf.AccountDestination(address)
		if !ok {
			xctl.xcheck(errors.New("no such address"), "looking up alias")
		} else if alias == nil {
			xctl.xcheck(errors.New("address not an alias"), "looking up alias")
		}
		xctl.xwriteok()
		xw := xctl.writer()
		fmt.Fprintf(xw, "# postpublic %v\n", alias.PostPublic)
		fmt.Fprintf(xw, "# listmembers %v\n", alias.ListMembers)
		fmt.Fprintf(xw, "# allowmsgfrom %v\n", alias.AllowMsgFrom)
		fmt.Fprintln(xw, "# members:")
		for _, a := range alias.Addresses {
			fmt.Fprintln(xw, a)
		}
		xw.xclose()

	case "aliasadd":
		/* protocol:
		> "aliasadd"
		> address
		> json alias
		< "ok" or error
		*/
		address := xctl.xread()
		line := xctl.xread()
		addr, err := smtp.ParseAddress(address)
		xctl.xcheck(err, "parsing address")
		var alias config.Alias
		xparseJSON(xctl, line, &alias)
		err = admin.AliasAdd(ctx, addr, alias)
		xctl.xcheck(err, "adding alias")
		xctl.xwriteok()

	case "aliasupdate":
		/* protocol:
		> "aliasupdate"
		> alias
		> "true" or "false" for postpublic
		> "true" or "false" for listmembers
		> "true" or "false" for allowmsgfrom
		< "ok" or error
		*/
		address := xctl.xread()
		postpublic := xctl.xread()
		listmembers := xctl.xread()
		allowmsgfrom := xctl.xread()
		addr, err := smtp.ParseAddress(address)
		xctl.xcheck(err, "parsing address")
		err = admin.DomainSave(ctx, addr.Domain.Name(), func(d *config.Domain) error {
			a, ok := d.Aliases[addr.Localpart.String()]
			if !ok {
				return fmt.Errorf("alias does not exist")
			}

			switch postpublic {
			case "false":
				a.PostPublic = false
			case "true":
				a.PostPublic = true
			}
			switch listmembers {
			case "false":
				a.ListMembers = false
			case "true":
				a.ListMembers = true
			}
			switch allowmsgfrom {
			case "false":
				a.AllowMsgFrom = false
			case "true":
				a.AllowMsgFrom = true
			}

			d.Aliases = maps.Clone(d.Aliases)
			d.Aliases[addr.Localpart.String()] = a
			return nil
		})
		xctl.xcheck(err, "saving alias")
		xctl.xwriteok()

	case "aliasrm":
		/* protocol:
		> "aliasrm"
		> alias
		< "ok" or error
		*/
		address := xctl.xread()
		addr, err := smtp.ParseAddress(address)
		xctl.xcheck(err, "parsing address")
		err = admin.AliasRemove(ctx, addr)
		xctl.xcheck(err, "removing alias")
		xctl.xwriteok()

	case "aliasaddaddr":
		/* protocol:
		> "aliasaddaddr"
		> alias
		> addresses as json
		< "ok" or error
		*/
		address := xctl.xread()
		line := xctl.xread()
		addr, err := smtp.ParseAddress(address)
		xctl.xcheck(err, "parsing address")
		var addresses []string
		xparseJSON(xctl, line, &addresses)
		err = admin.AliasAddressesAdd(ctx, addr, addresses)
		xctl.xcheck(err, "adding addresses to alias")
		xctl.xwriteok()

	case "aliasrmaddr":
		/* protocol:
		> "aliasrmaddr"
		> alias
		> addresses as json
		< "ok" or error
		*/
		address := xctl.xread()
		line := xctl.xread()
		addr, err := smtp.ParseAddress(address)
		xctl.xcheck(err, "parsing address")
		var addresses []string
		xparseJSON(xctl, line, &addresses)
		err = admin.AliasAddressesRemove(ctx, addr, addresses)
		xctl.xcheck(err, "removing addresses to alias")
		xctl.xwriteok()

	case "loglevels":
		/* protocol:
		> "loglevels"
		< "ok"
		< stream
		*/
		xctl.xwriteok()
		l := mox.Conf.LogLevels()
		keys := []string{}
		for k := range l {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		s := ""
		for _, k := range keys {
			ks := k
			if ks == "" {
				ks = "(default)"
			}
			s += ks + ": " + mlog.LevelStrings[l[k]] + "\n"
		}
		xctl.xstreamfrom(strings.NewReader(s))

	case "setloglevels":
		/* protocol:
		> "setloglevels"
		> pkg
		> level (if empty, log level for pkg will be unset)
		< "ok" or error
		*/
		pkg := xctl.xread()
		levelstr := xctl.xread()
		if levelstr == "" {
			mox.Conf.LogLevelRemove(log, pkg)
		} else {
			level, ok := mlog.Levels[levelstr]
			if !ok {
				xctl.xerror("bad level")
			}
			mox.Conf.LogLevelSet(log, pkg, level)
		}
		xctl.xwriteok()

	case "retrain":
		/* protocol:
		> "retrain"
		> account or empty
		< "ok" or error
		*/
		account := xctl.xread()

		xretrain := func(name string) {
			acc, err := store.OpenAccount(log, name, false)
			xctl.xcheck(err, "open account")
			defer func() {
				if acc != nil {
					err := acc.Close()
					log.Check(err, "closing account after retraining")
				}
			}()

			// todo: can we retrain an account without holding a write lock? perhaps by writing a junkfilter to a new location, and staying informed of message changes while we go through all messages in the account?

			acc.WithWLock(func() {
				conf, _ := acc.Conf()
				if conf.JunkFilter == nil {
					xctl.xcheck(store.ErrNoJunkFilter, "looking for junk filter")
				}

				// Remove existing junk filter files.
				basePath := mox.DataDirPath("accounts")
				dbPath := filepath.Join(basePath, acc.Name, "junkfilter.db")
				bloomPath := filepath.Join(basePath, acc.Name, "junkfilter.bloom")
				err := os.Remove(dbPath)
				log.Check(err, "removing old junkfilter database file", slog.String("path", dbPath))
				err = os.Remove(bloomPath)
				log.Check(err, "removing old junkfilter bloom filter file", slog.String("path", bloomPath))

				// Open junk filter, this creates new files.
				jf, _, err := acc.OpenJunkFilter(ctx, log)
				xctl.xcheck(err, "open new junk filter")
				defer func() {
					if jf == nil {
						return
					}
					err := jf.CloseDiscard()
					log.Check(err, "closing junk filter during cleanup")
				}()

				// Read through messages with either junk or nonjunk flag set, and train them.
				var total, trained int
				err = acc.DB.Write(ctx, func(tx *bstore.Tx) error {
					q := bstore.QueryTx[store.Message](tx)
					q.FilterEqual("Expunged", false)
					return q.ForEach(func(m store.Message) error {
						total++
						if m.Junk == m.Notjunk {
							return nil
						}
						ok, err := acc.TrainMessage(ctx, log, jf, m.Notjunk, m)
						if ok {
							trained++
						}
						if m.TrainedJunk == nil || *m.TrainedJunk != m.Junk {
							m.TrainedJunk = &m.Junk
							if err := tx.Update(&m); err != nil {
								return fmt.Errorf("marking message as trained: %v", err)
							}
						}
						return err
					})
				})
				xctl.xcheck(err, "training messages")
				log.Info("retrained messages", slog.Int("total", total), slog.Int("trained", trained))

				// Close junk filter, marking success.
				err = jf.Close()
				jf = nil
				xctl.xcheck(err, "closing junk filter")
			})
		}

		if account == "" {
			for _, name := range mox.Conf.Accounts() {
				xretrain(name)
			}
		} else {
			xretrain(account)
		}
		xctl.xwriteok()

	case "recalculatemailboxcounts":
		/* protocol:
		> "recalculatemailboxcounts"
		> account
		< "ok" or error
		< stream
		*/
		account := xctl.xread()
		acc, err := store.OpenAccount(log, account, false)
		xctl.xcheck(err, "open account")
		defer func() {
			if acc != nil {
				err := acc.Close()
				log.Check(err, "closing account after recalculating mailbox counts")
			}
		}()
		xctl.xwriteok()

		xw := xctl.writer()

		acc.WithWLock(func() {
			var changes []store.Change
			err = acc.DB.Write(ctx, func(tx *bstore.Tx) error {
				var totalSize int64
				err := bstore.QueryTx[store.Mailbox](tx).FilterEqual("Expunged", false).ForEach(func(mb store.Mailbox) error {
					mc, err := mb.CalculateCounts(tx)
					if err != nil {
						return fmt.Errorf("calculating counts for mailbox %q: %w", mb.Name, err)
					}
					totalSize += mc.Size

					if mc != mb.MailboxCounts {
						fmt.Fprintf(xw, "for %s setting new counts %s (was %s)\n", mb.Name, mc, mb.MailboxCounts)
						mb.HaveCounts = true
						mb.MailboxCounts = mc
						if err := tx.Update(&mb); err != nil {
							return fmt.Errorf("storing new counts for %q: %v", mb.Name, err)
						}
						changes = append(changes, mb.ChangeCounts())
					}
					return nil
				})
				if err != nil {
					return err
				}

				du := store.DiskUsage{ID: 1}
				if err := tx.Get(&du); err != nil {
					return fmt.Errorf("get disk usage: %v", err)
				}
				if du.MessageSize != totalSize {
					fmt.Fprintf(xw, "setting new total message size %d (was %d)\n", totalSize, du.MessageSize)
					du.MessageSize = totalSize
					if err := tx.Update(&du); err != nil {
						return fmt.Errorf("update disk usage: %v", err)
					}
				}
				return nil
			})
			xctl.xcheck(err, "write transaction for mailbox counts")

			store.BroadcastChanges(acc, changes)
		})
		xw.xclose()

	case "fixmsgsize":
		/* protocol:
		> "fixmsgsize"
		> account or empty
		< "ok" or error
		< stream
		*/

		accountOpt := xctl.xread()
		xctl.xwriteok()
		xw := xctl.writer()

		var foundProblem bool
		const batchSize = 10000

		xfixmsgsize := func(accName string) {
			acc, err := store.OpenAccount(log, accName, false)
			xctl.xcheck(err, "open account")
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
									fmt.Fprintf(xw, "get mailbox id %d for message with file error: %v\n", mb.ID, xerr)
								}
								fmt.Fprintf(xw, "checking file %s for message %d in mailbox %q (id %d): %v (continuing)\n", p, m.ID, mb.Name, mb.ID, err)
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
								fmt.Fprintf(xw, "get mailbox id %d for message with file size mismatch: %v\n", mb.ID, err)
								return nil
							}
							if mb.Expunged {
								fmt.Fprintf(xw, "message %d is in expunged mailbox %q (id %d) (continuing)\n", m.ID, mb.Name, mb.ID)
							}
							fmt.Fprintf(xw, "fixing message %d in mailbox %q (id %d) with incorrect size %d, should be %d (len msg prefix %d + on-disk file %s size %d)\n", m.ID, mb.Name, mb.ID, m.Size, correctSize, len(m.MsgPrefix), p, filesize)

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
							part, err := message.EnsurePart(log.Logger, false, mr, m.Size)
							if err != nil {
								fmt.Fprintf(xw, "parsing message %d again: %v (continuing)\n", m.ID, err)
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
					xctl.xcheck(err, "find and fix wrong message sizes")

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
			fmt.Fprintf(xw, "%d message size(s) fixed for account %s\n", total, accName)
		}

		if accountOpt != "" {
			xfixmsgsize(accountOpt)
		} else {
			for i, accName := range mox.Conf.Accounts() {
				var line string
				if i > 0 {
					line = "\n"
				}
				fmt.Fprintf(xw, "%sFixing message sizes in account %s...\n", line, accName)
				xfixmsgsize(accName)
			}
		}
		if foundProblem {
			fmt.Fprintf(xw, "\nProblems were found and fixed. You should invalidate messages stored at imap clients with the \"mox bumpuidvalidity account [mailbox]\" command.\n")
		}

		xw.xclose()

	case "reparse":
		/* protocol:
		> "reparse"
		> account or empty
		< "ok" or error
		< stream
		*/

		accountOpt := xctl.xread()
		xctl.xwriteok()
		xw := xctl.writer()

		xreparseAccount := func(accName string) {
			acc, err := store.OpenAccount(log, accName, false)
			xctl.xcheck(err, "open account")
			defer func() {
				err := acc.Close()
				log.Check(err, "closing account after reparsing messages")
			}()

			start := time.Now()
			total, err := acc.ReparseMessages(ctx, log)
			xctl.xcheck(err, "reparse messages")

			fmt.Fprintf(xw, "%d message(s) reparsed for account %s in %dms\n", total, accName, time.Since(start)/time.Millisecond)
		}

		if accountOpt != "" {
			xreparseAccount(accountOpt)
		} else {
			for i, accName := range mox.Conf.Accounts() {
				var line string
				if i > 0 {
					line = "\n"
				}
				fmt.Fprintf(xw, "%sReparsing account %s...\n", line, accName)
				xreparseAccount(accName)
			}
		}
		xw.xclose()

	case "reassignthreads":
		/* protocol:
		> "reassignthreads"
		> account or empty
		< "ok" or error
		< stream
		*/

		accountOpt := xctl.xread()
		xctl.xwriteok()
		xw := xctl.writer()

		xreassignThreads := func(accName string) {
			acc, err := store.OpenAccount(log, accName, false)
			xctl.xcheck(err, "open account")
			defer func() {
				err := acc.Close()
				log.Check(err, "closing account after reassigning threads")
			}()

			// We don't want to step on an existing upgrade process.
			err = acc.ThreadingWait(log)
			xctl.xcheck(err, "waiting for threading upgrade to finish")
			// todo: should we try to continue if the threading upgrade failed? only if there is a chance it will succeed this time...

			// todo: reassigning isn't atomic (in a single transaction), ideally it would be (bstore would need to be able to handle large updates).
			const batchSize = 50000
			total, err := acc.ResetThreading(ctx, log, batchSize, true)
			xctl.xcheck(err, "resetting threading fields")
			fmt.Fprintf(xw, "New thread base subject assigned to %d message(s), starting to reassign threads...\n", total)

			// Assign threads again. Ideally we would do this in a single transaction, but
			// bstore/boltdb cannot handle so many pending changes, so we set a high batchsize.
			err = acc.AssignThreads(ctx, log, nil, 0, 50000, xw)
			xctl.xcheck(err, "reassign threads")

			fmt.Fprintf(xw, "Threads reassigned. You should invalidate messages stored at imap clients with the \"mox bumpuidvalidity account [mailbox]\" command.\n")
		}

		if accountOpt != "" {
			xreassignThreads(accountOpt)
		} else {
			for i, accName := range mox.Conf.Accounts() {
				var line string
				if i > 0 {
					line = "\n"
				}
				fmt.Fprintf(xw, "%sReassigning threads for account %s...\n", line, accName)
				xreassignThreads(accName)
			}
		}
		xw.xclose()

	case "backup":
		xbackupctl(ctx, xctl)

	case "imapserve":
		/* protocol:
		> "imapserve"
		> address
		< "ok or error"
		imap protocol
		*/
		address := xctl.xread()
		xctl.xwriteok()
		imapserver.ServeConnPreauth("(imapserve)", cid, xctl.conn, address)
		xctl.log.Debug("imap connection finished")

	default:
		log.Info("unrecognized command", slog.String("cmd", cmd))
		xctl.xwrite("unrecognized command")
		return
	}
}
