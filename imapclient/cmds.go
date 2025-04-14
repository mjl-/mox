package imapclient

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"github.com/mjl-/flate"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/scram"
)

// Capability writes the IMAP4 "CAPABILITY" command, requesting a list of
// capabilities from the server. They are returned in an UntaggedCapability
// response. The server also sends capabilities in initial server greeting, in the
// response code.
func (c *Conn) Capability() (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("capability")
}

// Noop writes the IMAP4 "NOOP" command, which does nothing on its own, but a
// server will return any pending untagged responses for new message delivery and
// changes to mailboxes.
func (c *Conn) Noop() (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("noop")
}

// Logout ends the IMAP4 session by writing an IMAP "LOGOUT" command. [Conn.Close]
// must still be called on this client to close the socket.
func (c *Conn) Logout() (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("logout")
}

// StartTLS enables TLS on the connection with the IMAP4 "STARTTLS" command.
func (c *Conn) StartTLS(config *tls.Config) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	resp, rerr = c.transactf("starttls")
	c.xcheckf(rerr, "starttls command")

	conn := c.xprefixConn()
	tlsConn := tls.Client(conn, config)
	err := tlsConn.Handshake()
	c.xcheckf(err, "tls handshake")
	c.conn = tlsConn
	return
}

// Login authenticates using the IMAP4 "LOGIN" command, sending the plain text
// password to the server.
//
// Authentication is not allowed while the "LOGINDISABLED" capability is announced.
// Call [Conn.StartTLS] first.
//
// See [Conn.AuthenticateSCRAM] for a better authentication mechanism.
func (c *Conn) Login(username, password string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	fmt.Fprintf(c.xbw, "%s login %s ", c.nextTag(), astring(username))
	defer c.xtracewrite(mlog.LevelTraceauth)()
	fmt.Fprintf(c.xbw, "%s\r\n", astring(password))
	c.xtracewrite(mlog.LevelTrace) // Restore.
	return c.responseOK()
}

// AuthenticatePlain executes the AUTHENTICATE command with SASL mechanism "PLAIN",
// sending the password in plain text password to the server.
//
// Required capability: "AUTH=PLAIN"
//
// Authentication is not allowed while the "LOGINDISABLED" capability is announced.
// Call [Conn.StartTLS] first.
//
// See [Conn.AuthenticateSCRAM] for a better authentication mechanism.
func (c *Conn) AuthenticatePlain(username, password string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	err := c.WriteCommandf("", "authenticate plain")
	c.xcheckf(err, "writing authenticate command")
	_, rerr = c.readContinuation()
	c.xresponse(rerr, &resp)

	defer c.xtracewrite(mlog.LevelTraceauth)()
	xw := base64.NewEncoder(base64.StdEncoding, c.xbw)
	fmt.Fprintf(xw, "\u0000%s\u0000%s", username, password)
	xw.Close()
	c.xtracewrite(mlog.LevelTrace) // Restore.
	fmt.Fprintf(c.xbw, "\r\n")
	c.xflush()
	return c.responseOK()
}

// todo: implement cram-md5, write its credentials as traceauth.

// AuthenticateSCRAM executes the IMAP4 "AUTHENTICATE" command with one of the
// following SASL mechanisms: SCRAM-SHA-256(-PLUS) or SCRAM-SHA-1(-PLUS).//
//
// With SCRAM, the password is not sent to the server in plain text, but only
// derived hashes are exchanged by both parties as proof of knowledge of password.
//
// Authentication is not allowed while the "LOGINDISABLED" capability is announced.
// Call [Conn.StartTLS] first.
//
// Required capability: SCRAM-SHA-256-PLUS, SCRAM-SHA-256, SCRAM-SHA-1-PLUS,
// SCRAM-SHA-1.
//
// The PLUS variants bind the authentication exchange to the TLS connection,
// detecting MitM attacks.
func (c *Conn) AuthenticateSCRAM(mechanism string, h func() hash.Hash, username, password string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	var cs *tls.ConnectionState
	lmech := strings.ToLower(mechanism)
	if strings.HasSuffix(lmech, "-plus") {
		tlsConn, ok := c.conn.(*tls.Conn)
		if !ok {
			c.xerrorf("cannot use scram plus without tls")
		}
		xcs := tlsConn.ConnectionState()
		cs = &xcs
	}
	sc := scram.NewClient(h, username, "", false, cs)
	clientFirst, err := sc.ClientFirst()
	c.xcheckf(err, "scram clientFirst")
	// todo: only send clientFirst if server has announced SASL-IR
	err = c.Writelinef("%s authenticate %s %s", c.nextTag(), mechanism, base64.StdEncoding.EncodeToString([]byte(clientFirst)))
	c.xcheckf(err, "writing command line")

	xreadContinuation := func() []byte {
		var line string
		line, rerr = c.readContinuation()
		c.xresponse(rerr, &resp)
		buf, err := base64.StdEncoding.DecodeString(line)
		c.xcheckf(err, "parsing base64 from remote")
		return buf
	}

	serverFirst := xreadContinuation()
	clientFinal, err := sc.ServerFirst(serverFirst, password)
	c.xcheckf(err, "scram clientFinal")
	err = c.Writelinef("%s", base64.StdEncoding.EncodeToString([]byte(clientFinal)))
	c.xcheckf(err, "write scram clientFinal")

	serverFinal := xreadContinuation()
	err = sc.ServerFinal(serverFinal)
	c.xcheckf(err, "scram serverFinal")

	// We must send a response to the server continuation line, but we have nothing to say. ../rfc/9051:6221
	err = c.Writelinef("%s", base64.StdEncoding.EncodeToString(nil))
	c.xcheckf(err, "scram client end")

	return c.responseOK()
}

// CompressDeflate enables compression with deflate on the connection by executing
// the IMAP4 "COMPRESS=DEFAULT" command.
//
// Required capability: "COMPRESS=DEFLATE".
//
// State: Authenticated or selected.
func (c *Conn) CompressDeflate() (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	resp, rerr = c.transactf("compress deflate")
	c.xcheck(rerr)

	c.xflateBW = bufio.NewWriter(c)
	fw0, err := flate.NewWriter(c.xflateBW, flate.DefaultCompression)
	c.xcheckf(err, "deflate") // Cannot happen.
	fw := moxio.NewFlateWriter(fw0)

	c.compress = true
	c.xflateWriter = fw
	c.xtw = moxio.NewTraceWriter(mlog.New("imapclient", nil), "CW: ", fw)
	c.xbw = bufio.NewWriter(c.xtw)

	rc := c.xprefixConn()
	fr := flate.NewReaderPartial(rc)
	c.tr = moxio.NewTraceReader(mlog.New("imapclient", nil), "CR: ", fr)
	c.br = bufio.NewReader(c.tr)

	return
}

// Enable enables capabilities for use with the connection by executing the IMAP4 "ENABLE" command.
//
// Required capability: "ENABLE" or "IMAP4rev2"
func (c *Conn) Enable(capabilities ...Capability) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	var caps strings.Builder
	for _, c := range capabilities {
		caps.WriteString(" " + string(c))
	}
	return c.transactf("enable%s", caps.String())
}

// Select opens the mailbox with the IMAP4 "SELECT" command.
//
// If a mailbox is selected/active, it is automatically deselected before
// selecting the mailbox, without permanently removing ("expunging") messages
// marked \Deleted.
//
// If the mailbox cannot be opened, the connection is left in Authenticated state,
// not Selected.
func (c *Conn) Select(mailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("select %s", astring(mailbox))
}

// Examine opens the mailbox like [Conn.Select], but read-only, with the IMAP4
// "EXAMINE" command.
func (c *Conn) Examine(mailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("examine %s", astring(mailbox))
}

// Create makes a new mailbox on the server using the IMAP4 "CREATE" command.
//
// SpecialUse can only be used on servers that announced the "CREATE-SPECIAL-USE"
// capability. Specify flags like \Archive, \Drafts, \Junk, \Sent, \Trash, \All.
func (c *Conn) Create(mailbox string, specialUse []string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	var useStr string
	if len(specialUse) > 0 {
		useStr = fmt.Sprintf(" USE (%s)", strings.Join(specialUse, " "))
	}
	return c.transactf("create %s%s", astring(mailbox), useStr)
}

// Delete removes an entire mailbox and its messages using the IMAP4 "DELETE"
// command.
func (c *Conn) Delete(mailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("delete %s", astring(mailbox))
}

// Rename changes the name of a mailbox and all its child mailboxes
// using the IMAP4 "RENAME" command.
func (c *Conn) Rename(omailbox, nmailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("rename %s %s", astring(omailbox), astring(nmailbox))
}

// Subscribe marks a mailbox as subscribed using the IMAP4 "SUBSCRIBE" command.
//
// The mailbox does not have to exist. It is not an error if the mailbox is already
// subscribed.
func (c *Conn) Subscribe(mailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("subscribe %s", astring(mailbox))
}

// Unsubscribe marks a mailbox as unsubscribed using the IMAP4 "UNSUBSCRIBE"
// command.
func (c *Conn) Unsubscribe(mailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("unsubscribe %s", astring(mailbox))
}

// List lists mailboxes using the IMAP4 "LIST" command with the basic LIST syntax.
// Pattern can contain * (match any) or % (match any except hierarchy delimiter).
func (c *Conn) List(pattern string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf(`list "" %s`, astring(pattern))
}

// ListFull lists mailboxes using the LIST command with the extended LIST
// syntax requesting all supported data.
//
// Required capability: "LIST-EXTENDED". If "IMAP4rev2" is announced, the command
// is also available but only with a single pattern.
//
// Pattern can contain * (match any) or % (match any except hierarchy delimiter).
func (c *Conn) ListFull(subscribedOnly bool, patterns ...string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	var subscribedStr string
	if subscribedOnly {
		subscribedStr = "subscribed recursivematch"
	}
	for i, s := range patterns {
		patterns[i] = astring(s)
	}
	return c.transactf(`list (%s) "" (%s) return (subscribed children special-use status (messages uidnext uidvalidity unseen deleted size recent appendlimit))`, subscribedStr, strings.Join(patterns, " "))
}

// Namespace requests the hiearchy separator using the IMAP4 "NAMESPACE" command.
//
// Required capability: "NAMESPACE" or "IMAP4rev2".
//
// Server will return an UntaggedNamespace response with personal/shared/other
// namespaces if present.
func (c *Conn) Namespace() (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("namespace")
}

// Status requests information about a mailbox using the IMAP4 "STATUS" command. For
// example, number of messages, size, etc. At least one attribute required.
func (c *Conn) Status(mailbox string, attrs ...StatusAttr) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	l := make([]string, len(attrs))
	for i, a := range attrs {
		l[i] = string(a)
	}
	return c.transactf("status %s (%s)", astring(mailbox), strings.Join(l, " "))
}

// Append represents a parameter to the IMAP4 "APPEND" or "REPLACE" commands, for
// adding a message to mailbox, or replacing a message with a new version in a
// mailbox.
type Append struct {
	Flags    []string   // Optional, flags for the new message.
	Received *time.Time // Optional, the INTERNALDATE field, typically time at which a message was received.
	Size     int64
	Data     io.Reader // Required, must return Size bytes.
}

// Append adds message to mailbox with flags and optional receive time using the
// IMAP4 "APPEND" command.
func (c *Conn) Append(mailbox string, message Append) (resp Response, rerr error) {
	return c.MultiAppend(mailbox, message)
}

// MultiAppend atomatically adds multiple messages to the mailbox.
//
// Required capability: "MULTIAPPEND"
func (c *Conn) MultiAppend(mailbox string, message Append, more ...Append) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	fmt.Fprintf(c.xbw, "%s append %s", c.nextTag(), astring(mailbox))

	msgs := append([]Append{message}, more...)
	for _, m := range msgs {
		var date string
		if m.Received != nil {
			date = ` "` + m.Received.Format("_2-Jan-2006 15:04:05 -0700") + `"`
		}

		// todo: use literal8 if needed, with "UTF8()" if required.
		// todo: for larger messages, use a synchronizing literal.

		fmt.Fprintf(c.xbw, " (%s)%s {%d+}\r\n", strings.Join(m.Flags, " "), date, m.Size)
		defer c.xtracewrite(mlog.LevelTracedata)()
		_, err := io.Copy(c.xbw, m.Data)
		c.xcheckf(err, "write message data")
		c.xtracewrite(mlog.LevelTrace) // Restore
	}

	fmt.Fprintf(c.xbw, "\r\n")
	c.xflush()
	return c.responseOK()
}

// note: No Idle or Notify command. Idle/Notify is better implemented by
// writing the request and reading and handling the responses as they come in.

// CloseMailbox closes the selected/active mailbox using the IMAP4 "CLOSE" command,
// permanently removing ("expunging") any messages marked with \Deleted.
//
// See [Conn.Unselect] for closing a mailbox without permanently removing messages.
func (c *Conn) CloseMailbox() (resp Response, rerr error) {
	return c.transactf("close")
}

// Unselect closes the selected/active mailbox using the IMAP4 "UNSELECT" command,
// but unlike MailboxClose does not permanently remove ("expunge") any messages
// marked with \Deleted.
//
// Required capability: "UNSELECT" or "IMAP4rev2".
//
// If Unselect is not available, call [Conn.Select] with a non-existent mailbox for
// the same effect: Deselecting a mailbox without permanently removing messages
// marked \Deleted.
func (c *Conn) Unselect() (resp Response, rerr error) {
	return c.transactf("unselect")
}

// Expunge removes all messages marked as deleted for the selected mailbox using
// the IMAP4 "EXPUNGE" command. If other sessions marked messages as deleted, even
// if they aren't visible in the session, they are removed as well.
//
// UIDExpunge gives more control over which the messages that are removed.
func (c *Conn) Expunge() (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("expunge")
}

// UIDExpunge is like expunge, but only removes messages matching UID set, using
// the IMAP4 "UID EXPUNGE" command.
//
// Required capability: "UIDPLUS" or "IMAP4rev2".
func (c *Conn) UIDExpunge(uidSet NumSet) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("uid expunge %s", uidSet.String())
}

// Note: No search, fetch command yet due to its large syntax.

// MSNStoreFlagsSet stores a new set of flags for messages matching message
// sequence numbers (MSNs) from sequence set with the IMAP4 "STORE" command.
//
// If silent, no untagged responses with the updated flags will be sent by the
// server.
//
// Method [Conn.UIDStoreFlagsSet], which operates on a uid set, should be
// preferred.
func (c *Conn) MSNStoreFlagsSet(seqset string, silent bool, flags ...string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	item := "flags"
	if silent {
		item += ".silent"
	}
	return c.transactf("store %s %s (%s)", seqset, item, strings.Join(flags, " "))
}

// MSNStoreFlagsAdd is like [Conn.MSNStoreFlagsSet], but only adds flags, leaving
// current flags on the message intact.
//
// Method [Conn.UIDStoreFlagsAdd], which operates on a uid set, should be
// preferred.
func (c *Conn) MSNStoreFlagsAdd(seqset string, silent bool, flags ...string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	item := "+flags"
	if silent {
		item += ".silent"
	}
	return c.transactf("store %s %s (%s)", seqset, item, strings.Join(flags, " "))
}

// MSNStoreFlagsClear is like [Conn.MSNStoreFlagsSet], but only removes flags,
// leaving other flags on the message intact.
//
// Method [Conn.UIDStoreFlagsClear], which operates on a uid set, should be
// preferred.
func (c *Conn) MSNStoreFlagsClear(seqset string, silent bool, flags ...string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	item := "-flags"
	if silent {
		item += ".silent"
	}
	return c.transactf("store %s %s (%s)", seqset, item, strings.Join(flags, " "))
}

// UIDStoreFlagsSet stores a new set of flags for messages matching UIDs from
// uidSet with the IMAP4 "UID STORE" command.
//
// If silent, no untagged responses with the updated flags will be sent by the
// server.
//
// Required capability: "UIDPLUS" or "IMAP4rev2".
func (c *Conn) UIDStoreFlagsSet(uidSet string, silent bool, flags ...string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	item := "flags"
	if silent {
		item += ".silent"
	}
	return c.transactf("uid store %s %s (%s)", uidSet, item, strings.Join(flags, " "))
}

// UIDStoreFlagsAdd is like UIDStoreFlagsSet, but only adds flags, leaving
// current flags on the message intact.
//
// Required capability: "UIDPLUS" or "IMAP4rev2".
func (c *Conn) UIDStoreFlagsAdd(uidSet string, silent bool, flags ...string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	item := "+flags"
	if silent {
		item += ".silent"
	}
	return c.transactf("uid store %s %s (%s)", uidSet, item, strings.Join(flags, " "))
}

// UIDStoreFlagsClear is like UIDStoreFlagsSet, but only removes flags, leaving
// other flags on the message intact.
//
// Required capability: "UIDPLUS" or "IMAP4rev2".
func (c *Conn) UIDStoreFlagsClear(uidSet string, silent bool, flags ...string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	item := "-flags"
	if silent {
		item += ".silent"
	}
	return c.transactf("uid store %s %s (%s)", uidSet, item, strings.Join(flags, " "))
}

// MSNCopy adds messages from the sequences in the sequence set in the
// selected/active mailbox to destMailbox using the IMAP4 "COPY" command.
//
// Method [Conn.UIDCopy], operating on UIDs instead of sequence numbers, should be
// preferred.
func (c *Conn) MSNCopy(seqSet string, destMailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("copy %s %s", seqSet, astring(destMailbox))
}

// UIDCopy is like copy, but operates on UIDs, using the IMAP4 "UID COPY" command.
//
// Required capability: "UIDPLUS" or "IMAP4rev2".
func (c *Conn) UIDCopy(uidSet string, destMailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("uid copy %s %s", uidSet, astring(destMailbox))
}

// MSNSearch returns messages from the sequence set in the selected/active mailbox
// that match the search critera using the IMAP4 "SEARCH" command.
//
// Method [Conn.UIDSearch], operating on UIDs instead of sequence numbers, should be
// preferred.
func (c *Conn) MSNSearch(seqSet string, criteria string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("seach %s %s", seqSet, criteria)
}

// UIDSearch returns messages from the uid set in the selected/active mailbox that
// match the search critera using the IMAP4 "SEARCH" command.
//
// Criteria is a search program, see RFC 9051 and RFC 3501 for details.
//
// Required capability: "UIDPLUS" or "IMAP4rev2".
func (c *Conn) UIDSearch(seqSet string, criteria string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("seach %s %s", seqSet, criteria)
}

// MSNMove moves messages from the sequence set in the selected/active mailbox to
// destMailbox using the IMAP4 "MOVE" command.
//
// Required capability: "MOVE" or "IMAP4rev2".
//
// Method [Conn.UIDMove], operating on UIDs instead of sequence numbers, should be
// preferred.
func (c *Conn) MSNMove(seqSet string, destMailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("move %s %s", seqSet, astring(destMailbox))
}

// UIDMove is like move, but operates on UIDs, using the IMAP4 "UID MOVE" command.
//
// Required capability: "MOVE" or "IMAP4rev2".
func (c *Conn) UIDMove(uidSet string, destMailbox string) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)
	return c.transactf("uid move %s %s", uidSet, astring(destMailbox))
}

// MSNReplace is like the preferred [Conn.UIDReplace], but operates on a message
// sequence number (MSN) instead of a UID.
//
// Required capability: "REPLACE".
//
// Method [Conn.UIDReplace], operating on UIDs instead of sequence numbers, should be
// preferred.
func (c *Conn) MSNReplace(msgseq string, mailbox string, msg Append) (resp Response, rerr error) {
	// todo: parse msgseq, must be nznumber, with a known msgseq. or "*" with at least one message.
	return c.replace("replace", msgseq, mailbox, msg)
}

// UIDReplace uses the IMAP4 "UID REPLACE" command to replace a message from the
// selected/active mailbox with a new/different version of the message in the named
// mailbox, which may be the same or different than the selected mailbox.
//
// The replaced message is indicated by uid.
//
// Required capability: "REPLACE".
func (c *Conn) UIDReplace(uid string, mailbox string, msg Append) (resp Response, rerr error) {
	// todo: parse uid, must be nznumber, with a known uid. or "*" with at least one message.
	return c.replace("uid replace", uid, mailbox, msg)
}

func (c *Conn) replace(cmd string, num string, mailbox string, msg Append) (resp Response, rerr error) {
	defer c.recover(&rerr, &resp)

	// todo: use synchronizing literal for larger messages.

	var date string
	if msg.Received != nil {
		date = ` "` + msg.Received.Format("_2-Jan-2006 15:04:05 -0700") + `"`
	}
	// todo: only use literal8 if needed, possibly with "UTF8()"
	// todo: encode mailbox
	err := c.WriteCommandf("", "%s %s %s (%s)%s ~{%d+}", cmd, num, astring(mailbox), strings.Join(msg.Flags, " "), date, msg.Size)
	c.xcheckf(err, "writing replace command")

	defer c.xtracewrite(mlog.LevelTracedata)()
	_, err = io.Copy(c.xbw, msg.Data)
	c.xcheckf(err, "write message data")
	c.xtracewrite(mlog.LevelTrace)

	fmt.Fprintf(c.xbw, "\r\n")
	c.xflush()

	return c.responseOK()
}
