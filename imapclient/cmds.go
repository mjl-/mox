package imapclient

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/mjl-/mox/scram"
)

// Capability requests a list of capabilities from the server. They are returned in
// an UntaggedCapability response. The server also sends capabilities in initial
// server greeting, in the response code.
func (c *Conn) Capability() (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("capability")
}

// Noop does nothing on its own, but a server will return any pending untagged
// responses for new message delivery and changes to mailboxes.
func (c *Conn) Noop() (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("noop")
}

// Logout ends the IMAP session by writing a LOGOUT command. Close must still be
// called on this client to close the socket.
func (c *Conn) Logout() (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("logout")
}

// Starttls enables TLS on the connection with the STARTTLS command.
func (c *Conn) Starttls(config *tls.Config) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	untagged, result, rerr = c.Transactf("starttls")
	c.xcheckf(rerr, "starttls command")
	conn := tls.Client(c.conn, config)
	err := conn.Handshake()
	c.xcheckf(err, "tls handshake")
	c.conn = conn
	c.r = bufio.NewReader(conn)
	return untagged, result, nil
}

// Login authenticates with username and password
func (c *Conn) Login(username, password string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("login %s %s", astring(username), astring(password))
}

// Authenticate with plaintext password using AUTHENTICATE PLAIN.
func (c *Conn) AuthenticatePlain(username, password string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)

	untagged, result, rerr = c.Transactf("authenticate plain %s", base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "\u0000%s\u0000%s", username, password)))
	return
}

// Authenticate with SCRAM-SHA-256(-PLUS) or SCRAM-SHA-1(-PLUS). With SCRAM, the
// password is not exchanged in plaintext form, but only derived hashes are
// exchanged by both parties as proof of knowledge of password.
//
// The PLUS variants bind the authentication exchange to the TLS connection,
// detecting MitM attacks.
func (c *Conn) AuthenticateSCRAM(method string, h func() hash.Hash, username, password string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)

	var cs *tls.ConnectionState
	lmethod := strings.ToLower(method)
	if strings.HasSuffix(lmethod, "-plus") {
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
	c.LastTag = c.nextTag()
	err = c.Writelinef("%s authenticate %s %s", c.LastTag, method, base64.StdEncoding.EncodeToString([]byte(clientFirst)))
	c.xcheckf(err, "writing command line")

	xreadContinuation := func() []byte {
		var line string
		line, untagged, result, rerr = c.ReadContinuation()
		c.xcheckf(err, "read continuation")
		if result.Status != "" {
			c.xerrorf("unexpected status %q", result.Status)
		}
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

	return c.ResponseOK()
}

// Enable enables capabilities for use with the connection, verifying the server has indeed enabled them.
func (c *Conn) Enable(capabilities ...string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)

	untagged, result, rerr = c.Transactf("enable %s", strings.Join(capabilities, " "))
	c.xcheck(rerr)
	var enabled UntaggedEnabled
	c.xgetUntagged(untagged, &enabled)
	got := map[string]struct{}{}
	for _, cap := range enabled {
		got[cap] = struct{}{}
	}
	for _, cap := range capabilities {
		if _, ok := got[cap]; !ok {
			c.xerrorf("capability %q not enabled by server", cap)
		}
	}
	return
}

// Select opens mailbox as active mailbox.
func (c *Conn) Select(mailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("select %s", astring(mailbox))
}

// Examine opens mailbox as active mailbox read-only.
func (c *Conn) Examine(mailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("examine %s", astring(mailbox))
}

// Create makes a new mailbox on the server.
func (c *Conn) Create(mailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("create %s", astring(mailbox))
}

// Delete removes an entire mailbox and its messages.
func (c *Conn) Delete(mailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("delete %s", astring(mailbox))
}

// Rename changes the name of a mailbox and all its child mailboxes.
func (c *Conn) Rename(omailbox, nmailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("rename %s %s", astring(omailbox), astring(nmailbox))
}

// Subscribe marks a mailbox as subscribed. The mailbox does not have to exist. It
// is not an error if the mailbox is already subscribed.
func (c *Conn) Subscribe(mailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("subscribe %s", astring(mailbox))
}

// Unsubscribe marks a mailbox as unsubscribed.
func (c *Conn) Unsubscribe(mailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("unsubscribe %s", astring(mailbox))
}

// List lists mailboxes with the basic LIST syntax.
// Pattern can contain * (match any) or % (match any except hierarchy delimiter).
func (c *Conn) List(pattern string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf(`list "" %s`, astring(pattern))
}

// ListFull lists mailboxes with the extended LIST syntax requesting all supported data.
// Pattern can contain * (match any) or % (match any except hierarchy delimiter).
func (c *Conn) ListFull(subscribedOnly bool, patterns ...string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	var subscribedStr string
	if subscribedOnly {
		subscribedStr = "subscribed recursivematch"
	}
	for i, s := range patterns {
		patterns[i] = astring(s)
	}
	return c.Transactf(`list (%s) "" (%s) return (subscribed children special-use status (messages uidnext uidvalidity unseen deleted size recent appendlimit))`, subscribedStr, strings.Join(patterns, " "))
}

// Namespace returns the hiearchy separator in an UntaggedNamespace response with personal/shared/other namespaces if present.
func (c *Conn) Namespace() (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("namespace")
}

// Status requests information about a mailbox, such as number of messages, size, etc.
func (c *Conn) Status(mailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("status %s", astring(mailbox))
}

// Append adds message to mailbox with flags and optional receive time.
func (c *Conn) Append(mailbox string, flags []string, received *time.Time, message []byte) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	var date string
	if received != nil {
		date = ` "` + received.Format("_2-Jan-2006 15:04:05 -0700") + `"`
	}
	return c.Transactf("append %s (%s)%s {%d+}\r\n%s", astring(mailbox), strings.Join(flags, " "), date, len(message), message)
}

// note: No idle command. Idle is better implemented by writing the request and reading and handling the responses as they come in.

// CloseMailbox closes the currently selected/active mailbox, permanently removing
// any messages marked with \Deleted.
func (c *Conn) CloseMailbox() (untagged []Untagged, result Result, rerr error) {
	return c.Transactf("close")
}

// Unselect closes the currently selected/active mailbox, but unlike CloseMailbox
// does not permanently remove any messages marked with \Deleted.
func (c *Conn) Unselect() (untagged []Untagged, result Result, rerr error) {
	return c.Transactf("unselect")
}

// Expunge removes messages marked as deleted for the selected mailbox.
func (c *Conn) Expunge() (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("expunge")
}

// UIDExpunge is like expunge, but only removes messages matching uidSet.
func (c *Conn) UIDExpunge(uidSet NumSet) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("uid expunge %s", uidSet.String())
}

// Note: No search, fetch command yet due to its large syntax.

// StoreFlagsSet stores a new set of flags for messages from seqset with the STORE command.
// If silent, no untagged responses with the updated flags will be sent by the server.
func (c *Conn) StoreFlagsSet(seqset string, silent bool, flags ...string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	item := "flags"
	if silent {
		item += ".silent"
	}
	return c.Transactf("store %s %s (%s)", seqset, item, strings.Join(flags, " "))
}

// StoreFlagsAdd is like StoreFlagsSet, but only adds flags, leaving current flags on the message intact.
func (c *Conn) StoreFlagsAdd(seqset string, silent bool, flags ...string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	item := "+flags"
	if silent {
		item += ".silent"
	}
	return c.Transactf("store %s %s (%s)", seqset, item, strings.Join(flags, " "))
}

// StoreFlagsClear is like StoreFlagsSet, but only removes flags, leaving other flags on the message intact.
func (c *Conn) StoreFlagsClear(seqset string, silent bool, flags ...string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	item := "-flags"
	if silent {
		item += ".silent"
	}
	return c.Transactf("store %s %s (%s)", seqset, item, strings.Join(flags, " "))
}

// Copy adds messages from the sequences in seqSet in the currently selected/active mailbox to dstMailbox.
func (c *Conn) Copy(seqSet NumSet, dstMailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("copy %s %s", seqSet.String(), astring(dstMailbox))
}

// UIDCopy is like copy, but operates on UIDs.
func (c *Conn) UIDCopy(uidSet NumSet, dstMailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("uid copy %s %s", uidSet.String(), astring(dstMailbox))
}

// Move moves messages from the sequences in seqSet in the currently selected/active mailbox to dstMailbox.
func (c *Conn) Move(seqSet NumSet, dstMailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("move %s %s", seqSet.String(), astring(dstMailbox))
}

// UIDMove is like move, but operates on UIDs.
func (c *Conn) UIDMove(uidSet NumSet, dstMailbox string) (untagged []Untagged, result Result, rerr error) {
	defer c.recover(&rerr)
	return c.Transactf("uid move %s %s", uidSet.String(), astring(dstMailbox))
}
