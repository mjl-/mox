package queue

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

// We won't be dialing remote servers. We just connect the smtp port of the first
// ip in the "local" listener, with fallback to localhost:1025 for any destination
// address and try to deliver. Our smtpserver uses a mocked dns resolver to give
// spf/dkim a chance to pass.
func deliverLocalserve(ctx context.Context, log mlog.Log, msgs []*Msg, backoff time.Duration) {
	m0 := msgs[0]

	addr := "localhost:1025"
	l, ok := mox.Conf.Static.Listeners["local"]
	if ok && l.SMTP.Enabled {
		port := 1025
		if l.SMTP.Port != 0 {
			port = l.SMTP.Port
		}
		addr = net.JoinHostPort(l.IPs[0], fmt.Sprintf("%d", port))
	}
	var d net.Dialer
	dialctx, dialcancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialcancel()
	conn, err := d.DialContext(dialctx, "tcp", addr)
	dialcancel()
	if err != nil {
		failMsgsDB(log, msgs, m0.DialedIPs, backoff, dsn.NameIP{}, err)
		return
	}
	defer func() {
		if conn != nil {
			err = conn.Close()
			log.Check(err, "closing connection")
		}
	}()

	clientctx, clientcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer clientcancel()
	localhost := dns.Domain{ASCII: "localhost"}
	client, err := smtpclient.New(clientctx, log.Logger, conn, smtpclient.TLSOpportunistic, false, localhost, localhost, smtpclient.Opts{})
	clientcancel()
	if err != nil {
		failMsgsDB(log, msgs, m0.DialedIPs, backoff, dsn.NameIP{}, err)
		return
	}
	conn = nil // Will be closed when closing client.
	defer func() {
		err := client.Close()
		log.Check(err, "closing smtp client")
	}()

	var msgr io.ReadCloser
	var size int64
	if len(m0.DSNUTF8) > 0 {
		msgr = io.NopCloser(bytes.NewReader(m0.DSNUTF8))
		size = int64(len(m0.DSNUTF8))
	} else {
		size = m0.Size
		p := m0.MessagePath()
		f, err := os.Open(p)
		if err != nil {
			log.Errorx("opening message for delivery", err, slog.String("remote", addr), slog.String("path", p))
			err = fmt.Errorf("opening message file: %v", err)
			failMsgsDB(log, msgs, m0.DialedIPs, backoff, dsn.NameIP{}, err)
			return
		}
		msgr = store.FileMsgReader(m0.MsgPrefix, f)
		defer func() {
			if msgr != nil {
				err := msgr.Close()
				log.Check(err, "closing message after delivery attempt")
			}
		}()
	}

	deliverctx, delivercancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer delivercancel()
	requireTLS := m0.RequireTLS != nil && *m0.RequireTLS
	rcpts := make([]string, len(msgs))
	for i, m := range msgs {
		rcpts[i] = m.Recipient().String()
	}
	rcptErrs, err := client.DeliverMultiple(deliverctx, m0.Sender().String(), rcpts, size, msgr, m0.Has8bit, m0.SMTPUTF8, requireTLS)
	delivercancel()
	if err != nil {
		log.Infox("smtp transaction for delivery failed", err)
	}

	// Must close before processing, because that may try to remove the message file,
	// and on Windows we can't have it open when we remove it.
	cerr := msgr.Close()
	log.Check(cerr, "closing message after delivery attempt")
	msgr = nil

	processDeliveries(log, m0, msgs, addr, "localhost", backoff, rcptErrs, err)
}
