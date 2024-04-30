package smtpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

// compose dsn message and add it to the queue for delivery to rcptTo.
func queueDSN(ctx context.Context, log mlog.Log, c *conn, rcptTo smtp.Path, m dsn.Message, requireTLS bool) error {
	buf, err := m.Compose(c.log, false)
	if err != nil {
		return err
	}
	bufDKIM, err := mox.DKIMSign(ctx, c.log, m.From, false, buf)
	log.Check(err, "dkim signing dsn")
	buf = append([]byte(bufDKIM), buf...)

	var bufUTF8 []byte
	if c.smtputf8 {
		bufUTF8, err = m.Compose(c.log, true)
		if err != nil {
			c.log.Errorx("composing dsn with utf-8 for incoming delivery for unknown user, continuing with ascii-only dsn", err)
		} else {
			bufUTF8DKIM, err := mox.DKIMSign(ctx, log, m.From, true, bufUTF8)
			log.Check(err, "dkim signing dsn with utf8")
			bufUTF8 = append([]byte(bufUTF8DKIM), bufUTF8...)
		}
	}

	f, err := store.CreateMessageTemp(c.log, "smtp-dsn")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer store.CloseRemoveTempFile(c.log, f, "smtpserver dsn message")

	if _, err := f.Write([]byte(buf)); err != nil {
		return fmt.Errorf("writing dsn file: %w", err)
	}

	// Queue DSN with null reverse path so failures to deliver will eventually drop the
	// message instead of causing delivery loops.
	// ../rfc/3464:433
	const has8bit = false
	const smtputf8 = false
	var reqTLS *bool
	if requireTLS {
		reqTLS = &requireTLS
	}
	qm := queue.MakeMsg(smtp.Path{}, rcptTo, has8bit, smtputf8, int64(len(buf)), m.MessageID, nil, reqTLS, time.Now(), m.Subject)
	qm.DSNUTF8 = bufUTF8
	if err := queue.Add(ctx, c.log, mox.Conf.Static.Postmaster.Account, f, qm); err != nil {
		return err
	}
	return nil
}
