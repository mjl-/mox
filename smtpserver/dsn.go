package smtpserver

import (
	"context"
	"fmt"
	"os"

	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

// compose dsn message and add it to the queue for delivery to rcptTo.
func queueDSN(ctx context.Context, c *conn, rcptTo smtp.Path, m dsn.Message) error {
	buf, err := m.Compose(c.log, false)
	if err != nil {
		return err
	}
	var bufUTF8 []byte
	if c.smtputf8 {
		bufUTF8, err = m.Compose(c.log, true)
		if err != nil {
			c.log.Errorx("composing dsn with utf-8 for incoming delivery for unknown user, continuing with ascii-only dsn", err)
		}
	}

	f, err := store.CreateMessageTemp("smtp-dsn")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer func() {
		if f != nil {
			err := os.Remove(f.Name())
			c.log.Check(err, "removing temporary dsn message file")
			err = f.Close()
			c.log.Check(err, "closing temporary dsn message file")
		}
	}()
	if _, err := f.Write([]byte(buf)); err != nil {
		return fmt.Errorf("writing dsn file: %w", err)
	}

	// Queue DSN with null reverse path so failures to deliver will eventually drop the
	// message instead of causing delivery loops.
	// ../rfc/3464:433
	const has8bit = false
	const smtputf8 = false
	if _, err := queue.Add(ctx, c.log, "", smtp.Path{}, rcptTo, has8bit, smtputf8, int64(len(buf)), m.MessageID, nil, f, bufUTF8, true); err != nil {
		return err
	}
	err = f.Close()
	c.log.Check(err, "closing dsn file")
	f = nil
	return nil
}
