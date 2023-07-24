package smtpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/store"
)

// rejectPresent returns whether the message is already present in the rejects mailbox.
func rejectPresent(log *mlog.Log, acc *store.Account, rejectsMailbox string, m *store.Message, f *os.File) (present bool, msgID string, hash []byte, rerr error) {
	if p, err := message.Parse(store.FileMsgReader(m.MsgPrefix, f)); err != nil {
		log.Infox("parsing reject message for message-id", err)
	} else if header, err := p.Header(); err != nil {
		log.Infox("parsing reject message header for message-id", err)
	} else {
		msgID = header.Get("Message-Id")
	}

	// We must not read MsgPrefix, it will likely change for subsequent deliveries.
	h := sha256.New()
	if _, err := io.Copy(h, &moxio.AtReader{R: f}); err != nil {
		log.Infox("copying reject message to hash", err)
	} else {
		hash = h.Sum(nil)
	}

	if msgID == "" && len(hash) == 0 {
		return false, "", nil, fmt.Errorf("no message-id or hash for determining reject message presence")
	}

	var exists bool
	var err error
	acc.WithRLock(func() {
		err = acc.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
			mbq := bstore.QueryTx[store.Mailbox](tx)
			mbq.FilterNonzero(store.Mailbox{Name: rejectsMailbox})
			mb, err := mbq.Get()
			if err == bstore.ErrAbsent {
				return nil
			}
			if err != nil {
				return fmt.Errorf("looking for rejects mailbox: %w", err)
			}

			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(store.Message{MailboxID: mb.ID})
			q.FilterEqual("Expunged", false)
			q.FilterFn(func(m store.Message) bool {
				return msgID != "" && m.MessageID == msgID || len(hash) > 0 && bytes.Equal(m.MessageHash, hash)
			})
			exists, err = q.Exists()
			return err
		})
	})
	if err != nil {
		return false, "", nil, fmt.Errorf("querying for presence of reject message: %w", err)
	}
	return exists, msgID, hash, nil
}
