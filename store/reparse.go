package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime/debug"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
)

// We process messages in database transactions in batches. Otherwise, for accounts
// with many messages, we would get slowdown with many unwritten blocks in memory.
var reparseMessageBatchSize = 1000

// ReparseMessages reparses all messages, updating the MIME structure in
// Message.ParsedBuf.
//
// Typically called during automatic account upgrade, or manually.
//
// Returns total number of messages, all of which were reparsed.
func (a *Account) ReparseMessages(ctx context.Context, log mlog.Log) (int, error) {
	type Result struct {
		Message *Message
		Buf     []byte
		Err     error
	}

	// We'll have multiple goroutines that pick up messages to parse. The assumption is
	// that reads of messages from disk are the bottleneck.
	nprog := 10
	work := make(chan *Message, nprog)
	results := make(chan Result, nprog)

	processMessage := func(m *Message) {
		r := Result{Message: m}

		defer func() {
			x := recover()
			if x != nil {
				r.Err = fmt.Errorf("unhandled panic parsing message: %v", x)
				log.Error("processMessage panic", slog.Any("err", x))
				debug.PrintStack()
				metrics.PanicInc(metrics.Store)
			}

			results <- r
		}()

		mr := a.MessageReader(*m)
		p, err := message.EnsurePart(log.Logger, false, mr, m.Size)
		if err != nil {
			// note: p is still set to a usable part
			log.Debugx("reparsing message", err, slog.Int64("msgid", m.ID))
		}
		r.Buf, r.Err = json.Marshal(p)
	}

	// Start goroutines that parse messages.
	for range nprog {
		go func() {
			for {
				m, ok := <-work
				if !ok {
					return
				}

				processMessage(m)
			}
		}()
	}
	defer close(work) // Stop goroutines when done.

	total := 0
	var lastID int64 // Each db transaction starts after lastID.
	for {
		var n int
		err := a.DB.Write(ctx, func(tx *bstore.Tx) error {
			var busy int

			q := bstore.QueryTx[Message](tx)
			q.FilterEqual("Expunged", false)
			q.FilterGreater("ID", lastID)
			q.Limit(reparseMessageBatchSize)
			q.SortAsc("ID")
			err := q.ForEach(func(m Message) error {
				lastID = m.ID
				n++

				for {
					select {
					case work <- &m:
						busy++
						return nil

					case r := <-results:
						busy--
						if r.Err != nil {
							log.Errorx("marshal parsed form of message", r.Err, slog.Int64("msgid", r.Message.ID))
						} else {
							if err := tx.Update(r.Message); err != nil {
								return fmt.Errorf("update message: %w", err)
							}
						}
					}
				}
			})
			if err != nil {
				return fmt.Errorf("reparsing messages: %w", err)
			}

			// Drain remaining reparses.
			for ; busy > 0; busy-- {
				r := <-results
				if r.Err != nil {
					log.Errorx("marshal parsed form of message", r.Err, slog.Int64("msgid", r.Message.ID))
				} else {
					if err := tx.Update(r.Message); err != nil {
						return fmt.Errorf("update message with id %d: %w", r.Message.ID, err)
					}
				}
			}

			return nil
		})
		total += n
		if err != nil {
			return total, fmt.Errorf("update messages with parsed mime structure: %w", err)
		}
		log.Debug("reparse message progress", slog.Int("total", total))
		if n < reparseMessageBatchSize {
			break
		}
	}

	return total, nil
}
