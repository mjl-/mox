package mox

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"time"

	"github.com/mjl-/mox/mlog"
)

// StartTLSSessionTicketKeyRefresher sets session keys on the TLS config, and
// rotates them periodically.
//
// Useful for TLS configs that are being cloned for each connection. The
// automatically managed keys would happen in the cloned config, and not make
// it back to the base config.
func StartTLSSessionTicketKeyRefresher(ctx context.Context, log mlog.Log, c *tls.Config) {
	var keys [][32]byte
	first := make(chan struct{})

	// Similar to crypto/tls, we rotate keys once a day. Previous keys stay valid for 7
	// days. We currently only store ticket keys in memory, so a restart invalidates
	// previous session tickets. We could store them in the future.
	go func() {
		for {
			var nk [32]byte
			cryptorand.Read(nk[:])
			if len(keys) > 7 {
				keys = keys[:7]
			}
			keys = append([][32]byte{nk}, keys...)
			c.SetSessionTicketKeys(keys)

			if first != nil {
				first <- struct{}{}
				first = nil
			}

			ctxDone := Sleep(ctx, 24*time.Hour)
			if ctxDone {
				break
			}
			log.Info("rotating tls session keys")
		}
	}()

	<-first
}
