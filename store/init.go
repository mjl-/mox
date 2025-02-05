package store

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
)

// AuthDB and AuthDBTypes are exported for ../backup.go.
var AuthDB *bstore.DB
var AuthDBTypes = []any{TLSPublicKey{}, LoginAttempt{}, LoginAttemptState{}}

// Init opens auth.db.
func Init(ctx context.Context) error {
	if AuthDB != nil {
		return fmt.Errorf("already initialized")
	}
	pkglog := mlog.New("store", nil)
	p := mox.DataDirPath("auth.db")
	os.MkdirAll(filepath.Dir(p), 0770)
	opts := bstore.Options{Timeout: 5 * time.Second, Perm: 0660, RegisterLogger: moxvar.RegisterLogger(p, pkglog.Logger)}
	var err error
	AuthDB, err = bstore.Open(ctx, p, &opts, AuthDBTypes...)
	if err != nil {
		return err
	}

	startLoginAttemptWriter(ctx)

	go func() {
		defer func() {
			x := recover()
			if x == nil {
				return
			}

			mlog.New("store", nil).Error("unhandled panic in LoginAttemptCleanup", slog.Any("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Store)

		}()

		t := time.NewTicker(24 * time.Hour)
		for {
			err := LoginAttemptCleanup(ctx)
			pkglog.Check(err, "cleaning up old historic login attempts")

			select {
			case <-t.C:
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// Close closes auth.db.
func Close() error {
	if AuthDB == nil {
		return fmt.Errorf("not open")
	}
	err := AuthDB.Close()
	AuthDB = nil
	return err
}
