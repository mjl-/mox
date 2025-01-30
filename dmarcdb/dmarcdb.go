// Package dmarcdb stores incoming DMARC aggrate reports and evaluations for outgoing aggregate reports.
//
// With DMARC, a domain can request reports with DMARC evaluation results to be
// sent to a specified address. Mox parses such reports, stores them in its
// database and makes them available through its admin web interface. Mox also
// keeps track of the evaluations it does for incoming messages and sends reports
// to mail servers that request reports.
//
// Only aggregate reports are stored and sent. Failure reports about individual
// messages are not implemented.
package dmarcdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
)

// Init opens the databases.
//
// The incoming reports and evaluations for outgoing reports are in separate
// databases for simpler file-based handling of the databases.
func Init() error {
	if ReportsDB != nil || EvalDB != nil {
		return fmt.Errorf("already initialized")
	}

	log := mlog.New("dmarcdb", nil)
	var err error

	ReportsDB, err = openReportsDB(mox.Shutdown, log)
	if err != nil {
		return fmt.Errorf("open reports db: %v", err)
	}

	EvalDB, err = openEvalDB(mox.Shutdown, log)
	if err != nil {
		return fmt.Errorf("open eval db: %v", err)
	}

	return nil
}

func Close() error {
	if err := ReportsDB.Close(); err != nil {
		return fmt.Errorf("closing reports db: %w", err)
	}
	ReportsDB = nil

	if err := EvalDB.Close(); err != nil {
		return fmt.Errorf("closing eval db: %w", err)
	}
	EvalDB = nil
	return nil
}

func openReportsDB(ctx context.Context, log mlog.Log) (*bstore.DB, error) {
	p := mox.DataDirPath("dmarcrpt.db")
	os.MkdirAll(filepath.Dir(p), 0770)
	opts := bstore.Options{Timeout: 5 * time.Second, Perm: 0660, RegisterLogger: moxvar.RegisterLogger(p, log.Logger)}
	return bstore.Open(ctx, p, &opts, ReportsDBTypes...)
}

func openEvalDB(ctx context.Context, log mlog.Log) (*bstore.DB, error) {
	p := mox.DataDirPath("dmarceval.db")
	os.MkdirAll(filepath.Dir(p), 0770)
	opts := bstore.Options{Timeout: 5 * time.Second, Perm: 0660, RegisterLogger: moxvar.RegisterLogger(p, log.Logger)}
	return bstore.Open(ctx, p, &opts, EvalDBTypes...)
}
