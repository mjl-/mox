package tlsrptdb

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

var (
	ReportDBTypes = []any{Record{}}
	ReportDB      *bstore.DB

	// Accessed directly by tlsrptsend.
	ResultDBTypes = []any{TLSResult{}, SuppressAddress{}}
	ResultDB      *bstore.DB
)

// Init opens and possibly initializes the databases.
func Init() error {
	if ReportDB != nil || ResultDB != nil {
		return fmt.Errorf("already initialized")
	}

	log := mlog.New("tlsrptdb", nil)
	var err error

	ReportDB, err = openReportDB(mox.Shutdown, log)
	if err != nil {
		return fmt.Errorf("opening report db: %v", err)
	}
	ResultDB, err = openResultDB(mox.Shutdown, log)
	if err != nil {
		return fmt.Errorf("opening result db: %v", err)
	}
	return nil
}

func openReportDB(ctx context.Context, log mlog.Log) (*bstore.DB, error) {
	p := mox.DataDirPath("tlsrpt.db")
	os.MkdirAll(filepath.Dir(p), 0770)
	opts := bstore.Options{Timeout: 5 * time.Second, Perm: 0660, RegisterLogger: moxvar.RegisterLogger(p, log.Logger)}
	return bstore.Open(ctx, p, &opts, ReportDBTypes...)
}

func openResultDB(ctx context.Context, log mlog.Log) (*bstore.DB, error) {
	p := mox.DataDirPath("tlsrptresult.db")
	os.MkdirAll(filepath.Dir(p), 0770)
	opts := bstore.Options{Timeout: 5 * time.Second, Perm: 0660, RegisterLogger: moxvar.RegisterLogger(p, log.Logger)}
	return bstore.Open(ctx, p, &opts, ResultDBTypes...)
}

// Close closes the database connections.
func Close() error {
	if err := ResultDB.Close(); err != nil {
		return fmt.Errorf("closing result db: %w", err)
	}
	ResultDB = nil

	if err := ReportDB.Close(); err != nil {
		return fmt.Errorf("closing report db: %w", err)
	}
	ReportDB = nil
	return nil
}
