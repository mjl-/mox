package tlsrptdb

import (
	"sync"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

var (
	xlog = mlog.New("tlsrptdb")

	ReportDBTypes = []any{TLSReportRecord{}}
	ReportDB      *bstore.DB
	mutex         sync.Mutex

	// Accessed directly by tlsrptsend.
	ResultDBTypes = []any{TLSResult{}, TLSRPTSuppressAddress{}}
	ResultDB      *bstore.DB
)

// Init opens and possibly initializes the databases.
func Init() error {
	if _, err := reportDB(mox.Shutdown); err != nil {
		return err
	}
	if _, err := resultDB(mox.Shutdown); err != nil {
		return err
	}
	return nil
}

// Close closes the database connections.
func Close() {
	if ResultDB != nil {
		err := ResultDB.Close()
		xlog.Check(err, "closing result database")
		ResultDB = nil
	}

	mutex.Lock()
	defer mutex.Unlock()
	if ReportDB != nil {
		err := ReportDB.Close()
		xlog.Check(err, "closing report database")
		ReportDB = nil
	}
}
