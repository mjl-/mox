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
	"github.com/mjl-/mox/mox-"
)

// Init opens the databases.
//
// The incoming reports and evaluations for outgoing reports are in separate
// databases for simpler file-based handling of the databases.
func Init() error {
	if _, err := reportsDB(mox.Shutdown); err != nil {
		return err
	}
	if _, err := evalDB(mox.Shutdown); err != nil {
		return err
	}
	return nil
}
