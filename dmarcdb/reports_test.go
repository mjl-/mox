package dmarcdb

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
)

var ctxbg = context.Background()

func TestDMARCDB(t *testing.T) {
	mox.Shutdown = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/dmarcdb/mox.conf")
	mox.MustLoadConfig(true, false)

	dbpath := mox.DataDirPath("dmarcrpt.db")
	os.MkdirAll(filepath.Dir(dbpath), 0770)

	if err := Init(); err != nil {
		t.Fatalf("init database: %s", err)
	}
	defer os.Remove(dbpath)
	defer func() {
		ReportsDB.Close()
		ReportsDB = nil
	}()

	feedback := &dmarcrpt.Feedback{
		ReportMetadata: dmarcrpt.ReportMetadata{
			OrgName:          "google.com",
			Email:            "noreply-dmarc-support@google.com",
			ExtraContactInfo: "https://support.google.com/a/answer/2466580",
			ReportID:         "10051505501689795560",
			DateRange: dmarcrpt.DateRange{
				Begin: 1596412800,
				End:   1596499199,
			},
		},
		PolicyPublished: dmarcrpt.PolicyPublished{
			Domain:          "example.org",
			ADKIM:           "r",
			ASPF:            "r",
			Policy:          "reject",
			SubdomainPolicy: "reject",
			Percentage:      100,
		},
		Records: []dmarcrpt.ReportRecord{
			{
				Row: dmarcrpt.Row{
					SourceIP: "127.0.0.1",
					Count:    1,
					PolicyEvaluated: dmarcrpt.PolicyEvaluated{
						Disposition: dmarcrpt.DispositionNone,
						DKIM:        dmarcrpt.DMARCPass,
						SPF:         dmarcrpt.DMARCPass,
					},
				},
				Identifiers: dmarcrpt.Identifiers{
					HeaderFrom: "example.org",
				},
				AuthResults: dmarcrpt.AuthResults{
					DKIM: []dmarcrpt.DKIMAuthResult{
						{
							Domain:   "example.org",
							Result:   dmarcrpt.DKIMPass,
							Selector: "example",
						},
					},
					SPF: []dmarcrpt.SPFAuthResult{
						{
							Domain: "example.org",
							Result: dmarcrpt.SPFPass,
						},
					},
				},
			},
		},
	}
	if err := AddReport(ctxbg, feedback, dns.Domain{ASCII: "google.com"}); err != nil {
		t.Fatalf("adding report: %s", err)
	}

	records, err := Records(ctxbg)
	if err != nil || len(records) != 1 || !reflect.DeepEqual(&records[0].Feedback, feedback) {
		t.Fatalf("records: got err %v, records %#v, expected no error, single record with feedback %#v", err, records, feedback)
	}

	record, err := RecordID(ctxbg, records[0].ID)
	if err != nil || !reflect.DeepEqual(&record.Feedback, feedback) {
		t.Fatalf("record id: got err %v, record %#v, expected feedback %#v", err, record, feedback)
	}

	start := time.Unix(1596412800, 0)
	end := time.Unix(1596499199, 0)
	records, err = RecordsPeriodDomain(ctxbg, start, end, "example.org")
	if err != nil || len(records) != 1 || !reflect.DeepEqual(&records[0].Feedback, feedback) {
		t.Fatalf("records: got err %v, records %#v, expected no error, single record with feedback %#v", err, records, feedback)
	}

	records, err = RecordsPeriodDomain(ctxbg, end, end, "example.org")
	if err != nil || len(records) != 0 {
		t.Fatalf("records: got err %v, records %#v, expected no error and no records", err, records)
	}
	records, err = RecordsPeriodDomain(ctxbg, start, end, "other.example")
	if err != nil || len(records) != 0 {
		t.Fatalf("records: got err %v, records %#v, expected no error and no records", err, records)
	}
}
