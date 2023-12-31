package tlsrptdb

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/tlsrpt"
)

var ctxbg = context.Background()
var pkglog = mlog.New("tlsrptdb", nil)

const reportJSON = `{
     "organization-name": "Company-X",
     "date-range": {
       "start-datetime": "2016-04-01T00:00:00Z",
       "end-datetime": "2016-04-01T23:59:59Z"
     },
     "contact-info": "sts-reporting@company-x.example",
     "report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
     "policies": [{
       "policy": {
         "policy-type": "sts",
         "policy-string": ["version: STSv1","mode: testing",
               "mx: *.mail.company-y.example","max_age: 86400"],
         "policy-domain": "test.xmox.nl",
         "mx-host": ["*.mail.company-y.example"]
       },
       "summary": {
         "total-successful-session-count": 5326,
         "total-failure-session-count": 303
       },
       "failure-details": [{
         "result-type": "certificate-expired",
         "sending-mta-ip": "2001:db8:abcd:0012::1",
         "receiving-mx-hostname": "mx1.mail.company-y.example",
         "failed-session-count": 100
       }, {
         "result-type": "starttls-not-supported",
         "sending-mta-ip": "2001:db8:abcd:0013::1",
         "receiving-mx-hostname": "mx2.mail.company-y.example",
         "receiving-ip": "203.0.113.56",
         "failed-session-count": 200,
         "additional-information": "https://reports.company-x.example/report_info ? id = 5065427 c - 23 d3# StarttlsNotSupported "
       }, {
         "result-type": "validation-failure",
         "sending-mta-ip": "198.51.100.62",
         "receiving-ip": "203.0.113.58",
         "receiving-mx-hostname": "mx-backup.mail.company-y.example",
         "failed-session-count": 3,
         "failure-reason-code": "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"
       }]
     }]
   }`

func TestReport(t *testing.T) {
	mox.Context = ctxbg
	mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/tlsrpt/fake.conf")
	mox.Conf.Static.DataDir = "."
	// Recognize as configured domain.
	mox.Conf.Dynamic.Domains = map[string]config.Domain{
		"test.xmox.nl": {},
	}

	dbpath := mox.DataDirPath("tlsrpt.db")
	os.MkdirAll(filepath.Dir(dbpath), 0770)
	defer os.Remove(dbpath)
	defer os.Remove(mox.DataDirPath("tlsrptresult.db"))

	if err := Init(); err != nil {
		t.Fatalf("init database: %s", err)
	}
	defer Close()

	files, err := os.ReadDir("../testdata/tlsreports")
	if err != nil {
		t.Fatalf("listing reports: %s", err)
	}
	for _, file := range files {
		f, err := os.Open("../testdata/tlsreports/" + file.Name())
		if err != nil {
			t.Fatalf("open %q: %s", file, err)
		}
		reportJSON, err := tlsrpt.ParseMessage(pkglog.Logger, f)
		f.Close()
		if err != nil {
			t.Fatalf("parsing TLSRPT from message %q: %s", file.Name(), err)
		}
		report := reportJSON.Convert()
		if err := AddReport(ctxbg, pkglog, dns.Domain{ASCII: "mox.example"}, "tlsrpt@mox.example", false, &report); err != nil {
			t.Fatalf("adding report to database: %s", err)
		}
	}

	reportJSON, err := tlsrpt.Parse(strings.NewReader(reportJSON))
	if err != nil {
		t.Fatalf("parsing report: %v", err)
	}
	report := reportJSON.Convert()
	if err := AddReport(ctxbg, pkglog, dns.Domain{ASCII: "company-y.example"}, "tlsrpt@company-y.example", false, &report); err != nil {
		t.Fatalf("adding report to database: %s", err)
	}

	records, err := Records(ctxbg)
	if err != nil {
		t.Fatalf("fetching records: %s", err)
	}
	for _, r := range records {
		if r.FromDomain != "company-y.example" {
			continue
		}
		if !reflect.DeepEqual(r.Report, report) {
			t.Fatalf("report, got %#v, expected %#v", r.Report, report)
		}
		if _, err := RecordID(ctxbg, r.ID); err != nil {
			t.Fatalf("get record by id: %v", err)
		}
	}

	start, _ := time.Parse(time.RFC3339, "2016-04-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2016-04-01T23:59:59Z")
	records, err = RecordsPeriodDomain(ctxbg, start, end, dns.Domain{ASCII: "test.xmox.nl"})
	if err != nil || len(records) != 1 {
		t.Fatalf("got err %v, records %#v, expected no error with 1 record", err, records)
	}
}
