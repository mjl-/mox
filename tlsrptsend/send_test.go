package tlsrptsend

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/exp/slog"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
)

var ctxbg = context.Background()

func tcheckf(t *testing.T, err error, format string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func tcompare(t *testing.T, got, expect any) {
	t.Helper()
	if !reflect.DeepEqual(got, expect) {
		t.Fatalf("got:\n%v\nexpected:\n%v", got, expect)
	}
}

func TestSendReports(t *testing.T) {
	mlog.SetConfig(map[string]slog.Level{"": mlog.LevelDebug})

	os.RemoveAll("../testdata/tlsrptsend/data")
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/tlsrptsend/mox.conf")
	mox.MustLoadConfig(true, false)

	err := tlsrptdb.Init()
	tcheckf(t, err, "init database")

	db := tlsrptdb.ResultDB

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_smtp._tls.sender.example.": {
				"v=TLSRPTv1; rua=mailto:tls-reports@sender.example,https://ignored.example/",
			},
			"_smtp._tls.mailhost.sender.example.": {
				"v=TLSRPTv1; rua=mailto:tls-reports1@mailhost.sender.example,mailto:tls-reports2@mailhost.sender.example; rua=mailto:tls-reports3@mailhost.sender.example",
			},
			"_smtp._tls.noreport.example.": {
				"v=TLSRPTv1; rua=mailto:tls-reports@noreport.example",
			},
			"_smtp._tls.mailhost.norua.example.": {
				"v=TLSRPTv1;",
			},
		},
	}

	endUTC := midnightUTC(time.Now())
	dayUTC := endUTC.Add(-12 * time.Hour).Format("20060102")

	tlsResults := []tlsrptdb.TLSResult{
		// For report1 below.
		{
			PolicyDomain:    "sender.example",
			DayUTC:          dayUTC,
			RecipientDomain: "sender.example",
			IsHost:          false,
			SendReport:      true,
			Results: []tlsrpt.Result{
				{
					Policy: tlsrpt.ResultPolicy{
						Type:   tlsrpt.STS,
						Domain: "sender.example",
						String: []string{"... mtasts policy ..."},
						MXHost: []string{"*.sender.example"},
					},
					Summary: tlsrpt.Summary{
						TotalSuccessfulSessionCount: 10,
						TotalFailureSessionCount:    3,
					},
					FailureDetails: []tlsrpt.FailureDetails{
						{
							ResultType:          tlsrpt.ResultCertificateExpired,
							SendingMTAIP:        "1.2.3.4",
							ReceivingMXHostname: "mailhost.sender.example",
							ReceivingMXHelo:     "mailhost.sender.example",
							ReceivingIP:         "4.3.2.1",
							FailedSessionCount:  3,
						},
					},
				},
			},
		},

		// For report2 below.
		{
			PolicyDomain:    "mailhost.sender.example",
			DayUTC:          dayUTC,
			RecipientDomain: "sender.example",
			IsHost:          true,
			SendReport:      false, // Would be ignored if on its own, but we have another result for this policy domain.
			Results: []tlsrpt.Result{
				{
					Policy: tlsrpt.ResultPolicy{
						Type:   tlsrpt.TLSA,
						Domain: "mailhost.sender.example",
						String: []string{"... tlsa record ..."},
					},
					Summary: tlsrpt.Summary{
						TotalSuccessfulSessionCount: 10,
						TotalFailureSessionCount:    1,
					},
					FailureDetails: []tlsrpt.FailureDetails{
						{
							ResultType:          tlsrpt.ResultValidationFailure,
							SendingMTAIP:        "1.2.3.4",
							ReceivingMXHostname: "mailhost.sender.example",
							ReceivingMXHelo:     "mailhost.sender.example",
							ReceivingIP:         "4.3.2.1",
							FailedSessionCount:  1,
							FailureReasonCode:   "dns-extended-error-7-signature-expired",
						},
					},
				},
			},
		},
		{
			PolicyDomain:    "mailhost.sender.example",
			DayUTC:          dayUTC,
			RecipientDomain: "sharedsender.example",
			IsHost:          true,
			SendReport:      true, // Causes previous result to be included in this report.
			Results: []tlsrpt.Result{
				{
					Policy: tlsrpt.ResultPolicy{
						Type:   tlsrpt.TLSA,
						Domain: "mailhost.sender.example",
						String: []string{"... tlsa record ..."},
					},
					Summary: tlsrpt.Summary{
						TotalSuccessfulSessionCount: 10,
						TotalFailureSessionCount:    1,
					},
					FailureDetails: []tlsrpt.FailureDetails{
						{
							ResultType:          tlsrpt.ResultValidationFailure,
							SendingMTAIP:        "1.2.3.4",
							ReceivingMXHostname: "mailhost.sender.example",
							ReceivingMXHelo:     "mailhost.sender.example",
							ReceivingIP:         "4.3.2.1",
							FailedSessionCount:  1,
							FailureReasonCode:   "dns-extended-error-7-signature-expired",
						},
					},
				},
			},
		},

		// No report due to SendReport false.
		{
			PolicyDomain:    "mailhost.noreport.example",
			DayUTC:          dayUTC,
			RecipientDomain: "noreport.example",
			IsHost:          true,
			SendReport:      false, // No report.
			Results: []tlsrpt.Result{
				{
					Policy: tlsrpt.ResultPolicy{
						Type:   tlsrpt.NoPolicyFound,
						Domain: "mailhost.noreport.example",
					},
					Summary: tlsrpt.Summary{
						TotalSuccessfulSessionCount: 2,
						TotalFailureSessionCount:    1,
					},
				},
			},
		},

		// No report due to no mailto rua.
		{
			PolicyDomain:    "mailhost.norua.example",
			DayUTC:          dayUTC,
			RecipientDomain: "norua.example",
			IsHost:          true,
			SendReport:      false, // No report.
			Results: []tlsrpt.Result{
				{
					Policy: tlsrpt.ResultPolicy{
						Type:   tlsrpt.NoPolicyFound,
						Domain: "mailhost.norua.example",
					},
					Summary: tlsrpt.Summary{
						TotalSuccessfulSessionCount: 2,
						TotalFailureSessionCount:    1,
					},
				},
			},
		},

		// No report due to no TLSRPT record.
		{
			PolicyDomain:    "mailhost.notlsrpt.example",
			DayUTC:          dayUTC,
			RecipientDomain: "notlsrpt.example",
			IsHost:          true,
			SendReport:      true,
			Results: []tlsrpt.Result{
				{
					Policy: tlsrpt.ResultPolicy{
						Type:   tlsrpt.NoPolicyFound,
						Domain: "mailhost.notlsrpt.example",
					},
					Summary: tlsrpt.Summary{
						TotalSuccessfulSessionCount: 2,
						TotalFailureSessionCount:    1,
					},
				},
			},
		},
	}

	report1 := tlsrpt.Report{
		OrganizationName: "mox.example",
		DateRange: tlsrpt.TLSRPTDateRange{
			Start: endUTC.Add(-24 * time.Hour),
			End:   endUTC.Add(-time.Second),
		},
		ContactInfo: "postmaster@mox.example",
		ReportID:    endUTC.Add(-12*time.Hour).Format("20060102") + ".sender.example@mox.example",
		Policies: []tlsrpt.Result{
			{
				Policy: tlsrpt.ResultPolicy{
					Type:   tlsrpt.STS,
					Domain: "sender.example",
					String: []string{"... mtasts policy ..."},
					MXHost: []string{"*.sender.example"},
				},
				Summary: tlsrpt.Summary{
					TotalSuccessfulSessionCount: 10,
					TotalFailureSessionCount:    3,
				},
				FailureDetails: []tlsrpt.FailureDetails{
					{
						ResultType:          tlsrpt.ResultCertificateExpired,
						SendingMTAIP:        "1.2.3.4",
						ReceivingMXHostname: "mailhost.sender.example",
						ReceivingMXHelo:     "mailhost.sender.example",
						ReceivingIP:         "4.3.2.1",
						FailedSessionCount:  3,
					},
				},
			},
			// Includes reports about MX target, for DANE policies.
			{
				Policy: tlsrpt.ResultPolicy{
					Type:   tlsrpt.TLSA,
					Domain: "mailhost.sender.example",
					String: []string{"... tlsa record ..."},
				},
				Summary: tlsrpt.Summary{
					TotalSuccessfulSessionCount: 10,
					TotalFailureSessionCount:    1,
				},
				FailureDetails: []tlsrpt.FailureDetails{
					{
						ResultType:          tlsrpt.ResultValidationFailure,
						SendingMTAIP:        "1.2.3.4",
						ReceivingMXHostname: "mailhost.sender.example",
						ReceivingMXHelo:     "mailhost.sender.example",
						ReceivingIP:         "4.3.2.1",
						FailedSessionCount:  1,
						FailureReasonCode:   "dns-extended-error-7-signature-expired",
					},
				},
			},
		},
	}
	report2 := tlsrpt.Report{
		OrganizationName: "mox.example",
		DateRange: tlsrpt.TLSRPTDateRange{
			Start: endUTC.Add(-24 * time.Hour),
			End:   endUTC.Add(-time.Second),
		},
		ContactInfo: "postmaster@mox.example",
		ReportID:    endUTC.Add(-12*time.Hour).Format("20060102") + ".mailhost.sender.example@mox.example",
		Policies: []tlsrpt.Result{
			// The MX target policies are per-recipient domain, so the MX operator can see the
			// affected recipient domains.
			{
				Policy: tlsrpt.ResultPolicy{
					Type:   tlsrpt.TLSA,
					Domain: "sender.example", // Recipient domain.
					String: []string{"... tlsa record ..."},
					MXHost: []string{"mailhost.sender.example"}, // Original policy domain.
				},
				Summary: tlsrpt.Summary{
					TotalSuccessfulSessionCount: 10,
					TotalFailureSessionCount:    1,
				},
				FailureDetails: []tlsrpt.FailureDetails{
					{
						ResultType:          tlsrpt.ResultValidationFailure,
						SendingMTAIP:        "1.2.3.4",
						ReceivingMXHostname: "mailhost.sender.example",
						ReceivingMXHelo:     "mailhost.sender.example",
						ReceivingIP:         "4.3.2.1",
						FailedSessionCount:  1,
						FailureReasonCode:   "dns-extended-error-7-signature-expired",
					},
				},
			},
			{
				Policy: tlsrpt.ResultPolicy{
					Type:   tlsrpt.TLSA,
					Domain: "sharedsender.example", // Recipient domain.
					String: []string{"... tlsa record ..."},
					MXHost: []string{"mailhost.sender.example"}, // Original policy domain.
				},
				Summary: tlsrpt.Summary{
					TotalSuccessfulSessionCount: 10,
					TotalFailureSessionCount:    1,
				},
				FailureDetails: []tlsrpt.FailureDetails{
					{
						ResultType:          tlsrpt.ResultValidationFailure,
						SendingMTAIP:        "1.2.3.4",
						ReceivingMXHostname: "mailhost.sender.example",
						ReceivingMXHelo:     "mailhost.sender.example",
						ReceivingIP:         "4.3.2.1",
						FailedSessionCount:  1,
						FailureReasonCode:   "dns-extended-error-7-signature-expired",
					},
				},
			},
		},
	}
	report3 := tlsrpt.Report{
		OrganizationName: "mox.example",
		DateRange: tlsrpt.TLSRPTDateRange{
			Start: endUTC.Add(-24 * time.Hour),
			End:   endUTC.Add(-time.Second),
		},
		ContactInfo: "postmaster@mox.example",
		ReportID:    endUTC.Add(-12*time.Hour).Format("20060102") + ".mailhost.sender.example@mox.example",
		Policies: []tlsrpt.Result{
			// The MX target policies are per-recipient domain, so the MX operator can see the
			// affected recipient domains.
			{
				Policy: tlsrpt.ResultPolicy{
					Type:   tlsrpt.TLSA,
					Domain: "sharedsender.example", // Recipient domain.
					String: []string{"... tlsa record ..."},
					MXHost: []string{"mailhost.sender.example"}, // Original policy domain.
				},
				Summary: tlsrpt.Summary{
					TotalSuccessfulSessionCount: 10,
					TotalFailureSessionCount:    1,
				},
				FailureDetails: []tlsrpt.FailureDetails{
					{
						ResultType:          tlsrpt.ResultValidationFailure,
						SendingMTAIP:        "1.2.3.4",
						ReceivingMXHostname: "mailhost.sender.example",
						ReceivingMXHelo:     "mailhost.sender.example",
						ReceivingIP:         "4.3.2.1",
						FailedSessionCount:  1,
						FailureReasonCode:   "dns-extended-error-7-signature-expired",
					},
				},
			},
		},
	}

	// Set a timeUntil that we steplock and that causes the actual sleep to return
	// immediately when we want to.
	wait := make(chan struct{})
	step := make(chan time.Duration)
	jitteredTimeUntil = func(_ time.Time) time.Duration {
		wait <- struct{}{}
		return <-step
	}

	sleepBetween = func(ctx context.Context, d time.Duration) (ok bool) { return true }

	test := func(results []tlsrptdb.TLSResult, expReports map[string][]tlsrpt.Report) {
		t.Helper()

		mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)

		for _, r := range results {
			err := db.Insert(ctxbg, &r)
			tcheckf(t, err, "inserting tlsresult")
		}

		haveReports := map[string][]tlsrpt.Report{}

		var mutex sync.Mutex

		var index int
		queueAdd = func(ctx context.Context, log mlog.Log, qm *queue.Msg, msgFile *os.File) error {
			mutex.Lock()
			defer mutex.Unlock()

			// Read message file. Also write copy to disk for inspection.
			buf, err := io.ReadAll(&moxio.AtReader{R: msgFile})
			tcheckf(t, err, "read report message")
			p := fmt.Sprintf("../testdata/tlsrptsend/data/report%d.eml", index)
			index++
			err = os.WriteFile(p, append(append([]byte{}, qm.MsgPrefix...), buf...), 0600)
			tcheckf(t, err, "write report message")

			reportJSON, err := tlsrpt.ParseMessage(log.Logger, msgFile)
			tcheckf(t, err, "parsing generated report message")

			addr := qm.Recipient().String()
			haveReports[addr] = append(haveReports[addr], reportJSON.Convert())

			return nil
		}

		Start(resolver)
		// Run first loop.
		<-wait
		step <- 0
		<-wait

		tcompare(t, haveReports, expReports)

		// Second loop. Evaluations cleaned, should not result in report messages.
		haveReports = map[string][]tlsrpt.Report{}
		step <- 0
		<-wait
		tcompare(t, haveReports, map[string][]tlsrpt.Report{})

		// Caus Start to stop.
		mox.ShutdownCancel()
		step <- time.Minute

		leftover, err := bstore.QueryDB[tlsrptdb.TLSResult](ctxbg, db).List()
		tcheckf(t, err, "querying database")
		if len(leftover) != 0 {
			t.Fatalf("leftover results in database after sending reports: %v", leftover)
		}
		_, err = bstore.QueryDB[tlsrptdb.TLSResult](ctxbg, db).Delete()
		tcheckf(t, err, "cleaning from database")
	}

	// Multiple results, some are combined into a single report, another result
	// generates a separate report to multiple rua's, and the last don't send a report.
	test(tlsResults, map[string][]tlsrpt.Report{
		"tls-reports@sender.example":           {report1},
		"tls-reports1@mailhost.sender.example": {report2},
		"tls-reports2@mailhost.sender.example": {report2},
		"tls-reports3@mailhost.sender.example": {report2},
	})

	// If MX target has same reporting addresses as recipient domain, only recipient
	// domain should get a report.
	resolver.TXT["_smtp._tls.mailhost.sender.example."] = []string{"v=TLSRPTv1; rua=mailto:tls-reports@sender.example"}
	test(tlsResults[:2], map[string][]tlsrpt.Report{
		"tls-reports@sender.example": {report1},
	})

	resolver.TXT["_smtp._tls.sharedsender.example."] = []string{"v=TLSRPTv1; rua=mailto:tls-reports@sender.example"}
	test(tlsResults, map[string][]tlsrpt.Report{
		"tls-reports@sender.example": {report1, report3},
	})

	// Suppressed addresses don't get a report.
	resolver.TXT["_smtp._tls.mailhost.sender.example."] = []string{"v=TLSRPTv1; rua=mailto:tls-reports1@mailhost.sender.example,mailto:tls-reports2@mailhost.sender.example; rua=mailto:tls-reports3@mailhost.sender.example"}
	db.Insert(ctxbg,
		&tlsrptdb.TLSRPTSuppressAddress{ReportingAddress: "tls-reports@sender.example", Until: time.Now().Add(-time.Minute)},                  // Expired, so ignored.
		&tlsrptdb.TLSRPTSuppressAddress{ReportingAddress: "tls-reports1@mailhost.sender.example", Until: time.Now().Add(time.Minute)},         // Still valid.
		&tlsrptdb.TLSRPTSuppressAddress{ReportingAddress: "tls-reports3@mailhost.sender.example", Until: time.Now().Add(31 * 24 * time.Hour)}, // Still valid.
	)
	test(tlsResults, map[string][]tlsrpt.Report{
		"tls-reports@sender.example":           {report1},
		"tls-reports2@mailhost.sender.example": {report2},
	})

	// Make reports success-only, ensuring we don't get a report anymore.
	for i := range tlsResults {
		for j := range tlsResults[i].Results {
			tlsResults[i].Results[j].Summary.TotalFailureSessionCount = 0
			tlsResults[i].Results[j].FailureDetails = nil
		}
	}
	test(tlsResults, map[string][]tlsrpt.Report{})

	// But when we want to send report for all-successful connections, we get reports again.
	mox.Conf.Static.OutgoingTLSReportsForAllSuccess = true
	for _, report := range []*tlsrpt.Report{&report1, &report2} {
		for i := range report.Policies {
			report.Policies[i].Summary.TotalFailureSessionCount = 0
			report.Policies[i].FailureDetails = nil
		}
	}
	test(tlsResults, map[string][]tlsrpt.Report{
		"tls-reports@sender.example":           {report1},
		"tls-reports2@mailhost.sender.example": {report2},
	})
}
