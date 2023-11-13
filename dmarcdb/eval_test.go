package dmarcdb

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/queue"
)

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

func TestEvaluations(t *testing.T) {
	os.RemoveAll("../testdata/dmarcdb/data")
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/dmarcdb/mox.conf")
	mox.MustLoadConfig(true, false)
	EvalDB = nil

	_, err := evalDB(ctxbg)
	tcheckf(t, err, "database")
	defer func() {
		EvalDB.Close()
		EvalDB = nil
	}()

	parseJSON := func(s string) (e Evaluation) {
		t.Helper()
		err := json.Unmarshal([]byte(s), &e)
		tcheckf(t, err, "unmarshal")
		return
	}
	packJSON := func(e Evaluation) string {
		t.Helper()
		buf, err := json.Marshal(e)
		tcheckf(t, err, "marshal")
		return string(buf)
	}

	e0 := Evaluation{
		PolicyDomain:  "sender1.example",
		Evaluated:     time.Now().Round(0),
		IntervalHours: 1,
		PolicyPublished: dmarcrpt.PolicyPublished{
			Domain:          "sender1.example",
			ADKIM:           dmarcrpt.AlignmentRelaxed,
			ASPF:            dmarcrpt.AlignmentRelaxed,
			Policy:          dmarcrpt.DispositionReject,
			SubdomainPolicy: dmarcrpt.DispositionReject,
			Percentage:      100,
		},
		SourceIP:        "10.1.2.3",
		Disposition:     dmarcrpt.DispositionNone,
		AlignedDKIMPass: true,
		AlignedSPFPass:  true,
		EnvelopeTo:      "mox.example",
		EnvelopeFrom:    "sender1.example",
		HeaderFrom:      "sender1.example",
		DKIMResults: []dmarcrpt.DKIMAuthResult{
			{
				Domain:   "sender1.example",
				Selector: "test",
				Result:   dmarcrpt.DKIMPass,
			},
		},
		SPFResults: []dmarcrpt.SPFAuthResult{
			{
				Domain: "sender1.example",
				Scope:  dmarcrpt.SPFDomainScopeMailFrom,
				Result: dmarcrpt.SPFPass,
			},
		},
	}
	e1 := e0
	e2 := parseJSON(strings.ReplaceAll(packJSON(e0), "sender1.example", "sender2.example"))
	e3 := parseJSON(strings.ReplaceAll(packJSON(e0), "10.1.2.3", "10.3.2.1"))
	e3.Optional = true

	for i, e := range []*Evaluation{&e0, &e1, &e2, &e3} {
		e.Evaluated = e.Evaluated.Add(time.Duration(i) * time.Second)
		err = AddEvaluation(ctxbg, 3600, e)
		tcheckf(t, err, "add evaluation")
	}

	expStats := map[string]EvaluationStat{
		"sender1.example": {
			Domain:       dns.Domain{ASCII: "sender1.example"},
			Dispositions: []string{"none"},
			Count:        3,
			SendReport:   true,
		},
		"sender2.example": {
			Domain:       dns.Domain{ASCII: "sender2.example"},
			Dispositions: []string{"none"},
			Count:        1,
			SendReport:   true,
		},
	}
	stats, err := EvaluationStats(ctxbg)
	tcheckf(t, err, "evaluation stats")
	tcompare(t, stats, expStats)

	// EvaluationsDomain
	evals, err := EvaluationsDomain(ctxbg, dns.Domain{ASCII: "sender1.example"})
	tcheckf(t, err, "get evaluations for domain")
	tcompare(t, evals, []Evaluation{e0, e1, e3})

	evals, err = EvaluationsDomain(ctxbg, dns.Domain{ASCII: "sender2.example"})
	tcheckf(t, err, "get evaluations for domain")
	tcompare(t, evals, []Evaluation{e2})

	evals, err = EvaluationsDomain(ctxbg, dns.Domain{ASCII: "bogus.example"})
	tcheckf(t, err, "get evaluations for domain")
	tcompare(t, evals, []Evaluation{})

	// RemoveEvaluationsDomain
	err = RemoveEvaluationsDomain(ctxbg, dns.Domain{ASCII: "sender1.example"})
	tcheckf(t, err, "remove evaluations")

	expStats = map[string]EvaluationStat{
		"sender2.example": {
			Domain:       dns.Domain{ASCII: "sender2.example"},
			Dispositions: []string{"none"},
			Count:        1,
			SendReport:   true,
		},
	}
	stats, err = EvaluationStats(ctxbg)
	tcheckf(t, err, "evaluation stats")
	tcompare(t, stats, expStats)
}

func TestSendReports(t *testing.T) {
	mlog.SetConfig(map[string]mlog.Level{"": mlog.LevelDebug})

	os.RemoveAll("../testdata/dmarcdb/data")
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/dmarcdb/mox.conf")
	mox.MustLoadConfig(true, false)
	EvalDB = nil

	db, err := evalDB(ctxbg)
	tcheckf(t, err, "database")
	defer func() {
		EvalDB.Close()
		EvalDB = nil
	}()

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_dmarc.sender.example.": {
				"v=DMARC1; rua=mailto:dmarcrpt@sender.example; ri=3600",
			},
		},
	}

	end := nextWholeHour(time.Now())

	eval := Evaluation{
		PolicyDomain:  "sender.example",
		Evaluated:     end.Add(-time.Hour / 2),
		IntervalHours: 1,
		PolicyPublished: dmarcrpt.PolicyPublished{
			Domain:          "sender.example",
			ADKIM:           dmarcrpt.AlignmentRelaxed,
			ASPF:            dmarcrpt.AlignmentRelaxed,
			Policy:          dmarcrpt.DispositionReject,
			SubdomainPolicy: dmarcrpt.DispositionReject,
			Percentage:      100,
		},
		SourceIP:        "10.1.2.3",
		Disposition:     dmarcrpt.DispositionNone,
		AlignedDKIMPass: true,
		AlignedSPFPass:  true,
		EnvelopeTo:      "mox.example",
		EnvelopeFrom:    "sender.example",
		HeaderFrom:      "sender.example",
		DKIMResults: []dmarcrpt.DKIMAuthResult{
			{
				Domain:   "sender.example",
				Selector: "test",
				Result:   dmarcrpt.DKIMPass,
			},
		},
		SPFResults: []dmarcrpt.SPFAuthResult{
			{
				Domain: "sender.example",
				Scope:  dmarcrpt.SPFDomainScopeMailFrom,
				Result: dmarcrpt.SPFPass,
			},
		},
	}

	expFeedback := &dmarcrpt.Feedback{
		XMLName: xml.Name{Local: "feedback"},
		Version: "1.0",
		ReportMetadata: dmarcrpt.ReportMetadata{
			OrgName: "mail.mox.example",
			Email:   "postmaster@mail.mox.example",
			DateRange: dmarcrpt.DateRange{
				Begin: end.Add(-1 * time.Hour).Unix(),
				End:   end.Add(-time.Second).Unix(),
			},
		},
		PolicyPublished: dmarcrpt.PolicyPublished{
			Domain:          "sender.example",
			ADKIM:           dmarcrpt.AlignmentRelaxed,
			ASPF:            dmarcrpt.AlignmentRelaxed,
			Policy:          dmarcrpt.DispositionReject,
			SubdomainPolicy: dmarcrpt.DispositionReject,
			Percentage:      100,
		},
		Records: []dmarcrpt.ReportRecord{
			{
				Row: dmarcrpt.Row{
					SourceIP: "10.1.2.3",
					Count:    1,
					PolicyEvaluated: dmarcrpt.PolicyEvaluated{
						Disposition: dmarcrpt.DispositionNone,
						DKIM:        dmarcrpt.DMARCPass,
						SPF:         dmarcrpt.DMARCPass,
					},
				},
				Identifiers: dmarcrpt.Identifiers{
					EnvelopeTo:   "mox.example",
					EnvelopeFrom: "sender.example",
					HeaderFrom:   "sender.example",
				},
				AuthResults: dmarcrpt.AuthResults{
					DKIM: []dmarcrpt.DKIMAuthResult{
						{
							Domain:   "sender.example",
							Selector: "test",
							Result:   dmarcrpt.DKIMPass,
						},
					},
					SPF: []dmarcrpt.SPFAuthResult{
						{
							Domain: "sender.example",
							Scope:  dmarcrpt.SPFDomainScopeMailFrom,
							Result: dmarcrpt.SPFPass,
						},
					},
				},
			},
		},
	}

	// Set a timeUntil that we steplock and that causes the actual sleep to return immediately when we want to.
	wait := make(chan struct{})
	step := make(chan time.Duration)
	jitteredTimeUntil = func(_ time.Time) time.Duration {
		wait <- struct{}{}
		return <-step
	}

	sleepBetween = func(ctx context.Context, between time.Duration) (ok bool) { return true }

	test := func(evals []Evaluation, expAggrAddrs map[string]struct{}, expErrorAddrs map[string]struct{}, optExpReport *dmarcrpt.Feedback) {
		t.Helper()

		mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)

		for _, e := range evals {
			err := db.Insert(ctxbg, &e)
			tcheckf(t, err, "inserting evaluation")
		}

		aggrAddrs := map[string]struct{}{}
		errorAddrs := map[string]struct{}{}

		queueAdd = func(ctx context.Context, log *mlog.Log, qm *queue.Msg, msgFile *os.File) error {
			// Read message file. Also write copy to disk for inspection.
			buf, err := io.ReadAll(&moxio.AtReader{R: msgFile})
			tcheckf(t, err, "read report message")
			err = os.WriteFile("../testdata/dmarcdb/data/report.eml", append(append([]byte{}, qm.MsgPrefix...), buf...), 0600)
			tcheckf(t, err, "write report message")

			var feedback *dmarcrpt.Feedback
			addr := qm.Recipient().String()
			isErrorReport := strings.Contains(string(buf), "DMARC aggregate reporting error report")
			if isErrorReport {
				errorAddrs[addr] = struct{}{}
			} else {
				aggrAddrs[addr] = struct{}{}

				feedback, err = dmarcrpt.ParseMessageReport(log, msgFile)
				tcheckf(t, err, "parsing generated report message")
			}

			if optExpReport != nil {
				// Parse report in message and compare with expected.
				optExpReport.ReportMetadata.ReportID = feedback.ReportMetadata.ReportID
				tcompare(t, feedback, expFeedback)
			}

			return nil
		}

		Start(resolver)
		// Run first loop.
		<-wait
		step <- 0
		<-wait
		tcompare(t, aggrAddrs, expAggrAddrs)
		tcompare(t, errorAddrs, expErrorAddrs)

		// Second loop. Evaluations cleaned, should not result in report messages.
		aggrAddrs = map[string]struct{}{}
		errorAddrs = map[string]struct{}{}
		step <- 0
		<-wait
		tcompare(t, aggrAddrs, map[string]struct{}{})
		tcompare(t, errorAddrs, map[string]struct{}{})

		// Caus Start to stop.
		mox.ShutdownCancel()
		step <- time.Minute
	}

	// Typical case, with a single address that receives an aggregate report.
	test([]Evaluation{eval}, map[string]struct{}{"dmarcrpt@sender.example": {}}, map[string]struct{}{}, expFeedback)

	// Only optional evaluations, no report at all.
	evalOpt := eval
	evalOpt.Optional = true
	test([]Evaluation{evalOpt}, map[string]struct{}{}, map[string]struct{}{}, nil)

	// Address is suppressed.
	sa := SuppressAddress{ReportingAddress: "dmarcrpt@sender.example", Until: time.Now().Add(time.Minute)}
	err = db.Insert(ctxbg, &sa)
	tcheckf(t, err, "insert suppress address")
	test([]Evaluation{eval}, map[string]struct{}{}, map[string]struct{}{}, nil)

	// Suppression has expired.
	sa.Until = time.Now().Add(-time.Minute)
	err = db.Update(ctxbg, &sa)
	tcheckf(t, err, "update suppress address")
	test([]Evaluation{eval}, map[string]struct{}{"dmarcrpt@sender.example": {}}, map[string]struct{}{}, expFeedback)

	// Two RUA's, one with a size limit that doesn't pass, and one that does pass.
	resolver.TXT["_dmarc.sender.example."] = []string{"v=DMARC1; rua=mailto:dmarcrpt1@sender.example!1,mailto:dmarcrpt2@sender.example!10t; ri=3600"}
	test([]Evaluation{eval}, map[string]struct{}{"dmarcrpt2@sender.example": {}}, map[string]struct{}{}, nil)

	// Redirect to external domain, without permission, no report sent.
	resolver.TXT["_dmarc.sender.example."] = []string{"v=DMARC1; rua=mailto:unauthorized@other.example"}
	test([]Evaluation{eval}, map[string]struct{}{}, map[string]struct{}{}, nil)

	// Redirect to external domain, with basic permission.
	resolver.TXT = map[string][]string{
		"_dmarc.sender.example.":                       {"v=DMARC1; rua=mailto:authorized@other.example"},
		"sender.example._report._dmarc.other.example.": {"v=DMARC1"},
	}
	test([]Evaluation{eval}, map[string]struct{}{"authorized@other.example": {}}, map[string]struct{}{}, nil)

	// Redirect to authorized external domain, with 2 allowed replacements and 1 invalid and 1 refusing due to size.
	resolver.TXT = map[string][]string{
		"_dmarc.sender.example.":                       {"v=DMARC1; rua=mailto:authorized@other.example"},
		"sender.example._report._dmarc.other.example.": {"v=DMARC1; rua=mailto:good1@other.example,mailto:bad1@yetanother.example,mailto:good2@other.example,mailto:badsize@other.example!1"},
	}
	test([]Evaluation{eval}, map[string]struct{}{"good1@other.example": {}, "good2@other.example": {}}, map[string]struct{}{}, nil)

	// Without RUA, we send no message.
	resolver.TXT = map[string][]string{
		"_dmarc.sender.example.": {"v=DMARC1;"},
	}
	test([]Evaluation{eval}, map[string]struct{}{}, map[string]struct{}{}, nil)

	// If message size limit is reached, an error repor is sent.
	resolver.TXT = map[string][]string{
		"_dmarc.sender.example.": {"v=DMARC1; rua=mailto:dmarcrpt@sender.example!1"},
	}
	test([]Evaluation{eval}, map[string]struct{}{}, map[string]struct{}{"dmarcrpt@sender.example": {}}, nil)
}
