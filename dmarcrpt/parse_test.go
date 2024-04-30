package dmarcrpt

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mjl-/mox/mlog"
)

var pkglog = mlog.New("dmarcrpt", nil)

const reportExample = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>10051505501689795560</report_id>
    <date_range>
      <begin>1596412800</begin>
      <end>1596499199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>127.0.0.1</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.org</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.org</domain>
        <result>pass</result>
        <selector>example</selector>
      </dkim>
      <spf>
        <domain>example.org</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`

func TestParseReport(t *testing.T) {
	var expect = &Feedback{
		XMLName: xml.Name{Local: "feedback"},
		ReportMetadata: ReportMetadata{
			OrgName:          "google.com",
			Email:            "noreply-dmarc-support@google.com",
			ExtraContactInfo: "https://support.google.com/a/answer/2466580",
			ReportID:         "10051505501689795560",
			DateRange: DateRange{
				Begin: 1596412800,
				End:   1596499199,
			},
		},
		PolicyPublished: PolicyPublished{
			Domain:          "example.org",
			ADKIM:           "r",
			ASPF:            "r",
			Policy:          "reject",
			SubdomainPolicy: "reject",
			Percentage:      100,
		},
		Records: []ReportRecord{
			{
				Row: Row{
					SourceIP: "127.0.0.1",
					Count:    1,
					PolicyEvaluated: PolicyEvaluated{
						Disposition: DispositionNone,
						DKIM:        DMARCPass,
						SPF:         DMARCPass,
					},
				},
				Identifiers: Identifiers{
					HeaderFrom: "example.org",
				},
				AuthResults: AuthResults{
					DKIM: []DKIMAuthResult{
						{
							Domain:   "example.org",
							Result:   DKIMPass,
							Selector: "example",
						},
					},
					SPF: []SPFAuthResult{
						{
							Domain: "example.org",
							Result: SPFPass,
						},
					},
				},
			},
		},
	}

	feedback, err := ParseReport(strings.NewReader(reportExample))
	if err != nil {
		t.Fatalf("parsing report: %s", err)
	}
	if !reflect.DeepEqual(expect, feedback) {
		t.Fatalf("expected:\n%#v\ngot:\n%#v", expect, feedback)
	}
}

func TestParseMessageReport(t *testing.T) {
	dir := filepath.FromSlash("../testdata/dmarc-reports")
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("listing dmarc aggregate report emails: %s", err)
	}

	for _, file := range files {
		p := filepath.Join(dir, file.Name())
		f, err := os.Open(p)
		if err != nil {
			t.Fatalf("open %q: %s", p, err)
		}
		_, err = ParseMessageReport(pkglog.Logger, f)
		if err != nil {
			t.Fatalf("ParseMessageReport: %q: %s", p, err)
		}
		f.Close()
	}

	// No report in a non-multipart message.
	_, err = ParseMessageReport(pkglog.Logger, strings.NewReader("From: <mjl@mox.example>\r\n\r\nNo report.\r\n"))
	if err != ErrNoReport {
		t.Fatalf("message without report, got err %#v, expected ErrNoreport", err)
	}

	// No report in a multipart message.
	var multipartNoreport = strings.ReplaceAll(`From: <mjl@mox.example>
To: <mjl@mox.example>
Subject: Report Domain: mox.example Submitter: mail.mox.example
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="===============5735553800636657282=="

--===============5735553800636657282==
Content-Type: text/plain
MIME-Version: 1.0

test

--===============5735553800636657282==
Content-Type: text/html
MIME-Version: 1.0

<html></html>

--===============5735553800636657282==--
`, "\n", "\r\n")
	_, err = ParseMessageReport(pkglog.Logger, strings.NewReader(multipartNoreport))
	if err != ErrNoReport {
		t.Fatalf("message without report, got err %#v, expected ErrNoreport", err)
	}
}

func FuzzParseReport(f *testing.F) {
	f.Add("")
	f.Add(reportExample)
	f.Fuzz(func(t *testing.T, s string) {
		ParseReport(strings.NewReader(s))
	})
}
