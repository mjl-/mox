package tlsrpt

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

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
         "policy-domain": "company-y.example",
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

// ../rfc/8460:1015
var tlsrptMessage = strings.ReplaceAll(`From: tlsrpt@mail.sender.example.com
Date: Fri, May 09 2017 16:54:30 -0800
To: mts-sts-tlsrpt@example.net
Subject: Report Domain: example.net
Submitter: mail.sender.example.com
Report-ID: <735ff.e317+bf22029@example.net>
TLS-Report-Domain: example.net
TLS-Report-Submitter: mail.sender.example.com
MIME-Version: 1.0
Content-Type: multipart/report; report-type="tlsrpt";
	boundary="----=_NextPart_000_024E_01CC9B0A.AFE54C00"
Content-Language: en-us

This is a multipart message in MIME format.

------=_NextPart_000_024E_01CC9B0A.AFE54C00
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

This is an aggregate TLS report from mail.sender.example.com

------=_NextPart_000_024E_01CC9B0A.AFE54C00
Content-Type: application/tlsrpt+json
Content-Transfer-Encoding: 8bit
Content-Disposition: attachment;
	filename="mail.sender.example!example.com!1013662812!1013749130.json.gz"

`+reportJSON+`

------=_NextPart_000_024E_01CC9B0A.AFE54C00--
`, "\n", "\r\n")

// Message without multipart.
var tlsrptMessage2 = strings.ReplaceAll(`From: tlsrpt@mail.sender.example.com
To: mts-sts-tlsrpt@example.net
Subject: Report Domain: example.net
Report-ID: <735ff.e317+bf22029@example.net>
TLS-Report-Domain: example.net
TLS-Report-Submitter: mail.sender.example.com
MIME-Version: 1.0
Content-Type: application/tlsrpt+json
Content-Transfer-Encoding: 8bit
Content-Disposition: attachment;
	filename="mail.sender.example!example.com!1013662812!1013749130.json.gz"

`+reportJSON+`
`, "\n", "\r\n")

func TestReport(t *testing.T) {
	// ../rfc/8460:1756

	var report Report
	dec := json.NewDecoder(strings.NewReader(reportJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		t.Fatalf("parsing report: %s", err)
	}

	if _, err := ParseMessage(xlog, strings.NewReader(tlsrptMessage)); err != nil {
		t.Fatalf("parsing TLSRPT from message: %s", err)
	}

	if _, err := ParseMessage(xlog, strings.NewReader(tlsrptMessage2)); err != nil {
		t.Fatalf("parsing TLSRPT from message: %s", err)
	}

	if _, err := ParseMessage(xlog, strings.NewReader(strings.ReplaceAll(tlsrptMessage, "multipart/report", "multipart/related"))); err != ErrNoReport {
		t.Fatalf("got err %v, expected ErrNoReport", err)
	}

	if _, err := ParseMessage(xlog, strings.NewReader(strings.ReplaceAll(tlsrptMessage, "application/tlsrpt+json", "application/json"))); err != ErrNoReport {
		t.Fatalf("got err %v, expected ErrNoReport", err)
	}

	files, err := os.ReadDir("../testdata/tlsreports")
	if err != nil {
		t.Fatalf("listing reports: %s", err)
	}
	for _, file := range files {
		f, err := os.Open("../testdata/tlsreports/" + file.Name())
		if err != nil {
			t.Fatalf("open %q: %s", file, err)
		}
		if _, err := ParseMessage(xlog, f); err != nil {
			t.Fatalf("parsing TLSRPT from message %q: %s", file.Name(), err)
		}
		f.Close()
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add(tlsrptMessage)
	f.Fuzz(func(t *testing.T, s string) {
		ParseMessage(xlog, strings.NewReader(s))
	})
}
