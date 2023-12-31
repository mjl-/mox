package tlsrpt_test

import (
	"context"
	"log"
	"strings"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/tlsrpt"
)

func ExampleLookup() {
	ctx := context.Background()
	resolver := dns.StrictResolver{}
	domain, err := dns.ParseDomain("domain.example")
	if err != nil {
		log.Fatalf("parsing domain: %v", err)
	}

	// Lookup TLSRPT record in DNS, and parse it.
	record, txt, err := tlsrpt.Lookup(ctx, slog.Default(), resolver, domain)
	if err != nil {
		log.Fatalf("looking up tlsrpt record: %v", err)
	}

	log.Printf("TLSRPT record: %s", txt)
	log.Printf("Parsed: %v", record)
}

func ExampleParseMessage() {
	// Message, as received over SMTP.
	msg := `From: <tlsrpt@mail.sender.example.com>
To: <mts-sts-tlsrpt@example.net>
Subject: Report Domain: example.net
Report-ID: <735ff.e317+bf22029@example.net>
TLS-Report-Domain: example.net
TLS-Report-Submitter: mail.sender.example.com
MIME-Version: 1.0
Content-Type: application/tlsrpt+gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
        filename="mail.sender.example!example.com!1013662812!1013749130.json.gz"

H4sIAPZreGUAA51UbW/aMBD+DL/Cyr5NdeokJIVI0za1aPswdRWgiXWqImMbai2JI9tBMMR/n52Y
lwkx2KQocXx3vud57s6bbscTcoFL/gtrLkpY4oJ5KfDuRVHhcg2n3o1xoVgzKHG5sLZNt9PxlMZS
Q7uveRsRoiCBqAdRMEEobZ5nG9zxWEnPeYZRGg/M8+x1O1ubiYhSY6IhL+fC+iqtoGSVkJqXiw/E
oVr5bIWLKmcNutYOObUBMUriXnhHYBjRCPbuCIazhCE46CUMI9YnvVkbVYmcE86UCfphUFpWbnPt
SO7/oV5XzKFpKB0sSksDzJ1h95dMKiNkCsaT8TJw3h2vEJSlQDNleRx2Vyl46xeY5/6O2vqYWuuE
VxlemOh+0kPIa3Zf/kRBhTmjtAjPHWNSwVeh9BHSs4nbDPa9bYI9VRcFlkeyaKFxDlVNCFNqXpul
+dr2IaIubY44CpObY9+5SVVLduIYoego0c6LMm1Wag924yBLpupc78tBmGmLOSe2O9mq4pLRvWrK
dJ2RGhYaQ161bYeClM76KZ4RarozCNP0UCDJCOPLJqJVajcJxSq4VCELm9ETbgFCjUNL7hyJZpJ0
rmAptJG0sr38bzyiK3mEl3gcYneZIh/5QRD5cXKJrEG188CUcnuZmLLbMZZFc7XYA1+1rlR6e9tO
rPJP5tlZMhsH3gNOwTvgJhoQAEEYARq9AWOn2aPQ451iwLtC7CXOOW1vOtdrfxE6GPT9OPBNGf0k
vEak/jVVgDNMftbVf/ZUdGy3oyIZVo2dNudPYzTIvmXD0Sh7Gn2dfs+ePk4+Z1+Gj5/MZzi9Hw4f
hg9Oqa4bc7N46W67vwF2Eq+hDAYAAA==
`
	msg = strings.ReplaceAll(msg, "\n", "\r\n")

	// Parse the email message, and the TLSRPT report within.
	reportJSON, err := tlsrpt.ParseMessage(slog.Default(), strings.NewReader(msg))
	if err != nil {
		log.Fatalf("parsing tlsrpt report in message: %v", err)
	}

	log.Printf("report: %#v", reportJSON)
}
