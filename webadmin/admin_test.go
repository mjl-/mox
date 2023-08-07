package webadmin

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
)

var ctxbg = context.Background()

func init() {
	mox.LimitersInit()
}

func TestAdminAuth(t *testing.T) {
	test := func(passwordfile, authHdr string, expect bool) {
		t.Helper()

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/ignored", nil)
		if authHdr != "" {
			r.Header.Add("Authorization", authHdr)
		}
		ok := checkAdminAuth(ctxbg, passwordfile, w, r)
		if ok != expect {
			t.Fatalf("got %v, expected %v", ok, expect)
		}
	}

	const authOK = "Basic YWRtaW46bW94dGVzdDEyMw=="  // admin:moxtest123
	const authBad = "Basic YWRtaW46YmFkcGFzc3dvcmQ=" // admin:badpassword

	const path = "../testdata/http-passwordfile"
	os.Remove(path)
	defer os.Remove(path)

	test(path, authOK, false) // Password file does not exist.

	adminpwhash, err := bcrypt.GenerateFromPassword([]byte("moxtest123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("generate bcrypt hash: %v", err)
	}
	if err := os.WriteFile(path, adminpwhash, 0660); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	// We loop to also exercise the auth cache.
	for i := 0; i < 2; i++ {
		test(path, "", false)                 // Empty/missing header.
		test(path, "Malformed ", false)       // Not "Basic"
		test(path, "Basic malformed ", false) // Bad base64.
		test(path, "Basic dGVzdA== ", false)  // base64 is ok, but wrong tokens inside.
		test(path, authBad, false)            // Wrong password.
		test(path, authOK, true)
	}
}

func TestCheckDomain(t *testing.T) {
	// NOTE: we aren't currently looking at the results, having the code paths executed is better than nothing.

	resolver := dns.MockResolver{
		MX: map[string][]*net.MX{
			"mox.example.": {{Host: "mail.mox.example.", Pref: 10}},
		},
		A: map[string][]string{
			"mail.mox.example.": {"127.0.0.2"},
		},
		AAAA: map[string][]string{
			"mail.mox.example.": {"127.0.0.2"},
		},
		TXT: map[string][]string{
			"mox.example.":                 {"v=spf1 mx -all"},
			"test._domainkey.mox.example.": {"v=DKIM1;h=sha256;k=ed25519;p=ln5zd/JEX4Jy60WAhUOv33IYm2YZMyTQAdr9stML504="},
			"_dmarc.mox.example.":          {"v=DMARC1; p=reject; rua=mailto:mjl@mox.example"},
			"_smtp._tls.mox.example":       {"v=TLSRPTv1; rua=mailto:tlsrpt@mox.example;"},
			"_mta-sts.mox.example":         {"v=STSv1; id=20160831085700Z"},
		},
		CNAME: map[string]string{},
	}

	listener := config.Listener{
		IPs:            []string{"127.0.0.2"},
		Hostname:       "mox.example",
		HostnameDomain: dns.Domain{ASCII: "mox.example"},
	}
	listener.SMTP.Enabled = true
	listener.AutoconfigHTTPS.Enabled = true
	listener.MTASTSHTTPS.Enabled = true

	mox.Conf.Static.Listeners = map[string]config.Listener{
		"public": listener,
	}
	domain := config.Domain{
		DKIM: config.DKIM{
			Selectors: map[string]config.Selector{
				"test": {
					HashEffective:    "sha256",
					HeadersEffective: []string{"From", "Date", "Subject"},
					Key:              ed25519.NewKeyFromSeed(make([]byte, 32)), // warning: fake zero key, do not copy this code.
					Domain:           dns.Domain{ASCII: "test"},
				},
				"missing": {
					HashEffective:    "sha256",
					HeadersEffective: []string{"From", "Date", "Subject"},
					Key:              ed25519.NewKeyFromSeed(make([]byte, 32)), // warning: fake zero key, do not copy this code.
					Domain:           dns.Domain{ASCII: "missing"},
				},
			},
			Sign: []string{"test", "test2"},
		},
	}
	mox.Conf.Dynamic.Domains = map[string]config.Domain{
		"mox.example": domain,
	}

	// Make a dialer that fails immediately before actually connecting.
	done := make(chan struct{})
	close(done)
	dialer := &net.Dialer{Deadline: time.Now().Add(-time.Second), Cancel: done}

	checkDomain(ctxbg, resolver, dialer, "mox.example")
	// todo: check returned data

	Admin{}.Domains(ctxbg)        // todo: check results
	dnsblsStatus(ctxbg, resolver) // todo: check results
}
