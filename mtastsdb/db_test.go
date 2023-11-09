package mtastsdb

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtasts"
)

func tcheckf(t *testing.T, err error, format string, args ...any) {
	if err != nil {
		t.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func TestDB(t *testing.T) {
	mox.Shutdown = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/mtasts/fake.conf")
	mox.Conf.Static.DataDir = "."

	dbpath := mox.DataDirPath("mtasts.db")
	os.MkdirAll(filepath.Dir(dbpath), 0770)
	os.Remove(dbpath)
	defer os.Remove(dbpath)

	if err := Init(false); err != nil {
		t.Fatalf("init database: %s", err)
	}
	defer Close()

	// Mock time.
	now := time.Now().Round(0)
	timeNow = func() time.Time { return now }
	defer func() { timeNow = time.Now }()

	if p, err := lookup(ctxbg, dns.Domain{ASCII: "example.com"}); err != ErrNotFound {
		t.Fatalf("expected not found, got %v, %#v", err, p)
	}

	policy1 := mtasts.Policy{
		Version: "STSv1",
		Mode:    mtasts.ModeTesting,
		MX: []mtasts.STSMX{
			{Domain: dns.Domain{ASCII: "mx1.example.com"}},
			{Domain: dns.Domain{ASCII: "mx2.example.com"}},
			{Domain: dns.Domain{ASCII: "mx.backup-example.com"}},
		},
		MaxAgeSeconds: 1296000,
	}
	if err := Upsert(ctxbg, dns.Domain{ASCII: "example.com"}, "123", &policy1, policy1.String()); err != nil {
		t.Fatalf("upsert record: %s", err)
	}
	if got, err := lookup(ctxbg, dns.Domain{ASCII: "example.com"}); err != nil {
		t.Fatalf("lookup after insert: %s", err)
	} else if !reflect.DeepEqual(got.Policy, policy1) {
		t.Fatalf("mismatch between inserted and retrieved: got %#v, want %#v", got, policy1)
	}

	policy2 := mtasts.Policy{
		Version: "STSv1",
		Mode:    mtasts.ModeEnforce,
		MX: []mtasts.STSMX{
			{Domain: dns.Domain{ASCII: "mx1.example.com"}},
		},
		MaxAgeSeconds: 360000,
	}
	if err := Upsert(ctxbg, dns.Domain{ASCII: "example.com"}, "124", &policy2, policy2.String()); err != nil {
		t.Fatalf("upsert record: %s", err)
	}
	if got, err := lookup(ctxbg, dns.Domain{ASCII: "example.com"}); err != nil {
		t.Fatalf("lookup after insert: %s", err)
	} else if !reflect.DeepEqual(got.Policy, policy2) {
		t.Fatalf("mismatch between inserted and retrieved: got %v, want %v", got, policy2)
	}

	// Check if database holds expected record.
	records, err := PolicyRecords(ctxbg)
	tcheckf(t, err, "policyrecords")
	expRecords := []PolicyRecord{
		{"example.com", now, now.Add(time.Duration(policy2.MaxAgeSeconds) * time.Second), now, now, false, "124", policy2, policy2.String()},
	}
	records[0].Policy = mtasts.Policy{}
	expRecords[0].Policy = mtasts.Policy{}
	if !reflect.DeepEqual(records, expRecords) {
		t.Fatalf("records mismatch, got %#v, expected %#v", records, expRecords)
	}

	if err := Upsert(ctxbg, dns.Domain{ASCII: "other.example.com"}, "", nil, ""); err != nil {
		t.Fatalf("upsert record: %s", err)
	}
	records, err = PolicyRecords(ctxbg)
	tcheckf(t, err, "policyrecords")
	policyNone := mtasts.Policy{Mode: mtasts.ModeNone, MaxAgeSeconds: 5 * 60}
	expRecords = []PolicyRecord{
		{"other.example.com", now, now.Add(5 * 60 * time.Second), now, now, true, "", policyNone, ""},
		{"example.com", now, now.Add(time.Duration(policy2.MaxAgeSeconds) * time.Second), now, now, false, "124", policy2, policy2.String()},
	}
	if !reflect.DeepEqual(records, expRecords) {
		t.Fatalf("records mismatch, got %#v, expected %#v", records, expRecords)
	}

	if _, err := lookup(ctxbg, dns.Domain{ASCII: "other.example.com"}); err != ErrBackoff {
		t.Fatalf("got %#v, expected ErrBackoff", err)
	}

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_mta-sts.example.com.":           {"v=STSv1; id=124"},
			"_mta-sts.other.example.com.":     {"v=STSv1; id=1"},
			"_mta-sts.temperror.example.com.": {""},
		},
		Fail: []string{
			"txt _mta-sts.temperror.example.com.",
		},
	}

	testGet := func(domain string, expPolicy *mtasts.Policy, expFresh bool, expErr error) {
		t.Helper()
		p, _, fresh, err := Get(ctxbg, resolver, dns.Domain{ASCII: domain})
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got err %v, expected %v", err, expErr)
		}
		if !reflect.DeepEqual(p, expPolicy) || fresh != expFresh {
			t.Fatalf("got policy %#v, fresh %v, expected %#v, %v", p, fresh, expPolicy, expFresh)
		}
	}

	testGet("example.com", &policy2, true, nil)
	testGet("other.example.com", nil, false, nil) // Back off, already in database.
	testGet("absent.example.com", nil, true, nil) // No MTA-STS.
	testGet("temperror.example.com", nil, false, mtasts.ErrDNS)

	// Force refetch of policy, that will fail.
	mtasts.HTTPClient.Transport = &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("bad")
		},
	}
	defer func() {
		mtasts.HTTPClient.Transport = nil
	}()
	resolver.TXT["_mta-sts.example.com."] = []string{"v=STSv1; id=125"}
	testGet("example.com", &policy2, false, nil)

	// Cached policy but no longer a DNS record.
	delete(resolver.TXT, "_mta-sts.example.com.")
	testGet("example.com", &policy2, false, nil)
}
