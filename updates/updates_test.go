package updates

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/mjl-/mox/dns"
)

func TestUpdates(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_updates.mox.example.":        {"v=UPDATES0; l=v0.0.1"},
			"_updates.one.example.":        {"other", "v=UPDATES0; l=v0.0.1-rc1"},
			"_updates.dup.example.":        {"v=UPDATES0; l=v0.0.1", "v=UPDATES0; l=v0.0.1"},
			"_updates.other.example.":      {"other"},
			"_updates.malformed.example.":  {"v=UPDATES0; l=bogus"},
			"_updates.malformed2.example.": {"v=UPDATES0; bogus"},
			"_updates.malformed3.example.": {"v=UPDATES0; l=v0.0.1; l=v0.0.1"},
			"_updates.temperror.example.":  {"v=UPDATES0; l=v0.0.1"},
			"_updates.unknown.example.":    {"v=UPDATES0; l=v0.0.1; unknown=ok"},
		},
		Fail: []string{
			"txt _updates.temperror.example.",
		},
	}

	lookup := func(dom string, expVersion string, expRecord *Record, expErr error) {
		t.Helper()

		d, _ := dns.ParseDomain(dom)
		expv, _ := ParseVersion(expVersion)

		version, record, err := Lookup(context.Background(), resolver, d)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("lookup: got err %v, expected %v", err, expErr)
		}
		if version != expv || !reflect.DeepEqual(record, expRecord) {
			t.Fatalf("lookup: got version %v, record %#v, expected %v %#v", version, record, expv, expRecord)
		}
	}

	lookup("mox.example", "v0.0.1", &Record{Version: "UPDATES0", Latest: Version{0, 0, 1}}, nil)
	lookup("one.example", "v0.0.1", &Record{Version: "UPDATES0", Latest: Version{0, 0, 1}}, nil)
	lookup("absent.example", "", nil, ErrNoRecord)
	lookup("dup.example", "", nil, ErrMultipleRecords)
	lookup("other.example", "", nil, ErrNoRecord)
	lookup("malformed.example", "", nil, ErrRecordSyntax)
	lookup("malformed2.example", "", nil, ErrRecordSyntax)
	lookup("malformed3.example", "", nil, ErrRecordSyntax)
	lookup("temperror.example", "", nil, ErrDNS)
	lookup("unknown.example", "v0.0.1", &Record{Version: "UPDATES0", Latest: Version{0, 0, 1}}, nil)

	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := []byte(priv.Public().(ed25519.PublicKey))
	changelog := Changelog{
		Changes: []Change{
			{
				PubKey: pub,
				Sig:    ed25519.Sign(priv, []byte("test")),
				Text:   "test",
			},
		},
	}

	fetch := func(baseURL string, version Version, status int, pubKey []byte, expChangelog *Changelog, expErr error) {
		t.Helper()

		mux := &http.ServeMux{}
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if status == 0 {
				panic("bad serve")
			}
			w.WriteHeader(status)
			err := json.NewEncoder(w).Encode(changelog)
			if err != nil {
				t.Fatalf("encode changelog: %v", err)
			}
		})
		s := httptest.NewUnstartedServer(mux)
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.Start()
		defer s.Close()
		if baseURL == "" {
			baseURL = s.URL
		}

		changelog, err := FetchChangelog(context.Background(), baseURL, version, pubKey)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("fetch changelog: got err %v, expected %v", err, expErr)
		}
		if !reflect.DeepEqual(changelog, expChangelog) {
			t.Fatalf("fetch changelog: got changelog %v, expected %v", changelog, expChangelog)
		}
	}

	fetch("", Version{}, 200, pub, &changelog, nil)
	fetch("", Version{1, 1, 1}, 200, pub, &changelog, nil)
	fetch("", Version{}, 200, make([]byte, ed25519.PublicKeySize), nil, ErrChangelogFetch) // Invalid public key.
	changelog.Changes[0].Text = "bad"
	fetch("", Version{}, 200, pub, nil, ErrChangelogFetch) // Invalid signature.
	changelog.Changes[0].Text = "test"
	fetch("", Version{}, 404, pub, nil, ErrChangelogFetch)
	fetch("", Version{}, 503, pub, nil, ErrChangelogFetch)
	fetch("", Version{}, 0, pub, nil, ErrChangelogFetch)
	fetch("bogusurl", Version{}, 200, pub, nil, ErrChangelogFetch)

	check := func(dom string, base Version, baseURL string, status int, pubKey []byte, expVersion Version, expRecord *Record, expChangelog *Changelog, expErr error) {
		t.Helper()

		mux := &http.ServeMux{}
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if status == 0 {
				panic("bad serve")
			}
			w.WriteHeader(status)
			err := json.NewEncoder(w).Encode(changelog)
			if err != nil {
				t.Fatalf("encode changelog: %v", err)
			}
		})
		s := httptest.NewUnstartedServer(mux)
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.Start()
		defer s.Close()
		if baseURL == "" {
			baseURL = s.URL
		}

		version, record, changelog, err := Check(context.Background(), resolver, dns.Domain{ASCII: dom}, base, baseURL, pubKey)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("check: got err %v, expected %v", err, expErr)
		}
		if version != expVersion || !reflect.DeepEqual(record, expRecord) || !reflect.DeepEqual(changelog, expChangelog) {
			t.Fatalf("check: got version %v, record %#v, changelog %v, expected %v %#v %v", version, record, changelog, expVersion, expRecord, expChangelog)
		}
	}

	check("mox.example", Version{0, 0, 1}, "", 0, pub, Version{0, 0, 1}, &Record{Version: "UPDATES0", Latest: Version{0, 0, 1}}, nil, nil)
	check("mox.example", Version{0, 0, 0}, "", 200, pub, Version{0, 0, 1}, &Record{Version: "UPDATES0", Latest: Version{0, 0, 1}}, &changelog, nil)
	check("mox.example", Version{0, 0, 0}, "", 0, pub, Version{0, 0, 1}, &Record{Version: "UPDATES0", Latest: Version{0, 0, 1}}, nil, ErrChangelogFetch)
	check("absent.example", Version{0, 0, 1}, "", 200, pub, Version{}, nil, nil, ErrNoRecord)
}
