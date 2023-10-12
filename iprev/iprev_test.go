package iprev

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
)

func TestIPRev(t *testing.T) {
	resolver := dns.MockResolver{
		PTR: map[string][]string{
			"10.0.0.1":    {"basic.example."},
			"10.0.0.4":    {"absent.example.", "b.example."},
			"10.0.0.5":    {"other.example.", "c.example."},
			"10.0.0.6":    {"temperror.example.", "d.example."},
			"10.0.0.7":    {"temperror.example.", "temperror2.example."},
			"10.0.0.8":    {"other.example."},
			"2001:db8::1": {"basic6.example."},
		},
		A: map[string][]string{
			"basic.example.":      {"10.0.0.1"},
			"b.example.":          {"10.0.0.4"},
			"c.example.":          {"10.0.0.5"},
			"d.example.":          {"10.0.0.6"},
			"other.example.":      {"10.9.9.9"},
			"temperror.example.":  {"10.0.0.99"},
			"temperror2.example.": {"10.0.0.99"},
		},
		AAAA: map[string][]string{
			"basic6.example.": {"2001:db8::1"},
		},
		Fail: []string{
			"ptr 10.0.0.3",
			"ptr 2001:db8::3",
			"ip temperror.example.",
			"ip temperror2.example.",
		},
		Authentic: []string{
			"ptr 10.0.0.1",
			"ptr 10.0.0.5", // Only IP to name authentic, not name to IP.
			"ip basic.example.",
			"ip d.example.", // Only name to IP authentic, not IP to name.
		},
	}

	test := func(ip string, expStatus Status, expName string, expNames string, expAuth bool, expErr error) {
		t.Helper()

		status, name, names, auth, err := Lookup(context.Background(), resolver, net.ParseIP(ip))
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got err %v, expected err %v", err, expErr)
		} else if err != nil {
			return
		} else if status != expStatus || name != expName || strings.Join(names, ",") != expNames || auth != expAuth {
			t.Fatalf("got status %q, name %q, names %v, auth %v, expected %q %q %v %v", status, name, names, auth, expStatus, expName, expNames, expAuth)
		}
	}

	test("10.0.0.1", StatusPass, "basic.example.", "basic.example.", true, nil)
	test("10.0.0.2", StatusPermerror, "", "", false, ErrNoRecord)
	test("10.0.0.3", StatusTemperror, "", "", false, ErrDNS)
	test("10.0.0.4", StatusPass, "b.example.", "absent.example.,b.example.", false, nil)
	test("10.0.0.5", StatusPass, "c.example.", "other.example.,c.example.", false, nil)
	test("10.0.0.6", StatusPass, "d.example.", "temperror.example.,d.example.", false, nil)
	test("10.0.0.7", StatusTemperror, "", "temperror.example.,temperror2.example.", false, ErrDNS)
	test("10.0.0.8", StatusFail, "", "other.example.", false, nil)
	test("2001:db8::1", StatusPass, "basic6.example.", "basic6.example.", false, nil)
	test("2001:db8::2", StatusPermerror, "", "", false, ErrNoRecord)
	test("2001:db8::3", StatusTemperror, "", "", false, ErrDNS)
}
