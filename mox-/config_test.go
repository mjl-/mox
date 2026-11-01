package mox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mlog"
)

func TestChatmailConfig(t *testing.T) {
	log := mlog.New("mox", nil)

	var static config.Static
	static.Postmaster.Account = "mjl"
	static.Postmaster.Mailbox = "Postmaster"

	parse := func(t *testing.T, domainsConf string) []error {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "domains.conf")
		if err := os.WriteFile(path, []byte(domainsConf), 0660); err != nil {
			t.Fatalf("writing domains.conf: %v", err)
		}
		_, _, _, _, errs := ParseDynamicConfig(context.Background(), log, path, static)
		return errs
	}
	checkErrs := func(t *testing.T, errs []error, want string) {
		t.Helper()
		if want == "" {
			if len(errs) > 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			return
		}
		for _, err := range errs {
			if strings.Contains(err.Error(), want) {
				return
			}
		}
		t.Fatalf("no error containing %q in %v", want, errs)
	}

	// Chatmail account without chatmail mode enabled is an error.
	checkErrs(t, parse(t, `Domains:
	example.org: nil
Accounts:
	mjl:
		Domain: example.org
		Destinations:
			mjl@example.org: nil
		Chatmail: true
`), "chatmail account, but chatmail is not enabled")

	// Chatmail domain without chatmail mode enabled is an error.
	checkErrs(t, parse(t, `Domains:
	example.org:
		Chatmail: true
Accounts:
	mjl:
		Domain: example.org
		Destinations:
			mjl@example.org: nil
`), "chatmail domain, but chatmail is not enabled")

	// Chatmail domain and account with chatmail mode enabled is fine.
	checkErrs(t, parse(t, `Chatmail:
	Enabled: true
Domains:
	example.org:
		Chatmail: true
Accounts:
	mjl:
		Domain: example.org
		Destinations:
			mjl@example.org: nil
		Chatmail: true
`), "")
}
