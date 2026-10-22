package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

var ctxbg = context.Background()

// setupChatmail loads a chatmail configuration from a writable temporary copy of
// the testdata config, so tests can modify domains.conf.
func setupChatmail(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"mox.conf", "domains.conf"} {
		buf, err := os.ReadFile(filepath.Join("..", "testdata", "chatmail", name))
		if err != nil {
			t.Fatalf("reading testdata %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), buf, 0660); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	oldStatic, oldDynamic := mox.ConfigStaticPath, mox.ConfigDynamicPath
	mox.ConfigStaticPath = filepath.Join(dir, "mox.conf")
	mox.ConfigDynamicPath = filepath.Join(dir, "domains.conf")
	mox.MustLoadConfig(true, false)
	if err := store.Init(ctxbg); err != nil {
		t.Fatalf("store init: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store close: %v", err)
		}
		mox.ConfigStaticPath, mox.ConfigDynamicPath = oldStatic, oldDynamic
	})
}

func TestOpenEmailAuthChatmail(t *testing.T) {
	setupChatmail(t)
	log := mlog.New("admin", nil)

	// First login for a new address at a chatmail domain creates the account.
	acc, name, err := OpenEmailAuth(log, "newuser@chat.example", "testpassword", false, true)
	if err != nil {
		t.Fatalf("creating account on first login: %v", err)
	}
	if name != "newuser" {
		t.Fatalf("got account name %q, expected %q", name, "newuser")
	}
	conf, ok := mox.Conf.Account(name)
	if !ok || !conf.Chatmail {
		t.Fatalf("account %q not marked as chatmail: %#v", name, conf)
	}
	if err := acc.Close(); err != nil {
		t.Fatalf("closing account: %v", err)
	}

	// Logging in with the password now authenticates.
	acc, name, err = OpenEmailAuth(log, "newuser@chat.example", "testpassword", false, true)
	if err != nil || name != "newuser" {
		t.Fatalf("authenticating created account: %v, %q", err, name)
	}
	if err := acc.Close(); err != nil {
		t.Fatalf("closing account: %v", err)
	}

	// A wrong password for an existing address does not create or authenticate.
	if _, _, err := OpenEmailAuth(log, "newuser@chat.example", "wrongpassword", false, true); !errors.Is(err, store.ErrUnknownCredentials) {
		t.Fatalf("got err %v, expected ErrUnknownCredentials", err)
	}

	// Without canCreate (e.g. CRAM-MD5), unknown addresses are not created.
	if _, _, err := OpenEmailAuth(log, "other@chat.example", "testpassword", false, false); !errors.Is(err, store.ErrUnknownCredentials) {
		t.Fatalf("got err %v, expected ErrUnknownCredentials", err)
	}

	// A too-short password does not create an account.
	if _, _, err := OpenEmailAuth(log, "short@chat.example", "short", false, true); !errors.Is(err, store.ErrUnknownCredentials) {
		t.Fatalf("got err %v, expected ErrUnknownCredentials", err)
	}
	if _, ok := mox.Conf.Account("short"); ok {
		t.Fatalf("account created with too-short password")
	}

	// Addresses at a non-chatmail domain are not created.
	if _, _, err := OpenEmailAuth(log, "newuser@mox.example", "testpassword", false, true); !errors.Is(err, store.ErrUnknownCredentials) {
		t.Fatalf("got err %v, expected ErrUnknownCredentials", err)
	}

	// With autoregistration disabled, new accounts are not created.
	mox.Conf.Dynamic.Chatmail.AutoregistrationDisabled = true
	if _, _, err := OpenEmailAuth(log, "third@chat.example", "testpassword", false, true); !errors.Is(err, store.ErrUnknownCredentials) {
		t.Fatalf("got err %v, expected ErrUnknownCredentials", err)
	}
}

func TestOpenEmailAuthChatmailComplete(t *testing.T) {
	setupChatmail(t)
	log := mlog.New("admin", nil)

	// Simulate an automatic creation that was interrupted after adding the account
	// to the configuration, but before setting the password.
	addr, err := smtp.ParseAddress("interrupted@chat.example")
	if err != nil {
		t.Fatalf("parsing address: %v", err)
	}
	if _, err := createChatmailAccountConfig(ctxbg, log, addr); err != nil {
		t.Fatalf("creating account config: %v", err)
	}

	// The next login completes the creation.
	acc, name, err := OpenEmailAuth(log, "interrupted@chat.example", "testpassword", false, true)
	if err != nil {
		t.Fatalf("completing account creation: %v", err)
	}
	if name != "interrupted" {
		t.Fatalf("got account name %q, expected %q", name, "interrupted")
	}
	if err := acc.Close(); err != nil {
		t.Fatalf("closing account: %v", err)
	}

	// The password now authenticates, and a wrong password is rejected.
	acc, _, err = OpenEmailAuth(log, "interrupted@chat.example", "testpassword", false, true)
	if err != nil {
		t.Fatalf("authenticating completed account: %v", err)
	}
	if err := acc.Close(); err != nil {
		t.Fatalf("closing account: %v", err)
	}
	if _, _, err := OpenEmailAuth(log, "interrupted@chat.example", "wrongpassword", false, true); !errors.Is(err, store.ErrUnknownCredentials) {
		t.Fatalf("got err %v, expected ErrUnknownCredentials", err)
	}
}

func TestOpenEmailAuthChatmailDomainDisabled(t *testing.T) {
	setupChatmail(t)
	log := mlog.New("admin", nil)

	dom := mox.Conf.Dynamic.Domains["chat.example"]
	dom.Disabled = true
	mox.Conf.Dynamic.Domains["chat.example"] = dom

	if _, _, err := OpenEmailAuth(log, "disabled@chat.example", "testpassword", false, true); !errors.Is(err, store.ErrUnknownCredentials) {
		t.Fatalf("got err %v, expected ErrUnknownCredentials", err)
	}
	if _, ok := mox.Conf.Account("disabled"); ok {
		t.Fatal("account created for disabled domain")
	}
}
