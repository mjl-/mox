package admin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"

	"golang.org/x/text/secure/precis"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

// OpenEmailAuth authenticates a user with an email address and password, like
// store.OpenEmailAuth.
//
// For chatmail servers, when the address is not known yet and the domain is
// marked as a chatmail domain, a new account is created for the address, with
// the provided password. This implements account creation on first login, where
// the client chooses the credentials. canCreate must only be set for
// authentication mechanisms that transmit the cleartext password to the server
// (e.g. PLAIN and LOGIN, but not CRAM-MD5, SCRAM or TLS client certificates).
//
// A new account is only created if chatmail mode is enabled for the server and
// automatic registration has not been disabled.
func OpenEmailAuth(log mlog.Log, email, password string, checkLoginDisabled, canCreate bool) (*store.Account, string, error) {
	acc, accName, err := store.OpenEmailAuth(log, email, password, checkLoginDisabled)
	if err == nil || !canCreate || !errors.Is(err, store.ErrUnknownCredentials) {
		return acc, accName, err
	}

	// Only create accounts for chatmail domains, when chatmail mode is enabled and
	// automatic registration is not disabled.
	dyn := mox.Conf.DynamicConfig()
	if !dyn.Chatmail.Enabled || dyn.Chatmail.AutoregistrationDisabled {
		return nil, "", err
	}
	addr, aerr := smtp.ParseAddress(email)
	if aerr != nil {
		return nil, "", err
	}
	dom, ok := dyn.Domains[addr.Domain.Name()]
	if !ok || !dom.Chatmail {
		return nil, "", err
	}

	// Validate the password before changing any configuration. SetPassword requires
	// a password of 8 to 72 bytes after normalization (the bcrypt limit).
	pw, perr := precis.OpaqueString.String(password)
	if perr != nil || len(pw) < 8 || len(pw) > 72 {
		return nil, "", err
	}

	return createChatmailAccount(log, addr, password)
}

// createChatmailAccount creates a new chatmail account for addr with the given
// password, and returns the opened account.
func createChatmailAccount(log mlog.Log, addr smtp.Address, password string) (*store.Account, string, error) {
	ctx := context.TODO()
	name, err := createChatmailAccountConfig(ctx, log, addr)
	if err != nil {
		return nil, "", err
	}

	// The account database is created on first open. Setting the password can be
	// slow (bcrypt), so it is done after releasing the dynamic config lock.
	a, err := store.OpenAccount(log, name, false)
	if err != nil {
		removeChatmailAccountConfig(ctx, log, name)
		return nil, "", fmt.Errorf("opening new chatmail account: %w", err)
	}
	if err := a.SetPassword(log, password); err != nil {
		err := a.Close()
		log.Check(err, "closing new chatmail account after error")
		removeChatmailAccountConfig(ctx, log, name)
		return nil, "", fmt.Errorf("setting password for new chatmail account: %w", err)
	}
	log.Info("created chatmail account", slog.String("account", name), slog.String("address", addr.String()))
	return a, name, nil
}

// removeChatmailAccountConfig removes the account name from the dynamic
// configuration, and removes its directory. Used to clean up after a failed
// automatic account creation.
func removeChatmailAccountConfig(ctx context.Context, log mlog.Log, name string) {
	defer mox.Conf.DynamicLockUnlock()()

	// Only remove if the account is still present.
	c := mox.Conf.Dynamic
	if _, ok := c.Accounts[name]; !ok {
		return
	}
	nc := c
	nc.Accounts = map[string]config.Account{}
	for n, a := range c.Accounts {
		if n != name {
			nc.Accounts[n] = a
		}
	}
	if err := mox.WriteDynamicLocked(ctx, log, nc); err != nil {
		log.Errorx("removing chatmail account config after failed create", err, slog.String("account", name))
		return
	}
	dir := filepath.Join(mox.DataDirPath("accounts"), name)
	if err := os.RemoveAll(dir); err != nil {
		log.Errorx("removing chatmail account directory after failed create", err, slog.String("account", name))
	}
}

// createChatmailAccountConfig adds a new account with chatmail flag enabled to
// the dynamic configuration, and reloads it. It returns the account name.
func createChatmailAccountConfig(ctx context.Context, log mlog.Log, addr smtp.Address) (string, error) {
	defer mox.Conf.DynamicLockUnlock()()

	c := mox.Conf.Dynamic

	if err := checkAddressAvailable(addr); err != nil {
		return "", fmt.Errorf("%w: address not available: %v", store.ErrUnknownCredentials, err)
	}

	// The account name defaults to the localpart of the address. It must be a safe
	// filename and unique.
	name := string(addr.Localpart)
	if !validAccountName(name) {
		name = ""
	}
	if name == "" {
		name = fmt.Sprintf("chatmail-%d", mox.CryptoRandInt())
	} else if _, ok := c.Accounts[name]; ok {
		name = fmt.Sprintf("%s-%d", name, mox.CryptoRandInt())
	}
	accountDir := filepath.Join(mox.DataDirPath("accounts"), name)
	if _, err := os.Stat(accountDir); err == nil {
		return "", fmt.Errorf("%w: account directory %q already exists", store.ErrUnknownCredentials, accountDir)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("stat account directory %q: %w", accountDir, err)
	}

	nc := c
	nc.Accounts = map[string]config.Account{}
	maps.Copy(nc.Accounts, c.Accounts)
	acc := MakeAccountConfig(addr)
	acc.Chatmail = true
	nc.Accounts[name] = acc

	if err := mox.WriteDynamicLocked(ctx, log, nc); err != nil {
		return "", fmt.Errorf("writing domains.conf: %w", err)
	}
	return name, nil
}

// validAccountName returns whether name can be used as an account name: a safe
// filename that is not a special directory name.
func validAccountName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}
