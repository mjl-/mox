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
// A new account is only created if chatmail mode is enabled for the server,
// automatic registration has not been disabled, and the domain is enabled.
func OpenEmailAuth(log mlog.Log, email, password string, checkLoginDisabled, canCreate bool) (*store.Account, string, error) {
	acc, accName, err := store.OpenEmailAuth(log, email, password, checkLoginDisabled)
	if err == nil || !canCreate || !errors.Is(err, store.ErrUnknownCredentials) {
		return acc, accName, err
	}

	addr, aerr := smtp.ParseAddress(email)
	if aerr != nil || !chatmailAutoCreateAllowed(mox.Conf.DynamicConfig(), addr) {
		return nil, "", err
	}

	// Validate the password before changing any configuration. SetPassword requires
	// a password of 8 to 72 bytes after normalization (the bcrypt limit).
	pw, perr := precis.OpaqueString.String(password)
	if perr != nil || len(pw) < 8 || len(pw) > 72 {
		return nil, "", err
	}

	// If the address is already configured, a previous automatic creation may have
	// been interrupted after writing the configuration but before setting the
	// password. Complete that creation. Otherwise the password was wrong.
	if accName == "" {
		if name, _, _, _, lerr := mox.LookupAddress(addr.Localpart, addr.Domain, false, false, false); lerr == nil {
			accName = name
		}
	}
	if accName != "" {
		return completeChatmailAccount(log, accName, password)
	}
	return createChatmailAccount(log, addr, password)
}

// chatmailAutoCreateAllowed returns whether automatic account creation is allowed
// for addr.
func chatmailAutoCreateAllowed(dyn config.Dynamic, addr smtp.Address) bool {
	if !dyn.Chatmail.Enabled || dyn.Chatmail.AutoregistrationDisabled {
		return false
	}
	dom, ok := dyn.Domains[addr.Domain.Name()]
	return ok && dom.Chatmail && !dom.Disabled
}

// completeChatmailAccount sets the password for an account whose automatic
// creation was interrupted before the password was set.
func completeChatmailAccount(log mlog.Log, name, password string) (*store.Account, string, error) {
	conf, ok := mox.Conf.Account(name)
	if !ok || !conf.Chatmail {
		return nil, "", store.ErrUnknownCredentials
	}
	a, err := store.OpenAccount(log, name, false)
	if err != nil {
		return nil, "", fmt.Errorf("opening chatmail account to complete creation: %w", err)
	}
	set, err := a.PasswordSet()
	if err != nil {
		xerr := a.Close()
		log.Check(xerr, "closing chatmail account after checking password")
		return nil, "", fmt.Errorf("checking password for chatmail account: %w", err)
	}
	if set {
		xerr := a.Close()
		log.Check(xerr, "closing chatmail account with wrong password")
		return nil, "", store.ErrUnknownCredentials
	}
	if err := a.SetPassword(log, password); err != nil {
		xerr := a.Close()
		log.Check(xerr, "closing chatmail account after setting password")
		return nil, "", fmt.Errorf("setting password for chatmail account: %w", err)
	}
	log.Info("completed chatmail account creation", slog.String("account", name))
	return a, name, nil
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
		return nil, "", fmt.Errorf("opening new chatmail account: %w", err)
	}
	if err := a.SetPassword(log, password); err != nil {
		xerr := a.Close()
		log.Check(xerr, "closing new chatmail account after error")
		return nil, "", fmt.Errorf("setting password for new chatmail account: %w", err)
	}
	log.Info("created chatmail account", slog.String("account", name), slog.String("address", addr.String()))
	return a, name, nil
}

// createChatmailAccountConfig adds a new account with chatmail flag enabled to
// the dynamic configuration, and reloads it. It returns the account name.
func createChatmailAccountConfig(ctx context.Context, log mlog.Log, addr smtp.Address) (string, error) {
	defer mox.Conf.DynamicLockUnlock()()

	c := mox.Conf.Dynamic

	// Recheck under the lock: an admin may have disabled chatmail mode or automatic
	// registration, or the domain, since OpenEmailAuth checked.
	if !chatmailAutoCreateAllowed(c, addr) {
		return "", store.ErrUnknownCredentials
	}
	if err := checkAddressAvailable(addr); err != nil {
		return "", fmt.Errorf("%w: address not available: %v", store.ErrUnknownCredentials, err)
	}

	// The account name defaults to the localpart of the address. It must be a safe
	// filename and must not be in use.
	base := string(addr.Localpart)
	if !validAccountName(base) {
		base = ""
	}
	var name string
	for i := 0; ; i++ {
		if i > 16 {
			return "", fmt.Errorf("finding unused account name")
		}
		if i == 0 && base != "" {
			name = base
		} else {
			name = fmt.Sprintf("chatmail-%d", mox.CryptoRandInt())
		}
		if _, ok := c.Accounts[name]; ok {
			continue
		}
		accountDir := filepath.Join(mox.DataDirPath("accounts"), name)
		if _, err := os.Stat(accountDir); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("stat account directory %q: %w", accountDir, err)
		}
		break
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
