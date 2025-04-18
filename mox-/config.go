package mox

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/mjl-/autocert"

	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/smtp"
)

var pkglog = mlog.New("mox", nil)

// Pedantic enables stricter parsing.
var Pedantic bool

// Config paths are set early in program startup. They will point to files in
// the same directory.
var (
	ConfigStaticPath  string
	ConfigDynamicPath string
	Conf              = Config{Log: map[string]slog.Level{"": slog.LevelError}}
)

var ErrConfig = errors.New("config error")

// Set by packages webadmin, webaccount, webmail, webapisrv to prevent cyclic dependencies.
var NewWebadminHandler = func(basePath string, isForwarded bool) http.Handler { return nopHandler }
var NewWebaccountHandler = func(basePath string, isForwarded bool) http.Handler { return nopHandler }
var NewWebmailHandler = func(maxMsgSize int64, basePath string, isForwarded bool, accountPath string) http.Handler {
	return nopHandler
}
var NewWebapiHandler = func(maxMsgSize int64, basePath string, isForwarded bool) http.Handler { return nopHandler }

var nopHandler = http.HandlerFunc(nil)

// Config as used in the code, a processed version of what is in the config file.
//
// Use methods to lookup a domain/account/address in the dynamic configuration.
type Config struct {
	Static config.Static // Does not change during the lifetime of a running instance.

	logMutex sync.Mutex // For accessing the log levels.
	Log      map[string]slog.Level

	dynamicMutex     sync.Mutex
	Dynamic          config.Dynamic // Can only be accessed directly by tests. Use methods on Config for locked access.
	dynamicMtime     time.Time
	DynamicLastCheck time.Time // For use by quickstart only to skip checks.

	// From canonical full address (localpart@domain, lower-cased when
	// case-insensitive, stripped of catchall separator) to account and address.
	// Domains are IDNA names in utf8. Dynamic config lock must be held when accessing.
	AccountDestinationsLocked map[string]AccountDestination

	// Like AccountDestinationsLocked, but for aliases.
	aliases map[string]config.Alias
}

type AccountDestination struct {
	Catchall    bool           // If catchall destination for its domain.
	Localpart   smtp.Localpart // In original casing as written in config file.
	Account     string
	Destination config.Destination
}

// LogLevelSet sets a new log level for pkg. An empty pkg sets the default log
// value that is used if no explicit log level is configured for a package.
// This change is ephemeral, no config file is changed.
func (c *Config) LogLevelSet(log mlog.Log, pkg string, level slog.Level) {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	l := c.copyLogLevels()
	l[pkg] = level
	c.Log = l
	log.Print("log level changed", slog.String("pkg", pkg), slog.Any("level", mlog.LevelStrings[level]))
	mlog.SetConfig(c.Log)
}

// LogLevelRemove removes a configured log level for a package.
func (c *Config) LogLevelRemove(log mlog.Log, pkg string) {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	l := c.copyLogLevels()
	delete(l, pkg)
	c.Log = l
	log.Print("log level cleared", slog.String("pkg", pkg))
	mlog.SetConfig(c.Log)
}

// copyLogLevels returns a copy of c.Log, for modifications.
// must be called with log lock held.
func (c *Config) copyLogLevels() map[string]slog.Level {
	m := map[string]slog.Level{}
	for pkg, level := range c.Log {
		m[pkg] = level
	}
	return m
}

// LogLevels returns a copy of the current log levels.
func (c *Config) LogLevels() map[string]slog.Level {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	return c.copyLogLevels()
}

// DynamicLockUnlock locks the dynamic config, will try updating the latest state
// from disk, and return an unlock function. Should be called as "defer
// Conf.DynamicLockUnlock()()".
func (c *Config) DynamicLockUnlock() func() {
	c.dynamicMutex.Lock()
	now := time.Now()
	if now.Sub(c.DynamicLastCheck) > time.Second {
		c.DynamicLastCheck = now
		if fi, err := os.Stat(ConfigDynamicPath); err != nil {
			pkglog.Errorx("stat domains config", err)
		} else if !fi.ModTime().Equal(c.dynamicMtime) {
			if errs := c.loadDynamic(); len(errs) > 0 {
				pkglog.Errorx("loading domains config", errs[0], slog.Any("errors", errs))
			} else {
				pkglog.Info("domains config reloaded")
				c.dynamicMtime = fi.ModTime()
			}
		}
	}
	return c.dynamicMutex.Unlock
}

func (c *Config) withDynamicLock(fn func()) {
	defer c.DynamicLockUnlock()()
	fn()
}

// must be called with dynamic lock held.
func (c *Config) loadDynamic() []error {
	d, mtime, accDests, aliases, err := ParseDynamicConfig(context.Background(), pkglog, ConfigDynamicPath, c.Static)
	if err != nil {
		return err
	}
	c.Dynamic = d
	c.dynamicMtime = mtime
	c.AccountDestinationsLocked = accDests
	c.aliases = aliases
	c.allowACMEHosts(pkglog, true)
	return nil
}

// DynamicConfig returns a shallow copy of the dynamic config. Must not be modified.
func (c *Config) DynamicConfig() (config config.Dynamic) {
	c.withDynamicLock(func() {
		config = c.Dynamic // Shallow copy.
	})
	return
}

func (c *Config) Domains() (l []string) {
	c.withDynamicLock(func() {
		for name := range c.Dynamic.Domains {
			l = append(l, name)
		}
	})
	slices.Sort(l)
	return l
}

func (c *Config) Accounts() (l []string) {
	c.withDynamicLock(func() {
		for name := range c.Dynamic.Accounts {
			l = append(l, name)
		}
	})
	return
}

func (c *Config) AccountsDisabled() (all, disabled []string) {
	c.withDynamicLock(func() {
		for name, conf := range c.Dynamic.Accounts {
			all = append(all, name)
			if conf.LoginDisabled != "" {
				disabled = append(disabled, name)
			}
		}
	})
	return
}

// DomainLocalparts returns a mapping of encoded localparts to account names for a
// domain, and encoded localparts to aliases. An empty localpart is a catchall
// destination for a domain.
func (c *Config) DomainLocalparts(d dns.Domain) (map[string]string, map[string]config.Alias) {
	suffix := "@" + d.Name()
	m := map[string]string{}
	aliases := map[string]config.Alias{}
	c.withDynamicLock(func() {
		for addr, ad := range c.AccountDestinationsLocked {
			if strings.HasSuffix(addr, suffix) {
				if ad.Catchall {
					m[""] = ad.Account
				} else {
					m[ad.Localpart.String()] = ad.Account
				}
			}
		}
		for addr, a := range c.aliases {
			if strings.HasSuffix(addr, suffix) {
				aliases[a.LocalpartStr] = a
			}
		}
	})
	return m, aliases
}

func (c *Config) Domain(d dns.Domain) (dom config.Domain, ok bool) {
	c.withDynamicLock(func() {
		dom, ok = c.Dynamic.Domains[d.Name()]
	})
	return
}

func (c *Config) DomainConfigs() (doms []config.Domain) {
	c.withDynamicLock(func() {
		doms = make([]config.Domain, 0, len(c.Dynamic.Domains))
		for _, d := range c.Dynamic.Domains {
			doms = append(doms, d)
		}
	})
	return
}

func (c *Config) Account(name string) (acc config.Account, ok bool) {
	c.withDynamicLock(func() {
		acc, ok = c.Dynamic.Accounts[name]
	})
	return
}

func (c *Config) AccountDestination(addr string) (accDest AccountDestination, alias *config.Alias, ok bool) {
	c.withDynamicLock(func() {
		accDest, ok = c.AccountDestinationsLocked[addr]
		if !ok {
			var a config.Alias
			a, ok = c.aliases[addr]
			if ok {
				alias = &a
			}
		}
	})
	return
}

func (c *Config) Routes(accountName string, domain dns.Domain) (accountRoutes, domainRoutes, globalRoutes []config.Route) {
	c.withDynamicLock(func() {
		acc := c.Dynamic.Accounts[accountName]
		accountRoutes = acc.Routes

		dom := c.Dynamic.Domains[domain.Name()]
		domainRoutes = dom.Routes

		globalRoutes = c.Dynamic.Routes
	})
	return
}

func (c *Config) IsClientSettingsDomain(d dns.Domain) (is bool) {
	c.withDynamicLock(func() {
		_, is = c.Dynamic.ClientSettingDomains[d]
	})
	return
}

func (c *Config) allowACMEHosts(log mlog.Log, checkACMEHosts bool) {
	for _, l := range c.Static.Listeners {
		if l.TLS == nil || l.TLS.ACME == "" {
			continue
		}

		m := c.Static.ACME[l.TLS.ACME].Manager
		hostnames := map[dns.Domain]struct{}{}

		hostnames[c.Static.HostnameDomain] = struct{}{}
		if l.HostnameDomain.ASCII != "" {
			hostnames[l.HostnameDomain] = struct{}{}
		}

		for _, dom := range c.Dynamic.Domains {
			// Do not allow TLS certificates for domains for which we only accept DMARC/TLS
			// reports as external party.
			if dom.ReportsOnly {
				continue
			}

			// Do not fetch TLS certs for disabled domains. The A/AAAA records may not be
			// configured or still point to a previous machine before a migration.
			if dom.Disabled {
				continue
			}

			if l.AutoconfigHTTPS.Enabled && !l.AutoconfigHTTPS.NonTLS {
				if d, err := dns.ParseDomain("autoconfig." + dom.Domain.ASCII); err != nil {
					log.Errorx("parsing autoconfig domain", err, slog.Any("domain", dom.Domain))
				} else {
					hostnames[d] = struct{}{}
				}
			}

			if l.MTASTSHTTPS.Enabled && dom.MTASTS != nil && !l.MTASTSHTTPS.NonTLS {
				d, err := dns.ParseDomain("mta-sts." + dom.Domain.ASCII)
				if err != nil {
					log.Errorx("parsing mta-sts domain", err, slog.Any("domain", dom.Domain))
				} else {
					hostnames[d] = struct{}{}
				}
			}

			if dom.ClientSettingsDomain != "" {
				hostnames[dom.ClientSettingsDNSDomain] = struct{}{}
			}
		}

		if l.WebserverHTTPS.Enabled {
			for from := range c.Dynamic.WebDNSDomainRedirects {
				hostnames[from] = struct{}{}
			}
			for _, wh := range c.Dynamic.WebHandlers {
				hostnames[wh.DNSDomain] = struct{}{}
			}
		}

		public := c.Static.Listeners["public"]
		ips := public.IPs
		if len(public.NATIPs) > 0 {
			ips = public.NATIPs
		}
		if public.IPsNATed {
			ips = nil
		}
		m.SetAllowedHostnames(log, dns.StrictResolver{Pkg: "autotls", Log: log.Logger}, hostnames, ips, checkACMEHosts)
	}
}

// todo future: write config parsing & writing code that can read a config and remembers the exact tokens including newlines and comments, and can write back a modified file. the goal is to be able to write a config file automatically (after changing fields through the ui), but not loose comments and whitespace, to still get useful diffs for storing the config in a version control system.

// WriteDynamicLocked prepares an updated internal state for the new dynamic
// config, then writes it to disk and activates it.
//
// Returns ErrConfig if the configuration is not valid.
//
// Must be called with config lock held.
func WriteDynamicLocked(ctx context.Context, log mlog.Log, c config.Dynamic) error {
	accDests, aliases, errs := prepareDynamicConfig(ctx, log, ConfigDynamicPath, Conf.Static, &c)
	if len(errs) > 0 {
		errstrs := make([]string, len(errs))
		for i, err := range errs {
			errstrs[i] = err.Error()
		}
		return fmt.Errorf("%w: %s", ErrConfig, strings.Join(errstrs, "; "))
	}

	var b bytes.Buffer
	err := sconf.Write(&b, c)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(ConfigDynamicPath, os.O_WRONLY, 0660)
	if err != nil {
		return err
	}
	defer func() {
		if f != nil {
			err := f.Close()
			log.Check(err, "closing file after error")
		}
	}()
	buf := b.Bytes()
	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("write domains.conf: %v", err)
	}
	if err := f.Truncate(int64(len(buf))); err != nil {
		return fmt.Errorf("truncate domains.conf after write: %v", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync domains.conf after write: %v", err)
	}
	if err := moxio.SyncDir(log, filepath.Dir(ConfigDynamicPath)); err != nil {
		return fmt.Errorf("sync dir of domains.conf after write: %v", err)
	}

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat after writing domains.conf: %v", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close written domains.conf: %v", err)
	}
	f = nil

	Conf.dynamicMtime = fi.ModTime()
	Conf.DynamicLastCheck = time.Now()
	Conf.Dynamic = c
	Conf.AccountDestinationsLocked = accDests
	Conf.aliases = aliases

	Conf.allowACMEHosts(log, true)

	return nil
}

// MustLoadConfig loads the config, quitting on errors.
func MustLoadConfig(doLoadTLSKeyCerts, checkACMEHosts bool) {
	errs := LoadConfig(context.Background(), pkglog, doLoadTLSKeyCerts, checkACMEHosts)
	if len(errs) > 1 {
		pkglog.Error("loading config file: multiple errors")
		for _, err := range errs {
			pkglog.Errorx("config error", err)
		}
		pkglog.Fatal("stopping after multiple config errors")
	} else if len(errs) == 1 {
		pkglog.Fatalx("loading config file", errs[0])
	}
}

// LoadConfig attempts to parse and load a config, returning any errors
// encountered.
func LoadConfig(ctx context.Context, log mlog.Log, doLoadTLSKeyCerts, checkACMEHosts bool) []error {
	Shutdown, ShutdownCancel = context.WithCancel(context.Background())
	Context, ContextCancel = context.WithCancel(context.Background())

	c, errs := ParseConfig(ctx, log, ConfigStaticPath, false, doLoadTLSKeyCerts, checkACMEHosts)
	if len(errs) > 0 {
		return errs
	}

	mlog.SetConfig(c.Log)
	SetConfig(c)
	return nil
}

// SetConfig sets a new config. Not to be used during normal operation.
func SetConfig(c *Config) {
	// Cannot just assign *c to Conf, it would copy the mutex.
	Conf = Config{c.Static, sync.Mutex{}, c.Log, sync.Mutex{}, c.Dynamic, c.dynamicMtime, c.DynamicLastCheck, c.AccountDestinationsLocked, c.aliases}

	// If we have non-standard CA roots, use them for all HTTPS requests.
	if Conf.Static.TLS.CertPool != nil {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
			RootCAs: Conf.Static.TLS.CertPool,
		}
	}

	SetPedantic(c.Static.Pedantic)
}

// Set pedantic in all packages.
func SetPedantic(p bool) {
	dkim.Pedantic = p
	dns.Pedantic = p
	message.Pedantic = p
	smtp.Pedantic = p
	Pedantic = p
}

// ParseConfig parses the static config at path p. If checkOnly is true, no changes
// are made, such as registering ACME identities. If doLoadTLSKeyCerts is true,
// the TLS KeyCerts configuration is loaded and checked. This is used during the
// quickstart in the case the user is going to provide their own certificates.
// If checkACMEHosts is true, the hosts allowed for acme are compared with the
// explicitly configured ips we are listening on.
func ParseConfig(ctx context.Context, log mlog.Log, p string, checkOnly, doLoadTLSKeyCerts, checkACMEHosts bool) (c *Config, errs []error) {
	c = &Config{
		Static: config.Static{
			DataDir: ".",
		},
	}

	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) && os.Getenv("MOXCONF") == "" {
			return nil, []error{fmt.Errorf("open config file: %v (hint: use mox -config ... or set MOXCONF=...)", err)}
		}
		return nil, []error{fmt.Errorf("open config file: %v", err)}
	}
	defer f.Close()
	if err := sconf.Parse(f, &c.Static); err != nil {
		return nil, []error{fmt.Errorf("parsing %s%v", p, err)}
	}

	if xerrs := PrepareStaticConfig(ctx, log, p, c, checkOnly, doLoadTLSKeyCerts); len(xerrs) > 0 {
		return nil, xerrs
	}

	pp := filepath.Join(filepath.Dir(p), "domains.conf")
	c.Dynamic, c.dynamicMtime, c.AccountDestinationsLocked, c.aliases, errs = ParseDynamicConfig(ctx, log, pp, c.Static)

	if !checkOnly {
		c.allowACMEHosts(log, checkACMEHosts)
	}

	return c, errs
}

// PrepareStaticConfig parses the static config file and prepares data structures
// for starting mox. If checkOnly is set no substantial changes are made, like
// creating an ACME registration.
func PrepareStaticConfig(ctx context.Context, log mlog.Log, configFile string, conf *Config, checkOnly, doLoadTLSKeyCerts bool) (errs []error) {
	addErrorf := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	c := &conf.Static

	// check that mailbox is in unicode NFC normalized form.
	checkMailboxNormf := func(mailbox string, format string, args ...any) {
		s := norm.NFC.String(mailbox)
		if mailbox != s {
			msg := fmt.Sprintf(format, args...)
			addErrorf("%s: mailbox %q is not in NFC normalized form, should be %q", msg, mailbox, s)
		}
	}

	// Post-process logging config.
	if logLevel, ok := mlog.Levels[c.LogLevel]; ok {
		conf.Log = map[string]slog.Level{"": logLevel}
	} else {
		addErrorf("invalid log level %q", c.LogLevel)
	}
	for pkg, s := range c.PackageLogLevels {
		if logLevel, ok := mlog.Levels[s]; ok {
			conf.Log[pkg] = logLevel
		} else {
			addErrorf("invalid package log level %q", s)
		}
	}

	if c.User == "" {
		c.User = "mox"
	}
	u, err := user.Lookup(c.User)
	if err != nil {
		uid, err := strconv.ParseUint(c.User, 10, 32)
		if err != nil {
			addErrorf("parsing unknown user %s as uid: %v (hint: add user mox with \"useradd -d $PWD mox\" or specify a different username on the quickstart command-line)", c.User, err)
		} else {
			// We assume the same gid as uid.
			c.UID = uint32(uid)
			c.GID = uint32(uid)
		}
	} else {
		if uid, err := strconv.ParseUint(u.Uid, 10, 32); err != nil {
			addErrorf("parsing uid %s: %v", u.Uid, err)
		} else {
			c.UID = uint32(uid)
		}
		if gid, err := strconv.ParseUint(u.Gid, 10, 32); err != nil {
			addErrorf("parsing gid %s: %v", u.Gid, err)
		} else {
			c.GID = uint32(gid)
		}
	}

	hostname, err := dns.ParseDomain(c.Hostname)
	if err != nil {
		addErrorf("parsing hostname: %s", err)
	} else if hostname.Name() != c.Hostname {
		addErrorf("hostname must be in unicode form %q instead of %q", hostname.Name(), c.Hostname)
	}
	c.HostnameDomain = hostname

	if c.HostTLSRPT.Account != "" {
		tlsrptLocalpart, err := smtp.ParseLocalpart(c.HostTLSRPT.Localpart)
		if err != nil {
			addErrorf("invalid localpart %q for host tlsrpt: %v", c.HostTLSRPT.Localpart, err)
		} else if tlsrptLocalpart.IsInternational() {
			// Does not appear documented in ../rfc/8460, but similar to DMARC it makes sense
			// to keep this ascii-only addresses.
			addErrorf("host TLSRPT localpart %q is an internationalized address, only conventional ascii-only address allowed for interopability", tlsrptLocalpart)
		}
		c.HostTLSRPT.ParsedLocalpart = tlsrptLocalpart
	}

	// Return private key for host name for use with an ACME. Used to return the same
	// private key as pre-generated for use with DANE, with its public key in DNS.
	// We only use this key for Listener's that have this ACME configured, and for
	// which the effective listener host name (either specific to the listener, or the
	// global name) is requested. Other host names can get a fresh private key, they
	// don't appear in DANE records.
	//
	// - run 0: only use listener with explicitly matching host name in listener
	//   (default quickstart config does not set it).
	// - run 1: only look at public listener (and host matching mox host name)
	// - run 2: all listeners (and host matching mox host name)
	findACMEHostPrivateKey := func(acmeName, host string, keyType autocert.KeyType, run int) crypto.Signer {
		for listenerName, l := range Conf.Static.Listeners {
			if l.TLS == nil || l.TLS.ACME != acmeName {
				continue
			}
			if run == 0 && host != l.HostnameDomain.ASCII {
				continue
			}
			if run == 1 && listenerName != "public" || host != Conf.Static.HostnameDomain.ASCII {
				continue
			}
			switch keyType {
			case autocert.KeyRSA2048:
				if len(l.TLS.HostPrivateRSA2048Keys) == 0 {
					continue
				}
				return l.TLS.HostPrivateRSA2048Keys[0]
			case autocert.KeyECDSAP256:
				if len(l.TLS.HostPrivateECDSAP256Keys) == 0 {
					continue
				}
				return l.TLS.HostPrivateECDSAP256Keys[0]
			default:
				return nil
			}
		}
		return nil
	}
	// Make a function for an autocert.Manager.GetPrivateKey, using findACMEHostPrivateKey.
	makeGetPrivateKey := func(acmeName string) func(host string, keyType autocert.KeyType) (crypto.Signer, error) {
		return func(host string, keyType autocert.KeyType) (crypto.Signer, error) {
			key := findACMEHostPrivateKey(acmeName, host, keyType, 0)
			if key == nil {
				key = findACMEHostPrivateKey(acmeName, host, keyType, 1)
			}
			if key == nil {
				key = findACMEHostPrivateKey(acmeName, host, keyType, 2)
			}
			if key != nil {
				log.Debug("found existing private key for certificate for host",
					slog.String("acmename", acmeName),
					slog.String("host", host),
					slog.Any("keytype", keyType))
				return key, nil
			}
			log.Debug("generating new private key for certificate for host",
				slog.String("acmename", acmeName),
				slog.String("host", host),
				slog.Any("keytype", keyType))
			switch keyType {
			case autocert.KeyRSA2048:
				return rsa.GenerateKey(cryptorand.Reader, 2048)
			case autocert.KeyECDSAP256:
				return ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
			default:
				return nil, fmt.Errorf("unrecognized requested key type %v", keyType)
			}
		}
	}
	for name, acme := range c.ACME {
		addAcmeErrorf := func(format string, args ...any) {
			addErrorf("acme provider %s: %s", name, fmt.Sprintf(format, args...))
		}

		var eabKeyID string
		var eabKey []byte
		if acme.ExternalAccountBinding != nil {
			eabKeyID = acme.ExternalAccountBinding.KeyID
			p := configDirPath(configFile, acme.ExternalAccountBinding.KeyFile)
			buf, err := os.ReadFile(p)
			if err != nil {
				addAcmeErrorf("reading external account binding key: %s", err)
			} else {
				dec := make([]byte, base64.RawURLEncoding.DecodedLen(len(buf)))
				n, err := base64.RawURLEncoding.Decode(dec, buf)
				if err != nil {
					addAcmeErrorf("parsing external account binding key as base64: %s", err)
				} else {
					eabKey = dec[:n]
				}
			}
		}

		if checkOnly {
			continue
		}

		acmeDir := dataDirPath(configFile, c.DataDir, "acme")
		os.MkdirAll(acmeDir, 0770)
		manager, err := autotls.Load(log, name, acmeDir, acme.ContactEmail, acme.DirectoryURL, eabKeyID, eabKey, makeGetPrivateKey(name), Shutdown.Done())
		if err != nil {
			addAcmeErrorf("loading ACME identity: %s", err)
		}
		acme.Manager = manager

		// Help configurations from older quickstarts.
		if acme.IssuerDomainName == "" && acme.DirectoryURL == "https://acme-v02.api.letsencrypt.org/directory" {
			acme.IssuerDomainName = "letsencrypt.org"
		}

		c.ACME[name] = acme
	}

	var haveUnspecifiedSMTPListener bool
	for name, l := range c.Listeners {
		addListenerErrorf := func(format string, args ...any) {
			addErrorf("listener %s: %s", name, fmt.Sprintf(format, args...))
		}

		if l.Hostname != "" {
			d, err := dns.ParseDomain(l.Hostname)
			if err != nil {
				addListenerErrorf("parsing hostname %q: %s", l.Hostname, err)
			}
			l.HostnameDomain = d
		}
		if l.TLS != nil {
			if l.TLS.ACME != "" && len(l.TLS.KeyCerts) != 0 {
				addListenerErrorf("cannot have ACME and static key/certificates")
			} else if l.TLS.ACME != "" {
				acme, ok := c.ACME[l.TLS.ACME]
				if !ok {
					addListenerErrorf("unknown ACME provider %q", l.TLS.ACME)
				}

				// If only checking or with missing ACME definition, we don't have an acme manager,
				// so set an empty tls config to continue.
				var tlsconfig, tlsconfigFallback *tls.Config
				if checkOnly || acme.Manager == nil {
					tlsconfig = &tls.Config{}
					tlsconfigFallback = &tls.Config{}
				} else {
					hostname := c.HostnameDomain
					if l.Hostname != "" {
						hostname = l.HostnameDomain
					}
					// If SNI is absent, we will use the listener hostname, but reject connections with
					// an SNI hostname that is not allowlisted.
					// Incoming SMTP deliveries use tlsconfigFallback for interoperability. TLS
					// connections for unknown SNI hostnames fall back to a certificate for the
					// listener hostname instead of causing the TLS connection to fail.
					tlsconfig = acme.Manager.TLSConfig(hostname, true, false)
					tlsconfigFallback = acme.Manager.TLSConfig(hostname, true, true)
					l.TLS.ACMEConfig = acme.Manager.ACMETLSConfig
				}
				l.TLS.Config = tlsconfig
				l.TLS.ConfigFallback = tlsconfigFallback
			} else if len(l.TLS.KeyCerts) != 0 {
				if doLoadTLSKeyCerts {
					if err := loadTLSKeyCerts(configFile, "listener "+name, l.TLS); err != nil {
						addListenerErrorf("%w", err)
					}
				}
			} else {
				addListenerErrorf("cannot have TLS config without ACME and without static keys/certificates")
			}
			for _, privKeyFile := range l.TLS.HostPrivateKeyFiles {
				keyPath := configDirPath(configFile, privKeyFile)
				privKey, err := loadPrivateKeyFile(keyPath)
				if err != nil {
					addListenerErrorf("parsing host private key for DANE and ACME certificates: %v", err)
					continue
				}
				switch k := privKey.(type) {
				case *rsa.PrivateKey:
					if k.N.BitLen() != 2048 {
						log.Error("need rsa key with 2048 bits, for host private key for DANE/ACME certificates, ignoring",
							slog.String("listener", name),
							slog.String("file", keyPath),
							slog.Int("bits", k.N.BitLen()))
						continue
					}
					l.TLS.HostPrivateRSA2048Keys = append(l.TLS.HostPrivateRSA2048Keys, k)
				case *ecdsa.PrivateKey:
					if k.Curve != elliptic.P256() {
						log.Error("unrecognized ecdsa curve for host private key for DANE/ACME certificates, ignoring", slog.String("listener", name), slog.String("file", keyPath))
						continue
					}
					l.TLS.HostPrivateECDSAP256Keys = append(l.TLS.HostPrivateECDSAP256Keys, k)
				default:
					log.Error("unrecognized key type for host private key for DANE/ACME certificates, ignoring",
						slog.String("listener", name),
						slog.String("file", keyPath),
						slog.String("keytype", fmt.Sprintf("%T", privKey)))
					continue
				}
			}
			if l.TLS.ACME != "" && (len(l.TLS.HostPrivateRSA2048Keys) == 0) != (len(l.TLS.HostPrivateECDSAP256Keys) == 0) {
				log.Warn("uncommon configuration with either only an RSA 2048 or ECDSA P256 host private key for DANE/ACME certificates; this ACME implementation can retrieve certificates for both type of keys, it is recommended to set either both or none; continuing")
			}

			// TLS 1.2 was introduced in 2008. TLS <1.2 was deprecated by ../rfc/8996:31 and ../rfc/8997:66 in 2021.
			var minVersion uint16 = tls.VersionTLS12
			if l.TLS.MinVersion != "" {
				versions := map[string]uint16{
					"TLSv1.0": tls.VersionTLS10,
					"TLSv1.1": tls.VersionTLS11,
					"TLSv1.2": tls.VersionTLS12,
					"TLSv1.3": tls.VersionTLS13,
				}
				v, ok := versions[l.TLS.MinVersion]
				if !ok {
					addListenerErrorf("unknown TLS mininum version %q", l.TLS.MinVersion)
				}
				minVersion = v
			}
			if l.TLS.Config != nil {
				l.TLS.Config.MinVersion = minVersion
			}
			if l.TLS.ConfigFallback != nil {
				l.TLS.ConfigFallback.MinVersion = minVersion
			}
			if l.TLS.ACMEConfig != nil {
				l.TLS.ACMEConfig.MinVersion = minVersion
			}
		} else {
			var needsTLS []string
			needtls := func(s string, v bool) {
				if v {
					needsTLS = append(needsTLS, s)
				}
			}
			needtls("IMAPS", l.IMAPS.Enabled)
			needtls("SMTP", l.SMTP.Enabled && !l.SMTP.NoSTARTTLS)
			needtls("Submissions", l.Submissions.Enabled)
			needtls("Submission", l.Submission.Enabled && !l.Submission.NoRequireSTARTTLS)
			needtls("AccountHTTPS", l.AccountHTTPS.Enabled)
			needtls("AdminHTTPS", l.AdminHTTPS.Enabled)
			needtls("AutoconfigHTTPS", l.AutoconfigHTTPS.Enabled && !l.AutoconfigHTTPS.NonTLS)
			needtls("MTASTSHTTPS", l.MTASTSHTTPS.Enabled && !l.MTASTSHTTPS.NonTLS)
			needtls("WebserverHTTPS", l.WebserverHTTPS.Enabled)
			if len(needsTLS) > 0 {
				addListenerErrorf("no tls config specified, but requires tls for %s", strings.Join(needsTLS, ", "))
			}
		}
		if l.AutoconfigHTTPS.Enabled && l.MTASTSHTTPS.Enabled && l.AutoconfigHTTPS.Port == l.MTASTSHTTPS.Port && l.AutoconfigHTTPS.NonTLS != l.MTASTSHTTPS.NonTLS {
			addListenerErrorf("autoconfig and mta-sts enabled on same port but with both http and https")
		}
		if l.SMTP.Enabled {
			if len(l.IPs) == 0 {
				haveUnspecifiedSMTPListener = true
			}
			for _, ipstr := range l.IPs {
				ip := net.ParseIP(ipstr)
				if ip == nil {
					addListenerErrorf("invalid IP %q", ipstr)
					continue
				}
				if ip.IsUnspecified() {
					haveUnspecifiedSMTPListener = true
					break
				}
				if len(c.SpecifiedSMTPListenIPs) >= 2 {
					haveUnspecifiedSMTPListener = true
				} else if len(c.SpecifiedSMTPListenIPs) > 0 && (c.SpecifiedSMTPListenIPs[0].To4() == nil) == (ip.To4() == nil) {
					haveUnspecifiedSMTPListener = true
				} else {
					c.SpecifiedSMTPListenIPs = append(c.SpecifiedSMTPListenIPs, ip)
				}
			}
		}
		for _, s := range l.SMTP.DNSBLs {
			d, err := dns.ParseDomain(s)
			if err != nil {
				addListenerErrorf("parsing DNSBL zone %q: %s", s, err)
				continue
			}
			l.SMTP.DNSBLZones = append(l.SMTP.DNSBLZones, d)
		}
		if l.IPsNATed && len(l.NATIPs) > 0 {
			addListenerErrorf("both IPsNATed and NATIPs configued (remove deprecated IPsNATed)")
		}
		for _, ipstr := range l.NATIPs {
			ip := net.ParseIP(ipstr)
			if ip == nil {
				addListenerErrorf("invalid ip %q", ipstr)
			} else if ip.IsUnspecified() || ip.IsLoopback() {
				addListenerErrorf("NAT ip that is the unspecified or loopback address %s", ipstr)
			}
		}
		cleanPath := func(kind string, enabled bool, path string) string {
			if !enabled {
				return path
			}
			if path != "" && !strings.HasPrefix(path, "/") {
				addListenerErrorf("%s with path %q that must start with a slash", kind, path)
			} else if path != "" && !strings.HasSuffix(path, "/") {
				log.Warn("http service path should end with a slash, using effective path with slash", slog.String("kind", kind), slog.String("path", path), slog.String("effectivepath", path+"/"))
				path += "/"
			}
			return path
		}
		l.AccountHTTP.Path = cleanPath("AccountHTTP", l.AccountHTTP.Enabled, l.AccountHTTP.Path)
		l.AccountHTTPS.Path = cleanPath("AccountHTTPS", l.AccountHTTPS.Enabled, l.AccountHTTPS.Path)
		l.AdminHTTP.Path = cleanPath("AdminHTTP", l.AdminHTTP.Enabled, l.AdminHTTP.Path)
		l.AdminHTTPS.Path = cleanPath("AdminHTTPS", l.AdminHTTPS.Enabled, l.AdminHTTPS.Path)
		l.WebmailHTTP.Path = cleanPath("WebmailHTTP", l.WebmailHTTP.Enabled, l.WebmailHTTP.Path)
		l.WebmailHTTPS.Path = cleanPath("WebmailHTTPS", l.WebmailHTTPS.Enabled, l.WebmailHTTPS.Path)
		l.WebAPIHTTP.Path = cleanPath("WebAPIHTTP", l.WebAPIHTTP.Enabled, l.WebAPIHTTP.Path)
		l.WebAPIHTTPS.Path = cleanPath("WebAPIHTTPS", l.WebAPIHTTPS.Enabled, l.WebAPIHTTPS.Path)
		c.Listeners[name] = l
	}
	if haveUnspecifiedSMTPListener {
		c.SpecifiedSMTPListenIPs = nil
	}

	var zerouse config.SpecialUseMailboxes
	if len(c.DefaultMailboxes) > 0 && (c.InitialMailboxes.SpecialUse != zerouse || len(c.InitialMailboxes.Regular) > 0) {
		addErrorf("cannot have both DefaultMailboxes and InitialMailboxes")
	}
	// DefaultMailboxes is deprecated.
	for _, mb := range c.DefaultMailboxes {
		checkMailboxNormf(mb, "default mailbox")
		// We don't create parent mailboxes for default mailboxes.
		if ParentMailboxName(mb) != "" {
			addErrorf("default mailbox cannot be a child mailbox")
		}
	}
	checkSpecialUseMailbox := func(nameOpt string) {
		if nameOpt != "" {
			checkMailboxNormf(nameOpt, "special-use initial mailbox")
			if strings.EqualFold(nameOpt, "inbox") {
				addErrorf("initial mailbox cannot be set to Inbox (Inbox is always created)")
			}
			// We don't currently create parent mailboxes for initial mailboxes.
			if ParentMailboxName(nameOpt) != "" {
				addErrorf("initial mailboxes cannot be child mailboxes")
			}
		}
	}
	checkSpecialUseMailbox(c.InitialMailboxes.SpecialUse.Archive)
	checkSpecialUseMailbox(c.InitialMailboxes.SpecialUse.Draft)
	checkSpecialUseMailbox(c.InitialMailboxes.SpecialUse.Junk)
	checkSpecialUseMailbox(c.InitialMailboxes.SpecialUse.Sent)
	checkSpecialUseMailbox(c.InitialMailboxes.SpecialUse.Trash)
	for _, name := range c.InitialMailboxes.Regular {
		checkMailboxNormf(name, "regular initial mailbox")
		if strings.EqualFold(name, "inbox") {
			addErrorf("initial regular mailbox cannot be set to Inbox (Inbox is always created)")
		}
		if ParentMailboxName(name) != "" {
			addErrorf("initial mailboxes cannot be child mailboxes")
		}
	}

	checkTransportSMTP := func(name string, isTLS bool, t *config.TransportSMTP) {
		addTransportErrorf := func(format string, args ...any) {
			addErrorf("transport %s: %s", name, fmt.Sprintf(format, args...))
		}

		var err error
		t.DNSHost, err = dns.ParseDomain(t.Host)
		if err != nil {
			addTransportErrorf("bad host %s: %v", t.Host, err)
		}

		if isTLS && t.STARTTLSInsecureSkipVerify {
			addTransportErrorf("cannot have STARTTLSInsecureSkipVerify with immediate TLS")
		}
		if isTLS && t.NoSTARTTLS {
			addTransportErrorf("cannot have NoSTARTTLS with immediate TLS")
		}

		if t.Auth == nil {
			return
		}
		seen := map[string]bool{}
		for _, m := range t.Auth.Mechanisms {
			if seen[m] {
				addTransportErrorf("duplicate authentication mechanism %s", m)
			}
			seen[m] = true
			switch m {
			case "SCRAM-SHA-256-PLUS":
			case "SCRAM-SHA-256":
			case "SCRAM-SHA-1-PLUS":
			case "SCRAM-SHA-1":
			case "CRAM-MD5":
			case "PLAIN":
			default:
				addTransportErrorf("unknown authentication mechanism %s", m)
			}
		}

		t.Auth.EffectiveMechanisms = t.Auth.Mechanisms
		if len(t.Auth.EffectiveMechanisms) == 0 {
			t.Auth.EffectiveMechanisms = []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1", "CRAM-MD5"}
		}
	}

	checkTransportSocks := func(name string, t *config.TransportSocks) {
		addTransportErrorf := func(format string, args ...any) {
			addErrorf("transport %s: %s", name, fmt.Sprintf(format, args...))
		}

		_, _, err := net.SplitHostPort(t.Address)
		if err != nil {
			addTransportErrorf("bad address %s: %v", t.Address, err)
		}
		for _, ipstr := range t.RemoteIPs {
			ip := net.ParseIP(ipstr)
			if ip == nil {
				addTransportErrorf("bad ip %s", ipstr)
			} else {
				t.IPs = append(t.IPs, ip)
			}
		}
		t.Hostname, err = dns.ParseDomain(t.RemoteHostname)
		if err != nil {
			addTransportErrorf("bad hostname %s: %v", t.RemoteHostname, err)
		}
	}

	checkTransportDirect := func(name string, t *config.TransportDirect) {
		addTransportErrorf := func(format string, args ...any) {
			addErrorf("transport %s: %s", name, fmt.Sprintf(format, args...))
		}

		if t.DisableIPv4 && t.DisableIPv6 {
			addTransportErrorf("both IPv4 and IPv6 are disabled, enable at least one")
		}
		t.IPFamily = "ip"
		if t.DisableIPv4 {
			t.IPFamily = "ip6"
		}
		if t.DisableIPv6 {
			t.IPFamily = "ip4"
		}
	}

	for name, t := range c.Transports {
		addTransportErrorf := func(format string, args ...any) {
			addErrorf("transport %s: %s", name, fmt.Sprintf(format, args...))
		}

		n := 0
		if t.Submissions != nil {
			n++
			checkTransportSMTP(name, true, t.Submissions)
		}
		if t.Submission != nil {
			n++
			checkTransportSMTP(name, false, t.Submission)
		}
		if t.SMTP != nil {
			n++
			checkTransportSMTP(name, false, t.SMTP)
		}
		if t.Socks != nil {
			n++
			checkTransportSocks(name, t.Socks)
		}
		if t.Direct != nil {
			n++
			checkTransportDirect(name, t.Direct)
		}
		if n > 1 {
			addTransportErrorf("cannot have multiple methods in a transport")
		}
	}

	// Load CA certificate pool.
	if c.TLS.CA != nil {
		if c.TLS.CA.AdditionalToSystem {
			var err error
			c.TLS.CertPool, err = x509.SystemCertPool()
			if err != nil {
				addErrorf("fetching system CA cert pool: %v", err)
			}
		} else {
			c.TLS.CertPool = x509.NewCertPool()
		}
		for _, certfile := range c.TLS.CA.CertFiles {
			p := configDirPath(configFile, certfile)
			pemBuf, err := os.ReadFile(p)
			if err != nil {
				addErrorf("reading TLS CA cert file: %v", err)
				continue
			} else if !c.TLS.CertPool.AppendCertsFromPEM(pemBuf) {
				// todo: can we check more fully if we're getting some useful data back?
				addErrorf("no CA certs added from %q", p)
			}
		}
	}
	return
}

// PrepareDynamicConfig parses the dynamic config file given a static file.
func ParseDynamicConfig(ctx context.Context, log mlog.Log, dynamicPath string, static config.Static) (c config.Dynamic, mtime time.Time, accDests map[string]AccountDestination, aliases map[string]config.Alias, errs []error) {
	addErrorf := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	f, err := os.Open(dynamicPath)
	if err != nil {
		addErrorf("parsing domains config: %v", err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		addErrorf("stat domains config: %v", err)
	}
	if err := sconf.Parse(f, &c); err != nil {
		addErrorf("parsing dynamic config file: %v", err)
		return
	}

	accDests, aliases, errs = prepareDynamicConfig(ctx, log, dynamicPath, static, &c)
	return c, fi.ModTime(), accDests, aliases, errs
}

func prepareDynamicConfig(ctx context.Context, log mlog.Log, dynamicPath string, static config.Static, c *config.Dynamic) (accDests map[string]AccountDestination, aliases map[string]config.Alias, errs []error) {
	addErrorf := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	// Check that mailbox is in unicode NFC normalized form.
	checkMailboxNormf := func(mailbox string, what string, errorf func(format string, args ...any)) {
		s := norm.NFC.String(mailbox)
		if mailbox != s {
			errorf("%s: mailbox %q is not in NFC normalized form, should be %q", what, mailbox, s)
		}
	}

	// Validate postmaster account exists.
	if _, ok := c.Accounts[static.Postmaster.Account]; !ok {
		addErrorf("postmaster account %q does not exist", static.Postmaster.Account)
	}
	checkMailboxNormf(static.Postmaster.Mailbox, "postmaster mailbox", addErrorf)

	accDests = map[string]AccountDestination{}
	aliases = map[string]config.Alias{}

	// Validate host TLSRPT account/address.
	if static.HostTLSRPT.Account != "" {
		if _, ok := c.Accounts[static.HostTLSRPT.Account]; !ok {
			addErrorf("host tlsrpt account %q does not exist", static.HostTLSRPT.Account)
		}
		checkMailboxNormf(static.HostTLSRPT.Mailbox, "host tlsrpt mailbox", addErrorf)

		// Localpart has been parsed already.

		addrFull := smtp.NewAddress(static.HostTLSRPT.ParsedLocalpart, static.HostnameDomain).String()
		dest := config.Destination{
			Mailbox:        static.HostTLSRPT.Mailbox,
			HostTLSReports: true,
		}
		accDests[addrFull] = AccountDestination{false, static.HostTLSRPT.ParsedLocalpart, static.HostTLSRPT.Account, dest}
	}

	var haveSTSListener, haveWebserverListener bool
	for _, l := range static.Listeners {
		if l.MTASTSHTTPS.Enabled {
			haveSTSListener = true
		}
		if l.WebserverHTTP.Enabled || l.WebserverHTTPS.Enabled {
			haveWebserverListener = true
		}
	}

	checkRoutes := func(descr string, routes []config.Route) {
		parseRouteDomains := func(l []string) []string {
			var r []string
			for _, e := range l {
				if e == "." {
					r = append(r, e)
					continue
				}
				prefix := ""
				if strings.HasPrefix(e, ".") {
					prefix = "."
					e = e[1:]
				}
				d, err := dns.ParseDomain(e)
				if err != nil {
					addErrorf("%s: invalid domain %s: %v", descr, e, err)
				}
				r = append(r, prefix+d.ASCII)
			}
			return r
		}

		for i := range routes {
			routes[i].FromDomainASCII = parseRouteDomains(routes[i].FromDomain)
			routes[i].ToDomainASCII = parseRouteDomains(routes[i].ToDomain)
			var ok bool
			routes[i].ResolvedTransport, ok = static.Transports[routes[i].Transport]
			if !ok {
				addErrorf("%s: route references undefined transport %s", descr, routes[i].Transport)
			}
		}
	}

	checkRoutes("global routes", c.Routes)

	// Validate domains.
	c.ClientSettingDomains = map[dns.Domain]struct{}{}
	for d, domain := range c.Domains {
		addDomainErrorf := func(format string, args ...any) {
			addErrorf(fmt.Sprintf("domain %v: %s", d, fmt.Sprintf(format, args...)))
		}

		dnsdomain, err := dns.ParseDomain(d)
		if err != nil {
			addDomainErrorf("parsing domain: %s", err)
		} else if dnsdomain.Name() != d {
			addDomainErrorf("must be specified in unicode form, %s", dnsdomain.Name())
		}

		domain.Domain = dnsdomain

		if domain.ClientSettingsDomain != "" {
			csd, err := dns.ParseDomain(domain.ClientSettingsDomain)
			if err != nil {
				addDomainErrorf("bad client settings domain %q: %s", domain.ClientSettingsDomain, err)
			}
			domain.ClientSettingsDNSDomain = csd
			c.ClientSettingDomains[csd] = struct{}{}
		}

		if domain.LocalpartCatchallSeparator != "" && len(domain.LocalpartCatchallSeparators) != 0 {
			addDomainErrorf("cannot have both LocalpartCatchallSeparator and LocalpartCatchallSeparators")
		}
		domain.LocalpartCatchallSeparatorsEffective = domain.LocalpartCatchallSeparators
		if domain.LocalpartCatchallSeparator != "" {
			domain.LocalpartCatchallSeparatorsEffective = append(domain.LocalpartCatchallSeparatorsEffective, domain.LocalpartCatchallSeparator)
		}
		sepSeen := map[string]bool{}
		for _, sep := range domain.LocalpartCatchallSeparatorsEffective {
			if sepSeen[sep] {
				addDomainErrorf("duplicate localpart catchall separator %q", sep)
			}
			sepSeen[sep] = true
		}

		for _, sign := range domain.DKIM.Sign {
			if _, ok := domain.DKIM.Selectors[sign]; !ok {
				addDomainErrorf("unknown selector %s for signing", sign)
			}
		}
		for name, sel := range domain.DKIM.Selectors {
			addSelectorErrorf := func(format string, args ...any) {
				addDomainErrorf("selector %s: %s", name, fmt.Sprintf(format, args...))
			}

			seld, err := dns.ParseDomain(name)
			if err != nil {
				addSelectorErrorf("parsing selector: %s", err)
			} else if seld.Name() != name {
				addSelectorErrorf("must be specified in unicode form, %q", seld.Name())
			}
			sel.Domain = seld

			if sel.Expiration != "" {
				exp, err := time.ParseDuration(sel.Expiration)
				if err != nil {
					addSelectorErrorf("invalid expiration %q: %v", sel.Expiration, err)
				} else {
					sel.ExpirationSeconds = int(exp / time.Second)
				}
			}

			sel.HashEffective = sel.Hash
			switch sel.HashEffective {
			case "":
				sel.HashEffective = "sha256"
			case "sha1":
				log.Error("using sha1 with DKIM is deprecated as not secure enough, switch to sha256")
			case "sha256":
			default:
				addSelectorErrorf("unsupported hash %q", sel.HashEffective)
			}

			pemBuf, err := os.ReadFile(configDirPath(dynamicPath, sel.PrivateKeyFile))
			if err != nil {
				addSelectorErrorf("reading private key: %s", err)
				continue
			}
			p, _ := pem.Decode(pemBuf)
			if p == nil {
				addSelectorErrorf("private key has no PEM block")
				continue
			}
			key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
			if err != nil {
				addSelectorErrorf("parsing private key: %s", err)
				continue
			}
			switch k := key.(type) {
			case *rsa.PrivateKey:
				if k.N.BitLen() < 1024 {
					// ../rfc/6376:757
					// Let's help user do the right thing.
					addSelectorErrorf("rsa keys should be >= 1024 bits, is %d bits", k.N.BitLen())
				}
				sel.Key = k
				sel.Algorithm = fmt.Sprintf("rsa-%d", k.N.BitLen())
			case ed25519.PrivateKey:
				if sel.HashEffective != "sha256" {
					addSelectorErrorf("hash algorithm %q is not supported with ed25519, only sha256 is", sel.HashEffective)
				}
				sel.Key = k
				sel.Algorithm = "ed25519"
			default:
				addSelectorErrorf("private key type %T not yet supported", key)
			}

			if len(sel.Headers) == 0 {
				// ../rfc/6376:2139
				// ../rfc/6376:2203
				// ../rfc/6376:2212
				// By default we seal signed headers, and we sign user-visible headers to
				// prevent/limit reuse of previously signed messages: All addressing fields, date
				// and subject, message-referencing fields, parsing instructions (content-type).
				sel.HeadersEffective = strings.Split("From,To,Cc,Bcc,Reply-To,References,In-Reply-To,Subject,Date,Message-Id,Content-Type", ",")
			} else {
				var from bool
				for _, h := range sel.Headers {
					from = from || strings.EqualFold(h, "From")
					// ../rfc/6376:2269
					if strings.EqualFold(h, "DKIM-Signature") || strings.EqualFold(h, "Received") || strings.EqualFold(h, "Return-Path") {
						log.Error("DKIM-signing header %q is recommended against as it may be modified in transit")
					}
				}
				if !from {
					addSelectorErrorf("From-field must always be DKIM-signed")
				}
				sel.HeadersEffective = sel.Headers
			}

			domain.DKIM.Selectors[name] = sel
		}

		if domain.MTASTS != nil {
			if !haveSTSListener {
				addDomainErrorf("MTA-STS enabled, but there is no listener for MTASTS", d)
			}
			sts := domain.MTASTS
			if sts.PolicyID == "" {
				addDomainErrorf("invalid empty MTA-STS PolicyID")
			}
			switch sts.Mode {
			case mtasts.ModeNone, mtasts.ModeTesting, mtasts.ModeEnforce:
			default:
				addDomainErrorf("invalid mtasts mode %q", sts.Mode)
			}
		}

		checkRoutes("routes for domain", domain.Routes)

		c.Domains[d] = domain
	}

	// To determine ReportsOnly.
	domainHasAddress := map[string]bool{}

	// Validate email addresses.
	for accName, acc := range c.Accounts {
		addAccountErrorf := func(format string, args ...any) {
			addErrorf("account %q: %s", accName, fmt.Sprintf(format, args...))
		}

		var err error
		acc.DNSDomain, err = dns.ParseDomain(acc.Domain)
		if err != nil {
			addAccountErrorf("parsing domain %s: %s", acc.Domain, err)
		}

		if strings.EqualFold(acc.RejectsMailbox, "Inbox") {
			addAccountErrorf("cannot set RejectsMailbox to inbox, messages will be removed automatically from the rejects mailbox")
		}
		checkMailboxNormf(acc.RejectsMailbox, "rejects mailbox", addErrorf)

		if len(acc.LoginDisabled) > 256 {
			addAccountErrorf("message for disabled login must be <256 characters")
		}
		for _, c := range acc.LoginDisabled {
			// For IMAP and SMTP. IMAP only allows UTF8 after "ENABLE IMAPrev2".
			if c < ' ' || c >= 0x7f {
				addAccountErrorf("message cannot contain control characters including newlines, and must be ascii-only")
			}
		}

		if acc.AutomaticJunkFlags.JunkMailboxRegexp != "" {
			r, err := regexp.Compile(acc.AutomaticJunkFlags.JunkMailboxRegexp)
			if err != nil {
				addAccountErrorf("invalid JunkMailboxRegexp regular expression: %v", err)
			}
			acc.JunkMailbox = r
		}
		if acc.AutomaticJunkFlags.NeutralMailboxRegexp != "" {
			r, err := regexp.Compile(acc.AutomaticJunkFlags.NeutralMailboxRegexp)
			if err != nil {
				addAccountErrorf("invalid NeutralMailboxRegexp regular expression: %v", err)
			}
			acc.NeutralMailbox = r
		}
		if acc.AutomaticJunkFlags.NotJunkMailboxRegexp != "" {
			r, err := regexp.Compile(acc.AutomaticJunkFlags.NotJunkMailboxRegexp)
			if err != nil {
				addAccountErrorf("invalid NotJunkMailboxRegexp regular expression: %v", err)
			}
			acc.NotJunkMailbox = r
		}

		if acc.JunkFilter != nil {
			params := acc.JunkFilter.Params
			if params.MaxPower < 0 || params.MaxPower > 0.5 {
				addAccountErrorf("junk filter MaxPower must be >= 0 and < 0.5")
			}
			if params.TopWords < 0 {
				addAccountErrorf("junk filter TopWords must be >= 0")
			}
			if params.IgnoreWords < 0 || params.IgnoreWords > 0.5 {
				addAccountErrorf("junk filter IgnoreWords must be >= 0 and < 0.5")
			}
			if params.RareWords < 0 {
				addAccountErrorf("junk filter RareWords must be >= 0")
			}
		}

		acc.ParsedFromIDLoginAddresses = make([]smtp.Address, len(acc.FromIDLoginAddresses))
		for i, s := range acc.FromIDLoginAddresses {
			a, err := smtp.ParseAddress(s)
			if err != nil {
				addAccountErrorf("invalid fromid login address %q: %v", s, err)
			}
			// We check later on if address belongs to account.
			dom, ok := c.Domains[a.Domain.Name()]
			if !ok {
				addAccountErrorf("unknown domain in fromid login address %q", s)
			} else if len(dom.LocalpartCatchallSeparatorsEffective) == 0 {
				addAccountErrorf("localpart catchall separator not configured for domain for fromid login address %q", s)
			}
			acc.ParsedFromIDLoginAddresses[i] = a
		}

		// Clear any previously derived state.
		acc.Aliases = nil

		c.Accounts[accName] = acc

		if acc.OutgoingWebhook != nil {
			u, err := url.Parse(acc.OutgoingWebhook.URL)
			if err == nil && (u.Scheme != "http" && u.Scheme != "https") {
				err = errors.New("scheme must be http or https")
			}
			if err != nil {
				addAccountErrorf("parsing outgoing hook url %q: %v", acc.OutgoingWebhook.URL, err)
			}

			// note: outgoing hook events are in ../queue/hooks.go, ../mox-/config.go, ../queue.go and ../webapi/gendoc.sh. keep in sync.
			outgoingHookEvents := []string{"delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"}
			for _, e := range acc.OutgoingWebhook.Events {
				if !slices.Contains(outgoingHookEvents, e) {
					addAccountErrorf("unknown outgoing hook event %q", e)
				}
			}
		}
		if acc.IncomingWebhook != nil {
			u, err := url.Parse(acc.IncomingWebhook.URL)
			if err == nil && (u.Scheme != "http" && u.Scheme != "https") {
				err = errors.New("scheme must be http or https")
			}
			if err != nil {
				addAccountErrorf("parsing incoming hook url %q: %v", acc.IncomingWebhook.URL, err)
			}
		}

		// todo deprecated: only localpart as keys for Destinations, we are replacing them with full addresses. if domains.conf is written, we won't have to do this again.
		replaceLocalparts := map[string]string{}

		for addrName, dest := range acc.Destinations {
			addDestErrorf := func(format string, args ...any) {
				addAccountErrorf("destination %q: %s", addrName, fmt.Sprintf(format, args...))
			}

			checkMailboxNormf(dest.Mailbox, "destination mailbox", addDestErrorf)

			if dest.SMTPError != "" {
				if len(dest.SMTPError) > 256 {
					addDestErrorf("smtp error must be smaller than 256 bytes")
				}
				for _, c := range dest.SMTPError {
					if c < ' ' || c >= 0x7f {
						addDestErrorf("smtp error cannot contain contain control characters (including newlines) or non-ascii")
						break
					}
				}

				if dest.Mailbox != "" {
					addDestErrorf("cannot have both SMTPError and Mailbox")
				}
				if len(dest.Rulesets) != 0 {
					addDestErrorf("cannot have both SMTPError and Rulesets")
				}

				t := strings.SplitN(dest.SMTPError, " ", 2)
				switch t[0] {
				default:
					addDestErrorf("smtp error must be 421 or 550 (with optional message), not %q", dest.SMTPError)

				case "421":
					dest.SMTPErrorCode = smtp.C451LocalErr
					dest.SMTPErrorSecode = smtp.SeSys3Other0
					dest.SMTPErrorMsg = "error processing"
				case "550":
					dest.SMTPErrorCode = smtp.C550MailboxUnavail
					dest.SMTPErrorSecode = smtp.SeAddr1UnknownDestMailbox1
					dest.SMTPErrorMsg = "no such user(s)"
				}
				if len(t) > 1 {
					dest.SMTPErrorMsg = strings.TrimSpace(t[1])
				}
				acc.Destinations[addrName] = dest
			}

			if dest.MessageAuthRequiredSMTPError != "" {
				if len(dest.MessageAuthRequiredSMTPError) > 256 {
					addDestErrorf("message authentication required smtp error must be smaller than 256 bytes")
				}
				for _, c := range dest.MessageAuthRequiredSMTPError {
					if c < ' ' || c >= 0x7f {
						addDestErrorf("message authentication required smtp error cannot contain contain control characters (including newlines) or non-ascii")
						break
					}
				}
			}

			for i, rs := range dest.Rulesets {
				addRulesetErrorf := func(format string, args ...any) {
					addDestErrorf("ruleset %d: %s", i+1, fmt.Sprintf(format, args...))
				}

				checkMailboxNormf(rs.Mailbox, "ruleset mailbox", addRulesetErrorf)

				n := 0

				if rs.SMTPMailFromRegexp != "" {
					n++
					r, err := regexp.Compile(rs.SMTPMailFromRegexp)
					if err != nil {
						addRulesetErrorf("invalid SMTPMailFrom regular expression: %v", err)
					}
					c.Accounts[accName].Destinations[addrName].Rulesets[i].SMTPMailFromRegexpCompiled = r
				}
				if rs.MsgFromRegexp != "" {
					n++
					r, err := regexp.Compile(rs.MsgFromRegexp)
					if err != nil {
						addRulesetErrorf("invalid MsgFrom regular expression: %v", err)
					}
					c.Accounts[accName].Destinations[addrName].Rulesets[i].MsgFromRegexpCompiled = r
				}
				if rs.VerifiedDomain != "" {
					n++
					d, err := dns.ParseDomain(rs.VerifiedDomain)
					if err != nil {
						addRulesetErrorf("invalid VerifiedDomain: %v", err)
					}
					c.Accounts[accName].Destinations[addrName].Rulesets[i].VerifiedDNSDomain = d
				}

				var hdr [][2]*regexp.Regexp
				for k, v := range rs.HeadersRegexp {
					n++
					if strings.ToLower(k) != k {
						addRulesetErrorf("header field %q must only have lower case characters", k)
					}
					if strings.ToLower(v) != v {
						addRulesetErrorf("header value %q must only have lower case characters", v)
					}
					rk, err := regexp.Compile(k)
					if err != nil {
						addRulesetErrorf("invalid rule header regexp %q: %v", k, err)
					}
					rv, err := regexp.Compile(v)
					if err != nil {
						addRulesetErrorf("invalid rule header regexp %q: %v", v, err)
					}
					hdr = append(hdr, [...]*regexp.Regexp{rk, rv})
				}
				c.Accounts[accName].Destinations[addrName].Rulesets[i].HeadersRegexpCompiled = hdr

				if n == 0 {
					addRulesetErrorf("ruleset must have at least one rule")
				}

				if rs.IsForward && rs.ListAllowDomain != "" {
					addRulesetErrorf("ruleset cannot have both IsForward and ListAllowDomain")
				}
				if rs.IsForward {
					if rs.SMTPMailFromRegexp == "" || rs.VerifiedDomain == "" {
						addRulesetErrorf("ruleset with IsForward must have both SMTPMailFromRegexp and VerifiedDomain too")
					}
				}
				if rs.ListAllowDomain != "" {
					d, err := dns.ParseDomain(rs.ListAllowDomain)
					if err != nil {
						addRulesetErrorf("invalid ListAllowDomain %q: %v", rs.ListAllowDomain, err)
					}
					c.Accounts[accName].Destinations[addrName].Rulesets[i].ListAllowDNSDomain = d
				}

				checkMailboxNormf(rs.AcceptRejectsToMailbox, "rejects mailbox", addRulesetErrorf)
				if strings.EqualFold(rs.AcceptRejectsToMailbox, "inbox") {
					addRulesetErrorf("AcceptRejectsToMailbox cannot be set to Inbox")
				}
			}

			// Catchall destination for domain.
			if strings.HasPrefix(addrName, "@") {
				d, err := dns.ParseDomain(addrName[1:])
				if err != nil {
					addDestErrorf("parsing domain %q", addrName[1:])
					continue
				} else if _, ok := c.Domains[d.Name()]; !ok {
					addDestErrorf("unknown domain for address")
					continue
				}
				domainHasAddress[d.Name()] = true
				addrFull := "@" + d.Name()
				if _, ok := accDests[addrFull]; ok {
					addDestErrorf("duplicate canonicalized catchall destination address %s", addrFull)
				}
				accDests[addrFull] = AccountDestination{true, "", accName, dest}
				continue
			}

			// todo deprecated: remove support for parsing destination as just a localpart instead full address.
			var address smtp.Address
			if localpart, err := smtp.ParseLocalpart(addrName); err != nil && errors.Is(err, smtp.ErrBadLocalpart) {
				address, err = smtp.ParseAddress(addrName)
				if err != nil {
					addDestErrorf("invalid email address")
					continue
				} else if _, ok := c.Domains[address.Domain.Name()]; !ok {
					addDestErrorf("unknown domain for address")
					continue
				}
			} else {
				if err != nil {
					addDestErrorf("invalid localpart %q", addrName)
					continue
				}
				address = smtp.NewAddress(localpart, acc.DNSDomain)
				if _, ok := c.Domains[acc.DNSDomain.Name()]; !ok {
					addDestErrorf("unknown domain %s", acc.DNSDomain.Name())
					continue
				}
				replaceLocalparts[addrName] = address.Pack(true)
			}

			origLP := address.Localpart
			dc := c.Domains[address.Domain.Name()]
			domainHasAddress[address.Domain.Name()] = true
			lp := CanonicalLocalpart(address.Localpart, dc)
			var hasSep bool
			for _, sep := range dc.LocalpartCatchallSeparatorsEffective {
				if strings.Contains(string(address.Localpart), sep) {
					hasSep = true
					addDestErrorf("localpart of address %s includes domain catchall separator %s", address, sep)
				}
			}
			if !hasSep {
				address.Localpart = lp
			}
			addrFull := address.Pack(true)
			if _, ok := accDests[addrFull]; ok {
				addDestErrorf("duplicate canonicalized destination address %s", addrFull)
			}
			accDests[addrFull] = AccountDestination{false, origLP, accName, dest}
		}

		for lp, addr := range replaceLocalparts {
			dest, ok := acc.Destinations[lp]
			if !ok {
				addAccountErrorf("could not find localpart %q to replace with address in destinations", lp)
			} else {
				log.Warn(`deprecation warning: support for account destination addresses specified as just localpart ("username") instead of full email address will be removed in the future; update domains.conf, for each Account, for each Destination, ensure each key is an email address by appending "@" and the default domain for the account`,
					slog.Any("localpart", lp),
					slog.Any("address", addr),
					slog.String("account", accName))
				acc.Destinations[addr] = dest
				delete(acc.Destinations, lp)
			}
		}

		// Now that all addresses are parsed, check if all fromid login addresses match
		// configured addresses.
		for i, a := range acc.ParsedFromIDLoginAddresses {
			// For domain catchall.
			if _, ok := accDests["@"+a.Domain.Name()]; ok {
				continue
			}
			dc := c.Domains[a.Domain.Name()]
			a.Localpart = CanonicalLocalpart(a.Localpart, dc)
			if _, ok := accDests[a.Pack(true)]; !ok {
				addAccountErrorf("fromid login address %q does not match its destination addresses", acc.FromIDLoginAddresses[i])
			}
		}

		checkRoutes("routes for account", acc.Routes)
	}

	// Set DMARC destinations.
	for d, domain := range c.Domains {
		addDomainErrorf := func(format string, args ...any) {
			addErrorf("domain %s: %s", d, fmt.Sprintf(format, args...))
		}

		dmarc := domain.DMARC
		if dmarc == nil {
			continue
		}
		if _, ok := c.Accounts[dmarc.Account]; !ok {
			addDomainErrorf("DMARC account %q does not exist", dmarc.Account)
		}

		// Note: For backwards compabilitiy, DMARC reporting localparts can contain catchall separators.
		lp, err := smtp.ParseLocalpart(dmarc.Localpart)
		if err != nil {
			addDomainErrorf("invalid DMARC localpart %q: %s", dmarc.Localpart, err)
		}
		if lp.IsInternational() {
			// ../rfc/8616:234
			addDomainErrorf("DMARC localpart %q is an internationalized address, only conventional ascii-only address possible for interopability", lp)
		}
		addrdom := domain.Domain
		if dmarc.Domain != "" {
			addrdom, err = dns.ParseDomain(dmarc.Domain)
			if err != nil {
				addDomainErrorf("DMARC domain %q: %s", dmarc.Domain, err)
			} else if adomain, ok := c.Domains[addrdom.Name()]; !ok {
				addDomainErrorf("unknown domain %q for DMARC address", addrdom)
			} else if !adomain.LocalpartCaseSensitive {
				lp = smtp.Localpart(strings.ToLower(string(lp)))
			}
		} else if !domain.LocalpartCaseSensitive {
			lp = smtp.Localpart(strings.ToLower(string(lp)))
		}
		if addrdom == domain.Domain {
			domainHasAddress[addrdom.Name()] = true
		}

		domain.DMARC.ParsedLocalpart = lp
		domain.DMARC.DNSDomain = addrdom
		c.Domains[d] = domain
		addrFull := smtp.NewAddress(lp, addrdom).String()
		dest := config.Destination{
			Mailbox:      dmarc.Mailbox,
			DMARCReports: true,
		}
		checkMailboxNormf(dmarc.Mailbox, "DMARC mailbox for account", addDomainErrorf)
		accDests[addrFull] = AccountDestination{false, lp, dmarc.Account, dest}
	}

	// Set TLSRPT destinations.
	for d, domain := range c.Domains {
		addDomainErrorf := func(format string, args ...any) {
			addErrorf("domain %s: %s", d, fmt.Sprintf(format, args...))
		}

		tlsrpt := domain.TLSRPT
		if tlsrpt == nil {
			continue
		}
		if _, ok := c.Accounts[tlsrpt.Account]; !ok {
			addDomainErrorf("TLSRPT account %q does not exist", tlsrpt.Account)
		}

		// Note: For backwards compabilitiy, TLS reporting localparts can contain catchall separators.
		lp, err := smtp.ParseLocalpart(tlsrpt.Localpart)
		if err != nil {
			addDomainErrorf("invalid TLSRPT localpart %q: %s", tlsrpt.Localpart, err)
		}
		if lp.IsInternational() {
			// Does not appear documented in ../rfc/8460, but similar to DMARC it makes sense
			// to keep this ascii-only addresses.
			addDomainErrorf("TLSRPT localpart %q is an internationalized address, only conventional ascii-only address allowed for interopability", lp)
		}
		addrdom := domain.Domain
		if tlsrpt.Domain != "" {
			addrdom, err = dns.ParseDomain(tlsrpt.Domain)
			if err != nil {
				addDomainErrorf("TLSRPT domain %q: %s", tlsrpt.Domain, err)
			} else if adomain, ok := c.Domains[addrdom.Name()]; !ok {
				addDomainErrorf("unknown domain %q for TLSRPT address", tlsrpt.Domain)
			} else if !adomain.LocalpartCaseSensitive {
				lp = smtp.Localpart(strings.ToLower(string(lp)))
			}
		} else if !domain.LocalpartCaseSensitive {
			lp = smtp.Localpart(strings.ToLower(string(lp)))
		}
		if addrdom == domain.Domain {
			domainHasAddress[addrdom.Name()] = true
		}

		domain.TLSRPT.ParsedLocalpart = lp
		domain.TLSRPT.DNSDomain = addrdom
		c.Domains[d] = domain
		addrFull := smtp.NewAddress(lp, addrdom).String()
		dest := config.Destination{
			Mailbox:          tlsrpt.Mailbox,
			DomainTLSReports: true,
		}
		checkMailboxNormf(tlsrpt.Mailbox, "TLSRPT mailbox", addDomainErrorf)
		accDests[addrFull] = AccountDestination{false, lp, tlsrpt.Account, dest}
	}

	// Set ReportsOnly for domains, based on whether we have seen addresses (possibly
	// from DMARC or TLS reporting).
	for d, domain := range c.Domains {
		domain.ReportsOnly = !domainHasAddress[domain.Domain.Name()]
		c.Domains[d] = domain
	}

	// Aliases, per domain. Also add references to accounts.
	for d, domain := range c.Domains {
		for lpstr, a := range domain.Aliases {
			addAliasErrorf := func(format string, args ...any) {
				addErrorf("domain %s: alias %s: %s", d, lpstr, fmt.Sprintf(format, args...))
			}

			var err error
			a.LocalpartStr = lpstr
			var clp smtp.Localpart
			lp, err := smtp.ParseLocalpart(lpstr)
			if err != nil {
				addAliasErrorf("parsing alias: %v", err)
				continue
			} else {
				var hasSep bool
				for _, sep := range domain.LocalpartCatchallSeparatorsEffective {
					if strings.Contains(string(lp), sep) {
						addAliasErrorf("alias contains localpart catchall separator")
						hasSep = true
					}
				}
				if hasSep {
					continue
				}
				clp = CanonicalLocalpart(lp, domain)
			}

			addr := smtp.NewAddress(clp, domain.Domain).Pack(true)
			if _, ok := aliases[addr]; ok {
				addAliasErrorf("duplicate alias address %q", addr)
				continue
			}
			if _, ok := accDests[addr]; ok {
				addAliasErrorf("alias %q already present as regular address", addr)
				continue
			}
			if len(a.Addresses) == 0 {
				// Not currently possible, Addresses isn't optional.
				addAliasErrorf("alias %q needs at least one destination address", addr)
				continue
			}
			a.ParsedAddresses = make([]config.AliasAddress, 0, len(a.Addresses))
			seen := map[string]bool{}
			for _, destAddr := range a.Addresses {
				da, err := smtp.ParseAddress(destAddr)
				if err != nil {
					addAliasErrorf("parsing destination address %q: %v", destAddr, err)
					continue
				}
				dastr := da.Pack(true)
				accDest, ok := accDests[dastr]
				if !ok {
					addAliasErrorf("references non-existent address %q", destAddr)
					continue
				}
				if seen[dastr] {
					addAliasErrorf("duplicate address %q", destAddr)
					continue
				}
				seen[dastr] = true
				aa := config.AliasAddress{Address: da, AccountName: accDest.Account, Destination: accDest.Destination}
				a.ParsedAddresses = append(a.ParsedAddresses, aa)
			}
			a.Domain = domain.Domain
			c.Domains[d].Aliases[lpstr] = a
			aliases[addr] = a

			for _, aa := range a.ParsedAddresses {
				acc := c.Accounts[aa.AccountName]
				var addrs []string
				if a.ListMembers {
					addrs = make([]string, len(a.ParsedAddresses))
					for i := range a.ParsedAddresses {
						addrs[i] = a.ParsedAddresses[i].Address.Pack(true)
					}
				}
				// Keep the non-sensitive fields.
				accAlias := config.Alias{
					PostPublic:   a.PostPublic,
					ListMembers:  a.ListMembers,
					AllowMsgFrom: a.AllowMsgFrom,
					LocalpartStr: a.LocalpartStr,
					Domain:       a.Domain,
				}
				acc.Aliases = append(acc.Aliases, config.AddressAlias{SubscriptionAddress: aa.Address.Pack(true), Alias: accAlias, MemberAddresses: addrs})
				c.Accounts[aa.AccountName] = acc
			}
		}
	}

	// Check webserver configs.
	if (len(c.WebDomainRedirects) > 0 || len(c.WebHandlers) > 0) && !haveWebserverListener {
		addErrorf("WebDomainRedirects or WebHandlers configured but no listener with WebserverHTTP or WebserverHTTPS enabled")
	}

	c.WebDNSDomainRedirects = map[dns.Domain]dns.Domain{}
	for from, to := range c.WebDomainRedirects {
		addRedirectErrorf := func(format string, args ...any) {
			addErrorf("web redirect %s to %s: %s", from, to, fmt.Sprintf(format, args...))
		}

		fromdom, err := dns.ParseDomain(from)
		if err != nil {
			addRedirectErrorf("parsing domain for redirect %s: %v", from, err)
		}
		todom, err := dns.ParseDomain(to)
		if err != nil {
			addRedirectErrorf("parsing domain for redirect %s: %v", to, err)
		} else if fromdom == todom {
			addRedirectErrorf("will not redirect domain %s to itself", todom)
		}
		var zerodom dns.Domain
		if _, ok := c.WebDNSDomainRedirects[fromdom]; ok && fromdom != zerodom {
			addRedirectErrorf("duplicate redirect domain %s", from)
		}
		c.WebDNSDomainRedirects[fromdom] = todom
	}

	for i := range c.WebHandlers {
		wh := &c.WebHandlers[i]

		addHandlerErrorf := func(format string, args ...any) {
			addErrorf("webhandler %s %s: %s", wh.Domain, wh.PathRegexp, fmt.Sprintf(format, args...))
		}

		if wh.LogName == "" {
			wh.Name = fmt.Sprintf("%d", i)
		} else {
			wh.Name = wh.LogName
		}

		dom, err := dns.ParseDomain(wh.Domain)
		if err != nil {
			addHandlerErrorf("parsing domain: %v", err)
		}
		wh.DNSDomain = dom

		if !strings.HasPrefix(wh.PathRegexp, "^") {
			addHandlerErrorf("path regexp must start with a ^")
		}
		re, err := regexp.Compile(wh.PathRegexp)
		if err != nil {
			addHandlerErrorf("compiling regexp: %v", err)
		}
		wh.Path = re

		var n int
		if wh.WebStatic != nil {
			n++
			ws := wh.WebStatic
			if ws.StripPrefix != "" && !strings.HasPrefix(ws.StripPrefix, "/") {
				addHandlerErrorf("static: prefix to strip %s must start with a slash", ws.StripPrefix)
			}
			for k := range ws.ResponseHeaders {
				xk := k
				k := strings.TrimSpace(xk)
				if k != xk || k == "" {
					addHandlerErrorf("static: bad header %q", xk)
				}
			}
		}
		if wh.WebRedirect != nil {
			n++
			wr := wh.WebRedirect
			if wr.BaseURL != "" {
				u, err := url.Parse(wr.BaseURL)
				if err != nil {
					addHandlerErrorf("redirect: parsing redirect url %s: %v", wr.BaseURL, err)
				}
				switch u.Path {
				case "", "/":
					u.Path = "/"
				default:
					addHandlerErrorf("redirect: BaseURL must have empty path", wr.BaseURL)
				}
				wr.URL = u
			}
			if wr.OrigPathRegexp != "" && wr.ReplacePath != "" {
				re, err := regexp.Compile(wr.OrigPathRegexp)
				if err != nil {
					addHandlerErrorf("compiling regexp %s: %v", wr.OrigPathRegexp, err)
				}
				wr.OrigPath = re
			} else if wr.OrigPathRegexp != "" || wr.ReplacePath != "" {
				addHandlerErrorf("redirect: must have either both OrigPathRegexp and ReplacePath, or neither")
			} else if wr.BaseURL == "" {
				addHandlerErrorf("must at least one of BaseURL and OrigPathRegexp+ReplacePath")
			}
			if wr.StatusCode != 0 && (wr.StatusCode < 300 || wr.StatusCode >= 400) {
				addHandlerErrorf("redirect: invalid redirect status code %d", wr.StatusCode)
			}
		}
		if wh.WebForward != nil {
			n++
			wf := wh.WebForward
			u, err := url.Parse(wf.URL)
			if err != nil {
				addHandlerErrorf("forward: parsing url %s: %v", wf.URL, err)
			}
			wf.TargetURL = u

			for k := range wf.ResponseHeaders {
				xk := k
				k := strings.TrimSpace(xk)
				if k != xk || k == "" {
					addHandlerErrorf("forrward: bad header %q", xk)
				}
			}
		}
		if wh.WebInternal != nil {
			n++
			wi := wh.WebInternal
			if !strings.HasPrefix(wi.BasePath, "/") || !strings.HasSuffix(wi.BasePath, "/") {
				addHandlerErrorf("internal service: base path %q must start and end with /", wi.BasePath)
			}
			// todo: we could make maxMsgSize and accountPath configurable
			const isForwarded = false
			switch wi.Service {
			case "admin":
				wi.Handler = NewWebadminHandler(wi.BasePath, isForwarded)
			case "account":
				wi.Handler = NewWebaccountHandler(wi.BasePath, isForwarded)
			case "webmail":
				accountPath := ""
				wi.Handler = NewWebmailHandler(config.DefaultMaxMsgSize, wi.BasePath, isForwarded, accountPath)
			case "webapi":
				wi.Handler = NewWebapiHandler(config.DefaultMaxMsgSize, wi.BasePath, isForwarded)
			default:
				addHandlerErrorf("internal service: unknown service %q", wi.Service)
			}
			wi.Handler = SafeHeaders(http.StripPrefix(wi.BasePath[:len(wi.BasePath)-1], wi.Handler))
		}
		if n != 1 {
			addHandlerErrorf("must have exactly one handler, not %d", n)
		}
	}

	c.MonitorDNSBLZones = nil
	for _, s := range c.MonitorDNSBLs {
		d, err := dns.ParseDomain(s)
		if err != nil {
			addErrorf("dnsbl %s: parsing dnsbl zone: %v", s, err)
			continue
		}
		if slices.Contains(c.MonitorDNSBLZones, d) {
			addErrorf("dnsbl %s: duplicate zone", s)
			continue
		}
		c.MonitorDNSBLZones = append(c.MonitorDNSBLZones, d)
	}

	return
}

func loadPrivateKeyFile(keyPath string) (crypto.Signer, error) {
	keyBuf, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading host private key: %v", err)
	}
	b, _ := pem.Decode(keyBuf)
	if b == nil {
		return nil, fmt.Errorf("parsing pem block for private key: %v", err)
	}
	var privKey any
	switch b.Type {
	case "PRIVATE KEY":
		privKey, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		err = fmt.Errorf("unknown pem type %q", b.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %v", err)
	}
	if k, ok := privKey.(crypto.Signer); ok {
		return k, nil
	}
	return nil, fmt.Errorf("parsed private key not a crypto.Signer, but %T", privKey)
}

func loadTLSKeyCerts(configFile, kind string, ctls *config.TLS) error {
	certs := []tls.Certificate{}
	for _, kp := range ctls.KeyCerts {
		certPath := configDirPath(configFile, kp.CertFile)
		keyPath := configDirPath(configFile, kp.KeyFile)
		cert, err := loadX509KeyPairPrivileged(certPath, keyPath)
		if err != nil {
			return fmt.Errorf("tls config for %q: parsing x509 key pair: %v", kind, err)
		}
		certs = append(certs, cert)
	}
	ctls.Config = &tls.Config{
		Certificates: certs,
	}
	ctls.ConfigFallback = ctls.Config
	return nil
}

// load x509 key/cert files from file descriptor possibly passed in by privileged
// process.
func loadX509KeyPairPrivileged(certPath, keyPath string) (tls.Certificate, error) {
	certBuf, err := readFilePrivileged(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading tls certificate: %v", err)
	}
	keyBuf, err := readFilePrivileged(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading tls key: %v", err)
	}
	return tls.X509KeyPair(certBuf, keyBuf)
}

// like os.ReadFile, but open privileged file possibly passed in by root process.
func readFilePrivileged(path string) ([]byte, error) {
	f, err := OpenPrivileged(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
