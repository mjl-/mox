package mox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/smtp"
)

var xlog = mlog.New("mox")

// Config paths are set early in program startup. They will point to files in
// the same directory.
var (
	ConfigStaticPath  string
	ConfigDynamicPath string
	Conf              = Config{Log: map[string]mlog.Level{"": mlog.LevelError}}
)

// Config as used in the code, a processed version of what is in the config file.
//
// Use methods to lookup a domain/account/address in the dynamic configuration.
type Config struct {
	Static config.Static // Does not change during the lifetime of a running instance.

	logMutex sync.Mutex // For accessing the log levels.
	Log      map[string]mlog.Level

	dynamicMutex     sync.Mutex
	Dynamic          config.Dynamic // Can only be accessed directly by tests. Use methods on Config for locked access.
	dynamicMtime     time.Time
	DynamicLastCheck time.Time // For use by quickstart only to skip checks.
	// From canonical full address (localpart@domain, lower-cased when
	// case-insensitive, stripped of catchall separator) to account and address.
	// Domains are IDNA names in utf8.
	accountDestinations map[string]AccountDestination
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
func (c *Config) LogLevelSet(pkg string, level mlog.Level) {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	l := c.copyLogLevels()
	l[pkg] = level
	c.Log = l
	xlog.Print("log level changed", mlog.Field("pkg", pkg), mlog.Field("level", mlog.LevelStrings[level]))
	mlog.SetConfig(c.Log)
}

// LogLevelRemove removes a configured log level for a package.
func (c *Config) LogLevelRemove(pkg string) {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	l := c.copyLogLevels()
	delete(l, pkg)
	c.Log = l
	xlog.Print("log level cleared", mlog.Field("pkg", pkg))
	mlog.SetConfig(c.Log)
}

// copyLogLevels returns a copy of c.Log, for modifications.
// must be called with log lock held.
func (c *Config) copyLogLevels() map[string]mlog.Level {
	m := map[string]mlog.Level{}
	for pkg, level := range c.Log {
		m[pkg] = level
	}
	return m
}

// LogLevels returns a copy of the current log levels.
func (c *Config) LogLevels() map[string]mlog.Level {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	return c.copyLogLevels()
}

func (c *Config) withDynamicLock(fn func()) {
	c.dynamicMutex.Lock()
	defer c.dynamicMutex.Unlock()
	now := time.Now()
	if now.Sub(c.DynamicLastCheck) > time.Second {
		c.DynamicLastCheck = now
		if fi, err := os.Stat(ConfigDynamicPath); err != nil {
			xlog.Errorx("stat domains config", err)
		} else if !fi.ModTime().Equal(c.dynamicMtime) {
			if errs := c.loadDynamic(); len(errs) > 0 {
				xlog.Errorx("loading domains config", errs[0], mlog.Field("errors", errs))
			} else {
				xlog.Info("domains config reloaded")
				c.dynamicMtime = fi.ModTime()
			}
		}
	}
	fn()
}

// must be called with dynamic lock held.
func (c *Config) loadDynamic() []error {
	d, mtime, accDests, err := ParseDynamicConfig(context.Background(), ConfigDynamicPath, c.Static)
	if err != nil {
		return err
	}
	c.Dynamic = d
	c.dynamicMtime = mtime
	c.accountDestinations = accDests
	c.allowACMEHosts(true)
	return nil
}

func (c *Config) Domains() (l []string) {
	c.withDynamicLock(func() {
		for name := range c.Dynamic.Domains {
			l = append(l, name)
		}
	})
	sort.Slice(l, func(i, j int) bool {
		return l[i] < l[j]
	})
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

// DomainLocalparts returns a mapping of encoded localparts to account names for a
// domain. An empty localpart is a catchall destination for a domain.
func (c *Config) DomainLocalparts(d dns.Domain) map[string]string {
	suffix := "@" + d.Name()
	m := map[string]string{}
	c.withDynamicLock(func() {
		for addr, ad := range c.accountDestinations {
			if strings.HasSuffix(addr, suffix) {
				if ad.Catchall {
					m[""] = ad.Account
				} else {
					m[ad.Localpart.String()] = ad.Account
				}
			}
		}
	})
	return m
}

func (c *Config) Domain(d dns.Domain) (dom config.Domain, ok bool) {
	c.withDynamicLock(func() {
		dom, ok = c.Dynamic.Domains[d.Name()]
	})
	return
}

func (c *Config) Account(name string) (acc config.Account, ok bool) {
	c.withDynamicLock(func() {
		acc, ok = c.Dynamic.Accounts[name]
	})
	return
}

func (c *Config) AccountDestination(addr string) (accDests AccountDestination, ok bool) {
	c.withDynamicLock(func() {
		accDests, ok = c.accountDestinations[addr]
	})
	return
}

func (c *Config) WebServer() (r map[dns.Domain]dns.Domain, l []config.WebHandler) {
	c.withDynamicLock(func() {
		r = c.Dynamic.WebDNSDomainRedirects
		l = c.Dynamic.WebHandlers
	})
	return r, l
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

func (c *Config) allowACMEHosts(checkACMEHosts bool) {
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
			if l.AutoconfigHTTPS.Enabled && !l.AutoconfigHTTPS.NonTLS {
				if d, err := dns.ParseDomain("autoconfig." + dom.Domain.ASCII); err != nil {
					xlog.Errorx("parsing autoconfig domain", err, mlog.Field("domain", dom.Domain))
				} else {
					hostnames[d] = struct{}{}
				}
			}

			if l.MTASTSHTTPS.Enabled && dom.MTASTS != nil && !l.MTASTSHTTPS.NonTLS {
				d, err := dns.ParseDomain("mta-sts." + dom.Domain.ASCII)
				if err != nil {
					xlog.Errorx("parsing mta-sts domain", err, mlog.Field("domain", dom.Domain))
				} else {
					hostnames[d] = struct{}{}
				}
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
		m.SetAllowedHostnames(dns.StrictResolver{Pkg: "autotls"}, hostnames, ips, checkACMEHosts)
	}
}

// todo future: write config parsing & writing code that can read a config and remembers the exact tokens including newlines and comments, and can write back a modified file. the goal is to be able to write a config file automatically (after changing fields through the ui), but not loose comments and whitespace, to still get useful diffs for storing the config in a version control system.

// must be called with lock held.
func writeDynamic(ctx context.Context, log *mlog.Log, c config.Dynamic) error {
	accDests, errs := prepareDynamicConfig(ctx, ConfigDynamicPath, Conf.Static, &c)
	if len(errs) > 0 {
		return errs[0]
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
	if err := moxio.SyncDir(filepath.Dir(ConfigDynamicPath)); err != nil {
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
	Conf.accountDestinations = accDests

	Conf.allowACMEHosts(true)

	return nil
}

// MustLoadConfig loads the config, quitting on errors.
func MustLoadConfig(doLoadTLSKeyCerts, checkACMEHosts bool) {
	errs := LoadConfig(context.Background(), doLoadTLSKeyCerts, checkACMEHosts)
	if len(errs) > 1 {
		xlog.Error("loading config file: multiple errors")
		for _, err := range errs {
			xlog.Errorx("config error", err)
		}
		xlog.Fatal("stopping after multiple config errors")
	} else if len(errs) == 1 {
		xlog.Fatalx("loading config file", errs[0])
	}
}

// LoadConfig attempts to parse and load a config, returning any errors
// encountered.
func LoadConfig(ctx context.Context, doLoadTLSKeyCerts, checkACMEHosts bool) []error {
	Shutdown, ShutdownCancel = context.WithCancel(context.Background())
	Context, ContextCancel = context.WithCancel(context.Background())

	c, errs := ParseConfig(ctx, ConfigStaticPath, false, doLoadTLSKeyCerts, checkACMEHosts)
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
	Conf = Config{c.Static, sync.Mutex{}, c.Log, sync.Mutex{}, c.Dynamic, c.dynamicMtime, c.DynamicLastCheck, c.accountDestinations}

	// If we have non-standard CA roots, use them for all HTTPS requests.
	if Conf.Static.TLS.CertPool != nil {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
			RootCAs: Conf.Static.TLS.CertPool,
		}
	}

	moxvar.Pedantic = c.Static.Pedantic
}

// ParseConfig parses the static config at path p. If checkOnly is true, no changes
// are made, such as registering ACME identities. If doLoadTLSKeyCerts is true,
// the TLS KeyCerts configuration is loaded and checked. This is used during the
// quickstart in the case the user is going to provide their own certificates.
// If checkACMEHosts is true, the hosts allowed for acme are compared with the
// explicitly configured ips we are listening on.
func ParseConfig(ctx context.Context, p string, checkOnly, doLoadTLSKeyCerts, checkACMEHosts bool) (c *Config, errs []error) {
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

	if xerrs := PrepareStaticConfig(ctx, p, c, checkOnly, doLoadTLSKeyCerts); len(xerrs) > 0 {
		return nil, xerrs
	}

	pp := filepath.Join(filepath.Dir(p), "domains.conf")
	c.Dynamic, c.dynamicMtime, c.accountDestinations, errs = ParseDynamicConfig(ctx, pp, c.Static)

	if !checkOnly {
		c.allowACMEHosts(checkACMEHosts)
	}

	return c, errs
}

// PrepareStaticConfig parses the static config file and prepares data structures
// for starting mox. If checkOnly is set no substantial changes are made, like
// creating an ACME registration.
func PrepareStaticConfig(ctx context.Context, configFile string, conf *Config, checkOnly, doLoadTLSKeyCerts bool) (errs []error) {
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
		conf.Log = map[string]mlog.Level{"": logLevel}
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
	var userErr user.UnknownUserError
	if err != nil && errors.As(err, &userErr) {
		uid, err := strconv.ParseUint(c.User, 10, 32)
		if err != nil {
			addErrorf("parsing unknown user %s as uid: %v (hint: add user mox with \"useradd -d $PWD mox\" or specify a different username on the quickstart command-line)", c.User, err)
		} else {
			// We assume the same gid as uid.
			c.UID = uint32(uid)
			c.GID = uint32(uid)
		}
	} else if err != nil {
		addErrorf("looking up user: %v", err)
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
		addErrorf("hostname must be in IDNA form %q", hostname.Name())
	}
	c.HostnameDomain = hostname

	for name, acme := range c.ACME {
		if checkOnly {
			continue
		}
		acmeDir := dataDirPath(configFile, c.DataDir, "acme")
		os.MkdirAll(acmeDir, 0770)
		manager, err := autotls.Load(name, acmeDir, acme.ContactEmail, acme.DirectoryURL, Shutdown.Done())
		if err != nil {
			addErrorf("loading ACME identity for %q: %s", name, err)
		}
		acme.Manager = manager
		c.ACME[name] = acme
	}

	var haveUnspecifiedSMTPListener bool
	for name, l := range c.Listeners {
		if l.Hostname != "" {
			d, err := dns.ParseDomain(l.Hostname)
			if err != nil {
				addErrorf("bad listener hostname %q: %s", l.Hostname, err)
			}
			l.HostnameDomain = d
		}
		if l.TLS != nil {
			if l.TLS.ACME != "" && len(l.TLS.KeyCerts) != 0 {
				addErrorf("listener %q: cannot have ACME and static key/certificates", name)
			} else if l.TLS.ACME != "" {
				acme, ok := c.ACME[l.TLS.ACME]
				if !ok {
					addErrorf("listener %q: unknown ACME provider %q", name, l.TLS.ACME)
				}

				// If only checking or with missing ACME definition, we don't have an acme manager,
				// so set an empty tls config to continue.
				var tlsconfig *tls.Config
				if checkOnly || acme.Manager == nil {
					tlsconfig = &tls.Config{}
				} else {
					tlsconfig = acme.Manager.TLSConfig.Clone()
					l.TLS.ACMEConfig = acme.Manager.ACMETLSConfig

					// SMTP STARTTLS connections are commonly made without SNI, because certificates
					// often aren't validated.
					hostname := c.HostnameDomain
					if l.Hostname != "" {
						hostname = l.HostnameDomain
					}
					getCert := tlsconfig.GetCertificate
					tlsconfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
						if hello.ServerName == "" {
							hello.ServerName = hostname.ASCII
						}
						return getCert(hello)
					}
				}
				l.TLS.Config = tlsconfig
			} else if len(l.TLS.KeyCerts) != 0 {
				if doLoadTLSKeyCerts {
					if err := loadTLSKeyCerts(configFile, "listener "+name, l.TLS); err != nil {
						addErrorf("%w", err)
					}
				}
			} else {
				addErrorf("listener %q: cannot have TLS config without ACME and without static keys/certificates", name)
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
					addErrorf("listener %q: unknown TLS mininum version %q", name, l.TLS.MinVersion)
				}
				minVersion = v
			}
			if l.TLS.Config != nil {
				l.TLS.Config.MinVersion = minVersion
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
				addErrorf("listener %q does not specify tls config, but requires tls for %s", name, strings.Join(needsTLS, ", "))
			}
		}
		if l.AutoconfigHTTPS.Enabled && l.MTASTSHTTPS.Enabled && l.AutoconfigHTTPS.Port == l.MTASTSHTTPS.Port && l.AutoconfigHTTPS.NonTLS != l.MTASTSHTTPS.NonTLS {
			addErrorf("listener %q tries to enable autoconfig and mta-sts enabled on same port but with both http and https", name)
		}
		if l.SMTP.Enabled {
			if len(l.IPs) == 0 {
				haveUnspecifiedSMTPListener = true
			}
			for _, ipstr := range l.IPs {
				ip := net.ParseIP(ipstr)
				if ip == nil {
					addErrorf("listener %q has invalid IP %q", name, ipstr)
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
				addErrorf("listener %q has invalid DNSBL zone %q", name, s)
				continue
			}
			l.SMTP.DNSBLZones = append(l.SMTP.DNSBLZones, d)
		}
		if l.IPsNATed && len(l.NATIPs) > 0 {
			addErrorf("listener %q has both IPsNATed and NATIPs (remove deprecated IPsNATed)", name)
		}
		for _, ipstr := range l.NATIPs {
			ip := net.ParseIP(ipstr)
			if ip == nil {
				addErrorf("listener %q has invalid ip %q", name, ipstr)
			} else if ip.IsUnspecified() || ip.IsLoopback() {
				addErrorf("listener %q has NAT ip that is the unspecified or loopback address %s", name, ipstr)
			}
		}
		checkPath := func(kind string, enabled bool, path string) {
			if enabled && path != "" && !strings.HasPrefix(path, "/") {
				addErrorf("listener %q has %s with path %q that must start with a slash", name, kind, path)
			}
		}
		checkPath("AccountHTTP", l.AccountHTTP.Enabled, l.AccountHTTP.Path)
		checkPath("AccountHTTPS", l.AccountHTTPS.Enabled, l.AccountHTTPS.Path)
		checkPath("AdminHTTP", l.AdminHTTP.Enabled, l.AdminHTTP.Path)
		checkPath("AdminHTTPS", l.AdminHTTPS.Enabled, l.AdminHTTPS.Path)
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
	}
	checkSpecialUseMailbox := func(nameOpt string) {
		if nameOpt != "" {
			checkMailboxNormf(nameOpt, "special-use initial mailbox")
			if strings.EqualFold(nameOpt, "inbox") {
				addErrorf("initial mailbox cannot be set to Inbox (Inbox is always created)")
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
	}

	checkTransportSMTP := func(name string, isTLS bool, t *config.TransportSMTP) {
		var err error
		t.DNSHost, err = dns.ParseDomain(t.Host)
		if err != nil {
			addErrorf("transport %s: bad host %s: %v", name, t.Host, err)
		}

		if isTLS && t.STARTTLSInsecureSkipVerify {
			addErrorf("transport %s: cannot have STARTTLSInsecureSkipVerify with immediate TLS")
		}
		if isTLS && t.NoSTARTTLS {
			addErrorf("transport %s: cannot have NoSTARTTLS with immediate TLS")
		}

		if t.Auth == nil {
			return
		}
		seen := map[string]bool{}
		for _, m := range t.Auth.Mechanisms {
			if seen[m] {
				addErrorf("transport %s: duplicate authentication mechanism %s", name, m)
			}
			seen[m] = true
			switch m {
			case "SCRAM-SHA-256":
			case "SCRAM-SHA-1":
			case "CRAM-MD5":
			case "PLAIN":
			default:
				addErrorf("transport %s: unknown authentication mechanism %s", name, m)
			}
		}

		t.Auth.EffectiveMechanisms = t.Auth.Mechanisms
		if len(t.Auth.EffectiveMechanisms) == 0 {
			t.Auth.EffectiveMechanisms = []string{"SCRAM-SHA-256", "SCRAM-SHA-1", "CRAM-MD5"}
		}
	}

	checkTransportSocks := func(name string, t *config.TransportSocks) {
		_, _, err := net.SplitHostPort(t.Address)
		if err != nil {
			addErrorf("transport %s: bad address %s: %v", name, t.Address, err)
		}
		for _, ipstr := range t.RemoteIPs {
			ip := net.ParseIP(ipstr)
			if ip == nil {
				addErrorf("transport %s: bad ip %s", name, ipstr)
			} else {
				t.IPs = append(t.IPs, ip)
			}
		}
		t.Hostname, err = dns.ParseDomain(t.RemoteHostname)
		if err != nil {
			addErrorf("transport %s: bad hostname %s: %v", name, t.RemoteHostname, err)
		}
	}

	for name, t := range c.Transports {
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
		if n > 1 {
			addErrorf("transport %s: cannot have multiple methods in a transport", name)
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
func ParseDynamicConfig(ctx context.Context, dynamicPath string, static config.Static) (c config.Dynamic, mtime time.Time, accDests map[string]AccountDestination, errs []error) {
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

	accDests, errs = prepareDynamicConfig(ctx, dynamicPath, static, &c)
	return c, fi.ModTime(), accDests, errs
}

func prepareDynamicConfig(ctx context.Context, dynamicPath string, static config.Static, c *config.Dynamic) (accDests map[string]AccountDestination, errs []error) {
	log := xlog.WithContext(ctx)

	addErrorf := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	// Check that mailbox is in unicode NFC normalized form.
	checkMailboxNormf := func(mailbox string, format string, args ...any) {
		s := norm.NFC.String(mailbox)
		if mailbox != s {
			msg := fmt.Sprintf(format, args...)
			addErrorf("%s: mailbox %q is not in NFC normalized form, should be %q", msg, mailbox, s)
		}
	}

	// Validate postmaster account exists.
	if _, ok := c.Accounts[static.Postmaster.Account]; !ok {
		addErrorf("postmaster account %q does not exist", static.Postmaster.Account)
	}
	checkMailboxNormf(static.Postmaster.Mailbox, "postmaster mailbox")

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
	for d, domain := range c.Domains {
		dnsdomain, err := dns.ParseDomain(d)
		if err != nil {
			addErrorf("bad domain %q: %s", d, err)
		} else if dnsdomain.Name() != d {
			addErrorf("domain %s must be specified in IDNA form, %s", d, dnsdomain.Name())
		}

		domain.Domain = dnsdomain

		for _, sign := range domain.DKIM.Sign {
			if _, ok := domain.DKIM.Selectors[sign]; !ok {
				addErrorf("selector %s for signing is missing in domain %s", sign, d)
			}
		}
		for name, sel := range domain.DKIM.Selectors {
			seld, err := dns.ParseDomain(name)
			if err != nil {
				addErrorf("bad selector %q: %s", name, err)
			} else if seld.Name() != name {
				addErrorf("selector %q must be specified in IDNA form, %q", name, seld.Name())
			}
			sel.Domain = seld

			if sel.Expiration != "" {
				exp, err := time.ParseDuration(sel.Expiration)
				if err != nil {
					addErrorf("selector %q has invalid expiration %q: %v", name, sel.Expiration, err)
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
				addErrorf("unsupported hash %q for selector %q in domain %s", sel.HashEffective, name, d)
			}

			pemBuf, err := os.ReadFile(configDirPath(dynamicPath, sel.PrivateKeyFile))
			if err != nil {
				addErrorf("reading private key for selector %s in domain %s: %s", name, d, err)
				continue
			}
			p, _ := pem.Decode(pemBuf)
			if p == nil {
				addErrorf("private key for selector %s in domain %s has no PEM block", name, d)
				continue
			}
			key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
			if err != nil {
				addErrorf("parsing private key for selector %s in domain %s: %s", name, d, err)
				continue
			}
			switch k := key.(type) {
			case *rsa.PrivateKey:
				if k.N.BitLen() < 1024 {
					// ../rfc/6376:757
					// Let's help user do the right thing.
					addErrorf("rsa keys should be >= 1024 bits")
				}
				sel.Key = k
			case ed25519.PrivateKey:
				if sel.HashEffective != "sha256" {
					addErrorf("hash algorithm %q is not supported with ed25519, only sha256 is", sel.HashEffective)
				}
				sel.Key = k
			default:
				addErrorf("private key type %T not yet supported, at selector %s in domain %s", key, name, d)
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
					addErrorf("From-field must always be DKIM-signed")
				}
				sel.HeadersEffective = sel.Headers
			}

			domain.DKIM.Selectors[name] = sel
		}

		if domain.MTASTS != nil {
			if !haveSTSListener {
				addErrorf("MTA-STS enabled for domain %q, but there is no listener for MTASTS", d)
			}
			sts := domain.MTASTS
			if sts.PolicyID == "" {
				addErrorf("invalid empty MTA-STS PolicyID")
			}
			switch sts.Mode {
			case mtasts.ModeNone, mtasts.ModeTesting, mtasts.ModeEnforce:
			default:
				addErrorf("invalid mtasts mode %q", sts.Mode)
			}
		}

		checkRoutes("routes for domain", domain.Routes)

		c.Domains[d] = domain
	}

	// Validate email addresses.
	accDests = map[string]AccountDestination{}
	for accName, acc := range c.Accounts {
		var err error
		acc.DNSDomain, err = dns.ParseDomain(acc.Domain)
		if err != nil {
			addErrorf("parsing domain %s for account %q: %s", acc.Domain, accName, err)
		}

		if strings.EqualFold(acc.RejectsMailbox, "Inbox") {
			addErrorf("account %q: cannot set RejectsMailbox to inbox, messages will be removed automatically from the rejects mailbox", accName)
		}
		checkMailboxNormf(acc.RejectsMailbox, "account %q", accName)

		if acc.AutomaticJunkFlags.JunkMailboxRegexp != "" {
			r, err := regexp.Compile(acc.AutomaticJunkFlags.JunkMailboxRegexp)
			if err != nil {
				addErrorf("invalid JunkMailboxRegexp regular expression: %v", err)
			}
			acc.JunkMailbox = r
		}
		if acc.AutomaticJunkFlags.NeutralMailboxRegexp != "" {
			r, err := regexp.Compile(acc.AutomaticJunkFlags.NeutralMailboxRegexp)
			if err != nil {
				addErrorf("invalid NeutralMailboxRegexp regular expression: %v", err)
			}
			acc.NeutralMailbox = r
		}
		if acc.AutomaticJunkFlags.NotJunkMailboxRegexp != "" {
			r, err := regexp.Compile(acc.AutomaticJunkFlags.NotJunkMailboxRegexp)
			if err != nil {
				addErrorf("invalid NotJunkMailboxRegexp regular expression: %v", err)
			}
			acc.NotJunkMailbox = r
		}
		c.Accounts[accName] = acc

		// todo deprecated: only localpart as keys for Destinations, we are replacing them with full addresses. if domains.conf is written, we won't have to do this again.
		replaceLocalparts := map[string]string{}

		for addrName, dest := range acc.Destinations {
			checkMailboxNormf(dest.Mailbox, "account %q, destination %q", accName, addrName)

			for i, rs := range dest.Rulesets {
				checkMailboxNormf(rs.Mailbox, "account %q, destination %q, ruleset %d", accName, addrName, i+1)

				n := 0

				if rs.SMTPMailFromRegexp != "" {
					n++
					r, err := regexp.Compile(rs.SMTPMailFromRegexp)
					if err != nil {
						addErrorf("invalid SMTPMailFrom regular expression: %v", err)
					}
					c.Accounts[accName].Destinations[addrName].Rulesets[i].SMTPMailFromRegexpCompiled = r
				}
				if rs.VerifiedDomain != "" {
					n++
					d, err := dns.ParseDomain(rs.VerifiedDomain)
					if err != nil {
						addErrorf("invalid VerifiedDomain: %v", err)
					}
					c.Accounts[accName].Destinations[addrName].Rulesets[i].VerifiedDNSDomain = d
				}

				var hdr [][2]*regexp.Regexp
				for k, v := range rs.HeadersRegexp {
					n++
					if strings.ToLower(k) != k {
						addErrorf("header field %q must only have lower case characters", k)
					}
					if strings.ToLower(v) != v {
						addErrorf("header value %q must only have lower case characters", v)
					}
					rk, err := regexp.Compile(k)
					if err != nil {
						addErrorf("invalid rule header regexp %q: %v", k, err)
					}
					rv, err := regexp.Compile(v)
					if err != nil {
						addErrorf("invalid rule header regexp %q: %v", v, err)
					}
					hdr = append(hdr, [...]*regexp.Regexp{rk, rv})
				}
				c.Accounts[accName].Destinations[addrName].Rulesets[i].HeadersRegexpCompiled = hdr

				if n == 0 {
					addErrorf("ruleset must have at least one rule")
				}

				if rs.IsForward && rs.ListAllowDomain != "" {
					addErrorf("ruleset cannot have both IsForward and ListAllowDomain")
				}
				if rs.IsForward {
					if rs.SMTPMailFromRegexp == "" || rs.VerifiedDomain == "" {
						addErrorf("ruleset with IsForward must have both SMTPMailFromRegexp and VerifiedDomain too")
					}
				}
				if rs.ListAllowDomain != "" {
					d, err := dns.ParseDomain(rs.ListAllowDomain)
					if err != nil {
						addErrorf("invalid ListAllowDomain %q: %v", rs.ListAllowDomain, err)
					}
					c.Accounts[accName].Destinations[addrName].Rulesets[i].ListAllowDNSDomain = d
				}

				checkMailboxNormf(rs.AcceptRejectsToMailbox, "account %q, destination %q, ruleset %d, rejects mailbox", accName, addrName, i+1)
				if strings.EqualFold(rs.AcceptRejectsToMailbox, "inbox") {
					addErrorf("account %q, destination %q, ruleset %d: AcceptRejectsToMailbox cannot be set to Inbox", accName, addrName, i+1)
				}
			}

			// Catchall destination for domain.
			if strings.HasPrefix(addrName, "@") {
				d, err := dns.ParseDomain(addrName[1:])
				if err != nil {
					addErrorf("parsing domain %q in account %q", addrName[1:], accName)
					continue
				} else if _, ok := c.Domains[d.Name()]; !ok {
					addErrorf("unknown domain for address %q in account %q", addrName, accName)
					continue
				}
				addrFull := "@" + d.Name()
				if _, ok := accDests[addrFull]; ok {
					addErrorf("duplicate canonicalized catchall destination address %s", addrFull)
				}
				accDests[addrFull] = AccountDestination{true, "", accName, dest}
				continue
			}

			// todo deprecated: remove support for parsing destination as just a localpart instead full address.
			var address smtp.Address
			if localpart, err := smtp.ParseLocalpart(addrName); err != nil && errors.Is(err, smtp.ErrBadLocalpart) {
				address, err = smtp.ParseAddress(addrName)
				if err != nil {
					addErrorf("invalid email address %q in account %q", addrName, accName)
					continue
				} else if _, ok := c.Domains[address.Domain.Name()]; !ok {
					addErrorf("unknown domain for address %q in account %q", addrName, accName)
					continue
				}
			} else {
				if err != nil {
					addErrorf("invalid localpart %q in account %q", addrName, accName)
					continue
				}
				address = smtp.NewAddress(localpart, acc.DNSDomain)
				if _, ok := c.Domains[acc.DNSDomain.Name()]; !ok {
					addErrorf("unknown domain %s for account %q", acc.DNSDomain.Name(), accName)
					continue
				}
				replaceLocalparts[addrName] = address.Pack(true)
			}

			origLP := address.Localpart
			dc := c.Domains[address.Domain.Name()]
			if lp, err := CanonicalLocalpart(address.Localpart, dc); err != nil {
				addErrorf("canonicalizing localpart %s: %v", address.Localpart, err)
			} else if dc.LocalpartCatchallSeparator != "" && strings.Contains(string(address.Localpart), dc.LocalpartCatchallSeparator) {
				addErrorf("localpart of address %s includes domain catchall separator %s", address, dc.LocalpartCatchallSeparator)
			} else {
				address.Localpart = lp
			}
			addrFull := address.Pack(true)
			if _, ok := accDests[addrFull]; ok {
				addErrorf("duplicate canonicalized destination address %s", addrFull)
			}
			accDests[addrFull] = AccountDestination{false, origLP, accName, dest}
		}

		for lp, addr := range replaceLocalparts {
			dest, ok := acc.Destinations[lp]
			if !ok {
				addErrorf("could not find localpart %q to replace with address in destinations", lp)
			} else {
				log.Error(`deprecation warning: support for account destination addresses specified as just localpart ("username") instead of full email address will be removed in the future; update domains.conf, for each Account, for each Destination, ensure each key is an email address by appending "@" and the default domain for the account`, mlog.Field("localpart", lp), mlog.Field("address", addr), mlog.Field("account", accName))
				acc.Destinations[addr] = dest
				delete(acc.Destinations, lp)
			}
		}

		checkRoutes("routes for account", acc.Routes)
	}

	// Set DMARC destinations.
	for d, domain := range c.Domains {
		dmarc := domain.DMARC
		if dmarc == nil {
			continue
		}
		if _, ok := c.Accounts[dmarc.Account]; !ok {
			addErrorf("DMARC account %q does not exist", dmarc.Account)
		}
		lp, err := smtp.ParseLocalpart(dmarc.Localpart)
		if err != nil {
			addErrorf("invalid DMARC localpart %q: %s", dmarc.Localpart, err)
		}
		if lp.IsInternational() {
			// ../rfc/8616:234
			addErrorf("DMARC localpart %q is an internationalized address, only conventional ascii-only address possible for interopability", lp)
		}
		addrdom := domain.Domain
		if dmarc.Domain != "" {
			addrdom, err = dns.ParseDomain(dmarc.Domain)
			if err != nil {
				addErrorf("DMARC domain %q: %s", dmarc.Domain, err)
			} else if _, ok := c.Domains[addrdom.Name()]; !ok {
				addErrorf("unknown domain %q for DMARC address in domain %q", dmarc.Domain, d)
			}
		}

		domain.DMARC.ParsedLocalpart = lp
		domain.DMARC.DNSDomain = addrdom
		c.Domains[d] = domain
		addrFull := smtp.NewAddress(lp, addrdom).String()
		dest := config.Destination{
			Mailbox:      dmarc.Mailbox,
			DMARCReports: true,
		}
		checkMailboxNormf(dmarc.Mailbox, "DMARC mailbox for account %q", dmarc.Account)
		accDests[addrFull] = AccountDestination{false, lp, dmarc.Account, dest}
	}

	// Set TLSRPT destinations.
	for d, domain := range c.Domains {
		tlsrpt := domain.TLSRPT
		if tlsrpt == nil {
			continue
		}
		if _, ok := c.Accounts[tlsrpt.Account]; !ok {
			addErrorf("TLSRPT account %q does not exist", tlsrpt.Account)
		}
		lp, err := smtp.ParseLocalpart(tlsrpt.Localpart)
		if err != nil {
			addErrorf("invalid TLSRPT localpart %q: %s", tlsrpt.Localpart, err)
		}
		if lp.IsInternational() {
			// Does not appear documented in ../rfc/8460, but similar to DMARC it makes sense
			// to keep this ascii-only addresses.
			addErrorf("TLSRPT localpart %q is an internationalized address, only conventional ascii-only address allowed for interopability", lp)
		}
		addrdom := domain.Domain
		if tlsrpt.Domain != "" {
			addrdom, err = dns.ParseDomain(tlsrpt.Domain)
			if err != nil {
				addErrorf("TLSRPT domain %q: %s", tlsrpt.Domain, err)
			} else if _, ok := c.Domains[addrdom.Name()]; !ok {
				addErrorf("unknown domain %q for TLSRPT address in domain %q", tlsrpt.Domain, d)
			}
		}

		domain.TLSRPT.ParsedLocalpart = lp
		domain.TLSRPT.DNSDomain = addrdom
		c.Domains[d] = domain
		addrFull := smtp.NewAddress(lp, addrdom).String()
		dest := config.Destination{
			Mailbox:    tlsrpt.Mailbox,
			TLSReports: true,
		}
		checkMailboxNormf(tlsrpt.Mailbox, "TLSRPT mailbox for account %q", tlsrpt.Account)
		accDests[addrFull] = AccountDestination{false, lp, tlsrpt.Account, dest}
	}

	// Check webserver configs.
	if (len(c.WebDomainRedirects) > 0 || len(c.WebHandlers) > 0) && !haveWebserverListener {
		addErrorf("WebDomainRedirects or WebHandlers configured but no listener with WebserverHTTP or WebserverHTTPS enabled")
	}

	c.WebDNSDomainRedirects = map[dns.Domain]dns.Domain{}
	for from, to := range c.WebDomainRedirects {
		fromdom, err := dns.ParseDomain(from)
		if err != nil {
			addErrorf("parsing domain for redirect %s: %v", from, err)
		}
		todom, err := dns.ParseDomain(to)
		if err != nil {
			addErrorf("parsing domain for redirect %s: %v", to, err)
		} else if fromdom == todom {
			addErrorf("will not redirect domain %s to itself", todom)
		}
		var zerodom dns.Domain
		if _, ok := c.WebDNSDomainRedirects[fromdom]; ok && fromdom != zerodom {
			addErrorf("duplicate redirect domain %s", from)
		}
		c.WebDNSDomainRedirects[fromdom] = todom
	}

	for i := range c.WebHandlers {
		wh := &c.WebHandlers[i]

		if wh.LogName == "" {
			wh.Name = fmt.Sprintf("%d", i)
		} else {
			wh.Name = wh.LogName
		}

		dom, err := dns.ParseDomain(wh.Domain)
		if err != nil {
			addErrorf("webhandler %s %s: parsing domain: %v", wh.Domain, wh.PathRegexp, err)
		}
		wh.DNSDomain = dom

		if !strings.HasPrefix(wh.PathRegexp, "^") {
			addErrorf("webhandler %s %s: path regexp must start with a ^", wh.Domain, wh.PathRegexp)
		}
		re, err := regexp.Compile(wh.PathRegexp)
		if err != nil {
			addErrorf("webhandler %s %s: compiling regexp: %v", wh.Domain, wh.PathRegexp, err)
		}
		wh.Path = re

		var n int
		if wh.WebStatic != nil {
			n++
			ws := wh.WebStatic
			if ws.StripPrefix != "" && !strings.HasPrefix(ws.StripPrefix, "/") {
				addErrorf("webstatic %s %s: prefix to strip %s must start with a slash", wh.Domain, wh.PathRegexp, ws.StripPrefix)
			}
			for k := range ws.ResponseHeaders {
				xk := k
				k := strings.TrimSpace(xk)
				if k != xk || k == "" {
					addErrorf("webstatic %s %s: bad header %q", wh.Domain, wh.PathRegexp, xk)
				}
			}
		}
		if wh.WebRedirect != nil {
			n++
			wr := wh.WebRedirect
			if wr.BaseURL != "" {
				u, err := url.Parse(wr.BaseURL)
				if err != nil {
					addErrorf("webredirect %s %s: parsing redirect url %s: %v", wh.Domain, wh.PathRegexp, wr.BaseURL, err)
				}
				switch u.Path {
				case "", "/":
					u.Path = "/"
				default:
					addErrorf("webredirect %s %s: BaseURL must have empty path", wh.Domain, wh.PathRegexp, wr.BaseURL)
				}
				wr.URL = u
			}
			if wr.OrigPathRegexp != "" && wr.ReplacePath != "" {
				re, err := regexp.Compile(wr.OrigPathRegexp)
				if err != nil {
					addErrorf("webredirect %s %s: compiling regexp %s: %v", wh.Domain, wh.PathRegexp, wr.OrigPathRegexp, err)
				}
				wr.OrigPath = re
			} else if wr.OrigPathRegexp != "" || wr.ReplacePath != "" {
				addErrorf("webredirect %s %s: must have either both OrigPathRegexp and ReplacePath, or neither", wh.Domain, wh.PathRegexp)
			} else if wr.BaseURL == "" {
				addErrorf("webredirect %s %s: must at least one of BaseURL and OrigPathRegexp+ReplacePath", wh.Domain, wh.PathRegexp)
			}
			if wr.StatusCode != 0 && (wr.StatusCode < 300 || wr.StatusCode >= 400) {
				addErrorf("webredirect %s %s: invalid redirect status code %d", wh.Domain, wh.PathRegexp, wr.StatusCode)
			}
		}
		if wh.WebForward != nil {
			n++
			wf := wh.WebForward
			u, err := url.Parse(wf.URL)
			if err != nil {
				addErrorf("webforward %s %s: parsing url %s: %v", wh.Domain, wh.PathRegexp, wf.URL, err)
			}
			wf.TargetURL = u

			for k := range wf.ResponseHeaders {
				xk := k
				k := strings.TrimSpace(xk)
				if k != xk || k == "" {
					addErrorf("webforward %s %s: bad header %q", wh.Domain, wh.PathRegexp, xk)
				}
			}
		}
		if n != 1 {
			addErrorf("webhandler %s %s: must have exactly one handler, not %d", wh.Domain, wh.PathRegexp, n)
		}
	}

	return
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
