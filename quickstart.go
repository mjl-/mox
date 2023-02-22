package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	_ "embed"

	"golang.org/x/crypto/bcrypt"

	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

//go:embed mox.service
var moxService string

func pwgen() string {
	rand := mox.NewRand()
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_;:,<.>/"
	s := ""
	for i := 0; i < 12; i++ {
		s += string(chars[rand.Intn(len(chars))])
	}
	return s
}

func cmdQuickstart(c *cmd) {
	c.params = "user@domain"
	c.help = `Quickstart generates configuration files and prints instructions to quickly set up a mox instance.

Quickstart prints initial admin and account passwords, configuration files, DNS
records you should create, instructions for setting correct user/group and
permissions, and if you run it on Linux it prints a systemd service file.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	// We take care to cleanup created files when we error out.
	// We don't want to get a new user into trouble with half of the files
	// after encountering an error.

	// We use fatalf instead of log.Fatal* to cleanup files.
	var cleanupPaths []string
	fatalf := func(format string, args ...any) {
		// We remove in reverse order because dirs would have been created first and must
		// be removed last, after their files have been removed.
		for i := len(cleanupPaths) - 1; i >= 0; i-- {
			p := cleanupPaths[i]
			if err := os.Remove(p); err != nil {
				log.Printf("cleaning up %q: %s", p, err)
			}
		}

		log.Fatalf(format, args...)
	}

	xwritefile := func(path string, data []byte, perm os.FileMode) {
		os.MkdirAll(filepath.Dir(path), 0770)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			fatalf("creating file %q: %s", path, err)
		}
		cleanupPaths = append(cleanupPaths, path)
		_, err = f.Write(data)
		if err == nil {
			err = f.Close()
		}
		if err != nil {
			fatalf("writing file %q: %s", path, err)
		}
	}

	addr, err := smtp.ParseAddress(args[0])
	if err != nil {
		fatalf("parsing email address: %s", err)
	}
	username := addr.Localpart.String()
	domain := addr.Domain

	for _, c := range username {
		if c > 0x7f {
			fmt.Printf(`NOTE: Username %q is not ASCII-only. It is recommended you also configure an
ASCII-only alias. Both for delivery of email from other systems, and for
logging in with IMAP.

`, username)
			break
		}
	}

	// Gather IP addresses for public and private listeners.
	// If we cannot find addresses for a category we fallback to all ips or localhost ips.
	// We look at each network interface. If an interface has a private address, we
	// conservatively assume all addresses on that interface are private.
	ifaces, err := net.Interfaces()
	if err != nil {
		fatalf("listing network interfaces: %s", err)
	}
	var privateIPs, publicIPs []string
	parseAddrIP := func(s string) net.IP {
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			s = s[1 : len(s)-1]
		}
		ip, _, _ := net.ParseCIDR(s)
		return ip
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			fatalf("listing address for network interface: %s", err)
		}
		if len(addrs) == 0 {
			continue
		}

		// todo: should we detect temporary/ephemeral ipv6 addresses and not add them?
		var nonpublic bool
		for _, addr := range addrs {
			ip := parseAddrIP(addr.String())
			if ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			if ip.IsLoopback() || ip.IsPrivate() {
				nonpublic = true
				break
			}
		}

		for _, addr := range addrs {
			ip := parseAddrIP(addr.String())
			if ip == nil {
				continue
			}
			if ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			if nonpublic {
				privateIPs = append(privateIPs, ip.String())
			} else {
				publicIPs = append(publicIPs, ip.String())
			}
		}
	}

	publicListenerIPs := []string{"0.0.0.0", "::"}
	privateListenerIPs := []string{"127.0.0.1", "::1"}
	if len(publicIPs) > 0 {
		publicListenerIPs = publicIPs
	}
	if len(privateIPs) > 0 {
		privateListenerIPs = privateIPs
	}

	resolver := dns.StrictResolver{}

	var hostname dns.Domain
	hostnameStr, err := os.Hostname()
	if err != nil {
		fatalf("hostname: %s", err)
	}
	if strings.Contains(hostnameStr, ".") {
		hostname, err = dns.ParseDomain(hostnameStr)
		if err != nil {
			fatalf("parsing hostname: %v", err)
		}
	} else {
		// It seems Linux machines don't have a single FQDN configured. E.g. /etc/hostname
		// is just the name without domain. We'll look up the names for all IPs, and hope
		// to find a single FQDN name (with at least 1 dot).
		names := map[string]struct{}{}
		if len(publicIPs) > 0 {
			fmt.Printf("Trying to find hostname by reverse lookup of public IPs %s...", strings.Join(publicIPs, ", "))
		}
		var warned bool
		warnf := func(format string, args ...any) {
			warned = true
			fmt.Printf("\n%s", fmt.Sprintf(format, args...))
		}
		for _, ip := range publicIPs {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			l, err := resolver.LookupAddr(ctx, ip)
			if err != nil {
				warnf("WARNING: looking up reverse name(s) for %s: %v", ip, err)
			}
			for _, name := range l {
				if strings.Contains(name, ".") {
					names[name] = struct{}{}
				}
			}
		}
		var nameList []string
		for k := range names {
			nameList = append(nameList, strings.TrimRight(k, "."))
		}
		sort.Slice(nameList, func(i, j int) bool {
			return nameList[i] < nameList[j]
		})
		if len(nameList) == 0 {
			hostname, err = dns.ParseDomain(hostnameStr + "." + domain.Name())
			if err != nil {
				fmt.Println()
				fatalf("parsing hostname: %v", err)
			}
			warnf(`WARNING: cannot determine hostname because the system name is not an FQDN and
no public IPs resolving to an FQDN were found. Quickstart will continue with the
following hostname, please replace it in the suggested DNS records and config
files if this is not correct:

	%s
`, hostname)
		} else {
			if len(nameList) > 1 {
				warnf("WARNING: multiple hostnames found for the public IPs, using the first of: %s", strings.Join(nameList, ", "))
			}
			hostname, err = dns.ParseDomain(nameList[0])
			if err != nil {
				fmt.Println()
				fatalf("parsing hostname %s: %v", nameList[0], err)
			}
		}
		if warned {
			fmt.Printf("\n\n")
		} else {
			fmt.Printf(" found %s\n", hostname)
		}
	}

	// todo: lookup without going through /etc/hosts, because a machine typically has its name configured there, and LookupIPAddr will return it, but we care about DNS settings that the rest of the world uses to find us. perhaps we should check if the address resolves to 127.0.0.0/8?
	fmt.Printf("Looking up IPs for hostname %s...", hostname)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupIPAddr(ctx, hostname.ASCII+".")
	var xips []net.IPAddr
	for _, ip := range ips {
		// During linux install, you may get an alias for you full hostname in /etc/hosts
		// resolving to 127.0.1.1, which would result in a false positive about the
		// hostname having a record. Filter it out. It is a bit surprising that hosts don't
		// otherwise know their FQDN.
		if !ip.IP.IsLoopback() {
			xips = append(xips, ip)
		}
	}
	if err == nil && len(xips) == 0 {
		err = errors.New("hostname not in dns, probably only in /etc/hosts")
	}
	ips = xips
	if err != nil {
		fmt.Printf(`

WARNING: Quickstart assumed the hostname of this machine is %s and generates a
config for that host, but could not retrieve that name from DNS:

	%s

This likely means one of two things:

1. You don't have any DNS records for this machine at all. You should add them
   before continuing.
2. The hostname mentioned is not the correct host name of this machine. You will
   have to replace the hostname in the suggested DNS records and generated
   config/mox.conf file. Make sure your hostname resolves to your public IPs, and
   your public IPs resolve back (reverse) to your hostname.


`, hostname, err)
	} else {
		fmt.Printf(" OK\n")

		var l []string
		type result struct {
			IP    string
			Addrs []string
			Err   error
		}
		results := make(chan result)
		for _, ip := range ips {
			s := ip.String()
			l = append(l, s)
			go func() {
				addrs, err := resolver.LookupAddr(ctx, s)
				results <- result{s, addrs, err}
			}()
		}
		fmt.Printf("Looking up reverse names for IP(s) %s...", strings.Join(l, ", "))
		var warned bool
		warnf := func(format string, args ...any) {
			fmt.Printf("\nWARNING: %s", fmt.Sprintf(format, args...))
			warned = true
		}
		for i := 0; i < len(ips); i++ {
			r := <-results
			if r.Err != nil {
				warnf("looking up reverse name for %s: %v", r.IP, r.Err)
				continue
			}
			if len(r.Addrs) != 1 {
				warnf("expected exactly 1 name for %s, got %d (%v)", r.IP, len(r.Addrs), r.Addrs)
			}
			var match bool
			for i, a := range r.Addrs {
				a = strings.TrimRight(a, ".")
				r.Addrs[i] = a // For potential error message below.
				d, err := dns.ParseDomain(a)
				if err != nil {
					warnf("parsing reverse name %q for %s: %v", a, r.IP, err)
				}
				if d == hostname {
					match = true
				}
			}
			if !match {
				warnf("reverse name(s) %s for ip %s do not match hostname %s, which will cause other mail servers to reject incoming messages from this IP", strings.Join(r.Addrs, ","), r.IP, hostname)
			}
		}
		if warned {
			fmt.Printf("\n\n\n")
		} else {
			fmt.Printf(" OK\n\n")
		}
	}
	cancel()

	dc := config.Dynamic{}
	sc := config.Static{DataDir: "../data"}
	os.MkdirAll(sc.DataDir, 0770)
	sc.LogLevel = "info"
	sc.Hostname = hostname.Name()
	sc.ACME = map[string]config.ACME{
		"letsencrypt": {
			DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
			ContactEmail: args[0], // todo: let user specify an alternative fallback address?
		},
	}
	sc.AdminPasswordFile = "adminpasswd"
	adminpw := pwgen()
	adminpwhash, err := bcrypt.GenerateFromPassword([]byte(adminpw), bcrypt.DefaultCost)
	if err != nil {
		fatalf("generating hash for generated admin password: %s", err)
	}
	xwritefile(filepath.Join("config", sc.AdminPasswordFile), adminpwhash, 0660)
	fmt.Printf("Admin password: %s\n", adminpw)

	public := config.Listener{
		IPs: publicListenerIPs,
		TLS: &config.TLS{
			ACME: "letsencrypt",
		},
	}
	public.SMTP.Enabled = true
	public.Submissions.Enabled = true
	public.IMAPS.Enabled = true
	public.AutoconfigHTTPS.Enabled = true
	public.MTASTSHTTPS.Enabled = true

	// Suggest blocklists, but we'll comment them out after generating the config.
	public.SMTP.DNSBLs = []string{"sbl.spamhaus.org", "bl.spamcop.net"}

	internal := config.Listener{
		IPs:      privateListenerIPs,
		Hostname: "localhost",
	}
	internal.AccountHTTP.Enabled = true
	internal.AdminHTTP.Enabled = true
	internal.MetricsHTTP.Enabled = true

	sc.Listeners = map[string]config.Listener{
		"public":   public,
		"internal": internal,
	}
	sc.Postmaster.Account = username
	sc.Postmaster.Mailbox = "Postmaster"

	mox.ConfigStaticPath = "config/mox.conf"
	mox.ConfigDynamicPath = "config/domains.conf"

	mox.Conf.DynamicLastCheck = time.Now() // Prevent error logging by Make calls below.

	accountConf := mox.MakeAccountConfig(addr)
	confDomain, keyPaths, err := mox.MakeDomainConfig(context.Background(), domain, hostname, username)
	if err != nil {
		fatalf("making domain config: %s", err)
	}
	cleanupPaths = append(cleanupPaths, keyPaths...)

	dc.Domains = map[string]config.Domain{
		domain.Name(): confDomain,
	}
	dc.Accounts = map[string]config.Account{
		username: accountConf,
	}

	// Build config in memory, so we can easily comment out the DNSBLs config.
	var sb strings.Builder
	sc.CheckUpdates = true // Commented out below.
	if err := sconf.WriteDocs(&sb, &sc); err != nil {
		fatalf("generating static config: %v", err)
	}
	confstr := sb.String()
	confstr = strings.ReplaceAll(confstr, "\nCheckUpdates: true\n", "\n#\n# RECOMMENDED: please enable to stay up to date\n#\n#CheckUpdates: true\n")
	confstr = strings.ReplaceAll(confstr, "DNSBLs:\n", "#DNSBLs:\n")
	for _, bl := range public.SMTP.DNSBLs {
		confstr = strings.ReplaceAll(confstr, "- "+bl+"\n", "#- "+bl+"\n")
	}
	xwritefile("config/mox.conf", []byte(confstr), 0660)

	// Generate domains config, and add a commented out example for delivery to a mailing list.
	var db bytes.Buffer
	if err := sconf.WriteDocs(&db, &dc); err != nil {
		fatalf("generating domains config: %v", err)
	}

	// This approach is a bit horrible, but it generates a convenient
	// example that includes the comments. Though it is gone by the first
	// write of the file by mox.
	odests := fmt.Sprintf("\t\tDestinations:\n\t\t\t%s: nil\n", addr.Localpart.String())
	var destsExample = struct {
		Destinations map[string]config.Destination
	}{
		Destinations: map[string]config.Destination{
			addr.Localpart.String(): {
				Rulesets: []config.Ruleset{
					{
						VerifiedDomain: "list.example.org",
						HeadersRegexp: map[string]string{
							"^list-id$": `<name\.list\.example\.org>`,
						},
						ListAllowDomain: "list.example.org",
						Mailbox:         "Lists/Example",
					},
				},
			},
		},
	}
	var destBuf strings.Builder
	if err := sconf.Describe(&destBuf, destsExample); err != nil {
		fatalf("describing destination example: %v", err)
	}
	ndests := odests + "#\t\t\tIf you receive email from mailing lists, you probably want to configure them like the example below.\n"
	for _, line := range strings.Split(destBuf.String(), "\n")[1:] {
		ndests += "#\t\t" + line + "\n"
	}
	dconfstr := strings.ReplaceAll(db.String(), odests, ndests)
	xwritefile("config/domains.conf", []byte(dconfstr), 0660)

	// Verify config.
	mc, errs := mox.ParseConfig(context.Background(), "config/mox.conf", true)
	if len(errs) > 0 {
		if len(errs) > 1 {
			log.Printf("checking generated config, multiple errors:")
			for _, err := range errs {
				log.Println(err)
			}
			fatalf("aborting due to multiple config errors")
		}
		fatalf("checking generated config: %s", errs[0])
	}
	mox.SetConfig(mc)
	// NOTE: Now that we've prepared the config, we can open the account
	// and set a passsword, and the public key for the DKIM private keys
	// are available for generating the DKIM DNS records below.

	confDomain, ok := mc.Domain(domain)
	if !ok {
		fatalf("cannot find domain in new config")
	}

	acc, _, err := store.OpenEmail(args[0])
	if err != nil {
		fatalf("open account: %s", err)
	}
	cleanupPaths = append(cleanupPaths, sc.DataDir, filepath.Join(sc.DataDir, "accounts"), filepath.Join(sc.DataDir, "accounts", username), filepath.Join(sc.DataDir, "accounts", username, "index.db"))

	password := pwgen()
	if err := acc.SetPassword(password); err != nil {
		fatalf("setting password: %s", err)
	}
	if err := acc.Close(); err != nil {
		fatalf("closing account: %s", err)
	}
	fmt.Printf("IMAP and SMTP submission password for %s: %s\n\n", args[0], password)
	fmt.Println(`When configuring your email client, use the email address as username. If
autoconfig/autodiscover does not work, use the settings below.`)
	fmt.Println("")
	printClientConfig(domain)

	fmt.Println("")
	fmt.Println(`Configuration files have been written to config/mox.conf and
config/domains.conf. You should review them. Then create the DNS records below.
You can also skip creating the DNS records and start mox immediately. The admin
interface can show these same records, and has a page to check they have been
configured correctly.`)

	// We do not verify the records exist: If they don't exist, we would only be
	// priming dns caches with negative/absent records, causing our "quick setup" to
	// appear to fail or take longer than "quick".

	records, err := mox.DomainRecords(confDomain, domain)
	if err != nil {
		fatalf("making required DNS records")
	}
	fmt.Print("\n\n\n" + strings.Join(records, "\n") + "\n\n\n\n")

	fmt.Printf(`WARNING: The configuration and DNS records above assume you do not currently
have email configured for your domain. If you do already have email configured,
or if you are sending email for your domain from other machines/services, you
should understand the consequences of the DNS records above before
continuing!

You can now start mox with "mox serve", but see below for recommended ownership
and permissions.

`)

	userName := "root"
	groupName := "root"
	if u, err := user.Current(); err != nil {
		log.Printf("get current user: %v", err)
	} else {
		userName = u.Username
		if g, err := user.LookupGroupId(u.Gid); err != nil {
			log.Printf("get current group: %v", err)
		} else {
			groupName = g.Name
		}
	}
	fmt.Printf(`Assuming the mox binary is in the current directory, and you will run mox under
user name "mox", and the admin user is the current user, the following command
sets the correct permissions:

	sudo useradd -d $PWD mox
	sudo chown %s:mox . mox
	sudo chown -R mox:%s config data
	sudo chmod 751 .
	sudo chmod 750 mox
	sudo chmod -R u=rwX,g=rwX,o= config data
	sudo chmod g+s $(find . -type d)

`, userName, groupName)

	// For now, we only give service config instructions for linux.
	if runtime.GOOS == "linux" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Printf("current working directory: %v", err)
			pwd = "/home/service/mox"
		}
		service := strings.ReplaceAll(moxService, "/home/service/mox", pwd)
		xwritefile("mox.service", []byte(service), 0644)
		cleanupPaths = append(cleanupPaths, "mox.service")
		fmt.Printf(`See mox.service for a systemd service file. To enable and start:

	sudo chmod 644 mox.service
	sudo systemctl enable $PWD/mox.service
	sudo systemctl start mox.service
	sudo journalctl -f -u mox.service # See logs

`)
	}

	fmt.Println(`For secure email exchange you should have a strictly validating DNSSEC
resolver. An easy and the recommended way is to install unbound.

Enjoy!

PS: If port 443 is not available on this machine, automatic TLS with Let's
Encrypt will not work. You can configure existing TLS certificates/keys in mox
(run "mox config describe-static" for examples, and don't forget to renew the
certificates!), or disable TLS (not secure, but perhaps you are just evaluating
mox). If you disable TLS, you must also remove the DNS records about mta-sts,
autoconfig, autodiscover and the SRV records. You also have to edit
config/mox.conf and disable (comment out) TLS in the "public" listener, replace
field "Submissions" with "Submission" and add a sub field "NoRequireSTARTTLS:
true", replace field "IMAPS" with "IMAP" add add a sub field "NoRequireSTARTTLS:
true", and set the "Enabled" field of "AutoconfigHTTPS" and "MTASTSHTTPS" to
false. Final warning: If you disable TLS, your email messages, and user name and
potentially password will be transferred over the internet in plain text!`)

	cleanupPaths = nil
}
