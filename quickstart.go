package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	_ "embed"

	"golang.org/x/crypto/bcrypt"

	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/admin"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/rdap"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"slices"
)

//go:embed mox.service
var moxService string

func cmdQuickstart(c *cmd) {
	c.params = "[-skipdial] [-existing-webserver] [-hostname host] user@domain [user | uid]"
	c.help = `Quickstart generates configuration files and prints instructions to quickly set up a mox instance.

Quickstart writes configuration files, prints initial admin and account
passwords, DNS records you should create. If you run it on Linux it writes a
systemd service file and prints commands to enable and start mox as service.

All output is written to quickstart.log for later reference.

The user or uid is optional, defaults to "mox", and is the user or uid/gid mox
will run as after initialization.

Quickstart assumes mox will run on the machine you run quickstart on and uses
its host name and public IPs. On many systems the hostname is not a fully
qualified domain name, but only the first dns "label", e.g. "mail" in case of
"mail.example.org". If so, quickstart does a reverse DNS lookup to find the
hostname, and as fallback uses the label plus the domain of the email address
you specified. Use flag -hostname to explicitly specify the hostname mox will
run on.

Mox is by far easiest to operate if you let it listen on port 443 (HTTPS) and
80 (HTTP). TLS will be fully automatic with ACME with Let's Encrypt.

You can run mox along with an existing webserver, but because of MTA-STS and
autoconfig, you'll need to forward HTTPS traffic for two domains to mox. Run
"mox quickstart -existing-webserver ..." to generate configuration files and
instructions for configuring mox along with an existing webserver.

But please first consider configuring mox on port 443. It can itself serve
domains with HTTP/HTTPS, including with automatic TLS with ACME, is easily
configured through both configuration files and admin web interface, and can act
as a reverse proxy (and static file server for that matter), so you can forward
traffic to your existing backend applications. Look for "WebHandlers:" in the
output of "mox config describe-domains" and see the output of
"mox config example webhandlers".
`
	var existingWebserver bool
	var hostname string
	var skipDial bool
	c.flag.BoolVar(&existingWebserver, "existing-webserver", false, "use if a webserver is already running, so mox won't listen on port 80 and 443; you'll have to provide tls certificates/keys, and configure the existing webserver as reverse proxy, forwarding requests to mox.")
	c.flag.StringVar(&hostname, "hostname", "", "hostname mox will run on, by default the hostname of the machine quickstart runs on; if specified, the IPs for the hostname are configured for the public listener")
	c.flag.BoolVar(&skipDial, "skipdial", false, "skip check for outgoing smtp (port 25) connectivity or for domain age with rdap")
	args := c.Parse()
	if len(args) != 1 && len(args) != 2 {
		c.Usage()
	}

	// Write all output to quickstart.log.
	logfile, err := os.Create("quickstart.log")
	xcheckf(err, "creating quickstart.log")

	origStdout := os.Stdout
	origStderr := os.Stderr
	piper, pipew, err := os.Pipe()
	xcheckf(err, "creating pipe for logging to logfile")
	pipec := make(chan struct{})
	go func() {
		io.Copy(io.MultiWriter(origStdout, logfile), piper)
		close(pipec)
		if err := piper.Close(); err != nil {
			log.Printf("close pipe: %v", err)
		}
	}()
	// A single pipe, so writes to stdout and stderr don't get interleaved.
	os.Stdout = pipew
	os.Stderr = pipew
	logClose := func() {
		if err := pipew.Close(); err != nil {
			log.Printf("close pipe: %v", err)
		}
		<-pipec
		os.Stdout = origStdout
		os.Stderr = origStderr
		err := logfile.Close()
		xcheckf(err, "closing quickstart.log")
	}
	defer logClose()
	log.SetOutput(os.Stdout)
	fmt.Printf("(output is also written to quickstart.log)\n\n")
	defer fmt.Printf("\n(output is also written to quickstart.log)\n")

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

		log.Printf(format, args...)
		logClose()
		os.Exit(1)
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
	accountName := addr.Localpart.String()
	domain := addr.Domain

	for _, c := range accountName {
		if c > 0x7f {
			fmt.Printf(`NOTE: Username %q is not ASCII-only. It is recommended you also configure an
ASCII-only alias. Both for delivery of email from other systems, and for
logging in with IMAP.

`, accountName)
			break
		}
	}

	resolver := dns.StrictResolver{}
	// We don't want to spend too much total time on the DNS lookups. Because DNS may
	// not work during quickstart, and we don't want to loop doing requests and having
	// to wait for a timeout each time.
	resolveCtx, resolveCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer resolveCancel()

	// Some DNSSEC-verifying resolvers return unauthentic data for ".", so we check "com".
	fmt.Printf("Checking if DNS resolvers are DNSSEC-verifying...")
	_, resolverDNSSECResult, err := resolver.LookupNS(resolveCtx, "com.")
	if err != nil {
		fmt.Println("")
		fatalf("checking dnssec support in resolver: %v", err)
	} else if !resolverDNSSECResult.Authentic {
		fmt.Printf(`

WARNING: It looks like the DNS resolvers configured on your system do not
verify DNSSEC, or aren't trusted (by having loopback IPs or through "options
trust-ad" in /etc/resolv.conf).  Without DNSSEC, outbound delivery with SMTP
used unprotected MX records, and SMTP STARTTLS connections cannot verify the TLS
certificate with DANE (based on a public key in DNS), and will fall back to
either MTA-STS for verification, or use "opportunistic TLS" with no certificate
verification.

Recommended action: Install unbound, a DNSSEC-verifying recursive DNS resolver,
ensure it has DNSSEC root keys (see unbound-anchor), and enable support for
"extended dns errors" (EDE, available since unbound v1.16.0, see below; not
required, but it gives helpful error messages about DNSSEC failures instead of
generic DNS SERVFAIL errors). Test with "dig com. ns" and look for "ad"
(authentic data) in response "flags".

cat <<EOF >/etc/unbound/unbound.conf.d/ede.conf
server:
    ede: yes
    val-log-level: 2
EOF

Troubleshooting hints:
- Ensure /etc/resolv.conf has "nameserver 127.0.0.1". If the IP is 127.0.0.53,
  DNS resolving is done by systemd-resolved. Make sure "resolvconf" isn't
  overwriting /etc/resolv.conf (Debian has a package "openresolv" that makes this
  easier). "dig" also shows to which IP the DNS request was sent.
- Ensure unbound has DNSSEC root keys available. See unbound config option
  "auto-trust-anchor-file" and the unbound-anchor command. Ensure the file exists.
- Run "./mox dns lookup ns com." to simulate the DNSSEC check done by mox. The
  output should say "with dnssec".
- The "delv" command can check whether a domain is DNSSEC-signed, but it does
  its own DNSSEC verification instead of relying on the resolver, so you cannot
  use it to check whether unbound is verifying DNSSEC correctly.
- Increase logging in unbound, see options "verbosity" and "log-queries".

`)
	} else {
		fmt.Println(" OK")
	}

	// We are going to find the (public) IPs to listen on and possibly the host name.

	// Start with reasonable defaults. We'll replace them specific IPs, if we can find them.
	privateListenerIPs := []string{"127.0.0.1", "::1"}
	publicListenerIPs := []string{"0.0.0.0", "::"}
	var publicNATIPs []string // Actual public IP, but when it is NATed and machine doesn't have direct access.
	defaultPublicListenerIPs := true

	// If we find IPs based on network interfaces, {public,private}ListenerIPs are set
	// based on these values.
	var loopbackIPs, privateIPs, publicIPs []string

	// Gather IP addresses for public and private listeners.
	// We look at each network interface. If an interface has a private address, we
	// conservatively assume all addresses on that interface are private.
	ifaces, err := net.Interfaces()
	if err != nil {
		fatalf("listing network interfaces: %s", err)
	}
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
				if ip.IsLoopback() {
					loopbackIPs = append(loopbackIPs, ip.String())
				} else {
					privateIPs = append(privateIPs, ip.String())
				}
			} else {
				publicIPs = append(publicIPs, ip.String())
			}
		}
	}

	var dnshostname dns.Domain
	if hostname == "" {
		hostnameStr, err := os.Hostname()
		if err != nil {
			fatalf("hostname: %s", err)
		}
		if strings.Contains(hostnameStr, ".") {
			dnshostname, err = dns.ParseDomain(hostnameStr)
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
				revctx, revcancel := context.WithTimeout(resolveCtx, 5*time.Second)
				defer revcancel()
				l, _, err := resolver.LookupAddr(revctx, ip)
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
			slices.Sort(nameList)
			if len(nameList) == 0 {
				dnshostname, err = dns.ParseDomain(hostnameStr + "." + domain.Name())
				if err != nil {
					fmt.Println()
					fatalf("parsing hostname: %v", err)
				}
				warnf(`WARNING: cannot determine hostname because the system name is not an FQDN and
no public IPs resolving to an FQDN were found. Quickstart guessed the host name
below. If it is not correct, please remove the generated config files and run
quickstart again with the -hostname flag.

		%s
`, dnshostname)
			} else {
				if len(nameList) > 1 {
					warnf(`WARNING: multiple hostnames found for the public IPs, using the first of: %s
If this is not correct, remove the generated config files and run quickstart
again with the -hostname flag.
`, strings.Join(nameList, ", "))
				}
				dnshostname, err = dns.ParseDomain(nameList[0])
				if err != nil {
					fmt.Println()
					fatalf("parsing hostname %s: %v", nameList[0], err)
				}
			}
			if warned {
				fmt.Printf("\n\n")
			} else {
				fmt.Printf(" found %s\n", dnshostname)
			}
		}
	} else {
		// Host name was explicitly configured on command-line. We'll try to use its public
		// IPs below.
		var err error
		dnshostname, err = dns.ParseDomain(hostname)
		if err != nil {
			fatalf("parsing hostname: %v", err)
		}
	}

	fmt.Printf("Looking up IPs for hostname %s...", dnshostname)
	ipctx, ipcancel := context.WithTimeout(resolveCtx, 5*time.Second)
	defer ipcancel()
	ips, domainDNSSECResult, err := resolver.LookupIPAddr(ipctx, dnshostname.ASCII+".")
	ipcancel()
	var xips []net.IPAddr
	var hostIPs []string
	var dnswarned bool
	hostPrivate := len(ips) > 0
	for _, ip := range ips {
		if !ip.IP.IsPrivate() {
			hostPrivate = false
		}
		// During linux install, you may get an alias for you full hostname in /etc/hosts
		// resolving to 127.0.1.1, which would result in a false positive about the
		// hostname having a record. Filter it out. It is a bit surprising that hosts don't
		// otherwise know their FQDN.
		if ip.IP.IsLoopback() {
			dnswarned = true
			fmt.Printf("\n\nWARNING: Your hostname is resolving to a loopback IP address %s. This likely breaks email delivery to local accounts. /etc/hosts likely contains a line like %q. Either replace it with your actual IP(s), or remove the line.\n", ip.IP, fmt.Sprintf("%s %s", ip.IP, dnshostname.ASCII))
			continue
		}
		xips = append(xips, ip)
		hostIPs = append(hostIPs, ip.String())
	}
	if err == nil && len(xips) == 0 {
		// todo: possibly check this by trying to resolve without using /etc/hosts?
		err = errors.New("hostname not in dns, probably only in /etc/hosts")
	}
	ips = xips

	// We may have found private and public IPs on the machine, and IPs for the host
	// name we think we should use. They may not match with each other. E.g. the public
	// IPs on interfaces could be different from the IPs for the host. We don't try to
	// detect all possible configs, but just generate what makes sense given whether we
	// found public/private/hostname IPs. If the user is doing sensible things, it
	// should be correct. But they should be checking the generated config file anyway.
	// And we do log which host name we are using, and whether we detected a NAT setup.
	// In the future, we may do an interactive setup that can guide the user better.

	if !hostPrivate && len(publicIPs) == 0 && len(privateIPs) > 0 {
		// We only have private IPs, assume we are behind a NAT and put the IPs of the host in NATIPs.
		publicListenerIPs = privateIPs
		publicNATIPs = hostIPs
		defaultPublicListenerIPs = false
		if len(loopbackIPs) > 0 {
			privateListenerIPs = loopbackIPs
		}
	} else {
		if len(hostIPs) > 0 {
			publicListenerIPs = hostIPs
			defaultPublicListenerIPs = false

			// Only keep private IPs that are not in host-based publicListenerIPs. For
			// internal-only setups, including integration tests.
			m := map[string]bool{}
			for _, ip := range hostIPs {
				m[ip] = true
			}
			var npriv []string
			for _, ip := range privateIPs {
				if !m[ip] {
					npriv = append(npriv, ip)
				}
			}
			sort.Strings(npriv)
			privateIPs = npriv
		} else if len(publicIPs) > 0 {
			publicListenerIPs = publicIPs
			defaultPublicListenerIPs = false
			hostIPs = publicIPs // For DNSBL check below.
		}
		if len(privateIPs) > 0 {
			privateListenerIPs = append(privateIPs, loopbackIPs...)
		} else if len(loopbackIPs) > 0 {
			privateListenerIPs = loopbackIPs
		}
	}
	if err != nil {
		if !dnswarned {
			fmt.Printf("\n")
		}
		dnswarned = true
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


`, dnshostname, err)
	} else if !domainDNSSECResult.Authentic {
		if !dnswarned {
			fmt.Printf("\n")
		}
		dnswarned = true
		fmt.Printf(`
NOTE: It looks like the DNS records of your domain (zone) are not DNSSEC-signed.
Mail servers that send email to your domain, or receive email from your domain,
cannot verify that the MX/SPF/DKIM/DMARC/MTA-STS records they receive are
authentic. DANE, for authenticated delivery without relying on a pool of
certificate authorities, requires DNSSEC, so will not be configured at this
time.
Recommended action: Continue now, but consider enabling DNSSEC for your domain
later at your DNS operator, and adding DANE records for protecting incoming
messages over SMTP.

`)
	}

	if !dnswarned {
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
				revctx, revcancel := context.WithTimeout(resolveCtx, 5*time.Second)
				defer revcancel()
				addrs, _, err := resolver.LookupAddr(revctx, s)
				results <- result{s, addrs, err}
			}()
		}
		fmt.Printf("Looking up reverse names for IP(s) %s...", strings.Join(l, ", "))
		var warned bool
		warnf := func(format string, args ...any) {
			fmt.Printf("\nWARNING: %s", fmt.Sprintf(format, args...))
			warned = true
		}
		for range ips {
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
				if d == dnshostname {
					match = true
				}
			}
			if !match {
				warnf("reverse name(s) %s for ip %s do not match hostname %s, which will cause other mail servers to reject incoming messages from this IP", strings.Join(r.Addrs, ","), r.IP, dnshostname)
			}
		}
		if warned {
			fmt.Printf("\n\n")
		} else {
			fmt.Printf(" OK\n")
		}
	}

	if !skipDial {
		// Check outgoing SMTP connectivity.
		fmt.Printf("Checking if outgoing smtp connections can be made by connecting to gmail.com mx on port 25...")
		mxctx, mxcancel := context.WithTimeout(context.Background(), 5*time.Second)
		mx, _, err := resolver.LookupMX(mxctx, "gmail.com.")
		mxcancel()
		if err == nil && len(mx) == 0 {
			err = errors.New("no mx records")
		}
		var ok bool
		if err != nil {
			fmt.Printf("\n\nERROR: looking up gmail.com mx record: %s\n", err)
		} else {
			dialctx, dialcancel := context.WithTimeout(context.Background(), 10*time.Second)
			d := net.Dialer{}
			addr := net.JoinHostPort(mx[0].Host, "25")
			conn, err := d.DialContext(dialctx, "tcp", addr)
			dialcancel()
			if err != nil {
				fmt.Printf("\n\nERROR: connecting to %s: %s\n", addr, err)
			} else {
				if err := conn.Close(); err != nil {
					log.Printf("closing smtp connection: %v", err)
				}
				fmt.Printf(" OK\n")
				ok = true
			}
		}
		if !ok {
			fmt.Printf(`
WARNING: Could not verify outgoing smtp connections can be made, outgoing
delivery may not be working. Many providers block outgoing smtp connections by
default, requiring an explicit request or a cooldown period before allowing
outgoing smtp connections. To send through a smarthost, configure a "Transport"
in mox.conf and use it in "Routes" in domains.conf. See
"mox config example transport".

`)
		}

		// Check if domain is recently registered.
		rdapctx, rdapcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer rdapcancel()
		orgdom := publicsuffix.Lookup(rdapctx, c.log.Logger, domain)
		fmt.Printf("\nChecking if domain %s was registered recently...", orgdom)
		registration, err := rdap.LookupLastDomainRegistration(rdapctx, c.log, orgdom)
		rdapcancel()
		if err != nil {
			fmt.Printf(" error: %s (continuing)\n\n", err)
		} else {
			age := time.Since(registration)
			const day = 24 * time.Hour
			const year = 365 * day
			years := age / year
			days := (age - years*year) / day
			var s string
			if years == 1 {
				s = "1 year, "
			} else if years > 0 {
				s = fmt.Sprintf("%d years, ", years)
			}
			if days == 1 {
				s += "1 day"
			} else {
				s += fmt.Sprintf("%d days", days)
			}
			fmt.Printf(" %s", s)
			// 6 weeks is a guess, mail servers/service providers will have different policies.
			if age < 6*7*day {
				fmt.Printf(" (recent!)\nWARNING: Mail servers may treat messages coming from recently registered domains\n(in the order of weeks to months) with suspicion, with higher probability of\nmessages being classified as junk.\n\n")
			} else {
				fmt.Printf(" OK\n\n")
			}
		}
	}

	zones := []dns.Domain{
		{ASCII: "sbl.spamhaus.org"},
		{ASCII: "bl.spamcop.net"},
	}
	if len(hostIPs) > 0 {
		fmt.Printf("Checking whether host name IPs are listed in popular DNS block lists...")
		var listed bool
		for _, zone := range zones {
			for _, ip := range hostIPs {
				dnsblctx, dnsblcancel := context.WithTimeout(context.Background(), 5*time.Second)
				status, expl, err := dnsbl.Lookup(dnsblctx, c.log.Logger, resolver, zone, net.ParseIP(ip))
				dnsblcancel()
				if status == dnsbl.StatusPass {
					continue
				}
				errstr := ""
				if err != nil {
					errstr = fmt.Sprintf(" (%s)", err)
				}
				fmt.Printf("\nWARNING: checking your public IP %s in DNS block list %s: %v %s%s", ip, zone.Name(), status, expl, errstr)
				listed = true
			}
		}
		if listed {
			log.Printf(`
Other mail servers are likely to reject email from IPs that are in a blocklist.
If all your IPs are in block lists, you will encounter problems delivering
email. Your IP may be in block lists only temporarily. To see if your IPs are
listed in more DNS block lists, visit:

`)
			for _, ip := range hostIPs {
				fmt.Printf("- https://multirbl.valli.org/lookup/%s.html\n", url.PathEscape(ip))
			}
			fmt.Printf("\n")
		} else {
			fmt.Printf(" OK\n")
		}
	}

	if defaultPublicListenerIPs {
		log.Printf(`
WARNING: Could not find your public IP address(es). The "public" listener is
configured to listen on 0.0.0.0 (IPv4) and :: (IPv6). If you don't change these
to your actual public IP addresses, you will likely get "address in use" errors
when starting mox because the "internal" listener binds to a specific IP
address on the same port(s). If you are behind a NAT, instead configure the
actual public IPs in the listener's "NATIPs" option.

`)
	}
	if len(publicNATIPs) > 0 {
		log.Printf(`
NOTE: Quickstart used the IPs of the host name of the mail server, but only
found private IPs on the machine. This indicates this machine is behind a NAT,
so the host IPs were configured in the NATIPs field of the public listeners. If
you are behind a NAT that does not preserve the remote IPs of connections, you
will likely experience problems accepting email due to IP-based policies. For
example, SPF is a mechanism that checks if an IP address is allowed to send
email for a domain, and mox uses IP-based (non)junk classification, and IP-based
rate-limiting both for accepting email and blocking bad actors (such as with too
many authentication failures).

`)
	}

	fmt.Printf("\n")

	user := "mox"
	if len(args) == 2 {
		user = args[1]
	}

	dc := config.Dynamic{}
	sc := config.Static{
		DataDir:           filepath.FromSlash("../data"),
		User:              user,
		LogLevel:          "debug", // Help new users, they'll bring it back to info when it all works.
		Hostname:          dnshostname.Name(),
		AdminPasswordFile: "adminpasswd",
	}

	// todo: let user specify an alternative fallback address?
	// Don't attempt to use a non-ascii localpart with Let's Encrypt, it won't work.
	// Messages to postmaster will get to the account too.
	var contactEmail string
	if addr.Localpart.IsInternational() {
		contactEmail = smtp.NewAddress("postmaster", addr.Domain).Pack(false)
	} else {
		contactEmail = addr.Pack(false)
	}
	if !existingWebserver {
		sc.ACME = map[string]config.ACME{
			"letsencrypt": {
				DirectoryURL:     "https://acme-v02.api.letsencrypt.org/directory",
				ContactEmail:     contactEmail,
				IssuerDomainName: "letsencrypt.org",
			},
		}
	}

	dataDir := "data" // ../data is relative to config/
	os.MkdirAll(dataDir, 0770)
	adminpw := mox.GeneratePassword()
	adminpwhash, err := bcrypt.GenerateFromPassword([]byte(adminpw), bcrypt.DefaultCost)
	if err != nil {
		fatalf("generating hash for generated admin password: %s", err)
	}
	xwritefile(filepath.Join("config", sc.AdminPasswordFile), adminpwhash, 0660)
	fmt.Printf("Admin password: %s\n", adminpw)

	public := config.Listener{
		IPs:    publicListenerIPs,
		NATIPs: publicNATIPs,
	}
	public.SMTP.Enabled = true
	public.Submissions.Enabled = true
	public.IMAPS.Enabled = true

	if existingWebserver {
		hostbase := filepath.FromSlash("path/to/" + dnshostname.Name())
		mtastsbase := filepath.FromSlash("path/to/mta-sts." + domain.Name())
		autoconfigbase := filepath.FromSlash("path/to/autoconfig." + domain.Name())
		mailbase := filepath.FromSlash("path/to/mail." + domain.Name())
		public.TLS = &config.TLS{
			KeyCerts: []config.KeyCert{
				{CertFile: hostbase + "-chain.crt.pem", KeyFile: hostbase + ".key.pem"},
				{CertFile: mtastsbase + "-chain.crt.pem", KeyFile: mtastsbase + ".key.pem"},
				{CertFile: autoconfigbase + "-chain.crt.pem", KeyFile: autoconfigbase + ".key.pem"},
			},
		}
		if mailbase != hostbase {
			public.TLS.KeyCerts = append(public.TLS.KeyCerts, config.KeyCert{CertFile: mailbase + "-chain.crt.pem", KeyFile: mailbase + ".key.pem"})
		}

		fmt.Println(
			`Placeholder paths to TLS certificates to be provided by the existing webserver
have been placed in config/mox.conf and need to be edited.

No private keys for the public listener have been generated for use with DANE.
To configure DANE (which requires DNSSEC), set config field HostPrivateKeyFiles
in the "public" Listener to both RSA 2048-bit and ECDSA P-256 private key files
and check the admin page for the needed DNS records.`)

	} else {
		// todo: we may want to generate a second set of keys, make the user already add it to the DNS, but keep the private key offline. would require config option to specify a public key only, so the dane records can be generated.
		hostRSAPrivateKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
		if err != nil {
			fatalf("generating rsa private key for host: %s", err)
		}
		hostECDSAPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
		if err != nil {
			fatalf("generating ecsa private key for host: %s", err)
		}
		now := time.Now()
		timestamp := now.Format("20060102T150405")
		hostRSAPrivateKeyFile := filepath.Join("hostkeys", fmt.Sprintf("%s.%s.%s.privatekey.pkcs8.pem", dnshostname.Name(), timestamp, "rsa2048"))
		hostECDSAPrivateKeyFile := filepath.Join("hostkeys", fmt.Sprintf("%s.%s.%s.privatekey.pkcs8.pem", dnshostname.Name(), timestamp, "ecdsap256"))
		xwritehostkeyfile := func(path string, key crypto.Signer) {
			buf, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				fatalf("marshaling host private key to pkcs8 for %s: %s", path, err)
			}
			var b bytes.Buffer
			block := pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: buf,
			}
			err = pem.Encode(&b, &block)
			if err != nil {
				fatalf("pem-encoding host private key file for %s: %s", path, err)
			}
			xwritefile(path, b.Bytes(), 0600)
		}
		xwritehostkeyfile(filepath.Join("config", hostRSAPrivateKeyFile), hostRSAPrivateKey)
		xwritehostkeyfile(filepath.Join("config", hostECDSAPrivateKeyFile), hostECDSAPrivateKey)

		public.TLS = &config.TLS{
			ACME: "letsencrypt",
			HostPrivateKeyFiles: []string{
				hostRSAPrivateKeyFile,
				hostECDSAPrivateKeyFile,
			},
			HostPrivateRSA2048Keys:   []crypto.Signer{hostRSAPrivateKey},
			HostPrivateECDSAP256Keys: []crypto.Signer{hostECDSAPrivateKey},
		}
		public.AutoconfigHTTPS.Enabled = true
		public.MTASTSHTTPS.Enabled = true
		public.WebserverHTTP.Enabled = true
		public.WebserverHTTPS.Enabled = true
	}

	// Suggest blocklists, but we'll comment them out after generating the config.
	for _, zone := range zones {
		public.SMTP.DNSBLs = append(public.SMTP.DNSBLs, zone.Name())
	}

	// Monitor DNSBLs by default, without using them for incoming deliveries.
	for _, zone := range zones {
		dc.MonitorDNSBLs = append(dc.MonitorDNSBLs, zone.Name())
	}

	internal := config.Listener{
		IPs:      privateListenerIPs,
		Hostname: "localhost",
	}
	internal.AccountHTTP.Enabled = true
	internal.AdminHTTP.Enabled = true
	internal.WebmailHTTP.Enabled = true
	internal.WebAPIHTTP.Enabled = true
	internal.MetricsHTTP.Enabled = true
	if existingWebserver {
		internal.AccountHTTP.Port = 1080
		internal.AccountHTTP.Forwarded = true
		internal.AdminHTTP.Port = 1080
		internal.AdminHTTP.Forwarded = true
		internal.WebmailHTTP.Port = 1080
		internal.WebmailHTTP.Forwarded = true
		internal.WebAPIHTTP.Port = 1080
		internal.WebAPIHTTP.Forwarded = true
		internal.AutoconfigHTTPS.Enabled = true
		internal.AutoconfigHTTPS.Port = 81
		internal.AutoconfigHTTPS.NonTLS = true
		internal.MTASTSHTTPS.Enabled = true
		internal.MTASTSHTTPS.Port = 81
		internal.MTASTSHTTPS.NonTLS = true
		internal.WebserverHTTP.Enabled = true
		internal.WebserverHTTP.Port = 81
	}

	sc.Listeners = map[string]config.Listener{
		"public":   public,
		"internal": internal,
	}
	sc.Postmaster.Account = accountName
	sc.Postmaster.Mailbox = "Postmaster"
	sc.HostTLSRPT.Account = accountName
	sc.HostTLSRPT.Localpart = "tlsreports"
	sc.HostTLSRPT.Mailbox = "TLSRPT"

	mox.ConfigStaticPath = filepath.FromSlash("config/mox.conf")
	mox.ConfigDynamicPath = filepath.FromSlash("config/domains.conf")

	mox.Conf.DynamicLastCheck = time.Now() // Prevent error logging by Make calls below.

	accountConf := admin.MakeAccountConfig(addr)
	const withMTASTS = true
	confDomain, keyPaths, err := admin.MakeDomainConfig(context.Background(), domain, dnshostname, accountName, withMTASTS)
	if err != nil {
		fatalf("making domain config: %s", err)
	}
	cleanupPaths = append(cleanupPaths, keyPaths...)

	dc.Domains = map[string]config.Domain{
		domain.Name(): confDomain,
	}
	dc.Accounts = map[string]config.Account{
		accountName: accountConf,
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
	xwritefile(filepath.FromSlash("config/mox.conf"), []byte(confstr), 0660)

	// Generate domains config, and add a commented out example for delivery to a mailing list.
	var db bytes.Buffer
	if err := sconf.WriteDocs(&db, &dc); err != nil {
		fatalf("generating domains config: %v", err)
	}

	// This approach is a bit horrible, but it generates a convenient
	// example that includes the comments. Though it is gone by the first
	// write of the file by mox.
	odests := fmt.Sprintf("\t\tDestinations:\n\t\t\t%s: nil\n", addr.String())
	var destsExample = struct {
		Destinations map[string]config.Destination
	}{
		Destinations: map[string]config.Destination{
			addr.String(): {
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
	ndests := odests + "# If you receive email from mailing lists, you may want to configure them like the\n# example below (remove the empty/false SMTPMailRegexp and IsForward).\n# If you are receiving forwarded email, see the IsForwarded option in a Ruleset.\n"
	for _, line := range strings.Split(destBuf.String(), "\n")[1:] {
		ndests += "#\t\t" + line + "\n"
	}
	dconfstr := strings.ReplaceAll(db.String(), odests, ndests)
	xwritefile(filepath.FromSlash("config/domains.conf"), []byte(dconfstr), 0660)

	// Verify config.
	loadTLSKeyCerts := !existingWebserver
	mc, errs := mox.ParseConfig(context.Background(), c.log, filepath.FromSlash("config/mox.conf"), true, loadTLSKeyCerts, false)
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

	acc, _, _, err := store.OpenEmail(c.log, args[0], false)
	if err != nil {
		fatalf("open account: %s", err)
	}
	cleanupPaths = append(cleanupPaths, dataDir, filepath.Join(dataDir, "accounts"), filepath.Join(dataDir, "accounts", accountName), filepath.Join(dataDir, "accounts", accountName, "index.db"))

	password := mox.GeneratePassword()

	// Kludge to cause no logging to be printed about setting a new password.
	loglevel := mox.Conf.Log[""]
	mox.Conf.Log[""] = mlog.LevelWarn
	mlog.SetConfig(mox.Conf.Log)
	if err := acc.SetPassword(c.log, password); err != nil {
		fatalf("setting password: %s", err)
	}
	mox.Conf.Log[""] = loglevel
	mlog.SetConfig(mox.Conf.Log)

	if err := acc.Close(); err != nil {
		fatalf("closing account: %s", err)
	}
	fmt.Printf("IMAP, SMTP submission and HTTP account password for %s: %s\n\n", args[0], password)
	fmt.Printf(`When configuring your email client, use the email address as username. If
autoconfig/autodiscover does not work, use these settings:
`)
	printClientConfig(domain)

	if existingWebserver {
		fmt.Printf(`
Configuration files have been written to config/mox.conf and
config/domains.conf.

Create the DNS records below, by adding them to your zone file or through the
web interface of your DNS operator. The admin interface can show these same
records, and has a page to check they have been configured correctly.

You must configure your existing webserver to forward requests for:

	https://mta-sts.%s/
	https://autoconfig.%s/

To mox, at:

	http://127.0.0.1:81

If it makes it easier to get a TLS certificate for %s, you can add a
reverse proxy for that hostname too.

You must edit mox.conf and configure the paths to the TLS certificates and keys.
The paths are relative to config/ directory that holds mox.conf! To test if your
config is valid, run:

	./mox config test

The DNS records to add:
`, domain.ASCII, domain.ASCII, dnshostname.ASCII)
	} else {
		fmt.Printf(`
Configuration files have been written to config/mox.conf and
config/domains.conf. You should review them. Then create the DNS records below,
by adding them to your zone file or through the web interface of your DNS
operator. You can also skip creating the DNS records and start mox immediately.
The admin interface can show these same records, and has a page to check they
have been configured correctly. The DNS records to add:
`)
	}

	// We do not verify the records exist: If they don't exist, we would only be
	// priming dns caches with negative/absent records, causing our "quick setup" to
	// appear to fail or take longer than "quick".

	records, err := admin.DomainRecords(confDomain, domain, domainDNSSECResult.Authentic, "letsencrypt.org", "")
	if err != nil {
		fatalf("making required DNS records")
	}
	fmt.Print("\n\n" + strings.Join(records, "\n") + "\n\n\n\n")

	fmt.Printf(`WARNING: The configuration and DNS records above assume you do not currently
have email configured for your domain. If you do already have email configured,
or if you are sending email for your domain from other machines/services, you
should understand the consequences of the DNS records above before
continuing!
`)
	if os.Getenv("MOX_DOCKER") == "" {
		fmt.Printf(`
You can now start mox with "./mox serve", as root.
`)
	} else {
		fmt.Printf(`
You can now start the mox container.
`)
	}
	fmt.Printf(`
File ownership and permissions are automatically set correctly by mox when
starting up. On linux, you may want to enable mox as a systemd service.

`)

	// For now, we only give service config instructions for linux when not running in docker.
	if runtime.GOOS == "linux" && os.Getenv("MOX_DOCKER") == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Printf("current working directory: %v", err)
			pwd = "/home/mox"
		}
		service := strings.ReplaceAll(moxService, "/home/mox", pwd)
		xwritefile("mox.service", []byte(service), 0644)
		cleanupPaths = append(cleanupPaths, "mox.service")
		fmt.Printf(`See mox.service for a systemd service file. To enable and start:

	sudo chmod 644 mox.service
	sudo systemctl enable $PWD/mox.service
	sudo systemctl start mox.service
	sudo journalctl -f -u mox.service # See logs
`)
	}

	fmt.Printf(`
After starting mox, the web interfaces are served at:

http://localhost/         - account (email address as username)
http://localhost/webmail/ - webmail (email address as username)
http://localhost/admin/   - admin (empty username)

To access these from your browser, run
"ssh -L 8080:localhost:80 you@yourmachine" locally and open
http://localhost:8080/[...].

If you run into problem, have questions/feedback or found a bug, please let us
know. Mox needs your help!

Enjoy!
`)

	if !existingWebserver {
		fmt.Printf(`
PS: If you want to run mox along side an existing webserver that uses port 443
and 80, see "mox help quickstart" with the -existing-webserver option.
`)
	}

	cleanupPaths = nil
}
