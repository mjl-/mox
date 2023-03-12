package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sconf"
	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/http"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/spf"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
	"github.com/mjl-/mox/updates"
)

var (
	changelogDomain = "xmox.nl"
	changelogURL    = "https://updates.xmox.nl/changelog"
	changelogPubKey = base64Decode("sPNiTDQzvb4FrytNEiebJhgyQzn57RwEjNbGWMM/bDY=")
)

func base64Decode(s string) []byte {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return buf
}

func envString(k, def string) string {
	s := os.Getenv(k)
	if s == "" {
		return def
	}
	return s
}

var commands = []struct {
	cmd string
	fn  func(c *cmd)
}{
	{"serve", cmdServe},
	{"quickstart", cmdQuickstart},
	{"stop", cmdStop},
	{"setaccountpassword", cmdSetaccountpassword},
	{"setadminpassword", cmdSetadminpassword},
	{"loglevels", cmdLoglevels},
	{"queue list", cmdQueueList},
	{"queue kick", cmdQueueKick},
	{"queue drop", cmdQueueDrop},
	{"queue dump", cmdQueueDump},
	{"import maildir", cmdImportMaildir},
	{"import mbox", cmdImportMbox},
	{"export maildir", cmdExportMaildir},
	{"export mbox", cmdExportMbox},
	{"localserve", cmdLocalserve},
	{"help", cmdHelp},

	{"config test", cmdConfigTest},
	{"config dnscheck", cmdConfigDNSCheck},
	{"config dnsrecords", cmdConfigDNSRecords},
	{"config describe-domains", cmdConfigDescribeDomains},
	{"config describe-static", cmdConfigDescribeStatic},
	{"config account add", cmdConfigAccountAdd},
	{"config account rm", cmdConfigAccountRemove},
	{"config address add", cmdConfigAddressAdd},
	{"config address rm", cmdConfigAddressRemove},
	{"config domain add", cmdConfigDomainAdd},
	{"config domain rm", cmdConfigDomainRemove},
	{"config describe-sendmail", cmdConfigDescribeSendmail},
	{"config printservice", cmdConfigPrintservice},
	{"example", cmdExample},

	{"checkupdate", cmdCheckupdate},
	{"cid", cmdCid},
	{"clientconfig", cmdClientConfig},
	{"deliver", cmdDeliver},
	{"dkim gened25519", cmdDKIMGened25519},
	{"dkim genrsa", cmdDKIMGenrsa},
	{"dkim lookup", cmdDKIMLookup},
	{"dkim txt", cmdDKIMTXT},
	{"dkim verify", cmdDKIMVerify},
	{"dkim sign", cmdDKIMSign},
	{"dmarc lookup", cmdDMARCLookup},
	{"dmarc parsereportmsg", cmdDMARCParsereportmsg},
	{"dmarc verify", cmdDMARCVerify},
	{"dnsbl check", cmdDNSBLCheck},
	{"dnsbl checkhealth", cmdDNSBLCheckhealth},
	{"mtasts lookup", cmdMTASTSLookup},
	{"retrain", cmdRetrain},
	{"sendmail", cmdSendmail},
	{"spf check", cmdSPFCheck},
	{"spf lookup", cmdSPFLookup},
	{"spf parse", cmdSPFParse},
	{"tlsrpt lookup", cmdTLSRPTLookup},
	{"tlsrpt parsereportmsg", cmdTLSRPTParsereportmsg},
	{"version", cmdVersion},

	// Not listed.
	{"helpall", cmdHelpall},
	{"junk analyze", cmdJunkAnalyze},
	{"junk check", cmdJunkCheck},
	{"junk play", cmdJunkPlay},
	{"junk test", cmdJunkTest},
	{"junk train", cmdJunkTrain},
	{"bumpuidvalidity", cmdBumpUIDValidity},
	{"dmarcdb addreport", cmdDMARCDBAddReport},
	{"ensureparsed", cmdEnsureParsed},
	{"message parse", cmdMessageParse},
	{"tlsrptdb addreport", cmdTLSRPTDBAddReport},
	{"updates addsigned", cmdUpdatesAddSigned},
	{"updates genkey", cmdUpdatesGenkey},
	{"updates pubkey", cmdUpdatesPubkey},
	{"updates serve", cmdUpdatesServe},
	{"updates verify", cmdUpdatesVerify},
}

var cmds []cmd

func init() {
	for _, xc := range commands {
		c := cmd{words: strings.Split(xc.cmd, " "), fn: xc.fn}
		cmds = append(cmds, c)
	}
}

type cmd struct {
	words []string
	fn    func(c *cmd)

	// Set before calling command.
	flag     *flag.FlagSet
	flagArgs []string
	_gather  bool // Set when using Parse to gather usage for a command.

	// Set by invoked command or Parse.
	unlisted bool   // If set, command is not listed until at least some words are matched from command.
	params   string // Arguments to command. Multiple lines possible.
	help     string // Additional explanation. First line is synopsis, the rest is only printed for an explicit help/usage for that command.
	args     []string
}

func (c *cmd) Parse() []string {
	// To gather params and usage information, we just run the command but cause this
	// panic after the command has registered its flags and set its params and help
	// information. This is then caught and that info printed.
	if c._gather {
		panic("gather")
	}

	c.flag.Usage = c.Usage
	c.flag.Parse(c.flagArgs)
	c.args = c.flag.Args()
	return c.args
}

func (c *cmd) gather() {
	c.flag = flag.NewFlagSet("mox "+strings.Join(c.words, " "), flag.ExitOnError)
	c._gather = true
	defer func() {
		x := recover()
		// panic generated by Parse.
		if x != "gather" {
			panic(x)
		}
	}()
	c.fn(c)
}

func (c *cmd) makeUsage() string {
	var r strings.Builder
	cs := "mox " + strings.Join(c.words, " ")
	for i, line := range strings.Split(strings.TrimSpace(c.params), "\n") {
		s := ""
		if i == 0 {
			s = "usage:"
		}
		if line != "" {
			line = " " + line
		}
		fmt.Fprintf(&r, "%6s %s%s\n", s, cs, line)
	}
	c.flag.SetOutput(&r)
	c.flag.PrintDefaults()
	return r.String()
}

func (c *cmd) printUsage() {
	fmt.Fprint(os.Stderr, c.makeUsage())
	if c.help != "" {
		fmt.Fprint(os.Stderr, "\n"+c.help+"\n")
	}
}

func (c *cmd) Usage() {
	c.printUsage()
	os.Exit(2)
}

func cmdHelp(c *cmd) {
	c.params = "[command ...]"
	c.help = `Prints help about matching commands.

If multiple commands match, they are listed along with the first line of their help text.
If a single command matches, its usage and full help text is printed.
`
	args := c.Parse()
	if len(args) == 0 {
		c.Usage()
	}

	equal := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	prefix := func(l, pre []string) bool {
		if len(pre) > len(l) {
			return false
		}
		return equal(pre, l[:len(pre)])
	}

	var partial []cmd
	for _, c := range cmds {
		if equal(c.words, args) {
			c.gather()
			fmt.Print(c.makeUsage())
			if c.help != "" {
				fmt.Print("\n" + c.help + "\n")
			}
			return
		} else if prefix(c.words, args) {
			partial = append(partial, c)
		}
	}
	if len(partial) == 0 {
		fmt.Fprintf(os.Stderr, "%s: unknown command\n", strings.Join(args, " "))
		os.Exit(2)
	}
	for _, c := range partial {
		c.gather()
		line := "mox " + strings.Join(c.words, " ")
		fmt.Printf("%s\n", line)
		if c.help != "" {
			fmt.Printf("\t%s\n", strings.Split(c.help, "\n")[0])
		}
	}
}

func cmdHelpall(c *cmd) {
	c.unlisted = true
	c.help = `Print all detailed usage and help information for all listed commands.

Used to generate documentation.
`
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	n := 0
	for _, c := range cmds {
		c.gather()
		if c.unlisted {
			continue
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "\n")
		}
		n++

		fmt.Fprintf(os.Stderr, "# mox %s\n\n", strings.Join(c.words, " "))
		if c.help != "" {
			fmt.Println(c.help + "\n")
		}
		s := c.makeUsage()
		s = "\t" + strings.ReplaceAll(s, "\n", "\n\t")
		fmt.Println(s)
	}
}

func usage(l []cmd, unlisted bool) {
	var lines []string
	if !unlisted {
		lines = append(lines, "mox [-config config/mox.conf] [-pedantic] ...")
	}
	for _, c := range l {
		c.gather()
		if c.unlisted && !unlisted {
			continue
		}
		for _, line := range strings.Split(c.params, "\n") {
			x := append([]string{"mox"}, c.words...)
			if line != "" {
				x = append(x, line)
			}
			lines = append(lines, strings.Join(x, " "))
		}
	}
	for i, line := range lines {
		pre := "       "
		if i == 0 {
			pre = "usage: "
		}
		fmt.Fprintln(os.Stderr, pre+line)
	}
	os.Exit(2)
}

var loglevel string
var pedantic bool

// subcommands that are not "serve" should use this function to load the config, it
// restores any loglevel specified on the command-line, instead of using the
// loglevels from the config file.
func mustLoadConfig() {
	mox.MustLoadConfig(false)
	if level, ok := mlog.Levels[loglevel]; ok && loglevel != "" {
		mox.Conf.Log[""] = level
		mlog.SetConfig(mox.Conf.Log)
	}
	if pedantic {
		moxvar.Pedantic = true
	}
}

func main() {
	log.SetFlags(0)

	// If invoked as sendmail, e.g. /usr/sbin/sendmail, we do enough so cron can get a
	// message sent using smtp submission to a configured server.
	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "sendmail" {
		c := &cmd{
			flag:     flag.NewFlagSet("sendmail", flag.ExitOnError),
			flagArgs: os.Args[1:],
		}
		cmdSendmail(c)
		return
	}

	flag.StringVar(&mox.ConfigStaticPath, "config", envString("MOXCONF", "config/mox.conf"), "configuration file, other config files are looked up in the same directory, defaults to $MOXCONF with a fallback to mox.conf")
	flag.StringVar(&loglevel, "loglevel", "", "if non-empty, this log level is set early in startup")
	flag.BoolVar(&pedantic, "pedantic", false, "protocol violations result in errors instead of accepting/working around them")

	flag.Usage = func() { usage(cmds, false) }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage(cmds, false)
	}
	if pedantic {
		moxvar.Pedantic = true
	}

	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	if level, ok := mlog.Levels[loglevel]; ok && loglevel != "" {
		mox.Conf.Log[""] = level
		mlog.SetConfig(mox.Conf.Log)
		// note: SetConfig may be called again when subcommands loads config.
	}

	var partial []cmd
next:
	for _, c := range cmds {
		for i, w := range c.words {
			if i >= len(args) || w != args[i] {
				if i > 0 {
					partial = append(partial, c)
				}
				continue next
			}
		}
		c.flag = flag.NewFlagSet("mox "+strings.Join(c.words, " "), flag.ExitOnError)
		c.flagArgs = args[len(c.words):]
		c.fn(&c)
		return
	}
	if len(partial) > 0 {
		usage(partial, true)
	}
	usage(cmds, false)
}

func xcheckf(err error, format string, args ...any) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log.Fatalf("%s: %s", msg, err)
}

func xparseIP(s, what string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		log.Fatalf("invalid %s: %q", what, s)
	}
	return ip
}

func xparseDomain(s, what string) dns.Domain {
	d, err := dns.ParseDomain(s)
	xcheckf(err, "parsing %s %q", what, s)
	return d
}

func cmdClientConfig(c *cmd) {
	c.params = "domain"
	c.help = `Print the configuration for email clients for a domain.

Sending email is typically not done on the SMTP port 25, but on submission
ports 465 (with TLS) and 587 (without initial TLS, but usually added to the
connection with STARTTLS). For IMAP, the port with TLS is 993 and without is
143.

Without TLS/STARTTLS, passwords are sent in clear text, which should only be
configured over otherwise secured connections, like a VPN.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	d := xparseDomain(args[0], "domain")
	mustLoadConfig()
	printClientConfig(d)
}

func printClientConfig(d dns.Domain) {
	cc, err := mox.ClientConfigDomain(d)
	xcheckf(err, "getting client config")
	fmt.Printf("%-20s %-30s %5s %-15s %s\n", "Protocol", "Host", "Port", "Listener", "Note")
	for _, e := range cc.Entries {
		fmt.Printf("%-20s %-30s %5d %-15s %s\n", e.Protocol, e.Host, e.Port, e.Listener, e.Note)
	}
}

func cmdConfigTest(c *cmd) {
	c.help = `Parses and validates the configuration files.

If valid, the command exits with status 0. If not valid, all errors encountered
are printed.
`
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	_, errs := mox.ParseConfig(context.Background(), mox.ConfigStaticPath, true, false, false)
	if len(errs) > 1 {
		log.Printf("multiple errors:")
		for _, err := range errs {
			log.Printf("%s", err)
		}
		os.Exit(1)
	} else if len(errs) == 1 {
		log.Fatalf("%s", errs[0])
		os.Exit(1)
	}
	fmt.Println("config OK")
}

func cmdConfigDescribeStatic(c *cmd) {
	c.params = ">mox.conf"
	c.help = `Prints an annotated empty configuration for use as mox.conf.

The static configuration file cannot be reloaded while mox is running. Mox has
to be restarted for changes to the static configuration file to take effect.

This configuration file needs modifications to make it valid. For example, it
may contain unfinished list items.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	var sc config.Static
	err := sconf.Describe(os.Stdout, &sc)
	xcheckf(err, "describing config")
}

func cmdConfigDescribeDomains(c *cmd) {
	c.params = ">domains.conf"
	c.help = `Prints an annotated empty configuration for use as domains.conf.

The domains configuration file contains the domains and their configuration,
and accounts and their configuration. This includes the configured email
addresses. The mox admin web interface, and the mox command line interface, can
make changes to this file. Mox automatically reloads this file when it changes.

Like the static configuration, the example domains.conf printed by this command
needs modifications to make it valid.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	var dc config.Dynamic
	err := sconf.Describe(os.Stdout, &dc)
	xcheckf(err, "describing config")
}

func cmdConfigPrintservice(c *cmd) {
	c.params = ">mox.service"
	c.help = `Prints a systemd unit service file for mox.

This is the same file as generated using quickstart. If the systemd service file
has changed with a newer version of mox, use this command to generate an up to
date version.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	pwd, err := os.Getwd()
	if err != nil {
		log.Printf("current working directory: %v", err)
		pwd = "/home/mox"
	}
	service := strings.ReplaceAll(moxService, "/home/mox", pwd)
	fmt.Print(service)
}

func cmdConfigDomainAdd(c *cmd) {
	c.params = "domain account [localpart]"
	c.help = `Adds a new domain to the configuration and reloads the configuration.

The account is used for the postmaster mailboxes the domain, including as DMARC and
TLS reporting. Localpart is the "username" at the domain for this account. If
must be set if and only if account does not yet exist.
`
	args := c.Parse()
	if len(args) != 2 && len(args) != 3 {
		c.Usage()
	}

	d := xparseDomain(args[0], "domain")
	mustLoadConfig()

	if len(args) == 2 {
		args = append(args, "")
	}
	ctl := xctl()
	ctl.xwrite("domainadd")
	for _, s := range args {
		ctl.xwrite(s)
	}
	ctl.xreadok()
	fmt.Printf("domain added, remember to add dns records, see:\n\nmox config dnsrecords %s\nmox config dnscheck %s\n", d.Name(), d.Name())
}

func cmdConfigDomainRemove(c *cmd) {
	c.params = "domain"
	c.help = `Remove a domain from the configuration and reload the configuration.

This is a dangerous operation. Incoming email delivery for this domain will be
rejected.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	d := xparseDomain(args[0], "domain")
	mustLoadConfig()
	ctl := xctl()
	ctl.xwrite("domainrm")
	ctl.xwrite(args[0])
	ctl.xreadok()
	fmt.Printf("domain removed, remember to remove dns records for %s\n", d)
}

func cmdConfigAccountAdd(c *cmd) {
	c.params = "account address"
	c.help = `Add an account with an email address and reload the configuration.

Email can be delivered to this address/account. A password has to be configured
explicitly, see the setaccountpassword command.
`
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}

	mustLoadConfig()
	ctl := xctl()
	ctl.xwrite("accountadd")
	for _, s := range args {
		ctl.xwrite(s)
	}
	ctl.xreadok()
	fmt.Printf("account added, set a password with \"mox setaccountpassword %s\"\n", args[1])
}

func cmdConfigAccountRemove(c *cmd) {
	c.params = "account"
	c.help = `Remove an account and reload the configuration.

Email addresses for this account will also be removed, and incoming email for
these addresses will be rejected.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctl := xctl()
	ctl.xwrite("accountrm")
	ctl.xwrite(args[0])
	ctl.xreadok()
	fmt.Println("account removed")
}

func cmdConfigAddressAdd(c *cmd) {
	c.params = "address account"
	c.help = "Adds an address to an account and reloads the configuration."
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}

	mustLoadConfig()
	ctl := xctl()
	ctl.xwrite("addressadd")
	for _, s := range args {
		ctl.xwrite(s)
	}
	ctl.xreadok()
	fmt.Println("address added")
}

func cmdConfigAddressRemove(c *cmd) {
	c.params = "address"
	c.help = `Remove an address and reload the configuration.

Incoming email for this address will be rejected.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctl := xctl()
	ctl.xwrite("addressrm")
	ctl.xwrite(args[0])
	ctl.xreadok()
	fmt.Println("address removed")
}

func cmdConfigDNSRecords(c *cmd) {
	c.params = "domain"
	c.help = `Prints annotated DNS records as zone file that should be created for the domain.

The zone file can be imported into existing DNS software. You should review the
DNS records, especially if your domain previously/currently has email
configured.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	d := xparseDomain(args[0], "domain")
	mustLoadConfig()
	domConf, ok := mox.Conf.Domain(d)
	if !ok {
		log.Fatalf("unknown domain")
	}
	records, err := mox.DomainRecords(domConf, d)
	xcheckf(err, "records")
	fmt.Print(strings.Join(records, "\n") + "\n")
}

func cmdConfigDNSCheck(c *cmd) {
	c.params = "domain"
	c.help = "Check the DNS records with the configuration for the domain, and print any errors/warnings."
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	d := xparseDomain(args[0], "domain")
	mustLoadConfig()
	_, ok := mox.Conf.Domain(d)
	if !ok {
		log.Fatalf("unknown domain")
	}

	// todo future: move http.Admin.CheckDomain to mox- and make it return a regular error.
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		err, ok := x.(*sherpa.Error)
		if !ok {
			panic(x)
		}
		log.Fatalf("%s", err)
	}()

	printResult := func(name string, r http.Result) {
		if len(r.Errors) == 0 && len(r.Warnings) == 0 {
			return
		}
		fmt.Printf("# %s\n", name)
		for _, s := range r.Errors {
			fmt.Printf("error: %s\n", s)
		}
		for _, s := range r.Warnings {
			fmt.Printf("warning: %s\n", s)
		}
	}

	result := http.Admin{}.CheckDomain(context.Background(), args[0])
	printResult("IPRev", result.IPRev.Result)
	printResult("MX", result.MX.Result)
	printResult("TLS", result.TLS.Result)
	printResult("SPF", result.SPF.Result)
	printResult("DKIM", result.DKIM.Result)
	printResult("DMARC", result.DMARC.Result)
	printResult("TLSRPT", result.TLSRPT.Result)
	printResult("MTASTS", result.MTASTS.Result)
	printResult("SRVConf", result.SRVConf.Result)
	printResult("Autoconf", result.Autoconf.Result)
	printResult("Autodiscover", result.Autodiscover.Result)
}

var examples = []struct {
	Name string
	Get  func() string
}{
	{
		"webhandlers",
		func() string {
			const webhandlers = `# Snippet of domains.conf to configure WebDomainRedirects and WebHandlers.

# Redirect all requests for mox.example to https://www.mox.example.
WebDomainRedirects:
	mox.example: www.mox.example

# Each request is matched against these handlers until one matches and serves it.
WebHandlers:
	-
		# Redirect all plain http requests to https, leaving path, query strings, etc
		# intact. When the request is already to https, the destination URL would have the
		# same scheme, host and path, causing this redirect handler to not match the
		# request (and not cause a redirect loop) and the webserver to serve the request
		# with a later handler.
		LogName: redirhttps
		Domain: www.mox.example
		PathRegexp: ^/
		# Could leave DontRedirectPlainHTTP at false if it wasn't for this being an
		# example for doing this redirect.
		DontRedirectPlainHTTP: true
		WebRedirect:
			BaseURL: https://www.mox.example
	-
		# The name of the handler, used in logging and metrics.
		LogName: staticmjl
		# With ACME configured, each configured domain will automatically get a TLS
		# certificate on first request.
		Domain: www.mox.example
		PathRegexp: ^/who/mjl/
		WebStatic:
			StripPrefix: /who/mjl
			# Requested path /who/mjl/inferno/ resolves to local web/mjl/inferno.
			# If a directory contains an index.html, it is served when a directory is requested.
			Root: web/mjl
			# With ListFiles true, if a directory does not contain an index.html, the contents are listed.
			ListFiles: true
			ResponseHeaders:
				X-Mox: hi
	-
		LogName: redir
		Domain: www.mox.example
		PathRegexp: ^/redir/a/b/c
		# Don't redirect from plain HTTP to HTTPS.
		DontRedirectPlainHTTP: true
		WebRedirect:
			# Just change the domain and add query string set fragment. No change to scheme.
			# Path will start with /redir/a/b/c (and whathever came after) because no
			# OrigPathRegexp+ReplacePath is set.
			BaseURL: //moxest.example?q=1#frag
			# Default redirection is 308 - Permanent Redirect.
			StatusCode: 307
	-
		LogName: oldnew
		Domain: www.mox.example
		PathRegexp: ^/old/
		WebRedirect:
			# Replace path, leaving rest of URL intact.
			OrigPathRegexp: ^/old/(.*)
			ReplacePath: /new/$1
	-
		LogName: app
		Domain: www.mox.example
		PathRegexp: ^/app/
		WebForward:
			# Strip the path matched by PathRegexp before forwarding the request. So original
			# request /app/api become just /api.
			StripPath: true
			# URL of backend, where requests are forwarded to. The path in the URL is kept,
			# so for incoming request URL /app/api, the outgoing request URL has path /app-v2/api.
			# Requests are made with Go's net/http DefaultTransporter, including using
			# HTTP_PROXY and HTTPS_PROXY environment variables.
			URL: http://127.0.0.1:8900/app-v2/
			# Add headers to response.
			ResponseHeaders:
				X-Frame-Options: deny
				X-Content-Type-Options: nosniff
`
			// Parse just so we know we have the syntax right.
			// todo: ideally we would have a complete config file and parse it fully.
			var conf struct {
				WebDomainRedirects map[string]string
				WebHandlers        []config.WebHandler
			}
			err := sconf.Parse(strings.NewReader(webhandlers), &conf)
			xcheckf(err, "parsing webhandlers example")
			return webhandlers
		},
	},
}

func cmdExample(c *cmd) {
	c.params = "[name]"
	c.help = `List available examples, or print a specific example.`

	args := c.Parse()
	if len(args) > 1 {
		c.Usage()
	}

	var match func() string
	for _, ex := range examples {
		if len(args) == 0 {
			fmt.Println(ex.Name)
		} else if args[0] == ex.Name {
			match = ex.Get
		}
	}
	if len(args) == 0 {
		return
	}
	if match == nil {
		log.Fatalln("not found")
	}
	fmt.Print(match())
}

func cmdLoglevels(c *cmd) {
	c.params = "[level [pkg]]"
	c.help = `Print the log levels, or set a new default log level, or a level for the given package.

By default, a single log level applies to all logging in mox. But for each
"pkg", an overriding log level can be configured. Examples of packages:
smtpserver, smtpclient, queue, imapserver, spf, dkim, dmarc, junk, message,
etc.

Specify a pkg and an empty level to clear the configured level for a package.

Valid labels: error, info, debug, trace, traceauth, tracedata.
`
	args := c.Parse()
	if len(args) > 2 {
		c.Usage()
	}
	mustLoadConfig()

	if len(args) == 0 {
		ctl := xctl()
		ctl.xwrite("loglevels")
		ctl.xreadok()
		ctl.xstreamto(os.Stdout)
		return
	}

	ctl := xctl()
	ctl.xwrite("setloglevels")
	if len(args) == 2 {
		ctl.xwrite(args[1])
	} else {
		ctl.xwrite("")
	}
	ctl.xwrite(args[0])
	ctl.xreadok()
}

func cmdStop(c *cmd) {
	c.help = `Shut mox down, giving connections maximum 3 seconds to stop before closing them.

While shutting down, new IMAP and SMTP connections will get a status response
indicating temporary unavailability. Existing connections will get a 3 second
period to finish their transaction and shut down. Under normal circumstances,
only IMAP has long-living connections, with the IDLE command to get notified of
new mail deliveries.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()

	ctl := xctl()
	ctl.xwrite("stop")
	// Read will hang until remote has shut down.
	buf := make([]byte, 128)
	n, err := ctl.conn.Read(buf)
	if err == nil {
		log.Fatalf("expected eof after graceful shutdown, got data %q", buf[:n])
	} else if err != io.EOF {
		log.Fatalf("expected eof after graceful shutdown, got error %v", err)
	}
	fmt.Println("mox stopped")
}

func cmdSetadminpassword(c *cmd) {
	c.help = `Set a new admin password, for the web interface.

The password is read from stdin. Its bcrypt hash is stored in a file named
"adminpasswd" in the configuration directory.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()

	path := mox.ConfigDirPath(mox.Conf.Static.AdminPasswordFile)
	if path == "" {
		log.Fatal("no admin password file configured")
	}

	pw := xreadpassword()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	xcheckf(err, "generating hash for password")
	err = os.WriteFile(path, hash, 0660)
	xcheckf(err, "writing hash to admin password file")
}

func xreadpassword() string {
	fmt.Printf(`
Type new password. Password WILL echo.

WARNING: Bots will try to bruteforce your password. Connections with failed
authentication attempts will be rate limited but attackers WILL find weak
passwords. If your account is compromised, spammers are likely to abuse your
system, spamming your address and the wider internet in your name. So please
pick a random, unguessable password, preferrably at least 12 characters.

`)
	fmt.Printf("password: ")
	buf := make([]byte, 64)
	n, err := os.Stdin.Read(buf)
	xcheckf(err, "reading stdin")
	pw := string(buf[:n])
	pw = strings.TrimSuffix(strings.TrimSuffix(pw, "\r\n"), "\n")
	if len(pw) < 8 {
		log.Fatal("password must be at least 8 characters")
	}
	return pw
}

func cmdSetaccountpassword(c *cmd) {
	c.params = "address"
	c.help = `Set new password an account.

The password is read from stdin. Secrets derived from the password, but not the
password itself, are stored in the account database. The stored secrets are for
authentication with: scram-sha-256, scram-sha-1, cram-md5, plain text (bcrypt
hash).

Any email address configured for the account can be used.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()

	pw := xreadpassword()

	ctl := xctl()
	ctl.xwrite("setaccountpassword")
	ctl.xwrite(args[0])
	ctl.xwrite(pw)
	ctl.xreadok()
}

func cmdDeliver(c *cmd) {
	c.unlisted = true
	c.params = "address < message"
	c.help = "Deliver message to address."
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()

	ctl := xctl()
	ctl.xwrite("deliver")
	ctl.xwrite(args[0])
	ctl.xreadok()
	ctl.xstreamfrom(os.Stdin)
	line := ctl.xread()
	if line == "ok" {
		fmt.Println("message delivered")
	} else {
		log.Fatalf("deliver: %s", line)
	}
}

func cmdQueueList(c *cmd) {
	c.help = `List messages in the delivery queue.

This prints the message with its ID, last and next delivery attempts, last
error.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()

	ctl := xctl()
	ctl.xwrite("queue")
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueKick(c *cmd) {
	c.params = "[-id id] [-todomain domain] [-recipient address]"
	c.help = `Schedule matching messages in the queue for immediate delivery.

Messages deliveries are normally attempted with exponential backoff. The first
retry after 7.5 minutes, and doubling each time. Kicking messages sets their
next scheduled attempt to now, it can cause delivery to fail earlier than
without rescheduling.
`
	var id int64
	var todomain, recipient string
	c.flag.Int64Var(&id, "id", 0, "id of message in queue")
	c.flag.StringVar(&todomain, "todomain", "", "destination domain of messages")
	c.flag.StringVar(&recipient, "recipient", "", "recipient email address")
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()

	ctl := xctl()
	ctl.xwrite("queuekick")
	ctl.xwrite(fmt.Sprintf("%d", id))
	ctl.xwrite(todomain)
	ctl.xwrite(recipient)
	count := ctl.xread()
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s messages scheduled\n", count)
	} else {
		log.Fatalf("scheduling messages for immediate delivery: %s", line)
	}
}

func cmdQueueDrop(c *cmd) {
	c.params = "[-id id] [-todomain domain] [-recipient address]"
	c.help = `Remove matching messages from the queue.

Dangerous operation, this completely removes the message. If you want to store
the message, use "queue dump" before removing.
`
	var id int64
	var todomain, recipient string
	c.flag.Int64Var(&id, "id", 0, "id of message in queue")
	c.flag.StringVar(&todomain, "todomain", "", "destination domain of messages")
	c.flag.StringVar(&recipient, "recipient", "", "recipient email address")
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()

	ctl := xctl()
	ctl.xwrite("queuedrop")
	ctl.xwrite(fmt.Sprintf("%d", id))
	ctl.xwrite(todomain)
	ctl.xwrite(recipient)
	count := ctl.xread()
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s messages dropped\n", count)
	} else {
		log.Fatalf("scheduling messages for immediate delivery: %s", line)
	}
}

func cmdQueueDump(c *cmd) {
	c.params = "id"
	c.help = `Dump a message from the queue.

The message is printed to stdout and is in standard internet mail format.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()

	ctl := xctl()
	ctl.xwrite("queuedump")
	ctl.xwrite(args[0])
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdDKIMGenrsa(c *cmd) {
	c.params = ">$selector._domainkey.$domain.rsakey.pkcs8.pem"
	c.help = `Generate a new 2048 bit RSA private key for use with DKIM.

The generated file is in PEM format, and has a comment it is generated for use
with DKIM, by mox.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	buf, err := mox.MakeDKIMRSAKey(dns.Domain{}, dns.Domain{})
	xcheckf(err, "making rsa private key")
	_, err = os.Stdout.Write(buf)
	xcheckf(err, "writing rsa private key")
}

func cmdDKIMGened25519(c *cmd) {
	c.params = ">$selector._domainkey.$domain.ed25519key.pkcs8.pem"
	c.help = `Generate a new ed25519 key for use with DKIM.

Ed25519 keys are much smaller than RSA keys of comparable cryptographic
strength. This is convenient because of maximum DNS message sizes. At the time
of writing, not many mail servers appear to support ed25519 DKIM keys though,
so it is recommended to sign messages with both RSA and ed25519 keys.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	buf, err := mox.MakeDKIMEd25519Key(dns.Domain{}, dns.Domain{})
	xcheckf(err, "making dkim ed25519 key")
	_, err = os.Stdout.Write(buf)
	xcheckf(err, "writing dkim ed25519 key")
}

func cmdDKIMTXT(c *cmd) {
	c.params = "<$selector._domainkey.$domain.key.pkcs8.pem"
	c.help = `Print a DKIM DNS TXT record with the public key derived from the private key read from stdin.

The DNS should be configured as a TXT record at $selector._domainkey.$domain.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	privKey, err := parseDKIMKey(os.Stdin)
	xcheckf(err, "reading dkim private key from stdin")

	r := dkim.Record{
		Version: "DKIM1",
		Hashes:  []string{"sha256"},
		Flags:   []string{"s"},
	}

	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		r.PublicKey = key.Public()
	case ed25519.PrivateKey:
		r.PublicKey = key.Public()
		r.Key = "ed25519"
	default:
		log.Fatalf("unsupported private key type %T, must be rsa or ed25519", privKey)
	}

	record, err := r.Record()
	xcheckf(err, "making record")
	fmt.Print("<selector>._domainkey.<your.domain.> IN TXT ")
	for record != "" {
		s := record
		if len(s) > 255 {
			s, record = record[:255], record[255:]
		} else {
			record = ""
		}
		fmt.Printf(`"%s" `, s)
	}
	fmt.Println("")
}

func parseDKIMKey(r io.Reader) (any, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading pem from stdin: %v", err)
	}
	b, _ := pem.Decode(buf)
	if b == nil {
		return nil, fmt.Errorf("decoding pem: %v", err)
	}
	privKey, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %v", err)
	}
	return privKey, nil
}

func cmdDKIMVerify(c *cmd) {
	c.params = "message"
	c.help = `Verify the DKIM signatures in a message and print the results.

The message is parsed, and the DKIM-Signature headers are validated. Validation
of older messages may fail because the DNS records have been removed or changed
by now, or because the signature header may have specified an expiration time
that was passed.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	msgf, err := os.Open(args[0])
	xcheckf(err, "open message")

	results, err := dkim.Verify(context.Background(), dns.StrictResolver{}, false, dkim.DefaultPolicy, msgf, true)
	xcheckf(err, "dkim verify")

	for _, result := range results {
		var sigh string
		if result.Sig == nil {
			log.Printf("warning: could not parse signature")
		} else {
			sigh, err = result.Sig.Header()
			if err != nil {
				log.Printf("warning: packing signature: %s", err)
			}
		}
		var txt string
		if result.Record == nil {
			log.Printf("warning: missing DNS record")
		} else {
			txt, err = result.Record.Record()
			if err != nil {
				log.Printf("warning: packing record: %s", err)
			}
		}
		fmt.Printf("status %q, err %v\nrecord %q\nheader %s\n", result.Status, result.Err, txt, sigh)
	}
}

func cmdDKIMSign(c *cmd) {
	c.params = "message"
	c.help = `Sign a message, adding DKIM-Signature headers based on the domain in the From header.

The message is parsed, the domain looked up in the configuration files, and
DKIM-Signature headers generated. The message is printed with the DKIM-Signature
headers prepended.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	msgf, err := os.Open(args[0])
	xcheckf(err, "open message")
	defer msgf.Close()

	p, err := message.Parse(msgf)
	xcheckf(err, "parsing message")

	if len(p.Envelope.From) != 1 {
		log.Fatalf("found %d from headers, need exactly 1", len(p.Envelope.From))
	}
	localpart := smtp.Localpart(p.Envelope.From[0].User)
	dom, err := dns.ParseDomain(p.Envelope.From[0].Host)
	xcheckf(err, "parsing domain in from header")

	mustLoadConfig()

	domConf, ok := mox.Conf.Domain(dom)
	if !ok {
		log.Fatalf("domain %s not configured", dom)
	}

	headers, err := dkim.Sign(context.Background(), localpart, dom, domConf.DKIM, false, msgf)
	xcheckf(err, "signing message with dkim")
	if headers == "" {
		log.Fatalf("no DKIM configured for domain %s", dom)
	}
	_, err = fmt.Fprint(os.Stdout, headers)
	xcheckf(err, "write headers")
	_, err = io.Copy(os.Stdout, msgf)
	xcheckf(err, "write message")
}

func cmdDKIMLookup(c *cmd) {
	c.params = "selector domain"
	c.help = "Lookup and print the DKIM record for the selector at the domain."
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}

	selector := xparseDomain(args[0], "selector")
	domain := xparseDomain(args[1], "domain")

	status, record, txt, err := dkim.Lookup(context.Background(), dns.StrictResolver{}, selector, domain)
	if err != nil {
		fmt.Printf("error: %s\n", err)
	}
	if status != dkim.StatusNeutral {
		fmt.Printf("status: %s\n", status)
	}
	if txt != "" {
		fmt.Printf("TXT record: %s\n", txt)
	}
	if record != nil {
		fmt.Printf("Record:\n")
		pairs := []any{
			"version", record.Version,
			"hashes", record.Hashes,
			"key", record.Key,
			"notes", record.Notes,
			"services", record.Services,
			"flags", record.Flags,
		}
		for i := 0; i < len(pairs); i += 2 {
			fmt.Printf("\t%s: %v\n", pairs[i], pairs[i+1])
		}
	}
}

func cmdDMARCLookup(c *cmd) {
	c.params = "domain"
	c.help = "Lookup dmarc policy for domain, a DNS TXT record at _dmarc.<domain>, validate and print it."
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	fromdomain := xparseDomain(args[0], "domain")
	_, domain, _, txt, err := dmarc.Lookup(context.Background(), dns.StrictResolver{}, fromdomain)
	xcheckf(err, "dmarc lookup domain %s", fromdomain)
	fmt.Printf("dmarc record at domain %s: %s\n", domain, txt)
}

func cmdDMARCVerify(c *cmd) {
	c.params = "remoteip mailfromaddress helodomain < message"
	c.help = `Parse an email message and evaluate it against the DMARC policy of the domain in the From-header.

mailfromaddress and helodomain are used for SPF validation. If both are empty,
SPF validation is skipped.

mailfromaddress should be the address used as MAIL FROM in the SMTP session.
For DSN messages, that address may be empty. The helo domain was specified at
the beginning of the SMTP transaction that delivered the message. These values
can be found in message headers.
`
	args := c.Parse()
	if len(args) != 3 {
		c.Usage()
	}

	var heloDomain *dns.Domain

	remoteIP := xparseIP(args[0], "remoteip")

	var mailfrom *smtp.Address
	if args[1] != "" {
		a, err := smtp.ParseAddress(args[1])
		xcheckf(err, "parsing mailfrom address")
		mailfrom = &a
	}
	if args[2] != "" {
		d := xparseDomain(args[2], "helo domain")
		heloDomain = &d
	}
	var received *spf.Received
	spfStatus := spf.StatusNone
	var spfIdentity *dns.Domain
	if mailfrom != nil || heloDomain != nil {
		spfArgs := spf.Args{
			RemoteIP:      remoteIP,
			LocalIP:       net.ParseIP("127.0.0.1"),
			LocalHostname: dns.Domain{ASCII: "localhost"},
		}
		if mailfrom != nil {
			spfArgs.MailFromLocalpart = mailfrom.Localpart
			spfArgs.MailFromDomain = mailfrom.Domain
		}
		if heloDomain != nil {
			spfArgs.HelloDomain = dns.IPDomain{Domain: *heloDomain}
		}
		rspf, spfDomain, expl, err := spf.Verify(context.Background(), dns.StrictResolver{}, spfArgs)
		if err != nil {
			log.Printf("spf verify: %v (explanation: %q)", err, expl)
		} else {
			received = &rspf
			spfStatus = received.Result
			// todo: should probably potentially do two separate spf validations
			if mailfrom != nil {
				spfIdentity = &mailfrom.Domain
			} else {
				spfIdentity = heloDomain
			}
			fmt.Printf("spf result: %s: %s\n", spfDomain, spfStatus)
		}
	}

	data, err := io.ReadAll(os.Stdin)
	xcheckf(err, "read message")
	dmarcFrom, _, err := message.From(bytes.NewReader(data))
	xcheckf(err, "extract dmarc from message")

	const ignoreTestMode = false
	dkimResults, err := dkim.Verify(context.Background(), dns.StrictResolver{}, true, func(*dkim.Sig) error { return nil }, bytes.NewReader(data), ignoreTestMode)
	xcheckf(err, "dkim verify")
	for _, r := range dkimResults {
		fmt.Printf("dkim result: %q (err %v)\n", r.Status, r.Err)
	}

	_, result := dmarc.Verify(context.Background(), dns.StrictResolver{}, dmarcFrom.Domain, dkimResults, spfStatus, spfIdentity, false)
	xcheckf(result.Err, "dmarc verify")
	fmt.Printf("dmarc from: %s\ndmarc status: %q\ndmarc reject: %v\ncmarc record: %s\n", dmarcFrom, result.Status, result.Reject, result.Record)
}

func cmdDMARCParsereportmsg(c *cmd) {
	c.params = "message ..."
	c.help = `Parse a DMARC report from an email message, and print its extracted details.

DMARC reports are periodically mailed, if requested in the DMARC DNS record of
a domain. Reports are sent by mail servers that received messages with our
domain in a From header. This may or may not be legatimate email. DMARC reports
contain summaries of evaluations of DMARC and DKIM/SPF, which can help
understand email deliverability problems.
`
	args := c.Parse()
	if len(args) == 0 {
		c.Usage()
	}

	for _, arg := range args {
		f, err := os.Open(arg)
		xcheckf(err, "open %q", arg)
		feedback, err := dmarcrpt.ParseMessageReport(f)
		xcheckf(err, "parse report in %q", arg)
		meta := feedback.ReportMetadata
		fmt.Printf("Report: period %s-%s, organisation %q, reportID %q, %s\n", time.Unix(meta.DateRange.Begin, 0).UTC().String(), time.Unix(meta.DateRange.End, 0).UTC().String(), meta.OrgName, meta.ReportID, meta.Email)
		if len(meta.Errors) > 0 {
			fmt.Printf("Errors:\n")
			for _, s := range meta.Errors {
				fmt.Printf("\t- %s\n", s)
			}
		}
		pol := feedback.PolicyPublished
		fmt.Printf("Policy: domain %q, policy %q, subdomainpolicy %q, dkim %q, spf %q, percentage %d, options %q\n", pol.Domain, pol.Policy, pol.SubdomainPolicy, pol.ADKIM, pol.ASPF, pol.Percentage, pol.ReportingOptions)
		for _, record := range feedback.Records {
			idents := record.Identifiers
			fmt.Printf("\theaderfrom %q, envelopes from %q, to %q\n", idents.HeaderFrom, idents.EnvelopeFrom, idents.EnvelopeTo)
			eval := record.Row.PolicyEvaluated
			var reasons string
			for _, reason := range eval.Reasons {
				reasons += "; " + string(reason.Type)
				if reason.Comment != "" {
					reasons += fmt.Sprintf(": %q", reason.Comment)
				}
			}
			fmt.Printf("\tresult %s: dkim %s, spf %s; sourceIP %s, count %d%s\n", eval.Disposition, eval.DKIM, eval.SPF, record.Row.SourceIP, record.Row.Count, reasons)
			for _, dkim := range record.AuthResults.DKIM {
				var result string
				if dkim.HumanResult != "" {
					result = fmt.Sprintf(": %q", dkim.HumanResult)
				}
				fmt.Printf("\t\tdkim %s; domain %q selector %q%s\n", dkim.Result, dkim.Domain, dkim.Selector, result)
			}
			for _, spf := range record.AuthResults.SPF {
				fmt.Printf("\t\tspf %s; domain %q scope %q\n", spf.Result, spf.Domain, spf.Scope)
			}
		}
	}
}

func cmdDMARCDBAddReport(c *cmd) {
	c.unlisted = true
	c.params = "fromdomain < message"
	c.help = "Add a DMARC report to the database."
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()

	fromdomain := xparseDomain(args[0], "domain")
	fmt.Fprintln(os.Stderr, "reading report message from stdin")
	report, err := dmarcrpt.ParseMessageReport(os.Stdin)
	xcheckf(err, "parse message")
	err = dmarcdb.AddReport(context.Background(), report, fromdomain)
	xcheckf(err, "add dmarc report")
}

func cmdTLSRPTLookup(c *cmd) {
	c.params = "domain"
	c.help = `Lookup the TLSRPT record for the domain.

A TLSRPT record typically contains an email address where reports about TLS
connectivity should be sent. Mail servers attempting delivery to our domain
should attempt to use TLS. TLSRPT lets them report how many connection
successfully used TLS, and how what kind of errors occurred otherwise.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	d := xparseDomain(args[0], "domain")
	_, txt, err := tlsrpt.Lookup(context.Background(), dns.StrictResolver{}, d)
	xcheckf(err, "tlsrpt lookup for %s", d)
	fmt.Println(txt)
}

func cmdTLSRPTParsereportmsg(c *cmd) {
	c.params = "message ..."
	c.help = `Parse and print the TLSRPT in the message.

The report is printed in formatted JSON.
`
	args := c.Parse()
	if len(args) == 0 {
		c.Usage()
	}

	for _, arg := range args {
		f, err := os.Open(arg)
		xcheckf(err, "open %q", arg)
		report, err := tlsrpt.ParseMessage(f)
		xcheckf(err, "parse report in %q", arg)
		// todo future: only print the highlights?
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "\t")
		err = enc.Encode(report)
		xcheckf(err, "write report")
	}
}

func cmdSPFCheck(c *cmd) {
	c.params = "domain ip"
	c.help = `Check the status of IP for the policy published in DNS for the domain.

IPs may be allowed to send for a domain, or disallowed, and several shades in
between. If not allowed, an explanation may be provided by the policy. If so,
the explanation is printed. The SPF mechanism that matched (if any) is also
printed.
`
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}

	domain := xparseDomain(args[0], "domain")

	ip := xparseIP(args[1], "ip")

	spfargs := spf.Args{
		RemoteIP:          ip,
		MailFromLocalpart: "user",
		MailFromDomain:    domain,
		HelloDomain:       dns.IPDomain{Domain: domain},
		LocalIP:           net.ParseIP("127.0.0.1"),
		LocalHostname:     dns.Domain{ASCII: "localhost"},
	}
	r, _, explanation, err := spf.Verify(context.Background(), dns.StrictResolver{}, spfargs)
	if err != nil {
		fmt.Printf("error: %s\n", err)
	}
	if explanation != "" {
		fmt.Printf("explanation: %s\n", explanation)
	}
	fmt.Printf("status: %s\n", r.Result)
	if r.Mechanism != "" {
		fmt.Printf("mechanism: %s\n", r.Mechanism)
	}
}

func cmdSPFParse(c *cmd) {
	c.params = "txtrecord"
	c.help = "Parse the record as SPF record. If valid, nothing is printed."
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	_, _, err := spf.ParseRecord(args[0])
	xcheckf(err, "parsing record")
}

func cmdSPFLookup(c *cmd) {
	c.params = "domain"
	c.help = "Lookup the SPF record for the domain and print it."
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	domain := xparseDomain(args[0], "domain")
	_, txt, _, err := spf.Lookup(context.Background(), dns.StrictResolver{}, domain)
	xcheckf(err, "spf lookup for %s", domain)
	fmt.Println(txt)
}

func cmdMTASTSLookup(c *cmd) {
	c.params = "domain"
	c.help = `Lookup the MTASTS record and policy for the domain.

MTA-STS is a mechanism for a domain to specify if it requires TLS connections
for delivering email. If a domain has a valid MTA-STS DNS TXT record at
_mta-sts.<domain> it signals it implements MTA-STS. A policy can then be
fetched at https://mta-sts.<domain>/.well-known/mta-sts.txt. The policy
specifies the mode (enforce, testing, none), which MX servers support TLS and
should be used, and how long the policy can be cached.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	domain := xparseDomain(args[0], "domain")

	record, policy, err := mtasts.Get(context.Background(), dns.StrictResolver{}, domain)
	if err != nil {
		fmt.Printf("error: %s\n", err)
	}
	if record != nil {
		fmt.Printf("DNS TXT record _mta-sts.%s: %s\n", domain.ASCII, record.String())
	}
	if policy != nil {
		fmt.Println("")
		fmt.Printf("policy at https://mta-sts.%s/.well-known/mta-sts.txt:\n", domain.ASCII)
		fmt.Printf("%s", policy.String())
	}
}

func cmdRetrain(c *cmd) {
	c.params = "accountname"
	c.help = `Recreate and retrain the junk filter for the account.

Useful after having made changes to the junk filter configuration, or if the
implementation has changed.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctl := xctl()
	ctl.xwrite("retrain")
	ctl.xwrite(args[0])
	ctl.xreadok()
}

func cmdTLSRPTDBAddReport(c *cmd) {
	c.unlisted = true
	c.params = "< message"
	c.help = "Parse a TLS report from the message and add it to the database."
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	mustLoadConfig()

	// First read message, to get the From-header. Then parse it as TLSRPT.
	fmt.Fprintln(os.Stderr, "reading report message from stdin")
	buf, err := io.ReadAll(os.Stdin)
	xcheckf(err, "reading message")
	part, err := message.Parse(bytes.NewReader(buf))
	xcheckf(err, "parsing message")
	if part.Envelope == nil || len(part.Envelope.From) != 1 {
		log.Fatalf("message must have one From-header")
	}
	from := part.Envelope.From[0]
	domain := xparseDomain(from.Host, "domain")

	report, err := tlsrpt.ParseMessage(bytes.NewReader(buf))
	xcheckf(err, "parsing tls report in message")

	mailfrom := from.User + "@" + from.Host // todo future: should escape and such
	err = tlsrptdb.AddReport(context.Background(), domain, mailfrom, report)
	xcheckf(err, "add tls report to database")
}

func cmdDNSBLCheck(c *cmd) {
	c.params = "zone ip"
	c.help = `Test if IP is in the DNS blocklist of the zone, e.g. bl.spamcop.net.

If the IP is in the blocklist, an explanation is printed. This is typically a
URL with more information.
`
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}

	zone := xparseDomain(args[0], "zone")
	ip := xparseIP(args[1], "ip")

	status, explanation, err := dnsbl.Lookup(context.Background(), dns.StrictResolver{}, zone, ip)
	fmt.Printf("status: %s\n", status)
	if status == dnsbl.StatusFail {
		fmt.Printf("explanation: %q\n", explanation)
	}
	if err != nil {
		fmt.Printf("error: %s\n", err)
	}
}

func cmdDNSBLCheckhealth(c *cmd) {
	c.params = "zone"
	c.help = `Check the health of the DNS blocklist represented by zone, e.g. bl.spamcop.net.

The health of a DNS blocklist can be checked by querying for 127.0.0.1 and
127.0.0.2. The second must and the first must not be present.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	zone := xparseDomain(args[0], "zone")
	err := dnsbl.CheckHealth(context.Background(), dns.StrictResolver{}, zone)
	xcheckf(err, "unhealthy")
	fmt.Println("healthy")
}

func cmdCheckupdate(c *cmd) {
	c.help = `Check if a newer version of mox is available.

A single DNS TXT lookup to _updates.xmox.nl tells if a new version is
available. If so, a changelog is fetched from https://updates.xmox.nl, and the
individual entries validated with a builtin public key. The changelog is
printed.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()

	current, lastknown, _, err := mox.LastKnown()
	if err != nil {
		log.Printf("getting last known version: %s", err)
	} else {
		fmt.Printf("last known version: %s\n", lastknown)
		fmt.Printf("current version: %s\n", current)
	}
	latest, _, err := updates.Lookup(context.Background(), dns.StrictResolver{}, dns.Domain{ASCII: changelogDomain})
	xcheckf(err, "lookup of latest version")
	fmt.Printf("latest version: %s\n", latest)

	if latest.After(current) {
		changelog, err := updates.FetchChangelog(context.Background(), changelogURL, current, changelogPubKey)
		xcheckf(err, "fetching changelog")
		if len(changelog.Changes) == 0 {
			log.Printf("no changes in changelog")
			return
		}
		fmt.Println("Changelog")
		for _, c := range changelog.Changes {
			fmt.Println("\n" + strings.TrimSpace(c.Text))
		}
	}
}

func cmdCid(c *cmd) {
	c.params = "cid"
	c.help = `Turn an ID from a Received header into a cid, for looking up in logs.

A cid is essentially a connection counter initialized when mox starts. Each log
line contains a cid. Received headers added by mox contain a unique ID that can
be decrypted to a cid by admin of a mox instance only.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	recvidpath := mox.DataDirPath("receivedid.key")
	recvidbuf, err := os.ReadFile(recvidpath)
	xcheckf(err, "reading %s", recvidpath)
	if len(recvidbuf) != 16+8 {
		log.Fatalf("bad data in %s: got %d bytes, expect 16+8=24", recvidpath, len(recvidbuf))
	}
	err = mox.ReceivedIDInit(recvidbuf[:16], recvidbuf[16:])
	xcheckf(err, "init receivedid")

	cid, err := mox.ReceivedToCid(args[0])
	xcheckf(err, "received id to cid")
	fmt.Printf("%x\n", cid)
}

func cmdVersion(c *cmd) {
	c.help = "Prints this mox version."
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	fmt.Println(moxvar.Version)
}

func cmdEnsureParsed(c *cmd) {
	c.unlisted = true
	c.params = "account"
	c.help = "Ensure messages in the database have a ParsedBuf."
	var all bool
	c.flag.BoolVar(&all, "all", false, "store new parsed message for all messages")
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	a, err := store.OpenAccount(args[0])
	xcheckf(err, "open account")
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing account: %v", err)
		}
	}()

	n := 0
	err = a.DB.Write(func(tx *bstore.Tx) error {
		q := bstore.QueryTx[store.Message](tx)
		q.FilterFn(func(m store.Message) bool {
			return all || m.ParsedBuf == nil
		})
		l, err := q.List()
		if err != nil {
			return fmt.Errorf("list messages: %v", err)
		}
		for _, m := range l {
			mr := a.MessageReader(m)
			p, err := message.EnsurePart(mr, m.Size)
			if err != nil {
				log.Printf("parsing message %d: %v (continuing)", m.ID, err)
			}
			m.ParsedBuf, err = json.Marshal(p)
			if err != nil {
				return fmt.Errorf("marshal parsed message: %v", err)
			}
			if err := tx.Update(&m); err != nil {
				return fmt.Errorf("update message: %v", err)
			}
			n++
		}
		return nil
	})
	xcheckf(err, "update messages with parsed mime structure")
	fmt.Printf("%d messages updated\n", n)
}

func cmdMessageParse(c *cmd) {
	c.unlisted = true
	c.params = "message.eml"
	c.help = "Parse message, print JSON representation."

	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	f, err := os.Open(args[0])
	xcheckf(err, "open")
	defer f.Close()

	part, err := message.Parse(f)
	xcheckf(err, "parsing message")
	err = part.Walk(nil)
	xcheckf(err, "parsing nested parts")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "\t")
	err = enc.Encode(part)
	xcheckf(err, "write")
}

func cmdBumpUIDValidity(c *cmd) {
	c.unlisted = true
	c.params = "account mailbox"
	c.help = "Change the IMAP UID validity of the mailbox, causing IMAP clients to refetch messages."
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}

	mustLoadConfig()
	a, err := store.OpenAccount(args[0])
	xcheckf(err, "open account")
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing account: %v", err)
		}
	}()

	var uidvalidity uint32
	err = a.DB.Write(func(tx *bstore.Tx) error {
		mb, err := bstore.QueryTx[store.Mailbox](tx).FilterEqual("Name", args[1]).Get()
		if err != nil {
			return fmt.Errorf("looking up mailbox: %v", err)
		}
		mb.UIDValidity++
		uidvalidity = mb.UIDValidity
		err = tx.Update(&mb)
		if err != nil {
			return fmt.Errorf("updating uid validity for mailbox: %v", err)
		}
		return nil
	})
	xcheckf(err, "updating uidvalidity for mailbox: %v", err)
	fmt.Printf("uid validity for %q is now %d\n", args[1], uidvalidity)
}

var submitconf struct {
	LocalHostname      string `sconf-doc:"Hosts don't always have an FQDN, set it explicitly, for EHLO."`
	Host               string `sconf-doc:"Host to dial for delivery, e.g. mail.<domain>."`
	Port               int    `sconf-doc:"Port to dial for delivery, e.g. 465 for submissions, 587 for submission, or perhaps 25 for smtp."`
	TLS                bool   `sconf-doc:"Connect with TLS. Usually for connections to port 465."`
	STARTTLS           bool   `sconf-doc:"After starting in plain text, use STARTTLS to enable TLS. For port 587 and 25."`
	Username           string `sconf-doc:"For SMTP plain auth."`
	Password           string `sconf-doc:"For SMTP plain auth."`
	AuthMethod         string `sconf-doc:"Ignored for now, regardless of value, AUTH PLAIN is done. This will change in the future."`
	From               string `sconf-doc:"Address for MAIL FROM in SMTP and From-header in message."`
	DefaultDestination string `sconf:"optional" sconf-doc:"Used when specified address does not contain an @ and may be a local user (eg root)."`
}

func cmdConfigDescribeSendmail(c *cmd) {
	c.params = ">/etc/moxsubmit.conf"
	c.help = `Describe configuration for mox when invoked as sendmail.`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	err := sconf.Describe(os.Stdout, submitconf)
	xcheckf(err, "describe config")
}

func cmdSendmail(c *cmd) {
	c.params = "[-Fname] [ignoredflags] [-t] [<message]"
	c.help = `Sendmail is a drop-in replacement for /usr/sbin/sendmail to deliver emails sent by unix processes like cron.

If invoked as "sendmail", it will act as sendmail for sending messages. Its
intention is to let processes like cron send emails. Messages are submitted to
an actual mail server over SMTP. The destination mail server and credentials are
configured in /etc/moxsubmit.conf, see mox config describe-sendmail. The From
message header is rewritten to the configured address. When the addressee
appears to be a local user, because without @, the message is sent to the
configured default address.

If submitting an email fails, it is added to a directory moxsubmit.failures in
the user's home directory.

Most flags are ignored to fake compatibility with other sendmail
implementations. A single recipient is required, or the tflag.

/etc/moxsubmit.conf should be group-readable and not readable by others and this
binary should be setgid that group:

	groupadd moxsubmit
	install -m 2755 -o root -g moxsubmit mox /usr/sbin/sendmail
	touch /etc/moxsubmit.conf
	chown root:moxsubmit /etc/moxsubmit.conf
	chmod 640 /etc/moxsubmit.conf
	# edit /etc/moxsubmit.conf
`

	// We are faking that we parse flags, this is non-standard, we want to be lax and ignore most flags.
	args := c.flagArgs
	c.flagArgs = []string{}
	c.Parse() // We still have to call Parse for the usage gathering.

	// Typical cron usage of sendmail:
	// anacron: https://salsa.debian.org/debian/anacron/-/blob/c939c8c80fc9419c11a5e6be5cbe84f03ad332fd/runjob.c#L183
	// cron: https://github.com/vixie/cron/blob/fea7a6c5421f88f034be8eef66a84d8b65b5fbe0/config.h#L41

	var from string
	var tflag bool // If set, we need to take the recipient(s) from the message headers. We only do one recipient, in To.
	o := 0
	for i, s := range args {
		if s == "--" {
			o = i + 1
			break
		}
		if !strings.HasPrefix(s, "-") {
			o = i
			break
		}
		s = s[1:]
		if strings.HasPrefix(s, "F") {
			from = s[1:]
			log.Printf("ignoring -F %q", from) // todo
		} else if s == "t" {
			tflag = true
		}
		o = i + 1
		// Ignore options otherwise.
		// todo: we may want to parse more flags. some invocations may not be about sending a message. for now, we'll assume sendmail is only invoked to send a message.
	}
	args = args[o:]

	// todo: perhaps allow configuration of config file through environment variable? have to keep in mind that mox with setgid moxsubmit would be reading the file.
	const confPath = "/etc/moxsubmit.conf"
	err := sconf.ParseFile(confPath, &submitconf)
	xcheckf(err, "parsing config")

	var recipient string
	if len(args) == 1 && !tflag {
		recipient = args[0]
		if !strings.Contains(recipient, "@") {
			if submitconf.DefaultDestination == "" {
				log.Fatalf("recipient %q has no @ and no default destination configured", recipient)
			}
			recipient = submitconf.DefaultDestination
		} else {
			_, err := smtp.ParseAddress(args[0])
			xcheckf(err, "parsing recipient address")
		}
	} else if !tflag || len(args) != 0 {
		log.Fatalln("need either exactly 1 recipient, or -t")
	}

	// Read message and build message we are going to send. We replace \n
	// with \r\n, and we replace the From header.
	// todo: should we also wrap lines that are too long? perhaps only if this is just text, no multipart?
	var sb strings.Builder
	r := bufio.NewReader(os.Stdin)
	header := true // Whether we are in the header.
	fmt.Fprintf(&sb, "From: <%s>\r\n", submitconf.From)
	var haveTo bool
	for {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			xcheckf(err, "reading message")
		}
		if line != "" {
			if !strings.HasSuffix(line, "\n") {
				line += "\n"
			}
			if !strings.HasSuffix(line, "\r\n") {
				line = line[:len(line)-1] + "\r\n"
			}
			if header && line == "\r\n" {
				// Bare \r\n marks end of header.
				if !haveTo {
					line = fmt.Sprintf("To: <%s>\r\n", recipient) + line
				}
				header = false
			} else if header {
				t := strings.SplitN(line, ":", 2)
				if len(t) != 2 {
					log.Fatalf("invalid message, missing colon in header")
				}
				k := strings.ToLower(t[0])
				if k == "from" {
					// We already added a From header.
					if err == io.EOF {
						break
					}
					continue
				} else if tflag && k == "to" {
					if recipient != "" {
						log.Fatalf("only single To header allowed")
					}
					s := strings.TrimSpace(t[1])
					if !strings.Contains(s, "@") {
						if submitconf.DefaultDestination == "" {
							log.Fatalf("recipient %q has no @ and no default destination is configured", s)
						}
						recipient = submitconf.DefaultDestination
					} else {
						addrs, err := mail.ParseAddressList(s)
						xcheckf(err, "parsing To address list")
						if len(addrs) != 1 {
							log.Fatalf("only single address allowed in To header")
						}
						recipient = addrs[0].Address
					}
				}
				if k == "to" {
					haveTo = true
				}
			}
			sb.WriteString(line)
		}
		if err == io.EOF {
			break
		}
	}
	msg := sb.String()

	if recipient == "" {
		log.Fatalf("no recipient")
	}

	// Message seems acceptable. We'll try to deliver it from here. If that fails, we
	// store the message in the users home directory.

	xcheckf := func(err error, format string, args ...any) {
		if err == nil {
			return
		}
		log.Printf("submit failed: %s: %s", fmt.Sprintf(format, args...), err)
		homedir, err := os.UserHomeDir()
		xcheckf(err, "finding homedir for storing message after failed delivery")
		maildir := filepath.Join(homedir, "moxsubmit.failures")
		os.Mkdir(maildir, 0700)
		f, err := os.CreateTemp(maildir, "newmsg.")
		xcheckf(err, "creating temp file for storing message after failed delivery")
		defer func() {
			if f != nil {
				if err := os.Remove(f.Name()); err != nil {
					log.Printf("removing temp file after failure storing failed delivery: %v", err)
				}
			}
		}()
		_, err = f.Write([]byte(msg))
		xcheckf(err, "writing message to temp file after failed delivery")
		name := f.Name()
		err = f.Close()
		xcheckf(err, "closing message in temp file after failed delivery")
		f = nil
		log.Printf("saved message in %s", name)
		os.Exit(1)
	}

	var conn net.Conn
	addr := net.JoinHostPort(submitconf.Host, fmt.Sprintf("%d", submitconf.Port))
	d := net.Dialer{Timeout: 30 * time.Second}
	if submitconf.TLS {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, nil)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	xcheckf(err, "dial submit server")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tlsMode := smtpclient.TLSStrict
	if !submitconf.STARTTLS {
		tlsMode = smtpclient.TLSSkip
	}
	// todo: should have more auth options, scram-sha-256 at least, perhaps cram-md5 for compatibility as well.
	authLine := fmt.Sprintf("AUTH PLAIN %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\u0000%s\u0000%s", submitconf.Username, submitconf.Password))))
	mox.Conf.Static.HostnameDomain.ASCII = submitconf.LocalHostname
	client, err := smtpclient.New(ctx, mlog.New("sendmail"), conn, tlsMode, submitconf.Host, authLine)
	xcheckf(err, "open smtp session")

	err = client.Deliver(ctx, submitconf.From, recipient, int64(len(msg)), strings.NewReader(msg), true, false)
	xcheckf(err, "submit message")

	if err := client.Close(); err != nil {
		log.Printf("closing smtp session after message was sent: %v", err)
	}
}
