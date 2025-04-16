package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/secure/precis"

	"github.com/mjl-/adns"

	"github.com/mjl-/autocert"
	"github.com/mjl-/bstore"
	"github.com/mjl-/sconf"
	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/admin"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dane"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/rdap"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/spf"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
	"github.com/mjl-/mox/updates"
	"github.com/mjl-/mox/webadmin"
	"github.com/mjl-/mox/webapi"
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
	{"queue holdrules list", cmdQueueHoldrulesList},
	{"queue holdrules add", cmdQueueHoldrulesAdd},
	{"queue holdrules remove", cmdQueueHoldrulesRemove},
	{"queue list", cmdQueueList},
	{"queue hold", cmdQueueHold},
	{"queue unhold", cmdQueueUnhold},
	{"queue schedule", cmdQueueSchedule},
	{"queue transport", cmdQueueTransport},
	{"queue requiretls", cmdQueueRequireTLS},
	{"queue fail", cmdQueueFail},
	{"queue drop", cmdQueueDrop},
	{"queue dump", cmdQueueDump},
	{"queue retired list", cmdQueueRetiredList},
	{"queue retired print", cmdQueueRetiredPrint},
	{"queue suppress list", cmdQueueSuppressList},
	{"queue suppress add", cmdQueueSuppressAdd},
	{"queue suppress remove", cmdQueueSuppressRemove},
	{"queue suppress lookup", cmdQueueSuppressLookup},
	{"queue webhook list", cmdQueueHookList},
	{"queue webhook schedule", cmdQueueHookSchedule},
	{"queue webhook cancel", cmdQueueHookCancel},
	{"queue webhook print", cmdQueueHookPrint},
	{"queue webhook retired list", cmdQueueHookRetiredList},
	{"queue webhook retired print", cmdQueueHookRetiredPrint},
	{"import maildir", cmdImportMaildir},
	{"import mbox", cmdImportMbox},
	{"export maildir", cmdExportMaildir},
	{"export mbox", cmdExportMbox},
	{"localserve", cmdLocalserve},
	{"help", cmdHelp},
	{"backup", cmdBackup},
	{"verifydata", cmdVerifydata},
	{"licenses", cmdLicenses},

	{"config test", cmdConfigTest},
	{"config dnscheck", cmdConfigDNSCheck},
	{"config dnsrecords", cmdConfigDNSRecords},
	{"config describe-domains", cmdConfigDescribeDomains},
	{"config describe-static", cmdConfigDescribeStatic},
	{"config account list", cmdConfigAccountList},
	{"config account add", cmdConfigAccountAdd},
	{"config account rm", cmdConfigAccountRemove},
	{"config account disable", cmdConfigAccountDisable},
	{"config account enable", cmdConfigAccountEnable},
	{"config address add", cmdConfigAddressAdd},
	{"config address rm", cmdConfigAddressRemove},
	{"config domain add", cmdConfigDomainAdd},
	{"config domain rm", cmdConfigDomainRemove},
	{"config domain disable", cmdConfigDomainDisable},
	{"config domain enable", cmdConfigDomainEnable},
	{"config tlspubkey list", cmdConfigTlspubkeyList},
	{"config tlspubkey get", cmdConfigTlspubkeyGet},
	{"config tlspubkey add", cmdConfigTlspubkeyAdd},
	{"config tlspubkey rm", cmdConfigTlspubkeyRemove},
	{"config tlspubkey gen", cmdConfigTlspubkeyGen},
	{"config alias list", cmdConfigAliasList},
	{"config alias print", cmdConfigAliasPrint},
	{"config alias add", cmdConfigAliasAdd},
	{"config alias update", cmdConfigAliasUpdate},
	{"config alias rm", cmdConfigAliasRemove},
	{"config alias addaddr", cmdConfigAliasAddaddr},
	{"config alias rmaddr", cmdConfigAliasRemoveaddr},

	{"config describe-sendmail", cmdConfigDescribeSendmail},
	{"config printservice", cmdConfigPrintservice},
	{"config ensureacmehostprivatekeys", cmdConfigEnsureACMEHostprivatekeys},
	{"config example", cmdConfigExample},

	{"admin imapserve", cmdIMAPServe},

	{"checkupdate", cmdCheckupdate},
	{"cid", cmdCid},
	{"clientconfig", cmdClientConfig},
	{"deliver", cmdDeliver},
	// todo: turn cmdDANEDialmx into a regular "dialmx" command that follows mta-sts policy, with options to require dane, mta-sts or requiretls. the code will be similar to queue/direct.go
	{"dane dial", cmdDANEDial},
	{"dane dialmx", cmdDANEDialmx},
	{"dane makerecord", cmdDANEMakeRecord},
	{"dns lookup", cmdDNSLookup},
	{"dkim gened25519", cmdDKIMGened25519},
	{"dkim genrsa", cmdDKIMGenrsa},
	{"dkim lookup", cmdDKIMLookup},
	{"dkim txt", cmdDKIMTXT},
	{"dkim verify", cmdDKIMVerify},
	{"dkim sign", cmdDKIMSign},
	{"dmarc lookup", cmdDMARCLookup},
	{"dmarc parsereportmsg", cmdDMARCParsereportmsg},
	{"dmarc verify", cmdDMARCVerify},
	{"dmarc checkreportaddrs", cmdDMARCCheckreportaddrs},
	{"dnsbl check", cmdDNSBLCheck},
	{"dnsbl checkhealth", cmdDNSBLCheckhealth},
	{"mtasts lookup", cmdMTASTSLookup},
	{"rdap domainage", cmdRDAPDomainage},
	{"retrain", cmdRetrain},
	{"sendmail", cmdSendmail},
	{"spf check", cmdSPFCheck},
	{"spf lookup", cmdSPFLookup},
	{"spf parse", cmdSPFParse},
	{"tlsrpt lookup", cmdTLSRPTLookup},
	{"tlsrpt parsereportmsg", cmdTLSRPTParsereportmsg},
	{"version", cmdVersion},
	{"webapi", cmdWebapi},

	{"example", cmdExample},
	{"bumpuidvalidity", cmdBumpUIDValidity},
	{"reassignuids", cmdReassignUIDs},
	{"fixuidmeta", cmdFixUIDMeta},
	{"fixmsgsize", cmdFixmsgsize},
	{"reparse", cmdReparse},
	{"ensureparsed", cmdEnsureParsed},
	{"recalculatemailboxcounts", cmdRecalculateMailboxCounts},
	{"message parse", cmdMessageParse},
	{"reassignthreads", cmdReassignthreads},

	// Not listed.
	{"helpall", cmdHelpall},
	{"junk analyze", cmdJunkAnalyze},
	{"junk check", cmdJunkCheck},
	{"junk play", cmdJunkPlay},
	{"junk test", cmdJunkTest},
	{"junk train", cmdJunkTrain},
	{"dmarcdb addreport", cmdDMARCDBAddReport},
	{"tlsrptdb addreport", cmdTLSRPTDBAddReport},
	{"updates addsigned", cmdUpdatesAddSigned},
	{"updates genkey", cmdUpdatesGenkey},
	{"updates pubkey", cmdUpdatesPubkey},
	{"updates serve", cmdUpdatesServe},
	{"updates verify", cmdUpdatesVerify},
	{"gentestdata", cmdGentestdata},
	{"ximport maildir", cmdXImportMaildir},
	{"ximport mbox", cmdXImportMbox},
	{"openaccounts", cmdOpenaccounts},
	{"readmessages", cmdReadmessages},
	{"queuefillretired", cmdQueueFillRetired},
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

	log mlog.Log
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

	prefix := func(l, pre []string) bool {
		if len(pre) > len(l) {
			return false
		}
		return slices.Equal(pre, l[:len(pre)])
	}

	var partial []cmd
	for _, c := range cmds {
		if slices.Equal(c.words, args) {
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
			fmt.Fprintln(os.Stderr, c.help+"\n")
		}
		s := c.makeUsage()
		s = "\t" + strings.ReplaceAll(s, "\n", "\n\t")
		fmt.Fprintln(os.Stderr, s)
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

var loglevel string // Empty will be interpreted as info, except by localserve.
var pedantic bool

// subcommands that are not "serve" should use this function to load the config, it
// restores any loglevel specified on the command-line, instead of using the
// loglevels from the config file and it does not load files like TLS keys/certs.
func mustLoadConfig() {
	mox.MustLoadConfig(false, false)
	ll := loglevel
	if ll == "" {
		ll = "info"
	}
	if level, ok := mlog.Levels[ll]; ok {
		mox.Conf.Log[""] = level
		mlog.SetConfig(mox.Conf.Log)
	} else {
		log.Fatal("unknown loglevel", slog.String("loglevel", loglevel))
	}
	if pedantic {
		mox.SetPedantic(true)
	}
}

func main() {
	// CheckConsistencyOnClose is true by default, for all the test packages. A regular
	// mox server should never use it. But integration tests enable it again with a
	// flag.
	store.CheckConsistencyOnClose = false
	store.MsgFilesPerDirShiftSet(13) // For 1<<13 = 8k message files per directory.

	ctxbg := context.Background()
	mox.Shutdown = ctxbg
	mox.Context = ctxbg

	log.SetFlags(0)

	// If invoked as sendmail, e.g. /usr/sbin/sendmail, we do enough so cron can get a
	// message sent using smtp submission to a configured server.
	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "sendmail" {
		c := &cmd{
			flag:     flag.NewFlagSet("sendmail", flag.ExitOnError),
			flagArgs: os.Args[1:],
			log:      mlog.New("sendmail", nil),
		}
		cmdSendmail(c)
		return
	}

	flag.StringVar(&mox.ConfigStaticPath, "config", envString("MOXCONF", filepath.FromSlash("config/mox.conf")), "configuration file, other config files are looked up in the same directory, defaults to $MOXCONF with a fallback to mox.conf")
	flag.StringVar(&loglevel, "loglevel", "", "if non-empty, this log level is set early in startup")
	flag.BoolVar(&pedantic, "pedantic", false, "protocol violations result in errors instead of accepting/working around them")
	flag.BoolVar(&store.CheckConsistencyOnClose, "checkconsistency", false, "dangerous option for testing only, enables data checks that abort/panic when inconsistencies are found")

	var cpuprofile, memprofile, tracefile string
	flag.StringVar(&cpuprofile, "cpuprof", "", "store cpu profile to file")
	flag.StringVar(&memprofile, "memprof", "", "store mem profile to file")
	flag.StringVar(&tracefile, "trace", "", "store execution trace to file")

	flag.Usage = func() { usage(cmds, false) }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage(cmds, false)
	}

	if tracefile != "" {
		defer traceExecution(tracefile)()
	}
	defer profile(cpuprofile, memprofile)()

	if pedantic {
		mox.SetPedantic(true)
	}

	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	ll := loglevel
	if ll == "" {
		ll = "info"
	}
	if level, ok := mlog.Levels[ll]; ok {
		mox.Conf.Log[""] = level
		mlog.SetConfig(mox.Conf.Log)
		// note: SetConfig may be called again when subcommands loads config.
	} else {
		log.Fatalf("unknown loglevel %q", loglevel)
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
		c.log = mlog.New(strings.Join(c.words, ""), nil)
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
	cc, err := admin.ClientConfigsDomain(d)
	xcheckf(err, "getting client config")
	fmt.Printf("%-20s %-30s %5s %-15s %s\n", "Protocol", "Host", "Port", "Listener", "Note")
	for _, e := range cc.Entries {
		fmt.Printf("%-20s %-30s %5d %-15s %s\n", e.Protocol, e.Host, e.Port, e.Listener, e.Note)
	}
	fmt.Printf(`
To prevent authentication mechanism downgrade attempts that may result in
clients sending plain text passwords to a MitM, clients should always be
explicitly configured with the most secure authentication mechanism supported,
the first of: SCRAM-SHA-256-PLUS, SCRAM-SHA-1-PLUS, SCRAM-SHA-256, SCRAM-SHA-1,
CRAM-MD5.
`)
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

	mox.FilesImmediate = true

	_, errs := mox.ParseConfig(context.Background(), c.log, mox.ConfigStaticPath, true, true, false)
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
	c.params = "[-disabled] domain account [localpart]"
	c.help = `Adds a new domain to the configuration and reloads the configuration.

The account is used for the postmaster mailboxes the domain, including as DMARC and
TLS reporting. Localpart is the "username" at the domain for this account. If
must be set if and only if account does not yet exist.

The domain can be created in disabled mode, preventing automatically requesting
TLS certificates with ACME, and rejecting incoming/outgoing messages involving
the domain, but allowing further configuration of the domain.
`
	var disabled bool
	c.flag.BoolVar(&disabled, "disabled", false, "disable the new domain")
	args := c.Parse()
	if len(args) != 2 && len(args) != 3 {
		c.Usage()
	}

	d := xparseDomain(args[0], "domain")
	mustLoadConfig()
	var localpart smtp.Localpart
	if len(args) == 3 {
		var err error
		localpart, err = smtp.ParseLocalpart(args[2])
		xcheckf(err, "parsing localpart")
	}
	ctlcmdConfigDomainAdd(xctl(), disabled, d, args[1], localpart)
}

func ctlcmdConfigDomainAdd(ctl *ctl, disabled bool, domain dns.Domain, account string, localpart smtp.Localpart) {
	ctl.xwrite("domainadd")
	if disabled {
		ctl.xwrite("true")
	} else {
		ctl.xwrite("false")
	}
	ctl.xwrite(domain.Name())
	ctl.xwrite(account)
	ctl.xwrite(string(localpart))
	ctl.xreadok()
	fmt.Printf("domain added, remember to add dns records, see:\n\nmox config dnsrecords %s\nmox config dnscheck %s\n", domain.Name(), domain.Name())
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
	ctlcmdConfigDomainRemove(xctl(), d)
}

func ctlcmdConfigDomainRemove(ctl *ctl, d dns.Domain) {
	ctl.xwrite("domainrm")
	ctl.xwrite(d.Name())
	ctl.xreadok()
	fmt.Printf("domain removed, remember to remove dns records for %s\n", d)
}

func cmdConfigDomainDisable(c *cmd) {
	c.params = "domain"
	c.help = `Disable a domain and reload the configuration.

This is a dangerous operation. Incoming/outgoing messages involving this domain
will be rejected.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	d := xparseDomain(args[0], "domain")
	mustLoadConfig()
	ctlcmdConfigDomainDisabled(xctl(), d, true)
	fmt.Printf("domain disabled")
}

func cmdConfigDomainEnable(c *cmd) {
	c.params = "domain"
	c.help = `Enable a domain and reload the configuration.

Incoming/outgoing messages involving this domain will be accepted again.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	d := xparseDomain(args[0], "domain")
	mustLoadConfig()
	ctlcmdConfigDomainDisabled(xctl(), d, false)
}

func ctlcmdConfigDomainDisabled(ctl *ctl, d dns.Domain, disabled bool) {
	ctl.xwrite("domaindisabled")
	ctl.xwrite(d.Name())
	if disabled {
		ctl.xwrite("true")
	} else {
		ctl.xwrite("false")
	}
	ctl.xreadok()
}

func cmdConfigAliasList(c *cmd) {
	c.params = "domain"
	c.help = `Show aliases (lists) for domain.`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAliasList(xctl(), args[0])
}

func ctlcmdConfigAliasList(ctl *ctl, address string) {
	ctl.xwrite("aliaslist")
	ctl.xwrite(address)
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func cmdConfigAliasPrint(c *cmd) {
	c.params = "alias"
	c.help = `Print settings and members of alias (list).`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAliasPrint(xctl(), args[0])
}

func ctlcmdConfigAliasPrint(ctl *ctl, address string) {
	ctl.xwrite("aliasprint")
	ctl.xwrite(address)
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func cmdConfigAliasAdd(c *cmd) {
	c.params = "alias@domain rcpt1@domain ..."
	c.help = `Add new alias (list) with one or more addresses and public posting enabled.

An alias is used for delivering incoming email to multiple recipients. If you
want to add an address to an account, don't use an alias, just add the address
to the account.
`
	args := c.Parse()
	if len(args) < 2 {
		c.Usage()
	}

	alias := config.Alias{PostPublic: true, Addresses: args[1:]}

	mustLoadConfig()
	ctlcmdConfigAliasAdd(xctl(), args[0], alias)
}

func ctlcmdConfigAliasAdd(ctl *ctl, address string, alias config.Alias) {
	ctl.xwrite("aliasadd")
	ctl.xwrite(address)
	xctlwriteJSON(ctl, alias)
	ctl.xreadok()
}

func cmdConfigAliasUpdate(c *cmd) {
	c.params = "alias@domain [-postpublic false|true -listmembers false|true -allowmsgfrom false|true]"
	c.help = `Update alias (list) configuration.`
	var postpublic, listmembers, allowmsgfrom string
	c.flag.StringVar(&postpublic, "postpublic", "", "whether anyone or only list members can post")
	c.flag.StringVar(&listmembers, "listmembers", "", "whether list members can list members")
	c.flag.StringVar(&allowmsgfrom, "allowmsgfrom", "", "whether alias address can be used in message from header")
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	alias := args[0]
	mustLoadConfig()
	ctlcmdConfigAliasUpdate(xctl(), alias, postpublic, listmembers, allowmsgfrom)
}

func ctlcmdConfigAliasUpdate(ctl *ctl, alias, postpublic, listmembers, allowmsgfrom string) {
	ctl.xwrite("aliasupdate")
	ctl.xwrite(alias)
	ctl.xwrite(postpublic)
	ctl.xwrite(listmembers)
	ctl.xwrite(allowmsgfrom)
	ctl.xreadok()
}

func cmdConfigAliasRemove(c *cmd) {
	c.params = "alias@domain"
	c.help = "Remove alias (list)."
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAliasRemove(xctl(), args[0])
}

func ctlcmdConfigAliasRemove(ctl *ctl, alias string) {
	ctl.xwrite("aliasrm")
	ctl.xwrite(alias)
	ctl.xreadok()
}

func cmdConfigAliasAddaddr(c *cmd) {
	c.params = "alias@domain rcpt1@domain ..."
	c.help = `Add addresses to alias (list).`
	args := c.Parse()
	if len(args) < 2 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAliasAddaddr(xctl(), args[0], args[1:])
}

func ctlcmdConfigAliasAddaddr(ctl *ctl, alias string, addresses []string) {
	ctl.xwrite("aliasaddaddr")
	ctl.xwrite(alias)
	xctlwriteJSON(ctl, addresses)
	ctl.xreadok()
}

func cmdConfigAliasRemoveaddr(c *cmd) {
	c.params = "alias@domain rcpt1@domain ..."
	c.help = `Remove addresses from alias (list).`
	args := c.Parse()
	if len(args) < 2 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAliasRmaddr(xctl(), args[0], args[1:])
}

func ctlcmdConfigAliasRmaddr(ctl *ctl, alias string, addresses []string) {
	ctl.xwrite("aliasrmaddr")
	ctl.xwrite(alias)
	xctlwriteJSON(ctl, addresses)
	ctl.xreadok()
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
	ctlcmdConfigAccountAdd(xctl(), args[0], args[1])
}

func ctlcmdConfigAccountAdd(ctl *ctl, account, address string) {
	ctl.xwrite("accountadd")
	ctl.xwrite(account)
	ctl.xwrite(address)
	ctl.xreadok()
	fmt.Printf("account added, set a password with \"mox setaccountpassword %s\"\n", account)
}

func cmdConfigAccountRemove(c *cmd) {
	c.params = "account"
	c.help = `Remove an account and reload the configuration.

Email addresses for this account will also be removed, and incoming email for
these addresses will be rejected.

All data for the account will be removed.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAccountRemove(xctl(), args[0])
}

func ctlcmdConfigAccountRemove(ctl *ctl, account string) {
	ctl.xwrite("accountrm")
	ctl.xwrite(account)
	ctl.xreadok()
	fmt.Println("account removed")
}

func cmdConfigAccountList(c *cmd) {
	c.help = `List all accounts.

Each account is printed on a line, with optional additional tab-separated
information, such as "(disabled)".
`
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAccountList(xctl())
}

func ctlcmdConfigAccountList(ctl *ctl) {
	ctl.xwrite("accountlist")
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func cmdConfigAccountDisable(c *cmd) {
	c.params = "account message"
	c.help = `Disable login for an account, showing message to users when they try to login.

Incoming email will still be accepted for the account, and queued email from the
account will still be delivered. No new login sessions are possible.

Message must be non-empty, ascii-only without control characters including
newline, and maximum 256 characters because it is used in SMTP/IMAP.
`
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}
	if args[1] == "" {
		log.Fatalf("message must be non-empty")
	}

	mustLoadConfig()
	ctlcmdConfigAccountDisabled(xctl(), args[0], args[1])
	fmt.Println("account disabled")
}

func cmdConfigAccountEnable(c *cmd) {
	c.params = "account"
	c.help = `Enable login again for an account.

Login attempts by the user no long result in an error message.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAccountDisabled(xctl(), args[0], "")
	fmt.Println("account enabled")
}

func ctlcmdConfigAccountDisabled(ctl *ctl, account, loginDisabled string) {
	ctl.xwrite("accountdisabled")
	ctl.xwrite(account)
	ctl.xwrite(loginDisabled)
	ctl.xreadok()
}

func cmdConfigTlspubkeyList(c *cmd) {
	c.params = "[account]"
	c.help = `List TLS public keys for TLS client certificate authentication.

If account is absent, the TLS public keys for all accounts are listed.
`
	args := c.Parse()
	var accountOpt string
	if len(args) == 1 {
		accountOpt = args[0]
	} else if len(args) > 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigTlspubkeyList(xctl(), accountOpt)
}

func ctlcmdConfigTlspubkeyList(ctl *ctl, accountOpt string) {
	ctl.xwrite("tlspubkeylist")
	ctl.xwrite(accountOpt)
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func cmdConfigTlspubkeyGet(c *cmd) {
	c.params = "fingerprint"
	c.help = `Get a TLS public key for a fingerprint.

Prints the type, name, account and address for the key, and the certificate in
PEM format.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigTlspubkeyGet(xctl(), args[0])
}

func ctlcmdConfigTlspubkeyGet(ctl *ctl, fingerprint string) {
	ctl.xwrite("tlspubkeyget")
	ctl.xwrite(fingerprint)
	ctl.xreadok()
	typ := ctl.xread()
	name := ctl.xread()
	account := ctl.xread()
	address := ctl.xread()
	noimappreauth := ctl.xread()
	var b bytes.Buffer
	ctl.xstreamto(&b)
	buf := b.Bytes()
	var block *pem.Block
	if len(buf) != 0 {
		block = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: buf,
		}
	}

	fmt.Printf("type: %s\nname: %s\naccount: %s\naddress: %s\nno imap preauth: %s\n", typ, name, account, address, noimappreauth)
	if block != nil {
		fmt.Printf("certificate:\n\n")
		if err := pem.Encode(os.Stdout, block); err != nil {
			log.Fatalf("pem encode: %v", err)
		}
	}
}

func cmdConfigTlspubkeyAdd(c *cmd) {
	c.params = "address [name] < cert.pem"
	c.help = `Add a TLS public key to the account of the given address.

The public key is read from the certificate.

The optional name is a human-readable descriptive name of the key. If absent,
the CommonName from the certificate is used.
`
	var noimappreauth bool
	c.flag.BoolVar(&noimappreauth, "no-imap-preauth", false, "Don't automatically switch new IMAP connections authenticated with this key to \"authenticated\" state after the TLS handshake. For working around clients that ignore the untagged IMAP PREAUTH response and try to authenticate while already authenticated.")
	args := c.Parse()
	var address, name string
	if len(args) == 1 {
		address = args[0]
	} else if len(args) == 2 {
		address, name = args[0], args[1]
	} else {
		c.Usage()
	}

	buf, err := io.ReadAll(os.Stdin)
	xcheckf(err, "reading from stdin")
	block, _ := pem.Decode(buf)
	if block == nil {
		err = errors.New("no pem block found")
	} else if block.Type != "CERTIFICATE" {
		err = fmt.Errorf("unexpected type %q, expected CERTIFICATE", block.Type)
	}
	xcheckf(err, "parsing pem")

	mustLoadConfig()
	ctlcmdConfigTlspubkeyAdd(xctl(), address, name, noimappreauth, block.Bytes)
}

func ctlcmdConfigTlspubkeyAdd(ctl *ctl, address, name string, noimappreauth bool, certDER []byte) {
	ctl.xwrite("tlspubkeyadd")
	ctl.xwrite(address)
	ctl.xwrite(name)
	ctl.xwrite(fmt.Sprintf("%v", noimappreauth))
	ctl.xstreamfrom(bytes.NewReader(certDER))
	ctl.xreadok()
}

func cmdConfigTlspubkeyRemove(c *cmd) {
	c.params = "fingerprint"
	c.help = `Remove TLS public key for fingerprint.`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigTlspubkeyRemove(xctl(), args[0])
}

func ctlcmdConfigTlspubkeyRemove(ctl *ctl, fingerprint string) {
	ctl.xwrite("tlspubkeyrm")
	ctl.xwrite(fingerprint)
	ctl.xreadok()
}

func cmdConfigTlspubkeyGen(c *cmd) {
	c.params = "stem"
	c.help = `Generate an ed25519 private key and minimal certificate for use a TLS public key and write to files starting with stem.

The private key is written to $stem.$timestamp.ed25519privatekey.pkcs8.pem.
The certificate is written to $stem.$timestamp.certificate.pem.
The private key and certificate are also written to
$stem.$timestamp.ed25519privatekey-certificate.pem.

The certificate can be added to an account with "mox config account tlspubkey add".

The combined file can be used with "mox sendmail".

The private key is also written to standard error in raw-url-base64-encoded
form, also for use with "mox sendmail". The fingerprint is written to standard
error too, for reference.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	stem := args[0]
	timestamp := time.Now().Format("200601021504")
	prefix := stem + "." + timestamp

	seed := make([]byte, ed25519.SeedSize)
	if _, err := cryptorand.Read(seed); err != nil {
		panic(err)
	}
	privKey := ed25519.NewKeyFromSeed(seed)
	privKeyBuf, err := x509.MarshalPKCS8PrivateKey(privKey)
	xcheckf(err, "marshal private key as pkcs8")
	var b bytes.Buffer
	err = pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBuf})
	xcheckf(err, "marshal pkcs8 private key to pem")
	privKeyBufPEM := b.Bytes()

	certBuf, tlsCert := xminimalCert(privKey)
	b = bytes.Buffer{}
	err = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certBuf})
	xcheckf(err, "marshal certificate to pem")
	certBufPEM := b.Bytes()

	xwriteFile := func(p string, data []byte, what string) {
		log.Printf("writing %s", p)
		err = os.WriteFile(p, data, 0600)
		xcheckf(err, "writing %s file: %v", what, err)
	}

	xwriteFile(prefix+".ed25519privatekey.pkcs8.pem", privKeyBufPEM, "private key")
	xwriteFile(prefix+".certificate.pem", certBufPEM, "certificate")
	combinedPEM := slices.Concat(privKeyBufPEM, certBufPEM)
	xwriteFile(prefix+".ed25519privatekey-certificate.pem", combinedPEM, "combined private key and certificate")

	shabuf := sha256.Sum256(tlsCert.Leaf.RawSubjectPublicKeyInfo)

	_, err = fmt.Fprintf(os.Stderr, "ed25519 private key as raw-url-base64: %s\ned25519 public key fingerprint: %s\n",
		base64.RawURLEncoding.EncodeToString(seed),
		base64.RawURLEncoding.EncodeToString(shabuf[:]),
	)
	xcheckf(err, "write private key and public key fingerprint")
}

func cmdConfigAddressAdd(c *cmd) {
	c.params = "address account"
	c.help = `Adds an address to an account and reloads the configuration.

If address starts with a @ (i.e. a missing localpart), this is a catchall
address for the domain.
`
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAddressAdd(xctl(), args[0], args[1])
}

func ctlcmdConfigAddressAdd(ctl *ctl, address, account string) {
	ctl.xwrite("addressadd")
	ctl.xwrite(address)
	ctl.xwrite(account)
	ctl.xreadok()
	fmt.Println("address added")
}

func cmdConfigAddressRemove(c *cmd) {
	c.params = "address"
	c.help = `Remove an address and reload the configuration.

Incoming email for this address will be rejected after removing an address.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdConfigAddressRemove(xctl(), args[0])
}

func ctlcmdConfigAddressRemove(ctl *ctl, address string) {
	ctl.xwrite("addressrm")
	ctl.xwrite(address)
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

	resolver := dns.StrictResolver{Pkg: "main"}
	_, result, err := resolver.LookupTXT(context.Background(), d.ASCII+".")
	if !dns.IsNotFound(err) {
		xcheckf(err, "looking up record for dnssec-status")
	}

	var certIssuerDomainName, acmeAccountURI string
	public := mox.Conf.Static.Listeners["public"]
	if public.TLS != nil && public.TLS.ACME != "" {
		acme, ok := mox.Conf.Static.ACME[public.TLS.ACME]
		if ok && acme.Manager.Manager.Client != nil {
			certIssuerDomainName = acme.IssuerDomainName
			acc, err := acme.Manager.Manager.Client.GetReg(context.Background(), "")
			c.log.Check(err, "get public acme account")
			if err == nil {
				acmeAccountURI = acc.URI
			}
		}
	}

	records, err := admin.DomainRecords(domConf, d, result.Authentic, certIssuerDomainName, acmeAccountURI)
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

	printResult := func(name string, r webadmin.Result) {
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

	result := webadmin.Admin{}.CheckDomain(context.Background(), args[0])
	printResult("DNSSEC", result.DNSSEC.Result)
	printResult("IPRev", result.IPRev.Result)
	printResult("MX", result.MX.Result)
	printResult("TLS", result.TLS.Result)
	printResult("DANE", result.DANE.Result)
	printResult("SPF", result.SPF.Result)
	printResult("DKIM", result.DKIM.Result)
	printResult("DMARC", result.DMARC.Result)
	printResult("Host TLSRPT", result.HostTLSRPT.Result)
	printResult("Domain TLSRPT", result.DomainTLSRPT.Result)
	printResult("MTASTS", result.MTASTS.Result)
	printResult("SRV conf", result.SRVConf.Result)
	printResult("Autoconf", result.Autoconf.Result)
	printResult("Autodiscover", result.Autodiscover.Result)
}

func cmdConfigEnsureACMEHostprivatekeys(c *cmd) {
	c.params = ""
	c.help = `Ensure host private keys exist for TLS listeners with ACME.

In mox.conf, each listener can have TLS configured. Long-lived private key files
can be specified, which will be used when requesting ACME certificates.
Configuring these private keys makes it feasible to publish DANE TLSA records
for the corresponding public keys in DNS, protected with DNSSEC, allowing TLS
certificate verification without depending on a list of Certificate Authorities
(CAs). Previous versions of mox did not pre-generate private keys for use with
ACME certificates, but would generate private keys on-demand. By explicitly
configuring private keys, they will not change automatedly with new
certificates, and the DNS TLSA records stay valid.

This command looks for listeners in mox.conf with TLS with ACME configured. For
each missing host private key (of type rsa-2048 and ecdsa-p256) a key is written
to config/hostkeys/. If a certificate exists in the ACME "cache", its private
key is copied. Otherwise a new private key is generated. Snippets for manually
updating/editing mox.conf are printed.

After running this command, and updating mox.conf, run "mox config dnsrecords"
for a domain and create the TLSA DNS records it suggests to enable DANE.
`
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	// Load a private key from p, in various forms. We only look at the first PEM
	// block. Files with only a private key, or with multiple blocks but private key
	// first like autocert does, can be loaded.
	loadPrivateKey := func(f *os.File) (any, error) {
		buf, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("reading private key file: %v", err)
		}
		block, _ := pem.Decode(buf)
		if block == nil {
			return nil, fmt.Errorf("no pem block found in pem file")
		}
		var privKey any
		switch block.Type {
		case "EC PRIVATE KEY":
			privKey, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		default:
			return nil, fmt.Errorf("unrecognized pem block type %q", block.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("parsing private key of type %q: %v", block.Type, err)
		}
		return privKey, nil
	}

	// Either load a private key from file, or if it doesn't exist generate a new
	// private key.
	xtryLoadPrivateKey := func(kt autocert.KeyType, p string) any {
		f, err := os.Open(p)
		if err != nil && errors.Is(err, fs.ErrNotExist) {
			switch kt {
			case autocert.KeyRSA2048:
				privKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
				xcheckf(err, "generating new 2048-bit rsa private key")
				return privKey
			case autocert.KeyECDSAP256:
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
				xcheckf(err, "generating new ecdsa p-256 private key")
				return privKey
			}
			log.Fatalf("unexpected keytype %v", kt)
			return nil
		}
		xcheckf(err, "%s: open acme key and certificate file", p)

		// Load private key from file. autocert stores a PEM file that starts with a
		// private key, followed by certificate(s). So we can just read it and should find
		// the private key we are looking for.
		privKey, err := loadPrivateKey(f)
		if xerr := f.Close(); xerr != nil {
			log.Printf("closing private key file: %v", xerr)
		}
		xcheckf(err, "parsing private key from acme key and certificate file")

		switch k := privKey.(type) {
		case *rsa.PrivateKey:
			if k.N.BitLen() == 2048 {
				return privKey
			}
			log.Printf("warning: rsa private key in %s has %d bits, skipping and generating new 2048-bit rsa private key", p, k.N.BitLen())
			privKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
			xcheckf(err, "generating new 2048-bit rsa private key")
			return privKey
		case *ecdsa.PrivateKey:
			if k.Curve == elliptic.P256() {
				return privKey
			}
			log.Printf("warning: ecdsa private key in %s has curve %v, skipping and generating new p-256 ecdsa key", p, k.Curve.Params().Name)
			privKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
			xcheckf(err, "generating new ecdsa p-256 private key")
			return privKey
		default:
			log.Fatalf("%s: unexpected private key file of type %T", p, privKey)
			return nil
		}
	}

	// Write privKey as PKCS#8 private key to p. Only if file does not yet exist.
	writeHostPrivateKey := func(privKey any, p string) error {
		os.MkdirAll(filepath.Dir(p), 0700)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("create: %v", err)
		}
		defer func() {
			if f != nil {
				if err := f.Close(); err != nil {
					log.Printf("closing new hostkey file %s after error: %v", p, err)
				}
				if err := os.Remove(p); err != nil {
					log.Printf("removing new hostkey file %s after error: %v", p, err)
				}
			}
		}()
		buf, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return fmt.Errorf("marshal private host key: %v", err)
		}
		block := pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: buf,
		}
		if err := pem.Encode(f, &block); err != nil {
			return fmt.Errorf("write as pem: %v", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close: %v", err)
		}
		f = nil
		return nil
	}

	mustLoadConfig()
	timestamp := time.Now().Format("20060102T150405")
	didCreate := false
	for listenerName, l := range mox.Conf.Static.Listeners {
		if l.TLS == nil || l.TLS.ACME == "" {
			continue
		}
		haveKeyTypes := map[autocert.KeyType]bool{}
		for _, privKeyFile := range l.TLS.HostPrivateKeyFiles {
			p := mox.ConfigDirPath(privKeyFile)
			f, err := os.Open(p)
			xcheckf(err, "open host private key")
			privKey, err := loadPrivateKey(f)
			if err := f.Close(); err != nil {
				log.Printf("closing host private key file: %v", err)
			}
			xcheckf(err, "loading host private key")
			switch k := privKey.(type) {
			case *rsa.PrivateKey:
				if k.N.BitLen() == 2048 {
					haveKeyTypes[autocert.KeyRSA2048] = true
				}
			case *ecdsa.PrivateKey:
				if k.Curve == elliptic.P256() {
					haveKeyTypes[autocert.KeyECDSAP256] = true
				}
			}
		}
		created := []string{}
		for _, kt := range []autocert.KeyType{autocert.KeyRSA2048, autocert.KeyECDSAP256} {
			if haveKeyTypes[kt] {
				continue
			}
			// Lookup key in ACME cache.
			host := l.HostnameDomain
			if host.ASCII == "" {
				host = mox.Conf.Static.HostnameDomain
			}
			filename := host.ASCII
			kind := "ecdsap256"
			if kt == autocert.KeyRSA2048 {
				filename += "+rsa"
				kind = "rsa2048"
			}
			p := mox.DataDirPath(filepath.Join("acme", "keycerts", l.TLS.ACME, filename))
			privKey := xtryLoadPrivateKey(kt, p)

			relPath := filepath.Join("hostkeys", fmt.Sprintf("%s.%s.%s.privatekey.pkcs8.pem", host.Name(), timestamp, kind))
			destPath := mox.ConfigDirPath(relPath)
			err := writeHostPrivateKey(privKey, destPath)
			xcheckf(err, "writing host private key file to %s: %v", destPath, err)
			created = append(created, relPath)
			fmt.Printf("Wrote host private key: %s\n", destPath)
		}
		didCreate = didCreate || len(created) > 0
		if len(created) > 0 {
			tls := config.TLS{
				HostPrivateKeyFiles: append(l.TLS.HostPrivateKeyFiles, created...),
			}
			fmt.Printf("\nEnsure Listener %q in %s has the following in its TLS section, below \"ACME: %s\" (don't forget to indent with tabs):\n\n", listenerName, mox.ConfigStaticPath, l.TLS.ACME)
			err := sconf.Write(os.Stdout, tls)
			xcheckf(err, "writing new TLS.HostPrivateKeyFiles section")
			fmt.Println()
		}
	}
	if didCreate {
		fmt.Printf(`
After updating mox.conf and restarting, run "mox config dnsrecords" for a
domain and create the TLSA DNS records it suggests to enable DANE.
`)
	}
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
		ctlcmdLoglevels(xctl())
	} else {
		var pkg string
		if len(args) == 2 {
			pkg = args[1]
		}
		ctlcmdSetLoglevels(xctl(), pkg, args[0])
	}
}

func ctlcmdLoglevels(ctl *ctl) {
	ctl.xwrite("loglevels")
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func ctlcmdSetLoglevels(ctl *ctl, pkg, level string) {
	ctl.xwrite("setloglevels")
	ctl.xwrite(pkg)
	ctl.xwrite(level)
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

	xctl := xctl()
	xctl.xwrite("stop")
	// Read will hang until remote has shut down.
	buf := make([]byte, 128)
	n, err := xctl.conn.Read(buf)
	if err == nil {
		log.Fatalf("expected eof after graceful shutdown, got data %q", buf[:n])
	} else if err != io.EOF {
		log.Fatalf("expected eof after graceful shutdown, got error %v", err)
	}
	fmt.Println("mox stopped")
}

func cmdBackup(c *cmd) {
	c.params = "destdir"
	c.help = `Creates a backup of the config and data directory.

Backup copies the config directory to <destdir>/config, and creates
<destdir>/data with a consistent snapshot of the databases and message files
and copies other files from the data directory. Empty directories are not
copied. The backup can then be stored elsewhere for long-term storage, or used
to fall back to should an upgrade fail. Simply copying files in the data
directory while mox is running can result in unusable database files.

Message files never change (they are read-only, though can be removed) and are
hard-linked so they don't consume additional space. If hardlinking fails, for
example when the backup destination directory is on a different file system, a
regular copy is made. Using a destination directory like "data/tmp/backup"
increases the odds hardlinking succeeds: the default systemd service file
specifically mounts the data directory, causing attempts to hardlink outside it
to fail with an error about cross-device linking.

All files in the data directory that aren't recognized (i.e. other than known
database files, message files, an acme directory, the "tmp" directory, etc),
are stored, but with a warning.

Remove files in the destination directory before doing another backup. The
backup command will not overwrite files, but print and return errors.

Exit code 0 indicates the backup was successful. A clean successful backup does
not print any output, but may print warnings. Use the -verbose flag for
details, including timing.

To restore a backup, first shut down mox, move away the old data directory and
move an earlier backed up directory in its place, run "mox verifydata
<datadir>", possibly with the "-fix" option, and restart mox. After the
restore, you may also want to run "mox bumpuidvalidity" for each account for
which messages in a mailbox changed, to force IMAP clients to synchronize
mailbox state.

Before upgrading, to check if the upgrade will likely succeed, first make a
backup, then use the new mox binary to run "mox verifydata <backupdir>/data".
This can change the backup files (e.g. upgrade database files, move away
unrecognized message files), so you should make a new backup before actually
upgrading.
`

	var verbose bool
	c.flag.BoolVar(&verbose, "verbose", false, "print progress")
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()

	dstDataDir, err := filepath.Abs(args[0])
	xcheckf(err, "making path absolute")

	ctlcmdBackup(xctl(), dstDataDir, verbose)
}

func ctlcmdBackup(ctl *ctl, dstDataDir string, verbose bool) {
	ctl.xwrite("backup")
	ctl.xwrite(dstDataDir)
	if verbose {
		ctl.xwrite("verbose")
	} else {
		ctl.xwrite("")
	}
	ctl.xstreamto(os.Stdout)
	ctl.xreadok()
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
	pw, err := precis.OpaqueString.String(pw)
	xcheckf(err, `checking password with "precis" requirements`)
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	xcheckf(err, "generating hash for password")
	err = os.WriteFile(path, hash, 0660)
	xcheckf(err, "writing hash to admin password file")
}

func xreadpassword() string {
	fmt.Printf(`
Type new password. Password WILL echo.

WARNING: Bots will try to bruteforce your password. Connections with failed
authentication attempts will be rate limited but attackers WILL find passwords
reused at other services and weak passwords. If your account is compromised,
spammers are likely to abuse your system, spamming your address and the wider
internet in your name. So please pick a random, unguessable password, preferably
at least 12 characters.

`)
	fmt.Printf("password: ")
	scanner := bufio.NewScanner(os.Stdin)
	// The default splitter for scanners is one that splits by lines, so we
	// don't have to set up another one here.

	// We discard the return value of Scan() since failing to tokenize could
	// either mean reaching EOF but no newline (which can be legitimate if the
	// CLI was programatically called to set the password, but with no trailing
	// newline), or an actual error. We can distinguish between the two by
	// calling Err() since it will return nil if it were EOF, but the actual
	// error if not.
	scanner.Scan()
	xcheckf(scanner.Err(), "reading stdin")
	// No need to trim, the scanner does not return the token in the output.
	pw := scanner.Text()
	if len(pw) < 8 {
		log.Fatal("password must be at least 8 characters")
	}
	return pw
}

func cmdSetaccountpassword(c *cmd) {
	c.params = "account"
	c.help = `Set new password an account.

The password is read from stdin. Secrets derived from the password, but not the
password itself, are stored in the account database. The stored secrets are for
authentication with: scram-sha-256, scram-sha-1, cram-md5, plain text (bcrypt
hash).

The parameter is an account name, as configured under Accounts in domains.conf
and as present in the data/accounts/ directory, not a configured email address
for an account.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()

	pw := xreadpassword()

	ctlcmdSetaccountpassword(xctl(), args[0], pw)
}

func ctlcmdSetaccountpassword(ctl *ctl, account, password string) {
	ctl.xwrite("setaccountpassword")
	ctl.xwrite(account)
	ctl.xwrite(password)
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
	ctlcmdDeliver(xctl(), args[0])
}

func ctlcmdDeliver(ctl *ctl, address string) {
	ctl.xwrite("deliver")
	ctl.xwrite(address)
	ctl.xreadok()
	ctl.xstreamfrom(os.Stdin)
	line := ctl.xread()
	if line == "ok" {
		fmt.Println("message delivered")
	} else {
		log.Fatalf("deliver: %s", line)
	}
}

func cmdDKIMGenrsa(c *cmd) {
	c.params = ">$selector._domainkey.$domain.rsa2048.privatekey.pkcs8.pem"
	c.help = `Generate a new 2048 bit RSA private key for use with DKIM.

The generated file is in PEM format, and has a comment it is generated for use
with DKIM, by mox.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	buf, err := admin.MakeDKIMRSAKey(dns.Domain{}, dns.Domain{})
	xcheckf(err, "making rsa private key")
	_, err = os.Stdout.Write(buf)
	xcheckf(err, "writing rsa private key")
}

func cmdDANEDial(c *cmd) {
	c.params = "host:port"
	var usages string
	c.flag.StringVar(&usages, "usages", "pkix-ta,pkix-ee,dane-ta,dane-ee", "allowed usages for dane, comma-separated list")
	c.help = `Dial the address using TLS with certificate verification using DANE.

Data is copied between connection and stdin/stdout until either side closes the
connection.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	allowedUsages := []adns.TLSAUsage{}
	if usages != "" {
		for _, s := range strings.Split(usages, ",") {
			var usage adns.TLSAUsage
			switch strings.ToLower(s) {
			case "pkix-ta", strconv.Itoa(int(adns.TLSAUsagePKIXTA)):
				usage = adns.TLSAUsagePKIXTA
			case "pkix-ee", strconv.Itoa(int(adns.TLSAUsagePKIXEE)):
				usage = adns.TLSAUsagePKIXEE
			case "dane-ta", strconv.Itoa(int(adns.TLSAUsageDANETA)):
				usage = adns.TLSAUsageDANETA
			case "dane-ee", strconv.Itoa(int(adns.TLSAUsageDANEEE)):
				usage = adns.TLSAUsageDANEEE
			default:
				log.Fatalf("unknown dane usage %q", s)
			}
			allowedUsages = append(allowedUsages, usage)
		}
	}

	pkixRoots, err := x509.SystemCertPool()
	xcheckf(err, "get system pkix certificate pool")

	resolver := dns.StrictResolver{Pkg: "danedial"}
	conn, record, err := dane.Dial(context.Background(), c.log.Logger, resolver, "tcp", args[0], allowedUsages, pkixRoots)
	xcheckf(err, "dial")
	log.Printf("(connected, verified with %s)", record)

	go func() {
		_, err := io.Copy(os.Stdout, conn)
		xcheckf(err, "copy from connection to stdout")
		err = conn.Close()
		c.log.Check(err, "closing connection")
	}()
	_, err = io.Copy(conn, os.Stdin)
	xcheckf(err, "copy from stdin to connection")
}

func cmdDANEDialmx(c *cmd) {
	c.params = "domain [destination-host]"
	var ehloHostname string
	c.flag.StringVar(&ehloHostname, "ehlohostname", "localhost", "hostname to send in smtp ehlo command")
	c.help = `Connect to MX server for domain using STARTTLS verified with DANE.

If no destination host is specified, regular delivery logic is used to find the
hosts to attempt delivery too. This involves following CNAMEs for the domain,
looking up MX records, and possibly falling back to the domain name itself as
host.

If a destination host is specified, that is the only candidate host considered
for dialing.

With a list of destinations gathered, each is dialed until a successful SMTP
session verified with DANE has been initialized, including EHLO and STARTTLS
commands.

Once connected, data is copied between connection and stdin/stdout, until
either side closes the connection.

This command follows the same logic as delivery attempts made from the queue,
sharing most of its code.
`
	args := c.Parse()
	if len(args) != 1 && len(args) != 2 {
		c.Usage()
	}

	ehloDomain := xparseDomain(ehloHostname, "ehlo host name")
	origNextHop := xparseDomain(args[0], "domain")

	ctxbg := context.Background()

	resolver := dns.StrictResolver{}
	var haveMX bool
	var expandedNextHopAuthentic bool
	var expandedNextHop dns.Domain
	var hosts []dns.IPDomain
	if len(args) == 1 {
		var permanent bool
		var origNextHopAuthentic bool
		var err error
		haveMX, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, hosts, permanent, err = smtpclient.GatherDestinations(ctxbg, c.log.Logger, resolver, dns.IPDomain{Domain: origNextHop})
		status := "temporary"
		if permanent {
			status = "permanent"
		}
		if err != nil {
			log.Fatalf("gathering destinations: %v (%s)", err, status)
		}
		if expandedNextHop != origNextHop {
			log.Printf("followed cnames to %s", expandedNextHop)
		}
		if haveMX {
			log.Printf("found mx record, trying mx hosts")
		} else {
			log.Printf("no mx record found, will try to connect to domain directly")
		}
		if !origNextHopAuthentic {
			log.Fatalf("error: initial domain not dnssec-secure")
		}
		if !expandedNextHopAuthentic {
			log.Fatalf("error: expanded domain not dnssec-secure")
		}

		l := []string{}
		for _, h := range hosts {
			l = append(l, h.String())
		}
		log.Printf("destinations: %s", strings.Join(l, ", "))
	} else {
		d := xparseDomain(args[1], "destination host")
		log.Printf("skipping domain mx/cname lookups, assuming domain is dnssec-protected")

		expandedNextHopAuthentic = true
		expandedNextHop = d
		hosts = []dns.IPDomain{{Domain: d}}
	}

	dialedIPs := map[string][]net.IP{}
	for _, host := range hosts {
		// It should not be possible for hosts to have IP addresses: They are not
		// allowed by dns.ParseDomain, and MX records cannot contain them.
		if host.IsIP() {
			log.Fatalf("unexpected IP address for destination host")
		}

		log.Printf("attempting to connect to %s", host)

		authentic, expandedAuthentic, expandedHost, ips, _, err := smtpclient.GatherIPs(ctxbg, c.log.Logger, resolver, "ip", host, dialedIPs)
		if err != nil {
			log.Printf("resolving ips for %s: %v, skipping", host, err)
			continue
		}
		if !authentic {
			log.Printf("no dnssec for ips of %s, skipping", host)
			continue
		}
		if !expandedAuthentic {
			log.Printf("no dnssec for cname-followed ips of %s, skipping", host)
			continue
		}
		if expandedHost != host.Domain {
			log.Printf("host %s cname-expanded to %s", host, expandedHost)
		}
		log.Printf("host %s resolved to ips %s, looking up tlsa records", host, ips)

		daneRequired, daneRecords, tlsaBaseDomain, err := smtpclient.GatherTLSA(ctxbg, c.log.Logger, resolver, host.Domain, expandedAuthentic, expandedHost)
		if err != nil {
			log.Printf("looking up tlsa records: %s, skipping", err)
			continue
		}
		tlsMode := smtpclient.TLSRequiredStartTLS
		if len(daneRecords) == 0 {
			if !daneRequired {
				log.Printf("host %s has no tlsa records, skipping", expandedHost)
				continue
			}
			log.Printf("warning: only unusable tlsa records found, continuing with required tls without certificate verification")
			daneRecords = nil
		} else {
			var l []string
			for _, r := range daneRecords {
				l = append(l, r.String())
			}
			log.Printf("tlsa records: %s", strings.Join(l, "; "))
		}

		tlsHostnames := smtpclient.GatherTLSANames(haveMX, expandedNextHopAuthentic, expandedAuthentic, origNextHop, expandedNextHop, host.Domain, tlsaBaseDomain)
		var l []string
		for _, name := range tlsHostnames {
			l = append(l, name.String())
		}
		log.Printf("gathered valid tls certificate names for potential verification with dane-ta: %s", strings.Join(l, ", "))

		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, _, err := smtpclient.Dial(ctxbg, c.log.Logger, dialer, dns.IPDomain{Domain: expandedHost}, ips, 25, dialedIPs, nil)
		if err != nil {
			log.Printf("dial %s: %v, skipping", expandedHost, err)
			continue
		}
		log.Printf("connected to %s, %s, starting smtp session with ehlo and starttls with dane verification", expandedHost, conn.RemoteAddr())

		var verifiedRecord adns.TLSA
		opts := smtpclient.Opts{
			DANERecords:        daneRecords,
			DANEMoreHostnames:  tlsHostnames[1:],
			DANEVerifiedRecord: &verifiedRecord,
			RootCAs:            mox.Conf.Static.TLS.CertPool,
		}
		tlsPKIX := false
		sc, err := smtpclient.New(ctxbg, c.log.Logger, conn, tlsMode, tlsPKIX, ehloDomain, tlsHostnames[0], opts)
		if err != nil {
			log.Printf("setting up smtp session: %v, skipping", err)
			if xerr := conn.Close(); xerr != nil {
				log.Printf("closing connection: %v", xerr)
			}
			continue
		}

		smtpConn, err := sc.Conn()
		if err != nil {
			log.Fatalf("error: taking over smtp connection: %s", err)
		}
		log.Printf("tls verified with tlsa record: %s", verifiedRecord)
		log.Printf("smtp session initialized and connected to stdin/stdout")

		go func() {
			_, err := io.Copy(os.Stdout, smtpConn)
			xcheckf(err, "copy from connection to stdout")
			if err := smtpConn.Close(); err != nil {
				log.Printf("closing smtp connection: %v", err)
			}
		}()
		_, err = io.Copy(smtpConn, os.Stdin)
		xcheckf(err, "copy from stdin to connection")
	}

	log.Fatalf("no remaining destinations")
}

func cmdDANEMakeRecord(c *cmd) {
	c.params = "usage selector matchtype [certificate.pem | publickey.pem | privatekey.pem]"
	c.help = `Print TLSA record for given certificate/key and parameters.

Valid values:
- usage: pkix-ta (0), pkix-ee (1), dane-ta (2), dane-ee (3)
- selector: cert (0), spki (1)
- matchtype: full (0), sha2-256 (1), sha2-512 (2)

Common DANE TLSA record parameters are: dane-ee spki sha2-256, or 3 1 1,
followed by a sha2-256 hash of the DER-encoded "SPKI" (subject public key info)
from the certificate. An example DNS zone file entry:

	_25._tcp.example.com. TLSA 3 1 1 133b919c9d65d8b1488157315327334ead8d83372db57465ecabf53ee5748aee

The first usable information from the pem file is used to compose the TLSA
record. In case of selector "cert", a certificate is required. Otherwise the
"subject public key info" (spki) of the first certificate or public or private
key (pkcs#8, pkcs#1 or ec private key) is used.
`

	args := c.Parse()
	if len(args) != 4 {
		c.Usage()
	}

	var usage adns.TLSAUsage
	switch strings.ToLower(args[0]) {
	case "pkix-ta", strconv.Itoa(int(adns.TLSAUsagePKIXTA)):
		usage = adns.TLSAUsagePKIXTA
	case "pkix-ee", strconv.Itoa(int(adns.TLSAUsagePKIXEE)):
		usage = adns.TLSAUsagePKIXEE
	case "dane-ta", strconv.Itoa(int(adns.TLSAUsageDANETA)):
		usage = adns.TLSAUsageDANETA
	case "dane-ee", strconv.Itoa(int(adns.TLSAUsageDANEEE)):
		usage = adns.TLSAUsageDANEEE
	default:
		if v, err := strconv.ParseUint(args[0], 10, 16); err != nil {
			log.Fatalf("bad usage %q", args[0])
		} else {
			// Does not influence certificate association data, so we can accept other numbers.
			log.Printf("warning: continuing with unrecognized tlsa usage %d", v)
			usage = adns.TLSAUsage(v)
		}
	}

	var selector adns.TLSASelector
	switch strings.ToLower(args[1]) {
	case "cert", strconv.Itoa(int(adns.TLSASelectorCert)):
		selector = adns.TLSASelectorCert
	case "spki", strconv.Itoa(int(adns.TLSASelectorSPKI)):
		selector = adns.TLSASelectorSPKI
	default:
		log.Fatalf("bad selector %q", args[1])
	}

	var matchType adns.TLSAMatchType
	switch strings.ToLower(args[2]) {
	case "full", strconv.Itoa(int(adns.TLSAMatchTypeFull)):
		matchType = adns.TLSAMatchTypeFull
	case "sha2-256", strconv.Itoa(int(adns.TLSAMatchTypeSHA256)):
		matchType = adns.TLSAMatchTypeSHA256
	case "sha2-512", strconv.Itoa(int(adns.TLSAMatchTypeSHA512)):
		matchType = adns.TLSAMatchTypeSHA512
	default:
		log.Fatalf("bad matchtype %q", args[2])
	}

	buf, err := os.ReadFile(args[3])
	xcheckf(err, "reading certificate")
	for {
		var block *pem.Block
		block, buf = pem.Decode(buf)
		if block == nil {
			extra := ""
			if len(buf) > 0 {
				extra = " (with leftover data from pem file)"
			}
			if selector == adns.TLSASelectorCert {
				log.Fatalf("no certificate found in pem file%s", extra)
			} else {
				log.Fatalf("no certificate or public or private key found in pem file%s", extra)
			}
		}
		var cert *x509.Certificate
		var data []byte
		if block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
			xcheckf(err, "parse certificate")
			switch selector {
			case adns.TLSASelectorCert:
				data = cert.Raw
			case adns.TLSASelectorSPKI:
				data = cert.RawSubjectPublicKeyInfo
			}
		} else if selector == adns.TLSASelectorCert {
			// We need a certificate, just a public/private key won't do.
			log.Printf("skipping pem type %q, certificate is required", block.Type)
			continue
		} else {
			var privKey, pubKey any
			var err error
			switch block.Type {
			case "PUBLIC KEY":
				_, err := x509.ParsePKIXPublicKey(block.Bytes)
				xcheckf(err, "parse pkix subject public key info (spki)")
				data = block.Bytes
			case "EC PRIVATE KEY":
				privKey, err = x509.ParseECPrivateKey(block.Bytes)
				xcheckf(err, "parse ec private key")
			case "RSA PRIVATE KEY":
				privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				xcheckf(err, "parse pkcs#1 rsa private key")
			case "RSA PUBLIC KEY":
				pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
				xcheckf(err, "parse pkcs#1 rsa public key")
			case "PRIVATE KEY":
				// PKCS#8 private key
				privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				xcheckf(err, "parse pkcs#8 private key")
			default:
				log.Printf("skipping unrecognized pem type %q", block.Type)
				continue
			}
			if data == nil {
				if pubKey == nil && privKey != nil {
					if signer, ok := privKey.(crypto.Signer); !ok {
						log.Fatalf("private key of type %T is not a signer, cannot get public key", privKey)
					} else {
						pubKey = signer.Public()
					}
				}
				if pubKey == nil {
					// Should not happen.
					log.Fatalf("internal error: did not find private or public key")
				}
				data, err = x509.MarshalPKIXPublicKey(pubKey)
				xcheckf(err, "marshal pkix subject public key info (spki)")
			}
		}

		switch matchType {
		case adns.TLSAMatchTypeFull:
		case adns.TLSAMatchTypeSHA256:
			p := sha256.Sum256(data)
			data = p[:]
		case adns.TLSAMatchTypeSHA512:
			p := sha512.Sum512(data)
			data = p[:]
		}
		fmt.Printf("%d %d %d %x\n", usage, selector, matchType, data)
		break
	}
}

func cmdDNSLookup(c *cmd) {
	c.params = "[ptr | mx | cname | ips | a | aaaa | ns | txt | srv | tlsa] name"
	c.help = `Lookup DNS name of given type.

Lookup always prints whether the response was DNSSEC-protected.

Examples:

mox dns lookup ptr 1.1.1.1
mox dns lookup mx xmox.nl
mox dns lookup txt _dmarc.xmox.nl.
mox dns lookup tlsa _25._tcp.xmox.nl
`
	args := c.Parse()

	if len(args) != 2 {
		c.Usage()
	}

	resolver := dns.StrictResolver{Pkg: "dns"}

	// like xparseDomain, but treat unparseable domain as an ASCII name so names with
	// underscores are still looked up, e,g <selector>._domainkey.<host>.
	xdomain := func(s string) dns.Domain {
		d, err := dns.ParseDomain(s)
		if err != nil {
			return dns.Domain{ASCII: strings.TrimSuffix(s, ".")}
		}
		return d
	}

	cmd, name := args[0], args[1]

	switch cmd {
	case "ptr":
		ip := xparseIP(name, "ip")
		ptrs, result, err := resolver.LookupAddr(context.Background(), ip.String())
		if err != nil {
			log.Fatalf("dns lookup: %v (%s)", err, dnssecStatus(result.Authentic))
		}
		fmt.Printf("names (%d, %s):\n", len(ptrs), dnssecStatus(result.Authentic))
		for _, ptr := range ptrs {
			fmt.Printf("- %s\n", ptr)
		}

	case "mx":
		name := xdomain(name)
		mxl, result, err := resolver.LookupMX(context.Background(), name.ASCII+".")
		if err != nil {
			log.Printf("dns lookup: %v (%s)", err, dnssecStatus(result.Authentic))
			// We can still have valid records...
		}
		fmt.Printf("mx records (%d, %s):\n", len(mxl), dnssecStatus(result.Authentic))
		for _, mx := range mxl {
			fmt.Printf("- %s, preference %d\n", mx.Host, mx.Pref)
		}

	case "cname":
		name := xdomain(name)
		target, result, err := resolver.LookupCNAME(context.Background(), name.ASCII+".")
		if err != nil {
			log.Fatalf("dns lookup: %v (%s)", err, dnssecStatus(result.Authentic))
		}
		fmt.Printf("%s (%s)\n", target, dnssecStatus(result.Authentic))

	case "ips", "a", "aaaa":
		network := "ip"
		if cmd == "a" {
			network = "ip4"
		} else if cmd == "aaaa" {
			network = "ip6"
		}
		name := xdomain(name)
		ips, result, err := resolver.LookupIP(context.Background(), network, name.ASCII+".")
		if err != nil {
			log.Fatalf("dns lookup: %v (%s)", err, dnssecStatus(result.Authentic))
		}
		fmt.Printf("records (%d, %s):\n", len(ips), dnssecStatus(result.Authentic))
		for _, ip := range ips {
			fmt.Printf("- %s\n", ip)
		}

	case "ns":
		name := xdomain(name)
		nsl, result, err := resolver.LookupNS(context.Background(), name.ASCII+".")
		if err != nil {
			log.Fatalf("dns lookup: %v (%s)", err, dnssecStatus(result.Authentic))
		}
		fmt.Printf("ns records (%d, %s):\n", len(nsl), dnssecStatus(result.Authentic))
		for _, ns := range nsl {
			fmt.Printf("- %s\n", ns)
		}

	case "txt":
		host := xdomain(name)
		l, result, err := resolver.LookupTXT(context.Background(), host.ASCII+".")
		if err != nil {
			log.Fatalf("dns lookup: %v (%s)", err, dnssecStatus(result.Authentic))
		}
		fmt.Printf("txt records (%d, %s):\n", len(l), dnssecStatus(result.Authentic))
		for _, txt := range l {
			fmt.Printf("- %s\n", txt)
		}

	case "srv":
		host := xdomain(name)
		_, l, result, err := resolver.LookupSRV(context.Background(), "", "", host.ASCII+".")
		if err != nil {
			log.Fatalf("dns lookup: %v (%s)", err, dnssecStatus(result.Authentic))
		}
		fmt.Printf("srv records (%d, %s):\n", len(l), dnssecStatus(result.Authentic))
		for _, srv := range l {
			fmt.Printf("- host %s, port %d, priority %d, weight %d\n", srv.Target, srv.Port, srv.Priority, srv.Weight)
		}

	case "tlsa":
		host := xdomain(name)
		l, result, err := resolver.LookupTLSA(context.Background(), 0, "", host.ASCII+".")
		if err != nil {
			log.Fatalf("dns lookup: %v (%s)", err, dnssecStatus(result.Authentic))
		}
		fmt.Printf("tlsa records (%d, %s):\n", len(l), dnssecStatus(result.Authentic))
		for _, tlsa := range l {
			fmt.Printf("- usage %q (%d), selector %q (%d), matchtype %q (%d), certificate association data %x\n", tlsa.Usage, tlsa.Usage, tlsa.Selector, tlsa.Selector, tlsa.MatchType, tlsa.MatchType, tlsa.CertAssoc)
		}
	default:
		log.Fatalf("unknown record type %q", args[0])
	}
}

func cmdDKIMGened25519(c *cmd) {
	c.params = ">$selector._domainkey.$domain.ed25519.privatekey.pkcs8.pem"
	c.help = `Generate a new ed25519 key for use with DKIM.

Ed25519 keys are much smaller than RSA keys of comparable cryptographic
strength. This is convenient because of maximum DNS message sizes. At the time
of writing, not many mail servers appear to support ed25519 DKIM keys though,
so it is recommended to sign messages with both RSA and ed25519 keys.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	buf, err := admin.MakeDKIMEd25519Key(dns.Domain{}, dns.Domain{})
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
	fmt.Print("<selector>._domainkey.<your.domain.> TXT ")
	for record != "" {
		s := record
		if len(s) > 100 {
			s, record = record[:100], record[100:]
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

	results, err := dkim.Verify(context.Background(), c.log.Logger, dns.StrictResolver{}, false, dkim.DefaultPolicy, msgf, true)
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
	defer func() {
		if err := msgf.Close(); err != nil {
			log.Printf("closing message file: %v", err)
		}
	}()

	p, err := message.Parse(c.log.Logger, true, msgf)
	xcheckf(err, "parsing message")

	if len(p.Envelope.From) != 1 {
		log.Fatalf("found %d from headers, need exactly 1", len(p.Envelope.From))
	}
	localpart, err := smtp.ParseLocalpart(p.Envelope.From[0].User)
	xcheckf(err, "parsing localpart of address in from-header")
	dom := xparseDomain(p.Envelope.From[0].Host, "domain of address in from-header")

	mustLoadConfig()

	domConf, ok := mox.Conf.Domain(dom)
	if !ok {
		log.Fatalf("domain %s not configured", dom)
	}

	selectors := mox.DKIMSelectors(domConf.DKIM)
	headers, err := dkim.Sign(context.Background(), c.log.Logger, localpart, dom, selectors, false, msgf)
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

	status, record, txt, authentic, err := dkim.Lookup(context.Background(), c.log.Logger, dns.StrictResolver{}, selector, domain)
	if err != nil {
		fmt.Printf("error: %s\n", err)
	}
	if status != dkim.StatusNeutral {
		fmt.Printf("status: %s\n", status)
	}
	if txt != "" {
		fmt.Printf("TXT record: %s\n", txt)
	}
	if authentic {
		fmt.Println("dnssec-signed: yes")
	} else {
		fmt.Println("dnssec-signed: no")
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
	_, domain, _, txt, authentic, err := dmarc.Lookup(context.Background(), c.log.Logger, dns.StrictResolver{}, fromdomain)
	xcheckf(err, "dmarc lookup domain %s", fromdomain)
	fmt.Printf("dmarc record at domain %s: %s\n", domain, txt)
	fmt.Printf("(%s)\n", dnssecStatus(authentic))
}

func dnssecStatus(v bool) string {
	if v {
		return "with dnssec"
	}
	return "without dnssec"
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
		rspf, spfDomain, expl, authentic, err := spf.Verify(context.Background(), c.log.Logger, dns.StrictResolver{}, spfArgs)
		if err != nil {
			log.Printf("spf verify: %v (explanation: %q, authentic %v)", err, expl, authentic)
		} else {
			received = &rspf
			spfStatus = received.Result
			// todo: should probably potentially do two separate spf validations
			if mailfrom != nil {
				spfIdentity = &mailfrom.Domain
			} else {
				spfIdentity = heloDomain
			}
			fmt.Printf("spf result: %s: %s (%s)\n", spfDomain, spfStatus, dnssecStatus(authentic))
		}
	}

	data, err := io.ReadAll(os.Stdin)
	xcheckf(err, "read message")
	dmarcFrom, _, _, err := message.From(c.log.Logger, false, bytes.NewReader(data), nil)
	xcheckf(err, "extract dmarc from message")

	const ignoreTestMode = false
	dkimResults, err := dkim.Verify(context.Background(), c.log.Logger, dns.StrictResolver{}, true, func(*dkim.Sig) error { return nil }, bytes.NewReader(data), ignoreTestMode)
	xcheckf(err, "dkim verify")
	for _, r := range dkimResults {
		fmt.Printf("dkim result: %q (err %v)\n", r.Status, r.Err)
	}

	_, result := dmarc.Verify(context.Background(), c.log.Logger, dns.StrictResolver{}, dmarcFrom.Domain, dkimResults, spfStatus, spfIdentity, false)
	xcheckf(result.Err, "dmarc verify")
	fmt.Printf("dmarc from: %s\ndmarc status: %q\ndmarc reject: %v\ncmarc record: %s\n", dmarcFrom, result.Status, result.Reject, result.Record)
}

func cmdDMARCCheckreportaddrs(c *cmd) {
	c.params = "domain"
	c.help = `For each reporting address in the domain's DMARC record, check if it has opted into receiving reports (if needed).

A DMARC record can request reports about DMARC evaluations to be sent to an
email/http address. If the organizational domains of that of the DMARC record
and that of the report destination address do not match, the destination
address must opt-in to receiving DMARC reports by creating a DMARC record at
<dmarcdomain>._report._dmarc.<reportdestdomain>.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	dom := xparseDomain(args[0], "domain")
	_, domain, record, txt, authentic, err := dmarc.Lookup(context.Background(), c.log.Logger, dns.StrictResolver{}, dom)
	xcheckf(err, "dmarc lookup domain %s", dom)
	fmt.Printf("dmarc record at domain %s: %q\n", domain, txt)
	fmt.Printf("(%s)\n", dnssecStatus(authentic))

	check := func(kind, addr string) {
		var authentic bool

		printResult := func(format string, args ...any) {
			fmt.Printf("%s %s: %s (%s)\n", kind, addr, fmt.Sprintf(format, args...), dnssecStatus(authentic))
		}

		u, err := url.Parse(addr)
		if err != nil {
			printResult("parsing uri: %v (skipping)", addr, err)
			return
		}
		var destdom dns.Domain
		switch u.Scheme {
		case "mailto":
			a, err := smtp.ParseAddress(u.Opaque)
			if err != nil {
				printResult("parsing destination email address %s: %v (skipping)", u.Opaque, err)
				return
			}
			destdom = a.Domain
		default:
			printResult("unrecognized scheme in reporting address %s (skipping)", u.Scheme)
			return
		}

		if publicsuffix.Lookup(context.Background(), c.log.Logger, dom) == publicsuffix.Lookup(context.Background(), c.log.Logger, destdom) {
			printResult("pass (same organizational domain)")
			return
		}

		accepts, status, _, txts, authentic, err := dmarc.LookupExternalReportsAccepted(context.Background(), c.log.Logger, dns.StrictResolver{}, domain, destdom)
		var txtstr string
		txtaddr := fmt.Sprintf("%s._report._dmarc.%s", domain.ASCII, destdom.ASCII)
		if len(txts) == 0 {
			txtstr = fmt.Sprintf(" (no txt records %s)", txtaddr)
		} else {
			txtstr = fmt.Sprintf(" (txt record %s: %q)", txtaddr, txts)
		}
		if status != dmarc.StatusNone {
			printResult("fail: %s%s", err, txtstr)
		} else if accepts {
			printResult("pass%s", txtstr)
		} else if err != nil {
			printResult("fail: %s%s", err, txtstr)
		} else {
			printResult("fail%s", txtstr)
		}
	}

	for _, uri := range record.AggregateReportAddresses {
		check("aggregate reporting", uri.Address)
	}
	for _, uri := range record.FailureReportAddresses {
		check("failure reporting", uri.Address)
	}
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
		feedback, err := dmarcrpt.ParseMessageReport(c.log.Logger, f)
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
	report, err := dmarcrpt.ParseMessageReport(c.log.Logger, os.Stdin)
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
	_, txt, err := tlsrpt.Lookup(context.Background(), c.log.Logger, dns.StrictResolver{}, d)
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
		reportJSON, err := tlsrpt.ParseMessage(c.log.Logger, f)
		xcheckf(err, "parse report in %q", arg)
		// todo future: only print the highlights?
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "\t")
		enc.SetEscapeHTML(false)
		err = enc.Encode(reportJSON)
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
	r, _, explanation, authentic, err := spf.Verify(context.Background(), c.log.Logger, dns.StrictResolver{}, spfargs)
	if err != nil {
		fmt.Printf("error: %s\n", err)
	}
	if explanation != "" {
		fmt.Printf("explanation: %s\n", explanation)
	}
	fmt.Printf("status: %s (%s)\n", r.Result, dnssecStatus(authentic))
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
	_, txt, _, authentic, err := spf.Lookup(context.Background(), c.log.Logger, dns.StrictResolver{}, domain)
	xcheckf(err, "spf lookup for %s", domain)
	fmt.Println(txt)
	fmt.Printf("(%s)\n", dnssecStatus(authentic))
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

	record, policy, _, err := mtasts.Get(context.Background(), c.log.Logger, dns.StrictResolver{}, domain)
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

func cmdRDAPDomainage(c *cmd) {
	c.params = "domain"
	c.help = `Lookup the age of domain in RDAP based on latest registration.

RDAP is the registration data access protocol. Registries run RDAP services for
their top level domains, providing information such as the registration date of
domains. This command looks up the "age" of a domain by looking at the most
recent "registration", "reregistration" or "reinstantiation" event.

Email messages from recently registered domains are often treated with
suspicion, and some mail systems are more likely to classify them as junk.

On each invocation, a bootstrap file with a list of registries (of top-level
domains) is retrieved, without caching. Do not run this command too often with
automation.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	domain := xparseDomain(args[0], "domain")

	registration, err := rdap.LookupLastDomainRegistration(context.Background(), c.log, domain)
	xcheckf(err, "looking up domain in rdap")

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
	fmt.Println(s)
}

func cmdRetrain(c *cmd) {
	c.params = "[accountname]"
	c.help = `Recreate and retrain the junk filter for the account or all accounts.

Useful after having made changes to the junk filter configuration, or if the
implementation has changed.
`
	args := c.Parse()
	if len(args) > 1 {
		c.Usage()
	}
	var account string
	if len(args) == 1 {
		account = args[0]
	}

	mustLoadConfig()
	ctlcmdRetrain(xctl(), account)
}

func ctlcmdRetrain(ctl *ctl, account string) {
	ctl.xwrite("retrain")
	ctl.xwrite(account)
	ctl.xreadok()
}

func cmdTLSRPTDBAddReport(c *cmd) {
	c.unlisted = true
	c.params = "< message"
	c.help = "Parse a TLS report from the message and add it to the database."
	var hostReport bool
	c.flag.BoolVar(&hostReport, "hostreport", false, "report for a host instead of domain")
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	mustLoadConfig()

	// First read message, to get the From-header. Then parse it as TLSRPT.
	fmt.Fprintln(os.Stderr, "reading report message from stdin")
	buf, err := io.ReadAll(os.Stdin)
	xcheckf(err, "reading message")
	part, err := message.Parse(c.log.Logger, true, bytes.NewReader(buf))
	xcheckf(err, "parsing message")
	if part.Envelope == nil || len(part.Envelope.From) != 1 {
		log.Fatalf("message must have one From-header")
	}
	from := part.Envelope.From[0]
	domain := xparseDomain(from.Host, "domain")

	reportJSON, err := tlsrpt.ParseMessage(c.log.Logger, bytes.NewReader(buf))
	xcheckf(err, "parsing tls report in message")

	mailfrom := from.User + "@" + from.Host // todo future: should escape and such
	report := reportJSON.Convert()
	err = tlsrptdb.AddReport(context.Background(), c.log, domain, mailfrom, hostReport, &report)
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

	status, explanation, err := dnsbl.Lookup(context.Background(), c.log.Logger, dns.StrictResolver{}, zone, ip)
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
	err := dnsbl.CheckHealth(context.Background(), c.log.Logger, dns.StrictResolver{}, zone)
	xcheckf(err, "unhealthy")
	fmt.Println("healthy")
}

func cmdCheckupdate(c *cmd) {
	c.help = `Check if a newer version of mox is available.

A single DNS TXT lookup to _updates.xmox.nl tells if a new version is
available. If so, a changelog is fetched from https://updates.xmox.nl, and the
individual entries verified with a builtin public key. The changelog is
printed.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()

	current, lastknown, _, err := store.LastKnown()
	if err != nil {
		log.Printf("getting last known version: %s", err)
	} else {
		fmt.Printf("last known version: %s\n", lastknown)
		fmt.Printf("current version: %s\n", current)
	}
	latest, _, err := updates.Lookup(context.Background(), c.log.Logger, dns.StrictResolver{}, dns.Domain{ASCII: changelogDomain})
	xcheckf(err, "lookup of latest version")
	fmt.Printf("latest version: %s\n", latest)

	if latest.After(current) {
		changelog, err := updates.FetchChangelog(context.Background(), c.log.Logger, changelogURL, current, changelogPubKey)
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
	fmt.Printf("%s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func cmdWebapi(c *cmd) {
	c.params = "[method [baseurl-with-credentials]"
	c.help = "Lists available methods, prints request/response parameters for method, or calls a method with a request read from standard input."
	args := c.Parse()
	if len(args) > 2 {
		c.Usage()
	}

	t := reflect.TypeFor[webapi.Methods]()
	methods := map[string]reflect.Type{}
	var ml []string
	for i := range t.NumMethod() {
		mt := t.Method(i)
		methods[mt.Name] = mt.Type
		ml = append(ml, mt.Name)
	}

	if len(args) == 0 {
		fmt.Println(strings.Join(ml, "\n"))
		return
	}

	mt, ok := methods[args[0]]
	if !ok {
		log.Fatalf("unknown method %q", args[0])
	}
	resultNotJSON := mt.Out(0).Kind() == reflect.Interface

	if len(args) == 1 {
		fmt.Println("# Example request")
		fmt.Println()
		printJSON("\t", mox.FillExample(nil, reflect.New(mt.In(1))).Interface())
		fmt.Println()
		if resultNotJSON {
			fmt.Println("Output is non-JSON data.")
			return
		}
		fmt.Println("# Example response")
		fmt.Println()
		printJSON("\t", mox.FillExample(nil, reflect.New(mt.Out(0))).Interface())
		return
	}

	var response any
	if !resultNotJSON {
		response = reflect.New(mt.Out(0))
	}

	fmt.Fprintln(os.Stderr, "reading request from stdin...")
	request, err := io.ReadAll(os.Stdin)
	xcheckf(err, "read message")

	dec := json.NewDecoder(bytes.NewReader(request))
	dec.DisallowUnknownFields()
	err = dec.Decode(reflect.New(mt.In(1)).Interface())
	xcheckf(err, "parsing request")

	resp, err := http.PostForm(args[1]+args[0], url.Values{"request": []string{string(request)}})
	xcheckf(err, "http post")
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("closing http response body: %v", err)
		}
	}()
	if resp.StatusCode == http.StatusBadRequest {
		buf, err := io.ReadAll(&moxio.LimitReader{R: resp.Body, Limit: 10 * 1024})
		xcheckf(err, "reading response for 400 bad request error")
		err = json.Unmarshal(buf, &response)
		if err == nil {
			printJSON("", response)
		} else {
			fmt.Fprintf(os.Stderr, "(not json)\n")
			os.Stderr.Write(buf)
		}
		os.Exit(1)
	} else if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "http response %s\n", resp.Status)
		_, err := io.Copy(os.Stderr, resp.Body)
		xcheckf(err, "copy body")
	} else {
		err := json.NewDecoder(resp.Body).Decode(&resp)
		xcheckf(err, "unmarshal response")
		printJSON("", response)
	}
}

func printJSON(indent string, v any) {
	fmt.Printf("%s", indent)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent(indent, "\t")
	enc.SetEscapeHTML(false)
	err := enc.Encode(v)
	xcheckf(err, "encode json")
}

// todo: should make it possible to run this command against a running mox. it should disconnect existing clients for accounts with a bumped uidvalidity, so they will reconnect and refetch the data.
func cmdBumpUIDValidity(c *cmd) {
	c.params = "account [mailbox]"
	c.help = `Change the IMAP UID validity of the mailbox, causing IMAP clients to refetch messages.

This can be useful after manually repairing metadata about the account/mailbox.

Opens account database file directly. Ensure mox does not have the account
open, or is not running.
`
	args := c.Parse()
	if len(args) != 1 && len(args) != 2 {
		c.Usage()
	}

	mustLoadConfig()
	a, err := store.OpenAccount(c.log, args[0], false)
	xcheckf(err, "open account")
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing account: %v", err)
		}
	}()

	err = a.DB.Write(context.Background(), func(tx *bstore.Tx) error {
		uidvalidity, err := a.NextUIDValidity(tx)
		if err != nil {
			return fmt.Errorf("assigning next uid validity: %v", err)
		}

		q := bstore.QueryTx[store.Mailbox](tx)
		q.FilterEqual("Expunged", false)
		if len(args) == 2 {
			q.FilterEqual("Name", args[1])
		}
		mbl, err := q.SortAsc("Name").List()
		if err != nil {
			return fmt.Errorf("looking up mailbox: %v", err)
		}
		if len(args) == 2 && len(mbl) != 1 {
			return fmt.Errorf("looking up mailbox %q, found %d mailboxes", args[1], len(mbl))
		}
		for _, mb := range mbl {
			mb.UIDValidity = uidvalidity
			err = tx.Update(&mb)
			if err != nil {
				return fmt.Errorf("updating uid validity for mailbox: %v", err)
			}
			fmt.Printf("uid validity for %q updated to %d\n", mb.Name, uidvalidity)
		}
		return nil
	})
	xcheckf(err, "updating database")
}

func cmdReassignUIDs(c *cmd) {
	c.params = "account [mailboxid]"
	c.help = `Reassign UIDs in one mailbox or all mailboxes in an account and bump UID validity, causing IMAP clients to refetch messages.

Opens account database file directly. Ensure mox does not have the account
open, or is not running.
`
	args := c.Parse()
	if len(args) != 1 && len(args) != 2 {
		c.Usage()
	}

	var mailboxID int64
	if len(args) == 2 {
		var err error
		mailboxID, err = strconv.ParseInt(args[1], 10, 64)
		xcheckf(err, "parsing mailbox id")
	}

	mustLoadConfig()
	a, err := store.OpenAccount(c.log, args[0], false)
	xcheckf(err, "open account")
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing account: %v", err)
		}
	}()

	// Gather the last-assigned UIDs per mailbox.
	uidlasts := map[int64]store.UID{}

	err = a.DB.Write(context.Background(), func(tx *bstore.Tx) error {
		// Reassign UIDs, going per mailbox. We assign starting at 1, only changing the
		// message if it isn't already at the intended UID. Doing it in this order ensures
		// we don't get into trouble with duplicate UIDs for a mailbox. We assign a new
		// modseq. Not strictly needed, but doesn't hurt. It's also why we assign a UID to
		// expunged messages.
		modseq, err := a.NextModSeq(tx)
		xcheckf(err, "assigning next modseq")

		q := bstore.QueryTx[store.Message](tx)
		if len(args) == 2 {
			q.FilterNonzero(store.Message{MailboxID: mailboxID})
		}
		q.SortAsc("MailboxID", "UID")
		err = q.ForEach(func(m store.Message) error {
			uidlasts[m.MailboxID]++
			uid := uidlasts[m.MailboxID]
			if m.UID != uid {
				m.UID = uid
				m.ModSeq = modseq
				if err := tx.Update(&m); err != nil {
					return fmt.Errorf("updating uid for message: %v", err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("reading through messages: %v", err)
		}

		// Now update the uidnext, uidvalidity and modseq for each mailbox.
		err = bstore.QueryTx[store.Mailbox](tx).FilterEqual("Expunged", false).ForEach(func(mb store.Mailbox) error {
			// Assign each mailbox a completely new uidvalidity.
			uidvalidity, err := a.NextUIDValidity(tx)
			if err != nil {
				return fmt.Errorf("assigning next uid validity: %v", err)
			}

			if mb.UIDValidity >= uidvalidity {
				// This should not happen, but since we're fixing things up after a hypothetical
				// mishap, might as well account for inconsistent uidvalidity.
				next := store.NextUIDValidity{ID: 1, Next: mb.UIDValidity + 2}
				if err := tx.Update(&next); err != nil {
					log.Printf("updating nextuidvalidity: %v, continuing", err)
				}
				mb.UIDValidity++
			} else {
				mb.UIDValidity = uidvalidity
			}
			mb.UIDNext = uidlasts[mb.ID] + 1
			mb.ModSeq = modseq
			if err := tx.Update(&mb); err != nil {
				return fmt.Errorf("updating uidvalidity and uidnext for mailbox: %v", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("updating mailboxes: %v", err)
		}
		return nil
	})
	xcheckf(err, "updating database")
}

func cmdFixUIDMeta(c *cmd) {
	c.params = "account"
	c.help = `Fix inconsistent UIDVALIDITY and UIDNEXT in messages/mailboxes/account.

The next UID to use for a message in a mailbox should always be higher than any
existing message UID in the mailbox. If it is not, the mailbox UIDNEXT is
updated.

Each mailbox has a UIDVALIDITY sequence number, which should always be lower
than the per-account next UIDVALIDITY to use. If it is not, the account next
UIDVALIDITY is updated.

Opens account database file directly. Ensure mox does not have the account
open, or is not running.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	a, err := store.OpenAccount(c.log, args[0], false)
	xcheckf(err, "open account")
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing account: %v", err)
		}
	}()

	var maxUIDValidity uint32

	err = a.DB.Write(context.Background(), func(tx *bstore.Tx) error {
		// We look at each mailbox, retrieve its max UID and compare against the mailbox
		// UIDNEXT.
		err := bstore.QueryTx[store.Mailbox](tx).FilterEqual("Expunged", false).ForEach(func(mb store.Mailbox) error {
			if mb.UIDValidity > maxUIDValidity {
				maxUIDValidity = mb.UIDValidity
			}
			m, err := bstore.QueryTx[store.Message](tx).FilterNonzero(store.Message{MailboxID: mb.ID}).SortDesc("UID").Limit(1).Get()
			if err == bstore.ErrAbsent || err == nil && m.UID < mb.UIDNext {
				return nil
			} else if err != nil {
				return fmt.Errorf("finding message with max uid in mailbox: %w", err)
			}
			olduidnext := mb.UIDNext
			mb.UIDNext = m.UID + 1
			log.Printf("fixing uidnext to %d (max uid is %d, old uidnext was %d) for mailbox %q (id %d)", mb.UIDNext, m.UID, olduidnext, mb.Name, mb.ID)
			if err := tx.Update(&mb); err != nil {
				return fmt.Errorf("updating mailbox uidnext: %v", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("processing mailboxes: %v", err)
		}

		uidvalidity := store.NextUIDValidity{ID: 1}
		if err := tx.Get(&uidvalidity); err != nil {
			return fmt.Errorf("reading account next uidvalidity: %v", err)
		}
		if maxUIDValidity >= uidvalidity.Next {
			log.Printf("account next uidvalidity %d <= highest uidvalidity %d found in mailbox, resetting account next uidvalidity to %d", uidvalidity.Next, maxUIDValidity, maxUIDValidity+1)
			uidvalidity.Next = maxUIDValidity + 1
			if err := tx.Update(&uidvalidity); err != nil {
				return fmt.Errorf("updating account next uidvalidity: %v", err)
			}
		}

		return nil
	})
	xcheckf(err, "updating database")
}

func cmdFixmsgsize(c *cmd) {
	c.params = "[account]"
	c.help = `Ensure message sizes in the database matching the sum of the message prefix length and on-disk file size.

Messages with an inconsistent size are also parsed again.

If an inconsistency is found, you should probably also run "mox
bumpuidvalidity" on the mailboxes or entire account to force IMAP clients to
refetch messages.
`
	args := c.Parse()
	if len(args) > 1 {
		c.Usage()
	}

	mustLoadConfig()
	var account string
	if len(args) == 1 {
		account = args[0]
	}
	ctlcmdFixmsgsize(xctl(), account)
}

func ctlcmdFixmsgsize(ctl *ctl, account string) {
	ctl.xwrite("fixmsgsize")
	ctl.xwrite(account)
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func cmdReparse(c *cmd) {
	c.params = "[account]"
	c.help = `Parse all messages in the account or all accounts again.

Can be useful after upgrading mox with improved message parsing. Messages are
parsed in batches, so other access to the mailboxes/messages are not blocked
while reparsing all messages.
`
	args := c.Parse()
	if len(args) > 1 {
		c.Usage()
	}

	mustLoadConfig()
	var account string
	if len(args) == 1 {
		account = args[0]
	}
	ctlcmdReparse(xctl(), account)
}

func ctlcmdReparse(ctl *ctl, account string) {
	ctl.xwrite("reparse")
	ctl.xwrite(account)
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func cmdEnsureParsed(c *cmd) {
	c.params = "account"
	c.help = "Ensure messages in the database have a pre-parsed MIME form in the database."
	var all bool
	c.flag.BoolVar(&all, "all", false, "store new parsed message for all messages")
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	a, err := store.OpenAccount(c.log, args[0], false)
	xcheckf(err, "open account")
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing account: %v", err)
		}
	}()

	n := 0
	err = a.DB.Write(context.Background(), func(tx *bstore.Tx) error {
		q := bstore.QueryTx[store.Message](tx)
		q.FilterEqual("Expunged", false)
		q.FilterFn(func(m store.Message) bool {
			return all || m.ParsedBuf == nil
		})
		l, err := q.List()
		if err != nil {
			return fmt.Errorf("list messages: %v", err)
		}
		for _, m := range l {
			mr := a.MessageReader(m)
			p, err := message.EnsurePart(c.log.Logger, false, mr, m.Size)
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

func cmdRecalculateMailboxCounts(c *cmd) {
	c.params = "account"
	c.help = `Recalculate message counts for all mailboxes in the account, and total message size for quota.

When a message is added to/removed from a mailbox, or when message flags change,
the total, unread, unseen and deleted messages are accounted, the total size of
the mailbox, and the total message size for the account. In case of a bug in
this accounting, the numbers could become incorrect. This command will find, fix
and print them.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	mustLoadConfig()
	ctlcmdRecalculateMailboxCounts(xctl(), args[0])
}

func ctlcmdRecalculateMailboxCounts(ctl *ctl, account string) {
	ctl.xwrite("recalculatemailboxcounts")
	ctl.xwrite(account)
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func cmdMessageParse(c *cmd) {
	c.params = "message.eml"
	c.help = "Parse message, print JSON representation."

	var smtputf8 bool
	c.flag.BoolVar(&smtputf8, "smtputf8", false, "check if message needs smtputf8")
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	f, err := os.Open(args[0])
	xcheckf(err, "open")
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("closing message file: %v", err)
		}
	}()

	part, err := message.Parse(c.log.Logger, false, f)
	xcheckf(err, "parsing message")
	err = part.Walk(c.log.Logger, nil)
	xcheckf(err, "parsing nested parts")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "\t")
	enc.SetEscapeHTML(false)
	err = enc.Encode(part)
	xcheckf(err, "write")

	if smtputf8 {
		needs, err := part.NeedsSMTPUTF8()
		xcheckf(err, "checking if message needs smtputf8")
		fmt.Println("message needs smtputf8:", needs)
	}
}

func cmdOpenaccounts(c *cmd) {
	c.unlisted = true
	c.params = "datadir account ..."
	c.help = `Open and close accounts, for triggering data upgrades, for tests.

Opens database files directly, not going through a running mox instance.
`

	args := c.Parse()
	if len(args) <= 1 {
		c.Usage()
	}

	dataDir := filepath.Clean(args[0])
	for _, accName := range args[1:] {
		accDir := filepath.Join(dataDir, "accounts", accName)
		log.Printf("opening account %s...", accDir)
		a, err := store.OpenAccountDB(c.log, accDir, accName)
		xcheckf(err, "open account %s", accName)
		err = a.ThreadingWait(c.log)
		xcheckf(err, "wait for threading upgrade to complete for %s", accName)
		err = a.Close()
		xcheckf(err, "close account %s", accName)
	}
}

func cmdReassignthreads(c *cmd) {
	c.params = "[account]"
	c.help = `Reassign message threads.

For all accounts, or optionally only the specified account.

Threading for all messages in an account is first reset, and new base subject
and normalized message-id saved with the message. Then all messages are
evaluated and matched against their parents/ancestors.

Messages are matched based on the References header, with a fall-back to an
In-Reply-To header, and if neither is present/valid, based only on base
subject.

A References header typically points to multiple previous messages in a
hierarchy. From oldest ancestor to most recent parent. An In-Reply-To header
would have only a message-id of the parent message.

A message is only linked to a parent/ancestor if their base subject is the
same. This ensures unrelated replies, with a new subject, are placed in their
own thread.

The base subject is lower cased, has whitespace collapsed to a single
space, and some components removed: leading "Re:", "Fwd:", "Fw:", or bracketed
tag (that mailing lists often add, e.g. "[listname]"), trailing "(fwd)", or
enclosing "[fwd: ...]".

Messages are linked to all their ancestors. If an intermediate parent/ancestor
message is deleted in the future, the message can still be linked to the earlier
ancestors. If the direct parent already wasn't available while matching, this is
stored as the message having a "missing link" to its stored ancestors.
`
	args := c.Parse()
	if len(args) > 1 {
		c.Usage()
	}

	mustLoadConfig()
	var account string
	if len(args) == 1 {
		account = args[0]
	}
	ctlcmdReassignthreads(xctl(), account)
}

func ctlcmdReassignthreads(ctl *ctl, account string) {
	ctl.xwrite("reassignthreads")
	ctl.xwrite(account)
	ctl.xreadok()
	ctl.xstreamto(os.Stdout)
}

func cmdIMAPServe(c *cmd) {
	c.params = "preauth-address"
	c.help = `Initiate a preauthenticated IMAP connection on file descriptor 0.

For use with tools that can do IMAP over tunneled connections, e.g. with SSH
during migrations. TLS is not possible on the connection, and authentication
does not require TLS.
`
	var fd0 bool
	c.flag.BoolVar(&fd0, "fd0", false, "write IMAP to file descriptor 0 instead of stdout")
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	address := args[0]
	output := os.Stdout
	if fd0 {
		output = os.Stdout
	}
	ctlcmdIMAPServe(xctl(), address, os.Stdin, output)
}

func ctlcmdIMAPServe(ctl *ctl, address string, input io.ReadCloser, output io.WriteCloser) {
	ctl.xwrite("imapserve")
	ctl.xwrite(address)
	ctl.xreadok()

	done := make(chan struct{}, 1)
	go func() {
		defer func() {
			done <- struct{}{}
		}()
		_, err := io.Copy(output, ctl.conn)
		if err == nil {
			err = io.EOF
		}
		log.Printf("reading from imap: %v", err)
	}()
	go func() {
		defer func() {
			done <- struct{}{}
		}()
		_, err := io.Copy(ctl.conn, input)
		if err == nil {
			err = io.EOF
		}
		log.Printf("writing to imap: %v", err)
	}()
	<-done
}

func cmdReadmessages(c *cmd) {
	c.unlisted = true
	c.params = "datadir account ..."
	c.help = `Open account, parse several headers for all messages.

For performance testing.

Opens database files directly, not going through a running mox instance.
`

	gomaxprocs := runtime.GOMAXPROCS(0)
	var procs, workqueuesize, limit int
	c.flag.IntVar(&procs, "procs", gomaxprocs, "number of goroutines for reading messages")
	c.flag.IntVar(&workqueuesize, "workqueuesize", 2*gomaxprocs, "number of messages to keep in work queue")
	c.flag.IntVar(&limit, "limit", 0, "number of messages to process if greater than zero")
	args := c.Parse()
	if len(args) <= 1 {
		c.Usage()
	}

	type threadPrep struct {
		references []string
		inReplyTo  []string
	}

	threadingFields := [][]byte{
		[]byte("references"),
		[]byte("in-reply-to"),
	}

	dataDir := filepath.Clean(args[0])
	for _, accName := range args[1:] {
		accDir := filepath.Join(dataDir, "accounts", accName)
		log.Printf("opening account %s...", accDir)
		a, err := store.OpenAccountDB(c.log, accDir, accName)
		xcheckf(err, "open account %s", accName)

		prepareMessages := func(in, out chan moxio.Work[store.Message, threadPrep]) {
			headerbuf := make([]byte, 8*1024)
			scratch := make([]byte, 4*1024)
			for {
				w, ok := <-in
				if !ok {
					return
				}

				m := w.In
				var partialPart struct {
					HeaderOffset int64
					BodyOffset   int64
				}
				if err := json.Unmarshal(m.ParsedBuf, &partialPart); err != nil {
					w.Err = fmt.Errorf("unmarshal part: %v", err)
				} else {
					size := partialPart.BodyOffset - partialPart.HeaderOffset
					if int(size) > len(headerbuf) {
						headerbuf = make([]byte, size)
					}
					if size > 0 {
						buf := headerbuf[:int(size)]
						err := func() error {
							mr := a.MessageReader(m)
							defer func() {
								if err := mr.Close(); err != nil {
									log.Printf("closing message reader: %v", err)
								}
							}()

							// ReadAt returns whole buffer or error. Single read should be fast.
							n, err := mr.ReadAt(buf, partialPart.HeaderOffset)
							if err != nil || n != len(buf) {
								return fmt.Errorf("read header: %v", err)
							}
							return nil
						}()
						if err != nil {
							w.Err = err
						} else if h, err := message.ParseHeaderFields(buf, scratch, threadingFields); err != nil {
							w.Err = err
						} else {
							w.Out.references = h["References"]
							w.Out.inReplyTo = h["In-Reply-To"]
						}
					}
				}

				out <- w
			}
		}

		n := 0
		t := time.Now()
		t0 := t

		processMessage := func(m store.Message, prep threadPrep) error {
			if n%100000 == 0 {
				log.Printf("%d messages (delta %s)", n, time.Since(t))
				t = time.Now()
			}
			n++
			return nil
		}

		wq := moxio.NewWorkQueue[store.Message, threadPrep](procs, workqueuesize, prepareMessages, processMessage)

		err = a.DB.Write(context.Background(), func(tx *bstore.Tx) error {
			q := bstore.QueryTx[store.Message](tx)
			q.FilterEqual("Expunged", false)
			q.SortAsc("ID")
			if limit > 0 {
				q.Limit(limit)
			}
			err = q.ForEach(wq.Add)
			if err == nil {
				err = wq.Finish()
			}
			wq.Stop()

			return err
		})
		xcheckf(err, "processing message")

		err = a.Close()
		xcheckf(err, "close account %s", accName)
		log.Printf("account %s, total time %s", accName, time.Since(t0))
	}
}

func cmdQueueFillRetired(c *cmd) {
	c.unlisted = true
	c.help = `Fill retired messag and webhooks queue with testdata.

For testing the pagination. Operates directly on queue database.
`
	var n int
	c.flag.IntVar(&n, "n", 10000, "retired messages and retired webhooks to insert")
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	mustLoadConfig()
	err := queue.Init()
	xcheckf(err, "init queue")
	err = queue.DB.Write(context.Background(), func(tx *bstore.Tx) error {
		now := time.Now()

		// Cause autoincrement ID for queue.Msg to be forwarded, and use the reserved ID
		// space for inserting retired messages.
		fm := queue.Msg{}
		err = tx.Insert(&fm)
		xcheckf(err, "temporarily insert message to get autoincrement sequence")
		err = tx.Delete(&fm)
		xcheckf(err, "removing temporary message for resetting autoincrement sequence")
		fm.ID += int64(n)
		err = tx.Insert(&fm)
		xcheckf(err, "temporarily insert message to forward autoincrement sequence")
		err = tx.Delete(&fm)
		xcheckf(err, "removing temporary message after forwarding autoincrement sequence")
		fm.ID -= int64(n)

		// And likewise for webhooks.
		fh := queue.Hook{Account: "x", URL: "x", NextAttempt: time.Now()}
		err = tx.Insert(&fh)
		xcheckf(err, "temporarily insert webhook to get autoincrement sequence")
		err = tx.Delete(&fh)
		xcheckf(err, "removing temporary webhook for resetting autoincrement sequence")
		fh.ID += int64(n)
		err = tx.Insert(&fh)
		xcheckf(err, "temporarily insert webhook to forward autoincrement sequence")
		err = tx.Delete(&fh)
		xcheckf(err, "removing temporary webhook after forwarding autoincrement sequence")
		fh.ID -= int64(n)

		for i := range n {
			t0 := now.Add(-time.Duration(i) * time.Second)
			last := now.Add(-time.Duration(i/10) * time.Second)
			mr := queue.MsgRetired{
				ID:                 fm.ID + int64(i),
				Queued:             t0,
				SenderAccount:      "test",
				SenderLocalpart:    "mox",
				SenderDomainStr:    "localhost",
				FromID:             fmt.Sprintf("%016d", i),
				RecipientLocalpart: "mox",
				RecipientDomain:    dns.IPDomain{Domain: dns.Domain{ASCII: "localhost"}},
				RecipientDomainStr: "localhost",
				Attempts:           i % 6,
				LastAttempt:        &last,
				Results: []queue.MsgResult{
					{
						Start:    last,
						Duration: time.Millisecond,
						Success:  i%10 != 0,
						Code:     250,
					},
				},
				Has8bit:          i%2 == 0,
				SMTPUTF8:         i%8 == 0,
				Size:             int64(i * 100),
				MessageID:        fmt.Sprintf("<msg%d@localhost>", i),
				Subject:          fmt.Sprintf("test message %d", i),
				Extra:            map[string]string{"i": fmt.Sprintf("%d", i)},
				LastActivity:     last,
				RecipientAddress: "mox@localhost",
				Success:          i%10 != 0,
				KeepUntil:        now.Add(48 * time.Hour),
			}
			err := tx.Insert(&mr)
			xcheckf(err, "inserting retired message")
		}

		for i := range n {
			t0 := now.Add(-time.Duration(i) * time.Second)
			last := now.Add(-time.Duration(i/10) * time.Second)
			var event string
			if i%10 != 0 {
				event = "delivered"
			}
			hr := queue.HookRetired{
				ID:            fh.ID + int64(i),
				QueueMsgID:    fm.ID + int64(i),
				FromID:        fmt.Sprintf("%016d", i),
				MessageID:     fmt.Sprintf("<msg%d@localhost>", i),
				Subject:       fmt.Sprintf("test message %d", i),
				Extra:         map[string]string{"i": fmt.Sprintf("%d", i)},
				Account:       "test",
				URL:           "http://localhost/hook",
				IsIncoming:    i%10 == 0,
				OutgoingEvent: event,
				Payload:       "{}",

				Submitted: t0,
				Attempts:  i % 6,
				Results: []queue.HookResult{
					{
						Start:    t0,
						Duration: time.Millisecond,
						URL:      "http://localhost/hook",
						Success:  i%10 != 0,
						Code:     200,
						Response: "ok",
					},
				},

				Success:      i%10 != 0,
				LastActivity: last,
				KeepUntil:    now.Add(48 * time.Hour),
			}
			err := tx.Insert(&hr)
			xcheckf(err, "inserting retired hook")
		}

		return nil
	})
	xcheckf(err, "add to queue")
	log.Printf("added %d retired messages and %d retired webhooks", n, n)
}
