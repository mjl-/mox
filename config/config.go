package config

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"regexp"
	"time"

	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/smtp"
)

// todo: better default values, so less has to be specified in the config file. junkfilter and rejects mailbox should be enabled by default. other features as well possibly.

// Port returns port if non-zero, and fallback otherwise.
func Port(port, fallback int) int {
	if port == 0 {
		return fallback
	}
	return port
}

// Static is a parsed form of the mox.conf configuration file, before converting it
// into a mox.Config after additional processing.
type Static struct {
	DataDir          string            `sconf-doc:"Directory where all data is stored, e.g. queue, accounts and messages, ACME TLS certs/keys. If this is a relative path, it is relative to the directory of mox.conf."`
	LogLevel         string            `sconf-doc:"Default log level, one of: error, info, debug, trace, traceauth, tracedata. Trace logs SMTP and IMAP protocol transcripts, with traceauth also messages with passwords, and tracedata on top of that also the full data exchanges (full messages), which can be a large amount of data."`
	PackageLogLevels map[string]string `sconf:"optional" sconf-doc:"Overrides of log level per package (e.g. queue, smtpclient, smtpserver, imapserver, spf, dkim, dmarc, dmarcdb, autotls, junk, mtasts, tlsrpt)."`
	Hostname         string            `sconf-doc:"Full hostname of system, e.g. mail.<domain>"`
	HostnameDomain   dns.Domain        `sconf:"-" json:"-"` // Parsed form of hostname.
	CheckUpdates     bool              `sconf:"optional" sconf-doc:"If enabled, a single DNS TXT lookup of _updates.xmox.nl is done every 24h to check for a new release. Each time a new release is found, a changelog is fetched from https://updates.xmox.nl and delivered to the postmaster mailbox."`
	TLS              struct {
		CA *struct {
			AdditionalToSystem bool     `sconf:"optional"`
			CertFiles          []string `sconf:"optional"`
		} `sconf:"optional"`
		CertPool *x509.CertPool `sconf:"-" json:"-"`
	} `sconf:"optional" sconf-doc:"Global TLS configuration, e.g. for additional Certificate Authorities."`
	ACME              map[string]ACME     `sconf:"optional" sconf-doc:"Automatic TLS configuration with ACME, e.g. through Let's Encrypt. The key is a name referenced in TLS configs, e.g. letsencrypt."`
	AdminPasswordFile string              `sconf:"optional" sconf-doc:"File containing hash of admin password, for authentication in the web admin pages (if enabled)."`
	Listeners         map[string]Listener `sconf-doc:"Listeners are groups of IP addresses and services enabled on those IP addresses, such as SMTP/IMAP or internal endpoints for administration or Prometheus metrics. All listeners with SMTP/IMAP services enabled will serve all configured domains."`
	Postmaster        struct {
		Account string
		Mailbox string `sconf-doc:"E.g. Postmaster or Inbox."`
	} `sconf-doc:"Destination for emails delivered to postmaster address."`
	DefaultMailboxes []string `sconf:"optional" sconf-doc:"Mailboxes to create when adding an account. Inbox is always created. If no mailboxes are specified, the following are automatically created: Sent, Archive, Trash, Drafts and Junk."`

	// All IPs that were explicitly listen on for external SMTP. Only set when there
	// are no unspecified external SMTP listeners and there is at most one for IPv4 and
	// at most one for IPv6. Used for setting the local address when making outgoing
	// connections. Those IPs are assumed to be in an SPF record for the domain,
	// potentially unlike other IPs on the machine.  If there is only one address
	// family, outgoing connections with the other address family are still made if
	// possible.
	SpecifiedSMTPListenIPs []net.IP `sconf:"-" json:"-"`
}

// Dynamic is the parsed form of domains.conf, and is automatically reloaded when changed.
type Dynamic struct {
	Domains  map[string]Domain  `sconf-doc:"Domains for which email is accepted. For internationalized domains, use their IDNA names in UTF-8."`
	Accounts map[string]Account `sconf-doc:"Accounts to which email can be delivered. An account can accept email for multiple domains, for multiple localparts, and deliver to multiple mailboxes."`
}

type ACME struct {
	DirectoryURL string        `sconf-doc:"For letsencrypt, use https://acme-v02.api.letsencrypt.org/directory."`
	RenewBefore  time.Duration `sconf:"optional" sconf-doc:"How long before expiration to renew the certificate. Default is 30 days."`
	ContactEmail string        `sconf-doc:"Email address to register at ACME provider. The provider can email you when certificates are about to expire. If you configure an address for which email is delivered by this server, keep in mind that TLS misconfigurations could result in such notification emails not arriving."`
	Port         int           `sconf:"optional" sconf-doc:"TLS port for ACME validation, 443 by default. You should only override this if you cannot listen on port 443 directly. ACME will make requests to port 443, so you'll have to add an external mechanism to get the connection here, e.g. by configuring port forwarding."`

	Manager *autotls.Manager `sconf:"-" json:"-"`
}

type Listener struct {
	IPs            []string   `sconf-doc:"Use 0.0.0.0 to listen on all IPv4 and/or :: to listen on all IPv6 addresses."`
	Hostname       string     `sconf:"optional" sconf-doc:"If empty, the config global Hostname is used."`
	HostnameDomain dns.Domain `sconf:"-" json:"-"` // Set when parsing config.

	TLS                *TLS  `sconf:"optional" sconf-doc:"For SMTP/IMAP STARTTLS, direct TLS and HTTPS connections."`
	SMTPMaxMessageSize int64 `sconf:"optional" sconf-doc:"Maximum size in bytes accepted incoming and outgoing messages. Default is 100MB."`
	SMTP               struct {
		Enabled         bool
		Port            int          `sconf:"optional" sconf-doc:"Default 25."`
		NoSTARTTLS      bool         `sconf:"optional" sconf-doc:"Do not offer STARTTLS to secure the connection. Not recommended."`
		RequireSTARTTLS bool         `sconf:"optional" sconf-doc:"Do not accept incoming messages if STARTTLS is not active. Can be used in combination with a strict MTA-STS policy. A remote SMTP server may not support TLS and may not be able to deliver messages."`
		DNSBLs          []string     `sconf:"optional" sconf-doc:"Addresses of DNS block lists for incoming messages. Block lists are only consulted for connections/messages without enough reputation to make an accept/reject decision. This prevents sending IPs of all communications to the block list provider. If any of the listed DNSBLs contains a requested IP address, the message is rejected as spam. The DNSBLs are checked for healthiness before use, at most once per 4 hours. Example DNSBLs: sbl.spamhaus.org, bl.spamcop.net"`
		DNSBLZones      []dns.Domain `sconf:"-"`
	} `sconf:"optional"`
	Submission struct {
		Enabled           bool
		Port              int  `sconf:"optional" sconf-doc:"Default 587."`
		NoRequireSTARTTLS bool `sconf:"optional" sconf-doc:"Do not require STARTTLS. Since users must login, this means password may be sent without encryption. Not recommended."`
	} `sconf:"optional" sconf-doc:"SMTP for submitting email, e.g. by email applications. Starts out in plain text, can be upgraded to TLS with the STARTTLS command. Prefer using Submissions which is always a TLS connection."`
	Submissions struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Default 465."`
	} `sconf:"optional" sconf-doc:"SMTP over TLS for submitting email, by email applications. Requires a TLS config."`
	IMAP struct {
		Enabled           bool
		Port              int  `sconf:"optional" sconf-doc:"Default 143."`
		NoRequireSTARTTLS bool `sconf:"optional" sconf-doc:"Enable this only when the connection is otherwise encrypted (e.g. through a VPN)."`
	} `sconf:"optional" sconf-doc:"IMAP for reading email, by email applications. Starts out in plain text, can be upgraded to TLS with the STARTTLS command. Prefer using IMAPS instead which is always a TLS connection."`
	IMAPS struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Default 993."`
	} `sconf:"optional" sconf-doc:"IMAP over TLS for reading email, by email applications. Requires a TLS config."`
	AccountHTTP struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Default 80."`
	} `sconf:"optional" sconf-doc:"Account web interface, for email users wanting to change their accounts, e.g. set new password, set new delivery rulesets."`
	AccountHTTPS struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Default 80."`
	} `sconf:"optional" sconf-doc:"Account web interface listener for HTTPS. Requires a TLS config."`
	AdminHTTP struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Default 80."`
	} `sconf:"optional" sconf-doc:"Admin web interface, for managing domains, accounts, etc. Served at /admin/. Preferrably only enable on non-public IPs."`
	AdminHTTPS struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Default 443."`
	} `sconf:"optional" sconf-doc:"Admin web interface listener for HTTPS. Requires a TLS config. Preferrably only enable on non-public IPs."`
	MetricsHTTP struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Default 8010."`
	} `sconf:"optional" sconf-doc:"Serve prometheus metrics, for monitoring. You should not enable this on a public IP."`
	PprofHTTP struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Default 8011."`
	} `sconf:"optional" sconf-doc:"Serve /debug/pprof/ for profiling a running mox instance. Do not enable this on a public IP!"`
	AutoconfigHTTPS struct {
		Enabled bool
		Port    int  `sconf:"optional" sconf-doc:"TLS port, 443 by default. You should only override this if you cannot listen on port 443 directly. Autoconfig requests will be made to port 443, so you'll have to add an external mechanism to get the connection here, e.g. by configuring port forwarding."`
		NonTLS  bool `sconf:"optional" sconf-doc:"If set, plain HTTP instead of HTTPS is spoken on the configured port. Can be useful when the autoconfig domain is reverse proxied."`
	} `sconf:"optional" sconf-doc:"Serve autoconfiguration/autodiscovery to simplify configuring email applications, will use port 443. Requires a TLS config."`
	MTASTSHTTPS struct {
		Enabled bool
		Port    int  `sconf:"optional" sconf-doc:"TLS port, 443 by default. You should only override this if you cannot listen on port 443 directly. MTA-STS requests will be made to port 443, so you'll have to add an external mechanism to get the connection here, e.g. by configuring port forwarding."`
		NonTLS  bool `sconf:"optional" sconf-doc:"If set, plain HTTP instead of HTTPS is spoken on the configured port. Can be useful when the mta-sts domain is reverse proxied."`
	} `sconf:"optional" sconf-doc:"Serve MTA-STS policies describing SMTP TLS requirements. Requires a TLS config."`
}

type Domain struct {
	Description                string  `sconf:"optional" sconf-doc:"Free-form description of domain."`
	LocalpartCatchallSeparator string  `sconf:"optional" sconf-doc:"If not empty, only the string before the separator is used to for email delivery decisions. For example, if set to \"+\", you+anything@example.com will be delivered to you@example.com."`
	LocalpartCaseSensitive     bool    `sconf:"optional" sconf-doc:"If set, upper/lower case is relevant for email delivery."`
	DKIM                       DKIM    `sconf:"optional" sconf-doc:"With DKIM signing, a domain is taking responsibility for (content of) emails it sends, letting receiving mail servers build up a (hopefully positive) reputation of the domain, which can help with mail delivery."`
	DMARC                      *DMARC  `sconf:"optional" sconf-doc:"With DMARC, a domain publishes, in DNS, a policy on how other mail servers should handle incoming messages with the From-header matching this domain and/or subdomain (depending on the configured alignment). Receiving mail servers use this to build up a reputation of this domain, which can help with mail delivery. A domain can also publish an email address to which reports about DMARC verification results can be sent by verifying mail servers, useful for monitoring. Incoming DMARC reports are automatically parsed, validated, added to metrics and stored in the reporting database for later display in the admin web pages."`
	MTASTS                     *MTASTS `sconf:"optional" sconf-doc:"With MTA-STS a domain publishes, in DNS, presence of a policy for using/requiring TLS for SMTP connections. The policy is served over HTTPS."`
	TLSRPT                     *TLSRPT `sconf:"optional" sconf-doc:"With TLSRPT a domain specifies in DNS where reports about encountered SMTP TLS behaviour should be sent. Useful for monitoring. Incoming TLS reports are automatically parsed, validated, added to metrics and stored in the reporting database for later display in the admin web pages."`

	Domain dns.Domain `sconf:"-" json:"-"`
}

type DMARC struct {
	Localpart string `sconf-doc:"Address-part before the @ that accepts DMARC reports. Must be non-internationalized. Recommended value: dmarc-reports."`
	Account   string `sconf-doc:"Account to deliver to."`
	Mailbox   string `sconf-doc:"Mailbox to deliver to, e.g. DMARC."`

	ParsedLocalpart smtp.Localpart `sconf:"-"`
}

type MTASTS struct {
	PolicyID string        `sconf-doc:"Policies are versioned. The version must be specified in the DNS record. If you change a policy, first change it in mox, then update the DNS record."`
	Mode     mtasts.Mode   `sconf-doc:"testing, enforce or none. If set to enforce, a remote SMTP server will not deliver email to us if it cannot make a TLS connection."`
	MaxAge   time.Duration `sconf-doc:"How long a remote mail server is allowed to cache a policy. Typically 1 or several weeks."`
	MX       []string      `sconf:"optional" sconf-doc:"List of server names allowed for SMTP. If empty, the configured hostname is set. Host names can contain a wildcard (*) as a leading label (matching a single label, e.g. *.example matches host.example, not sub.host.example)."`
	// todo: parse mx as valid mtasts.Policy.MX, with dns.ParseDomain but taking wildcard into account
}

type TLSRPT struct {
	Localpart string `sconf-doc:"Address-part before the @ that accepts TLSRPT reports. Recommended value: tls-reports."`
	Account   string `sconf-doc:"Account to deliver to."`
	Mailbox   string `sconf-doc:"Mailbox to deliver to, e.g. TLSRPT."`

	ParsedLocalpart smtp.Localpart `sconf:"-"`
}

type Selector struct {
	Hash             string `sconf:"optional" sconf-doc:"sha256 (default) or (older, not recommended) sha1"`
	HashEffective    string `sconf:"-"`
	Canonicalization struct {
		HeaderRelaxed bool `sconf-doc:"If set, some modifications to the headers (mostly whitespace) are allowed."`
		BodyRelaxed   bool `sconf-doc:"If set, some whitespace modifications to the message body are allowed."`
	} `sconf:"optional"`
	Headers          []string `sconf:"optional" sconf-doc:"Headers to sign with DKIM. If empty, a reasonable default set of headers is selected."`
	HeadersEffective []string `sconf:"-"`
	DontSealHeaders  bool     `sconf:"optional" sconf-doc:"If set, don't prevent duplicate headers from being added. Not recommended."`
	Expiration       string   `sconf:"optional" sconf-doc:"Period a signature is valid after signing, as duration, e.g. 72h. The period should be enough for delivery at the final destination, potentially with several hops/relays. In the order of days at least."`
	PrivateKeyFile   string   `sconf-doc:"Either an RSA or ed25519 private key file in PKCS8 PEM form."`

	ExpirationSeconds int           `sconf:"-" json:"-"` // Parsed from Expiration.
	Key               crypto.Signer `sconf:"-" json:"-"` // As parsed with x509.ParsePKCS8PrivateKey.
	Domain            dns.Domain    `sconf:"-" json:"-"` // Of selector only, not FQDN.
}

type DKIM struct {
	Selectors map[string]Selector `sconf-doc:"Emails can be DKIM signed. Config parameters are per selector. A DNS record must be created for each selector. Add the name to Sign to use the selector for signing messages."`
	Sign      []string            `sconf:"optional" sconf-doc:"List of selectors that emails will be signed with."`
}

type Account struct {
	Domain       string                 `sconf-doc:"Default domain for addresses specified in Destinations. An address can specify a domain override."`
	Description  string                 `sconf:"optional" sconf-doc:"Free form description, e.g. full name or alternative contact info."`
	Destinations map[string]Destination `sconf-doc:"Destinations, specified as (encoded) localpart for Domain, or a full address including domain override."`
	SubjectPass  struct {
		Period time.Duration `sconf-doc:"How long unique values are accepted after generating, e.g. 12h."` // todo: have a reasonable default for this?
	} `sconf:"optional" sconf-doc:"If configured, messages classified as weakly spam are rejected with instructions to retry delivery, but this time with a signed token added to the subject. During the next delivery attempt, the signed token will bypass the spam filter. Messages with a clear spam signal, such as a known bad reputation, are rejected/delayed without a signed token."`
	RejectsMailbox     string `sconf:"optional" sconf-doc:"Mail that looks like spam will be rejected, but a copy can be stored temporarily in a mailbox, e.g. Rejects. If mail isn't coming in when you expect, you can look there. The mail still isn't accepted, so the remote mail server may retry (hopefully, if legitimate), or give up (hopefully, if indeed a spammer). Messages are automatically removed from this mailbox, so do not set it to a mailbox that has messages you want to keep."`
	AutomaticJunkFlags struct {
		Enabled              bool   `sconf-doc:"If enabled, flags will be set automatically if they match a regular expression below. When two of the three mailbox regular expressions are set, the remaining one will match all unmatched messages. Messages are matched in the order specified and the search stops on the first match. Mailboxes are lowercased before matching."`
		JunkMailboxRegexp    string `sconf:"optional" sconf-doc:"Example: ^(junk|spam)."`
		NeutralMailboxRegexp string `sconf:"optional" sconf-doc:"Example: ^(inbox|neutral|postmaster|dmarc|tlsrpt|rejects), and you may wish to add trash depending on how you use it, or leave this empty."`
		NotJunkMailboxRegexp string `sconf:"optional" sconf-doc:"Example: .* or an empty string."`
	} `sconf:"optional" sconf-doc:"Automatically set $Junk and $NotJunk flags based on mailbox messages are delivered/moved/copied to. Email clients typically have too limited functionality to conveniently set these flags, especially $NonJunk, but they can all move messages to a different mailbox, so this helps them."`
	JunkFilter *JunkFilter `sconf:"optional" sconf-doc:"Content-based filtering, using the junk-status of individual messages to rank words in such messages as spam or ham. It is recommended you always set the applicable (non)-junk status on messages, and that you do not empty your Trash because those messages contain valuable ham/spam training information."` // todo: sane defaults for junkfilter

	DNSDomain      dns.Domain     `sconf:"-"` // Parsed form of Domain.
	JunkMailbox    *regexp.Regexp `sconf:"-" json:"-"`
	NeutralMailbox *regexp.Regexp `sconf:"-" json:"-"`
	NotJunkMailbox *regexp.Regexp `sconf:"-" json:"-"`
}

type JunkFilter struct {
	Threshold float64 `sconf-doc:"Approximate spaminess score between 0 and 1 above which emails are rejected as spam. Each delivery attempt adds a little noise to make it slightly harder for spammers to identify words that strongly indicate non-spaminess and use it to bypass the filter. E.g. 0.95."`
	junk.Params
}

type Destination struct {
	Mailbox  string    `sconf:"optional" sconf-doc:"Mailbox to deliver to if none of Rulesets match. Default: Inbox."`
	Rulesets []Ruleset `sconf:"optional" sconf-doc:"Delivery rules based on message and SMTP transaction. You may want to match each mailing list by SMTP MailFrom address, VerifiedDomain and/or List-ID header (typically <listname.example.org> if the list address is listname@example.org), delivering them to their own mailbox."`

	DMARCReports bool `sconf:"-" json:"-"`
	TLSReports   bool `sconf:"-" json:"-"`
}

// Equal returns whether d and o are equal, only looking at their user-changeable fields.
func (d Destination) Equal(o Destination) bool {
	if d.Mailbox != o.Mailbox || len(d.Rulesets) != len(o.Rulesets) {
		return false
	}
	for i, rs := range d.Rulesets {
		if !rs.Equal(o.Rulesets[i]) {
			return false
		}
	}
	return true
}

type Ruleset struct {
	SMTPMailFromRegexp string            `sconf:"optional" sconf-doc:"Matches if this regular expression matches (a substring of) the SMTP MAIL FROM address (not the message From-header). E.g. user@example.org."`
	VerifiedDomain     string            `sconf:"optional" sconf-doc:"Matches if this domain matches an SPF- and/or DKIM-verified (sub)domain."`
	HeadersRegexp      map[string]string `sconf:"optional" sconf-doc:"Matches if these header field/value regular expressions all match (substrings of) the message headers. Header fields and valuees are converted to lower case before matching. Whitespace is trimmed from the value before matching. A header field can occur multiple times in a message, only one instance has to match. For mailing lists, you could match on ^list-id$ with the value typically the mailing list address in angled brackets with @ replaced with a dot, e.g. <name\\.lists\\.example\\.org>."`
	// todo: add a SMTPRcptTo check, and MessageFrom that works on a properly parsed From header.

	ListAllowDomain string `sconf:"optional" sconf-doc:"Influence the spam filtering, this does not change whether this ruleset applies to a message. If this domain matches an SPF- and/or DKIM-verified (sub)domain, the message is accepted without further spam checks, such as a junk filter or DMARC reject evaluation. DMARC rejects should not apply for mailing lists that are not configured to rewrite the From-header of messages that don't have a passing DKIM signature of the From-domain. Otherwise, by rejecting messages, you may be automatically unsubscribed from the mailing list. The assumption is that mailing lists do their own spam filtering/moderation."`

	Mailbox string `sconf-doc:"Mailbox to deliver to if this ruleset matches."`

	SMTPMailFromRegexpCompiled *regexp.Regexp      `sconf:"-" json:"-"`
	VerifiedDNSDomain          dns.Domain          `sconf:"-"`
	HeadersRegexpCompiled      [][2]*regexp.Regexp `sconf:"-" json:"-"`
	ListAllowDNSDomain         dns.Domain          `sconf:"-"`
}

// Equal returns whether r and o are equal, only looking at their user-changeable fields.
func (r Ruleset) Equal(o Ruleset) bool {
	if r.SMTPMailFromRegexp != o.SMTPMailFromRegexp || r.VerifiedDomain != o.VerifiedDomain || r.ListAllowDomain != o.ListAllowDomain || r.Mailbox != o.Mailbox {
		return false
	}
	if !reflect.DeepEqual(r.HeadersRegexp, o.HeadersRegexp) {
		return false
	}
	return true
}

type TLS struct {
	ACME     string `sconf:"optional" sconf-doc:"Name of provider from top-level configuration to use for ACME, e.g. letsencrypt."`
	KeyCerts []struct {
		CertFile string `sconf-doc:"Certificate including intermediate CA certificates, in PEM format."`
		KeyFile  string `sconf-doc:"Private key for certificate, in PEM format. PKCS8 is recommended, but PKCS1 and EC private keys are recognized as well."`
	} `sconf:"optional"`
	MinVersion string `sconf:"optional" sconf-doc:"Minimum TLS version. Default: TLSv1.2."`

	Config     *tls.Config `sconf:"-" json:"-"` // TLS config for non-ACME-verification connections, i.e. SMTP and IMAP, and not port 443.
	ACMEConfig *tls.Config `sconf:"-" json:"-"` // TLS config that handles ACME verification, for serving on port 443.
}
