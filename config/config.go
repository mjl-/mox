package config

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"time"

	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/smtp"
)

// todo: better default values, so less has to be specified in the config file.

// DefaultMaxMsgSize is the maximum message size for incoming and outgoing
// messages, in bytes. Can be overridden per listener.
const DefaultMaxMsgSize = 100 * 1024 * 1024

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
	DataDir          string            `sconf-doc:"NOTE: This config file is in 'sconf' format. Indent with tabs. Comments must be on their own line, they don't end a line. Do not escape or quote strings. Details: https://pkg.go.dev/github.com/mjl-/sconf.\n\n\nDirectory where all data is stored, e.g. queue, accounts and messages, ACME TLS certs/keys. If this is a relative path, it is relative to the directory of mox.conf."`
	LogLevel         string            `sconf-doc:"Default log level, one of: error, info, debug, trace, traceauth, tracedata. Trace logs SMTP and IMAP protocol transcripts, with traceauth also messages with passwords, and tracedata on top of that also the full data exchanges (full messages), which can be a large amount of data."`
	PackageLogLevels map[string]string `sconf:"optional" sconf-doc:"Overrides of log level per package (e.g. queue, smtpclient, smtpserver, imapserver, spf, dkim, dmarc, dmarcdb, autotls, junk, mtasts, tlsrpt)."`
	User             string            `sconf:"optional" sconf-doc:"User to switch to after binding to all sockets as root. Default: mox. If the value is not a known user, it is parsed as integer and used as uid and gid."`
	NoFixPermissions bool              `sconf:"optional" sconf-doc:"If true, do not automatically fix file permissions when starting up. By default, mox will ensure reasonable owner/permissions on the working, data and config directories (and files), and mox binary (if present)."`
	Hostname         string            `sconf-doc:"Full hostname of system, e.g. mail.<domain>"`
	HostnameDomain   dns.Domain        `sconf:"-" json:"-"` // Parsed form of hostname.
	CheckUpdates     bool              `sconf:"optional" sconf-doc:"If enabled, a single DNS TXT lookup of _updates.xmox.nl is done every 24h to check for a new release. Each time a new release is found, a changelog is fetched from https://updates.xmox.nl/changelog and delivered to the postmaster mailbox."`
	Pedantic         bool              `sconf:"optional" sconf-doc:"In pedantic mode protocol violations (that happen in the wild) for SMTP/IMAP/etc result in errors instead of accepting such behaviour."`
	TLS              struct {
		CA *struct {
			AdditionalToSystem bool     `sconf:"optional"`
			CertFiles          []string `sconf:"optional"`
		} `sconf:"optional"`
		CertPool *x509.CertPool `sconf:"-" json:"-"`
	} `sconf:"optional" sconf-doc:"Global TLS configuration, e.g. for additional Certificate Authorities. Used for outgoing SMTP connections, HTTPS requests."`
	ACME              map[string]ACME     `sconf:"optional" sconf-doc:"Automatic TLS configuration with ACME, e.g. through Let's Encrypt. The key is a name referenced in TLS configs, e.g. letsencrypt."`
	AdminPasswordFile string              `sconf:"optional" sconf-doc:"File containing hash of admin password, for authentication in the web admin pages (if enabled)."`
	Listeners         map[string]Listener `sconf-doc:"Listeners are groups of IP addresses and services enabled on those IP addresses, such as SMTP/IMAP or internal endpoints for administration or Prometheus metrics. All listeners with SMTP/IMAP services enabled will serve all configured domains. If the listener is named 'public', it will get a few helpful additional configuration checks, for acme automatic tls certificates and monitoring of ips in dnsbls if those are configured."`
	Postmaster        struct {
		Account string
		Mailbox string `sconf-doc:"E.g. Postmaster or Inbox."`
	} `sconf-doc:"Destination for emails delivered to postmaster addresses: a plain 'postmaster' without domain, 'postmaster@<hostname>' (also for each listener with SMTP enabled), and as fallback for each domain without explicitly configured postmaster destination."`
	HostTLSRPT struct {
		Account   string `sconf-doc:"Account to deliver TLS reports to. Typically same account as for postmaster."`
		Mailbox   string `sconf-doc:"Mailbox to deliver TLS reports to. Recommended value: TLSRPT."`
		Localpart string `sconf-doc:"Localpart at hostname to accept TLS reports at. Recommended value: tls-reports."`

		ParsedLocalpart smtp.Localpart `sconf:"-"`
	} `sconf:"optional" sconf-doc:"Destination for per-host TLS reports (TLSRPT). TLS reports can be per recipient domain (for MTA-STS), or per MX host (for DANE). The per-domain TLS reporting configuration is in domains.conf. This is the TLS reporting configuration for this host. If absent, no host-based TLSRPT address is configured, and no host TLSRPT DNS record is suggested."`
	InitialMailboxes InitialMailboxes     `sconf:"optional" sconf-doc:"Mailboxes to create for new accounts. Inbox is always created. Mailboxes can be given a 'special-use' role, which are understood by most mail clients. If absent/empty, the following mailboxes are created: Sent, Archive, Trash, Drafts and Junk."`
	DefaultMailboxes []string             `sconf:"optional" sconf-doc:"Deprecated in favor of InitialMailboxes. Mailboxes to create when adding an account. Inbox is always created. If no mailboxes are specified, the following are automatically created: Sent, Archive, Trash, Drafts and Junk."`
	Transports       map[string]Transport `sconf:"optional" sconf-doc:"Transport are mechanisms for delivering messages. Transports can be referenced from Routes in accounts, domains and the global configuration. There is always an implicit/fallback delivery transport doing direct delivery with SMTP from the outgoing message queue. Transports are typically only configured when using smarthosts, i.e. when delivering through another SMTP server. Zero or one transport methods must be set in a transport, never multiple. When using an external party to send email for a domain, keep in mind you may have to add their IP address to your domain's SPF record, and possibly additional DKIM records."`
	// Awkward naming of fields to get intended default behaviour for zero values.
	NoOutgoingDMARCReports          bool  `sconf:"optional" sconf-doc:"Do not send DMARC reports (aggregate only). By default, aggregate reports on DMARC evaluations are sent to domains if their DMARC policy requests them. Reports are sent at whole hours, with a minimum of 1 hour and maximum of 24 hours, rounded up so a whole number of intervals cover 24 hours, aligned at whole days in UTC. Reports are sent from the postmaster@<mailhostname> address."`
	NoOutgoingTLSReports            bool  `sconf:"optional" sconf-doc:"Do not send TLS reports. By default, reports about failed SMTP STARTTLS connections and related MTA-STS/DANE policies are sent to domains if their TLSRPT DNS record requests them. Reports covering a 24 hour UTC interval are sent daily. Reports are sent from the postmaster address of the configured domain the mailhostname is in. If there is no such domain, or it does not have DKIM configured, no reports are sent."`
	OutgoingTLSReportsForAllSuccess bool  `sconf:"optional" sconf-doc:"Also send TLS reports if there were no SMTP STARTTLS connection failures. By default, reports are only sent when at least one failure occurred. If a report is sent, it does always include the successful connection counts as well."`
	QuotaMessageSize                int64 `sconf:"optional" sconf-doc:"Default maximum total message size in bytes for each individual account, only applicable if greater than zero. Can be overridden per account. Attempting to add new messages to an account beyond its maximum total size will result in an error. Useful to prevent a single account from filling storage. The quota only applies to the email message files, not to any file system overhead and also not the message index database file (account for approximately 15% overhead)."`

	// All IPs that were explicitly listened on for external SMTP. Only set when there
	// are no unspecified external SMTP listeners and there is at most one for IPv4 and
	// at most one for IPv6. Used for setting the local address when making outgoing
	// connections. Those IPs are assumed to be in an SPF record for the domain,
	// potentially unlike other IPs on the machine.  If there is only one address
	// family, outgoing connections with the other address family are still made if
	// possible.
	SpecifiedSMTPListenIPs []net.IP `sconf:"-" json:"-"`

	// To switch to after initialization as root.
	UID uint32 `sconf:"-" json:"-"`
	GID uint32 `sconf:"-" json:"-"`
}

// InitialMailboxes are mailboxes created for a new account.
type InitialMailboxes struct {
	SpecialUse SpecialUseMailboxes `sconf:"optional" sconf-doc:"Special-use roles to mailbox to create."`
	Regular    []string            `sconf:"optional" sconf-doc:"Regular, non-special-use mailboxes to create."`
}

// SpecialUseMailboxes holds mailbox names for special-use roles. Mail clients
// recognize these special-use roles, e.g. appending sent messages to whichever
// mailbox has the Sent special-use flag.
type SpecialUseMailboxes struct {
	Sent    string `sconf:"optional"`
	Archive string `sconf:"optional"`
	Trash   string `sconf:"optional"`
	Draft   string `sconf:"optional"`
	Junk    string `sconf:"optional"`
}

// Dynamic is the parsed form of domains.conf, and is automatically reloaded when changed.
type Dynamic struct {
	Domains            map[string]Domain  `sconf-doc:"NOTE: This config file is in 'sconf' format. Indent with tabs. Comments must be on their own line, they don't end a line. Do not escape or quote strings. Details: https://pkg.go.dev/github.com/mjl-/sconf.\n\n\nDomains for which email is accepted. For internationalized domains, use their IDNA names in UTF-8."`
	Accounts           map[string]Account `sconf-doc:"Accounts represent mox users, each with a password and email address(es) to which email can be delivered (possibly at different domains). Each account has its own on-disk directory holding its messages and index database. An account name is not an email address."`
	WebDomainRedirects map[string]string  `sconf:"optional" sconf-doc:"Redirect all requests from domain (key) to domain (value). Always redirects to HTTPS. For plain HTTP redirects, use a WebHandler with a WebRedirect."`
	WebHandlers        []WebHandler       `sconf:"optional" sconf-doc:"Handle webserver requests by serving static files, redirecting, reverse-proxying HTTP(s) or passing the request to an internal service. The first matching WebHandler will handle the request. Built-in system handlers, e.g. for ACME validation, autoconfig and mta-sts always run first. Built-in handlers for admin, account, webmail and webapi are evaluated after all handlers, including webhandlers (allowing for overrides of internal services for some domains). If no handler matches, the response status code is file not found (404). If webserver features are missing, forward the requests to an application that provides the needed functionality itself."`
	Routes             []Route            `sconf:"optional" sconf-doc:"Routes for delivering outgoing messages through the queue. Each delivery attempt evaluates account routes, domain routes and finally these global routes. The transport of the first matching route is used in the delivery attempt. If no routes match, which is the default with no configured routes, messages are delivered directly from the queue."`
	MonitorDNSBLs      []string           `sconf:"optional" sconf-doc:"DNS blocklists to periodically check with if IPs we send from are present, without using them for checking incoming deliveries.. Also see DNSBLs in SMTP listeners in mox.conf, which specifies DNSBLs to use both for incoming deliveries and for checking our IPs against. Example DNSBLs: sbl.spamhaus.org, bl.spamcop.net."`

	WebDNSDomainRedirects map[dns.Domain]dns.Domain `sconf:"-" json:"-"`
	MonitorDNSBLZones     []dns.Domain              `sconf:"-"`
	ClientSettingDomains  map[dns.Domain]struct{}   `sconf:"-" json:"-"`
}

type ACME struct {
	DirectoryURL           string                  `sconf-doc:"For letsencrypt, use https://acme-v02.api.letsencrypt.org/directory."`
	RenewBefore            time.Duration           `sconf:"optional" sconf-doc:"How long before expiration to renew the certificate. Default is 30 days."`
	ContactEmail           string                  `sconf-doc:"Email address to register at ACME provider. The provider can email you when certificates are about to expire. If you configure an address for which email is delivered by this server, keep in mind that TLS misconfigurations could result in such notification emails not arriving."`
	Port                   int                     `sconf:"optional" sconf-doc:"TLS port for ACME validation, 443 by default. You should only override this if you cannot listen on port 443 directly. ACME will make requests to port 443, so you'll have to add an external mechanism to get the connection here, e.g. by configuring port forwarding."`
	IssuerDomainName       string                  `sconf:"optional" sconf-doc:"If set, used for suggested CAA DNS records, for restricting TLS certificate issuance to a Certificate Authority. If empty and DirectyURL is for Let's Encrypt, this value is set automatically to letsencrypt.org."`
	ExternalAccountBinding *ExternalAccountBinding `sconf:"optional" sconf-doc:"ACME providers can require that a request for a new ACME account reference an existing non-ACME account known to the provider. External account binding references that account by a key id, and authorizes new ACME account requests by signing it with a key known both by the ACME client and ACME provider."`
	// ../rfc/8555:2111

	Manager *autotls.Manager `sconf:"-" json:"-"`
}

type ExternalAccountBinding struct {
	KeyID   string `sconf-doc:"Key identifier, from ACME provider."`
	KeyFile string `sconf-doc:"File containing the base64url-encoded key used to sign account requests with external account binding. The ACME provider will verify the account request is correctly signed by the key. File is evaluated relative to the directory of mox.conf."`
}

type Listener struct {
	IPs            []string   `sconf-doc:"Use 0.0.0.0 to listen on all IPv4 and/or :: to listen on all IPv6 addresses, but it is better to explicitly specify the IPs you want to use for email, as mox will make sure outgoing connections will only be made from one of those IPs. If both outgoing IPv4 and IPv6 connectivity is possible, and only one family has explicitly configured addresses, both address families are still used for outgoing connections. Use the \"direct\" transport to limit address families for outgoing connections."`
	NATIPs         []string   `sconf:"optional" sconf-doc:"If set, the mail server is configured behind a NAT and field IPs are internal instead of the public IPs, while NATIPs lists the public IPs. Used during IP-related DNS self-checks, such as for iprev, mx, spf, autoconfig, autodiscover, and for autotls."`
	IPsNATed       bool       `sconf:"optional" sconf-doc:"Deprecated, use NATIPs instead. If set, IPs are not the public IPs, but are NATed. Skips IP-related DNS self-checks."`
	Hostname       string     `sconf:"optional" sconf-doc:"If empty, the config global Hostname is used. The internal services webadmin, webaccount, webmail and webapi only match requests to IPs, this hostname, \"localhost\". All except webadmin also match for any client settings domain."`
	HostnameDomain dns.Domain `sconf:"-" json:"-"` // Set when parsing config.

	TLS                *TLS  `sconf:"optional" sconf-doc:"For SMTP/IMAP STARTTLS, direct TLS and HTTPS connections."`
	SMTPMaxMessageSize int64 `sconf:"optional" sconf-doc:"Maximum size in bytes for incoming and outgoing messages. Default is 100MB."`
	SMTP               struct {
		Enabled         bool
		Port            int  `sconf:"optional" sconf-doc:"Default 25."`
		NoSTARTTLS      bool `sconf:"optional" sconf-doc:"Do not offer STARTTLS to secure the connection. Not recommended."`
		RequireSTARTTLS bool `sconf:"optional" sconf-doc:"Do not accept incoming messages if STARTTLS is not active. Consider using in combination with an MTA-STS policy and/or DANE. A remote SMTP server may not support TLS and may not be able to deliver messages. Incoming messages for TLS reporting addresses ignore this setting and do not require TLS."`
		NoRequireTLS    bool `sconf:"optional" sconf-doc:"Do not announce the REQUIRETLS SMTP extension. Messages delivered using the REQUIRETLS extension should only be distributed onwards to servers also implementing the REQUIRETLS extension. In some situations, such as hosting mailing lists, this may not be feasible due to lack of support for the extension by mailing list subscribers."`
		// Reoriginated messages (such as messages sent to mailing list subscribers) should
		// keep REQUIRETLS. ../rfc/8689:412

		DNSBLs []string `sconf:"optional" sconf-doc:"Addresses of DNS block lists for incoming messages. Block lists are only consulted for connections/messages without enough reputation to make an accept/reject decision. This prevents sending IPs of all communications to the block list provider. If any of the listed DNSBLs contains a requested IP address, the message is rejected as spam. The DNSBLs are checked for healthiness before use, at most once per 4 hours. IPs we can send from are periodically checked for being in the configured DNSBLs. See MonitorDNSBLs in domains.conf to only monitor IPs we send from, without using those DNSBLs for incoming messages. Example DNSBLs: sbl.spamhaus.org, bl.spamcop.net. See https://www.spamhaus.org/sbl/ and https://www.spamcop.net/ for more information and terms of use."`

		FirstTimeSenderDelay *time.Duration `sconf:"optional" sconf-doc:"Delay before accepting a message from a first-time sender for the destination account. Default: 15s."`

		DNSBLZones []dns.Domain `sconf:"-"`
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
	AccountHTTP  WebService `sconf:"optional" sconf-doc:"Account web interface, for email users wanting to change their accounts, e.g. set new password, set new delivery rulesets. Default path is /."`
	AccountHTTPS WebService `sconf:"optional" sconf-doc:"Account web interface listener like AccountHTTP, but for HTTPS. Requires a TLS config."`
	AdminHTTP    WebService `sconf:"optional" sconf-doc:"Admin web interface, for managing domains, accounts, etc. Default path is /admin/. Preferably only enable on non-public IPs. Hint: use 'ssh -L 8080:localhost:80 you@yourmachine' and open http://localhost:8080/admin/, or set up a tunnel (e.g. WireGuard) and add its IP to the mox 'internal' listener."`
	AdminHTTPS   WebService `sconf:"optional" sconf-doc:"Admin web interface listener like AdminHTTP, but for HTTPS. Requires a TLS config."`
	WebmailHTTP  WebService `sconf:"optional" sconf-doc:"Webmail client, for reading email. Default path is /webmail/."`
	WebmailHTTPS WebService `sconf:"optional" sconf-doc:"Webmail client, like WebmailHTTP, but for HTTPS. Requires a TLS config."`
	WebAPIHTTP   WebService `sconf:"optional" sconf-doc:"Like WebAPIHTTP, but with plain HTTP, without TLS."`
	WebAPIHTTPS  WebService `sconf:"optional" sconf-doc:"WebAPI, a simple HTTP/JSON-based API for email, with HTTPS (requires a TLS config). Default path is /webapi/."`
	MetricsHTTP  struct {
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
	WebserverHTTP struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Port for plain HTTP (non-TLS) webserver."`
	} `sconf:"optional" sconf-doc:"All configured WebHandlers will serve on an enabled listener."`
	WebserverHTTPS struct {
		Enabled bool
		Port    int `sconf:"optional" sconf-doc:"Port for HTTPS webserver."`
	} `sconf:"optional" sconf-doc:"All configured WebHandlers will serve on an enabled listener. Either ACME must be configured, or for each WebHandler domain a TLS certificate must be configured."`
}

// WebService is an internal web interface: webmail, webaccount, webadmin, webapi.
type WebService struct {
	Enabled   bool
	Port      int    `sconf:"optional" sconf-doc:"Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname matching behaviour."`
	Path      string `sconf:"optional" sconf-doc:"Path to serve requests on."`
	Forwarded bool   `sconf:"optional" sconf-doc:"If set, X-Forwarded-* headers are used for the remote IP address for rate limiting and for the \"secure\" status of cookies."`
}

// Transport is a method to delivery a message. At most one of the fields can
// be non-nil. The non-nil field represents the type of transport. For a
// transport with all fields nil, regular email delivery is done.
type Transport struct {
	Submissions *TransportSMTP   `sconf:"optional" sconf-doc:"Submission SMTP over a TLS connection to submit email to a remote queue."`
	Submission  *TransportSMTP   `sconf:"optional" sconf-doc:"Submission SMTP over a plain TCP connection (possibly with STARTTLS) to submit email to a remote queue."`
	SMTP        *TransportSMTP   `sconf:"optional" sconf-doc:"SMTP over a plain connection (possibly with STARTTLS), typically for old-fashioned unauthenticated relaying to a remote queue."`
	Socks       *TransportSocks  `sconf:"optional" sconf-doc:"Like regular direct delivery, but makes outgoing connections through a SOCKS proxy."`
	Direct      *TransportDirect `sconf:"optional" sconf-doc:"Like regular direct delivery, but allows to tweak outgoing connections."`
}

// TransportSMTP delivers messages by "submission" (SMTP, typically
// authenticated) to the queue of a remote host (smarthost), or by relaying
// (SMTP, typically unauthenticated).
type TransportSMTP struct {
	Host                       string    `sconf-doc:"Host name to connect to and for verifying its TLS certificate."`
	Port                       int       `sconf:"optional" sconf-doc:"If unset or 0, the default port for submission(s)/smtp is used: 25 for SMTP, 465 for submissions (with TLS), 587 for submission (possibly with STARTTLS)."`
	STARTTLSInsecureSkipVerify bool      `sconf:"optional" sconf-doc:"If set an unverifiable remote TLS certificate during STARTTLS is accepted."`
	NoSTARTTLS                 bool      `sconf:"optional" sconf-doc:"If set for submission or smtp transport, do not attempt STARTTLS on the connection. Authentication credentials and messages will be transferred in clear text."`
	Auth                       *SMTPAuth `sconf:"optional" sconf-doc:"If set, authentication credentials for the remote server."`

	DNSHost dns.Domain `sconf:"-" json:"-"`
}

// SMTPAuth hold authentication credentials used when delivering messages
// through a smarthost.
type SMTPAuth struct {
	Username   string
	Password   string
	Mechanisms []string `sconf:"optional" sconf-doc:"Allowed authentication mechanisms. Defaults to SCRAM-SHA-256-PLUS, SCRAM-SHA-256, SCRAM-SHA-1-PLUS, SCRAM-SHA-1, CRAM-MD5. Not included by default: PLAIN. Specify the strongest mechanism known to be implemented by the server to prevent mechanism downgrade attacks."`

	EffectiveMechanisms []string `sconf:"-" json:"-"`
}

type TransportSocks struct {
	Address        string   `sconf-doc:"Address of SOCKS proxy, of the form host:port or ip:port."`
	RemoteIPs      []string `sconf-doc:"IP addresses connections from the SOCKS server will originate from. This IP addresses should be configured in the SPF record (keep in mind DNS record time to live (TTL) when adding a SOCKS proxy). Reverse DNS should be set up for these address, resolving to RemoteHostname. These are typically the IPv4 and IPv6 address for the host in the Address field."`
	RemoteHostname string   `sconf-doc:"Hostname belonging to RemoteIPs. This name is used during in SMTP EHLO. This is typically the hostname of the host in the Address field."`

	// todo: add authentication credentials?

	IPs      []net.IP   `sconf:"-" json:"-"` // Parsed form of RemoteIPs.
	Hostname dns.Domain `sconf:"-" json:"-"` // Parsed form of RemoteHostname
}

type TransportDirect struct {
	DisableIPv4 bool `sconf:"optional" sconf-doc:"If set, outgoing SMTP connections will *NOT* use IPv4 addresses to connect to remote SMTP servers."`
	DisableIPv6 bool `sconf:"optional" sconf-doc:"If set, outgoing SMTP connections will *NOT* use IPv6 addresses to connect to remote SMTP servers."`

	IPFamily string `sconf:"-" json:"-"`
}

type Domain struct {
	Description                string           `sconf:"optional" sconf-doc:"Free-form description of domain."`
	ClientSettingsDomain       string           `sconf:"optional" sconf-doc:"Hostname for client settings instead of the mail server hostname. E.g. mail.<domain>. For future migration to another mail operator without requiring all clients to update their settings, it is convenient to have client settings that reference a subdomain of the hosted domain instead of the hostname of the server where the mail is currently hosted. If empty, the hostname of the mail server is used for client configurations. Unicode name."`
	LocalpartCatchallSeparator string           `sconf:"optional" sconf-doc:"If not empty, only the string before the separator is used to for email delivery decisions. For example, if set to \"+\", you+anything@example.com will be delivered to you@example.com."`
	LocalpartCaseSensitive     bool             `sconf:"optional" sconf-doc:"If set, upper/lower case is relevant for email delivery."`
	DKIM                       DKIM             `sconf:"optional" sconf-doc:"With DKIM signing, a domain is taking responsibility for (content of) emails it sends, letting receiving mail servers build up a (hopefully positive) reputation of the domain, which can help with mail delivery."`
	DMARC                      *DMARC           `sconf:"optional" sconf-doc:"With DMARC, a domain publishes, in DNS, a policy on how other mail servers should handle incoming messages with the From-header matching this domain and/or subdomain (depending on the configured alignment). Receiving mail servers use this to build up a reputation of this domain, which can help with mail delivery. A domain can also publish an email address to which reports about DMARC verification results can be sent by verifying mail servers, useful for monitoring. Incoming DMARC reports are automatically parsed, validated, added to metrics and stored in the reporting database for later display in the admin web pages."`
	MTASTS                     *MTASTS          `sconf:"optional" sconf-doc:"MTA-STS is a mechanism that allows publishing a policy with requirements for WebPKI-verified SMTP STARTTLS connections for email delivered to a domain. Existence of a policy is announced in a DNS TXT record (often unprotected/unverified, MTA-STS's weak spot). If a policy exists, it is fetched with a WebPKI-verified HTTPS request. The policy can indicate that WebPKI-verified SMTP STARTTLS is required, and which MX hosts (optionally with a wildcard pattern) are allowd. MX hosts to deliver to are still taken from DNS (again, not necessarily protected/verified), but messages will only be delivered to domains matching the MX hosts from the published policy. Mail servers look up the MTA-STS policy when first delivering to a domain, then keep a cached copy, periodically checking the DNS record if a new policy is available, and fetching and caching it if so. To update a policy, first serve a new policy with an updated policy ID, then update the DNS record (not the other way around). To remove an enforced policy, publish an updated policy with mode \"none\" for a long enough period so all cached policies have been refreshed (taking DNS TTL and policy max age into account), then remove the policy from DNS, wait for TTL to expire, and stop serving the policy."`
	TLSRPT                     *TLSRPT          `sconf:"optional" sconf-doc:"With TLSRPT a domain specifies in DNS where reports about encountered SMTP TLS behaviour should be sent. Useful for monitoring. Incoming TLS reports are automatically parsed, validated, added to metrics and stored in the reporting database for later display in the admin web pages."`
	Routes                     []Route          `sconf:"optional" sconf-doc:"Routes for delivering outgoing messages through the queue. Each delivery attempt evaluates account routes, these domain routes and finally global routes. The transport of the first matching route is used in the delivery attempt. If no routes match, which is the default with no configured routes, messages are delivered directly from the queue."`
	Aliases                    map[string]Alias `sconf:"optional" sconf-doc:"Aliases that cause messages to be delivered to one or more locally configured addresses. Keys are localparts (encoded, as they appear in email addresses)."`

	Domain                  dns.Domain `sconf:"-"`
	ClientSettingsDNSDomain dns.Domain `sconf:"-" json:"-"`

	// Set when DMARC and TLSRPT (when set) has an address with different domain (we're
	// hosting the reporting), and there are no destination addresses configured for
	// the domain. Disables some functionality related to hosting a domain.
	ReportsOnly bool `sconf:"-" json:"-"`
}

// todo: allow external addresses as members of aliases. we would add messages for them to the queue for outgoing delivery. we should require an admin addresses to which delivery failures will be delivered (locally, and to use in smtp mail from, so dsns go there). also take care to evaluate smtputf8 (if external address requires utf8 and incoming transaction didn't).
// todo: as alternative to PostPublic, allow specifying a list of addresses (dmarc-like verified) that are (the only addresses) allowed to post to the list. if msgfrom is an external address, require a valid dkim signature to prevent dmarc-policy-related issues when delivering to remote members.
// todo: add option to require messages sent to an alias have that alias as From or Reply-To address?

type Alias struct {
	Addresses    []string `sconf-doc:"Expanded addresses to deliver to. These must currently be of addresses of local accounts. To prevent duplicate messages, a member address that is also an explicit recipient in the SMTP transaction will only have the message delivered once. If the address in the message From header is a member, that member also won't receive the message."`
	PostPublic   bool     `sconf:"optional" sconf-doc:"If true, anyone can send messages to the list. Otherwise only members, based on message From address, which is assumed to be DMARC-like-verified."`
	ListMembers  bool     `sconf:"optional" sconf-doc:"If true, members can see addresses of members."`
	AllowMsgFrom bool     `sconf:"optional" sconf-doc:"If true, members are allowed to send messages with this alias address in the message From header."`

	LocalpartStr    string         `sconf:"-"` // In encoded form.
	Domain          dns.Domain     `sconf:"-"`
	ParsedAddresses []AliasAddress `sconf:"-"` // Matches addresses.
}

type AliasAddress struct {
	Address     smtp.Address // Parsed address.
	AccountName string       // Looked up.
	Destination Destination  // Belonging to address.
}

type DMARC struct {
	Localpart string `sconf-doc:"Address-part before the @ that accepts DMARC reports. Must be non-internationalized. Recommended value: dmarc-reports."`
	Domain    string `sconf:"optional" sconf-doc:"Alternative domain for reporting address, for incoming reports. Typically empty, causing the domain wherein this config exists to be used. Can be used to receive reports for domains that aren't fully hosted on this server. Configure such a domain as a hosted domain without making all the DNS changes, and configure this field with a domain that is fully hosted on this server, so the localpart and the domain of this field form a reporting address. Then only update the DMARC DNS record for the not fully hosted domain, ensuring the reporting address is specified in its \"rua\" field as shown in the suggested DNS settings. Unicode name."`
	Account   string `sconf-doc:"Account to deliver to."`
	Mailbox   string `sconf-doc:"Mailbox to deliver to, e.g. DMARC."`

	ParsedLocalpart smtp.Localpart `sconf:"-"`
	DNSDomain       dns.Domain     `sconf:"-"` // Effective domain, always set based on Domain field or Domain where this is configured.
}

type MTASTS struct {
	PolicyID string        `sconf-doc:"Policies are versioned. The version must be specified in the DNS record. If you change a policy, first change it here to update the served policy, then update the DNS record with the updated policy ID."`
	Mode     mtasts.Mode   `sconf-doc:"If set to \"enforce\", a remote SMTP server will not deliver email to us if it cannot make a WebPKI-verified SMTP STARTTLS connection. In mode \"testing\", deliveries can be done without verified TLS, but errors will be reported through TLS reporting. In mode \"none\", verified TLS is not required, used for phasing out an MTA-STS policy."`
	MaxAge   time.Duration `sconf-doc:"How long a remote mail server is allowed to cache a policy. Typically 1 or several weeks."`
	MX       []string      `sconf:"optional" sconf-doc:"List of server names allowed for SMTP. If empty, the configured hostname is set. Host names can contain a wildcard (*) as a leading label (matching a single label, e.g. *.example matches host.example, not sub.host.example)."`
	// todo: parse mx as valid mtasts.Policy.MX, with dns.ParseDomain but taking wildcard into account
}

type TLSRPT struct {
	Localpart string `sconf-doc:"Address-part before the @ that accepts TLSRPT reports. Recommended value: tls-reports."`
	Domain    string `sconf:"optional" sconf-doc:"Alternative domain for reporting address, for incoming reports. Typically empty, causing the domain wherein this config exists to be used. Can be used to receive reports for domains that aren't fully hosted on this server. Configure such a domain as a hosted domain without making all the DNS changes, and configure this field with a domain that is fully hosted on this server, so the localpart and the domain of this field form a reporting address. Then only update the TLSRPT DNS record for the not fully hosted domain, ensuring the reporting address is specified in its \"rua\" field as shown in the suggested DNS settings. Unicode name."`
	Account   string `sconf-doc:"Account to deliver to."`
	Mailbox   string `sconf-doc:"Mailbox to deliver to, e.g. TLSRPT."`

	ParsedLocalpart smtp.Localpart `sconf:"-"`
	DNSDomain       dns.Domain     `sconf:"-"` // Effective domain, always set based on Domain field or Domain where this is configured.
}

type Canonicalization struct {
	HeaderRelaxed bool `sconf-doc:"If set, some modifications to the headers (mostly whitespace) are allowed."`
	BodyRelaxed   bool `sconf-doc:"If set, some whitespace modifications to the message body are allowed."`
}

type Selector struct {
	Hash             string           `sconf:"optional" sconf-doc:"sha256 (default) or (older, not recommended) sha1."`
	HashEffective    string           `sconf:"-"`
	Canonicalization Canonicalization `sconf:"optional"`
	Headers          []string         `sconf:"optional" sconf-doc:"Headers to sign with DKIM. If empty, a reasonable default set of headers is selected."`
	HeadersEffective []string         `sconf:"-"` // Used when signing. Based on Headers from config, or the reasonable default.
	DontSealHeaders  bool             `sconf:"optional" sconf-doc:"If set, don't prevent duplicate headers from being added. Not recommended."`
	Expiration       string           `sconf:"optional" sconf-doc:"Period a signature is valid after signing, as duration, e.g. 72h. The period should be enough for delivery at the final destination, potentially with several hops/relays. In the order of days at least."`
	PrivateKeyFile   string           `sconf-doc:"Either an RSA or ed25519 private key file in PKCS8 PEM form."`

	Algorithm         string        `sconf:"-"`          // "ed25519", "rsa-*", based on private key.
	ExpirationSeconds int           `sconf:"-" json:"-"` // Parsed from Expiration.
	Key               crypto.Signer `sconf:"-" json:"-"` // As parsed with x509.ParsePKCS8PrivateKey.
	Domain            dns.Domain    `sconf:"-" json:"-"` // Of selector only, not FQDN.
}

type DKIM struct {
	Selectors map[string]Selector `sconf-doc:"Emails can be DKIM signed. Config parameters are per selector. A DNS record must be created for each selector. Add the name to Sign to use the selector for signing messages."`
	Sign      []string            `sconf:"optional" sconf-doc:"List of selectors that emails will be signed with."`
}

type Route struct {
	FromDomain      []string `sconf:"optional" sconf-doc:"Matches if the envelope from domain matches one of the configured domains, or if the list is empty. If a domain starts with a dot, prefixes of the domain also match."`
	ToDomain        []string `sconf:"optional" sconf-doc:"Like FromDomain, but matching against the envelope to domain."`
	MinimumAttempts int      `sconf:"optional" sconf-doc:"Matches if at least this many deliveries have already been attempted. This can be used to attempt sending through a smarthost when direct delivery has failed for several times."`
	Transport       string   `sconf:"The transport used for delivering the message that matches requirements of the above fields."`

	// todo future: add ToMX, where we look up the MX record of the destination domain and check (the first, any, all?) mx host against the values in ToMX.

	FromDomainASCII   []string  `sconf:"-"`
	ToDomainASCII     []string  `sconf:"-"`
	ResolvedTransport Transport `sconf:"-" json:"-"`
}

// todo: move RejectsMailbox to store.Mailbox.SpecialUse, possibly with "X" prefix?

// note: outgoing hook events are in ../queue/hooks.go, ../mox-/config.go, ../queue.go and ../webapi/gendoc.sh. keep in sync.

type OutgoingWebhook struct {
	URL           string   `sconf-doc:"URL to POST webhooks."`
	Authorization string   `sconf:"optional" sconf-doc:"If not empty, value of Authorization header to add to HTTP requests."`
	Events        []string `sconf:"optional" sconf-doc:"Events to send outgoing delivery notifications for. If absent, all events are sent. Valid values: delivered, suppressed, delayed, failed, relayed, expanded, canceled, unrecognized."`
}

type IncomingWebhook struct {
	URL           string `sconf-doc:"URL to POST webhooks to for incoming deliveries over SMTP."`
	Authorization string `sconf:"optional" sconf-doc:"If not empty, value of Authorization header to add to HTTP requests."`
}

type SubjectPass struct {
	Period time.Duration `sconf-doc:"How long unique values are accepted after generating, e.g. 12h."` // todo: have a reasonable default for this?
}

type AutomaticJunkFlags struct {
	Enabled              bool   `sconf-doc:"If enabled, junk/nonjunk flags will be set automatically if they match some of the regular expressions. When two of the three mailbox regular expressions are set, the remaining one will match all unmatched messages. Messages are matched in the order 'junk', 'neutral', 'not junk', and the search stops on the first match. Mailboxes are lowercased before matching."`
	JunkMailboxRegexp    string `sconf:"optional" sconf-doc:"Example: ^(junk|spam)."`
	NeutralMailboxRegexp string `sconf:"optional" sconf-doc:"Example: ^(inbox|neutral|postmaster|dmarc|tlsrpt|rejects), and you may wish to add trash depending on how you use it, or leave this empty."`
	NotJunkMailboxRegexp string `sconf:"optional" sconf-doc:"Example: .* or an empty string."`
}

type Account struct {
	OutgoingWebhook          *OutgoingWebhook `sconf:"optional" sconf-doc:"Webhooks for events about outgoing deliveries."`
	IncomingWebhook          *IncomingWebhook `sconf:"optional" sconf-doc:"Webhooks for events about incoming deliveries over SMTP."`
	FromIDLoginAddresses     []string         `sconf:"optional" sconf-doc:"Login addresses that cause outgoing email to be sent with SMTP MAIL FROM addresses with a unique id after the localpart catchall separator (which must be enabled when addresses are specified here). Any delivery status notifications (DSN, e.g. for bounces), can be related to the original message and recipient with unique id's. You can login to an account with any valid email address, including variants with the localpart catchall separator. You can use this mechanism to both send outgoing messages with and without unique fromid for a given email address. With the webapi and webmail, a unique id will be generated. For submission, the id from the SMTP MAIL FROM command is used if present, and a unique id is generated otherwise."`
	KeepRetiredMessagePeriod time.Duration    `sconf:"optional" sconf-doc:"Period to keep messages retired from the queue (delivered or failed) around. Keeping retired messages is useful for maintaining the suppression list for transactional email, for matching incoming DSNs to sent messages, and for debugging. The time at which to clean up (remove) is calculated at retire time. E.g. 168h (1 week)."`
	KeepRetiredWebhookPeriod time.Duration    `sconf:"optional" sconf-doc:"Period to keep webhooks retired from the queue (delivered or failed) around. Useful for debugging. The time at which to clean up (remove) is calculated at retire time. E.g. 168h (1 week)."`

	Domain                       string                 `sconf-doc:"Default domain for account. Deprecated behaviour: If a destination is not a full address but only a localpart, this domain is added to form a full address."`
	Description                  string                 `sconf:"optional" sconf-doc:"Free form description, e.g. full name or alternative contact info."`
	FullName                     string                 `sconf:"optional" sconf-doc:"Full name, to use in message From header when composing messages in webmail. Can be overridden per destination."`
	Destinations                 map[string]Destination `sconf:"optional" sconf-doc:"Destinations, keys are email addresses (with IDNA domains). All destinations are allowed for logging in with IMAP/SMTP/webmail. If no destinations are configured, the account can not login. If the address is of the form '@domain', i.e. with localpart missing, it serves as a catchall for the domain, matching all messages that are not explicitly configured. Deprecated behaviour: If the address is not a full address but a localpart, it is combined with Domain to form a full address."`
	SubjectPass                  SubjectPass            `sconf:"optional" sconf-doc:"If configured, messages classified as weakly spam are rejected with instructions to retry delivery, but this time with a signed token added to the subject. During the next delivery attempt, the signed token will bypass the spam filter. Messages with a clear spam signal, such as a known bad reputation, are rejected/delayed without a signed token."`
	QuotaMessageSize             int64                  `sconf:"optional" sconf-doc:"Default maximum total message size in bytes for the account, overriding any globally configured default maximum size if non-zero. A negative value can be used to have no limit in case there is a limit by default. Attempting to add new messages to an account beyond its maximum total size will result in an error. Useful to prevent a single account from filling storage."`
	RejectsMailbox               string                 `sconf:"optional" sconf-doc:"Mail that looks like spam will be rejected, but a copy can be stored temporarily in a mailbox, e.g. Rejects. If mail isn't coming in when you expect, you can look there. The mail still isn't accepted, so the remote mail server may retry (hopefully, if legitimate), or give up (hopefully, if indeed a spammer). Messages are automatically removed from this mailbox, so do not set it to a mailbox that has messages you want to keep."`
	KeepRejects                  bool                   `sconf:"optional" sconf-doc:"Don't automatically delete mail in the RejectsMailbox listed above. This can be useful, e.g. for future spam training. It can also cause storage to fill up."`
	AutomaticJunkFlags           AutomaticJunkFlags     `sconf:"optional" sconf-doc:"Automatically set $Junk and $NotJunk flags based on mailbox messages are delivered/moved/copied to. Email clients typically have too limited functionality to conveniently set these flags, especially $NonJunk, but they can all move messages to a different mailbox, so this helps them."`
	JunkFilter                   *JunkFilter            `sconf:"optional" sconf-doc:"Content-based filtering, using the junk-status of individual messages to rank words in such messages as spam or ham. It is recommended you always set the applicable (non)-junk status on messages, and that you do not empty your Trash because those messages contain valuable ham/spam training information."` // todo: sane defaults for junkfilter
	MaxOutgoingMessagesPerDay    int                    `sconf:"optional" sconf-doc:"Maximum number of outgoing messages for this account in a 24 hour window. This limits the damage to recipients and the reputation of this mail server in case of account compromise. Default 1000."`
	MaxFirstTimeRecipientsPerDay int                    `sconf:"optional" sconf-doc:"Maximum number of first-time recipients in outgoing messages for this account in a 24 hour window. This limits the damage to recipients and the reputation of this mail server in case of account compromise. Default 200."`
	NoFirstTimeSenderDelay       bool                   `sconf:"optional" sconf-doc:"Do not apply a delay to SMTP connections before accepting an incoming message from a first-time sender. Can be useful for accounts that sends automated responses and want instant replies."`
	Routes                       []Route                `sconf:"optional" sconf-doc:"Routes for delivering outgoing messages through the queue. Each delivery attempt evaluates these account routes, domain routes and finally global routes. The transport of the first matching route is used in the delivery attempt. If no routes match, which is the default with no configured routes, messages are delivered directly from the queue."`

	DNSDomain                  dns.Domain     `sconf:"-"` // Parsed form of Domain.
	JunkMailbox                *regexp.Regexp `sconf:"-" json:"-"`
	NeutralMailbox             *regexp.Regexp `sconf:"-" json:"-"`
	NotJunkMailbox             *regexp.Regexp `sconf:"-" json:"-"`
	ParsedFromIDLoginAddresses []smtp.Address `sconf:"-" json:"-"`
	Aliases                    []AddressAlias `sconf:"-"`
}

type AddressAlias struct {
	SubscriptionAddress string
	Alias               Alias    // Without members.
	MemberAddresses     []string // Only if allowed to see.
}

type JunkFilter struct {
	Threshold float64 `sconf-doc:"Approximate spaminess score between 0 and 1 above which emails are rejected as spam. Each delivery attempt adds a little noise to make it slightly harder for spammers to identify words that strongly indicate non-spaminess and use it to bypass the filter. E.g. 0.95."`
	junk.Params
}

type Destination struct {
	Mailbox  string    `sconf:"optional" sconf-doc:"Mailbox to deliver to if none of Rulesets match. Default: Inbox."`
	Rulesets []Ruleset `sconf:"optional" sconf-doc:"Delivery rules based on message and SMTP transaction. You may want to match each mailing list by SMTP MailFrom address, VerifiedDomain and/or List-ID header (typically <listname.example.org> if the list address is listname@example.org), delivering them to their own mailbox."`
	FullName string    `sconf:"optional" sconf-doc:"Full name to use in message From header when composing messages coming from this address with webmail."`

	DMARCReports     bool `sconf:"-" json:"-"`
	HostTLSReports   bool `sconf:"-" json:"-"`
	DomainTLSReports bool `sconf:"-" json:"-"`
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
	SMTPMailFromRegexp string            `sconf:"optional" sconf-doc:"Matches if this regular expression matches (a substring of) the SMTP MAIL FROM address (not the message From-header). E.g. '^user@example\\.org$'."`
	MsgFromRegexp      string            `sconf:"optional" sconf-doc:"Matches if this regular expression matches (a substring of) the single address in the message From header."`
	VerifiedDomain     string            `sconf:"optional" sconf-doc:"Matches if this domain matches an SPF- and/or DKIM-verified (sub)domain."`
	HeadersRegexp      map[string]string `sconf:"optional" sconf-doc:"Matches if these header field/value regular expressions all match (substrings of) the message headers. Header fields and valuees are converted to lower case before matching. Whitespace is trimmed from the value before matching. A header field can occur multiple times in a message, only one instance has to match. For mailing lists, you could match on ^list-id$ with the value typically the mailing list address in angled brackets with @ replaced with a dot, e.g. <name\\.lists\\.example\\.org>."`
	// todo: add a SMTPRcptTo check

	// todo: once we implement ARC, we can use dkim domains that we cannot verify but that the arc-verified forwarding mail server was able to verify.
	IsForward              bool   `sconf:"optional" sconf-doc:"Influences spam filtering only, this option does not change whether a message matches this ruleset. Can only be used together with SMTPMailFromRegexp and VerifiedDomain. SMTPMailFromRegexp must be set to the address used to deliver the forwarded message, e.g. '^user(|\\+.*)@forward\\.example$'. Changes to junk analysis: 1. Messages are not rejected for failing a DMARC policy, because a legitimate forwarded message without valid/intact/aligned DKIM signature would be rejected because any verified SPF domain will be 'unaligned', of the forwarding mail server. 2. The sending mail server IP address, and sending EHLO and MAIL FROM domains and matching DKIM domain aren't used in future reputation-based spam classifications (but other verified DKIM domains are) because the forwarding server is not a useful spam signal for future messages."`
	ListAllowDomain        string `sconf:"optional" sconf-doc:"Influences spam filtering only, this option does not change whether a message matches this ruleset. If this domain matches an SPF- and/or DKIM-verified (sub)domain, the message is accepted without further spam checks, such as a junk filter or DMARC reject evaluation. DMARC rejects should not apply for mailing lists that are not configured to rewrite the From-header of messages that don't have a passing DKIM signature of the From-domain. Otherwise, by rejecting messages, you may be automatically unsubscribed from the mailing list. The assumption is that mailing lists do their own spam filtering/moderation."`
	AcceptRejectsToMailbox string `sconf:"optional" sconf-doc:"Influences spam filtering only, this option does not change whether a message matches this ruleset. If a message is classified as spam, it isn't rejected during the SMTP transaction (the normal behaviour), but accepted during the SMTP transaction and delivered to the specified mailbox. The specified mailbox is not automatically cleaned up like the account global Rejects mailbox, unless set to that Rejects mailbox."`

	Mailbox string `sconf-doc:"Mailbox to deliver to if this ruleset matches."`
	Comment string `sconf:"optional" sconf-doc:"Free-form comments."`

	SMTPMailFromRegexpCompiled *regexp.Regexp      `sconf:"-" json:"-"`
	MsgFromRegexpCompiled      *regexp.Regexp      `sconf:"-" json:"-"`
	VerifiedDNSDomain          dns.Domain          `sconf:"-"`
	HeadersRegexpCompiled      [][2]*regexp.Regexp `sconf:"-" json:"-"`
	ListAllowDNSDomain         dns.Domain          `sconf:"-"`
}

// Equal returns whether r and o are equal, only looking at their user-changeable fields.
func (r Ruleset) Equal(o Ruleset) bool {
	if r.SMTPMailFromRegexp != o.SMTPMailFromRegexp || r.MsgFromRegexp != o.MsgFromRegexp || r.VerifiedDomain != o.VerifiedDomain || r.IsForward != o.IsForward || r.ListAllowDomain != o.ListAllowDomain || r.AcceptRejectsToMailbox != o.AcceptRejectsToMailbox || r.Mailbox != o.Mailbox || r.Comment != o.Comment {
		return false
	}
	if !reflect.DeepEqual(r.HeadersRegexp, o.HeadersRegexp) {
		return false
	}
	return true
}

type KeyCert struct {
	CertFile string `sconf-doc:"Certificate including intermediate CA certificates, in PEM format."`
	KeyFile  string `sconf-doc:"Private key for certificate, in PEM format. PKCS8 is recommended, but PKCS1 and EC private keys are recognized as well."`
}

type TLS struct {
	ACME                string    `sconf:"optional" sconf-doc:"Name of provider from top-level configuration to use for ACME, e.g. letsencrypt."`
	KeyCerts            []KeyCert `sconf:"optional" sconf-doc:"Keys and certificates to use for this listener. The files are opened by the privileged root process and passed to the unprivileged mox process, so no special permissions are required on the files. If the private key will not be replaced when refreshing certificates, also consider adding the private key to HostPrivateKeyFiles and configuring DANE TLSA DNS records."`
	MinVersion          string    `sconf:"optional" sconf-doc:"Minimum TLS version. Default: TLSv1.2."`
	HostPrivateKeyFiles []string  `sconf:"optional" sconf-doc:"Private keys used for ACME certificates. Specified explicitly so DANE TLSA DNS records can be generated, even before the certificates are requested. DANE is a mechanism to authenticate remote TLS certificates based on a public key or certificate specified in DNS, protected with DNSSEC. DANE is opportunistic and attempted when delivering SMTP with STARTTLS. The private key files must be in PEM format. PKCS8 is recommended, but PKCS1 and EC private keys are recognized as well. Only RSA 2048 bit and ECDSA P-256 keys are currently used. The first of each is used when requesting new certificates through ACME."`

	Config                   *tls.Config     `sconf:"-" json:"-"` // TLS config for non-ACME-verification connections, i.e. SMTP and IMAP, and not port 443. Connections without SNI will use a certificate for the hostname of the listener, connections with an SNI hostname that isn't allowed will be rejected.
	ConfigFallback           *tls.Config     `sconf:"-" json:"-"` // Like Config, but uses the certificate for the listener hostname when the requested SNI hostname is not allowed, instead of causing the connection to fail.
	ACMEConfig               *tls.Config     `sconf:"-" json:"-"` // TLS config that handles ACME verification, for serving on port 443.
	HostPrivateRSA2048Keys   []crypto.Signer `sconf:"-" json:"-"` // Private keys for new TLS certificates for listener host name, for new certificates with ACME, and for DANE records.
	HostPrivateECDSAP256Keys []crypto.Signer `sconf:"-" json:"-"`
}

// todo: we could implement matching WebHandler.Domain as IPs too

type WebHandler struct {
	LogName               string       `sconf:"optional" sconf-doc:"Name to use in logging and metrics."`
	Domain                string       `sconf-doc:"Both Domain and PathRegexp must match for this WebHandler to match a request. Exactly one of WebStatic, WebRedirect, WebForward, WebInternal must be set."`
	PathRegexp            string       `sconf-doc:"Regular expression matched against request path, must always start with ^ to ensure matching from the start of the path. The matching prefix can optionally be stripped by WebForward. The regular expression does not have to end with $."`
	DontRedirectPlainHTTP bool         `sconf:"optional" sconf-doc:"If set, plain HTTP requests are not automatically permanently redirected (308) to HTTPS. If you don't have a HTTPS webserver configured, set this to true."`
	Compress              bool         `sconf:"optional" sconf-doc:"Transparently compress responses (currently with gzip) if the client supports it, the status is 200 OK, no Content-Encoding is set on the response yet and the Content-Type of the response hints that the data is compressible (text/..., specific application/... and .../...+json and .../...+xml). For static files only, a cache with compressed files is kept."`
	WebStatic             *WebStatic   `sconf:"optional" sconf-doc:"Serve static files."`
	WebRedirect           *WebRedirect `sconf:"optional" sconf-doc:"Redirect requests to configured URL."`
	WebForward            *WebForward  `sconf:"optional" sconf-doc:"Forward requests to another webserver, i.e. reverse proxy."`
	WebInternal           *WebInternal `sconf:"optional" sconf-doc:"Pass request to internal service, like webmail, webapi, etc."`

	Name      string         `sconf:"-"` // Either LogName, or numeric index if LogName was empty. Used instead of LogName in logging/metrics.
	DNSDomain dns.Domain     `sconf:"-"`
	Path      *regexp.Regexp `sconf:"-" json:"-"`
}

// Equal returns if wh and o are equal, only looking at fields in the configuration file, not the derived fields.
func (wh WebHandler) Equal(o WebHandler) bool {
	clean := func(x WebHandler) WebHandler {
		x.Name = ""
		x.DNSDomain = dns.Domain{}
		x.Path = nil
		x.WebStatic = nil
		x.WebRedirect = nil
		x.WebForward = nil
		x.WebInternal = nil
		return x
	}
	cwh := clean(wh)
	co := clean(o)
	if cwh != co {
		return false
	}
	if (wh.WebStatic == nil) != (o.WebStatic == nil) || (wh.WebRedirect == nil) != (o.WebRedirect == nil) || (wh.WebForward == nil) != (o.WebForward == nil) || (wh.WebInternal == nil) != (o.WebInternal == nil) {
		return false
	}
	if wh.WebStatic != nil {
		return reflect.DeepEqual(wh.WebStatic, o.WebStatic)
	}
	if wh.WebRedirect != nil {
		return wh.WebRedirect.equal(*o.WebRedirect)
	}
	if wh.WebForward != nil {
		return wh.WebForward.equal(*o.WebForward)
	}
	if wh.WebInternal != nil {
		return wh.WebInternal.equal(*o.WebInternal)
	}
	return true
}

type WebStatic struct {
	StripPrefix      string            `sconf:"optional" sconf-doc:"Path to strip from the request URL before evaluating to a local path. If the requested URL path does not start with this prefix and ContinueNotFound it is considered non-matching and next WebHandlers are tried. If ContinueNotFound is not set, a file not found (404) is returned in that case."`
	Root             string            `sconf-doc:"Directory to serve files from for this handler. Keep in mind that relative paths are relative to the working directory of mox."`
	ListFiles        bool              `sconf:"optional" sconf-doc:"If set, and a directory is requested, and no index.html is present that can be served, a file listing is returned. Results in 403 if ListFiles is not set. If a directory is requested and the URL does not end with a slash, the response is a redirect to the path with trailing slash."`
	ContinueNotFound bool              `sconf:"optional" sconf-doc:"If a requested URL does not exist, don't return a file not found (404) response, but consider this handler non-matching and continue attempts to serve with later WebHandlers, which may be a reverse proxy generating dynamic content, possibly even writing a static file for a next request to serve statically. If ContinueNotFound is set, HTTP requests other than GET and HEAD do not match. This mechanism can be used to implement the equivalent of 'try_files' in other webservers."`
	ResponseHeaders  map[string]string `sconf:"optional" sconf-doc:"Headers to add to the response. Useful for cache-control, content-type, etc. By default, Content-Type headers are automatically added for recognized file types, unless added explicitly through this setting. For directory listings, a content-type header is skipped."`
}

type WebRedirect struct {
	BaseURL        string `sconf:"optional" sconf-doc:"Base URL to redirect to. The path must be empty and will be replaced, either by the request URL path, or by OrigPathRegexp/ReplacePath. Scheme, host, port and fragment stay intact, and query strings are combined. If empty, the response redirects to a different path through OrigPathRegexp and ReplacePath, which must then be set. Use a URL without scheme to redirect without changing the protocol, e.g. //newdomain/. If a redirect would send a request to a URL with the same scheme, host and path, the WebRedirect does not match so a next WebHandler can be tried. This can be used to redirect all plain http traffic to https."`
	OrigPathRegexp string `sconf:"optional" sconf-doc:"Regular expression for matching path. If set and path does not match, a 404 is returned. The HTTP path used for matching always starts with a slash."`
	ReplacePath    string `sconf:"optional" sconf-doc:"Replacement path for destination URL based on OrigPathRegexp. Implemented with Go's Regexp.ReplaceAllString: $1 is replaced with the text of the first submatch, etc. If both OrigPathRegexp and ReplacePath are empty, BaseURL must be set and all paths are redirected unaltered."`
	StatusCode     int    `sconf:"optional" sconf-doc:"Status code to use in redirect, e.g. 307. By default, a permanent redirect (308) is returned."`

	URL      *url.URL       `sconf:"-" json:"-"`
	OrigPath *regexp.Regexp `sconf:"-" json:"-"`
}

func (wr WebRedirect) equal(o WebRedirect) bool {
	wr.URL = nil
	wr.OrigPath = nil
	o.URL = nil
	o.OrigPath = nil
	return reflect.DeepEqual(wr, o)
}

type WebForward struct {
	StripPath       bool              `sconf:"optional" sconf-doc:"Strip the matching WebHandler path from the WebHandler before forwarding the request."`
	URL             string            `sconf-doc:"URL to forward HTTP requests to, e.g. http://127.0.0.1:8123/base. If StripPath is false the full request path is added to the URL. Host headers are sent unmodified. New X-Forwarded-{For,Host,Proto} headers are set. Any query string in the URL is ignored. Requests are made using Go's net/http.DefaultTransport that takes environment variables HTTP_PROXY and HTTPS_PROXY into account. Websocket connections are forwarded and data is copied between client and backend without looking at the framing. The websocket 'version' and 'key'/'accept' headers are verified during the handshake, but other websocket headers, including 'origin', 'protocol' and 'extensions' headers, are not inspected and the backend is responsible for verifying/interpreting them."`
	ResponseHeaders map[string]string `sconf:"optional" sconf-doc:"Headers to add to the response. Useful for adding security- and cache-related headers."`

	TargetURL *url.URL `sconf:"-" json:"-"`
}

func (wf WebForward) equal(o WebForward) bool {
	wf.TargetURL = nil
	o.TargetURL = nil
	return reflect.DeepEqual(wf, o)
}

type WebInternal struct {
	BasePath string `sconf-doc:"Path to use as root of internal service, e.g. /webmail/."`
	Service  string `sconf-doc:"Name of the service, values: admin, account, webmail, webapi."`

	Handler http.Handler `sconf:"-" json:"-"`
}

func (wi WebInternal) equal(o WebInternal) bool {
	wi.Handler = nil
	o.Handler = nil
	return reflect.DeepEqual(wi, o)
}
