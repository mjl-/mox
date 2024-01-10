# Features

## Easy to operate

The initial installation should be easy when using the quickstart. It performs
some DNS checks, generates config files, an initial admin account and an email
address account, and it prints all the DNS records (quite a few!) you need to
add for sending and receiving email. It also creates a systemd unit file to run
mox as a service on Linux, along with commands to enable the server. When run,
it fixes up file permissions. You normally only have to copy/paste text and run
the suggested commands.

Upgrades are usually a matter of replacing the binary and restart mox. Mox
tries hard to not make incompatible changes. After an update you may want to
change a configuration file to enable new functionality or behaviour.

The [configuration files](../config/) that come annotated with documentation
make it easy to discover and configure functionality. The web admin interface
guides you even more in making runtime configuration changes. The web admin
interface also writes to the runtime configuration file. So you get the power
of plain files for configuration (for readability, version control/diffs), and
the ease of a user interface for making changes.

Mox is an all-in-one email server built in a single coherent code base. This
ensures that all functionality works well together. And that you don't have to
configure lots of individual components for a fully working system.


## SMTP

SMTP is used to deliver and receive email messages on the internet. Email
clients also use it to ask an SMTP server to deliver messages (called
submission).

Mox implements:

- An SMTP server to accept deliveries of incoming messages, on port 25.
- An SMTP client and delivery queue for delivering messages to other mail
  servers, connecting to other servers on port 25.
- A "submission" (SMTP) server, so authenticated clients can submit messages to
  the queue, from which Mox will deliver, with retries.
- Commonly used SMTP extensions.

## SPF/DKIM/DMARC

SPF, DKIM and DMARC are mechanisms for "message authentication". SPF and DKIM
can be used to verify that a domain is indeed associated with an incoming
message. This allows mail servers to keep track of the reputation of a domain,
which is used during junk filtering.

SPF is a mechanism whereby a domain specifies in a TXT DNS record which IPs are
allowed to use its domain in an address in the `MAIL FROM` command in an SMTP
transaction. If a sending IP is not listed, a receiving mail server may reject
the email as likely being junk. However, the decision to reject isn't made
solely based on the SPF record, keep reading.

DKIM is a mechanism whereby a domain specifies public keys in DNS TXT records.
Legitimate messages originating from the domain will have one or more
`DKIM-Signature` message headers that reference a public key and contain a
signature. During delivery, the signature is verified.

DMARC is a mechanism whereby a domain specifies a policy in a DNS TXT record
about what to do messages that are not authenticated with "aligned" SPF and/or
DKIM. These policies include "reject", or "quarantine" (put in junk mailbox),
or "none" (don't treat differently).  DMARC authenticates the address in the
"From" header in an email message, since that is what users will typically look
at and trust.  For a message to pass the "aligned SPF" check, the SPF-domain
must match the domain the message "From" header.  For a message to pass the
"aligned DKIM" check, at least one verified DKIM domain must match the domain
in the message "From" header.  A non-aligned verified domain is not used for
DMARC, but can still be useful in junk filtering.

Mox sets up SPF, DKIM and DMARC for your domain, and adds `DKIM-Signature`
headers to outgoing messages.

For incoming messages, mox will perform SPF, DKIM and DMARC checks. DMARC
policies of domains are honored by mox, though mox interprets policy
"quarantine" as "reject": Mox does not claim to accept messages, only to hide
them away in a junk mailbox. Mox uses reputation of SPF-, DKIM- and
DMARC(-like) verified domains in its reputation-based junk filtering.

A domain's DMARC policy, as published in DNS records, can request reports about
DMARC policies as performed by other mail servers. This gives you, as domain
owner, insights into where both authenticated and non-authenticated messages
are being sent from. The policy specifies an email address whereto such reports
should be sent. Mox helps set up a policy to request such reports,
automatically processes such reports, and provides access through its admin web
interface. Mox also sends reports with the results of its DMARC evaluations to
domains that request them.


## DANE and MTA-STS

DANE and MTA-STS are mechanisms for more secure email delivery using SMTP.

Originally, SMTP delivered email messages over the internet in plain text.
Message delivery was vulnerable to eavesdropping/interception.

The SMTP STARTTLS extension added opportunistic TLS: If a server announces
support, a (delivering) SMTP client can "upgrade" a connection to TLS. This
prevents passive attackers from eavesdropping. But an active attacker can
simply strip server support for STARTTLS, causing a message to be transferred
in plain text. With opportunistic TLS for SMTP, the TLS certificate of a server
is not verified: Certificates that are expired or for other host names are
accepted.

Both old-fashioned plain text delivery and STARTTLS don't protect against
another active attack: Simply modifying DNS MX responses, causing email to be
delivered to another server entirely. That other server may implement STARTTLS,
and even have a certificate that can be verified. But the MX records need
protection as well.

Both DANE and MTA-STS are (different) opt-in mechanisms to protect MX records,
and for verifying TLS certificates of SMTP servers.

DANE protects MX records by requiring that they are DNSSEC-signed, causing
changes to DNS records to be detected.  With DANE, TLS certificates of an MX
host are verified through (hashes of) either public keys or full certificates.
These are published in DNS and must also be protected with DNSSEC. If a
connection is intercepted by a different server, the TLS certificate validation
would not pass.

MTA-STS uses PKIX (pool of trusted Certificate Authorities (CAs))to protect
both MX records and to verify TLS during SMTP STARTTLS. MTA-STS serves
existence/version of a policy at DNS record `_mta-sts.<recipientdomain>`, and
the policy itself at the PKIX-verified `https://mta-sts.<recipientdomain>`,
specifying allowed MX host names.  During delivery, MX targets not in the
MTA-STS policy are rejected.  The MTA-STS, MX, and MX target IP address DNS
records are not required to be protected with DNSSEC, and often aren't.  If an
attacker modifies the IP address of an MTA-STS-allowed MX target, the
PKIX-verification during SMTP STARTTLS will not pass. MTA-STS policies specify
how long they should be cached.  Attackers can suppress existence of an MTA-STS
record during the first communication between mail servers, but not on
subsequent deliveries.

For delivery of outgoing messages, mox will use both DANE and MTA-STS, if
configured for a recipient domain. MTA-STS policies are cached and periodically
refreshed.

Domains hosted by mox are both DANE- and MTA-STS protected by default. However,
DANE only applies if recipient domains and their MX records are DNSSEC-signed.
Mox requests certificates with ACME from Let's Encrypt by default, so TLS
certificates used in SMTP STARTTLS can be PKIX-verified.  Mox also serves
MTA-STS policies by default.

Mox also implements the REQUIRETLS SMTP extension. It allows message delivery
to specify that MX DNS records and SMTP server TLS certificates must be
verified along the full delivery path (not just the next hop), and that
delivery must be aborted if that cannot be guaranteed.

Mox also implements both incoming and outgoing TLS reporting, with both DANE
and MTA-STS details. TLS reports have aggregated counts of SMTP connections
(with failures, including about TLS, and success) and the DANE/MTA-STS policies
encountered. Domains can request delivery of TLS reports by specifying a report
destination address in a TLSRPT policy, specified in a DNS TXT record under a
domain.


## IMAP4

Email clients (also called Mail User Agents, MUAs) typically access messages
through IMAP4. IMAP4 gives access to all mailboxes (folders) in an account, and
all messages in those mailboxes. IMAP4 is a protocol with a long history, and
for which many extensions have been specified. IMAP4 can be used for
efficiently synchronizing an entire account for offline/local use, or used
reading messages "online" (e.g. with third party webmail software).

Mox implements up to IMAP4rev2, the latest revision of IMAP4 that includes lots
of functionality that used to be an extension. And mox implements commonly used
extensions on top of that, such as CONDSTORE and QRESYNC, with more extensions
to be implemented.


## Junk filtering

Junk email/spam/UCE (unsolicited commercial email) is still a big problem on
the internet. One great feature of email, that is worth protecting, is that you
can send an email to another person without previous introduction. However,
spammers have the same opportunity. Various mechanisms have been developed over
time to reduce the amount of junk.

### Reputation-based

Most of these mechanisms have components that involves reputation. The
reputation can be based on the IP address of the sending server, or the email
address (or just its domain) of the sender, or the contents of the message. Mox
uses the junk/non-junk classifications of messages by the user to evaluate
incoming messages.

Email clients have the ability to mark a message as junk, which typically sets
the junk-flag for the message and/or moves the message to the designated Junk
mailbox. An email client can also mark a message as non-junk, but this isn't
commonly done, so mox automatically automatically marks messages moved to
certain mailboxes (like Archive, Trash) as non-junk.

The message database, including junk/non-junk flags, is accessible by the SMTP
server. The database allows for efficiently looking up messages by (non)-junk
flags, verified SPF/DKIM/DMARC sender domain/address and originating IP
address. This allows mox to quickly analyze the reputation of an incoming
message, and make a decision to accept/reject a message if the sender
address/domain/IP has enough reputation signal. This means messages from people
you've communicated with before will reliably make it through the junk filter.
At least if they have set up SPF and/or DKIM, which allows associating their
messages with their domain.  Only messages without reputation, "first-time
senders", are subject to further scrutiny.

### First-time senders

For first-time senders, there is no, or not enough, signal in the sending
address/domain/IP address to make a decision. Mox does bayesian analysis on the
contents of such messages: The reputation of the words in a message are used to
calculate the probability that a message is junk, which must not pass a
configurable threshold.  The reputation of words is based on their occurrence
in historic junk/non-junk messages, as classified by the user.

### Delivery feedback

When an incoming message is rejected for being junk, mox returns a temporary
error. Mox never claims to accept a message only to drop it (some cloud mail
providers are known to do this!), or place it in a Junk mailbox, out of view of
the user. The effect is that a spammer will not learn whether there is an
actual temporary error, or their message is treated as junk. A legitimate
sender whose message is erroneously classified as junk will receive a DSN
message about the failed delivery attempts, making it clear a different means
of communication should be tried.

### Rejects mailbox

When mox rejects a message for being junk, it stores a copy of the message in
the special "Rejects" mailbox (automatically cleaned up). If you are expecting
an email, e.g. about signup to a new service, and it is rejected, you will find
the message in that mailbox. By moving the message to the Inbox, and marking it
as non-junk (e.g. by moving it to the Archive or Trash mailbox), future
messages by that sender will be accepted due to the now positive reputation.

### Reputation is per account

In mox, all reputation is per account, not shared among accounts. One account
may mark all messages from a sender as junk, causing them to be rejected, while
another account can accept messages from the same sender.

### DNSBL

Mox can be configured to use an IP-based DNS blocklist (DNSBL). These are
typically employed early in the SMTP session, to see if the remote IP is a
known spammer. If so, the delivery attempt is stopped early. Mox doesn't use
DNSBLs in its default installation. But if it is configured to use a DNSBL, it
is only invoked when the other reputation-based checks are not conclusive. For
these reasons:

1. If a sender with positive reputation finds their IP listed in a DNSBL, the
   email communication channels that have always worked will keep working (until
   the user marks a few of their messages as junk).
2. As little reliance on centralized parties (which DNSBLs typically are) as
   possible.
3. No leaking of IP addresses of mail servers a mox instance is communicating
   with to the DNSBL operator.

### Greylisting

Greylisting is a commonly implemented mechanism whereby the first delivery
attempt from a first-time sender is rejected with a temporary error. The idea
is that spammers don't implement delivery queueing, and will never try again.
A legitimate mail server would try again, typically within 5-15 minutes, and
the second or third attempt will be accepted. Mox does not implement
greylisting in this manner:

Mail servers typically send from multiple IP addresses. At least both an IPv4
and IPv6 address, and often multiple of each to reduce impact of a negative
reputation for an IP address (e.g. being listed in a DNSBL). IP-based
reputation incentivizes mail servers to use a different IP address for delivery
retries after encountering a failure. Greylisting incentivizes mail servers to
use the same IP address for retries. These incentives conflict, and mox regards
IP-based reputation as more (long-term) valuable. Due to delivering from
different IP addresses, greylisting can cause very long delays, or cause
delivery failures altogether.

Mox does employ mechanisms to slow down possible spammers: SMTP transactions of
first-time senders and for messages classified as junk are slowed down. This
reduces the rate at which junk mail would be received, and consumes resources
of the spammer. First-time senders are delayed for 15 seconds, making it
possible to wait for expected messages, such as for signups.


## Webmail

Mox includes a webmail client, still in early stages. Despite its looks, and
missing features like composing messages in HTML, it is surprisingly usable,
featuring:

- Text and HTML rendering of messages, with/without external resources
  (tracking images).
- Threading, including muting threads
- Drag-and-drop for moving messages
- Layout: top/bottom vs left/right, adjustable widths/heights
- Keyboard shortcuts

The webmail benefits from having access to the message database, allowing for
new functionality that wouldn't be easy to implement with SMTP/IMAP4. For
example, mox keeps track of REQUIRETLS support of MX hosts (mail servers) of
recipient domains. The webmail show this information when composing a message,
and can enable REQUIRETLS by default.

See [webmail screenshots](../screenshots/#hdr-webmail).


## Internationalized email

Originally, email addresses were ASCII-only. An email address consists of a
"localpart", an "@" and a domain name. Only ASCII was allowed in message
headers. With internationalized email, localparts can be in UTF-8, domains can
use internationalized domain names (IDN/IDNA: unicode names with both an UTF-8
encoding, and an ASCII encoding for use in DNS with domains starting with
"xn--"), and message headers are allowed to contain UTF-8 as well.

With internationalized email, users of scripts not representable in ASCII can
use their native scripts for their email addresses.

Mox implements internationalized email.


## Automatic account configuration

To configure an email account in an email client, you typically need to specify:

1. Email address and full name.
2. Submission (SMTP) server address, port, TLS mode, username, password and
   authentication mechanism.
3. IMAP4 server address, port, TLS mode, username, password and authentication
   mechanism.

This can be cumbersome to configure manually. Email clients can choose from
several autoconfiguration mechanisms to automatically find (some of) the right
settings, given an email address:

SRV DNS records
: The domain of the email address is used for looking up DNS SRV records, which
point to the submission (SMTP) and IMAP servers, ports (with implied TLS
mode). Not specified: username, authentication mechanism. Only secure when used
with DNSSEC. Mox prints SRV records to add for a domain.

Thunderbird-style autoconfig
: The domain of the email address is used for looking up an XML config file at
`https://autoconfig.<domain>`, protected with WebPKI. The configuration file
holds all settings. Mox serves autoconfig profiles on its webserver.

Autodiscover-style autodiscovery
: The domain of the email address is used to look up a SRV record that points
to an PKIX-protected HTTPS webserver that serves an XML configuration file with
all settings. Only secure when the SRV lookup is DNSSEC-protected. Mox serves
autodiscover profiles on its webserver.

Apple device management profile
: A configuration file with all settings must be transferred to the device
manually. Mox lets users download these profiles in the account web interface,
and shows a QR code to easily download the profile.

Even though email clients have many options to automatically find the correct
settings, many still prefer to guess incorrect legacy settings.


## ACME for automatic TLS

A modern email server needs a PKIX TLS certificate for its own hostname, used
for SMTP with STARTTLS. Each domain with a "mail" CNAME for IMAP4 and SMTP
submission, with MTA-STS and with autoconfiguration needs three more
PKIX/WebPKI TLS certificates. Manually preventing your email infrastructure
from automatic periodic expiration is cumbersome, but [an
option](../config/#cfg-mox-conf-Listeners-x-TLS-KeyCerts). With ACME, TLS
certificates are retrieved and refreshed automatically.

The quickstart sets mox up with ACME using Let's Encrypt. Other ACME providers
can be [defined](../config/#cfg-mox-conf-ACME-x) and
[configured](../config/#cfg-mox-conf-Listeners-x-TLS-ACME). Mox supports
[external account binding](../config/#cfg-mox-conf-ACME-x-ExternalAccountBinding)
(EAB) for ACME providers that require association with an existing non-ACME
account. Mox also suggests DNS CAA records, explicitly allowlisting Certificate
Authorities (CAs) allowed to sign certificates for a domain. Mox recommends CAA
records that only allow the account ID that mox has registered, preventing
potential MitM attempts.

ACME is also used for TLS certificates for the webserver, see below.

## Webserver

Mox includes a configurable webserver. This may seem to add unnecessary
complexity and functionality to an email server, but contemporary email already
requires the complexity of an HTTP stack due to MTA-STS and automatic account
configuration. Not to mention webmail and an admin web interface. Luckily, mox
can build on the proven HTTP client and server stack of the Go standard
library.

Mox mostly adds configuration options for:

- Redirections of [entire domains](../config/#cfg-domains-conf-WebDomainRedirects) or
  [paths](../config/#cfg-domains-conf-WebHandlers-dash-WebRedirect).
- [Serving static files](../config/#cfg-domains-conf-WebHandlers-dash-WebStatic)
  from a directory, including optional directory listings.
- [Forwarding/Reverse proxying](../config/#cfg-domains-conf-WebHandlers-dash-WebForward),
  including WebSocket connections.

Incoming requests are handled by going through the list of configured handlers.
The first matching handler takes care of the request, matching on:

- Host
- Path (regular expression)

Handlers can specify additional behaviour:

- Automatically redirect plain HTTP requests to HTTPS.
- Automatically compress the response if it seems compressible (based on
  content-type). A compressed static files are kept in a fixed size cache.
- Strip the matched path before serving static file or forwarding the request.
- Add custom headers to the response.

These settings can all be configued through the admin web interface.

TLS certificates for configured domains are managed automatically if ACME is
configured.

You may be tempted to install mox on a server that already runs a webserver. It
is possible to configure mox to work with an existing webserver, but it will
complicate the configuration significantly: The mox configuration has to be
modified for
[autoconfig](../config/#cfg-mox-conf-Listeners-x-AutoconfigHTTPS-NonTLS) and
[MTA-STS](../config/#cfg-mox-conf-Listeners-x-MTASTSHTTPS-NonTLS) and the
existing webserver needs to be configured to forward. You will likely manage
TLS certificates outside of mox and have to configure the paths to the [keys
and certificates](../config/#cfg-mox-conf-Listeners-x-TLS-KeyCerts), and
refresh them timely, restarting mox. Also see the `-existing-webserver` option
in the [quickstart command](../commands/#hdr-mox-quickstart).


## Localserve

The [mox localserve](../commands/#hdr-mox-localserve) starts a local mox
instance with a lot of its functionality: SMTP/submission, IMAP4, Webmail,
account and admin web interface and the webserver. Localserve listens on the
standard ports + 1000, so no special privileges are needed.

Localserve is useful for testing the email functionality of your application:
Localserve can accept all email (catchall), optionally return
temporary/permanent errors, and you can read messages in the webmail.
Localserve enables "pedantic mode", raising errors for non-standard protocol
behaviour.


## Admin web interface

The admin web interface helps admins set up accounts, configure addresses, and
set up new domains (with instructions to create DNS records, and with a check
to see if they are correct). Changes made through the admin web interface
updates the [domains.conf config file](../config/#hdr-domains-conf).

Received DMARC and TLS reports can be viewed, and cached MTA-STS policies
listed.

DMARC evaluations for outgoing DMARC reports, and SMTP (TLS) connection results
for outgoing TLS reports can be viewed, and removed. Suppression lists for
addresses for outgoing reports can be managed as well. Some domains don't
accept reports at the addresses they configure, and send DSNs. The suppression
list helps reduce operational noise.

See [Admin web interface screenshots](../screenshots/#hdr-admin-web-interface).


## Metrics and logging

Mox provides [prometheus metrics](https://prometheus.io/docs/concepts/metric_types/)
for monitoring.  A standard set of application metrics are exposed: Open file
descriptors, memory/cpu usage, etc. Mox also exposes metrics specific to its
internals. See the example
[prometheus rules](https://github.com/mjl-/mox/blob/main/prometheus.rules) in
the repository.

Mox has configurable log levels, per
[functional package](https://pkg.go.dev/github.com/mjl-/mox#section-directories).
Mox logs in structured [logfmt](https://brandur.org/logfmt) format, which is
easy to work with (parse, filter, derive metrics from). Mox also includes three
trace-level logs, for SMTP and IMAP4: trace, traceauth (logs sensitive
authentication data, like passwords), tracedata (logs (bulk) message content).


## Security

Mox aims to be a secure mail server. Many email-security features have been
implemented. Mox comes with a automated test suite, which includes fuzzing. Mox
is written in Go, a modern safer programming language that prevents whole
classes of bugs, or limits their impact.


## Reusable components

Most non-server Go packages mox consists of are written to be reusable Go
packages.

There is no guarantee that there will be no breaking changes. With Go's
dependency versioning approach (minimal version selection), Go code will never
unexpectedly stop compiling. Incompatibilities will show when explicitly
updating a dependency. Making the required changes is typically fairly
straightforward.

Incompatible changes compared to previous releases are tracked in the git
repository, see [apidiff/](https://github.com/mjl-/mox/tree/main/apidiff).
