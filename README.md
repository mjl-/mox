Mox is a modern full-featured open source secure mail server for low-maintenance self-hosted email.

For more details, see the mox website, https://www.xmox.nl.

See Quickstart below to get started.

## Features

- Quick and easy to start/maintain mail server, for your own domain(s).
- SMTP (with extensions) for receiving, submitting and delivering email.
- IMAP4 (with extensions) for giving email clients access to email.
- Webmail for reading/sending email from the browser.
- SPF/DKIM/DMARC for authenticating messages/delivery, also DMARC aggregate
  reports.
- Reputation tracking, learning (per user) host-, domain- and
  sender address-based reputation from (Non-)Junk email classification.
- Bayesian spam filtering that learns (per user) from (Non-)Junk email.
- Slowing down senders with no/low reputation or questionable email content
  (similar to greylisting). Rejected emails are stored in a mailbox called Rejects
  for a short period, helping with misclassified legitimate synchronous
  signup/login/transactional emails.
- Internationalized email, with unicode in email address usernames
  ("localparts"), and in domain names (IDNA).
- Automatic TLS with ACME, for use with Let's Encrypt and other CA's.
- DANE and MTA-STS for inbound and outbound delivery over SMTP with STARTTLS,
  including REQUIRETLS and with incoming/outgoing TLSRPT reporting.
- Web admin interface that helps you set up your domains, accounts and list
  aliases (instructions to create DNS records, configure
  SPF/DKIM/DMARC/TLSRPT/MTA-STS), for status information, and modifying the
  configuration file.
- Account autodiscovery (with SRV records, Microsoft-style, Thunderbird-style,
  and Apple device management profiles) for easy account setup (though client
  support is limited).
- Webserver with serving static files and forwarding requests (reverse
  proxy), so port 443 can also be used to serve websites.
- Simple HTTP/JSON API for sending transaction email and receiving delivery
  events and incoming messages (webapi and webhooks).
- Prometheus metrics and structured logging for operational insight.
- "mox localserve" subcommand for running mox locally for email-related
  testing/developing, including pedantic mode.
- Most non-server Go packages mox consists of are written to be reusable.

Mox is available under the MIT-license and was created by Mechiel Lukkien,
mechiel@ueber.net. Mox includes BSD-3-claused code from the Go Authors, and the
Public Suffix List by Mozilla under Mozilla Public License, v2.0.

Mox has automated tests, including for interoperability with Postfix for SMTP.
Mox is manually tested with email clients: Mozilla Thunderbird, mutt, iOS Mail,
macOS Mail, Android Mail, Microsoft Outlook. Mox is also manually tested to
interoperate with popular cloud providers: gmail.com, outlook.com, yahoo.com,
proton.me.

The code is heavily cross-referenced with the RFCs for readability/maintainability.

# Quickstart

The easiest way to get started with serving email for your domain is to get a
(virtual) machine dedicated to serving email, name it `[host].[domain]` (e.g.
mail.example.com). Having a DNSSEC-verifying resolver installed, such as
unbound, is highly recommended. Run as root:

	# Create mox user and homedir (or pick another name or homedir):
	useradd -m -d /home/mox mox

	cd /home/mox
	... compile or download mox to this directory, see below ...

	# Generate config files for your address/domain:
	./mox quickstart you@example.com

The quickstart:

- Creates configuration files mox.conf and domains.conf.
- Adds the domain and an account for the email address to domains.conf
- Generates an admin and account password.
- Prints the DNS records you need to add, for the machine and domain.
- Prints commands to start mox, and optionally install mox as a service.

A machine that doesn't already run a webserver is highly recommended because
modern email requires HTTPS, and mox currently needs to run a webserver for
automatic TLS with ACME.  You could combine mox with an existing webserver, but
it requires a lot more configuration. If you want to serve websites on the same
machine, consider using the webserver built into mox. It's pretty good! If you
want to run an existing webserver on port 443/80, see `mox help quickstart`.

After starting, you can access the admin web interface on internal IPs.

# Download

Download a mox binary from
https://beta.gobuilds.org/github.com/mjl-/mox@latest/linux-amd64-latest/.

Symlink or rename it to "mox".

The URL above always resolves to the latest release for linux/amd64 built with
the latest Go toolchain.  See the links at the bottom of that page for binaries
for other platforms.

# Compiling

You can easily (cross) compile mox yourself. You need a recent Go toolchain
installed.  Run `go version`, it must be >= 1.21. Download the latest version
from https://go.dev/dl/ or see https://go.dev/doc/manage-install.

To download the source code of the latest release, and compile it to binary "mox":

	GOBIN=$PWD CGO_ENABLED=0 go install github.com/mjl-/mox@latest

Mox only compiles for and fully works on unix systems. Mox also compiles for
Windows, but "mox serve" does not yet work, though "mox localserve" (for a
local test instance) and most other subcommands do. Mox does not compile for
Plan 9.

# Docker

Although not recommended, you can also run mox with docker image
`r.xmox.nl/mox`, with tags like `v0.0.1` and `v0.0.1-go1.20.1-alpine3.17.2`, see
https://r.xmox.nl/r/mox/.  See
https://github.com/mjl-/mox/blob/main/docker-compose.yml to get started.

New docker images aren't (automatically) generated for new Go runtime/compile
releases.

It is important to run with docker host networking, so mox can use the public
IPs and has correct remote IP information for incoming connections (important
for junk filtering and rate-limiting).

# Future/development

See develop.txt for instructions/tips for developing on mox.

Mox will receive funding for essentially full-time continued work from August
2023 to August 2024 through NLnet/EU's NGI0 Entrust, see
https://nlnet.nl/project/Mox/.

## Roadmap

- Calendaring with CalDAV/iCal
- More IMAP extensions (PREVIEW, WITHIN, IMPORTANT, COMPRESS=DEFLATE,
  CREATE-SPECIAL-USE, SAVEDATE, UNAUTHENTICATE, REPLACE, QUOTA, NOTIFY,
  MULTIAPPEND, OBJECTID, MULTISEARCH, THREAD, SORT)
- SMTP DSN extension
- ARC, with forwarded email from trusted source
- Forwarding (to an external address)
- Add special IMAP mailbox ("Queue?") that contains queued but
  undelivered messages, updated with IMAP flags/keywords/tags and message headers.
- External addresses in aliases/lists.
- Autoresponder (out of office/vacation)
- OAUTH2 support, for single sign on
- IMAP extensions for "online"/non-syncing/webmail clients (SORT (including
  DISPLAYFROM, DISPLAYTO), THREAD, PARTIAL, CONTEXT=SEARCH CONTEXT=SORT ESORT,
  FILTERS)
- Improve support for mobile clients with extensions: IMAP URLAUTH, SMTP
  CHUNKING and BINARYMIME, IMAP CATENATE
- Mailing list manager
- Privilege separation, isolating parts of the application to more restricted
  sandbox (e.g. new unauthenticated connections)
- Using mox as backup MX
- JMAP
- Sieve for filtering (for now see Rulesets in the account config)
- Milter support, for integration with external tools
- IMAP Sieve extension, to run Sieve scripts after message changes (not only
  new deliveries)

There are many smaller improvements to make as well, search for "todo" in the code.

## Not supported/planned

There is currently no plan to implement the following. Though this may
change in the future.

- Functioning as SMTP relay
- POP3
- Delivery to (unix) OS system users
- Support for pluggable delivery mechanisms
- iOS Mail push notifications (with XAPPLEPUSHSERVICE undocumented imap
  extension and hard to get APNS certificate)


# FAQ - Frequently Asked Questions

## Why a new mail server implementation?

Mox aims to make "running a mail server" easy and nearly effortless. Excellent
quality (open source) mail server software exists, but getting a working setup
typically requires you configure half a dozen services (SMTP, IMAP,
SPF/DKIM/DMARC, spam filtering), which are often written in C (where small bugs
often have large consequences). That seems to lead to people no longer running
their own mail servers, instead switching to one of the few centralized email
providers. Email with SMTP is a long-time decentralized messaging protocol. To
keep it decentralized, people need to run their own mail server. Mox aims to
make that easy.

## Where is the documentation?

To keep mox as a project maintainable, documentation is integrated into, and
generated from the code.

A list of mox commands, and their help output, are at
https://www.xmox.nl/commands/.

Mox is configured through configuration files, and each field comes with
documentation. See https://www.xmox.nl/config/ for config files containing all
fields and their documentation.

You can get the same information by running "mox" without arguments to list its
subcommands and usage, and "mox help [subcommand]" for more details.

The example config files are printed by "mox config describe-static" and "mox
config describe-dynamic".

If you're missing some documentation, please create an issue describing what is
unclear or confusing, and we'll try to improve the documentation.

## Is Mox affected by SMTP smuggling?

Mox itself is not affected: it only treats "\r\n.\r\n" as SMTP end-of-message.
But read on for caveats.

SMTP smuggling exploits differences in handling by SMTP servers of: carriage
returns (CR, or "\r"), newlines (line feeds, LF, "\n") in the context of "dot
stuffing".  SMTP is a text-based protocol. An SMTP transaction to send a
message is finalized with a "\r\n.\r\n" sequence. This sequence could occur in
the message being transferred, so any verbatim "." at the start of a line in a
message is "escaped" with another dot ("dot stuffing"), to not trigger the SMTP
end-of-message. SMTP smuggling takes advantage of bugs in some mail servers
that interpret other sequences than "\r\n.\r\n" as SMTP end-of-message. For
example "\n.\n" or even "\r.\r", and perhaps even other magic character
combinations.

Before v0.0.9, mox accepted SMTP transactions with bare carriage returns
(without newline) for compatibility with real-world email messages, considering
them meaningless and therefore innocuous.

Since v0.0.9, SMTP transactions with bare carriage returns are rejected.
Sending messages with bare carriage returns to buggy mail servers can cause
those mail servers to materialize non-existent messages. Now that mox rejects
messages with bare carriage returns, sending a message through mox can no
longer be used to trigger those bugs.

Mox can still handle bare carriage returns in email messages, e.g. those
imported from mbox files or Maildirs, or from messages added over IMAP. Mox
still fixes up messages with bare newlines by adding the missing carriage
returns.

Before v0.0.9, an SMTP transaction for a message containing "\n.\n" would
result in a non-specific error message, and "\r\n.\n" would result in the dot
being dropped. Since v0.0.9, these sequences are rejected with a message
mentioning SMTP smuggling.

## How do I import/export email?

Use the import functionality on the accounts web page to import a zip/tgz with
maildirs/mbox files, or use the "mox import maildir" or "mox import mbox"
subcommands. You could also use your IMAP email client, add your mox account,
and copy or move messages from one account to the other.

Similarly, see the export functionality on the accounts web page and the "mox
export maildir" and "mox export mbox" subcommands to export email.

Importing large mailboxes may require a lot of memory (a limitation of the
current database). Splitting up mailboxes in smaller parts (e.g. 100k messages)
would help.

## How can I help?

Mox needs users and testing in real-life setups! So just give it a try, send
and receive emails through it with your favourite email clients, and file an
issue if you encounter a problem or would like to see a feature/functionality
implemented.

Instead of switching email for your domain over to mox, you could simply
configure mox for a subdomain, e.g. [you]@moxtest.[yourdomain].

If you have experience with how the email protocols are used in the wild, e.g.
compatibility issues, limitations, anti-spam measures, specification
violations, that would be interesting to hear about.

Pull requests for bug fixes and new code are welcome too. If the changes are
large, it helps to start a discussion (create an "issue") before doing all the
work. In practice, starting with a small contribution and growing from there has
the highest chance of success.

By contributing (e.g. code), you agree your contributions are licensed under the
MIT license (like mox), and have the rights to do so.

## Where can I discuss mox?

Join #mox on irc.oftc.net, or #mox:matrix.org, or #mox on the "Gopher slack".

For bug reports, please file an issue at https://github.com/mjl-/mox/issues/new.

## How do I change my password?

Regular users (doing IMAP/SMTP with authentication) can change their password
at the account page, e.g. `http://localhost/`. Or you can set a password with "mox
setaccountpassword".

The admin can change the password of any account through the admin page, at
`http://localhost/admin/` by default (leave username empty when logging in).

The account and admin pages are served on localhost for configs created with
the quickstart.  To access these from your browser, run
`ssh -L 8080:localhost:80 you@yourmachine` locally and open
`http://localhost:8080/[...]`.

The admin password can be changed with "mox setadminpassword".

## How do I configure a second mox instance as a backup MX?

Unfortunately, mox does not yet provide an option for that. Mox does spam
filtering based on reputation of received messages. It will take a good amount
of work to share that information with a backup MX. Without that information,
spammers could use a backup MX to get their spam accepted.

Until mox has a proper solution, you can simply run a single SMTP server. The
author has run a single mail server for over a decade without issues. Machines
and network connectivity are stable nowadays, and email delivery will be
retried for many hours during temporary errors (e.g. when rebooting a machine
after updates).

## How do I stay up to date?

Please set "CheckUpdates: true" in mox.conf. Mox will check for a new version
through a DNS TXT request for `_updates.xmox.nl` once per 24h. Only if a new
version is published will the changelog be fetched and delivered to the
postmaster mailbox.

The changelog, including latest update instructions, is at
https://updates.xmox.nl/changelog.

You can also monitor newly added releases on this repository with the github
"watch" feature, or use the github RSS feed for tags
(https://github.com/mjl-/mox/tags.atom) or releases
(https://github.com/mjl-/mox/releases.atom), or monitor the docker images.

Keep in mind you have a responsibility to keep the internet-connected software
you run up to date and secure.

## How do I upgrade my mox installation?

We try to make upgrades effortless and you can typically just put a new binary
in place and restart. If manual actions are required, the release notes mention
them. Check the release notes of all version between your current installation
and the release you're upgrading to.

Before upgrading, make a backup of the data directory with `mox backup
<destdir>`. This writes consistent snapshots of the database files, and
duplicates message files from the outgoing queue and accounts.  Using the new
mox binary, run `mox verifydata <backupdir>` (do NOT use the "live" data
directory!) for a dry run. If this fails, an upgrade will probably fail too.
Important: verifydata with the new mox binary can modify the database files (due
to automatic schema upgrades). So make a fresh backup again before the actual
upgrade. See the help output of the "backup" and "verifydata" commands for more
details.

During backup, message files are hardlinked if possible, and copied otherwise.
Using a destination directory like `data/tmp/backup` increases the odds
hardlinking succeeds: the default mox systemd service file mounts
the data directory separately, so hardlinks to outside the data directory are
cross-device and will fail.

If an upgrade fails and you have to restore (parts) of the data directory, you
should run `mox verifydata <datadir>` (with the original binary) on the
restored directory before starting mox again. If problematic files are found,
for example queue or account message files that are not in the database, run
`mox verifydata -fix <datadir>` to move away those files. After a restore, you may
also want to run `mox bumpuidvalidity <account>` for each account for which
messages in a mailbox changed, to force IMAP clients to synchronize mailbox
state.

## How secure is mox?

Security is high on the priority list for mox. Mox is young, so don't expect no
bugs at all. Mox does have automated tests for some security aspects, e.g. for
login, and uses fuzzing. Mox is written in Go, so some classes of bugs such as
buffer mishandling do not typically result in privilege escalation.  Of course
logic bugs will still exist. If you find any security issues, please email them
to mechiel@ueber.net.

## I'm now running an email server, but how does email work?

Congrats and welcome to the club! Running an email server on the internet comes
with some responsibilities so you should understand how it works. See
https://explained-from-first-principles.com/email/ for a thorough explanation.

## What are the minimum requirements to run mox?

Mox does not need much. Nowadays most machines are larger than mox needs. You
can start with a machine with 512MB RAM, any CPU will do. For storage you
should account for the size of the email messages (no compression currently),
an additional 15% overhead for the meta data, and add some more headroom.
Expand as necessary.

## Won't the big email providers block my email?

It is a common misconception that it is impossible to run your own email server
nowadays. The claim is that the handful big email providers will simply block
your email. However, you can run your own email server just fine, and your
email will be accepted, provided you are doing it right.

If your email is rejected, it is often because your IP address has a bad email
sending reputation. Email servers often use IP blocklists to reject email
networks with a bad email sending reputation. These blocklists often work at
the level of whole network ranges. So if you try to run an email server from a
hosting provider with a bad reputation (which happens if they don't monitor
their network or don't act on abuse/spam reports), your IP too will have a bad
reputation and other mail servers (both large and small) may reject messages
coming from you. During the quickstart, mox checks if your IPs are on a few
often-used blocklists. It's typically not a good idea to host an email server
on the cheapest or largest cloud providers: They often don't spend the
resources necessary for a good reputation, or they simply block all outgoing
SMTP traffic. It's better to look for a technically-focused local provider.
They too may initially block outgoing SMTP connections on new machines to
prevent spam from their networks. But they will either automatically open up
outgoing SMTP traffic after a cool down period (e.g. 24 hours), or after you've
contacted their support.

After you get past the IP blocklist checks, email servers use many more signals
to determine if your email message could be spam and should be rejected. Mox
helps you set up a system that doesn't trigger most of the technical signals
(e.g. with SPF/DKIM/DMARC). But there are more signals, for example: Sending to
a mail server or address for the first time. Sending from a newly registered
domain (especially if you're sending automated messages, and if you send more
messages after previous messages were rejected), domains that existed for a few
weeks to a month are treated more friendly. Sending messages with content that
resembles known spam messages.

Should your email be rejected, you will typically get an error message during
the SMTP transaction that explains why. In the case of big email providers the
error message often has instructions on how to prove to them you are a
legitimate sender.

## Can mox deliver through a smarthost?

Yes, you can configure a "Transport" in mox.conf and configure "Routes" in
domains.conf to send some or all messages through the transport. A transport
can be an SMTP relay or authenticated submission, or making mox make outgoing
connections through a SOCKS proxy.

For an example, see https://www.xmox.nl/config/#hdr-example-transport. For
details about Transports and Routes, see
https://www.xmox.nl/config/#cfg-mox-conf-Transports and
https://www.xmox.nl/config/#cfg-domains-conf-Routes.

Remember to add the IP addresses of the transport to the SPF records of your
domains. Keep in mind some 3rd party submission servers may mishandle your
messages, for example by replacing your Message-Id header and thereby
invalidating your DKIM-signatures, or rejecting messages with more than one
DKIM-signature.

## Can I use mox to send transactional email?

Yes. While you can use SMTP submission to send messages you've composed
yourself, and monitor a mailbox for DSNs, a more convenient option is to use
the mox HTTP/JSON-based webapi and webhooks.

The mox webapi can be used to send outgoing messages that mox composes. The web
api can also be used to deal with messages stored in an account, like changing
message flags, retrieving messages in parsed form or individual parts of
multipart messages, or moving messages to another mailbox or deleting messages
altogether.

Mox webhooks can be used to receive updates about incoming and outgoing
deliveries. Mox can automatically manage per account suppression lists.

See https://www.xmox.nl/features/#hdr-webapi-and-webhooks for details.

## Can I use existing TLS certificates/keys?

Yes. The quickstart command creates a config that uses ACME with Let's Encrypt,
but you can change the config file to use existing certificate and key files.

You'll see "ACME: letsencrypt" in the "TLS" section of the "public" Listener.
Remove or comment out the ACME-line, and add a "KeyCerts" section, see
https://www.xmox.nl/config/#cfg-mox-conf-Listeners-x-TLS-KeyCerts

You can have multiple certificates and keys: The line with the "-" (dash) is
the start of a list item. Duplicate that line up to and including the line with
KeyFile for each certificate/key you have. Mox makes a TLS config that holds
all specified certificates/keys, and uses it for all services for that Listener
(including a webserver), choosing the correct certificate for incoming
requests.

Keep in mind that for each email domain you host, you will need a certificate
for `mta-sts.<domain>`, `autoconfig.<domain>` and `mail.<domain>`, unless you
disable MTA-STS, autoconfig and the client-settings-domain for that domain.

Mox opens the key and certificate files during initial startup, as root (and
passes file descriptors to the unprivileged process).  No special permissions
are needed on the key and certificate files.

## Can I directly access mailboxes through the file system?

No, mox only provides access to email through protocols like IMAP.

While it can be convenient for users/email clients to access email through
conventions like Maildir, providing such access puts quite a burden on the
server: The server has to continuously watch for changes made to the mail store
by external programs, and sync its internal state. By only providing access to
emails through mox, the storage/state management is simpler and easier to
implement reliably.

Not providing direct file system access also allows future improvements in the
storage mechanism. Such as encryption of all stored messages. Programs won't be
able to access such messages directly.

Mox stores metadata about delivered messages in its per-account message index
database, more than fits in a simple (filename-based) format like Maildir. The
IP address of the remote SMTP server during delivery, SPF/DKIM/DMARC domains
and validation status, and more...

For efficiency, mox doesn't prepend message headers generated during delivery
(e.g. Authentication-Results) to the on-disk message file, but only stores it
in the database. This prevents a rewrite of the entire message file. When
reading a message, mox combines the prepended headers from the database with
the message file.

Mox user accounts have no relation to operating system user accounts. Multiple
system users reading their email on a single machine is not very common
anymore. All data (for all accounts) stored by mox is accessible only by the
mox process.  Messages are currently stored as individual files in standard
Internet Message Format (IMF), at `data/accounts/<account>/msg/<dir>/<msgid>`:
`msgid` is a consecutive unique integer id assigned by the per-account message
index database; `dir` groups 8k consecutive message ids into a directory,
ensuring they don't become too large.  The message index database file for an
account is at `data/accounts/<account>/index.db`, accessed with the bstore
database library, which uses bbolt (formerly BoltDB) for storage, a
transactional key/value library/file format inspired by LMDB.
