Mox is a modern full-featured open source secure mail server for low-maintenance self-hosted email.

See Quickstart below to get started.

## Features

- Quick and easy to start/maintain mail server, for your own domain(s).
- SMTP (with extensions) for receiving and submitting email.
- IMAP4 (with extensions) for giving email clients access to email.
- Automatic TLS with ACME, for use with Let's Encrypt and other CA's.
- SPF, verifying that a remote host is allowed to sent email for a domain.
- DKIM, verifying that a message is signed by the claimed sender domain,
  and for signing emails sent by mox for others to verify.
- DMARC, for enforcing SPF/DKIM policies set by domains. Incoming DMARC
  aggregate reports are analyzed.
- Reputation tracking, learning (per user) host- and domain-based reputation from
  (Non-)Junk email.
- Bayesian spam filtering that learns (per user) from (Non-)Junk email.
- Slowing down senders with no/low reputation or questionable email content
  (similar to greylisting). Rejected emails are stored in a mailbox called Rejects
  for a short period, helping with misclassified legitimate synchronous
  signup/login/transactional emails.
- Internationalized email, with unicode names in domains and usernames
  ("localparts").
- TLSRPT, parsing reports about TLS usage and issues.
- MTA-STS, for ensuring TLS is used whenever it is required. Both serving of
  policies, and tracking and applying policies of remote servers.
- Web admin interface that helps you set up your domains and accounts
  (instructions to create DNS records, configure
  SPF/DKIM/DMARC/TLSRPT/MTA-STS), for status information, managing
  accounts/domains, and modifying the configuration file.
- Autodiscovery (with SRV records, Microsoft-style and Thunderbird-style) for
  easy account setup (though not many clients support it).
- Webserver with serving static files and forwarding requests (reverse
  proxy), so port 443 can also be used to serve websites.
- Prometheus metrics and structured logging for operational insight.
- "localserve" subcommand for running mox locally for email-related
  testing/developing, including pedantic mode.

Mox is available under the MIT-license and was created by Mechiel Lukkien,
mechiel@ueber.net. Mox includes the Public Suffix List by Mozilla, under Mozilla
Public License, v2.0.


# Download

You can easily (cross) compile mox if you have a recent Go toolchain installed
(see "go version", it must be >= 1.19; otherwise, see https://go.dev/dl/ or
https://go.dev/doc/manage-install and $HOME/go/bin):

	GOBIN=$PWD CGO_ENABLED=0 go install github.com/mjl-/mox@latest

Or you can download a binary built with the latest Go toolchain from
https://beta.gobuilds.org/github.com/mjl-/mox, and symlink or rename it to
"mox".

Verify you have a working mox binary:

	./mox version

Note: Mox only compiles for/works on unix systems, not on Plan 9 or Windows.

You can also run mox with docker image `r.xmox.nl/mox`, with tags like `v0.0.1`
and `v0.0.1-go1.20.1-alpine3.17.2`, see https://r.xmox.nl/repo/mox/.  See
docker-compose.yml in this repository for instructions on starting. You must run
docker with host networking, because mox needs to find your actual public IP's
and get the remote IPs for incoming connections, not a local/internal NAT IP.


# Quickstart

The easiest way to get started with serving email for your domain is to get a
vm/machine dedicated to serving email, name it [host].[domain] (e.g.
mail.example.com), login as root, and run:

	# Create mox user and homedir (or pick another name or homedir):
	useradd -m -d /home/mox mox

	cd /home/mox
	... compile or download mox to this directory, see above ...

	# Generate config files for your address/domain:
	./mox quickstart you@example.com

The quickstart creates an account, generates a password and configuration
files, prints the DNS records you need to manually create and prints commands
to start mox and optionally install mox as a service.

A dedicated machine is highly recommended because modern email requires HTTPS,
and mox currently needs it for automatic TLS.  You could combine mox with an
existing webserver, but it requires more configuration. If you want to serve
websites on the same machine, consider using the webserver built into mox. If
you want to run an existing webserver on port 443/80, see "mox help quickstart",
it'll tell you to run "./mox quickstart -existing-webserver you@example.com".

After starting, you can access the admin web interface on internal IPs.


# Future/development

Mox has automated tests, including for interoperability with Postfix for SMTP.
Mox is manually tested with email clients: Mozilla Thunderbird, mutt, iOS Mail,
macOS Mail, Android Mail, Microsoft Outlook. Mox is also manually tested to
interoperate with popular cloud providers: gmail.com, outlook.com, yahoo.com,
proton.me.

The code is heavily cross-referenced with the RFCs for readability/maintainability.

## Roadmap

- Rate limiting and spam detection for submitted/outgoing messages, to reduce
  impact when an account gets compromised.
- Privilege separation, isolating parts of the application to more restricted
  sandbox (e.g. new unauthenticated connections).
- DANE and DNSSEC.
- Sending DMARC and TLS reports (currently only receiving).
- OAUTH2 support, for single sign on.
- Add special IMAP mailbox ("Queue?") that contains queued but
  not-yet-delivered messages.
- Sieve for filtering (for now see Rulesets in the account config)
- Calendaring
- IMAP CONDSTORE and QRESYNC extensions
- IMAP THREAD extension
- Using mox as backup MX.
- Old-style internationalization in messages.
- JMAP
- Webmail

There are many smaller improvements to make as well, search for "todo" in the code.

## Not supported

But perhaps in the future...

- HTTP-based API for sending messages and receiving delivery feedback
- Functioning as SMTP relay
- Forwarding (to an external address)
- Autoresponders
- POP3
- Delivery to (unix) OS system users
- PGP or S/MIME
- Mailing list manager
- Support for pluggable delivery mechanisms


# FAQ - Frequently Asked Questions

## Why a new mail server implementation?

Mox aims to make "running a mail server" easy and nearly effortless. Excellent
quality mail server software exists, but getting a working setup typically
requires you configure half a dozen services (SMTP, IMAP, SPF/DKIM/DMARC, spam
filtering). That seems to lead to people no longer running their own mail
servers, instead switching to one of the few centralized email providers. Email
with SMTP is a long-time decentralized messaging protocol. To keep it
decentralized, people need to run their own mail server. Mox aims to make that
easy.

## Where is the documentation?

See all commands and help text at https://pkg.go.dev/github.com/mjl-/mox/, and
example config files at https://pkg.go.dev/github.com/mjl-/mox/config/.

You can get the same information by running "mox" without arguments to list its
subcommands and usage, and "mox help [subcommand]" for more details.

The example config files are printed by "mox config describe-static" and "mox
config describe-dynamic".

Mox is still in early stages, and documentation is still limited. Please create
an issue describing what is unclear or confusing, and we'll try to improve the
documentation.

## How do I import/export email?

Use the import functionality on the accounts web page to import a zip/tgz with
maildirs/mbox files, or use the "mox import maildir" or "mox import mbox"
subcommands. You could also use your IMAP email client, add your mox account,
and copy or move messages from one account to the other.

Similarly, see the export functionality on the accounts web page and the "mox
export maildir" and "mox export mbox" subcommands to export email.

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
large, it helps to start a discussion (create a ticket) before doing all the
work.

By contributing (e.g. code), you agree your contributions are licensed under the
MIT license (like mox), and have the rights to do so.

## Where can I discuss mox?

Join #mox on irc.oftc.net, or #mox on the "Gopher slack".

For bug reports, please file an issue at https://github.com/mjl-/mox/issues/new.

## How do I change my password?

Regular users (doing IMAP/SMTP with authentication) can change their password
at the account page, e.g. http://localhost/. Or you can set a password with "mox
setaccountpassword".

The admin can change the password of any account through the admin page, at
http://localhost/admin/ by default (leave username empty when logging in).

The account and admin pages are served on localhost on your mail server.
To access these from your browser, run
`ssh -L 8080:localhost:80 you@yourmachine` locally and open
http://localhost:8080/[...].

The admin password can be changed with "mox setadminpassword".

## How do I configure a second mox instance as a backup MX?

Unfortunately, mox does not yet provide an option for that. Mox does spam
filtering based on reputation of received messages. It will take a good amount
of work to share that information with a backup MX. Without that information,
spammers could use a backup MX to get their spam accepted. Until mox has a
proper solution, you can simply run a single SMTP server.

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

Keep in mind you have a responsibility to keep the internect-connected software
you run up to date and secure.

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
