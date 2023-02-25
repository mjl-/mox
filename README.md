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
- Prometheus metrics and structured logging for operational insight.

Mox is available under the MIT-license and was created by Mechiel Lukkien,
mechiel@ueber.net. Mox includes the Public Suffix List by Mozilla, under Mozilla
Public License, v2.0.


# Download

You can easily (cross) compile mox if you have a recent Go toolchain installed
(see "go version", it must be >= 1.19; otherwise, see https://go.dev/dl/ or
https://go.dev/doc/manage-install and $HOME/go/bin):

	GOBIN=$PWD go install github.com/mjl-/mox@latest

Or you can download a binary built with the latest Go toolchain from
https://beta.gobuilds.org/github.com/mjl-/mox, and symlink or rename it to
"mox".

Verify you have a working mox binary:

	./mox version

Note: Mox only compiles/works on unix systems, not on Plan 9 or Windows.

You can also run mox with docker image "moxmail/mox" on hub.docker.com, with
tags like "latest", "0.0.1", etc. See docker-compose.yml in this repository.


# Quickstart

The easiest way to get started with serving email for your domain is to get a
vm/machine dedicated to serving email, name it [host].[domain], login as an
admin user, e.g. /home/service, download mox, and generate a configuration for
your desired email address at your domain:

	./mox quickstart you@example.com

This creates an account, generates a password and configuration files, prints
the DNS records you need to manually create and prints commands to set
permissions and install mox as a service.

If you already have email configured for your domain, or if you are already
sending email for your domain from other machines/services, you should modify
the suggested configuration and/or DNS records.

A dedicated machine is highly recommended because modern email requires HTTPS,
also for automatic TLS.  You can combine mox with an existing webserver, but it
requires more configuration.

After starting, you can access the admin web interface on internal IPs.


# Future/development

Mox has automated tests, including for interoperability with Postfix for SMTP.
Mox is manually tested with email clients: Mozilla Thunderbird, mutt, iOS Mail,
macOS Mail, Android Mail, Microsoft Outlook. Mox is also manually tested to
interoperate with popular cloud providers: gmail.com, outlook.com, yahoo.com,
proton.me.

The code is heavily cross-referenced with the RFCs for readability/maintainability.

## Roadmap

- Strict vs lax mode, defaulting to lax when receiving from the internet, and
  strict when sending.
- "developer server" mode, to easily launch a local SMTP/IMAP server to test
  your apps mail sending capabilities.
- Rate limiting and spam detection for submitted/outgoing messages, to reduce
  impact when an account gets compromised.
- Privilege separation, isolating parts of the application to more restricted
  sandbox (e.g. new unauthenticated connections).
- DANE and DNSSEC.
- Sending DMARC and TLS reports (currently only receiving).
- OAUTH2 support, for single sign on.
- Basic reverse proxy, so port 443 can be used for regular web serving too.
- Using mox as backup MX.
- ACME verification over HTTP (in addition to current tls-alpn01).
- Add special IMAP mailbox ("Queue?") that contains queued but
  not-yet-delivered messages.
- Old-style internationalization in messages.
- Calendaring
- Webmail

There are many smaller improvements to make as well, search for "todo" in the code.

## Not supported

But perhaps in the future...

- Sieve for filtering (for now see Rulesets in the account config)
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

Instead of switching your email for your domain over to mox, you could simply
configure mox for a subdomain, e.g. [you]@moxtest.[yourdomain].

If you have experience with how the email protocols are used in the wild, e.g.
compatibility issues, limitations, anti-spam measures, specification
violations, that would be interesting to hear about.

Pull requests for bug fixes and new code are welcome too. If the changes are
large, it helps to start a discussion (create a ticket) before doing all the
work.

## Where can I discuss mox?

Join #mox on irc.oftc.net, or #mox on the "Gopher slack".

For bug reports, please file an issue at https://github.com/mjl-/mox/issues/new.

## How do I change my password?

Regular users (doing IMAP/SMTP with authentication) can change their password
at the account page, e.g. http://127.0.0.1/. Or you can set a password with "mox
setaccountpassword".

The admin password can be changed with "mox setadminpassword".

## How do I configure a second mox instance as a backup MX?

Unfortunately, mox does not yet provide an option for that. Mox does spam
filtering based on reputation of received messages. It will take a good amount
of work to share that information with a backup MX. Without that information,
spammer could use a backup MX to get their spam accepted. Until mox has a
proper solution, you can simply run a single SMTP server.

## How secure is mox?

Security is high on the priority list for mox. Mox is young, so don't expect no
bugs at all. Mox does have automated tests for some security aspects, e.g. for
login, and uses fuzzing. Mox is written in Go, so some classes of bugs such as
buffer mishandling do not typically result in privilege escalation.  Of course
logic bugs will still exist. If you find any security issues, please email them
to mechiel@ueber.net.
