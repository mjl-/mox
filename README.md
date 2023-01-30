Mox is a modern full-featured open source secure mail server for low-maintenance self-hosted email.

See Quickstart below to get started.

Mox features:

- Quick and easy to maintain mail server for your own domain through quickstart.
- SMTP for receiving and submitting email.
- IMAP4 for giving email clients access to email.
- Automatic TLS with ACME, for use with Let's Encrypt and other CA's.
- SPF, verifying that a remote host is allowed to sent email for a domain.
- DKIM, verifying that a message is signed by the claimed sender domain,
  and for signing emails sent by mox for others to verify.
- DMARC, for enforcing SPF/DKIM policies set by domains. Incoming DMARC
  aggregate reports are analyzed.
- Reputation tracking, learning (per user) host- and domain-based reputation from
  (Non-)Junk/Non-Junk email.
- Bayesian spam filtering that learns (per user) from (Non-)Junk email.
- Greylisting of servers with no/low reputation and questionable email content.
  Temporarily refused emails are available over IMAP in a special mailbox for a
  short period, helping with misclassified legimate synchronous
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

Not supported (but perhaps in the future):

- Webmail
- Functioning as SMTP relay
- HTTP-based API for sending messages and receiving delivery feedback
- Forwarding (to an external address)
- Autoresponders
- POP3
- Delivery to (unix) OS system users
- Sieve for filtering
- PGP or S/MIME
- Mailing list manager
- Calendaring
- Support for pluggable delivery mechanisms.

Mox has automated tests, including for interoperability with Postfix for SMTP.

Mox is manually tested with email clients: Mozilla Thunderbird, mutt, iOS Mail,
macOS Mail, Android Mail, Microsoft Outlook.

Mox is also manually tested to interoperate with popular cloud providers:
gmail.com, outlook.com, yahoo.com, proton.me.

Mox is implemented in Go, a modern safe programming language, and has a focus on
security.

Mox is available under the MIT-license.
Mox includes the Public Suffix List by Mozilla, under Mozilla Public License, v. 2.0.

Mox was created by Mechiel Lukkien, mechiel@ueber.net.


# Download

You can easily (cross) compile mox if you have a Go toolchain installed:

	go install github.com/mjl-/mox@latest

Or you can download binaries from https://beta.gobuilds.org/github.com/mjl-/mox


# Quickstart

The easiest way to get started with serving email for your domain is to get a
vm/machine dedicated to serving email named <host>.<domain>, login as an admin
user, e.g. /home/service, download mox, and generate a configuration for your
desired email address at your domain:

	./mox quickstart you@example.com

This creates an accounts, generates a password and configuration files, prints
the DNS records you need to manually add for your domain and prints commands to
set permissions and install as a service.

If you already have email configured for your domain, or if you are already
sending email for your domain from other machines/services, you should modify
the suggested configuration and/or DNS records.

A dedicated machine is convenient because modern email requires HTTPS.  You can
combine mox with an existing webserver, but it requires more configuration.

After starting, you can access the admin web interface on internal IPs.


# FAQ - Frequently Asked Questions

- Why a new mail server implementation?

Mox aims to make "running a mail server" easy and nearly effortless. Excellent
quality mail server software exists, but getting a working setup typically
requires you configure half a dozen services (SMTP, IMAP, SPF/DKIM/DMARC, spam
filtering). That seems to lead to people no longer running their own mail
servers, instead switching to one of the few centralized email providers. SMTP
is long-time distributed messaging protocol. To keep it distributed, people
need to run their own mail server. Mox aims to make that easy.

- Where is the documentation?

See all commands and help text at https://pkg.go.dev/github.com/mjl-/mox/, and
example config files at https://pkg.go.dev/github.com/mjl-/mox/config/.

You can get the same information by running "mox" without arguments to list its
subcommands and usage, and "mox help <subcommand>" for more details.

The example config files are printed by "mox config describe-static" and "mox
config describe-dynamic".

Mox is still in early stages, and documentation is still limited. Please create
an issue describing what is unclear or confusing, and we'll try to improve the
documentation.

- How do I import/export email?

Use the "mox import maildir" or "mox import mbox" subcommands. You could also
use your IMAP email client, add your mox account, and copy or move messages
from one account to the other.

Similarly, see the "mox export maildir" and "mox export mbox" subcommands to
export email.

- How can I help?

Mox needs users and testing in real-life setups! So just give it a try, send
and receive emails through it with your favourite email clients, and file an
issue if you encounter a problem or would like to see a feature/functionality
implemented.

Instead of switching your email for your domain over to mox, you could simply
configure mox for a subdomain, e.g. <you>@moxtest.<yourdomain>.

If you have experience with how the email protocols are used in the wild, e.g.
compatibility issues, limitations, anti-spam measures, specification
violations, that would be interesting to hear about.

Pull requests for bug fixes and new code are welcome too. If the changes are
large, it helps to start a discussion (create a ticket) before doing all the
work.

- How do I change my password?

Regular users (doing IMAP/SMTP with authentication) can change their password
at the account page, e.g. http://127.0.0.1/account/. Or you can set a password
with "mox setaccountpassword".

The admin password can be changed with "mox setadminpassword".

- How do I configure a second mox instance as a backup MX?

Unfortunately, mox does not yet provide an option for that. Mox does spam
filtering based on reputation of received messages. It will take a good amount
of work to share that information with a backup MX. Without that information,
spammer could use a backup MX to get their spam accepted. Until mox has a
proper solution, you can simply run a single SMTP server.

- How secure is mox?

Security is high on the priorit list for mox. Mox is young, so don't expect no
bugs at all. Mox does have automated tests for some security aspects, e.g. for
login, and uses fuzzing. Mox is written in Go, so some classes of bugs such as
buffer mishandling do not typically result in privilege escalation.  Of course
logic bugs will still exist. If you find any security issues, please email them
to mechiel@ueber.net.
