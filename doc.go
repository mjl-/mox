/*
Command mox is a modern full-featured open source secure mail server for
low-maintenance self-hosted email.

  - Quick and easy to set up with quickstart and automatic TLS with ACME and
    Let's Encrypt.
  - IMAP4 with extensions for accessing email.
  - SMTP with SPF, DKIM, DMARC, DNSBL, MTA-STS, TLSRPT for exchanging email.
  - Reputation-based and content-based spam filtering.
  - Internationalized email.
  - Admin web interface.

# Commands

	mox [-config mox.conf] ...
	mox serve
	mox quickstart user@domain
	mox restart
	mox stop
	mox setaccountpassword address
	mox setadminpassword
	mox loglevels [level [pkg]]
	mox queue list
	mox queue kick [-id id] [-todomain domain] [-recipient address]
	mox queue drop [-id id] [-todomain domain] [-recipient address]
	mox queue dump id
	mox import maildir accountname mailboxname maildir
	mox import mbox accountname mailboxname mbox
	mox export maildir dst-path account-path [mailbox]
	mox export mbox dst-path account-path [mailbox]
	mox help [command ...]
	mox config test
	mox config dnscheck domain
	mox config dnsrecords domain
	mox config describe-domains >domains.conf
	mox config describe-static >mox.conf
	mox config account add account address
	mox config account rm account
	mox config address add address account
	mox config address rm address
	mox config domain add domain account [localpart]
	mox config domain rm domain
	mox config describe-sendmail >/etc/moxsubmit.conf
	mox checkupdate
	mox cid cid
	mox clientconfig domain
	mox dkim gened25519 >$selector._domainkey.$domain.ed25519key.pkcs8.pem
	mox dkim genrsa >$selector._domainkey.$domain.rsakey.pkcs8.pem
	mox dkim lookup selector domain
	mox dkim txt <$selector._domainkey.$domain.key.pkcs8.pem
	mox dkim verify message
	mox dmarc lookup domain
	mox dmarc parsereportmsg message ...
	mox dmarc verify remoteip mailfromaddress helodomain < message
	mox dnsbl check zone ip
	mox dnsbl checkhealth zone
	mox mtasts lookup domain
	mox sendmail [-Fname] [ignoredflags] [-t] [<message]
	mox spf check domain ip
	mox spf lookup domain
	mox spf parse txtrecord
	mox tlsrpt lookup domain
	mox tlsrpt parsereportmsg message ...
	mox version

Many commands talk to a running mox instance, through the ctl file in the data
directory. Specify the configuration file (that holds the path to the data
directory) through the -config flag or MOXCONF environment variable.

# mox serve

Start mox, serving SMTP/IMAP/HTTPS.

Incoming email is accepted over SMTP. Email can be retrieved by users using
IMAP. HTTP listeners are started for the admin/account web interfaces, and for
automated TLS configuration. Missing essential TLS certificates are immediately
requested, other TLS certificates are requested on demand.

	usage: mox serve

# mox quickstart

Quickstart generates configuration files and prints instructions to quickly set up a mox instance.

Quickstart prints initial admin and account passwords, configuration files, DNS
records you should create, instructions for setting correct user/group and
permissions, and if you run it on Linux it prints a systemd service file.

	usage: mox quickstart user@domain

# mox restart

Restart mox after validating the configuration file.

Restart execs the mox binary, which have been updated. Restart returns after
the restart has finished. If you update the mox binary, keep in mind that the
validation of the configuration file is done by the old process with the old
binary. The new binary may report a syntax error. If you update the binary, you
should use the "config test" command with the new binary to validate the
configuration file.

Like stop, existing connections get a 3 second period for graceful shutdown.

	usage: mox restart

# mox stop

Shut mox down, giving connections maximum 3 seconds to stop before closing them.

While shutting down, new IMAP and SMTP connections will get a status response
indicating temporary unavailability. Existing connections will get a 3 second
period to finish their transaction and shut down. Under normal circumstances,
only IMAP has long-living connections, with the IDLE command to get notified of
new mail deliveries.

	usage: mox stop

# mox setaccountpassword

Set new password an account.

The password is read from stdin. Its bcrypt hash and SCRAM-SHA-256 derivations
are stored in the accounts database.

Any email address configured for the account can be used.

	usage: mox setaccountpassword address

# mox setadminpassword

Set a new admin password, for the web interface.

The password is read from stdin. Its bcrypt hash is stored in a file named
"adminpasswd" in the configuration directory.

	usage: mox setadminpassword

# mox loglevels

Print the log levels, or set a new default log level, or a level for the given package.

By default, a single log level applies to all logging in mox. But for each
"pkg", an overriding log level can be configured. Examples of packages:
smtpserver, smtpclient, queue, imapserver, spf, dkim, dmarc, junk, message,
etc.

Valid labels: error, info, debug, trace.

	usage: mox loglevels [level [pkg]]

# mox queue list

List messages in the delivery queue.

This prints the message with its ID, last and next delivery attempts, last
error.

	usage: mox queue list

# mox queue kick

Schedule matching messages in the queue for immediate delivery.

Messages deliveries are normally attempted with exponential backoff. The first
retry after 7.5 minutes, and doubling each time. Kicking messages sets their
next scheduled attempt to now, it can cause delivery to fail earlier than
without rescheduling.

	usage: mox queue kick [-id id] [-todomain domain] [-recipient address]
	  -id int
	    	id of message in queue
	  -recipient string
	    	recipient email address
	  -todomain string
	    	destination domain of messages

# mox queue drop

Remove matching messages from the queue.

Dangerous operation, this completely removes the message. If you want to store
the message, use "queue dump" before removing.

	usage: mox queue drop [-id id] [-todomain domain] [-recipient address]
	  -id int
	    	id of message in queue
	  -recipient string
	    	recipient email address
	  -todomain string
	    	destination domain of messages

# mox queue dump

Dump a message from the queue.

The message is printed to stdout and is in standard internet mail format.

	usage: mox queue dump id

# mox import maildir

Import a maildir into an account.

By default, messages will train the junk filter based on their flags and
mailbox naming. If the destination mailbox name starts with "junk" or "spam"
(case insensitive), messages are imported and trained as junk regardless of
pre-existing flags. Use the -train=false flag to prevent training the filter.

If the destination mailbox is "Sent", the recipients of the messages are added
to the message metadata, causing later incoming messages from these recipients
to be accepted, unless other reputation signals prevent that.

The message "read"/"seen" flag can be overridden during import with the
-markread flag.

Mailbox flags, like "seen", "answered", "forwarded", will be imported. An
attempt is made to parse dovecot keyword files.

The maildir files/directories are read by the mox process, so make sure it has
access to the maildir directories/files.

	usage: mox import maildir accountname mailboxname maildir
	  -markread
	    	mark all imported messages as read
	  -train
	    	train junkfilter with messages (default true)

# mox import mbox

Import an mbox into an account.

Using mbox is not recommended, maildir is a better format.

By default, messages will train the junk filter based on their flags and
mailbox naming. If the destination mailbox name starts with "junk" or "spam"
(case insensitive), messages are imported and trained as junk regardless of
pre-existing flags. Use the -train=false flag to prevent training the filter.

If the destination mailbox is "Sent", the recipients of the messages are added
to the message metadata, causing later incoming messages from these recipients
to be accepted, unless other reputation signals prevent that.

The message "read"/"seen" flag can be overridden during import with the
-markread flag.

The mailbox is read by the mox process, so make sure it has access to the
maildir directories/files.

	usage: mox import mbox accountname mailboxname mbox
	  -markread
	    	mark all imported messages as read
	  -train
	    	train junkfilter with messages (default true)

# mox export maildir

Export one or all mailboxes from an account in maildir format.

Export bypasses a running mox instance. It opens the account mailbox/message
database file directly. This may block if a running mox instance also has the
database open, e.g. for IMAP connections.

	usage: mox export maildir dst-path account-path [mailbox]

# mox export mbox

Export messages from one or all mailboxes in an account in mbox format.

Using mbox is not recommended. Maildir is a better format.

Export bypasses a running mox instance. It opens the account mailbox/message
database file directly. This may block if a running mox instance also has the
database open, e.g. for IMAP connections.

For mbox export, we use "mboxrd" where message lines starting with the magic
"From " string are escaped by prepending a >. We escape all ">*From ",
otherwise reconstructing the original could lose a ">".

	usage: mox export mbox dst-path account-path [mailbox]

# mox help

Prints help about matching commands.

If multiple commands match, they are listed along with the first line of their help text.
If a single command matches, its usage and full help text is printed.

	usage: mox help [command ...]

# mox config test

Parses and validates the configuration files.

If valid, the command exits with status 0. If not valid, all errors encountered
are printed.

	usage: mox config test

# mox config dnscheck

Check the DNS records with the configuration for the domain, and print any errors/warnings.

	usage: mox config dnscheck domain

# mox config dnsrecords

Prints annotated DNS records as zone file that should be created for the domain.

The zone file can be imported into existing DNS software. You should review the
DNS records, especially if your domain previously/currently has email
configured.

	usage: mox config dnsrecords domain

# mox config describe-domains

Prints an annotated empty configuration for use as domains.conf.

The domains configuration file contains the domains and their configuration,
and accounts and their configuration. This includes the configured email
addresses. The mox admin web interface, and the mox command line interface, can
make changes to this file. Mox automatically reloads this file when it changes.

Like the static configuration, the example domains.conf printed by this command
needs modifications to make it valid.

	usage: mox config describe-domains >domains.conf

# mox config describe-static

Prints an annotated empty configuration for use as mox.conf.

The static configuration file cannot be reloaded while mox is running. Mox has
to be restarted for changes to the static configuration file to take effect.

This configuration file needs modifications to make it valid. For example, it
may contain unfinished list items.

	usage: mox config describe-static >mox.conf

# mox config account add

Add an account with an email address and reload the configuration.

Email can be delivered to this address/account. A password has to be configured
explicitly, see the setaccountpassword command.

	usage: mox config account add account address

# mox config account rm

Remove an account and reload the configuration.

Email addresses for this account will also be removed, and incoming email for
these addresses will be rejected.

	usage: mox config account rm account

# mox config address add

Adds an address to an account and reloads the configuration.

	usage: mox config address add address account

# mox config address rm

Remove an address and reload the configuration.

Incoming email for this address will be rejected.

	usage: mox config address rm address

# mox config domain add

Adds a new domain to the configuration and reloads the configuration.

The account is used for the postmaster mailboxes the domain, including as DMARC and
TLS reporting. Localpart is the "username" at the domain for this account. If
must be set if and only if account does not yet exist.

	usage: mox config domain add domain account [localpart]

# mox config domain rm

Remove a domain from the configuration and reload the configuration.

This is a dangerous operation. Incoming email delivery for this domain will be
rejected.

	usage: mox config domain rm domain

# mox config describe-sendmail

Describe configuration for mox when invoked as sendmail.

	usage: mox config describe-sendmail >/etc/moxsubmit.conf

# mox checkupdate

Check if a newer version of mox is available.

A single DNS TXT lookup to _updates.xmox.nl tells if a new version is
available. If so, a changelog is fetched from https://updates.xmox.nl, and the
individual entries validated with a builtin public key. The changelog is
printed.

	usage: mox checkupdate

# mox cid

Turn an ID from a Received header into a cid, for looking up in logs.

A cid is essentially a connection counter initialized when mox starts. Each log
line contains a cid. Received headers added by mox contain a unique ID that can
be decrypted to a cid by admin of a mox instance only.

	usage: mox cid cid

# mox clientconfig

Print the configuration for email clients for a domain.

Sending email is typically not done on the SMTP port 25, but on submission
ports 465 (with TLS) and 587 (without initial TLS, but usually added to the
connection with STARTTLS). For IMAP, the port with TLS is 993 and without is
143.

Without TLS/STARTTLS, passwords are sent in clear text, which should only be
configured over otherwise secured connections, like a VPN.

	usage: mox clientconfig domain

# mox dkim gened25519

Generate a new ed25519 key for use with DKIM.

Ed25519 keys are much smaller than RSA keys of comparable cryptographic
strength. This is convenient because of maximum DNS message sizes. At the time
of writing, not many mail servers appear to support ed25519 DKIM keys though,
so it is recommended to sign messages with both RSA and ed25519 keys.

	usage: mox dkim gened25519 >$selector._domainkey.$domain.ed25519key.pkcs8.pem

# mox dkim genrsa

Generate a new 2048 bit RSA private key for use with DKIM.

The generated file is in PEM format, and has a comment it is generated for use
with DKIM, by mox.

	usage: mox dkim genrsa >$selector._domainkey.$domain.rsakey.pkcs8.pem

# mox dkim lookup

Lookup and print the DKIM record for the selector at the domain.

	usage: mox dkim lookup selector domain

# mox dkim txt

Print a DKIM DNS TXT record with the public key derived from the private key read from stdin.

The DNS should be configured as a TXT record at $selector._domainkey.$domain.

	usage: mox dkim txt <$selector._domainkey.$domain.key.pkcs8.pem

# mox dkim verify

Verify the DKIM signatures in a message and print the results.

The message is parsed, and the DKIM-Signature headers are validated. Validation
of older messages may fail because the DNS records have been removed or changed
by now, or because the signature header may have specified an expiration time
that was passed.

	usage: mox dkim verify message

# mox dmarc lookup

Lookup dmarc policy for domain, a DNS TXT record at _dmarc.<domain>, validate and print it.

	usage: mox dmarc lookup domain

# mox dmarc parsereportmsg

Parse a DMARC report from an email message, and print its extracted details.

DMARC reports are periodically mailed, if requested in the DMARC DNS record of
a domain. Reports are sent by mail servers that received messages with our
domain in a From header. This may or may not be legatimate email. DMARC reports
contain summaries of evaluations of DMARC and DKIM/SPF, which can help
understand email deliverability problems.

	usage: mox dmarc parsereportmsg message ...

# mox dmarc verify

Parse an email message and evaluate it against the DMARC policy of the domain in the From-header.

mailfromaddress and helodomain are used for SPF validation. If both are empty,
SPF validation is skipped.

mailfromaddress should be the address used as MAIL FROM in the SMTP session.
For DSN messages, that address may be empty. The helo domain was specified at
the beginning of the SMTP transaction that delivered the message. These values
can be found in message headers.

	usage: mox dmarc verify remoteip mailfromaddress helodomain < message

# mox dnsbl check

Test if IP is in the DNS blocklist of the zone, e.g. bl.spamcop.net.

If the IP is in the blocklist, an explanation is printed. This is typically a
URL with more information.

	usage: mox dnsbl check zone ip

# mox dnsbl checkhealth

Check the health of the DNS blocklist represented by zone, e.g. bl.spamcop.net.

The health of a DNS blocklist can be checked by querying for 127.0.0.1 and
127.0.0.2. The second must and the first must not be present.

	usage: mox dnsbl checkhealth zone

# mox mtasts lookup

Lookup the MTASTS record and policy for the domain.

MTA-STS is a mechanism for a domain to specify if it requires TLS connections
for delivering email. If a domain has a valid MTA-STS DNS TXT record at
_mta-sts.<domain> it signals it implements MTA-STS. A policy can then be
fetched at https://mta-sts.<domain>/.well-known/mta-sts.txt. The policy
specifies the mode (enforce, testing, none), which MX servers support TLS and
should be used, and how long the policy can be cached.

	usage: mox mtasts lookup domain

# mox sendmail

Sendmail is a drop-in replacement for /usr/sbin/sendmail to deliver emails sent by unix processes like cron.

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


	usage: mox sendmail [-Fname] [ignoredflags] [-t] [<message]

# mox spf check

Check the status of IP for the policy published in DNS for the domain.

IPs may be allowed to send for a domain, or disallowed, and several shades in
between. If not allowed, an explanation may be provided by the policy. If so,
the explanation is printed. The SPF mechanism that matched (if any) is also
printed.

	usage: mox spf check domain ip

# mox spf lookup

Lookup the SPF record for the domain and print it.

	usage: mox spf lookup domain

# mox spf parse

Parse the record as SPF record. If valid, nothing is printed.

	usage: mox spf parse txtrecord

# mox tlsrpt lookup

Lookup the TLSRPT record for the domain.

A TLSRPT record typically contains an email address where reports about TLS
connectivity should be sent. Mail servers attempting delivery to our domain
should attempt to use TLS. TLSRPT lets them report how many connection
successfully used TLS, and how what kind of errors occurred otherwise.

	usage: mox tlsrpt lookup domain

# mox tlsrpt parsereportmsg

Parse and print the TLSRPT in the message.

The report is printed in formatted JSON.

	usage: mox tlsrpt parsereportmsg message ...

# mox version

Prints this mox version.

	usage: mox version
*/
package main

// NOTE: DO NOT EDIT, this file is generated by gendoc.sh.
