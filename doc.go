/*
Command mox is a modern, secure, full-featured, open source mail server for
low-maintenance self-hosted email.

Mox is started with the "serve" subcommand, but mox also has many other
subcommands.

Many of those commands talk to a running mox instance, through the ctl file in
the data directory. Specify the configuration file (that holds the path to the
data directory) through the -config flag or MOXCONF environment variable.

Commands that don't talk to a running mox instance are often for
testing/debugging email functionality. For example for parsing an email message,
or looking up SPF/DKIM/DMARC records.

Below is the usage information as printed by the command when started without
any parameters. Followed by the help and usage information for each command.

# Usage

	mox [-config config/mox.conf] [-pedantic] ...
	mox serve
	mox quickstart [-skipdial] [-existing-webserver] [-hostname host] user@domain [user | uid]
	mox stop
	mox setaccountpassword account
	mox setadminpassword
	mox loglevels [level [pkg]]
	mox queue holdrules list
	mox queue holdrules add [ruleflags]
	mox queue holdrules remove ruleid
	mox queue list [filtersortflags]
	mox queue hold [filterflags]
	mox queue unhold [filterflags]
	mox queue schedule [filterflags] [-now] duration
	mox queue transport [filterflags] transport
	mox queue requiretls [filterflags] {yes | no | default}
	mox queue fail [filterflags]
	mox queue drop [filterflags]
	mox queue dump id
	mox queue retired list [filtersortflags]
	mox queue retired print id
	mox queue suppress list [-account account]
	mox queue suppress add account address
	mox queue suppress remove account address
	mox queue suppress lookup [-account account] address
	mox queue webhook list [filtersortflags]
	mox queue webhook schedule [filterflags] duration
	mox queue webhook cancel [filterflags]
	mox queue webhook print id
	mox queue webhook retired list [filtersortflags]
	mox queue webhook retired print id
	mox import maildir accountname mailboxname maildir
	mox import mbox accountname mailboxname mbox
	mox export maildir [-single] dst-dir account-path [mailbox]
	mox export mbox [-single] dst-dir account-path [mailbox]
	mox localserve
	mox help [command ...]
	mox backup destdir
	mox verifydata data-dir
	mox licenses
	mox config test
	mox config dnscheck domain
	mox config dnsrecords domain
	mox config describe-domains >domains.conf
	mox config describe-static >mox.conf
	mox config account list
	mox config account add account address
	mox config account rm account
	mox config account disable account message
	mox config account enable account
	mox config address add address account
	mox config address rm address
	mox config domain add [-disabled] domain account [localpart]
	mox config domain rm domain
	mox config domain disable domain
	mox config domain enable domain
	mox config tlspubkey list [account]
	mox config tlspubkey get fingerprint
	mox config tlspubkey add address [name] < cert.pem
	mox config tlspubkey rm fingerprint
	mox config tlspubkey gen stem
	mox config alias list domain
	mox config alias print alias
	mox config alias add alias@domain rcpt1@domain ...
	mox config alias update alias@domain [-postpublic false|true -listmembers false|true -allowmsgfrom false|true]
	mox config alias rm alias@domain
	mox config alias addaddr alias@domain rcpt1@domain ...
	mox config alias rmaddr alias@domain rcpt1@domain ...
	mox config describe-sendmail >/etc/moxsubmit.conf
	mox config printservice >mox.service
	mox config ensureacmehostprivatekeys
	mox config example [name]
	mox admin imapserve preauth-address
	mox checkupdate
	mox cid cid
	mox clientconfig domain
	mox dane dial host:port
	mox dane dialmx domain [destination-host]
	mox dane makerecord usage selector matchtype [certificate.pem | publickey.pem | privatekey.pem]
	mox dns lookup [ptr | mx | cname | ips | a | aaaa | ns | txt | srv | tlsa] name
	mox dkim gened25519 >$selector._domainkey.$domain.ed25519.privatekey.pkcs8.pem
	mox dkim genrsa >$selector._domainkey.$domain.rsa2048.privatekey.pkcs8.pem
	mox dkim lookup selector domain
	mox dkim txt <$selector._domainkey.$domain.key.pkcs8.pem
	mox dkim verify message
	mox dkim sign message
	mox dmarc lookup domain
	mox dmarc parsereportmsg message ...
	mox dmarc verify remoteip mailfromaddress helodomain < message
	mox dmarc checkreportaddrs domain
	mox dnsbl check zone ip
	mox dnsbl checkhealth zone
	mox mtasts lookup domain
	mox rdap domainage domain
	mox retrain [accountname]
	mox sendmail [-Fname] [ignoredflags] [-t] [<message]
	mox smtp dial host[:port]
	mox spf check domain ip
	mox spf lookup domain
	mox spf parse txtrecord
	mox tlsrpt lookup domain
	mox tlsrpt parsereportmsg message ...
	mox version
	mox webapi [method [baseurl-with-credentials]
	mox example [name]
	mox bumpuidvalidity account [mailbox]
	mox reassignuids account [mailboxid]
	mox fixuidmeta account
	mox fixmsgsize [account]
	mox reparse [account]
	mox ensureparsed account
	mox recalculatemailboxcounts account
	mox message parse message.eml
	mox reassignthreads [account]

# mox serve

Start mox, serving SMTP/IMAP/HTTPS.

Incoming email is accepted over SMTP. Email can be retrieved by users using
IMAP. HTTP listeners are started for the admin/account web interfaces, and for
automated TLS configuration. Missing essential TLS certificates are immediately
requested, other TLS certificates are requested on demand.

Only implemented on unix systems, not Windows.

	usage: mox serve

# mox quickstart

Quickstart generates configuration files and prints instructions to quickly set up a mox instance.

Quickstart writes configuration files, prints initial admin and account
passwords, DNS records you should create. If you run it on Linux it writes a
systemd service file and prints commands to enable and start mox as service.

All output is written to quickstart.log for later reference.

The user or uid is optional, defaults to "mox", and is the user or uid/gid mox
will run as after initialization.

Quickstart assumes mox will run on the machine you run quickstart on and uses
its host name and public IPs. On many systems the hostname is not a fully
qualified domain name, but only the first dns "label", e.g. "mail" in case of
"mail.example.org". If so, quickstart does a reverse DNS lookup to find the
hostname, and as fallback uses the label plus the domain of the email address
you specified. Use flag -hostname to explicitly specify the hostname mox will
run on.

Mox is by far easiest to operate if you let it listen on port 443 (HTTPS) and
80 (HTTP). TLS will be fully automatic with ACME with Let's Encrypt.

You can run mox along with an existing webserver, but because of MTA-STS and
autoconfig, you'll need to forward HTTPS traffic for two domains to mox. Run
"mox quickstart -existing-webserver ..." to generate configuration files and
instructions for configuring mox along with an existing webserver.

But please first consider configuring mox on port 443. It can itself serve
domains with HTTP/HTTPS, including with automatic TLS with ACME, is easily
configured through both configuration files and admin web interface, and can act
as a reverse proxy (and static file server for that matter), so you can forward
traffic to your existing backend applications. Look for "WebHandlers:" in the
output of "mox config describe-domains" and see the output of
"mox config example webhandlers".

	usage: mox quickstart [-skipdial] [-existing-webserver] [-hostname host] user@domain [user | uid]
	  -existing-webserver
	    	use if a webserver is already running, so mox won't listen on port 80 and 443; you'll have to provide tls certificates/keys, and configure the existing webserver as reverse proxy, forwarding requests to mox.
	  -hostname string
	    	hostname mox will run on, by default the hostname of the machine quickstart runs on; if specified, the IPs for the hostname are configured for the public listener
	  -skipdial
	    	skip check for outgoing smtp (port 25) connectivity or for domain age with rdap

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

The password is read from stdin. Secrets derived from the password, but not the
password itself, are stored in the account database. The stored secrets are for
authentication with: scram-sha-256, scram-sha-1, cram-md5, plain text (bcrypt
hash).

The parameter is an account name, as configured under Accounts in domains.conf
and as present in the data/accounts/ directory, not a configured email address
for an account.

	usage: mox setaccountpassword account

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

Specify a pkg and an empty level to clear the configured level for a package.

Valid labels: error, info, debug, trace, traceauth, tracedata.

	usage: mox loglevels [level [pkg]]

# mox queue holdrules list

List hold rules for the delivery queue.

Messages submitted to the queue that match a hold rule will be marked as on hold
and not scheduled for delivery.

	usage: mox queue holdrules list

# mox queue holdrules add

Add hold rule for the delivery queue.

Add a hold rule to mark matching newly submitted messages as on hold. Set the
matching rules with the flags. Don't specify any flags to match all submitted
messages.

	usage: mox queue holdrules add [ruleflags]
	  -account string
	    	account submitting the message
	  -recipientdom string
	    	recipient domain
	  -senderdom string
	    	sender domain

# mox queue holdrules remove

Remove hold rule for the delivery queue.

Remove a hold rule by its id.

	usage: mox queue holdrules remove ruleid

# mox queue list

List matching messages in the delivery queue.

Prints the message with its ID, last and next delivery attempts, last error.

	usage: mox queue list [filtersortflags]
	  -account string
	    	account that queued the message
	  -asc
	    	sort ascending instead of descending (default)
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -hold value
	    	true or false, whether to match only messages that are (not) on hold
	  -ids value
	    	comma-separated list of message IDs
	  -n int
	    	number of messages to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -sort value
	    	field to sort by, "nextattempt" (default) or "queued"
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue hold

Mark matching messages on hold.

Messages that are on hold are not delivered until marked as off hold again, or
otherwise handled by the admin.

	usage: mox queue hold [filterflags]
	  -account string
	    	account that queued the message
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -hold value
	    	true or false, whether to match only messages that are (not) on hold
	  -ids value
	    	comma-separated list of message IDs
	  -n int
	    	number of messages to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue unhold

Mark matching messages off hold.

Once off hold, messages can be delivered according to their current next
delivery attempt. See the "queue schedule" command.

	usage: mox queue unhold [filterflags]
	  -account string
	    	account that queued the message
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -hold value
	    	true or false, whether to match only messages that are (not) on hold
	  -ids value
	    	comma-separated list of message IDs
	  -n int
	    	number of messages to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue schedule

Change next delivery attempt for matching messages.

The next delivery attempt is adjusted by the duration parameter. If the -now
flag is set, the new delivery attempt is set to the duration added to the
current time, instead of added to the current scheduled time.

Schedule immediate delivery with "mox queue schedule -now 0".

	usage: mox queue schedule [filterflags] [-now] duration
	  -account string
	    	account that queued the message
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -hold value
	    	true or false, whether to match only messages that are (not) on hold
	  -ids value
	    	comma-separated list of message IDs
	  -n int
	    	number of messages to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -now
	    	schedule for duration relative to current time instead of relative to current next delivery attempt for messages
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue transport

Set transport for matching messages.

By default, the routing rules determine how a message is delivered. The default
and common case is direct delivery with SMTP. Messages can get a previously
configured transport assigned to use for delivery, e.g. using submission to
another mail server or with connections over a SOCKS proxy.

	usage: mox queue transport [filterflags] transport
	  -account string
	    	account that queued the message
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -hold value
	    	true or false, whether to match only messages that are (not) on hold
	  -ids value
	    	comma-separated list of message IDs
	  -n int
	    	number of messages to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue requiretls

Set TLS requirements for delivery of matching messages.

Value "yes" is handled as if the RequireTLS extension was specified during
submission.

Value "no" is handled as if the message has a header "TLS-Required: No". This
header is not added by the queue. If messages without this header are relayed
through other mail servers they will apply their own default TLS policy.

Value "default" is the default behaviour, currently for unverified opportunistic
TLS.

	usage: mox queue requiretls [filterflags] {yes | no | default}
	  -account string
	    	account that queued the message
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -hold value
	    	true or false, whether to match only messages that are (not) on hold
	  -ids value
	    	comma-separated list of message IDs
	  -n int
	    	number of messages to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue fail

Fail delivery of matching messages, delivering DSNs.

Failing a message is handled similar to how delivery is given up after all
delivery attempts failed. The DSN (delivery status notification) message
contains a line saying the message was canceled by the admin.

	usage: mox queue fail [filterflags]
	  -account string
	    	account that queued the message
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -hold value
	    	true or false, whether to match only messages that are (not) on hold
	  -ids value
	    	comma-separated list of message IDs
	  -n int
	    	number of messages to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue drop

Remove matching messages from the queue.

Dangerous operation, this completely removes the message. If you want to store
the message, use "queue dump" before removing.

	usage: mox queue drop [filterflags]
	  -account string
	    	account that queued the message
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -hold value
	    	true or false, whether to match only messages that are (not) on hold
	  -ids value
	    	comma-separated list of message IDs
	  -n int
	    	number of messages to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue dump

Dump a message from the queue.

The message is printed to stdout and is in standard internet mail format.

	usage: mox queue dump id

# mox queue retired list

List matching messages in the retired queue.

Prints messages with their ID and results.

	usage: mox queue retired list [filtersortflags]
	  -account string
	    	account that queued the message
	  -asc
	    	sort ascending instead of descending (default)
	  -from string
	    	from address of message, use "@example.com" to match all messages for a domain
	  -ids value
	    	comma-separated list of retired message IDs
	  -lastactivity string
	    	filter by time of last activity relative to now, value must start with "<" (before now) or ">" (after now)
	  -n int
	    	number of messages to return
	  -result value
	    	"success" or "failure" as result of delivery
	  -sort value
	    	field to sort by, "lastactivity" (default) or "queued"
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)
	  -to string
	    	recipient address of message, use "@example.com" to match all messages for a domain
	  -transport value
	    	transport to use for messages, empty string sets the default behaviour

# mox queue retired print

Print a message from the retired queue.

Prints a JSON representation of the information from the retired queue.

	usage: mox queue retired print id

# mox queue suppress list

Print addresses in suppression list.

	usage: mox queue suppress list [-account account]
	  -account string
	    	only show suppression list for this account

# mox queue suppress add

Add address to suppression list for account.

	usage: mox queue suppress add account address

# mox queue suppress remove

Remove address from suppression list for account.

	usage: mox queue suppress remove account address

# mox queue suppress lookup

Check if address is present in suppression list, for any or specific account.

	usage: mox queue suppress lookup [-account account] address
	  -account string
	    	only check address in specified account

# mox queue webhook list

List matching webhooks in the queue.

Prints list of webhooks, their IDs and basic information.

	usage: mox queue webhook list [filtersortflags]
	  -account string
	    	account that queued the message/webhook
	  -asc
	    	sort ascending instead of descending (default)
	  -event value
	    	event this webhook is about: incoming, delivered, suppressed, delayed, failed, relayed, expanded, canceled, unrecognized
	  -ids value
	    	comma-separated list of webhook IDs
	  -n int
	    	number of webhooks to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -sort value
	    	field to sort by, "nextattempt" (default) or "queued"
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)

# mox queue webhook schedule

Change next delivery attempt for matching webhooks.

The next delivery attempt is adjusted by the duration parameter. If the -now
flag is set, the new delivery attempt is set to the duration added to the
current time, instead of added to the current scheduled time.

Schedule immediate delivery with "mox queue schedule -now 0".

	usage: mox queue webhook schedule [filterflags] duration
	  -account string
	    	account that queued the message/webhook
	  -event value
	    	event this webhook is about: incoming, delivered, suppressed, delayed, failed, relayed, expanded, canceled, unrecognized
	  -ids value
	    	comma-separated list of webhook IDs
	  -n int
	    	number of webhooks to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -now
	    	schedule for duration relative to current time instead of relative to current next delivery attempt for webhooks
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)

# mox queue webhook cancel

Fail delivery of matching webhooks.

	usage: mox queue webhook cancel [filterflags]
	  -account string
	    	account that queued the message/webhook
	  -event value
	    	event this webhook is about: incoming, delivered, suppressed, delayed, failed, relayed, expanded, canceled, unrecognized
	  -ids value
	    	comma-separated list of webhook IDs
	  -n int
	    	number of webhooks to return
	  -nextattempt string
	    	filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)

# mox queue webhook print

Print details of a webhook from the queue.

The webhook is printed to stdout as JSON.

	usage: mox queue webhook print id

# mox queue webhook retired list

List matching webhooks in the retired queue.

Prints list of retired webhooks, their IDs and basic information.

	usage: mox queue webhook retired list [filtersortflags]
	  -account string
	    	account that queued the message/webhook
	  -asc
	    	sort ascending instead of descending (default)
	  -event value
	    	event this webhook is about: incoming, delivered, suppressed, delayed, failed, relayed, expanded, canceled, unrecognized
	  -ids value
	    	comma-separated list of retired webhook IDs
	  -lastactivity string
	    	filter by time of last activity relative to now, value must start with "<" (before now) or ">" (after now)
	  -n int
	    	number of webhooks to return
	  -sort value
	    	field to sort by, "lastactivity" (default) or "queued"
	  -submitted string
	    	filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)

# mox queue webhook retired print

Print details of a webhook from the retired queue.

The retired webhook is printed to stdout as JSON.

	usage: mox queue webhook retired print id

# mox import maildir

Import a maildir into an account.

The mbox/maildir archive is accessed and imported by the running mox process, so
it must have access to the archive files. The default suggested systemd service
file isolates mox from most of the file system, with only the "data/" directory
accessible, so you may want to put the mbox/maildir archive files in a
directory like "data/import/" to make it available to mox.

By default, messages will train the junk filter based on their flags and, if
"automatic junk flags" configuration is set, based on mailbox naming.

If the destination mailbox is the Sent mailbox, the recipients of the messages
are added to the message metadata, causing later incoming messages from these
recipients to be accepted, unless other reputation signals prevent that.

Users can also import mailboxes/messages through the account web page by
uploading a zip or tgz file with mbox and/or maildirs.

Messages are imported even if already present. Importing messages twice will
result in duplicate messages.

Mailbox flags, like "seen", "answered", will be imported. An optional
dovecot-keywords file can specify additional flags, like Forwarded/Junk/NotJunk.

	usage: mox import maildir accountname mailboxname maildir

# mox import mbox

Import an mbox into an account.

Using mbox is not recommended, maildir is a better defined format.

The mbox/maildir archive is accessed and imported by the running mox process, so
it must have access to the archive files. The default suggested systemd service
file isolates mox from most of the file system, with only the "data/" directory
accessible, so you may want to put the mbox/maildir archive files in a
directory like "data/import/" to make it available to mox.

By default, messages will train the junk filter based on their flags and, if
"automatic junk flags" configuration is set, based on mailbox naming.

If the destination mailbox is the Sent mailbox, the recipients of the messages
are added to the message metadata, causing later incoming messages from these
recipients to be accepted, unless other reputation signals prevent that.

Users can also import mailboxes/messages through the account web page by
uploading a zip or tgz file with mbox and/or maildirs.

Messages are imported even if already present. Importing messages twice will
result in duplicate messages.

	usage: mox import mbox accountname mailboxname mbox

# mox export maildir

Export one or all mailboxes from an account in maildir format.

Export bypasses a running mox instance. It opens the account mailbox/message
database file directly. This may block if a running mox instance also has the
database open, e.g. for IMAP connections. To export from a running instance, use
the accounts web page or webmail.

	usage: mox export maildir [-single] dst-dir account-path [mailbox]
	  -single
	    	export single mailbox, without any children. disabled if mailbox isn't specified.

# mox export mbox

Export messages from one or all mailboxes in an account in mbox format.

Using mbox is not recommended. Maildir is a better format.

Export bypasses a running mox instance. It opens the account mailbox/message
database file directly. This may block if a running mox instance also has the
database open, e.g. for IMAP connections. To export from a running instance, use
the accounts web page or webmail.

For mbox export, "mboxrd" is used where message lines starting with the magic
"From " string are escaped by prepending a >. All ">*From " are escaped,
otherwise reconstructing the original could lose a ">".

	usage: mox export mbox [-single] dst-dir account-path [mailbox]
	  -single
	    	export single mailbox, without any children. disabled if mailbox isn't specified.

# mox localserve

Start a local SMTP/IMAP server that accepts all messages, useful when testing/developing software that sends email.

Localserve starts mox with a configuration suitable for local email-related
software development/testing. It listens for SMTP/Submission(s), IMAP(s) and
HTTP(s), on the regular port numbers + 1000.

Data is stored in the system user's configuration directory under
"mox-localserve", e.g. $HOME/.config/mox-localserve/ on linux, but can be
overridden with the -dir flag. If the directory does not yet exist, it is
automatically initialized with configuration files, an account with email
address mox@localhost and password moxmoxmox, and a newly generated self-signed
TLS certificate.

Incoming messages are delivered as normal, falling back to accepting and
delivering to the mox account for unknown addresses.
Submitted messages are added to the queue, which delivers by ignoring the
destination servers, always connecting to itself instead.

Recipient addresses with the following localpart suffixes are handled specially:

- "temperror": fail with a temporary error code
- "permerror": fail with a permanent error code
- [45][0-9][0-9]: fail with the specific error code
- "timeout": no response (for an hour)

If the localpart begins with "mailfrom" or "rcptto", the error is returned
during those commands instead of during "data".

	usage: mox localserve
	  -dir string
	    	configuration storage directory (default "$userconfigdir/mox-localserve")
	  -initonly
	    	write configuration files and exit
	  -ip string
	    	serve on this ip instead of default 127.0.0.1 and ::1. only used when writing configuration, at first launch.

# mox help

Prints help about matching commands.

If multiple commands match, they are listed along with the first line of their help text.
If a single command matches, its usage and full help text is printed.

	usage: mox help [command ...]

# mox backup

Creates a backup of the config and data directory.

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

	usage: mox backup destdir
	  -verbose
	    	print progress

# mox verifydata

Verify the contents of a data directory, typically of a backup.

Verifydata checks all database files to see if they are valid BoltDB/bstore
databases. It checks that all messages in the database have a corresponding
on-disk message file and there are no unrecognized files. If option -fix is
specified, unrecognized message files are moved away. This may be needed after
a restore, because messages enqueued or delivered in the future may get those
message sequence numbers assigned and writing the message file would fail.
Consistency of message/mailbox UID, UIDNEXT and UIDVALIDITY is verified as
well.

Because verifydata opens the database files, schema upgrades may automatically
be applied. This can happen if you use a new mox release. It is useful to run
"mox verifydata" with a new binary before attempting an upgrade, but only on a
copy of the database files, as made with "mox backup". Before upgrading, make a
new backup again since "mox verifydata" may have upgraded the database files,
possibly making them potentially no longer readable by the previous version.

	usage: mox verifydata data-dir
	  -fix
	    	fix fixable problems, such as moving away message files not referenced by their database
	  -skip-size-check
	    	skip the check for message size

# mox licenses

Print licenses of mox source code and dependencies.

	usage: mox licenses

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

# mox config account list

List all accounts.

Each account is printed on a line, with optional additional tab-separated
information, such as "(disabled)".

	usage: mox config account list

# mox config account add

Add an account with an email address and reload the configuration.

Email can be delivered to this address/account. A password has to be configured
explicitly, see the setaccountpassword command.

	usage: mox config account add account address

# mox config account rm

Remove an account and reload the configuration.

Email addresses for this account will also be removed, and incoming email for
these addresses will be rejected.

All data for the account will be removed.

	usage: mox config account rm account

# mox config account disable

Disable login for an account, showing message to users when they try to login.

Incoming email will still be accepted for the account, and queued email from the
account will still be delivered. No new login sessions are possible.

Message must be non-empty, ascii-only without control characters including
newline, and maximum 256 characters because it is used in SMTP/IMAP.

	usage: mox config account disable account message

# mox config account enable

Enable login again for an account.

Login attempts by the user no long result in an error message.

	usage: mox config account enable account

# mox config address add

Adds an address to an account and reloads the configuration.

If address starts with a @ (i.e. a missing localpart), this is a catchall
address for the domain.

	usage: mox config address add address account

# mox config address rm

Remove an address and reload the configuration.

Incoming email for this address will be rejected after removing an address.

	usage: mox config address rm address

# mox config domain add

Adds a new domain to the configuration and reloads the configuration.

The account is used for the postmaster mailboxes the domain, including as DMARC and
TLS reporting. Localpart is the "username" at the domain for this account. If
must be set if and only if account does not yet exist.

The domain can be created in disabled mode, preventing automatically requesting
TLS certificates with ACME, and rejecting incoming/outgoing messages involving
the domain, but allowing further configuration of the domain.

	usage: mox config domain add [-disabled] domain account [localpart]
	  -disabled
	    	disable the new domain

# mox config domain rm

Remove a domain from the configuration and reload the configuration.

This is a dangerous operation. Incoming email delivery for this domain will be
rejected.

	usage: mox config domain rm domain

# mox config domain disable

Disable a domain and reload the configuration.

This is a dangerous operation. Incoming/outgoing messages involving this domain
will be rejected.

	usage: mox config domain disable domain

# mox config domain enable

Enable a domain and reload the configuration.

Incoming/outgoing messages involving this domain will be accepted again.

	usage: mox config domain enable domain

# mox config tlspubkey list

List TLS public keys for TLS client certificate authentication.

If account is absent, the TLS public keys for all accounts are listed.

	usage: mox config tlspubkey list [account]

# mox config tlspubkey get

Get a TLS public key for a fingerprint.

Prints the type, name, account and address for the key, and the certificate in
PEM format.

	usage: mox config tlspubkey get fingerprint

# mox config tlspubkey add

Add a TLS public key to the account of the given address.

The public key is read from the certificate.

The optional name is a human-readable descriptive name of the key. If absent,
the CommonName from the certificate is used.

	usage: mox config tlspubkey add address [name] < cert.pem
	  -no-imap-preauth
	    	Don't automatically switch new IMAP connections authenticated with this key to "authenticated" state after the TLS handshake. For working around clients that ignore the untagged IMAP PREAUTH response and try to authenticate while already authenticated.

# mox config tlspubkey rm

Remove TLS public key for fingerprint.

	usage: mox config tlspubkey rm fingerprint

# mox config tlspubkey gen

Generate an ed25519 private key and minimal certificate for use a TLS public key and write to files starting with stem.

The private key is written to $stem.$timestamp.ed25519privatekey.pkcs8.pem.
The certificate is written to $stem.$timestamp.certificate.pem.
The private key and certificate are also written to
$stem.$timestamp.ed25519privatekey-certificate.pem.

The certificate can be added to an account with "mox config account tlspubkey add".

The combined file can be used with "mox sendmail".

The private key is also written to standard error in raw-url-base64-encoded
form, also for use with "mox sendmail". The fingerprint is written to standard
error too, for reference.

	usage: mox config tlspubkey gen stem

# mox config alias list

Show aliases (lists) for domain.

	usage: mox config alias list domain

# mox config alias print

Print settings and members of alias (list).

	usage: mox config alias print alias

# mox config alias add

Add new alias (list) with one or more addresses and public posting enabled.

An alias is used for delivering incoming email to multiple recipients. If you
want to add an address to an account, don't use an alias, just add the address
to the account.

	usage: mox config alias add alias@domain rcpt1@domain ...

# mox config alias update

Update alias (list) configuration.

	usage: mox config alias update alias@domain [-postpublic false|true -listmembers false|true -allowmsgfrom false|true]
	  -allowmsgfrom string
	    	whether alias address can be used in message from header
	  -listmembers string
	    	whether list members can list members
	  -postpublic string
	    	whether anyone or only list members can post

# mox config alias rm

Remove alias (list).

	usage: mox config alias rm alias@domain

# mox config alias addaddr

Add addresses to alias (list).

	usage: mox config alias addaddr alias@domain rcpt1@domain ...

# mox config alias rmaddr

Remove addresses from alias (list).

	usage: mox config alias rmaddr alias@domain rcpt1@domain ...

# mox config describe-sendmail

Describe configuration for mox when invoked as sendmail.

	usage: mox config describe-sendmail >/etc/moxsubmit.conf

# mox config printservice

Prints a systemd unit service file for mox.

This is the same file as generated using quickstart. If the systemd service file
has changed with a newer version of mox, use this command to generate an up to
date version.

	usage: mox config printservice >mox.service

# mox config ensureacmehostprivatekeys

Ensure host private keys exist for TLS listeners with ACME.

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

	usage: mox config ensureacmehostprivatekeys

# mox config example

List available config examples, or print a specific example.

	usage: mox config example [name]

# mox admin imapserve

Initiate a preauthenticated IMAP connection on file descriptor 0.

For use with tools that can do IMAP over tunneled connections, e.g. with SSH
during migrations. TLS is not possible on the connection, and authentication
does not require TLS.

	usage: mox admin imapserve preauth-address
	  -fd0
	    	write IMAP to file descriptor 0 instead of stdout

# mox checkupdate

Check if a newer version of mox is available.

A single DNS TXT lookup to _updates.xmox.nl tells if a new version is
available. If so, a changelog is fetched from https://updates.xmox.nl, and the
individual entries verified with a builtin public key. The changelog is
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

# mox dane dial

Dial the address using TLS with certificate verification using DANE.

Data is copied between connection and stdin/stdout until either side closes the
connection.

	usage: mox dane dial host:port
	  -usages string
	    	allowed usages for dane, comma-separated list (default "pkix-ta,pkix-ee,dane-ta,dane-ee")

# mox dane dialmx

Connect to MX server for domain using STARTTLS verified with DANE.

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

	usage: mox dane dialmx domain [destination-host]
	  -ehlohostname string
	    	hostname to send in smtp ehlo command (default "localhost")

# mox dane makerecord

Print TLSA record for given certificate/key and parameters.

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

	usage: mox dane makerecord usage selector matchtype [certificate.pem | publickey.pem | privatekey.pem]

# mox dns lookup

Lookup DNS name of given type.

Lookup always prints whether the response was DNSSEC-protected.

Examples:

mox dns lookup ptr 1.1.1.1
mox dns lookup mx xmox.nl
mox dns lookup txt _dmarc.xmox.nl.
mox dns lookup tlsa _25._tcp.xmox.nl

	usage: mox dns lookup [ptr | mx | cname | ips | a | aaaa | ns | txt | srv | tlsa] name

# mox dkim gened25519

Generate a new ed25519 key for use with DKIM.

Ed25519 keys are much smaller than RSA keys of comparable cryptographic
strength. This is convenient because of maximum DNS message sizes. At the time
of writing, not many mail servers appear to support ed25519 DKIM keys though,
so it is recommended to sign messages with both RSA and ed25519 keys.

	usage: mox dkim gened25519 >$selector._domainkey.$domain.ed25519.privatekey.pkcs8.pem

# mox dkim genrsa

Generate a new 2048 bit RSA private key for use with DKIM.

The generated file is in PEM format, and has a comment it is generated for use
with DKIM, by mox.

	usage: mox dkim genrsa >$selector._domainkey.$domain.rsa2048.privatekey.pkcs8.pem

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

# mox dkim sign

Sign a message, adding DKIM-Signature headers based on the domain in the From header.

The message is parsed, the domain looked up in the configuration files, and
DKIM-Signature headers generated. The message is printed with the DKIM-Signature
headers prepended.

	usage: mox dkim sign message

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

# mox dmarc checkreportaddrs

For each reporting address in the domain's DMARC record, check if it has opted into receiving reports (if needed).

A DMARC record can request reports about DMARC evaluations to be sent to an
email/http address. If the organizational domains of that of the DMARC record
and that of the report destination address do not match, the destination
address must opt-in to receiving DMARC reports by creating a DMARC record at
<dmarcdomain>._report._dmarc.<reportdestdomain>.

	usage: mox dmarc checkreportaddrs domain

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

# mox rdap domainage

Lookup the age of domain in RDAP based on latest registration.

RDAP is the registration data access protocol. Registries run RDAP services for
their top level domains, providing information such as the registration date of
domains. This command looks up the "age" of a domain by looking at the most
recent "registration", "reregistration" or "reinstantiation" event.

Email messages from recently registered domains are often treated with
suspicion, and some mail systems are more likely to classify them as junk.

On each invocation, a bootstrap file with a list of registries (of top-level
domains) is retrieved, without caching. Do not run this command too often with
automation.

	usage: mox rdap domainage domain

# mox retrain

Recreate and retrain the junk filter for the account or all accounts.

Useful after having made changes to the junk filter configuration, or if the
implementation has changed.

	usage: mox retrain [accountname]

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
implementations. A single recipient or the -t flag with a To-header is required.
With the -t flag, Cc and Bcc headers are not handled specially, so Bcc is not
removed and the addresses do not receive the email.

/etc/moxsubmit.conf should be group-readable and not readable by others and this
binary should be setgid that group:

	groupadd moxsubmit
	install -m 2755 -o root -g moxsubmit mox /usr/sbin/sendmail
	touch /etc/moxsubmit.conf
	chown root:moxsubmit /etc/moxsubmit.conf
	chmod 640 /etc/moxsubmit.conf
	# edit /etc/moxsubmit.conf


	usage: mox sendmail [-Fname] [ignoredflags] [-t] [<message]

# mox smtp dial

Dial the address, initialize the SMTP session, including using STARTTLS to enable TLS if the server supports it.

If no port is specified, SMTP port 25 is used.

Data is copied between connection and stdin/stdout until either side closes the
connection.

The flags influence the TLS configuration, useful for debugging interoperability
issues.

No MTA-STS or DANE verification is done.

Hint: Use "mox -loglevel trace smtp dial ..." to see the protocol messages
exchanged during connection set up.

	usage: mox smtp dial host[:port]
	  -ehlohostname string
	    	our hostname to use during the SMTP EHLO command
	  -forcetls
	    	use TLS, even if remote SMTP server does not announce STARTTLS extension
	  -notls
	    	do not use TLS
	  -remotehostname string
	    	remote hostname to use for TLS verification, if enabled; the hostname from the parameter is used by default
	  -tlscerts string
	    	path to root ca certificates in pem form, for verification
	  -tlsciphersuites string
	    	ciphersuites to allow, comma-separated, order is ignored, only for TLS 1.2 and earlier, empty value uses TLS stack defaults; values: tls_ecdhe_ecdsa_with_aes_128_cbc_sha, tls_ecdhe_ecdsa_with_aes_128_gcm_sha256, tls_ecdhe_ecdsa_with_aes_256_cbc_sha, tls_ecdhe_ecdsa_with_aes_256_gcm_sha384, tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256, tls_ecdhe_rsa_with_aes_128_cbc_sha, tls_ecdhe_rsa_with_aes_128_gcm_sha256, tls_ecdhe_rsa_with_aes_256_cbc_sha, tls_ecdhe_rsa_with_aes_256_gcm_sha384, tls_ecdhe_rsa_with_chacha20_poly1305_sha256, and insecure: tls_ecdhe_ecdsa_with_aes_128_cbc_sha256, tls_ecdhe_ecdsa_with_rc4_128_sha, tls_ecdhe_rsa_with_3des_ede_cbc_sha, tls_ecdhe_rsa_with_aes_128_cbc_sha256, tls_ecdhe_rsa_with_rc4_128_sha, tls_rsa_with_3des_ede_cbc_sha, tls_rsa_with_aes_128_cbc_sha, tls_rsa_with_aes_128_cbc_sha256, tls_rsa_with_aes_128_gcm_sha256, tls_rsa_with_aes_256_cbc_sha, tls_rsa_with_aes_256_gcm_sha384, tls_rsa_with_rc4_128_sha
	  -tlscurves string
	    	tls ecc key exchange mechanisms to allow, comma-separated, order is ignored, empty value uses TLS stack defaults; values: curvep256, curvep384, curvep521, x25519, x25519mlkem768
	  -tlsnodynamicrecordsizing
	    	disable TLS dynamic record sizing
	  -tlsnosessiontickets
	    	disable TLS session tickets
	  -tlsrenegotiation string
	    	when to allow renegotiation; only applies to tls1.2 and earlier, not tls1.3; values: never, once, always (default "never")
	  -tlsverify
	    	verify remote hostname during TLS
	  -tlsversionmax string
	    	maximum TLS version, empty value uses TLS stack default; values: tls1.2, etc.
	  -tlsversionmin string
	    	minimum TLS version, empty value uses TLS stack default; values: tls1.2, etc.

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

# mox webapi

Lists available methods, prints request/response parameters for method, or calls a method with a request read from standard input.

	usage: mox webapi [method [baseurl-with-credentials]

# mox example

List available examples, or print a specific example.

	usage: mox example [name]

# mox bumpuidvalidity

Change the IMAP UID validity of the mailbox, causing IMAP clients to refetch messages.

This can be useful after manually repairing metadata about the account/mailbox.

Opens account database file directly. Ensure mox does not have the account
open, or is not running.

	usage: mox bumpuidvalidity account [mailbox]

# mox reassignuids

Reassign UIDs in one mailbox or all mailboxes in an account and bump UID validity, causing IMAP clients to refetch messages.

Opens account database file directly. Ensure mox does not have the account
open, or is not running.

	usage: mox reassignuids account [mailboxid]

# mox fixuidmeta

Fix inconsistent UIDVALIDITY and UIDNEXT in messages/mailboxes/account.

The next UID to use for a message in a mailbox should always be higher than any
existing message UID in the mailbox. If it is not, the mailbox UIDNEXT is
updated.

Each mailbox has a UIDVALIDITY sequence number, which should always be lower
than the per-account next UIDVALIDITY to use. If it is not, the account next
UIDVALIDITY is updated.

Opens account database file directly. Ensure mox does not have the account
open, or is not running.

	usage: mox fixuidmeta account

# mox fixmsgsize

Ensure message sizes in the database matching the sum of the message prefix length and on-disk file size.

Messages with an inconsistent size are also parsed again.

If an inconsistency is found, you should probably also run "mox
bumpuidvalidity" on the mailboxes or entire account to force IMAP clients to
refetch messages.

	usage: mox fixmsgsize [account]

# mox reparse

Parse all messages in the account or all accounts again.

Can be useful after upgrading mox with improved message parsing. Messages are
parsed in batches, so other access to the mailboxes/messages are not blocked
while reparsing all messages.

	usage: mox reparse [account]

# mox ensureparsed

Ensure messages in the database have a pre-parsed MIME form in the database.

	usage: mox ensureparsed account
	  -all
	    	store new parsed message for all messages

# mox recalculatemailboxcounts

Recalculate message counts for all mailboxes in the account, and total message size for quota.

When a message is added to/removed from a mailbox, or when message flags change,
the total, unread, unseen and deleted messages are accounted, the total size of
the mailbox, and the total message size for the account. In case of a bug in
this accounting, the numbers could become incorrect. This command will find, fix
and print them.

	usage: mox recalculatemailboxcounts account

# mox message parse

Parse message, print JSON representation.

	usage: mox message parse message.eml
	  -smtputf8
	    	check if message needs smtputf8

# mox reassignthreads

Reassign message threads.

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

	usage: mox reassignthreads [account]
*/
package main

// NOTE: DO NOT EDIT, this file is generated by gendoc.sh.
