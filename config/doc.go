/*
Package config holds the configuration file definitions.

Mox uses two config files:

1. mox.conf, also called the static configuration file.
2. domains.conf, also called the dynamic configuration file.

The static configuration file is never reloaded during the lifetime of a
running mox instance. After changes to mox.conf, mox must be restarted for the
changes to take effect.

The dynamic configuration file is reloaded automatically when it changes.
If the file contains an error after the change, the reload is aborted and the
previous version remains active.

Below are "empty" config files, generated from the config file definitions in
the source code, along with comments explaining the fields. Fields named "x" are
placeholders for user-chosen map keys.

# sconf

The config files are in "sconf" format. Properties of sconf files:

  - Indentation with tabs only.
  - "#" as first non-whitespace character makes the line a comment. Lines with a
    value cannot also have a comment.
  - Values don't have syntax indicating their type. For example, strings are
    not quoted/escaped and can never span multiple lines.
  - Fields that are optional can be left out completely. But the value of an
    optional field may itself have required fields.

See https://pkg.go.dev/github.com/mjl-/sconf for details.

# mox.conf

	# NOTE: This config file is in 'sconf' format. Indent with tabs. Comments must be
	# on their own line, they don't end a line. Do not escape or quote strings.
	# Details: https://pkg.go.dev/github.com/mjl-/sconf.


	# Directory where all data is stored, e.g. queue, accounts and messages, ACME TLS
	# certs/keys. If this is a relative path, it is relative to the directory of
	# mox.conf.
	DataDir:

	# Default log level, one of: error, info, debug, trace, traceauth, tracedata.
	# Trace logs SMTP and IMAP protocol transcripts, with traceauth also messages with
	# passwords, and tracedata on top of that also the full data exchanges (full
	# messages), which can be a large amount of data.
	LogLevel:

	# Overrides of log level per package (e.g. queue, smtpclient, smtpserver,
	# imapserver, spf, dkim, dmarc, dmarcdb, autotls, junk, mtasts, tlsrpt).
	# (optional)
	PackageLogLevels:
		x:

	# User to switch to after binding to all sockets as root. Default: mox. If the
	# value is not a known user, it is parsed as integer and used as uid and gid.
	# (optional)
	User:

	# If true, do not automatically fix file permissions when starting up. By default,
	# mox will ensure reasonable owner/permissions on the working, data and config
	# directories (and files), and mox binary (if present). (optional)
	NoFixPermissions: false

	# Full hostname of system, e.g. mail.<domain>
	Hostname:

	# If enabled, a single DNS TXT lookup of _updates.xmox.nl is done every 24h to
	# check for a new release. Each time a new release is found, a changelog is
	# fetched from https://updates.xmox.nl/changelog and delivered to the postmaster
	# mailbox. (optional)
	CheckUpdates: false

	# In pedantic mode protocol violations (that happen in the wild) for SMTP/IMAP/etc
	# result in errors instead of accepting such behaviour. (optional)
	Pedantic: false

	# Global TLS configuration, e.g. for additional Certificate Authorities. Used for
	# outgoing SMTP connections, HTTPS requests. (optional)
	TLS:

		# (optional)
		CA:

			# (optional)
			AdditionalToSystem: false

			# (optional)
			CertFiles:
				-

	# Automatic TLS configuration with ACME, e.g. through Let's Encrypt. The key is a
	# name referenced in TLS configs, e.g. letsencrypt. (optional)
	ACME:
		x:

			# For letsencrypt, use https://acme-v02.api.letsencrypt.org/directory.
			DirectoryURL:

			# How long before expiration to renew the certificate. Default is 30 days.
			# (optional)
			RenewBefore: 0s

			# Email address to register at ACME provider. The provider can email you when
			# certificates are about to expire. If you configure an address for which email is
			# delivered by this server, keep in mind that TLS misconfigurations could result
			# in such notification emails not arriving.
			ContactEmail:

			# TLS port for ACME validation, 443 by default. You should only override this if
			# you cannot listen on port 443 directly. ACME will make requests to port 443, so
			# you'll have to add an external mechanism to get the tls connection here, e.g. by
			# configuring firewall-level port forwarding. Validation over the https port uses
			# tls-alpn-01 with application-layer protocol negotiation, which essentially means
			# the original tls connection must make it here unmodified, an https reverse proxy
			# will not work. (optional)
			Port: 0

			# If set, used for suggested CAA DNS records, for restricting TLS certificate
			# issuance to a Certificate Authority. If empty and DirectyURL is for Let's
			# Encrypt, this value is set automatically to letsencrypt.org. (optional)
			IssuerDomainName:

			# ACME providers can require that a request for a new ACME account reference an
			# existing non-ACME account known to the provider. External account binding
			# references that account by a key id, and authorizes new ACME account requests by
			# signing it with a key known both by the ACME client and ACME provider.
			# (optional)
			ExternalAccountBinding:

				# Key identifier, from ACME provider.
				KeyID:

				# File containing the base64url-encoded key used to sign account requests with
				# external account binding. The ACME provider will verify the account request is
				# correctly signed by the key. File is evaluated relative to the directory of
				# mox.conf.
				KeyFile:

	# File containing hash of admin password, for authentication in the web admin
	# pages (if enabled). (optional)
	AdminPasswordFile:

	# Listeners are groups of IP addresses and services enabled on those IP addresses,
	# such as SMTP/IMAP or internal endpoints for administration or Prometheus
	# metrics. All listeners with SMTP/IMAP services enabled will serve all configured
	# domains. If the listener is named 'public', it will get a few helpful additional
	# configuration checks, for acme automatic tls certificates and monitoring of ips
	# in dnsbls if those are configured.
	Listeners:
		x:

			# Use 0.0.0.0 to listen on all IPv4 and/or :: to listen on all IPv6 addresses, but
			# it is better to explicitly specify the IPs you want to use for email, as mox
			# will make sure outgoing connections will only be made from one of those IPs. If
			# both outgoing IPv4 and IPv6 connectivity is possible, and only one family has
			# explicitly configured addresses, both address families are still used for
			# outgoing connections. Use the "direct" transport to limit address families for
			# outgoing connections.
			IPs:
				-

			# If set, the mail server is configured behind a NAT and field IPs are internal
			# instead of the public IPs, while NATIPs lists the public IPs. Used during
			# IP-related DNS self-checks, such as for iprev, mx, spf, autoconfig,
			# autodiscover, and for autotls. (optional)
			NATIPs:
				-

			# Deprecated, use NATIPs instead. If set, IPs are not the public IPs, but are
			# NATed. Skips IP-related DNS self-checks. (optional)
			IPsNATed: false

			# If empty, the config global Hostname is used. The internal services webadmin,
			# webaccount, webmail and webapi only match requests to IPs, this hostname,
			# "localhost". All except webadmin also match for any client settings domain.
			# (optional)
			Hostname:

			# For SMTP/IMAP STARTTLS, direct TLS and HTTPS connections. (optional)
			TLS:

				# Name of provider from top-level configuration to use for ACME, e.g. letsencrypt.
				# (optional)
				ACME:

				# Keys and certificates to use for this listener. The files are opened by the
				# privileged root process and passed to the unprivileged mox process, so no
				# special permissions are required on the files. If the private key will not be
				# replaced when refreshing certificates, also consider adding the private key to
				# HostPrivateKeyFiles and configuring DANE TLSA DNS records. (optional)
				KeyCerts:
					-

						# Certificate including intermediate CA certificates, in PEM format.
						CertFile:

						# Private key for certificate, in PEM format. PKCS8 is recommended, but PKCS1 and
						# EC private keys are recognized as well.
						KeyFile:

				# Minimum TLS version. Default: TLSv1.2. (optional)
				MinVersion:

				# Private keys used for ACME certificates. Specified explicitly so DANE TLSA DNS
				# records can be generated, even before the certificates are requested. DANE is a
				# mechanism to authenticate remote TLS certificates based on a public key or
				# certificate specified in DNS, protected with DNSSEC. DANE is opportunistic and
				# attempted when delivering SMTP with STARTTLS. The private key files must be in
				# PEM format. PKCS8 is recommended, but PKCS1 and EC private keys are recognized
				# as well. Only RSA 2048 bit and ECDSA P-256 keys are currently used. The first of
				# each is used when requesting new certificates through ACME. (optional)
				HostPrivateKeyFiles:
					-

			# Maximum size in bytes for incoming and outgoing messages. Default is 100MB.
			# (optional)
			SMTPMaxMessageSize: 0

			# (optional)
			SMTP:
				Enabled: false

				# Default 25. (optional)
				Port: 0

				# Do not offer STARTTLS to secure the connection. Not recommended. (optional)
				NoSTARTTLS: false

				# Do not accept incoming messages if STARTTLS is not active. Consider using in
				# combination with an MTA-STS policy and/or DANE. A remote SMTP server may not
				# support TLS and may not be able to deliver messages. Incoming messages for TLS
				# reporting addresses ignore this setting and do not require TLS. (optional)
				RequireSTARTTLS: false

				# Do not announce the REQUIRETLS SMTP extension. Messages delivered using the
				# REQUIRETLS extension should only be distributed onwards to servers also
				# implementing the REQUIRETLS extension. In some situations, such as hosting
				# mailing lists, this may not be feasible due to lack of support for the extension
				# by mailing list subscribers. (optional)
				NoRequireTLS: false

				# Addresses of DNS block lists for incoming messages. Block lists are only
				# consulted for connections/messages without enough reputation to make an
				# accept/reject decision. This prevents sending IPs of all communications to the
				# block list provider. If any of the listed DNSBLs contains a requested IP
				# address, the message is rejected as spam. The DNSBLs are checked for healthiness
				# before use, at most once per 4 hours. IPs we can send from are periodically
				# checked for being in the configured DNSBLs. See MonitorDNSBLs in domains.conf to
				# only monitor IPs we send from, without using those DNSBLs for incoming messages.
				# Example DNSBLs: sbl.spamhaus.org, bl.spamcop.net. See
				# https://www.spamhaus.org/sbl/ and https://www.spamcop.net/ for more information
				# and terms of use. (optional)
				DNSBLs:
					-

				# Delay before accepting a message from a first-time sender for the destination
				# account. Default: 15s. (optional)
				FirstTimeSenderDelay: 0s

				# Override default setting for enabling TLS session tickets. Disabling session
				# tickets may work around TLS interoperability issues. (optional)
				TLSSessionTicketsDisabled: false

			# SMTP for submitting email, e.g. by email applications. Starts out in plain text,
			# can be upgraded to TLS with the STARTTLS command. Prefer using Submissions which
			# is always a TLS connection. (optional)
			Submission:
				Enabled: false

				# Default 587. (optional)
				Port: 0

				# Do not require STARTTLS. Since users must login, this means password may be sent
				# without encryption. Not recommended. (optional)
				NoRequireSTARTTLS: false

			# SMTP over TLS for submitting email, by email applications. Requires a TLS
			# config. (optional)
			Submissions:
				Enabled: false

				# Default 465. (optional)
				Port: 0

				# Additionally enable submission on HTTPS port 443 via TLS ALPN. TLS Application
				# Layer Protocol Negotiation allows clients to request a specific protocol from
				# the server as part of the TLS connection setup. When this setting is enabled and
				# a client requests the 'smtp' protocol after TLS, it will be able to talk SMTP to
				# Mox on port 443. This is meant to be useful as a censorship circumvention
				# technique for Delta Chat. (optional)
				EnabledOnHTTPS: false

			# IMAP for reading email, by email applications. Starts out in plain text, can be
			# upgraded to TLS with the STARTTLS command. Prefer using IMAPS instead which is
			# always a TLS connection. (optional)
			IMAP:
				Enabled: false

				# Default 143. (optional)
				Port: 0

				# Enable this only when the connection is otherwise encrypted (e.g. through a
				# VPN). (optional)
				NoRequireSTARTTLS: false

			# IMAP over TLS for reading email, by email applications. Requires a TLS config.
			# (optional)
			IMAPS:
				Enabled: false

				# Default 993. (optional)
				Port: 0

				# Additionally enable IMAP on HTTPS port 443 via TLS ALPN. TLS Application Layer
				# Protocol Negotiation allows clients to request a specific protocol from the
				# server as part of the TLS connection setup. When this setting is enabled and a
				# client requests the 'imap' protocol after TLS, it will be able to talk IMAP to
				# Mox on port 443. This is meant to be useful as a censorship circumvention
				# technique for Delta Chat. (optional)
				EnabledOnHTTPS: false

			# Account web interface, for email users wanting to change their accounts, e.g.
			# set new password, set new delivery rulesets. Default path is /. (optional)
			AccountHTTP:
				Enabled: false

				# Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname
				# matching behaviour. (optional)
				Port: 0

				# Path to serve requests on. Should end with a slash, related to cookie paths.
				# (optional)
				Path:

				# If set, X-Forwarded-* headers are used for the remote IP address for rate
				# limiting and for the "secure" status of cookies. (optional)
				Forwarded: false

			# Account web interface listener like AccountHTTP, but for HTTPS. Requires a TLS
			# config. (optional)
			AccountHTTPS:
				Enabled: false

				# Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname
				# matching behaviour. (optional)
				Port: 0

				# Path to serve requests on. Should end with a slash, related to cookie paths.
				# (optional)
				Path:

				# If set, X-Forwarded-* headers are used for the remote IP address for rate
				# limiting and for the "secure" status of cookies. (optional)
				Forwarded: false

			# Admin web interface, for managing domains, accounts, etc. Default path is
			# /admin/. Preferably only enable on non-public IPs. Hint: use 'ssh -L
			# 8080:localhost:80 you@yourmachine' and open http://localhost:8080/admin/, or set
			# up a tunnel (e.g. WireGuard) and add its IP to the mox 'internal' listener.
			# (optional)
			AdminHTTP:
				Enabled: false

				# Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname
				# matching behaviour. (optional)
				Port: 0

				# Path to serve requests on. Should end with a slash, related to cookie paths.
				# (optional)
				Path:

				# If set, X-Forwarded-* headers are used for the remote IP address for rate
				# limiting and for the "secure" status of cookies. (optional)
				Forwarded: false

			# Admin web interface listener like AdminHTTP, but for HTTPS. Requires a TLS
			# config. (optional)
			AdminHTTPS:
				Enabled: false

				# Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname
				# matching behaviour. (optional)
				Port: 0

				# Path to serve requests on. Should end with a slash, related to cookie paths.
				# (optional)
				Path:

				# If set, X-Forwarded-* headers are used for the remote IP address for rate
				# limiting and for the "secure" status of cookies. (optional)
				Forwarded: false

			# Webmail client, for reading email. Default path is /webmail/. (optional)
			WebmailHTTP:
				Enabled: false

				# Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname
				# matching behaviour. (optional)
				Port: 0

				# Path to serve requests on. Should end with a slash, related to cookie paths.
				# (optional)
				Path:

				# If set, X-Forwarded-* headers are used for the remote IP address for rate
				# limiting and for the "secure" status of cookies. (optional)
				Forwarded: false

			# Webmail client, like WebmailHTTP, but for HTTPS. Requires a TLS config.
			# (optional)
			WebmailHTTPS:
				Enabled: false

				# Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname
				# matching behaviour. (optional)
				Port: 0

				# Path to serve requests on. Should end with a slash, related to cookie paths.
				# (optional)
				Path:

				# If set, X-Forwarded-* headers are used for the remote IP address for rate
				# limiting and for the "secure" status of cookies. (optional)
				Forwarded: false

			# Like WebAPIHTTP, but with plain HTTP, without TLS. (optional)
			WebAPIHTTP:
				Enabled: false

				# Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname
				# matching behaviour. (optional)
				Port: 0

				# Path to serve requests on. Should end with a slash, related to cookie paths.
				# (optional)
				Path:

				# If set, X-Forwarded-* headers are used for the remote IP address for rate
				# limiting and for the "secure" status of cookies. (optional)
				Forwarded: false

			# WebAPI, a simple HTTP/JSON-based API for email, with HTTPS (requires a TLS
			# config). Default path is /webapi/. (optional)
			WebAPIHTTPS:
				Enabled: false

				# Default 80 for HTTP and 443 for HTTPS. See Hostname at Listener for hostname
				# matching behaviour. (optional)
				Port: 0

				# Path to serve requests on. Should end with a slash, related to cookie paths.
				# (optional)
				Path:

				# If set, X-Forwarded-* headers are used for the remote IP address for rate
				# limiting and for the "secure" status of cookies. (optional)
				Forwarded: false

			# Serve prometheus metrics, for monitoring. You should not enable this on a public
			# IP. (optional)
			MetricsHTTP:
				Enabled: false

				# Default 8010. (optional)
				Port: 0

			# Serve /debug/pprof/ for profiling a running mox instance. Do not enable this on
			# a public IP! (optional)
			PprofHTTP:
				Enabled: false

				# Default 8011. (optional)
				Port: 0

			# Serve autoconfiguration/autodiscovery to simplify configuring email
			# applications, will use port 443. Requires a TLS config. (optional)
			AutoconfigHTTPS:
				Enabled: false

				# TLS port, 443 by default. You should only override this if you cannot listen on
				# port 443 directly. Autoconfig requests will be made to port 443, so you'll have
				# to add an external mechanism to get the connection here, e.g. by configuring
				# port forwarding. (optional)
				Port: 0

				# If set, plain HTTP instead of HTTPS is spoken on the configured port. Can be
				# useful when the autoconfig domain is reverse proxied. (optional)
				NonTLS: false

			# Serve MTA-STS policies describing SMTP TLS requirements. Requires a TLS config.
			# (optional)
			MTASTSHTTPS:
				Enabled: false

				# TLS port, 443 by default. You should only override this if you cannot listen on
				# port 443 directly. MTA-STS requests will be made to port 443, so you'll have to
				# add an external mechanism to get the connection here, e.g. by configuring port
				# forwarding. (optional)
				Port: 0

				# If set, plain HTTP instead of HTTPS is spoken on the configured port. Can be
				# useful when the mta-sts domain is reverse proxied. (optional)
				NonTLS: false

			# All configured WebHandlers will serve on an enabled listener. (optional)
			WebserverHTTP:
				Enabled: false

				# Port for plain HTTP (non-TLS) webserver. (optional)
				Port: 0

				# Disable rate limiting for all requests to this port. (optional)
				RateLimitDisabled: false

			# All configured WebHandlers will serve on an enabled listener. Either ACME must
			# be configured, or for each WebHandler domain a TLS certificate must be
			# configured. (optional)
			WebserverHTTPS:
				Enabled: false

				# Port for HTTPS webserver. (optional)
				Port: 0

				# Disable rate limiting for all requests to this port. (optional)
				RateLimitDisabled: false

	# Destination for emails delivered to postmaster addresses: a plain 'postmaster'
	# without domain, 'postmaster@<hostname>' (also for each listener with SMTP
	# enabled), and as fallback for each domain without explicitly configured
	# postmaster destination.
	Postmaster:
		Account:

		# E.g. Postmaster or Inbox.
		Mailbox:

	# Destination for per-host TLS reports (TLSRPT). TLS reports can be per recipient
	# domain (for MTA-STS), or per MX host (for DANE). The per-domain TLS reporting
	# configuration is in domains.conf. This is the TLS reporting configuration for
	# this host. If absent, no host-based TLSRPT address is configured, and no host
	# TLSRPT DNS record is suggested. (optional)
	HostTLSRPT:

		# Account to deliver TLS reports to. Typically same account as for postmaster.
		Account:

		# Mailbox to deliver TLS reports to. Recommended value: TLSRPT.
		Mailbox:

		# Localpart at hostname to accept TLS reports at. Recommended value: tlsreports.
		Localpart:

	# Mailboxes to create for new accounts. Inbox is always created. Mailboxes can be
	# given a 'special-use' role, which are understood by most mail clients. If
	# absent/empty, the following additional mailboxes are created: Sent, Archive,
	# Trash, Drafts and Junk. (optional)
	InitialMailboxes:

		# Special-use roles to mailbox to create. (optional)
		SpecialUse:

			# (optional)
			Sent:

			# (optional)
			Archive:

			# (optional)
			Trash:

			# (optional)
			Draft:

			# (optional)
			Junk:

		# Regular, non-special-use mailboxes to create. (optional)
		Regular:
			-

	# Deprecated in favor of InitialMailboxes. Mailboxes to create when adding an
	# account. Inbox is always created. If no mailboxes are specified, the following
	# are automatically created: Sent, Archive, Trash, Drafts and Junk. (optional)
	DefaultMailboxes:
		-

	# Transport are mechanisms for delivering messages. Transports can be referenced
	# from Routes in accounts, domains and the global configuration. There is always
	# an implicit/fallback delivery transport doing direct delivery with SMTP from the
	# outgoing message queue. Transports are typically only configured when using
	# smarthosts, i.e. when delivering through another SMTP server. Zero or one
	# transport methods must be set in a transport, never multiple. When using an
	# external party to send email for a domain, keep in mind you may have to add
	# their IP address to your domain's SPF record, and possibly additional DKIM
	# records. (optional)
	Transports:
		x:

			# Submission SMTP over a TLS connection to submit email to a remote queue.
			# (optional)
			Submissions:

				# Host name to connect to and for verifying its TLS certificate.
				Host:

				# If unset or 0, the default port for submission(s)/smtp is used: 25 for SMTP, 465
				# for submissions (with TLS), 587 for submission (possibly with STARTTLS).
				# (optional)
				Port: 0

				# If set an unverifiable remote TLS certificate during STARTTLS is accepted.
				# (optional)
				STARTTLSInsecureSkipVerify: false

				# If set for submission or smtp transport, do not attempt STARTTLS on the
				# connection. Authentication credentials and messages will be transferred in clear
				# text. (optional)
				NoSTARTTLS: false

				# If set, authentication credentials for the remote server. (optional)
				Auth:
					Username:
					Password:

					# Allowed authentication mechanisms. Defaults to SCRAM-SHA-256-PLUS,
					# SCRAM-SHA-256, SCRAM-SHA-1-PLUS, SCRAM-SHA-1, CRAM-MD5. Not included by default:
					# PLAIN. Specify the strongest mechanism known to be implemented by the server to
					# prevent mechanism downgrade attacks. (optional)
					Mechanisms:
						-

			# Submission SMTP over a plain TCP connection (possibly with STARTTLS) to submit
			# email to a remote queue. (optional)
			Submission:

				# Host name to connect to and for verifying its TLS certificate.
				Host:

				# If unset or 0, the default port for submission(s)/smtp is used: 25 for SMTP, 465
				# for submissions (with TLS), 587 for submission (possibly with STARTTLS).
				# (optional)
				Port: 0

				# If set an unverifiable remote TLS certificate during STARTTLS is accepted.
				# (optional)
				STARTTLSInsecureSkipVerify: false

				# If set for submission or smtp transport, do not attempt STARTTLS on the
				# connection. Authentication credentials and messages will be transferred in clear
				# text. (optional)
				NoSTARTTLS: false

				# If set, authentication credentials for the remote server. (optional)
				Auth:
					Username:
					Password:

					# Allowed authentication mechanisms. Defaults to SCRAM-SHA-256-PLUS,
					# SCRAM-SHA-256, SCRAM-SHA-1-PLUS, SCRAM-SHA-1, CRAM-MD5. Not included by default:
					# PLAIN. Specify the strongest mechanism known to be implemented by the server to
					# prevent mechanism downgrade attacks. (optional)
					Mechanisms:
						-

			# SMTP over a plain connection (possibly with STARTTLS), typically for
			# old-fashioned unauthenticated relaying to a remote queue. (optional)
			SMTP:

				# Host name to connect to and for verifying its TLS certificate.
				Host:

				# If unset or 0, the default port for submission(s)/smtp is used: 25 for SMTP, 465
				# for submissions (with TLS), 587 for submission (possibly with STARTTLS).
				# (optional)
				Port: 0

				# If set an unverifiable remote TLS certificate during STARTTLS is accepted.
				# (optional)
				STARTTLSInsecureSkipVerify: false

				# If set for submission or smtp transport, do not attempt STARTTLS on the
				# connection. Authentication credentials and messages will be transferred in clear
				# text. (optional)
				NoSTARTTLS: false

				# If set, authentication credentials for the remote server. (optional)
				Auth:
					Username:
					Password:

					# Allowed authentication mechanisms. Defaults to SCRAM-SHA-256-PLUS,
					# SCRAM-SHA-256, SCRAM-SHA-1-PLUS, SCRAM-SHA-1, CRAM-MD5. Not included by default:
					# PLAIN. Specify the strongest mechanism known to be implemented by the server to
					# prevent mechanism downgrade attacks. (optional)
					Mechanisms:
						-

			# Like regular direct delivery, but makes outgoing connections through a SOCKS
			# proxy. (optional)
			Socks:

				# Address of SOCKS proxy, of the form host:port or ip:port.
				Address:

				# IP addresses connections from the SOCKS server will originate from. This IP
				# addresses should be configured in the SPF record (keep in mind DNS record time
				# to live (TTL) when adding a SOCKS proxy). Reverse DNS should be set up for these
				# address, resolving to RemoteHostname. These are typically the IPv4 and IPv6
				# address for the host in the Address field.
				RemoteIPs:
					-

				# Hostname belonging to RemoteIPs. This name is used during in SMTP EHLO. This is
				# typically the hostname of the host in the Address field.
				RemoteHostname:

			# Like regular direct delivery, but allows to tweak outgoing connections.
			# (optional)
			Direct:

				# If set, outgoing SMTP connections will *NOT* use IPv4 addresses to connect to
				# remote SMTP servers. (optional)
				DisableIPv4: false

				# If set, outgoing SMTP connections will *NOT* use IPv6 addresses to connect to
				# remote SMTP servers. (optional)
				DisableIPv6: false

			# Immediately fails the delivery attempt. (optional)
			Fail:

				# SMTP error code and optional enhanced error code to use for the failure. If
				# empty, 554 is used (transaction failed). (optional)
				SMTPCode: 0

				# Message to include for the rejection. It will be shown in the DSN. (optional)
				SMTPMessage:

	# Do not send DMARC reports (aggregate only). By default, aggregate reports on
	# DMARC evaluations are sent to domains if their DMARC policy requests them.
	# Reports are sent at whole hours, with a minimum of 1 hour and maximum of 24
	# hours, rounded up so a whole number of intervals cover 24 hours, aligned at
	# whole days in UTC. Reports are sent from the postmaster@<mailhostname> address.
	# (optional)
	NoOutgoingDMARCReports: false

	# Do not send TLS reports. By default, reports about failed SMTP STARTTLS
	# connections and related MTA-STS/DANE policies are sent to domains if their
	# TLSRPT DNS record requests them. Reports covering a 24 hour UTC interval are
	# sent daily. Reports are sent from the postmaster address of the configured
	# domain the mailhostname is in. If there is no such domain, or it does not have
	# DKIM configured, no reports are sent. (optional)
	NoOutgoingTLSReports: false

	# Also send TLS reports if there were no SMTP STARTTLS connection failures. By
	# default, reports are only sent when at least one failure occurred. If a report
	# is sent, it does always include the successful connection counts as well.
	# (optional)
	OutgoingTLSReportsForAllSuccess: false

	# Default maximum total message size in bytes for each individual account, only
	# applicable if greater than zero. Can be overridden per account. Attempting to
	# add new messages to an account beyond its maximum total size will result in an
	# error. Useful to prevent a single account from filling storage. The quota only
	# applies to the email message files, not to any file system overhead and also not
	# the message index database file (account for approximately 15% overhead).
	# (optional)
	QuotaMessageSize: 0

# domains.conf

	# NOTE: This config file is in 'sconf' format. Indent with tabs. Comments must be
	# on their own line, they don't end a line. Do not escape or quote strings.
	# Details: https://pkg.go.dev/github.com/mjl-/sconf.


	# Domains for which email is accepted. For internationalized domains, use their
	# IDNA names in UTF-8.
	Domains:
		x:

			# Disabled domains can be useful during/before migrations. Domains that are
			# disabled can still be configured like normal, including adding addresses using
			# the domain to accounts. However, disabled domains: 1. Do not try to fetch ACME
			# certificates. TLS connections to host names involving the email domain will
			# fail. A TLS certificate for the hostname (that wil be used as MX) itself will be
			# requested. 2. Incoming deliveries over SMTP are rejected with a temporary error
			# '450 4.2.1 recipient domain temporarily disabled'. 3. Submissions over SMTP
			# using an (envelope) SMTP MAIL FROM address or message 'From' address of a
			# disabled domain will be rejected with a temporary error '451 4.3.0 sender domain
			# temporarily disabled'. Note that accounts with addresses at disabled domains can
			# still log in and read email (unless the account itself is disabled). (optional)
			Disabled: false

			# Free-form description of domain. (optional)
			Description:

			# Hostname for client settings instead of the mail server hostname. E.g.
			# mail.<domain>. For future migration to another mail operator without requiring
			# all clients to update their settings, it is convenient to have client settings
			# that reference a subdomain of the hosted domain instead of the hostname of the
			# server where the mail is currently hosted. If empty, the hostname of the mail
			# server is used for client configurations. Unicode name. (optional)
			ClientSettingsDomain:

			# If not empty, only the string before the separator is used to for email delivery
			# decisions. For example, if set to "+", you+anything@example.com will be
			# delivered to you@example.com. (optional)
			LocalpartCatchallSeparator:

			# Similar to LocalpartCatchallSeparator, but in case multiple are needed. For
			# example both "+" and "-". Only of one LocalpartCatchallSeparator or
			# LocalpartCatchallSeparators can be set. If set, the first separator is used to
			# make unique addresses for outgoing SMTP connections with FromIDLoginAddresses.
			# (optional)
			LocalpartCatchallSeparators:
				-

			# If set, upper/lower case is relevant for email delivery. (optional)
			LocalpartCaseSensitive: false

			# With DKIM signing, a domain is taking responsibility for (content of) emails it
			# sends, letting receiving mail servers build up a (hopefully positive) reputation
			# of the domain, which can help with mail delivery. (optional)
			DKIM:

				# Emails can be DKIM signed. Config parameters are per selector. A DNS record must
				# be created for each selector. Add the name to Sign to use the selector for
				# signing messages.
				Selectors:
					x:

						# sha256 (default) or (older, not recommended) sha1. (optional)
						Hash:

						# (optional)
						Canonicalization:

							# If set, some modifications to the headers (mostly whitespace) are allowed.
							HeaderRelaxed: false

							# If set, some whitespace modifications to the message body are allowed.
							BodyRelaxed: false

						# Headers to sign with DKIM. If empty, a reasonable default set of headers is
						# selected. (optional)
						Headers:
							-

						# If set, don't prevent duplicate headers from being added. Not recommended.
						# (optional)
						DontSealHeaders: false

						# Period a signature is valid after signing, as duration, e.g. 72h. The period
						# should be enough for delivery at the final destination, potentially with several
						# hops/relays. In the order of days at least. (optional)
						Expiration:

						# Either an RSA or ed25519 private key file in PKCS8 PEM form.
						PrivateKeyFile:

				# List of selectors that emails will be signed with. (optional)
				Sign:
					-

			# With DMARC, a domain publishes, in DNS, a policy on how other mail servers
			# should handle incoming messages with the From-header matching this domain and/or
			# subdomain (depending on the configured alignment). Receiving mail servers use
			# this to build up a reputation of this domain, which can help with mail delivery.
			# A domain can also publish an email address to which reports about DMARC
			# verification results can be sent by verifying mail servers, useful for
			# monitoring. Incoming DMARC reports are automatically parsed, validated, added to
			# metrics and stored in the reporting database for later display in the admin web
			# pages. (optional)
			DMARC:

				# Address-part before the @ that accepts DMARC reports. Must be
				# non-internationalized. Recommended value: dmarcreports.
				Localpart:

				# Alternative domain for reporting address, for incoming reports. Typically empty,
				# causing the domain wherein this config exists to be used. Can be used to receive
				# reports for domains that aren't fully hosted on this server. Configure such a
				# domain as a hosted domain without making all the DNS changes, and configure this
				# field with a domain that is fully hosted on this server, so the localpart and
				# the domain of this field form a reporting address. Then only update the DMARC
				# DNS record for the not fully hosted domain, ensuring the reporting address is
				# specified in its "rua" field as shown in the suggested DNS settings. Unicode
				# name. (optional)
				Domain:

				# Account to deliver to.
				Account:

				# Mailbox to deliver to, e.g. DMARC.
				Mailbox:

			# MTA-STS is a mechanism that allows publishing a policy with requirements for
			# WebPKI-verified SMTP STARTTLS connections for email delivered to a domain.
			# Existence of a policy is announced in a DNS TXT record (often
			# unprotected/unverified, MTA-STS's weak spot). If a policy exists, it is fetched
			# with a WebPKI-verified HTTPS request. The policy can indicate that
			# WebPKI-verified SMTP STARTTLS is required, and which MX hosts (optionally with a
			# wildcard pattern) are allowd. MX hosts to deliver to are still taken from DNS
			# (again, not necessarily protected/verified), but messages will only be delivered
			# to domains matching the MX hosts from the published policy. Mail servers look up
			# the MTA-STS policy when first delivering to a domain, then keep a cached copy,
			# periodically checking the DNS record if a new policy is available, and fetching
			# and caching it if so. To update a policy, first serve a new policy with an
			# updated policy ID, then update the DNS record (not the other way around). To
			# remove an enforced policy, publish an updated policy with mode "none" for a long
			# enough period so all cached policies have been refreshed (taking DNS TTL and
			# policy max age into account), then remove the policy from DNS, wait for TTL to
			# expire, and stop serving the policy. (optional)
			MTASTS:

				# Policies are versioned. The version must be specified in the DNS record. If you
				# change a policy, first change it here to update the served policy, then update
				# the DNS record with the updated policy ID.
				PolicyID:

				# If set to "enforce", a remote SMTP server will not deliver email to us if it
				# cannot make a WebPKI-verified SMTP STARTTLS connection. In mode "testing",
				# deliveries can be done without verified TLS, but errors will be reported through
				# TLS reporting. In mode "none", verified TLS is not required, used for phasing
				# out an MTA-STS policy.
				Mode:

				# How long a remote mail server is allowed to cache a policy. Typically 1 or
				# several weeks.
				MaxAge: 0s

				# List of server names allowed for SMTP. If empty, the configured hostname is set.
				# Host names can contain a wildcard (*) as a leading label (matching a single
				# label, e.g. *.example matches host.example, not sub.host.example). (optional)
				MX:
					-

			# With TLSRPT a domain specifies in DNS where reports about encountered SMTP TLS
			# behaviour should be sent. Useful for monitoring. Incoming TLS reports are
			# automatically parsed, validated, added to metrics and stored in the reporting
			# database for later display in the admin web pages. (optional)
			TLSRPT:

				# Address-part before the @ that accepts TLSRPT reports. Recommended value:
				# tlsreports.
				Localpart:

				# Alternative domain for reporting address, for incoming reports. Typically empty,
				# causing the domain wherein this config exists to be used. Can be used to receive
				# reports for domains that aren't fully hosted on this server. Configure such a
				# domain as a hosted domain without making all the DNS changes, and configure this
				# field with a domain that is fully hosted on this server, so the localpart and
				# the domain of this field form a reporting address. Then only update the TLSRPT
				# DNS record for the not fully hosted domain, ensuring the reporting address is
				# specified in its "rua" field as shown in the suggested DNS settings. Unicode
				# name. (optional)
				Domain:

				# Account to deliver to.
				Account:

				# Mailbox to deliver to, e.g. TLSRPT.
				Mailbox:

			# Routes for delivering outgoing messages through the queue. Each delivery attempt
			# evaluates account routes, these domain routes and finally global routes. The
			# transport of the first matching route is used in the delivery attempt. If no
			# routes match, which is the default with no configured routes, messages are
			# delivered directly from the queue. (optional)
			Routes:
				-

					# Matches if the envelope from domain matches one of the configured domains, or if
					# the list is empty. If a domain starts with a dot, prefixes of the domain also
					# match. (optional)
					FromDomain:
						-

					# Like FromDomain, but matching against the envelope to domain. (optional)
					ToDomain:
						-

					# Matches if at least this many deliveries have already been attempted. This can
					# be used to attempt sending through a smarthost when direct delivery has failed
					# for several times. (optional)
					MinimumAttempts: 0
					Transport:

			# Aliases that cause messages to be delivered to one or more locally configured
			# addresses. Keys are localparts (encoded, as they appear in email addresses).
			# (optional)
			Aliases:
				x:

					# Expanded addresses to deliver to. These must currently be of addresses of local
					# accounts. To prevent duplicate messages, a member address that is also an
					# explicit recipient in the SMTP transaction will only have the message delivered
					# once. If the address in the message From header is a member, that member also
					# won't receive the message.
					Addresses:
						-

					# If true, anyone can send messages to the list. Otherwise only members, based on
					# message From address, which is assumed to be DMARC-like-verified. (optional)
					PostPublic: false

					# If true, members can see addresses of members. (optional)
					ListMembers: false

					# If true, members are allowed to send messages with this alias address in the
					# message From header. (optional)
					AllowMsgFrom: false

	# Accounts represent mox users, each with a password and email address(es) to
	# which email can be delivered (possibly at different domains). Each account has
	# its own on-disk directory holding its messages and index database. An account
	# name is not an email address.
	Accounts:
		x:

			# Webhooks for events about outgoing deliveries. (optional)
			OutgoingWebhook:

				# URL to POST webhooks.
				URL:

				# If not empty, value of Authorization header to add to HTTP requests. (optional)
				Authorization:

				# Events to send outgoing delivery notifications for. If absent, all events are
				# sent. Valid values: delivered, suppressed, delayed, failed, relayed, expanded,
				# canceled, unrecognized. (optional)
				Events:
					-

			# Webhooks for events about incoming deliveries over SMTP. (optional)
			IncomingWebhook:

				# URL to POST webhooks to for incoming deliveries over SMTP.
				URL:

				# If not empty, value of Authorization header to add to HTTP requests. (optional)
				Authorization:

			# Login addresses that cause outgoing email to be sent with SMTP MAIL FROM
			# addresses with a unique id after the localpart catchall separator (which must be
			# enabled when addresses are specified here). Any delivery status notifications
			# (DSN, e.g. for bounces), can be related to the original message and recipient
			# with unique id's. You can login to an account with any valid email address,
			# including variants with the localpart catchall separator. You can use this
			# mechanism to both send outgoing messages with and without unique fromid for a
			# given email address. With the webapi and webmail, a unique id will be generated.
			# For submission, the id from the SMTP MAIL FROM command is used if present, and a
			# unique id is generated otherwise. (optional)
			FromIDLoginAddresses:
				-

			# Period to keep messages retired from the queue (delivered or failed) around.
			# Keeping retired messages is useful for maintaining the suppression list for
			# transactional email, for matching incoming DSNs to sent messages, and for
			# debugging. The time at which to clean up (remove) is calculated at retire time.
			# E.g. 168h (1 week). (optional)
			KeepRetiredMessagePeriod: 0s

			# Period to keep webhooks retired from the queue (delivered or failed) around.
			# Useful for debugging. The time at which to clean up (remove) is calculated at
			# retire time. E.g. 168h (1 week). (optional)
			KeepRetiredWebhookPeriod: 0s

			# If non-empty, login attempts on all protocols (e.g. SMTP/IMAP, web interfaces)
			# is rejected with this error message. Useful during migrations. Incoming
			# deliveries for addresses of this account are still accepted as normal.
			# (optional)
			LoginDisabled:

			# Default domain for account. Deprecated behaviour: If a destination is not a full
			# address but only a localpart, this domain is added to form a full address.
			Domain:

			# Free form description, e.g. full name or alternative contact info. (optional)
			Description:

			# Full name, to use in message From header when composing messages in webmail. Can
			# be overridden per destination. (optional)
			FullName:

			# Destinations, keys are email addresses (with IDNA domains). All destinations are
			# allowed for logging in with IMAP/SMTP/webmail. If no destinations are
			# configured, the account can not login. If the address is of the form '@domain',
			# i.e. with localpart missing, it serves as a catchall for the domain, matching
			# all messages that are not explicitly configured. Deprecated behaviour: If the
			# address is not a full address but a localpart, it is combined with Domain to
			# form a full address. (optional)
			Destinations:
				x:

					# Mailbox to deliver to if none of Rulesets match. Default: Inbox. (optional)
					Mailbox:

					# Delivery rules based on message and SMTP transaction. You may want to match each
					# mailing list by SMTP MailFrom address, VerifiedDomain and/or List-ID header
					# (typically <listname.example.org> if the list address is listname@example.org),
					# delivering them to their own mailbox. (optional)
					Rulesets:
						-

							# Matches if this regular expression matches (a substring of) the SMTP MAIL FROM
							# address (not the message From-header). E.g. '^user@example\.org$'. (optional)
							SMTPMailFromRegexp:

							# Matches if this regular expression matches (a substring of) the single address
							# in the message From header. (optional)
							MsgFromRegexp:

							# Matches if this domain matches an SPF- and/or DKIM-verified (sub)domain.
							# (optional)
							VerifiedDomain:

							# Matches if these header field/value regular expressions all match (substrings
							# of) the message headers. Header fields and valuees are converted to lower case
							# before matching. Whitespace is trimmed from the value before matching. A header
							# field can occur multiple times in a message, only one instance has to match. For
							# mailing lists, you could match on ^list-id$ with the value typically the mailing
							# list address in angled brackets with @ replaced with a dot, e.g.
							# <name\.lists\.example\.org>. (optional)
							HeadersRegexp:
								x:

							# Influences spam filtering only, this option does not change whether a message
							# matches this ruleset. Can only be used together with SMTPMailFromRegexp and
							# VerifiedDomain. SMTPMailFromRegexp must be set to the address used to deliver
							# the forwarded message, e.g. '^user(|\+.*)@forward\.example$'. Changes to junk
							# analysis: 1. Messages are not rejected for failing a DMARC policy, because a
							# legitimate forwarded message without valid/intact/aligned DKIM signature would
							# be rejected because any verified SPF domain will be 'unaligned', of the
							# forwarding mail server. 2. The sending mail server IP address, and sending EHLO
							# and MAIL FROM domains and matching DKIM domain aren't used in future
							# reputation-based spam classifications (but other verified DKIM domains are)
							# because the forwarding server is not a useful spam signal for future messages.
							# (optional)
							IsForward: false

							# Influences spam filtering only, this option does not change whether a message
							# matches this ruleset. If this domain matches an SPF- and/or DKIM-verified
							# (sub)domain, the message is accepted without further spam checks, such as a junk
							# filter or DMARC reject evaluation. DMARC rejects should not apply for mailing
							# lists that are not configured to rewrite the From-header of messages that don't
							# have a passing DKIM signature of the From-domain. Otherwise, by rejecting
							# messages, you may be automatically unsubscribed from the mailing list. The
							# assumption is that mailing lists do their own spam filtering/moderation.
							# (optional)
							ListAllowDomain:

							# Influences spam filtering only, this option does not change whether a message
							# matches this ruleset. If a message is classified as spam, it isn't rejected
							# during the SMTP transaction (the normal behaviour), but accepted during the SMTP
							# transaction and delivered to the specified mailbox. The specified mailbox is not
							# automatically cleaned up like the account global Rejects mailbox, unless set to
							# that Rejects mailbox. (optional)
							AcceptRejectsToMailbox:

							# Mailbox to deliver to if this ruleset matches.
							Mailbox:

							# Free-form comments. (optional)
							Comment:

					# If non-empty, incoming delivery attempts to this destination will be rejected
					# during SMTP RCPT TO with this error response line. Useful when a catchall
					# address is configured for the domain and messages to some addresses should be
					# rejected. The response line must start with an error code. Currently the
					# following error resonse codes are allowed: 421 (temporary local error), 550
					# (user not found). If the line consists of only an error code, an appropriate
					# error message is added. Rejecting messages with a 4xx code invites later retries
					# by the remote, while 5xx codes should prevent further delivery attempts.
					# (optional)
					SMTPError:

					# If non-empty, an additional DMARC-like message authentication check is done for
					# incoming messages, validating the domain in the From-header of the message.
					# Messages without either an aligned SPF or aligned DKIM pass are rejected during
					# the SMTP DATA command with a permanent error code followed by the message in
					# this field. The domain in the message 'From' header is matched in relaxed or
					# strict mode according to the domain's DMARC policy if present, or relaxed mode
					# (organizational instead of exact domain match) otherwise. Useful for
					# autoresponders that don't want to accept messages they don't want to send an
					# automated reply to. (optional)
					MessageAuthRequiredSMTPError:

					# Full name to use in message From header when composing messages coming from this
					# address with webmail. (optional)
					FullName:

			# If configured, messages classified as weakly spam are rejected with instructions
			# to retry delivery, but this time with a signed token added to the subject.
			# During the next delivery attempt, the signed token will bypass the spam filter.
			# Messages with a clear spam signal, such as a known bad reputation, are
			# rejected/delayed without a signed token. (optional)
			SubjectPass:

				# How long unique values are accepted after generating, e.g. 12h.
				Period: 0s

			# Default maximum total message size in bytes for the account, overriding any
			# globally configured default maximum size if non-zero. A negative value can be
			# used to have no limit in case there is a limit by default. Attempting to add new
			# messages to an account beyond its maximum total size will result in an error.
			# Useful to prevent a single account from filling storage. (optional)
			QuotaMessageSize: 0

			# Mail that looks like spam will be rejected, but a copy can be stored temporarily
			# in a mailbox, e.g. Rejects. If mail isn't coming in when you expect, you can
			# look there. The mail still isn't accepted, so the remote mail server may retry
			# (hopefully, if legitimate), or give up (hopefully, if indeed a spammer).
			# Messages are automatically removed from this mailbox, so do not set it to a
			# mailbox that has messages you want to keep. (optional)
			RejectsMailbox:

			# Don't automatically delete mail in the RejectsMailbox listed above. This can be
			# useful, e.g. for future spam training. It can also cause storage to fill up.
			# (optional)
			KeepRejects: false

			# Automatically set $Junk and $NotJunk flags based on mailbox messages are
			# delivered/moved/copied to. Email clients typically have too limited
			# functionality to conveniently set these flags, especially $NonJunk, but they can
			# all move messages to a different mailbox, so this helps them. (optional)
			AutomaticJunkFlags:

				# If enabled, junk/nonjunk flags will be set automatically if they match some of
				# the regular expressions. When two of the three mailbox regular expressions are
				# set, the remaining one will match all unmatched messages. Messages are matched
				# in the order 'junk', 'neutral', 'not junk', and the search stops on the first
				# match. Mailboxes are lowercased before matching.
				Enabled: false

				# Example: ^(junk|spam). (optional)
				JunkMailboxRegexp:

				# Example: ^(inbox|neutral|postmaster|dmarc|tlsrpt|rejects), and you may wish to
				# add trash depending on how you use it, or leave this empty. (optional)
				NeutralMailboxRegexp:

				# Example: .* or an empty string. (optional)
				NotJunkMailboxRegexp:

			# Content-based filtering, using the junk-status of individual messages to rank
			# words in such messages as spam or ham. It is recommended you always set the
			# applicable (non)-junk status on messages, and that you do not empty your Trash
			# because those messages contain valuable ham/spam training information.
			# (optional)
			JunkFilter:

				# Approximate spaminess score between 0 and 1 above which emails are rejected as
				# spam. Each delivery attempt adds a little noise to make it slightly harder for
				# spammers to identify words that strongly indicate non-spaminess and use it to
				# bypass the filter. E.g. 0.95.
				Threshold: 0.000000
				Params:

					# Track ham/spam ranking for single words. (optional)
					Onegrams: false

					# Track ham/spam ranking for each two consecutive words. (optional)
					Twograms: false

					# Track ham/spam ranking for each three consecutive words. (optional)
					Threegrams: false

					# Maximum power a word (combination) can have. If spaminess is 0.99, and max power
					# is 0.1, spaminess of the word will be set to 0.9. Similar for ham words.
					MaxPower: 0.000000

					# Number of most spammy/hammy words to use for calculating probability. E.g. 10.
					TopWords: 0

					# Ignore words that are this much away from 0.5 haminess/spaminess. E.g. 0.1,
					# causing word (combinations) of 0.4 to 0.6 to be ignored. (optional)
					IgnoreWords: 0.000000

					# Occurrences in word database until a word is considered rare and its influence
					# in calculating probability reduced. E.g. 1 or 2. (optional)
					RareWords: 0

			# Maximum number of outgoing messages for this account in a 24 hour window. This
			# limits the damage to recipients and the reputation of this mail server in case
			# of account compromise. Default 1000. (optional)
			MaxOutgoingMessagesPerDay: 0

			# Maximum number of first-time recipients in outgoing messages for this account in
			# a 24 hour window. This limits the damage to recipients and the reputation of
			# this mail server in case of account compromise. Default 200. (optional)
			MaxFirstTimeRecipientsPerDay: 0

			# Do not apply a delay to SMTP connections before accepting an incoming message
			# from a first-time sender. Can be useful for accounts that sends automated
			# responses and want instant replies. (optional)
			NoFirstTimeSenderDelay: false

			# If set, this account cannot set a password of their own choice, but can only set
			# a new randomly generated password, preventing password reuse across services and
			# use of weak passwords. Custom account passwords can be set by the admin.
			# (optional)
			NoCustomPassword: false

			# Routes for delivering outgoing messages through the queue. Each delivery attempt
			# evaluates these account routes, domain routes and finally global routes. The
			# transport of the first matching route is used in the delivery attempt. If no
			# routes match, which is the default with no configured routes, messages are
			# delivered directly from the queue. (optional)
			Routes:
				-

					# Matches if the envelope from domain matches one of the configured domains, or if
					# the list is empty. If a domain starts with a dot, prefixes of the domain also
					# match. (optional)
					FromDomain:
						-

					# Like FromDomain, but matching against the envelope to domain. (optional)
					ToDomain:
						-

					# Matches if at least this many deliveries have already been attempted. This can
					# be used to attempt sending through a smarthost when direct delivery has failed
					# for several times. (optional)
					MinimumAttempts: 0
					Transport:

	# Redirect all requests from domain (key) to domain (value). Always redirects to
	# HTTPS. For plain HTTP redirects, use a WebHandler with a WebRedirect. (optional)
	WebDomainRedirects:
		x:

	# Handle webserver requests by serving static files, redirecting, reverse-proxying
	# HTTP(s) or passing the request to an internal service. The first matching
	# WebHandler will handle the request. Built-in system handlers, e.g. for ACME
	# validation, autoconfig and mta-sts always run first. Built-in handlers for
	# admin, account, webmail and webapi are evaluated after all handlers, including
	# webhandlers (allowing for overrides of internal services for some domains). If
	# no handler matches, the response status code is file not found (404). If
	# webserver features are missing, forward the requests to an application that
	# provides the needed functionality itself. (optional)
	WebHandlers:
		-

			# Name to use in logging and metrics. (optional)
			LogName:

			# Both Domain and PathRegexp must match for this WebHandler to match a request.
			# Exactly one of WebStatic, WebRedirect, WebForward, WebInternal must be set.
			Domain:

			# Regular expression matched against request path, must always start with ^ to
			# ensure matching from the start of the path. The matching prefix can optionally
			# be stripped by WebForward. The regular expression does not have to end with $.
			PathRegexp:

			# If set, plain HTTP requests are not automatically permanently redirected (308)
			# to HTTPS. If you don't have a HTTPS webserver configured, set this to true.
			# (optional)
			DontRedirectPlainHTTP: false

			# Transparently compress responses (currently with gzip) if the client supports
			# it, the status is 200 OK, no Content-Encoding is set on the response yet and the
			# Content-Type of the response hints that the data is compressible (text/...,
			# specific application/... and .../...+json and .../...+xml). For static files
			# only, a cache with compressed files is kept. (optional)
			Compress: false

			# Serve static files. (optional)
			WebStatic:

				# Path to strip from the request URL before evaluating to a local path. If the
				# requested URL path does not start with this prefix and ContinueNotFound it is
				# considered non-matching and next WebHandlers are tried. If ContinueNotFound is
				# not set, a file not found (404) is returned in that case. (optional)
				StripPrefix:

				# Directory to serve files from for this handler. Keep in mind that relative paths
				# are relative to the working directory of mox.
				Root:

				# If set, and a directory is requested, and no index.html is present that can be
				# served, a file listing is returned. Results in 403 if ListFiles is not set. If a
				# directory is requested and the URL does not end with a slash, the response is a
				# redirect to the path with trailing slash. (optional)
				ListFiles: false

				# If a requested URL does not exist, don't return a file not found (404) response,
				# but consider this handler non-matching and continue attempts to serve with later
				# WebHandlers, which may be a reverse proxy generating dynamic content, possibly
				# even writing a static file for a next request to serve statically. If
				# ContinueNotFound is set, HTTP requests other than GET and HEAD do not match.
				# This mechanism can be used to implement the equivalent of 'try_files' in other
				# webservers. (optional)
				ContinueNotFound: false

				# Headers to add to the response. Useful for cache-control, content-type, etc. By
				# default, Content-Type headers are automatically added for recognized file types,
				# unless added explicitly through this setting. For directory listings, a
				# content-type header is skipped. (optional)
				ResponseHeaders:
					x:

			# Redirect requests to configured URL. (optional)
			WebRedirect:

				# Base URL to redirect to. The path must be empty and will be replaced, either by
				# the request URL path, or by OrigPathRegexp/ReplacePath. Scheme, host, port and
				# fragment stay intact, and query strings are combined. If empty, the response
				# redirects to a different path through OrigPathRegexp and ReplacePath, which must
				# then be set. Use a URL without scheme to redirect without changing the protocol,
				# e.g. //newdomain/. If a redirect would send a request to a URL with the same
				# scheme, host and path, the WebRedirect does not match so a next WebHandler can
				# be tried. This can be used to redirect all plain http traffic to https.
				# (optional)
				BaseURL:

				# Regular expression for matching path. If set and path does not match, a 404 is
				# returned. The HTTP path used for matching always starts with a slash. (optional)
				OrigPathRegexp:

				# Replacement path for destination URL based on OrigPathRegexp. Implemented with
				# Go's Regexp.ReplaceAllString: $1 is replaced with the text of the first
				# submatch, etc. If both OrigPathRegexp and ReplacePath are empty, BaseURL must be
				# set and all paths are redirected unaltered. (optional)
				ReplacePath:

				# Status code to use in redirect, e.g. 307. By default, a permanent redirect (308)
				# is returned. (optional)
				StatusCode: 0

			# Forward requests to another webserver, i.e. reverse proxy. (optional)
			WebForward:

				# Strip the matching WebHandler path from the WebHandler before forwarding the
				# request. (optional)
				StripPath: false

				# URL to forward HTTP requests to, e.g. http://127.0.0.1:8123/base. If StripPath
				# is false the full request path is added to the URL. Host headers are sent
				# unmodified. New X-Forwarded-{For,Host,Proto} headers are set. Any query string
				# in the URL is ignored. Requests are made using Go's net/http.DefaultTransport
				# that takes environment variables HTTP_PROXY and HTTPS_PROXY into account.
				# Websocket connections are forwarded and data is copied between client and
				# backend without looking at the framing. The websocket 'version' and
				# 'key'/'accept' headers are verified during the handshake, but other websocket
				# headers, including 'origin', 'protocol' and 'extensions' headers, are not
				# inspected and the backend is responsible for verifying/interpreting them.
				URL:

				# Headers to add to the response. Useful for adding security- and cache-related
				# headers. (optional)
				ResponseHeaders:
					x:

			# Pass request to internal service, like webmail, webapi, etc. (optional)
			WebInternal:

				# Path to use as root of internal service, e.g. /webmail/.
				BasePath:

				# Name of the service, values: admin, account, webmail, webapi.
				Service:

	# Routes for delivering outgoing messages through the queue. Each delivery attempt
	# evaluates account routes, domain routes and finally these global routes. The
	# transport of the first matching route is used in the delivery attempt. If no
	# routes match, which is the default with no configured routes, messages are
	# delivered directly from the queue. (optional)
	Routes:
		-

			# Matches if the envelope from domain matches one of the configured domains, or if
			# the list is empty. If a domain starts with a dot, prefixes of the domain also
			# match. (optional)
			FromDomain:
				-

			# Like FromDomain, but matching against the envelope to domain. (optional)
			ToDomain:
				-

			# Matches if at least this many deliveries have already been attempted. This can
			# be used to attempt sending through a smarthost when direct delivery has failed
			# for several times. (optional)
			MinimumAttempts: 0
			Transport:

	# DNS blocklists to periodically check with if IPs we send from are present,
	# without using them for checking incoming deliveries.. Also see DNSBLs in SMTP
	# listeners in mox.conf, which specifies DNSBLs to use both for incoming
	# deliveries and for checking our IPs against. Example DNSBLs: sbl.spamhaus.org,
	# bl.spamcop.net. (optional)
	MonitorDNSBLs:
		-

# Examples

Mox includes configuration files to illustrate common setups. You can see these
examples with "mox config example", and print a specific example with "mox
config example <name>". Below are all examples included in mox.

# Example webhandlers

	# Snippet of domains.conf to configure WebDomainRedirects and WebHandlers.

	# Redirect all requests for mox.example to https://www.mox.example.
	WebDomainRedirects:
		mox.example: www.mox.example

	# Each request is matched against these handlers until one matches and serves it.
	WebHandlers:
		-
			# Redirect all plain http requests to https, leaving path, query strings, etc
			# intact. When the request is already to https, the destination URL would have the
			# same scheme, host and path, causing this redirect handler to not match the
			# request (and not cause a redirect loop) and the webserver to serve the request
			# with a later handler.
			LogName: redirhttps
			Domain: www.mox.example
			PathRegexp: ^/
			# Could leave DontRedirectPlainHTTP at false if it wasn't for this being an
			# example for doing this redirect.
			DontRedirectPlainHTTP: true
			WebRedirect:
				BaseURL: https://www.mox.example
		-
			# The name of the handler, used in logging and metrics.
			LogName: staticmjl
			# With ACME configured, each configured domain will automatically get a TLS
			# certificate on first request.
			Domain: www.mox.example
			PathRegexp: ^/who/mjl/
			WebStatic:
				StripPrefix: /who/mjl
				# Requested path /who/mjl/inferno/ resolves to local web/mjl/inferno.
				# If a directory contains an index.html, it is served when a directory is requested.
				Root: web/mjl
				# With ListFiles true, if a directory does not contain an index.html, the contents are listed.
				ListFiles: true
				ResponseHeaders:
					X-Mox: hi
		-
			LogName: redir
			Domain: www.mox.example
			PathRegexp: ^/redir/a/b/c
			# Don't redirect from plain HTTP to HTTPS.
			DontRedirectPlainHTTP: true
			WebRedirect:
				# Just change the domain and add query string set fragment. No change to scheme.
				# Path will start with /redir/a/b/c (and whathever came after) because no
				# OrigPathRegexp+ReplacePath is set.
				BaseURL: //moxest.example?q=1#frag
				# Default redirection is 308 - Permanent Redirect.
				StatusCode: 307
		-
			LogName: oldnew
			Domain: www.mox.example
			PathRegexp: ^/old/
			WebRedirect:
				# Replace path, leaving rest of URL intact.
				OrigPathRegexp: ^/old/(.*)
				ReplacePath: /new/$1
		-
			LogName: app
			Domain: www.mox.example
			PathRegexp: ^/app/
			WebForward:
				# Strip the path matched by PathRegexp before forwarding the request. So original
				# request /app/api become just /api.
				StripPath: true
				# URL of backend, where requests are forwarded to. The path in the URL is kept,
				# so for incoming request URL /app/api, the outgoing request URL has path /app-v2/api.
				# Requests are made with Go's net/http DefaultTransporter, including using
				# HTTP_PROXY and HTTPS_PROXY environment variables.
				URL: http://127.0.0.1:8900/app-v2/
				# Add headers to response.
				ResponseHeaders:
					X-Frame-Options: deny
					X-Content-Type-Options: nosniff

# Example transport

	# Snippet for mox.conf, defining a transport called Example that connects on the
	# SMTP submission with TLS port 465 ("submissions"), authenticating with
	# SCRAM-SHA-256-PLUS (other providers may not support SCRAM-SHA-256-PLUS, but they
	# typically do support the older CRAM-MD5).:

	# Transport are mechanisms for delivering messages. Transports can be referenced
	# from Routes in accounts, domains and the global configuration. There is always
	# an implicit/fallback delivery transport doing direct delivery with SMTP from the
	# outgoing message queue. Transports are typically only configured when using
	# smarthosts, i.e. when delivering through another SMTP server. Zero or one
	# transport methods must be set in a transport, never multiple. When using an
	# external party to send email for a domain, keep in mind you may have to add
	# their IP address to your domain's SPF record, and possibly additional DKIM
	# records. (optional)
	Transports:
		Example:
			# Submission SMTP over a TLS connection to submit email to a remote queue.
			# (optional)
			Submissions:
				# Host name to connect to and for verifying its TLS certificate.
				Host: smtp.example.com

				# If set, authentication credentials for the remote server. (optional)
				Auth:
					Username: user@example.com
					Password: test1234
					Mechanisms:
						# Allowed authentication mechanisms. Defaults to SCRAM-SHA-256-PLUS,
						# SCRAM-SHA-256, SCRAM-SHA-1-PLUS, SCRAM-SHA-1, CRAM-MD5. Not included by default:
						# PLAIN. Specify the strongest mechanism known to be implemented by the server to
						# prevent mechanism downgrade attacks. (optional)

						- SCRAM-SHA-256-PLUS


	# Snippet for domains.conf, specifying a route that sends through the transport:

	# Routes for delivering outgoing messages through the queue. Each delivery attempt
	# evaluates account routes, domain routes and finally these global routes. The
	# transport of the first matching route is used in the delivery attempt. If no
	# routes match, which is the default with no configured routes, messages are
	# delivered directly from the queue. (optional)
	Routes:
		-
			Transport: Example
*/
package config

// NOTE: DO NOT EDIT, this file is generated by ../gendoc.sh.
