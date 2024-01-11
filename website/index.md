# Mox - modern, secure, all-in-one email server
## Stay in control of your email and keep email decentralized!

Complete email solution
: For sending and receiving email. With support for IMAP4, SMTP, SPF, DKIM,
DMARC, MTA-STS, DANE and DNSSEC, reputation-based
and content-based junk filtering, Internationalization (IDNA), automatic TLS
with ACME and Let's Encrypt, account autoconfiguration, webmail.

Quick & easy
: Use the quickstart command to set up mox for your domain(s) within 10
minutes. You'll get a secure mail server with a modern protocol stack. Upgrades
are mostly a matter of downloading the new version and restarting. Maintenance
via web interface (easy) or config file (powerful). No dependencies.

High quality and secure
: Mox has a modern Go code base with plenty of automated tests, automated
integration tests, is manually tested against popular mail server and client
software, and is fuzz-tested. The code is well-documented and cross-referenced
with the relevant standards (RFC's).

Open Source
: Mox is an open source project, [source code](https://github.com/mjl-/mox) is
MIT-licensed.

See [Features](features/) for the details, including roadmap.

## Latest release

The latest release is v0.0.9, released on 2024-01-09, see [release
notes](https://github.com/mjl-/mox/releases/tag/v0.0.9), [download
binaries](https://beta.gobuilds.org/github.com/mjl-/mox@v0.0.9/linux-amd64-latest/),
or see [all releases](https://github.com/mjl-/mox/releases).


## News

- 2024-01-09, [v0.0.9](https://github.com/mjl-/mox/releases/tag/v0.0.9) released
- 2023-12-08, There will be a
  [talk about mox](https://fosdem.org/2024/schedule/event/fosdem-2024-2261--servers-mox-a-modern-full-featured-mail-server/)
  in the ["Modern Email" devroom](https://fosdem.org/2024/schedule/track/modern-email/)
  at [FOSDEM 2024](https://fosdem.org/2024/) (Feb 3 & 4, Brussels). See you there!
- 2023-11-22, [v0.0.8](https://github.com/mjl-/mox/releases/tag/v0.0.8) released
- 2023-09-24, [v0.0.7](https://github.com/mjl-/mox/releases/tag/v0.0.7) released


## Quickstart demo

Mox is real easy to set up. Get a machine, download the mox binary, run the
quickstart, add the printed DNS records, and you're good to go. See the demo
below, or continue reading at [Install](install/).

<video controls preload="none" poster="files/video/quickstart-20240111.jpg">
	<source type="video/webm" src="files/video/quickstart-20240111.webm" />
	<source type="video/mp4" src="files/video/quickstart-20240111.mp4" />
</video>

## Background

Work on mox started in 2021. Admins were migrating their emails to just a few
cloud/hosting providers. In part because running and maintaining email software
had become more complicated over time: additional email protocols required yet
another component in the software stack. Combining all these components into a
working email server had become too troublesome over time. These components
were also often written in C, a programming language where a small mistake
typically has large consequences.

Mox is a modern email server that implements all modern email protocols in a
single easy to use and maintain application.


## Sponsors

Mox development is sponsored from August 2023 to August 2024 through NLnet/EU's
NGI0 Entrust, see https://nlnet.nl/project/Mox/.
