# Mox - modern, secure, all-in-one email server
## Stay in control of your email and keep email decentralized!

Complete email solution
: For sending and receiving email. With support for IMAP4, SMTP, SPF, DKIM,
DMARC, MTA-STS, DANE and DNSSEC, reputation-based
and content-based junk filtering, Internationalization (EIA/IDNA), automatic TLS
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

The latest release is v0.0.15, released on 2025-04-18, see [release
notes](https://github.com/mjl-/mox/releases/tag/v0.0.15), [download
binaries](https://beta.gobuilds.org/github.com/mjl-/mox@v0.0.15/linux-amd64-latest/),
or see [all releases](https://github.com/mjl-/mox/releases).


## News

- 2025-04-18, [v0.0.15](https://github.com/mjl-/mox/releases/tag/v0.0.15) released
- 2025-01-20, [v0.0.14](https://github.com/mjl-/mox/releases/tag/v0.0.14) released
- 2025-01-20, There will be another [talk about
  mox](https://fosdem.org/2025/schedule/event/fosdem-2025-5364-mox-and-simplifying-mail-server-setup-management/)
  at [FOSDEM 2025](https://fosdem.org/2025/) (Feb 1 & 2) in the ["Modern Email"
  devroom](https://fosdem.org/2025/schedule/track/modern-email/).
- 2024-11-06, [v0.0.13](https://github.com/mjl-/mox/releases/tag/v0.0.13) released
- 2024-10-06, [v0.0.12](https://github.com/mjl-/mox/releases/tag/v0.0.12) released
- 2024-04-30, [v0.0.11](https://github.com/mjl-/mox/releases/tag/v0.0.11) released
- 2024-03-09, [v0.0.10](https://github.com/mjl-/mox/releases/tag/v0.0.10) released
- 2024-01-09, [v0.0.9](https://github.com/mjl-/mox/releases/tag/v0.0.9) released
- 2023-12-08, There will be a
  [talk about mox](https://fosdem.org/2024/schedule/event/fosdem-2024-2261--servers-mox-a-modern-full-featured-mail-server/)
  in the ["Modern Email" devroom](https://fosdem.org/2024/schedule/track/modern-email/)
  at [FOSDEM 2024](https://fosdem.org/2024/) (Feb 3 & 4, Brussels). See you there!
- 2023-11-22, [v0.0.8](https://github.com/mjl-/mox/releases/tag/v0.0.8) released
- 2023-09-24, [v0.0.7](https://github.com/mjl-/mox/releases/tag/v0.0.7) released


## Quickstart demo

Mox is real easy to set up. Get a machine, download the mox binary, run the
quickstart, add the printed DNS records, and you've got a working modern mail
server. See the demo below, or continue reading at [Install](install/).

<video controls preload="none" poster="files/video/quickstart-20240111.jpg">
	<source type="video/mp4" src="files/video/quickstart-20240111.mp4" />
	<source type="video/webm" src="files/video/quickstart-20240111.webm" />
</video>

Not ready for a full setup yet? Try mox in less than a minute:
[download](https://beta.gobuilds.org/github.com/mjl-/mox) and run "mox
localserve". It serves a local-only SMTP/IMAP/Webmail/etc for testing and
development. No setup required.


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

Thanks to [NLnet foundation](https://nlnet.nl/), the European Commission's
[NGI](https://ngi.eu) programme, and the Netherlands Ministry of the Interior
and Kingdom Relations for financial support:

- [2024/2025](https://nlnet.nl/project/Mox-Automation/), NLnet NGI0 Zero Core
- [2024](https://nlnet.nl/project/Mox-API/), NLnet e-Commons Fund
- [2023/2024](https://nlnet.nl/project/Mox/), NLnet NGI0 Entrust

<div class="logos">
<a href="https://nlnet.nl/entrust/"><img src="files/ngi0entrust.svg" alt="Logo of NGI Zero Entrust" /></a>
<a href="https://nlnet.nl/core/"><img src="files/ngi0core.svg" alt="Logo of NGI Zero Core" /></a>
<a href="https://www.government.nl/ministries/ministry-of-the-interior-and-kingdom-relations"><img src="files/minbzk.svg" alt="Logo of financial supporter Netherlands Ministry of the Interior and Kingdom Relations" /></a>
</div>
