# Install

Mox aims to be easy to install. The commands and config files to set mox up for
a new domain, including running it as a service on Linux, are printed/created
through the quickstart.

## Quickstart

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


## Download

Download a mox binary from
https://beta.gobuilds.org/github.com/mjl-/mox@latest/linux-amd64-latest/.

Symlink or rename it to "mox".

The URL above always resolves to the latest release for linux/amd64 built with
the latest Go toolchain.  See the links at the bottom of that page for binaries
for other platforms.


## Compiling

You can easily (cross) compile mox yourself. You need a recent Go toolchain
installed.  Run `go version`, it must be >= 1.20. Download the latest version
from https://go.dev/dl/ or see https://go.dev/doc/manage-install.

To download the source code of the latest release, and compile it to binary "mox":

	GOBIN=$PWD CGO_ENABLED=0 go install github.com/mjl-/mox@latest

Mox only compiles for and fully works on unix systems. Mox also compiles for
Windows, but "mox serve" does not yet work, though "mox localserve" (for a
local test instance) and most other subcommands do. Mox does not compile for
Plan 9.


## Docker

Although not recommended, you can also run mox with docker image
`r.xmox.nl/mox`, with tags like `v0.0.1` and `v0.0.1-go1.20.1-alpine3.17.2`, see
https://r.xmox.nl/r/mox/.  See
https://github.com/mjl-/mox/blob/main/docker-compose.yml to get started.

New docker images aren't (automatically) generated for new Go runtime/compile
releases.

It is important to run with docker host networking, so mox can use the public
IPs and has correct remote IP information for incoming connections (important
for junk filtering and rate-limiting).


## Configuration

Mox tries to choose sane defaults. When you add a domain or account, you
shouldn't have to change any more configuration files in most cases. If you do
need to make changes, you can edit the configuration files: `config/mox.conf`
and/or `config/domains.conf`. You do have to separately add DNS records.

See [Config reference](../config/) for configuration files annotated with
documentation.

Mox comes with various subcommands, useful especially for testing. See [Command
reference](../commands/) for a list of commands, and their documentation.

If you have a question, see the [FAQ](../faq/). If your question remains
unanswered, please ask it on the [issue
tracker](https://github.com/mjl-/mox/issues/new).
