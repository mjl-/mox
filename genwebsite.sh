#!/bin/bash

mkdir website/html 2>/dev/null
rm -r website/html/* 2>/dev/null

set -euo pipefail

commithash=$(git rev-parse --short HEAD)
commitdate=$(git log -1 --date=format:"%Y-%m-%d" --format="%ad")
export commithash
export commitdate

# Link to static files and cross-references.
ln -sf ../../../mox-website-files/files website/html/files
ln -sf ../../rfc/xr website/html/xr


# All commands below are executed relative to ./website/
cd website

go run website.go -root -title 'Mox: modern, secure, all-in-one mail server' 'Mox' < index.md >html/index.html

mkdir html/features
(
	cat features/index.md
	echo
	sed -n -e '/# FAQ/q' -e '/## Roadmap/,/# FAQ/p' < ../README.md
	echo
	echo 'Also see the [Protocols](../protocols/) page for implementation status, and (non)-plans.'
) | go run website.go 'Features' >html/features/index.html

mkdir html/screenshots
go run website.go 'Screenshots' < screenshots/index.md >html/screenshots/index.html

mkdir html/install
go run website.go 'Install' < install/index.md >html/install/index.html

mkdir html/faq
sed -n '/# FAQ/,//p' < ../README.md | go run website.go 'FAQ' >html/faq/index.html

mkdir html/config
(
	echo '# Config reference'
	echo
	sed -n '/^Package config holds /,/\*\//p' < ../config/doc.go | grep -v -E '^(Package config holds |\*/)' | sed 's/^# /## /'
) | go run website.go 'Config reference' >html/config/index.html

mkdir html/commands
(
	echo '# Command reference'
	echo
	sed -n '/^Mox is started /,/\*\//p' < ../doc.go | grep -v '\*/' | sed 's/^# /## /'
) | go run website.go 'Command reference' >html/commands/index.html

mkdir html/protocols
go run website.go -protocols 'Protocols' <../rfc/index.txt >html/protocols/index.html
