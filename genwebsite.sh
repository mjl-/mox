#!/usr/bin/env bash

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

mkdir html/b
cat <<'EOF' >html/b/index.html
<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>mox build</title>
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<link rel="icon" href="noNeedlessFaviconRequestsPlease:" />
		<style>
body { padding: 1em; }
* { font-size: 18px; font-family: ubuntu, lato, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }
p { max-width: 50em; margin-bottom: 2ex; }
pre { font-family: 'ubuntu mono', monospace; }
pre, blockquote { padding: 1em; background-color: #eee; border-radius: .25em; display: inline-block; margin-bottom: 1em; }
h1 { margin: 1em 0 .5em 0; }
		</style>
	</head>
	<body>
<script>
const elem = (name, ...s) => {
	const e = document.createElement(name)
	e.append(...s)
	return e
}
const link = (url) => {
	const e = document.createElement('a')
	e.setAttribute('href', url)
	e.setAttribute('rel', 'noopener')
	e.appendChild(document.createTextNode(url))
	return e
}
let h = location.hash.substring(1)
const ok = /^[a-zA-Z0-9_\.]+$/.test(h)
if (!ok) {
	h = '<tag-or-branch-or-commithash>'
}
const init = () => {
	document.body.append(
		elem('p', 'Compile or download any version of mox, by tag (release), branch or commit hash.'),
		elem('h1', 'Compile'),
		elem('p', 'Run:'),
		elem('pre', 'CGO_ENABLED=0 GOBIN=$PWD go install github.com/mjl-/mox@'+h),
		elem('p', 'Mox is tested with the Go toolchain versions that are still have support: The most recent version, and the version before.'),
		elem('h1', 'Download'),
		elem('p', 'Download a binary for your platform:'),
		elem('blockquote', ok ?
			link('https://beta.gobuilds.org/github.com/mjl-/mox@'+h) :
			'https://beta.gobuilds.org/github.com/mjl-/mox@'+h
		),
		elem('p', 'Because mox is written in Go, builds are reproducible, also when cross-compiling. Gobuilds.org is a service that builds Go applications on-demand with the latest Go toolchain/runtime.'),
	)
}
window.addEventListener('load', init)
</script>
	</body>
</html>
EOF
