#!/bin/sh
set -x # print commands
set -e # exit on failed command

apk add unbound curl

(rm -r /tmp/mox 2>/dev/null || exit 0) # clean slate
mkdir /tmp/mox
cd /tmp/mox
mox quickstart moxtest1@mox1.example "$MOX_UID" > output.txt

sed -i -e '/- 172.28.1.10/d' -e 's/- 0.0.0.0/- 172.28.1.10/' -e '/- ::/d' -e 's/letsencrypt:/pebble:/g' -e 's/: letsencrypt/: pebble/g' -e 's,DirectoryURL: https://acme-v02.api.letsencrypt.org/directory,DirectoryURL: https://acmepebble.example:14000/dir,' config/mox.conf
cat <<EOF >>config/mox.conf

TLS:
	CA:
		CertFiles:
                        # So certificates from moxmail2 are trusted, and pebble's certificate is trusted.
			- /quickstart/tls/ca.pem
EOF

(cat /quickstart/example.zone; sed -n '/^;/,/IN CAA/p' output.txt) >/quickstart/example-quickstart.zone
unbound-control -s 172.28.1.30 reload # reload unbound with zone file changes

CURL_CA_BUNDLE=/quickstart/tls/ca.pem curl -o /quickstart/tmp-pebble-ca.pem https://acmepebble.example:15000/roots/0

mox serve &
while true; do
	if test -e data/ctl; then
		echo -n accountpass1234 | mox setaccountpassword moxtest1@mox1.example
		break
	fi
	sleep 0.1
done
wait
