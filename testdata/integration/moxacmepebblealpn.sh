#!/bin/sh
set -x # print commands
set -e # exit on failed command

apk add curl

(rm -r /tmp/mox 2>/dev/null || exit 0) # clean slate
mkdir /tmp/mox
cd /tmp/mox
mox quickstart -skipdial moxtest1@mox1.example "$MOX_UID" > output.txt

cp config/mox.conf config/mox.conf.orig
sed -i -e 's/letsencrypt:/pebble:/g' -e 's/: letsencrypt/: pebble/g' -e 's,DirectoryURL: https://acme-v02.api.letsencrypt.org/directory,DirectoryURL: https://acmepebble.example:14000/dir,' -e 's/Submissions:$/Submissions:\n\t\t\tEnabledOnHTTPS: true/' -e 's/IMAPS:$/IMAPS:\n\t\t\tEnabledOnHTTPS: true/' config/mox.conf
cat <<EOF >>config/mox.conf

TLS:
	CA:
		CertFiles:
                        # So certificates from moxmail2 are trusted, and pebble's certificate is trusted.
			- /integration/tls/ca.pem
EOF

CURL_CA_BUNDLE=/integration/tls/ca.pem curl -o /integration/tmp-pebble-ca.pem https://acmepebble.example:15000/roots/0

mox -checkconsistency serve &
while true; do
	if test -e data/ctl; then
		echo -n accountpass1234 | mox setaccountpassword moxtest1
		break
	fi
	sleep 0.1
done
wait
