#!/bin/sh
set -x # print commands
set -e # exit on failed command

apk add unbound curl

(rm -r /tmp/mox 2>/dev/null || exit 0) # clean slate
mkdir /tmp/mox
cd /tmp/mox
mox quickstart moxtest1@mox1.example "$MOX_UID" > output.txt

cp config/mox.conf config/mox.conf.orig
sed -i -e 's/letsencrypt:/pebble:/g' -e 's/: letsencrypt/: pebble/g' -e 's,DirectoryURL: https://acme-v02.api.letsencrypt.org/directory,DirectoryURL: https://acmepebble.example:14000/dir,' -e 's/SMTP:$/SMTP:\n\t\t\tFirstTimeSenderDelay: 1s/' config/mox.conf
cat <<EOF >>config/mox.conf

TLS:
	CA:
		CertFiles:
                        # So certificates from moxmail2 are trusted, and pebble's certificate is trusted.
			- /integration/tls/ca.pem
EOF

(
	cat /integration/example.zone;
	sed -n '/^;/,/IN CAA/p' output.txt |
		# allow sending from postfix for mox1.example.
		sed 's/mox1.example.  *IN TXT "v=spf1 mx ~all"/mox1.example. IN TXT "v=spf1 mx ip4:172.28.1.70 ~all"/'
) >/integration/example-integration.zone
unbound-control -s 172.28.1.30 reload # reload unbound with zone file changes

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
