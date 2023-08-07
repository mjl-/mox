#!/bin/sh
set -x # print commands
set -e # exit on failed command

apk add unbound

(rm -r /tmp/mox 2>/dev/null || exit 0) # clean slate
mkdir /tmp/mox
cd /tmp/mox
mox quickstart moxtest2@mox2.example "$MOX_UID" > output.txt

sed -i -e '/- 172.28.1.20/d' -e 's/- 0.0.0.0/- 172.28.1.20/' -e '/- ::/d' -e 's,ACME: .*$,KeyCerts:\n\t\t\t\t-\n\t\t\t\t\tCertFile: /integration/tls/moxmail2.pem\n\t\t\t\t\tKeyFile: /integration/tls/moxmail2-key.pem\n\t\t\t\t-\n\t\t\t\t\tCertFile: /integration/tls/mox2-autoconfig.pem\n\t\t\t\t\tKeyFile: /integration/tls/mox2-autoconfig-key.pem\n\t\t\t\t-\n\t\t\t\t\tCertFile: /integration/tls/mox2-mtasts.pem\n\t\t\t\t\tKeyFile: /integration/tls/mox2-mtasts-key.pem\n,' -e 's/SMTP:$/SMTP:\n\t\t\tFirstTimeSenderDelay: 1s/' config/mox.conf
cat <<EOF >>config/mox.conf

TLS:
	CA:
		CertFiles:
			# CA of our own certificates.
			- /integration/tls/ca.pem
			# CA used by moxacmepebble.
			- /integration/tmp-pebble-ca.pem
EOF

# A fresh file was set up by moxacmepebble.
sed -n '/^;/,/IN CAA/p' output.txt >>/integration/example-integration.zone
unbound-control -s 172.28.1.30 reload # reload unbound with zone file changes

mox -checkconsistency serve &
while true; do
	if test -e data/ctl; then
		echo -n accountpass4321 | mox setaccountpassword moxtest2@mox2.example
		break
	fi
	sleep 0.1
done
wait
