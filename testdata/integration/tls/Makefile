default:
	cfssl genkey -initca cfssl-ca-csr.json | cfssljson -bare ca
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname moxmail2.mox2.example - | cfssljson -bare moxmail2
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname autoconfig.mox2.example - | cfssljson -bare mox2-autoconfig
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname mta-sts.mox2.example - | cfssljson -bare mox2-mtasts
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname acmepebble.example - | cfssljson -bare acmepebble
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname postfixmail.postfix.example - | cfssljson -bare postfixmail
