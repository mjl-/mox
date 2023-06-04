default:
	cfssl genkey -initca cfssl-ca-csr.json | cfssljson -bare ca
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname moxmail1.mox1.example - | cfssljson -bare moxmail1
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname moxmail2.mox2.example - | cfssljson -bare moxmail2
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname moxmail3.mox3.example - | cfssljson -bare moxmail3
	echo '{}' | cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem -hostname postfixmail.postfix.example - | cfssljson -bare postfixmail
