package scram

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"hash"
	"math/big"
	"net"
	"testing"
	"time"
)

func base64Decode(s string) []byte {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic("bad base64")
	}
	return buf
}

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func TestSCRAMSHA1Server(t *testing.T) {
	// Test vector from ../rfc/5802:496
	salt := base64Decode("QSXCR+Q6sek8bf92")
	saltedPassword := SaltPassword(sha1.New, "pencil", salt, 4096)

	server, err := NewServer(sha1.New, []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"), nil, false)
	server.serverNonceOverride = "3rfcNHYJY1ZVvWVs7j"
	tcheck(t, err, "newserver")
	resp, err := server.ServerFirst(4096, salt)
	tcheck(t, err, "server first")
	if resp != "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096" {
		t.Fatalf("bad server first")
	}
	serverFinal, err := server.Finish([]byte("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="), saltedPassword)
	tcheck(t, err, "finish")
	if serverFinal != "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=" {
		t.Fatalf("bad server final")
	}
}

func TestSCRAMSHA256Server(t *testing.T) {
	// Test vector from ../rfc/7677:122
	salt := base64Decode("W22ZaJ0SNY7soEsUEjb6gQ==")
	saltedPassword := SaltPassword(sha256.New, "pencil", salt, 4096)

	server, err := NewServer(sha256.New, []byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"), nil, false)
	server.serverNonceOverride = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	tcheck(t, err, "newserver")
	resp, err := server.ServerFirst(4096, salt)
	tcheck(t, err, "server first")
	if resp != "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096" {
		t.Fatalf("bad server first")
	}
	serverFinal, err := server.Finish([]byte("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="), saltedPassword)
	tcheck(t, err, "finish")
	if serverFinal != "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Fatalf("bad server final")
	}
}

// Bad attempt with wrong password.
func TestScramServerBadPassword(t *testing.T) {
	salt := base64Decode("W22ZaJ0SNY7soEsUEjb6gQ==")
	saltedPassword := SaltPassword(sha256.New, "marker", salt, 4096)

	server, err := NewServer(sha256.New, []byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"), nil, false)
	server.serverNonceOverride = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	tcheck(t, err, "newserver")
	_, err = server.ServerFirst(4096, salt)
	tcheck(t, err, "server first")
	_, err = server.Finish([]byte("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="), saltedPassword)
	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("got %v, expected ErrInvalidProof", err)
	}
}

// Bad attempt with different number of rounds.
func TestScramServerBadIterations(t *testing.T) {
	salt := base64Decode("W22ZaJ0SNY7soEsUEjb6gQ==")
	saltedPassword := SaltPassword(sha256.New, "pencil", salt, 2048)

	server, err := NewServer(sha256.New, []byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"), nil, false)
	server.serverNonceOverride = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	tcheck(t, err, "newserver")
	_, err = server.ServerFirst(4096, salt)
	tcheck(t, err, "server first")
	_, err = server.Finish([]byte("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="), saltedPassword)
	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("got %v, expected ErrInvalidProof", err)
	}
}

// Another attempt but with a randomly different nonce.
func TestScramServerBad(t *testing.T) {
	salt := base64Decode("W22ZaJ0SNY7soEsUEjb6gQ==")
	saltedPassword := SaltPassword(sha256.New, "pencil", salt, 4096)

	server, err := NewServer(sha256.New, []byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"), nil, false)
	tcheck(t, err, "newserver")
	_, err = server.ServerFirst(4096, salt)
	tcheck(t, err, "server first")
	_, err = server.Finish([]byte("c=biws,r="+server.nonce+",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="), saltedPassword)
	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("got %v, expected ErrInvalidProof", err)
	}
}

func TestScramClient(t *testing.T) {
	c := NewClient(sha256.New, "user", "", false, nil)
	c.clientNonce = "rOprNGfwEbeRWgbNEkqO"
	clientFirst, err := c.ClientFirst()
	tcheck(t, err, "ClientFirst")
	if clientFirst != "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" {
		t.Fatalf("bad clientFirst")
	}
	clientFinal, err := c.ServerFirst([]byte("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"), "pencil")
	tcheck(t, err, "ServerFirst")
	if clientFinal != "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=" {
		t.Fatalf("bad clientFinal")
	}
	err = c.ServerFinal([]byte("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="))
	tcheck(t, err, "ServerFinal")
}

func TestScram(t *testing.T) {
	runHash := func(h func() hash.Hash, expErr error, username, authzid, password string, iterations int, clientNonce, serverNonce string, noServerPlus bool, clientcs, servercs *tls.ConnectionState) {
		t.Helper()

		defer func() {
			x := recover()
			if x == nil || x == "" {
				return
			}
			panic(x)
		}()

		// check err is either nil or the expected error. if the expected error, panic to abort the authentication session.
		xerr := func(err error, msg string) {
			t.Helper()
			if err != nil && !errors.Is(err, expErr) {
				t.Fatalf("%s: got %v, expected %v", msg, err, expErr)
			}
			if err != nil {
				panic("") // Abort test.
			}
		}

		salt := MakeRandom()
		saltedPassword := SaltPassword(h, password, salt, iterations)

		client := NewClient(h, username, "", noServerPlus, clientcs)
		client.clientNonce = clientNonce
		clientFirst, err := client.ClientFirst()
		xerr(err, "client.ClientFirst")

		server, err := NewServer(h, []byte(clientFirst), servercs, servercs != nil)
		xerr(err, "NewServer")
		server.serverNonceOverride = serverNonce

		serverFirst, err := server.ServerFirst(iterations, salt)
		xerr(err, "server.ServerFirst")

		clientFinal, err := client.ServerFirst([]byte(serverFirst), password)
		xerr(err, "client.ServerFirst")

		serverFinal, err := server.Finish([]byte(clientFinal), saltedPassword)
		xerr(err, "server.Finish")

		err = client.ServerFinal([]byte(serverFinal))
		xerr(err, "client.ServerFinal")

		if expErr != nil {
			t.Fatalf("got no error, expected %v", expErr)
		}
	}

	makeState := func(maxTLSVersion uint16) (tls.ConnectionState, tls.ConnectionState) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		tlsClient := tls.Client(client, &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion:         maxTLSVersion,
		})
		tlsServer := tls.Server(server, &tls.Config{
			Certificates: []tls.Certificate{fakeCert(t, "mox.example", false)},
			MaxVersion:   maxTLSVersion,
		})
		errc := make(chan error, 1)
		go func() {
			errc <- tlsServer.Handshake()
		}()
		err := tlsClient.Handshake()
		tcheck(t, err, "tls handshake")
		err = <-errc
		tcheck(t, err, "server tls handshake")
		clientcs := tlsClient.ConnectionState()
		servercs := tlsServer.ConnectionState()

		return clientcs, servercs
	}

	runPlus := func(maxTLSVersion uint16, expErr error, username, authzid, password string, iterations int, clientNonce, serverNonce string) {
		t.Helper()

		// PLUS variants.
		clientcs, servercs := makeState(maxTLSVersion)
		runHash(sha1.New, expErr, username, authzid, password, iterations, clientNonce, serverNonce, false, &clientcs, &servercs)
		runHash(sha256.New, expErr, username, authzid, password, iterations, clientNonce, serverNonce, false, &clientcs, &servercs)
	}

	run := func(expErr error, username, authzid, password string, iterations int, clientNonce, serverNonce string) {
		t.Helper()

		// Bare variants
		runHash(sha1.New, expErr, username, authzid, password, iterations, clientNonce, serverNonce, false, nil, nil)
		runHash(sha256.New, expErr, username, authzid, password, iterations, clientNonce, serverNonce, false, nil, nil)

		// Check with both TLS 1.2 for "tls-unique", and latest TLS for "tls-exporter".
		runPlus(tls.VersionTLS12, expErr, username, authzid, password, iterations, clientNonce, serverNonce)
		runPlus(0, expErr, username, authzid, password, iterations, clientNonce, serverNonce)
	}

	run(nil, "user", "", "pencil", 4096, "", "")
	run(nil, "mjl@mox.example", "", "testtest", 4096, "", "")
	run(nil, "mjl@mox.example", "", "short", 4096, "", "")
	run(nil, "mjl@mox.example", "", "short", 2048, "", "")
	run(nil, "mjl@mox.example", "mjl@mox.example", "testtest", 4096, "", "")
	run(nil, "mjl@mox.example", "other@mox.example", "testtest", 4096, "", "")
	run(nil, "mjl@mox.example", "other@mox.example", "testtest", 4096, "", "")
	run(ErrUnsafe, "user", "", "pencil", 1, "", "")                // Few iterations.
	run(ErrUnsafe, "user", "", "pencil", 2048, "short", "")        // Short client nonce.
	run(ErrUnsafe, "user", "", "pencil", 2048, "test1234", "test") // Server added too few random data.

	// Test mechanism downgrade attacks are detected.
	runHash(sha1.New, ErrServerDoesSupportChannelBinding, "user", "", "pencil", 4096, "", "", true, nil, nil)
	runHash(sha256.New, ErrServerDoesSupportChannelBinding, "user", "", "pencil", 4096, "", "", true, nil, nil)

	// Test channel binding, detecting MitM attacks.
	runChannelBind := func(maxTLSVersion uint16) {
		t.Helper()

		clientcs0, _ := makeState(maxTLSVersion)
		_, servercs1 := makeState(maxTLSVersion)
		runHash(sha1.New, ErrChannelBindingsDontMatch, "user", "", "pencil", 4096, "", "", false, &clientcs0, &servercs1)
		runHash(sha256.New, ErrChannelBindingsDontMatch, "user", "", "pencil", 4096, "", "", false, &clientcs0, &servercs1)

		// Client thinks it is on a TLS connection and server is not.
		runHash(sha1.New, ErrChannelBindingsDontMatch, "user", "", "pencil", 4096, "", "", false, &clientcs0, nil)
		runHash(sha256.New, ErrChannelBindingsDontMatch, "user", "", "pencil", 4096, "", "", false, &clientcs0, nil)
	}

	runChannelBind(0)
	runChannelBind(tls.VersionTLS12)
}

// Just a cert that appears valid.
func fakeCert(t *testing.T, name string, expired bool) tls.Certificate {
	notAfter := time.Now()
	if expired {
		notAfter = notAfter.Add(-time.Hour)
	} else {
		notAfter = notAfter.Add(time.Hour)
	}

	privKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	localCertBuf, err := x509.CreateCertificate(cryptorand.Reader, template, template, privKey.Public(), privKey)
	if err != nil {
		t.Fatalf("making certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(localCertBuf)
	if err != nil {
		t.Fatalf("parsing generated certificate: %s", err)
	}
	c := tls.Certificate{
		Certificate: [][]byte{localCertBuf},
		PrivateKey:  privKey,
		Leaf:        cert,
	}
	return c
}
