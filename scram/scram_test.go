package scram

import (
	"encoding/base64"
	"errors"
	"testing"
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

func TestScramServer(t *testing.T) {
	// Test vector from ../rfc/7677:122
	salt := base64Decode("W22ZaJ0SNY7soEsUEjb6gQ==")
	saltedPassword := SaltPassword("pencil", salt, 4096)

	server, err := NewServer([]byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"))
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
	saltedPassword := SaltPassword("marker", salt, 4096)

	server, err := NewServer([]byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"))
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
	saltedPassword := SaltPassword("pencil", salt, 2048)

	server, err := NewServer([]byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"))
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
	saltedPassword := SaltPassword("pencil", salt, 4096)

	server, err := NewServer([]byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"))
	tcheck(t, err, "newserver")
	_, err = server.ServerFirst(4096, salt)
	tcheck(t, err, "server first")
	_, err = server.Finish([]byte("c=biws,r="+server.nonce+",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="), saltedPassword)
	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("got %v, expected ErrInvalidProof", err)
	}
}

func TestScramClient(t *testing.T) {
	c := NewClient("user", "")
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
	run := func(expErr error, username, authzid, password string, iterations int, clientNonce, serverNonce string) {
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
		saltedPassword := SaltPassword(password, salt, iterations)

		client := NewClient(username, "")
		client.clientNonce = clientNonce
		clientFirst, err := client.ClientFirst()
		xerr(err, "client.ClientFirst")

		server, err := NewServer([]byte(clientFirst))
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

	run(nil, "user", "", "pencil", 4096, "", "")
	run(nil, "mjl@mox.example", "", "testtest", 4096, "", "")
	run(nil, "mjl@mox.example", "", "short", 4096, "", "")
	run(nil, "mjl@mox.example", "", "short", 2048, "", "")
	run(nil, "mjl@mox.example", "mjl@mox.example", "testtest", 4096, "", "")
	run(nil, "mjl@mox.example", "other@mox.example", "testtest", 4096, "", "")
	run(ErrUnsafe, "user", "", "pencil", 1, "", "")                // Few iterations.
	run(ErrUnsafe, "user", "", "pencil", 2048, "short", "")        // Short client nonce.
	run(ErrUnsafe, "user", "", "pencil", 2048, "test1234", "test") // Server added too few random data.
}
