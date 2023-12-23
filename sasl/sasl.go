// Package SASL implements Simple Authentication and Security Layer, RFC 4422.
package sasl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"hash"
	"strings"

	"github.com/mjl-/mox/scram"
)

// Client is a SASL client.
//
// A SASL client can be used for authentication in IMAP, SMTP and other protocols.
// A client and server exchange messages in step lock. In IMAP and SMTP, these
// messages are encoded with base64. Each SASL mechanism has predefined steps, but
// the transaction can be aborted by either side at any time. An IMAP or SMTP
// client must choose a SASL mechanism, instantiate a SASL client, and call Next
// with a nil parameter. The resulting data must be written to the server, properly
// encoded. The client must then read the response from the server and feed it to
// the SASL client, which will return more data to send, or an error.
type Client interface {
	// Name as used in SMTP or IMAP authentication, e.g. PLAIN, CRAM-MD5,
	// SCRAM-SHA-256. cleartextCredentials indicates if credentials are exchanged in
	// clear text, which can be used to decide if the exchange is logged.
	Info() (name string, cleartextCredentials bool)

	// Next must be called for each step of the SASL transaction. The first call has a
	// nil fromServer and serves to get a possible "initial response" from the client
	// to the server. When last is true, the message from client to server is the last
	// one, and the server must send a verdict. If err is set, the transaction must be
	// aborted.
	//
	// For the first toServer ("initial response"), a nil toServer indicates there is
	// no data, which is different from a non-nil zero-length toServer.
	Next(fromServer []byte) (toServer []byte, last bool, err error)
}

type clientPlain struct {
	Username, Password string
	step               int
}

var _ Client = (*clientPlain)(nil)

// NewClientPlain returns a client for SASL PLAIN authentication.
//
// PLAIN is specified in RFC 4616, The PLAIN Simple Authentication and Security
// Layer (SASL) Mechanism.
func NewClientPlain(username, password string) Client {
	return &clientPlain{username, password, 0}
}

func (a *clientPlain) Info() (name string, hasCleartextCredentials bool) {
	return "PLAIN", true
}

func (a *clientPlain) Next(fromServer []byte) (toServer []byte, last bool, rerr error) {
	defer func() { a.step++ }()
	switch a.step {
	case 0:
		return []byte(fmt.Sprintf("\u0000%s\u0000%s", a.Username, a.Password)), true, nil
	default:
		return nil, false, fmt.Errorf("invalid step %d", a.step)
	}
}

type clientLogin struct {
	Username, Password string
	step               int
}

var _ Client = (*clientLogin)(nil)

// NewClientLogin returns a client for the obsolete SASL LOGIN authentication.
//
// See https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
func NewClientLogin(username, password string) Client {
	return &clientLogin{username, password, 0}
}

func (a *clientLogin) Info() (name string, hasCleartextCredentials bool) {
	return "LOGIN", true
}

func (a *clientLogin) Next(fromServer []byte) (toServer []byte, last bool, rerr error) {
	defer func() { a.step++ }()
	switch a.step {
	case 0:
		return []byte(a.Username), false, nil
	case 1:
		return []byte(a.Password), true, nil
	default:
		return nil, false, fmt.Errorf("invalid step %d", a.step)
	}
}

type clientCRAMMD5 struct {
	Username, Password string
	step               int
}

var _ Client = (*clientCRAMMD5)(nil)

// NewClientCRAMMD5 returns a client for SASL CRAM-MD5 authentication.
//
// CRAM-MD5 is specified in RFC 2195, IMAP/POP AUTHorize Extension for Simple
// Challenge/Response.
func NewClientCRAMMD5(username, password string) Client {
	return &clientCRAMMD5{username, password, 0}
}

func (a *clientCRAMMD5) Info() (name string, hasCleartextCredentials bool) {
	return "CRAM-MD5", false
}

func (a *clientCRAMMD5) Next(fromServer []byte) (toServer []byte, last bool, rerr error) {
	defer func() { a.step++ }()
	switch a.step {
	case 0:
		return nil, false, nil
	case 1:
		// Validate the challenge.
		// ../rfc/2195:82
		s := string(fromServer)
		if !strings.HasPrefix(s, "<") || !strings.HasSuffix(s, ">") {
			return nil, false, fmt.Errorf("invalid challenge, missing angle brackets")
		}
		t := strings.SplitN(s, ".", 2)
		if len(t) != 2 || t[0] == "" {
			return nil, false, fmt.Errorf("invalid challenge, missing dot or random digits")
		}
		t = strings.Split(t[1], "@")
		if len(t) == 1 || t[0] == "" || t[len(t)-1] == "" {
			return nil, false, fmt.Errorf("invalid challenge, empty timestamp or empty hostname")
		}

		// ../rfc/2195:138
		key := []byte(a.Password)
		if len(key) > 64 {
			t := md5.Sum(key)
			key = t[:]
		}
		ipad := make([]byte, md5.BlockSize)
		opad := make([]byte, md5.BlockSize)
		copy(ipad, key)
		copy(opad, key)
		for i := range ipad {
			ipad[i] ^= 0x36
			opad[i] ^= 0x5c
		}
		ipadh := md5.New()
		ipadh.Write(ipad)
		ipadh.Write([]byte(fromServer))

		opadh := md5.New()
		opadh.Write(opad)
		opadh.Write(ipadh.Sum(nil))

		// ../rfc/2195:88
		return []byte(fmt.Sprintf("%s %x", a.Username, opadh.Sum(nil))), true, nil

	default:
		return nil, false, fmt.Errorf("invalid step %d", a.step)
	}
}

type clientSCRAMSHA struct {
	Username, Password string

	hash func() hash.Hash

	plus bool
	cs   tls.ConnectionState

	// When not doing PLUS variant, this field indicates whether that is because the
	// server doesn't support the PLUS variant. Used for detecting MitM attempts.
	noServerPlus bool

	name  string
	step  int
	scram *scram.Client
}

var _ Client = (*clientSCRAMSHA)(nil)

// NewClientSCRAMSHA1 returns a client for SASL SCRAM-SHA-1 authentication.
//
// Clients should prefer using the PLUS-variant with TLS channel binding, if
// supported by a server. If noServerPlus is set, this mechanism was chosen because
// the PLUS-variant was not supported by the server. If the server actually does
// implement the PLUS variant, this can indicate a MitM attempt, which is detected
// by the server and causes the authentication attempt to be aborted.
//
// SCRAM-SHA-1 is specified in RFC 5802, "Salted Challenge Response Authentication
// Mechanism (SCRAM) SASL and GSS-API Mechanisms".
func NewClientSCRAMSHA1(username, password string, noServerPlus bool) Client {
	return &clientSCRAMSHA{username, password, sha1.New, false, tls.ConnectionState{}, noServerPlus, "SCRAM-SHA-1", 0, nil}
}

// NewClientSCRAMSHA1PLUS returns a client for SASL SCRAM-SHA-1-PLUS authentication.
//
// The PLUS-variant binds the authentication exchange to the TLS connection,
// detecting any MitM attempt.
//
// SCRAM-SHA-1-PLUS is specified in RFC 5802, "Salted Challenge Response
// Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms".
func NewClientSCRAMSHA1PLUS(username, password string, cs tls.ConnectionState) Client {
	return &clientSCRAMSHA{username, password, sha1.New, true, cs, false, "SCRAM-SHA-1-PLUS", 0, nil}
}

// NewClientSCRAMSHA256 returns a client for SASL SCRAM-SHA-256 authentication.
//
// Clients should prefer using the PLUS-variant with TLS channel binding, if
// supported by a server. If noServerPlus is set, this mechanism was chosen because
// the PLUS-variant was not supported by the server. If the server actually does
// implement the PLUS variant, this can indicate a MitM attempt, which is detected
// by the server and causes the authentication attempt to be aborted.
//
// SCRAM-SHA-256 is specified in RFC 7677, "SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
// Simple Authentication and Security Layer (SASL) Mechanisms".
func NewClientSCRAMSHA256(username, password string, noServerPlus bool) Client {
	return &clientSCRAMSHA{username, password, sha256.New, false, tls.ConnectionState{}, noServerPlus, "SCRAM-SHA-256", 0, nil}
}

// NewClientSCRAMSHA256PLUS returns a client for SASL SCRAM-SHA-256-PLUS authentication.
//
// The PLUS-variant binds the authentication exchange to the TLS connection,
// detecting any MitM attempt.
//
// SCRAM-SHA-256-PLUS is specified in RFC 7677, "SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
// Simple Authentication and Security Layer (SASL) Mechanisms".
func NewClientSCRAMSHA256PLUS(username, password string, cs tls.ConnectionState) Client {
	return &clientSCRAMSHA{username, password, sha256.New, true, cs, false, "SCRAM-SHA-256-PLUS", 0, nil}
}

func (a *clientSCRAMSHA) Info() (name string, hasCleartextCredentials bool) {
	return a.name, false
}

func (a *clientSCRAMSHA) Next(fromServer []byte) (toServer []byte, last bool, rerr error) {
	defer func() { a.step++ }()
	switch a.step {
	case 0:
		var cs *tls.ConnectionState
		if a.plus {
			cs = &a.cs
		}
		a.scram = scram.NewClient(a.hash, a.Username, "", a.noServerPlus, cs)
		toserver, err := a.scram.ClientFirst()
		return []byte(toserver), false, err

	case 1:
		clientFinal, err := a.scram.ServerFirst(fromServer, a.Password)
		return []byte(clientFinal), false, err

	case 2:
		err := a.scram.ServerFinal(fromServer)
		return nil, true, err

	default:
		return nil, false, fmt.Errorf("invalid step %d", a.step)
	}
}
