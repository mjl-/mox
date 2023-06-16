// Package SASL implements Simple Authentication and Security Layer, RFC 4422.
package sasl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"

	"github.com/mjl-/mox/scram"
)

// Client is a SASL client
type Client interface {
	// Name as used in SMTP AUTH, e.g. PLAIN, CRAM-MD5, SCRAM-SHA-256.
	// cleartextCredentials indicates if credentials are exchanged in clear text, which influences whether they are logged.
	Info() (name string, cleartextCredentials bool)

	// Next is called for each step of the SASL communication. The first call has a nil
	// fromServer and serves to get a possible "initial response" from the client. If
	// the client sends its final message it indicates so with last. Returning an error
	// aborts the authentication attempt.
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

type clientCRAMMD5 struct {
	Username, Password string
	step               int
}

var _ Client = (*clientCRAMMD5)(nil)

// NewClientCRAMMD5 returns a client for SASL CRAM-MD5 authentication.
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

	name  string
	step  int
	scram *scram.Client
}

var _ Client = (*clientSCRAMSHA)(nil)

// NewClientSCRAMSHA1 returns a client for SASL SCRAM-SHA-1 authentication.
func NewClientSCRAMSHA1(username, password string) Client {
	return &clientSCRAMSHA{username, password, "SCRAM-SHA-1", 0, nil}
}

// NewClientSCRAMSHA256 returns a client for SASL SCRAM-SHA-256 authentication.
func NewClientSCRAMSHA256(username, password string) Client {
	return &clientSCRAMSHA{username, password, "SCRAM-SHA-256", 0, nil}
}

func (a *clientSCRAMSHA) Info() (name string, hasCleartextCredentials bool) {
	return a.name, false
}

func (a *clientSCRAMSHA) Next(fromServer []byte) (toServer []byte, last bool, rerr error) {
	defer func() { a.step++ }()
	switch a.step {
	case 0:
		var h func() hash.Hash
		switch a.name {
		case "SCRAM-SHA-1":
			h = sha1.New
		case "SCRAM-SHA-256":
			h = sha256.New
		default:
			return nil, false, fmt.Errorf("invalid SCRAM-SHA variant %q", a.name)
		}

		a.scram = scram.NewClient(h, a.Username, "")
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
