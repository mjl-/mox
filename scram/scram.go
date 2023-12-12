// Package scram implements the SCRAM-SHA-* SASL authentication mechanism, RFC 7677 and RFC 5802.
//
// SCRAM-SHA-256 and SCRAM-SHA-1 allow a client to authenticate to a server using a
// password without handing plaintext password over to the server. The client also
// verifies the server knows (a derivative of) the password. Both the client and
// server side are implemented.
package scram

// todo: test with messages that contains extensions
// todo: some tests for the parser
// todo: figure out how invalid parameters etc should be handled. just abort? perhaps mostly a problem for imap.

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

// Errors at scram protocol level. Can be exchanged between client and server.
var (
	ErrInvalidEncoding                 Error = "invalid-encoding"
	ErrExtensionsNotSupported          Error = "extensions-not-supported"
	ErrInvalidProof                    Error = "invalid-proof"
	ErrChannelBindingsDontMatch        Error = "channel-bindings-dont-match"
	ErrServerDoesSupportChannelBinding Error = "server-does-support-channel-binding"
	ErrChannelBindingNotSupported      Error = "channel-binding-not-supported"
	ErrUnsupportedChannelBindingType   Error = "unsupported-channel-binding-type"
	ErrUnknownUser                     Error = "unknown-user"
	ErrNoResources                     Error = "no-resources"
	ErrOtherError                      Error = "other-error"
)

var scramErrors = makeErrors()

func makeErrors() map[string]Error {
	l := []Error{
		ErrInvalidEncoding,
		ErrExtensionsNotSupported,
		ErrInvalidProof,
		ErrChannelBindingsDontMatch,
		ErrServerDoesSupportChannelBinding,
		ErrChannelBindingNotSupported,
		ErrUnsupportedChannelBindingType,
		ErrUnknownUser,
		ErrNoResources,
		ErrOtherError,
	}
	m := map[string]Error{}
	for _, e := range l {
		m[string(e)] = e
	}
	return m
}

var (
	ErrNorm     = errors.New("parameter not unicode normalized") // E.g. if client sends non-normalized username or authzid.
	ErrUnsafe   = errors.New("unsafe parameter")                 // E.g. salt, nonce too short, or too few iterations.
	ErrProtocol = errors.New("protocol error")                   // E.g. server responded with a nonce not prefixed by the client nonce.
)

type Error string

func (e Error) Error() string {
	return string(e)
}

// MakeRandom returns a cryptographically random buffer for use as salt or as
// nonce.
func MakeRandom() []byte {
	buf := make([]byte, 12)
	_, err := cryptorand.Read(buf)
	if err != nil {
		panic("generate random")
	}
	return buf
}

// SaltPassword returns a salted password.
func SaltPassword(h func() hash.Hash, password string, salt []byte, iterations int) []byte {
	password = norm.NFC.String(password)
	return pbkdf2.Key([]byte(password), salt, iterations, h().Size(), h)
}

// hmac0 returns the hmac with key over msg.
func hmac0(h func() hash.Hash, key []byte, msg string) []byte {
	mac := hmac.New(h, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func xor(a, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

// Server represents the server-side of a SCRAM-SHA-* authentication.
type Server struct {
	Authentication string // Username for authentication, "authc". Always set and non-empty.
	Authorization  string // If set, role of user to assume after authentication, "authz".

	h func() hash.Hash // sha1.New or sha256.New

	// Messages used in hash calculations.
	clientFirstBare         string
	serverFirst             string
	clientFinalWithoutProof string

	gs2header           string
	clientNonce         string // Client-part of the nonce.
	serverNonceOverride string // If set, server does not generate random nonce, but uses this. For tests with the test vector.
	nonce               string // Full client + server nonce.
}

// NewServer returns a server given the first SCRAM message from a client.
//
// The sequence for data and calls on a server:
//
//   - Read initial data from client, call NewServer (this call), then ServerFirst and write to the client.
//   - Read response from client, call Finish or FinishFinal and write the resulting string.
func NewServer(h func() hash.Hash, clientFirst []byte) (server *Server, rerr error) {
	p := newParser(clientFirst)
	defer p.recover(&rerr)

	server = &Server{h: h}

	// ../rfc/5802:949 ../rfc/5802:910
	gs2cbindFlag := p.xbyte()
	switch gs2cbindFlag {
	case 'n', 'y':
	case 'p':
		p.xerrorf("gs2 header with p: %w", ErrChannelBindingNotSupported)
	}
	p.xtake(",")
	if !p.take(",") {
		server.Authorization = p.xauthzid()
		if norm.NFC.String(server.Authorization) != server.Authorization {
			return nil, fmt.Errorf("%w: authzid", ErrNorm)
		}
		p.xtake(",")
	}
	server.gs2header = p.s[:p.o]
	server.clientFirstBare = p.s[p.o:]

	// ../rfc/5802:945
	if p.take("m=") {
		p.xerrorf("unexpected mandatory extension: %w", ErrExtensionsNotSupported)
	}
	server.Authentication = p.xusername()
	if norm.NFC.String(server.Authentication) != server.Authentication {
		return nil, fmt.Errorf("%w: username", ErrNorm)
	}
	p.xtake(",")
	server.clientNonce = p.xnonce()
	if len(server.clientNonce) < 8 {
		return nil, fmt.Errorf("%w: client nonce too short", ErrUnsafe)
	}
	// Extensions, we don't recognize them.
	for p.take(",") {
		p.xattrval()
	}
	p.xempty()
	return server, nil
}

// ServerFirst returns the string to send back to the client. To be called after NewServer.
func (s *Server) ServerFirst(iterations int, salt []byte) (string, error) {
	// ../rfc/5802:959
	serverNonce := s.serverNonceOverride
	if serverNonce == "" {
		serverNonce = base64.StdEncoding.EncodeToString(MakeRandom())
	}
	s.nonce = s.clientNonce + serverNonce
	s.serverFirst = fmt.Sprintf("r=%s,s=%s,i=%d", s.nonce, base64.StdEncoding.EncodeToString(salt), iterations)
	return s.serverFirst, nil
}

// Finish takes the final client message, and the salted password (probably
// from server storage), verifies the client, and returns a message to return
// to the client. If err is nil, authentication was successful. If the
// authorization requested is not acceptable, the server should call
// FinishError instead.
func (s *Server) Finish(clientFinal []byte, saltedPassword []byte) (serverFinal string, rerr error) {
	p := newParser(clientFinal)
	defer p.recover(&rerr)

	cbind := p.xchannelBinding()
	if cbind != s.gs2header {
		return "e=" + string(ErrChannelBindingsDontMatch), ErrChannelBindingsDontMatch
	}
	p.xtake(",")
	nonce := p.xnonce()
	if nonce != s.nonce {
		return "e=" + string(ErrInvalidProof), ErrInvalidProof
	}
	for !p.peek(",p=") {
		p.xtake(",")
		p.xattrval() // Ignored.
	}
	s.clientFinalWithoutProof = p.s[:p.o]
	p.xtake(",")
	proof := p.xproof()
	p.xempty()

	msg := s.clientFirstBare + "," + s.serverFirst + "," + s.clientFinalWithoutProof

	clientKey := hmac0(s.h, saltedPassword, "Client Key")
	h := s.h()
	h.Write(clientKey)
	storedKey := h.Sum(nil)

	clientSig := hmac0(s.h, storedKey, msg)
	xor(clientSig, clientKey) // Now clientProof.
	if !bytes.Equal(clientSig, proof) {
		return "e=" + string(ErrInvalidProof), ErrInvalidProof
	}

	serverKey := hmac0(s.h, saltedPassword, "Server Key")
	serverSig := hmac0(s.h, serverKey, msg)
	return fmt.Sprintf("v=%s", base64.StdEncoding.EncodeToString(serverSig)), nil
}

// FinishError returns an error message to write to the client for the final
// server message.
func (s *Server) FinishError(err Error) string {
	return "e=" + string(err)
}

// Client represents the client-side of a SCRAM-SHA-* authentication.
type Client struct {
	authc string
	authz string

	h func() hash.Hash // sha1.New or sha256.New

	// Messages used in hash calculations.
	clientFirstBare         string
	serverFirst             string
	clientFinalWithoutProof string
	authMessage             string

	gs2header      string
	clientNonce    string
	nonce          string // Full client + server nonce.
	saltedPassword []byte
}

// NewClient returns a client for authentication authc, optionally for
// authorization with role authz, for the hash (sha1.New or sha256.New).
//
// The sequence for data and calls on a client:
//
//   - ClientFirst, write result to server.
//   - Read response from server, feed to ServerFirst, write response to server.
//   - Read response from server, feed to ServerFinal.
func NewClient(h func() hash.Hash, authc, authz string) *Client {
	authc = norm.NFC.String(authc)
	authz = norm.NFC.String(authz)
	return &Client{authc: authc, authz: authz, h: h}
}

// ClientFirst returns the first client message to write to the server.
// No channel binding is done/supported.
// A random nonce is generated.
func (c *Client) ClientFirst() (clientFirst string, rerr error) {
	c.gs2header = fmt.Sprintf("n,%s,", saslname(c.authz))
	if c.clientNonce == "" {
		c.clientNonce = base64.StdEncoding.EncodeToString(MakeRandom())
	}
	c.clientFirstBare = fmt.Sprintf("n=%s,r=%s", saslname(c.authc), c.clientNonce)
	return c.gs2header + c.clientFirstBare, nil
}

// ServerFirst processes the first response message from the server. The
// provided nonce, salt and iterations are checked. If valid, a final client
// message is calculated and returned. This message must be written to the
// server. It includes proof that the client knows the password.
func (c *Client) ServerFirst(serverFirst []byte, password string) (clientFinal string, rerr error) {
	c.serverFirst = string(serverFirst)
	p := newParser(serverFirst)
	defer p.recover(&rerr)

	// ../rfc/5802:959
	if p.take("m=") {
		p.xerrorf("unsupported mandatory extension: %w", ErrExtensionsNotSupported)
	}

	c.nonce = p.xnonce()
	p.xtake(",")
	salt := p.xsalt()
	p.xtake(",")
	iterations := p.xiterations()
	// We ignore extensions that we don't know about.
	for p.take(",") {
		p.xattrval()
	}
	p.xempty()

	if !strings.HasPrefix(c.nonce, c.clientNonce) {
		return "", fmt.Errorf("%w: server dropped our nonce", ErrProtocol)
	}
	if len(c.nonce)-len(c.clientNonce) < 8 {
		return "", fmt.Errorf("%w: server nonce too short", ErrUnsafe)
	}
	if len(salt) < 8 {
		return "", fmt.Errorf("%w: salt too short", ErrUnsafe)
	}
	if iterations < 2048 {
		return "", fmt.Errorf("%w: too few iterations", ErrUnsafe)
	}

	c.clientFinalWithoutProof = fmt.Sprintf("c=%s,r=%s", base64.StdEncoding.EncodeToString([]byte(c.gs2header)), c.nonce)

	c.authMessage = c.clientFirstBare + "," + c.serverFirst + "," + c.clientFinalWithoutProof

	c.saltedPassword = SaltPassword(c.h, password, salt, iterations)
	clientKey := hmac0(c.h, c.saltedPassword, "Client Key")
	h := c.h()
	h.Write(clientKey)
	storedKey := h.Sum(nil)
	clientSig := hmac0(c.h, storedKey, c.authMessage)
	xor(clientSig, clientKey) // Now clientProof.
	clientProof := clientSig

	r := c.clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)
	return r, nil
}

// ServerFinal processes the final message from the server, verifying that the
// server knows the password.
func (c *Client) ServerFinal(serverFinal []byte) (rerr error) {
	p := newParser(serverFinal)
	defer p.recover(&rerr)

	if p.take("e=") {
		errstr := p.xvalue()
		var err error = scramErrors[errstr]
		if err == Error("") {
			err = errors.New(errstr)
		}
		return fmt.Errorf("error from server: %w", err)
	}
	p.xtake("v=")
	verifier := p.xbase64()

	serverKey := hmac0(c.h, c.saltedPassword, "Server Key")
	serverSig := hmac0(c.h, serverKey, c.authMessage)
	if !bytes.Equal(verifier, serverSig) {
		return fmt.Errorf("incorrect server signature")
	}
	return nil
}

// Convert "," to =2C and "=" to =3D.
func saslname(s string) string {
	var r string
	for _, c := range s {
		if c == ',' {
			r += "=2C"
		} else if c == '=' {
			r += "=3D"
		} else {
			r += string(c)
		}
	}
	return r
}
