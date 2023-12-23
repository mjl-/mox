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
	"crypto/tls"
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

func channelBindData(cs *tls.ConnectionState) ([]byte, error) {
	if cs.Version <= tls.VersionTLS12 {
		if cs.TLSUnique == nil {
			return nil, fmt.Errorf("no channel binding data available")
		}
		return cs.TLSUnique, nil
	}

	// "tls-exporter", ../rfc/9266:95
	// Since TLS 1.3, a zero-length and absent context have the same behaviour. ../rfc/8446:5385 ../rfc/8446:5405
	// This is different from TLS 1.2 and earlier. ../rfc/5705:206 ../rfc/5705:245
	return cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", []byte{}, 32)
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
	channelBinding      []byte
}

// NewServer returns a server given the first SCRAM message from a client.
//
// If cs is set, the PLUS variant can be negotiated, binding the authentication
// exchange to the TLS channel (preventing MitM attempts). If a client
// indicates it supports the PLUS variant, but thinks the server does not, the
// authentication attempt will fail.
//
// If channelBindingRequired is set, the client has indicated it will do channel
// binding and not doing so will cause the authentication to fail.
//
// The sequence for data and calls on a server:
//
//   - Read initial data from client, call NewServer (this call), then ServerFirst and write to the client.
//   - Read response from client, call Finish or FinishFinal and write the resulting string.
func NewServer(h func() hash.Hash, clientFirst []byte, cs *tls.ConnectionState, channelBindingRequired bool) (server *Server, rerr error) {
	p := newParser(clientFirst)
	defer p.recover(&rerr)

	server = &Server{h: h}

	// ../rfc/5802:949 ../rfc/5802:910
	gs2cbindFlag := p.xbyte()
	switch gs2cbindFlag {
	case 'n':
		// Client does not support channel binding.
		if channelBindingRequired {
			p.xerrorf("channel binding is required when specifying scram plus: %w", ErrChannelBindingsDontMatch)
		}
	case 'y':
		// Client supports channel binding but thinks we as server do not.
		p.xerrorf("gs2 channel bind flag is y, client believes server does not support channel binding: %w", ErrServerDoesSupportChannelBinding)
	case 'p':
		// Use channel binding.
		// It seems a cyrus-sasl client tells a server it is using the bare (non-PLUS)
		// scram authentication mechanism, but then does use channel binding. It seems to
		// use the server announcement of the plus variant only to learn the server
		// supports channel binding.
		p.xtake("=")
		cbname := p.xcbname()
		// Assume the channel binding name is case-sensitive, and lower-case as used in
		// examples. The ABNF rule accepts both lower and upper case. But the ABNF for
		// attribute names also allows that, while the text claims they are case
		// sensitive... ../rfc/5802:547
		switch cbname {
		case "tls-unique":
			if cs == nil {
				p.xerrorf("no tls connection: %w", ErrChannelBindingsDontMatch)
			} else if cs.Version >= tls.VersionTLS13 {
				// ../rfc/9266:122
				p.xerrorf("tls-unique not defined for tls 1.3 and later, use tls-exporter: %w", ErrChannelBindingsDontMatch)
			} else if cs.TLSUnique == nil {
				// As noted in the crypto/tls documentation.
				p.xerrorf("no tls-unique channel binding value for this tls connection, possibly due to missing extended master key support and/or resumed connection: %w", ErrChannelBindingsDontMatch)
			}
		case "tls-exporter":
			if cs == nil {
				p.xerrorf("no tls connection: %w", ErrChannelBindingsDontMatch)
			} else if cs.Version < tls.VersionTLS13 {
				// Using tls-exporter with pre-1.3 TLS would require more precautions. Perhaps later.
				// ../rfc/9266:201
				p.xerrorf("tls-exporter with tls before 1.3 not implemented, use tls-unique: %w", ErrChannelBindingsDontMatch)
			}
		default:
			p.xerrorf("unknown parameter p %s: %w", cbname, ErrUnsupportedChannelBindingType)
		}
		cb, err := channelBindData(cs)
		if err != nil {
			// We can pass back the error, it should never contain sensitive data, and only
			// happen due to incorrect calling or a TLS config that is currently impossible
			// (renegotiation enabled).
			p.xerrorf("error fetching channel binding data: %v: %w", err, ErrOtherError)
		}
		server.channelBinding = cb
	default:
		p.xerrorf("unrecognized gs2 channel bind flag")
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

	// ../rfc/5802:632
	// ../rfc/5802:946
	if p.take("m=") {
		p.xerrorf("unexpected mandatory extension: %w", ErrExtensionsNotSupported) // ../rfc/5802:973
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

	// If there is any channel binding, and it doesn't match, this may be a
	// MitM-attack. If the MitM would replace the channel binding, the signature
	// calculated below would not match.
	cbind := p.xchannelBinding()
	cbindExp := append([]byte(s.gs2header), s.channelBinding...)
	if !bytes.Equal(cbind, cbindExp) {
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

	authMsg := s.clientFirstBare + "," + s.serverFirst + "," + s.clientFinalWithoutProof

	clientKey := hmac0(s.h, saltedPassword, "Client Key")
	h := s.h()
	h.Write(clientKey)
	storedKey := h.Sum(nil)

	clientSig := hmac0(s.h, storedKey, authMsg)
	xor(clientSig, clientKey) // Now clientProof.
	if !bytes.Equal(clientSig, proof) {
		return "e=" + string(ErrInvalidProof), ErrInvalidProof
	}

	serverKey := hmac0(s.h, saltedPassword, "Server Key")
	serverSig := hmac0(s.h, serverKey, authMsg)
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

	h            func() hash.Hash     // sha1.New or sha256.New
	noServerPlus bool                 // Server did not announce support for PLUS-variant.
	cs           *tls.ConnectionState // If set, use PLUS-variant.

	// Messages used in hash calculations.
	clientFirstBare         string
	serverFirst             string
	clientFinalWithoutProof string
	authMessage             string

	gs2header       string
	clientNonce     string
	nonce           string // Full client + server nonce.
	saltedPassword  []byte
	channelBindData []byte // For PLUS-variant.
}

// NewClient returns a client for authentication authc, optionally for
// authorization with role authz, for the hash (sha1.New or sha256.New).
//
// If noServerPlus is true, the client would like to have used the PLUS-variant,
// that binds the authentication attempt to the TLS connection, but the client did
// not see support for the PLUS variant announced by the server. Used during
// negotiation to detect possible MitM attempt.
//
// If cs is not nil, the SCRAM PLUS-variant is negotiated, with channel binding to
// the unique TLS connection, either using "tls-exporter" for TLS 1.3 and later, or
// "tls-unique" otherwise.
//
// If cs is nil, no channel binding is done. If noServerPlus is also false, the
// client is configured to not attempt/"support" the PLUS-variant, ensuring servers
// that do support the PLUS-variant do not abort the connection.
//
// The sequence for data and calls on a client:
//
//   - ClientFirst, write result to server.
//   - Read response from server, feed to ServerFirst, write response to server.
//   - Read response from server, feed to ServerFinal.
func NewClient(h func() hash.Hash, authc, authz string, noServerPlus bool, cs *tls.ConnectionState) *Client {
	authc = norm.NFC.String(authc)
	authz = norm.NFC.String(authz)
	return &Client{authc: authc, authz: authz, h: h, noServerPlus: noServerPlus, cs: cs}
}

// ClientFirst returns the first client message to write to the server.
// No channel binding is done/supported.
// A random nonce is generated.
func (c *Client) ClientFirst() (clientFirst string, rerr error) {
	if c.noServerPlus && c.cs != nil {
		return "", fmt.Errorf("cannot set both claim channel binding is not supported, and use channel binding")
	}
	// The first byte of the gs2header indicates if/how channel binding should be used.
	// ../rfc/5802:903
	if c.cs != nil {
		if c.cs.Version >= tls.VersionTLS13 {
			c.gs2header = "p=tls-exporter"
		} else {
			c.gs2header = "p=tls-unique"
		}
		cbdata, err := channelBindData(c.cs)
		if err != nil {
			return "", fmt.Errorf("get channel binding data: %v", err)
		}
		c.channelBindData = cbdata
	} else if c.noServerPlus {
		// We support it, but we think server does not. If server does support it, we may
		// have been downgraded, and the server will tell us.
		c.gs2header = "y"
	} else {
		// We don't want to do channel binding.
		c.gs2header = "n"
	}
	c.gs2header += fmt.Sprintf(",%s,", saslname(c.authz))
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

	// ../rfc/5802:632
	// ../rfc/5802:959
	if p.take("m=") {
		p.xerrorf("unsupported mandatory extension: %w", ErrExtensionsNotSupported) // ../rfc/5802:973
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

	// We send our channel binding data if present. If the server has different values,
	// we'll get an error. If any MitM would try to modify the channel binding data,
	// the server cannot verify our signature and will fail the attempt.
	// ../rfc/5802:925 ../rfc/5802:1015
	cbindInput := append([]byte(c.gs2header), c.channelBindData...)
	c.clientFinalWithoutProof = fmt.Sprintf("c=%s,r=%s", base64.StdEncoding.EncodeToString(cbindInput), c.nonce)

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
