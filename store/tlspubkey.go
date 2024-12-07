package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
)

// TLSPublicKey is a public key for use with TLS client authentication based on the
// public key of the certificate.
type TLSPublicKey struct {
	// Raw-url-base64-encoded Subject Public Key Info of certificate.
	Fingerprint string
	Created     time.Time `bstore:"nonzero,default now"`
	Type        string    // E.g. "rsa-2048", "ecdsa-p256", "ed25519"

	// Descriptive name to identify the key, e.g. the device where key is used.
	Name string `bstore:"nonzero"`

	// If set, new immediate authenticated TLS connections are not moved to
	// "authenticated" state. For clients that don't understand it, and will try an
	// authenticate command anyway.
	NoIMAPPreauth bool

	CertDER      []byte `bstore:"nonzero"`
	Account      string `bstore:"nonzero"` // Key authenticates this account.
	LoginAddress string `bstore:"nonzero"` // Must belong to account.
}

// AuthDB and AuthDBTypes are exported for ../backup.go.
var AuthDB *bstore.DB
var AuthDBTypes = []any{TLSPublicKey{}}

// Init opens auth.db.
func Init(ctx context.Context) error {
	if AuthDB != nil {
		return fmt.Errorf("already initialized")
	}
	pkglog := mlog.New("store", nil)
	p := mox.DataDirPath("auth.db")
	os.MkdirAll(filepath.Dir(p), 0770)
	opts := bstore.Options{Timeout: 5 * time.Second, Perm: 0660, RegisterLogger: pkglog.Logger}
	var err error
	AuthDB, err = bstore.Open(ctx, p, &opts, AuthDBTypes...)
	return err
}

// Close closes auth.db.
func Close() error {
	if AuthDB == nil {
		return fmt.Errorf("not open")
	}
	err := AuthDB.Close()
	AuthDB = nil
	return err
}

// ParseTLSPublicKeyCert parses a certificate, preparing a TLSPublicKey for
// insertion into the database. Caller must set fields that are not in the
// certificat, such as Account and LoginAddress.
func ParseTLSPublicKeyCert(certDER []byte) (TLSPublicKey, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return TLSPublicKey{}, fmt.Errorf("parsing certificate: %v", err)
	}
	name := cert.Subject.CommonName
	if name == "" && cert.SerialNumber != nil {
		name = fmt.Sprintf("serial %x", cert.SerialNumber.Bytes())
	}

	buf := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fp := base64.RawURLEncoding.EncodeToString(buf[:])
	var typ string
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < 2048 {
			return TLSPublicKey{}, fmt.Errorf("rsa keys smaller than 2048 bits not accepted")
		}
		typ = "rsa-" + fmt.Sprintf("%d", bits)
	case *ecdsa.PublicKey:
		typ = "ecdsa-" + strings.ReplaceAll(strings.ToLower(k.Params().Name), "-", "")
	case ed25519.PublicKey:
		typ = "ed25519"
	default:
		return TLSPublicKey{}, fmt.Errorf("public key type %T not implemented", cert.PublicKey)
	}

	return TLSPublicKey{Fingerprint: fp, Type: typ, Name: name, CertDER: certDER}, nil
}

// TLSPublicKeyList returns tls public keys. If accountOpt is empty, keys for all
// accounts are returned.
func TLSPublicKeyList(ctx context.Context, accountOpt string) ([]TLSPublicKey, error) {
	q := bstore.QueryDB[TLSPublicKey](ctx, AuthDB)
	if accountOpt != "" {
		q.FilterNonzero(TLSPublicKey{Account: accountOpt})
	}
	return q.List()
}

// TLSPublicKeyGet retrieves a single tls public key by fingerprint.
// If absent, bstore.ErrAbsent is returned.
func TLSPublicKeyGet(ctx context.Context, fingerprint string) (TLSPublicKey, error) {
	pubKey := TLSPublicKey{Fingerprint: fingerprint}
	err := AuthDB.Get(ctx, &pubKey)
	return pubKey, err
}

// TLSPublicKeyAdd adds a new tls public key.
//
// Caller is responsible for checking the account and email address are valid.
func TLSPublicKeyAdd(ctx context.Context, pubKey *TLSPublicKey) error {
	if err := checkTLSPublicKeyAddress(pubKey.LoginAddress); err != nil {
		return err
	}
	return AuthDB.Insert(ctx, pubKey)
}

// TLSPublicKeyUpdate updates an existing tls public key.
//
// Caller is responsible for checking the account and email address are valid.
func TLSPublicKeyUpdate(ctx context.Context, pubKey *TLSPublicKey) error {
	if err := checkTLSPublicKeyAddress(pubKey.LoginAddress); err != nil {
		return err
	}
	return AuthDB.Update(ctx, pubKey)
}

func checkTLSPublicKeyAddress(addr string) error {
	a, err := smtp.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("parsing login address %q: %v", addr, err)
	}
	if a.String() != addr {
		return fmt.Errorf("login address %q must be specified in canonical form %q", addr, a.String())
	}
	return nil
}

// TLSPublicKeyRemove removes a tls public key.
func TLSPublicKeyRemove(ctx context.Context, fingerprint string) error {
	k := TLSPublicKey{Fingerprint: fingerprint}
	return AuthDB.Delete(ctx, &k)
}

// TLSPublicKeyRemoveForAccount removes all tls public keys for an account.
func TLSPublicKeyRemoveForAccount(ctx context.Context, account string) error {
	q := bstore.QueryDB[TLSPublicKey](ctx, AuthDB)
	q.FilterNonzero(TLSPublicKey{Account: account})
	_, err := q.Delete()
	return err
}
