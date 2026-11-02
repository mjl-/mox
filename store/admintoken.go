package store

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/mjl-/bstore"
)

// ErrAdminTokenInvalid is returned for unknown or expired admin tokens.
var ErrAdminTokenInvalid = errors.New("invalid or expired admin token")

// ErrAdminTokenExists is returned when adding a token with a name already in use.
var ErrAdminTokenExists = errors.New("admin token with name already exists")

// AdminToken is a token for authenticating to the admin API with an
// "Authorization: Bearer <token>" header. Only a hash of the token is stored.
type AdminToken struct {
	ID       int64
	Name     string    `bstore:"nonzero,unique"` // Descriptive name, e.g. the purpose of the token.
	Created  time.Time `bstore:"nonzero,default now"`
	Expires  time.Time // Zero means the token does not expire.
	LastUsed time.Time

	// Raw-url-base64-encoded SHA-256 hash of the token.
	TokenHash string `bstore:"nonzero,unique"`
}

func adminTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// AdminTokenList returns all admin tokens.
func AdminTokenList(ctx context.Context) ([]AdminToken, error) {
	return bstore.QueryDB[AdminToken](ctx, AuthDB).SortAsc("Name").List()
}

// AdminTokenAdd generates and stores a new admin token. The returned token is the
// only time the plain token is available. Expires can be zero for no expiration.
func AdminTokenAdd(ctx context.Context, name string, expires time.Time) (string, AdminToken, error) {
	if name == "" {
		return "", AdminToken{}, fmt.Errorf("name required")
	}
	if !expires.IsZero() && !expires.After(time.Now()) {
		return "", AdminToken{}, fmt.Errorf("expiration must be in the future")
	}

	var buf [32]byte
	cryptorand.Read(buf[:])
	token := base64.RawURLEncoding.EncodeToString(buf[:])

	at := AdminToken{Name: name, Expires: expires, TokenHash: adminTokenHash(token)}
	if err := AuthDB.Insert(ctx, &at); err != nil {
		if errors.Is(err, bstore.ErrUnique) {
			return "", AdminToken{}, fmt.Errorf("%w: %q", ErrAdminTokenExists, name)
		}
		return "", AdminToken{}, err
	}
	return token, at, nil
}

// AdminTokenRemove removes an admin token by ID, revoking it.
func AdminTokenRemove(ctx context.Context, id int64) error {
	return AuthDB.Delete(ctx, &AdminToken{ID: id})
}

// AdminTokenVerify looks up the admin token, checks it has not expired, and
// updates its LastUsed time. ErrAdminTokenInvalid is returned for unknown or
// expired tokens.
func AdminTokenVerify(ctx context.Context, token string) (AdminToken, error) {
	if token == "" {
		return AdminToken{}, ErrAdminTokenInvalid
	}
	var at AdminToken
	err := AuthDB.Write(ctx, func(tx *bstore.Tx) error {
		var err error
		at, err = bstore.QueryTx[AdminToken](tx).FilterNonzero(AdminToken{TokenHash: adminTokenHash(token)}).Get()
		if err == bstore.ErrAbsent {
			return ErrAdminTokenInvalid
		} else if err != nil {
			return err
		}
		if !at.Expires.IsZero() && !at.Expires.After(time.Now()) {
			return ErrAdminTokenInvalid
		}
		at.LastUsed = time.Now()
		return tx.Update(&at)
	})
	return at, err
}
