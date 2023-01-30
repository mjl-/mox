package mox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

var idCipher cipher.Block
var idRand []byte

func init() {
	// Init for tests. Overwritten in ../serve.go.
	err := ReceivedIDInit([]byte("0123456701234567"), []byte("01234567"))
	if err != nil {
		panic(err)
	}
}

// ReceivedIDInit sets an AES key (must be 16 bytes) and random buffer (must be
// 8 bytes) for use by ReceivedID.
func ReceivedIDInit(key, rand []byte) error {
	var err error
	idCipher, err = aes.NewCipher(key)
	idRand = rand
	return err
}

// ReceivedID returns an ID for use in a message Received header.
//
// The ID is based on the cid. The cid itself is a counter and would leak the
// number of connections in received headers. Instead they are obfuscated by
// encrypting them with AES with a per-install key and random buffer. This allows
// recovery of the cid based on the id. See subcommand cid.
func ReceivedID(cid int64) string {
	buf := make([]byte, 16)
	copy(buf, idRand)
	binary.BigEndian.PutUint64(buf[8:], uint64(cid))
	idCipher.Encrypt(buf, buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// ReceivedToCid returns the cid given a ReceivedID.
func ReceivedToCid(s string) (cid int64, err error) {
	buf, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("decode base64: %v", err)
	}
	if len(buf) != 16 {
		return 0, fmt.Errorf("bad length, got %d, expect 16", len(buf))
	}
	idCipher.Decrypt(buf, buf)
	if !bytes.Equal(buf[:8], idRand) {
		return 0, fmt.Errorf("rand mismatch")
	}
	cid = int64(binary.BigEndian.Uint64(buf[8:]))
	return cid, nil
}
