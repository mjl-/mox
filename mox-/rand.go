package mox

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
)

// NewRand returns a new PRNG seeded with random bytes from crypto/rand.
func NewRand() *mathrand.Rand {
	return mathrand.New(mathrand.NewSource(CryptoRandInt()))
}

// CryptoRandInt returns a cryptographically random number.
func CryptoRandInt() int64 {
	buf := make([]byte, 8)
	_, err := cryptorand.Read(buf)
	if err != nil {
		panic(fmt.Errorf("reading random bytes: %v", err))
	}
	return int64(binary.LittleEndian.Uint64(buf))
}
