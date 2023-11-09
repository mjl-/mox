package mox

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"sync"
)

type rand struct {
	*mathrand.Rand
	sync.Mutex
}

// NewPseudoRand returns a new PRNG seeded with random bytes from crypto/rand.
func NewPseudoRand() *rand {
	return &rand{Rand: mathrand.New(mathrand.NewSource(CryptoRandInt()))}
}

// Read can be called concurrently.
func (r *rand) Read(buf []byte) (int, error) {
	r.Lock()
	defer r.Unlock()
	return r.Rand.Read(buf)
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
