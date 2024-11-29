package mox

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	mathrand2 "math/rand/v2"
	"sync"
)

type rand struct {
	rand *mathrand2.Rand
	sync.Mutex
}

// NewPseudoRand returns a new PRNG seeded with random bytes from crypto/rand. Its
// functions can be called concurrently.
func NewPseudoRand() *rand {
	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		panic(err)
	}
	return &rand{rand: mathrand2.New(mathrand2.NewChaCha8(seed))}
}

func (r *rand) Float64() float64 {
	r.Lock()
	defer r.Unlock()
	return r.rand.Float64()
}

func (r *rand) IntN(n int) int {
	r.Lock()
	defer r.Unlock()
	return r.rand.IntN(n)
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
