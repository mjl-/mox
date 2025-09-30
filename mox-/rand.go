package mox

import (
	cryptorand "crypto/rand"
	"encoding/binary"
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
	cryptorand.Read(seed[:])
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
	var buf [8]byte
	cryptorand.Read(buf[:])
	return int64(binary.LittleEndian.Uint64(buf[:]))
}
