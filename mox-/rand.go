package mox

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"sync"
)

type rand struct {
	rand *mathrand.Rand
	sync.Mutex
}

// NewPseudoRand returns a new PRNG seeded with random bytes from crypto/rand. Its
// functions can be called concurrently.
func NewPseudoRand() *rand {
	return &rand{rand: mathrand.New(mathrand.NewSource(CryptoRandInt()))}
}

func (r *rand) Float64() float64 {
	r.Lock()
	defer r.Unlock()
	return r.rand.Float64()
}

func (r *rand) Intn(n int) int {
	r.Lock()
	defer r.Unlock()
	return r.rand.Intn(n)
}

func (r *rand) Read(buf []byte) (int, error) {
	r.Lock()
	defer r.Unlock()
	return r.rand.Read(buf)
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
