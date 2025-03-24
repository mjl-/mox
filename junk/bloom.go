package junk

import (
	"errors"
	"os"

	"golang.org/x/crypto/blake2b"

	"github.com/mjl-/mox/mlog"
)

// see https://en.wikipedia.org/wiki/Bloom_filter

var errWidth = errors.New("k and width wider than 256 bits and width not more than 32")
var errPowerOfTwo = errors.New("data not a power of two")

// Bloom is a bloom filter.
type Bloom struct {
	data     []byte
	k        int // Number of bits we store/lookup in the bloom filter per value.
	w        int // Number of bits needed to address a single bit position.
	modified bool

	log mlog.Log // For cid logging.
}

func bloomWidth(fileSize int) int {
	w := 0
	for bits := uint32(fileSize * 8); bits > 1; bits >>= 1 {
		w++
	}
	return w
}

// BloomValid returns an error if the bloom file parameters are not correct.
func BloomValid(fileSize int, k int) error {
	_, err := bloomValid(fileSize, k)
	return err
}

func bloomValid(fileSize, k int) (int, error) {
	w := bloomWidth(fileSize)
	if 1<<w != fileSize*8 {
		return 0, errPowerOfTwo
	}
	if k*w > 256 || w > 32 {
		return 0, errWidth
	}
	return w, nil
}

// NewBloom returns a bloom filter with given initial data.
//
// The number of bits in data must be a power of 2.
// K is the number of "hashes" (bits) to store/lookup for each value stored.
// Width is calculated as the number of bits needed to represent a single bit/hash
// position in the data.
//
// For each value stored/looked up, a hash over the value is calculated. The hash
// is split into "k" values that are "width" bits wide, each used to lookup a bit.
// K * width must not exceed 256.
func NewBloom(log mlog.Log, data []byte, k int) (*Bloom, error) {
	w, err := bloomValid(len(data), k)
	if err != nil {
		return nil, err
	}

	return &Bloom{
		data: data,
		k:    k,
		w:    w,
		log:  log,
	}, nil
}

func (b *Bloom) Add(s string) {
	h := hash([]byte(s), b.w)
	for range b.k {
		b.set(h.nextPos())
	}
}

func (b *Bloom) Has(s string) bool {
	h := hash([]byte(s), b.w)
	for range b.k {
		if !b.has(h.nextPos()) {
			return false
		}
	}
	return true
}

func (b *Bloom) Bytes() []byte {
	return b.data
}

func (b *Bloom) Modified() bool {
	return b.modified
}

// Ones returns the number of ones.
func (b *Bloom) Ones() (n int) {
	for _, d := range b.data {
		for range 8 {
			if d&1 != 0 {
				n++
			}
			d >>= 1
		}
	}
	return n
}

func (b *Bloom) Write(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0660)
	if err != nil {
		return err
	}
	if _, err := f.Write(b.data); err != nil {
		xerr := f.Close()
		b.log.Check(xerr, "closing bloom file after write failed")
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	b.modified = false
	return nil
}

func (b *Bloom) has(p int) bool {
	v := b.data[p>>3] >> (7 - (p & 7))
	return v&1 != 0
}

func (b *Bloom) set(p int) {
	by := p >> 3
	bi := p & 0x7
	var v byte = 1 << (7 - bi)
	if b.data[by]&v == 0 {
		b.data[by] |= v
		b.modified = true
	}
}

type bits struct {
	width int    // Number of bits for each position.
	buf   []byte // Remaining bytes to use for next position.
	cur   uint64 // Bits to read next position from. Replenished from buf.
	ncur  int    // Number of bits available in cur. We consume the highest bits first.
}

func hash(v []byte, width int) *bits {
	buf := blake2b.Sum256(v)
	return &bits{width: width, buf: buf[:]}
}

// nextPos returns the next bit position.
func (b *bits) nextPos() (v int) {
	if b.width > b.ncur {
		for len(b.buf) > 0 && b.ncur < 64-8 {
			b.cur <<= 8
			b.cur |= uint64(b.buf[0])
			b.ncur += 8
			b.buf = b.buf[1:]
		}
	}
	v = int((b.cur >> (b.ncur - b.width)) & ((1 << b.width) - 1))
	b.ncur -= b.width
	return v
}
