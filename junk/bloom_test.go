package junk

import (
	"fmt"
	"testing"
)

func TestBloom(t *testing.T) {
	if err := BloomValid(3, 10); err == nil {
		t.Fatalf("missing error for invalid bloom filter size")
	}

	_, err := NewBloom(make([]byte, 3), 10)
	if err == nil {
		t.Fatalf("missing error for invalid bloom filter size")
	}

	b, err := NewBloom(make([]byte, 256), 5)
	if err != nil {
		t.Fatalf("newbloom: %s", err)
	}

	absent := func(v string) {
		t.Helper()
		if b.Has(v) {
			t.Fatalf("should be absent: %q", v)
		}
	}

	present := func(v string) {
		t.Helper()
		if !b.Has(v) {
			t.Fatalf("should be present: %q", v)
		}
	}

	absent("test")
	if b.Modified() {
		t.Fatalf("bloom filter already modified?")
	}
	b.Add("test")
	present("test")
	present("test")
	words := []string{}
	for i := 'a'; i <= 'z'; i++ {
		words = append(words, fmt.Sprintf("%c", i))
	}
	for _, w := range words {
		absent(w)
		b.Add(w)
		present(w)
	}
	for _, w := range words {
		present(w)
	}
	if !b.Modified() {
		t.Fatalf("bloom filter was not modified?")
	}

	//log.Infof("ones: %d, m %d", b.Ones(), len(b.Bytes())*8)
}

func TestBits(t *testing.T) {
	b := &bits{width: 1, buf: []byte{0xff, 0xff}}
	for range 16 {
		if b.nextPos() != 1 {
			t.Fatalf("pos not 1")
		}
	}
	b = &bits{width: 2, buf: []byte{0xff, 0xff}}
	for range 8 {
		if b.nextPos() != 0b11 {
			t.Fatalf("pos not 0b11")
		}
	}

	b = &bits{width: 1, buf: []byte{0b10101010, 0b10101010}}
	for i := range 16 {
		if b.nextPos() != ((i + 1) % 2) {
			t.Fatalf("bad pos")
		}
	}
	b = &bits{width: 2, buf: []byte{0b10101010, 0b10101010}}
	for range 8 {
		if b.nextPos() != 0b10 {
			t.Fatalf("pos not 0b10")
		}
	}
}

func TestSet(t *testing.T) {
	b := &Bloom{
		data: []byte{
			0b10101010,
			0b00000000,
			0b11111111,
			0b01010101,
		},
	}
	for i := range 8 {
		v := b.has(i)
		if v != (i%2 == 0) {
			t.Fatalf("bad has")
		}
	}
	for i := 8; i < 16; i++ {
		if b.has(i) {
			t.Fatalf("bad has")
		}
	}
	for i := 16; i < 24; i++ {
		if !b.has(i) {
			t.Fatalf("bad has")
		}
	}
	for i := 24; i < 32; i++ {
		v := b.has(i)
		if v != (i%2 != 0) {
			t.Fatalf("bad has")
		}
	}
}

func TestOnes(t *testing.T) {
	ones := func(b *Bloom, x int) {
		t.Helper()
		n := b.Ones()
		if n != x {
			t.Fatalf("ones: got %d, expected %d", n, x)
		}
	}
	ones(&Bloom{data: []byte{0b10101010}}, 4)
	ones(&Bloom{data: []byte{0b01010101}}, 4)
	ones(&Bloom{data: []byte{0b11111111}}, 8)
	ones(&Bloom{data: []byte{0b00000000}}, 0)
}
