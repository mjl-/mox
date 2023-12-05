package moxio

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/mlog"
)

// todo: instead of a bufpool, should maybe just make an alternative to bufio.Reader with a big enough buffer that we can fully use to read a line.

var ErrLineTooLong = errors.New("line from remote too long") // Returned by Bufpool.Readline.

// Bufpool caches byte slices for reuse during parsing of line-terminated commands.
type Bufpool struct {
	c    chan []byte
	size int
}

// NewBufpool makes a new pool, initially empty, but holding at most "max" buffers of "size" bytes each.
func NewBufpool(max, size int) *Bufpool {
	return &Bufpool{
		c:    make(chan []byte, max),
		size: size,
	}
}

// get returns a buffer from the pool if available, otherwise allocates a new buffer.
// The buffer should be returned with a call to put.
func (b *Bufpool) get() []byte {
	var buf []byte

	// Attempt to get buffer from pool. Otherwise create new buffer.
	select {
	case buf = <-b.c:
	default:
	}
	if buf == nil {
		buf = make([]byte, b.size)
	}
	return buf
}

// put puts a "buf" back in the pool. Put clears the first "n" bytes, which should
// be all the bytes that have been read in the buffer. If the pool is full, the
// buffer is discarded, and will be cleaned up by the garbage collector.
// The caller should no longer reference "buf" after a call to put.
func (b *Bufpool) put(log mlog.Log, buf []byte, n int) {
	if len(buf) != b.size {
		log.Error("buffer with bad size returned, ignoring", slog.Int("badsize", len(buf)), slog.Int("expsize", b.size))
		return
	}

	for i := 0; i < n; i++ {
		buf[i] = 0
	}
	select {
	case b.c <- buf:
	default:
	}
}

// Readline reads a \n- or \r\n-terminated line. Line is returned without \n or \r\n.
// If the line was too long, ErrLineTooLong is returned.
// If an EOF is encountered before a \n, io.ErrUnexpectedEOF is returned.
func (b *Bufpool) Readline(log mlog.Log, r *bufio.Reader) (line string, rerr error) {
	var nread int
	buf := b.get()
	defer func() {
		b.put(log, buf, nread)
	}()

	// Read until newline. If we reach the end of the buffer first, we write back an
	// error and abort the connection because our protocols cannot be recovered. We
	// don't want to consume data until we finally see a newline, which may be never.
	for {
		if nread >= len(buf) {
			return "", fmt.Errorf("%w: no newline after all %d bytes", ErrLineTooLong, nread)
		}
		c, err := r.ReadByte()
		if err == io.EOF {
			return "", io.ErrUnexpectedEOF
		} else if err != nil {
			return "", fmt.Errorf("reading line from remote: %w", err)
		}
		if c == '\n' {
			var s string
			if nread > 0 && buf[nread-1] == '\r' {
				s = string(buf[:nread-1])
			} else {
				s = string(buf[:nread])
			}
			nread++
			return s, nil
		}
		buf[nread] = c
		nread++
	}
}
