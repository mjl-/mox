package store

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// MsgReader provides access to a message. Reads return the "MsgPrefix" in the
// database (typically received headers), followed by the on-disk msg file
// contents. MsgReader is an io.Reader, io.ReaderAt and io.Closer.
type MsgReader struct {
	prefix []byte   // First part of the message. Typically contains received headers.
	path   string   // To on-disk message file.
	size   int64    // Total size of message, including prefix and contents from path.
	offset int64    // Current reading offset.
	f      *os.File // Opened path, automatically opened after prefix has been read.
	err    error    // If set, error to return for reads. Sets io.EOF for readers, but ReadAt ignores them.
}

var errMsgClosed = errors.New("msg is closed")

// FileMsgReader makes a MsgReader for an open file.
// If initialization fails, reads will return the error.
// Only call close on the returned MsgReader if you want to close msgFile.
func FileMsgReader(prefix []byte, msgFile *os.File) *MsgReader {
	mr := &MsgReader{prefix: prefix, path: msgFile.Name(), f: msgFile}
	fi, err := msgFile.Stat()
	if err != nil {
		mr.err = err
		return mr
	}
	mr.size = int64(len(prefix)) + fi.Size()
	return mr
}

// Read reads data from the msg, taking prefix and on-disk msg file into account.
// The read offset is adjusted after the read.
func (m *MsgReader) Read(buf []byte) (int, error) {
	return m.read(buf, m.offset, false)
}

// ReadAt reads data from the msg, taking prefix and on-disk msg file into account.
// The read offset is not affected by ReadAt.
func (m *MsgReader) ReadAt(buf []byte, off int64) (n int, err error) {
	return m.read(buf, off, true)
}

// read always fill buf as far as possible, for ReadAt semantics.
func (m *MsgReader) read(buf []byte, off int64, pread bool) (int, error) {
	// If a reader has consumed the file and reached EOF, further ReadAt must not return eof.
	if m.err != nil && (!pread || m.err != io.EOF) {
		return 0, m.err
	}
	var o int
	for o < len(buf) {
		// First attempt to read from m.prefix.
		pn := int64(len(m.prefix)) - off
		if pn > 0 {
			n := len(buf)
			if int64(n) > pn {
				n = int(pn)
			}
			copy(buf[o:], m.prefix[int(off):int(off)+n])
			o += n
			off += int64(n)
			if !pread {
				m.offset += int64(n)
			}
			continue
		}

		// Now we need to read from file. Ensure it is open.
		if m.f == nil {
			f, err := os.Open(m.path)
			if err != nil {
				m.err = err
				break
			}
			m.f = f
		}
		n, err := m.f.ReadAt(buf[o:], off-int64(len(m.prefix)))
		if !pread && n > 0 {
			m.offset += int64(n)
		}
		if !pread || err != io.EOF {
			m.err = err
		}
		if n > 0 {
			o += n
			off += int64(n)
		}
		if err == io.EOF {
			if off > m.size && (m.err == nil || m.err == io.EOF) {
				err = fmt.Errorf("on-disk message larger than expected (off %d, size %d)", off, m.size)
				m.err = err
			}
			return o, err
		}
		if n <= 0 {
			break
		}
	}
	if off > m.size && (m.err == nil || m.err == io.EOF) {
		m.err = fmt.Errorf("on-disk message larger than expected (off %d, size %d, prefix %d)", off, m.size, len(m.prefix))
	}
	return o, m.err
}

// Close ensures the msg file is closed. Further reads will fail.
func (m *MsgReader) Close() error {
	if m.f != nil {
		if err := m.f.Close(); err != nil {
			return err
		}
		m.f = nil
	}
	if m.err == errMsgClosed {
		return m.err
	}
	m.err = errMsgClosed
	return nil
}

// Reset rewinds the offset and clears error conditions, making it usable as a fresh reader.
func (m *MsgReader) Reset() {
	m.offset = 0
	m.err = nil
}

// Size returns the total size of the contents of the message.
func (m *MsgReader) Size() int64 {
	return m.size
}
