package store

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/mlog"
)

// MsgSource is implemented by readers for mailbox file formats.
type MsgSource interface {
	// Return next message, or io.EOF when there are no more.
	Next() (*Message, *os.File, string, error)
	Close() error
}

// MboxReader reads messages from an mbox file, implementing MsgSource.
type MboxReader struct {
	log        mlog.Log
	createTemp func(log mlog.Log, pattern string) (*os.File, error)
	path       string
	line       int
	r          *bufio.Reader
	prevempty  bool
	nonfirst   bool
	eof        bool
	fromLine   string // "From "-line for this message.
	header     bool   // Now in header section.
}

// NewMboxReader initializes a MsgSource from which messages can be read.
func NewMboxReader(log mlog.Log, createTemp func(log mlog.Log, pattern string) (*os.File, error), filename string, r io.Reader) (*MboxReader, error) {
	return &MboxReader{
		log:        log,
		createTemp: createTemp,
		path:       filename,
		line:       1,
		r:          bufio.NewReader(r),
	}, nil
}

// Position returns "<filename>:<lineno>" for the current position.
func (mr *MboxReader) Position() string {
	return fmt.Sprintf("%s:%d", mr.path, mr.line)
}

// Next returns the next message read from the mbox file. The file is a temporary
// file and must be removed/consumed. The third return value is the position in the
// file.
func (mr *MboxReader) Next() (*Message, *os.File, string, error) {
	if mr.eof {
		return nil, nil, "", io.EOF
	}

	from := []byte("From ")

	if !mr.nonfirst {
		mr.header = true
		// First read, we're at the beginning of the file.
		line, err := mr.r.ReadBytes('\n')
		if err == io.EOF {
			return nil, nil, "", io.EOF
		}
		mr.line++

		if !bytes.HasPrefix(line, from) {
			return nil, nil, mr.Position(), fmt.Errorf(`first line does not start with "From "`)
		}
		mr.nonfirst = true
		mr.fromLine = strings.TrimSpace(string(line))
	}

	f, err := mr.createTemp(mr.log, "mboxreader")
	if err != nil {
		return nil, nil, mr.Position(), err
	}
	defer func() {
		if f != nil {
			CloseRemoveTempFile(mr.log, f, "message after mbox read error")
		}
	}()

	fromLine := mr.fromLine
	bf := bufio.NewWriter(f)
	var flags Flags
	keywords := map[string]bool{}
	var size int64
	for {
		line, err := mr.r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, nil, mr.Position(), fmt.Errorf("reading from mbox: %v", err)
		}
		if len(line) > 0 {
			mr.line++
			// We store data with crlf, adjust any imported messages with bare newlines. ../rfc/4155:354
			if !bytes.HasSuffix(line, []byte("\r\n")) {
				line = append(line[:len(line)-1], "\r\n"...)
			}

			if mr.header {
				// See https://doc.dovecot.org/admin_manual/mailbox_formats/mbox/
				if bytes.HasPrefix(line, []byte("Status:")) {
					s := strings.TrimSpace(strings.SplitN(string(line), ":", 2)[1])
					for _, c := range s {
						switch c {
						case 'R':
							flags.Seen = true
						}
					}
				} else if bytes.HasPrefix(line, []byte("X-Status:")) {
					s := strings.TrimSpace(strings.SplitN(string(line), ":", 2)[1])
					for _, c := range s {
						switch c {
						case 'A':
							flags.Answered = true
						case 'F':
							flags.Flagged = true
						case 'T':
							flags.Draft = true
						case 'D':
							flags.Deleted = true
						}
					}
				} else if bytes.HasPrefix(line, []byte("X-Keywords:")) {
					s := strings.TrimSpace(strings.SplitN(string(line), ":", 2)[1])
					for t := range strings.SplitSeq(s, ",") {
						word := strings.ToLower(strings.TrimSpace(t))
						switch word {
						case "forwarded", "$forwarded":
							flags.Forwarded = true
						case "junk", "$junk":
							flags.Junk = true
						case "notjunk", "$notjunk", "nonjunk", "$nonjunk":
							flags.Notjunk = true
						case "phishing", "$phishing":
							flags.Phishing = true
						case "mdnsent", "$mdnsent":
							flags.MDNSent = true
						default:
							if err := CheckKeyword(word); err == nil {
								keywords[word] = true
							}
						}
					}
				}
			}
			if bytes.Equal(line, []byte("\r\n")) {
				mr.header = false
			}

			// Next mail message starts at bare From word. ../rfc/4155:71
			if mr.prevempty && bytes.HasPrefix(line, from) {
				mr.fromLine = strings.TrimSpace(string(line))
				mr.header = true
				break
			}
			// ../rfc/4155:119
			if bytes.HasPrefix(line, []byte(">")) && bytes.HasPrefix(bytes.TrimLeft(line, ">"), []byte("From ")) {
				line = line[1:]
			}
			n, err := bf.Write(line)
			if err != nil {
				return nil, nil, mr.Position(), fmt.Errorf("writing message to file: %v", err)
			}
			size += int64(n)
			mr.prevempty = bytes.Equal(line, []byte("\r\n"))
		}
		if err == io.EOF {
			mr.eof = true
			break
		}
	}
	if err := bf.Flush(); err != nil {
		return nil, nil, mr.Position(), fmt.Errorf("flush: %v", err)
	}

	m := &Message{Flags: flags, Keywords: slices.Sorted(maps.Keys(keywords)), Size: size}

	if t := strings.SplitN(fromLine, " ", 3); len(t) == 3 {
		layouts := []string{time.ANSIC, time.UnixDate, time.RubyDate}
		for _, l := range layouts {
			t, err := time.Parse(l, t[2])
			if err == nil {
				m.Received = t
				break
			}
		}
	}

	// Prevent cleanup by defer.
	mf := f
	f = nil

	return m, mf, mr.Position(), nil
}

// Close is currently a no op, for interface MsgSource.
func (mr *MboxReader) Close() error {
	return nil
}

// we make a slice of files, for cur & new, for sorting by time, so we import
// messages in a natural order, with most recent messages latest.
type maildirFile struct {
	Name string
	Time time.Time
}

type MaildirReader struct {
	log                    mlog.Log
	createTemp             func(log mlog.Log, pattern string) (*os.File, error)
	dirNameCur, dirNameNew string
	rootCur, rootNew       *os.Root // For opening files. Closed when Close is called.
	filesCur, filesNew     []maildirFile
	dovecotFlags           []string // Lower-case flags/keywords.
}

// NewMaildirReader opens the "cur" and "new" files in dir, and returns a MsgSource
// to read messages from.
func NewMaildirReader(log mlog.Log, createTemp func(log mlog.Log, pattern string) (*os.File, error), dir string) (*MaildirReader, error) {
	pathCur := filepath.Join(dir, "cur")
	pathNew := filepath.Join(dir, "new")

	var rootCur, rootNew *os.Root

	defer func() {
		if rootCur != nil {
			err := rootCur.Close()
			log.Check(err, "closing root for cur dir")
		}
		if rootNew != nil {
			err := rootNew.Close()
			log.Check(err, "closing root for new dir")
		}
	}()

	var err error
	rootCur, err = os.OpenRoot(pathCur)
	if err != nil {
		return nil, fmt.Errorf("open 'cur' path: %w", err)
	}
	rootNew, err = os.OpenRoot(pathNew)
	if err != nil {
		return nil, fmt.Errorf("open 'new' path: %w", err)
	}

	filesCur, err := maildirRead(log, pathCur)
	if err != nil {
		return nil, fmt.Errorf("reading 'cur' directory: %w", err)
	}
	filesNew, err := maildirRead(log, pathNew)
	if err != nil {
		return nil, fmt.Errorf("reading 'new' directory: %w", err)
	}

	mr := &MaildirReader{
		log:        log,
		createTemp: createTemp,
		dirNameCur: pathCur,
		dirNameNew: pathNew,
		rootCur:    rootCur,
		rootNew:    rootNew,
		filesCur:   filesCur,
		filesNew:   filesNew,
	}

	// Best-effort parsing of dovecot keywords.
	kf, err := os.Open(filepath.Join(dir, "dovecot-keywords"))
	if err == nil {
		mr.dovecotFlags, err = ParseDovecotKeywordsFlags(kf, log)
		log.Check(err, "parsing dovecot keywords file")
		err = kf.Close()
		log.Check(err, "closing dovecot-keywords file")
	}

	// Prevent cleanup, no more chance of error.
	rootCur = nil
	rootNew = nil

	return mr, nil
}

func maildirRead(log mlog.Log, p string) ([]maildirFile, error) {
	dir, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := dir.Close()
		log.Check(err, "closing maildir dir")
	}()

	var files []maildirFile
	for {
		ents, err := dir.ReadDir(100)
		for _, e := range ents {
			f := maildirFile{
				Name: e.Name(),
				Time: messageTime(e),
			}
			files = append(files, f)
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("read dir: %w", err)
		}
	}

	slices.SortFunc(files, func(a, b maildirFile) int { return a.Time.Compare(b.Time) })
	return files, nil
}

// Take received time from filename, falling back to mtime for maildirs
// reconstructed some other sources of message files.
func messageTime(f os.DirEntry) time.Time {
	var t time.Time
	parts := strings.SplitN(f.Name(), ".", 3)
	if v, err := strconv.ParseInt(parts[0], 10, 64); len(parts) == 3 && err == nil {
		t = time.Unix(v, 0)
	} else if fi, err := f.Info(); err == nil {
		t = fi.ModTime()
	}
	return t
}

func (mr *MaildirReader) Next() (*Message, *os.File, string, error) {
	var file maildirFile
	var root *os.Root
	var dirName string
	if len(mr.filesCur) > 0 {
		file = mr.filesCur[0]
		mr.filesCur = mr.filesCur[1:]
		root = mr.rootCur
		dirName = mr.dirNameCur
	} else if len(mr.filesNew) > 0 {
		file = mr.filesNew[0]
		mr.filesNew = mr.filesNew[1:]
		root = mr.rootNew
		dirName = mr.dirNameNew
	} else {
		return nil, nil, "", io.EOF
	}

	p := filepath.Join(dirName, file.Name)
	sf, err := root.Open(file.Name)
	if err != nil {
		return nil, nil, p, fmt.Errorf("open message in maildir: %s", err)
	}
	defer func() {
		err := sf.Close()
		mr.log.Check(err, "closing message file after error")
	}()
	f, err := mr.createTemp(mr.log, "maildirreader")
	if err != nil {
		return nil, nil, p, err
	}
	defer func() {
		if f != nil {
			CloseRemoveTempFile(mr.log, f, "maildir temp message file")
		}
	}()

	// Copy data, changing bare \n into \r\n.
	r := bufio.NewReader(sf)
	w := bufio.NewWriter(f)
	var size int64
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, nil, p, fmt.Errorf("reading message: %v", err)
		}
		if len(line) > 0 {
			if !bytes.HasSuffix(line, []byte("\r\n")) {
				line = append(line[:len(line)-1], "\r\n"...)
			}

			if n, err := w.Write(line); err != nil {
				return nil, nil, p, fmt.Errorf("writing message: %v", err)
			} else {
				size += int64(n)
			}
		}
		if err == io.EOF {
			break
		}
	}
	if err := w.Flush(); err != nil {
		return nil, nil, p, fmt.Errorf("writing message: %v", err)
	}

	// Parse flags. See https://cr.yp.to/proto/maildir.html.
	flags := Flags{}
	keywords := map[string]bool{}
	t := strings.SplitN(file.Name, ":2,", 2)
	if len(t) == 2 {
		for _, c := range t[1] {
			switch c {
			case 'P':
				// Passed, doesn't map to a common IMAP flag.
			case 'R':
				flags.Answered = true
			case 'S':
				flags.Seen = true
			case 'T':
				flags.Deleted = true
			case 'D':
				flags.Draft = true
			case 'F':
				flags.Flagged = true
			default:
				if c >= 'a' && c <= 'z' {
					index := int(c - 'a')
					if index >= len(mr.dovecotFlags) {
						continue
					}
					kw := mr.dovecotFlags[index]
					switch kw {
					case "$forwarded", "forwarded":
						flags.Forwarded = true
					case "$junk", "junk":
						flags.Junk = true
					case "$notjunk", "notjunk", "nonjunk":
						flags.Notjunk = true
					case "$mdnsent", "mdnsent":
						flags.MDNSent = true
					case "$phishing", "phishing":
						flags.Phishing = true
					default:
						keywords[kw] = true
					}
				}
			}
		}
	}

	m := &Message{Received: file.Time, Flags: flags, Keywords: slices.Sorted(maps.Keys(keywords)), Size: size}

	// Prevent cleanup by defer.
	mf := f
	f = nil

	return m, mf, p, nil
}

// Close closes internal state. It does not close dirNew and dirCur passed to
// NewMaildirReader.
func (mr *MaildirReader) Close() error {
	var err0, err1 error
	if mr.rootCur != nil {
		err0 = mr.rootCur.Close()
	}
	if mr.rootNew != nil {
		err1 = mr.rootNew.Close()
	}
	return errors.Join(err0, err1)
}

// ParseDovecotKeywordsFlags attempts to parse a dovecot-keywords file. It only
// returns valid flags/keywords, as lower-case. If an error is encountered and
// returned, any keywords that were found are still returned. The returned list has
// both system/well-known flags and custom keywords.
func ParseDovecotKeywordsFlags(r io.Reader, log mlog.Log) ([]string, error) {
	/*
		If the dovecot-keywords file is present, we parse its additional flags, see
		https://doc.dovecot.org/admin_manual/mailbox_formats/maildir/

		0 Old
		1 Junk
		2 NonJunk
		3 $Forwarded
		4 $Junk
	*/
	keywords := make([]string, 26)
	end := 0
	scanner := bufio.NewScanner(r)
	var errs []string
	for scanner.Scan() {
		s := scanner.Text()
		t := strings.SplitN(s, " ", 2)
		if len(t) != 2 {
			errs = append(errs, fmt.Sprintf("unexpected dovecot keyword line: %q", s))
			continue
		}
		v, err := strconv.ParseInt(t[0], 10, 32)
		if err != nil {
			errs = append(errs, fmt.Sprintf("unexpected dovecot keyword index: %q", s))
			continue
		}
		if v < 0 || v >= int64(len(keywords)) {
			errs = append(errs, fmt.Sprintf("dovecot keyword index too big: %q", s))
			continue
		}
		index := int(v)
		if keywords[index] != "" {
			errs = append(errs, fmt.Sprintf("duplicate dovecot keyword: %q", s))
			continue
		}
		kw := strings.ToLower(t[1])
		if !systemWellKnownFlags[kw] {
			if err := CheckKeyword(kw); err != nil {
				errs = append(errs, fmt.Sprintf("invalid keyword %q", kw))
				continue
			}
		}
		keywords[index] = kw
		if index >= end {
			end = index + 1
		}
	}
	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("reading dovecot keywords file: %v", err))
	}
	var err error
	if len(errs) > 0 {
		err = errors.New(strings.Join(errs, "; "))
	}
	return keywords[:end], err
}
