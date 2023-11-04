// Package dmarcrpt parses DMARC aggregate feedback reports.
package dmarcrpt

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

var ErrNoReport = errors.New("no dmarc aggregate report found in message")

// ParseReport parses an XML aggregate feedback report.
// The maximum report size is 20MB.
func ParseReport(r io.Reader) (*Feedback, error) {
	r = &moxio.LimitReader{R: r, Limit: 20 * 1024 * 1024}
	var feedback Feedback
	d := xml.NewDecoder(r)
	if err := d.Decode(&feedback); err != nil {
		return nil, err
	}
	return &feedback, nil
}

// ParseMessageReport parses an aggregate feedback report from a mail message. The
// maximum message size is 15MB, the maximum report size after decompression is
// 20MB.
func ParseMessageReport(log *mlog.Log, r io.ReaderAt) (*Feedback, error) {
	// ../rfc/7489:1801
	p, err := message.Parse(log, true, &moxio.LimitAtReader{R: r, Limit: 15 * 1024 * 1024})
	if err != nil {
		return nil, fmt.Errorf("parsing mail message: %s", err)
	}

	return parseMessageReport(log, p)
}

func parseMessageReport(log *mlog.Log, p message.Part) (*Feedback, error) {
	// Pretty much any mime structure is allowed. ../rfc/7489:1861
	// In practice, some parties will send the report as the only (non-multipart)
	// content of the message.

	if p.MediaType != "MULTIPART" {
		return parseReport(p)
	}

	for {
		sp, err := p.ParseNextPart(log)
		if err == io.EOF {
			return nil, ErrNoReport
		}
		if err != nil {
			return nil, err
		}
		report, err := parseMessageReport(log, *sp)
		if err == ErrNoReport {
			continue
		} else if err != nil || report != nil {
			return report, err
		}
	}
}

func parseReport(p message.Part) (*Feedback, error) {
	ct := strings.ToLower(p.MediaType + "/" + p.MediaSubType)
	r := p.Reader()

	// If no (useful) content-type is set, try to detect it.
	if ct == "" || ct == "application/octet-stream" {
		data := make([]byte, 512)
		n, err := io.ReadFull(r, data)
		if err == io.EOF {
			return nil, ErrNoReport
		} else if err != nil && err != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("reading application/octet-stream for content-type detection: %v", err)
		}
		data = data[:n]
		ct = http.DetectContentType(data)
		r = io.MultiReader(bytes.NewReader(data), r)
	}

	switch ct {
	case "application/zip":
		// Google sends messages with direct application/zip content-type.
		return parseZip(r)
	case "application/gzip", "application/x-gzip":
		gzr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("decoding gzip xml report: %s", err)
		}
		return ParseReport(gzr)
	case "text/xml", "application/xml":
		return ParseReport(r)
	}
	return nil, ErrNoReport
}

func parseZip(r io.Reader) (*Feedback, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading feedback: %s", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return nil, fmt.Errorf("parsing zip file: %s", err)
	}
	if len(zr.File) != 1 {
		return nil, fmt.Errorf("zip contains %d files, expected 1", len(zr.File))
	}
	f, err := zr.File[0].Open()
	if err != nil {
		return nil, fmt.Errorf("opening file in zip: %s", err)
	}
	defer f.Close()
	return ParseReport(f)
}
