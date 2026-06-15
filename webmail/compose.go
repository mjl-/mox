package webmail

import (
	"io"
	"mime/multipart"
	"net/textproto"

	"github.com/mjl-/mox/message"
)

// writeAltBody writes a multipart/alternative body (a text/plain part followed
// by a text/html part) to w using the given boundary. textBody is the plain-text
// alternative; htmlBody is the sanitized HTML. xc is used only to format the
// parts (TextPart applies charset/transfer-encoding); it does not write to w.
func writeAltBody(w io.Writer, boundary, textBody, htmlBody string, xc *message.Composer) error {
	mp := multipart.NewWriter(w)
	if err := mp.SetBoundary(boundary); err != nil {
		return err
	}

	tbody, tct, tcte := xc.TextPart("plain", textBody)
	th := textproto.MIMEHeader{}
	th.Set("Content-Type", tct)
	th.Set("Content-Transfer-Encoding", tcte)
	tp, err := mp.CreatePart(th)
	if err != nil {
		return err
	}
	if _, err := tp.Write(tbody); err != nil {
		return err
	}

	hbody, hct, hcte := xc.TextPart("html", htmlBody)
	hh := textproto.MIMEHeader{}
	hh.Set("Content-Type", hct)
	hh.Set("Content-Transfer-Encoding", hcte)
	hp, err := mp.CreatePart(hh)
	if err != nil {
		return err
	}
	if _, err := hp.Write(hbody); err != nil {
		return err
	}

	return mp.Close()
}

// newAltBoundary returns a fresh multipart boundary string. We need the boundary
// value before writing the part headers that reference it.
func newAltBoundary() string {
	return multipart.NewWriter(io.Discard).Boundary()
}
