package message

import (
	"fmt"
	"io"
	"net/textproto"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
)

// From extracts the address in the From-header.
//
// An RFC5322 message must have a From header.
// In theory, multiple addresses may be present. In practice zero or multiple
// From headers may be present. From returns an error if there is not exactly
// one address. This address can be used for evaluating a DMARC policy against
// SPF and DKIM results.
func From(elog *slog.Logger, strict bool, r io.ReaderAt) (raddr smtp.Address, envelope *Envelope, header textproto.MIMEHeader, rerr error) {
	log := mlog.New("message", elog)

	// ../rfc/7489:1243

	// todo: only allow utf8 if enabled in session/message?

	p, err := Parse(log.Logger, strict, r)
	if err != nil {
		// todo: should we continue with p, perhaps headers can be parsed?
		return raddr, nil, nil, fmt.Errorf("parsing message: %v", err)
	}
	header, err = p.Header()
	if err != nil {
		return raddr, nil, nil, fmt.Errorf("parsing message header: %v", err)
	}
	from := p.Envelope.From
	if len(from) != 1 {
		return raddr, nil, nil, fmt.Errorf("from header has %d addresses, need exactly 1 address", len(from))
	}
	d, err := dns.ParseDomain(from[0].Host)
	if err != nil {
		return raddr, nil, nil, fmt.Errorf("bad domain in from address: %v", err)
	}
	addr := smtp.Address{Localpart: smtp.Localpart(from[0].User), Domain: d}
	return addr, p.Envelope, textproto.MIMEHeader(header), nil
}
