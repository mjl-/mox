package message

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/textproto"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
)

var (
	errFromHeaders   = errors.New("missing or duplicate from header")
	errFromAddresses = errors.New("from header does not have exactly one address")
)

// From extracts the address in the From-header.
//
// An RFC5322 message must have a From header.
// In theory, multiple addresses may be present. In practice zero or multiple
// From headers may be present. From returns an error if there is not exactly
// one From header with exactly one address. This address can be used for
// evaluating a DMARC policy against SPF and DKIM results.
func From(elog *slog.Logger, strict bool, r io.ReaderAt, p *Part) (raddr smtp.Address, envelope *Envelope, header textproto.MIMEHeader, rerr error) {
	log := mlog.New("message", elog)

	// ../rfc/7489:1243

	// todo: only allow utf8 if enabled in session/message?

	var err error
	if p == nil {
		var pp Part
		pp, err = Parse(log.Logger, strict, r)
		if err != nil {
			// todo: should we continue with p, perhaps headers can be parsed?
			return raddr, nil, nil, fmt.Errorf("parsing message: %v", err)
		}
		p = &pp
	}
	header, err = p.Header()
	if err != nil {
		return raddr, nil, nil, fmt.Errorf("parsing message header: %v", err)
	}
	// A message must have exactly one From header. ../rfc/5322:1145
	// Multiple From headers are only allowed by the obsolete syntax, which leaves
	// their interpretation unspecified. ../rfc/5322:1993
	// We would use the first, while DKIM signs the physically last instance
	// (../rfc/6376:2320), so the header we evaluate DMARC against and the header
	// covered by the signature need not be the same. Reject instead of picking.
	if l := header.Values("From"); len(l) != 1 {
		return raddr, nil, nil, fmt.Errorf("%w: %d headers", errFromHeaders, len(l))
	}
	from := p.Envelope.From
	if len(from) != 1 {
		return raddr, nil, nil, fmt.Errorf("%w: %d addresses", errFromAddresses, len(from))
	}
	d, err := dns.ParseDomain(from[0].Host)
	if err != nil {
		return raddr, nil, nil, fmt.Errorf("bad domain in from address: %v", err)
	}
	lp, err := smtp.ParseLocalpart(from[0].User)
	if err != nil {
		return raddr, nil, nil, fmt.Errorf("parsing localpart in from address: %v", err)
	}
	addr := smtp.NewAddress(lp, d)
	return addr, p.Envelope, textproto.MIMEHeader(header), nil
}
