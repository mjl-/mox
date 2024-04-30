package mox

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
)

// DKIMSelectors returns the selectors to use for signing.
func DKIMSelectors(dkimConf config.DKIM) []dkim.Selector {
	var l []dkim.Selector
	for _, sign := range dkimConf.Sign {
		sel := dkimConf.Selectors[sign]
		s := dkim.Selector{
			Hash:          sel.HashEffective,
			HeaderRelaxed: sel.Canonicalization.HeaderRelaxed,
			BodyRelaxed:   sel.Canonicalization.BodyRelaxed,
			Headers:       sel.HeadersEffective,
			SealHeaders:   !sel.DontSealHeaders,
			Expiration:    time.Duration(sel.ExpirationSeconds) * time.Second,
			PrivateKey:    sel.Key,
			Domain:        sel.Domain,
		}
		l = append(l, s)
	}
	return l
}

// DKIMSign looks up the domain for "from", and uses its DKIM configuration to
// generate DKIM-Signature headers, for inclusion in a message. The
// DKIM-Signatur headers, are returned. If no domain was found an empty string and
// nil error is returned.
func DKIMSign(ctx context.Context, log mlog.Log, from smtp.Path, smtputf8 bool, data []byte) (string, error) {
	// Add DKIM signature for domain, even if higher up than the full mail hostname.
	// This helps with an assumed (because default) relaxed DKIM policy. If the DMARC
	// policy happens to be strict, the signature won't help, but won't hurt either.
	fd := from.IPDomain.Domain
	var zerodom dns.Domain
	for fd != zerodom {
		confDom, ok := Conf.Domain(fd)
		if !ok {
			var nfd dns.Domain
			_, nfd.ASCII, _ = strings.Cut(fd.ASCII, ".")
			_, nfd.Unicode, _ = strings.Cut(fd.Unicode, ".")
			fd = nfd
			continue
		}

		selectors := DKIMSelectors(confDom.DKIM)
		dkimHeaders, err := dkim.Sign(ctx, log.Logger, from.Localpart, fd, selectors, smtputf8, bytes.NewReader(data))
		if err != nil {
			return "", fmt.Errorf("dkim sign for domain %s: %v", fd, err)
		}
		return dkimHeaders, nil
	}
	return "", nil
}
