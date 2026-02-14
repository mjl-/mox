package mox

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/mjl-/mox/arc"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
)

// ARCSeal looks up the domain for "from" and uses its ARC configuration to seal
// a message. Similar to DKIMSign, it walks up the domain hierarchy to find a
// configured domain. If the domain has ARC sealing enabled, the ARC headers (AAR
// + AMS + AS) are returned for prepending to the message. If no domain or ARC
// config is found, an empty string and nil error is returned.
func ARCSeal(ctx context.Context, log mlog.Log, resolver dns.Resolver, from smtp.Path, authResults message.AuthResults, smtputf8 bool, data []byte) (string, error) {
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

		if confDom.Disabled {
			return "", ErrDomainDisabled
		}

		if confDom.ARC == nil || !confDom.ARC.SealEnabled || confDom.ARC.SealSelector == "" {
			return "", nil
		}

		dkimSel, ok := confDom.DKIM.Selectors[confDom.ARC.SealSelector]
		if !ok {
			return "", fmt.Errorf("arc seal selector %q not found in DKIM selectors for domain %s", confDom.ARC.SealSelector, fd)
		}

		sel := arc.SealSelector{
			Hash:           dkimSel.HashEffective,
			PrivateKey:     dkimSel.Key,
			Domain:         fd,
			SelectorDomain: dkimSel.Domain,
			HeaderRelaxed:  dkimSel.Canonicalization.HeaderRelaxed,
			BodyRelaxed:    dkimSel.Canonicalization.BodyRelaxed,
			Headers:        dkimSel.HeadersEffective,
		}

		hostname := Conf.Static.HostnameDomain.ASCII
		arcHeaders, err := arc.Seal(ctx, log.Logger, resolver, sel, authResults, hostname, smtputf8, bytes.NewReader(data))
		if err != nil {
			return "", fmt.Errorf("arc seal for domain %s: %v", fd, err)
		}
		return arcHeaders, nil
	}
	return "", nil
}
