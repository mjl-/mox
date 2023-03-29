package mox

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

var (
	ErrDomainNotFound  = errors.New("domain not found")
	ErrAccountNotFound = errors.New("account not found")
)

// FindAccount looks up the account for localpart and domain.
//
// Can return ErrDomainNotFound and ErrAccountNotFound.
func FindAccount(localpart smtp.Localpart, domain dns.Domain, allowPostmaster bool) (accountName string, canonicalAddress string, dest config.Destination, rerr error) {
	if strings.EqualFold(string(localpart), "postmaster") {
		localpart = "postmaster"
	}
	var zerodomain dns.Domain
	if localpart == "postmaster" && domain == zerodomain {
		if !allowPostmaster {
			return "", "", config.Destination{}, ErrAccountNotFound
		}
		return Conf.Static.Postmaster.Account, "postmaster", config.Destination{Mailbox: Conf.Static.Postmaster.Mailbox}, nil
	}

	d, ok := Conf.Domain(domain)
	if !ok {
		return "", "", config.Destination{}, ErrDomainNotFound
	}

	localpart, err := CanonicalLocalpart(localpart, d)
	if err != nil {
		return "", "", config.Destination{}, fmt.Errorf("%w: %s", ErrAccountNotFound, err)
	}
	canonical := smtp.NewAddress(localpart, domain).String()

	accAddr, ok := Conf.AccountDestination(canonical)
	if !ok {
		if accAddr, ok = Conf.AccountDestination("@" + domain.Name()); !ok {
			return "", "", config.Destination{}, ErrAccountNotFound
		}
		canonical = "@" + domain.Name()
	}
	return accAddr.Account, canonical, accAddr.Destination, nil
}

// CanonicalLocalpart returns the canonical localpart, removing optional catchall
// separator, and optionally lower-casing the string.
func CanonicalLocalpart(localpart smtp.Localpart, d config.Domain) (smtp.Localpart, error) {
	if d.LocalpartCatchallSeparator != "" {
		t := strings.SplitN(string(localpart), d.LocalpartCatchallSeparator, 2)
		localpart = smtp.Localpart(t[0])
		if localpart == "" {
			return "", fmt.Errorf("empty localpart")
		}
	}

	if !d.LocalpartCaseSensitive {
		localpart = smtp.Localpart(strings.ToLower(string(localpart)))
	}
	return localpart, nil
}
