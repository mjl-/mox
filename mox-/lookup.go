package mox

import (
	"errors"
	"strings"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

var (
	ErrDomainNotFound  = errors.New("domain not found")
	ErrDomainDisabled  = errors.New("message/transaction involving temporarily disabled domain")
	ErrAddressNotFound = errors.New("address not found")
)

// LookupAddress looks up the account for localpart and domain.
//
// Can return ErrDomainNotFound and ErrAddressNotFound. If checkDomainDisabled is
// set, returns ErrDomainDisabled if domain is disabled.
func LookupAddress(localpart smtp.Localpart, domain dns.Domain, allowPostmaster, allowAlias, checkDomainDisabled bool) (accountName string, alias *config.Alias, canonicalAddress string, dest config.Destination, rerr error) {
	if strings.EqualFold(string(localpart), "postmaster") {
		localpart = "postmaster"
	}

	postmasterDomain := func() bool {
		var zerodomain dns.Domain
		if domain == zerodomain || domain == Conf.Static.HostnameDomain {
			return true
		}
		for _, l := range Conf.Static.Listeners {
			if l.SMTP.Enabled && domain == l.HostnameDomain {
				return true
			}
		}
		return false
	}

	// Check for special mail host addresses.
	if localpart == "postmaster" && postmasterDomain() {
		if !allowPostmaster {
			return "", nil, "", config.Destination{}, ErrAddressNotFound
		}
		return Conf.Static.Postmaster.Account, nil, "postmaster", config.Destination{Mailbox: Conf.Static.Postmaster.Mailbox}, nil
	}
	if localpart == Conf.Static.HostTLSRPT.ParsedLocalpart && domain == Conf.Static.HostnameDomain {
		// Get destination, should always be present.
		canonical := smtp.NewAddress(localpart, domain).String()
		accAddr, a, ok := Conf.AccountDestination(canonical)
		if !ok || a != nil {
			return "", nil, "", config.Destination{}, ErrAddressNotFound
		}
		return accAddr.Account, nil, canonical, accAddr.Destination, nil
	}

	d, ok := Conf.Domain(domain)
	if !ok || d.ReportsOnly {
		// For ReportsOnly, we also return ErrDomainNotFound, so this domain isn't
		// considered local/authoritative during delivery.
		return "", nil, "", config.Destination{}, ErrDomainNotFound
	}
	if d.Disabled && checkDomainDisabled {
		return "", nil, "", config.Destination{}, ErrDomainDisabled
	}

	localpart = CanonicalLocalpart(localpart, d)
	canonical := smtp.NewAddress(localpart, domain).String()

	accAddr, alias, ok := Conf.AccountDestination(canonical)
	if ok && alias != nil {
		if !allowAlias {
			return "", nil, "", config.Destination{}, ErrAddressNotFound
		}
		return "", alias, canonical, config.Destination{}, nil
	} else if !ok {
		if accAddr, alias, ok = Conf.AccountDestination("@" + domain.Name()); !ok || alias != nil {
			if localpart == "postmaster" && allowPostmaster {
				return Conf.Static.Postmaster.Account, nil, "postmaster", config.Destination{Mailbox: Conf.Static.Postmaster.Mailbox}, nil
			}
			return "", nil, "", config.Destination{}, ErrAddressNotFound
		}
		canonical = "@" + domain.Name()
	}
	return accAddr.Account, nil, canonical, accAddr.Destination, nil
}

// CanonicalLocalpart returns the canonical localpart, removing optional catchall
// separators, and optionally lower-casing the string.
func CanonicalLocalpart(localpart smtp.Localpart, d config.Domain) smtp.Localpart {
	for _, sep := range d.LocalpartCatchallSeparatorsEffective {
		t := strings.SplitN(string(localpart), sep, 2)
		localpart = smtp.Localpart(t[0])
	}

	if !d.LocalpartCaseSensitive {
		localpart = smtp.Localpart(strings.ToLower(string(localpart)))
	}
	return localpart
}

// AllowMsgFrom returns whether account is allowed to submit messages with address
// as message From header, based on configured addresses and membership of aliases
// that allow using its address.
func AllowMsgFrom(accountName string, msgFrom smtp.Address) (ok, domainDisabled bool) {
	accName, alias, _, _, err := LookupAddress(msgFrom.Localpart, msgFrom.Domain, false, true, true)
	if err != nil {
		return false, errors.Is(err, ErrDomainDisabled)
	}
	if alias != nil && alias.AllowMsgFrom {
		for _, aa := range alias.ParsedAddresses {
			if aa.AccountName == accountName {
				return true, false
			}
		}
		return false, false
	}
	return accName == accountName, false
}
