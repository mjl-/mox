package message

import (
	"fmt"
	"net/mail"

	"github.com/mjl-/mox/smtp"
)

// ParseAddressList parses a string as an address list header value
// (potentially multiple addresses, comma-separated, with optional display
// name).
func ParseAddressList(s string) ([]Address, error) {
	parser := mail.AddressParser{WordDecoder: &wordDecoder}
	addrs, err := parser.ParseList(s)
	if err != nil {
		return nil, fmt.Errorf("parsing address list: %v", err)
	}
	r := make([]Address, len(addrs))
	for i, a := range addrs {
		addr, err := smtp.ParseNetMailAddress(a.Address)
		if err != nil {
			return nil, fmt.Errorf("parsing adjusted address %q: %v", a.Address, err)
		}
		r[i] = Address{a.Name, addr.Localpart.String(), addr.Domain.ASCII}

	}
	return r, nil
}
