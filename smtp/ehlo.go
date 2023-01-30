package smtp

import (
	"net"

	"github.com/mjl-/mox/dns"
)

// Ehlo is the remote identification of an incoming SMTP connection.
type Ehlo struct {
	Name   dns.IPDomain // Name from EHLO/HELO line. Can be an IP or host name.
	ConnIP net.IP       // Address of connection.
}

func (e Ehlo) IsZero() bool {
	return e.Name.IsZero() && e.ConnIP == nil
}
