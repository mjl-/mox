package dsn

import (
	"net"
)

// NameIP represents a name and possibly IP, e.g. representing a connection destination.
type NameIP struct {
	Name string
	IP   net.IP
}

func (n NameIP) IsZero() bool {
	return n.Name == "" && n.IP == nil
}
