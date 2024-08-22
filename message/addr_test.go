package message

import (
	"testing"
)

func TestParseAddressList(t *testing.T) {
	l, err := ParseAddressList("=?iso-8859-2?Q?Krist=FDna?= <k@example.com>, mjl@mox.example")
	tcheck(t, err, "parsing address list")
	tcompare(t, l, []Address{{"Kristýna", "k", "example.com"}, {"", "mjl", "mox.example"}})
}
