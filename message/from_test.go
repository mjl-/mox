package message

import (
	"strings"
	"testing"
)

func TestFrom(t *testing.T) {
	check := func(headers, expAddr string, expErr error) {
		t.Helper()

		msg := strings.ReplaceAll(headers, "\n", "\r\n") + "\r\nbody\r\n"
		addr, _, _, err := From(pkglog.Logger, false, strings.NewReader(msg), nil)
		tfail(t, err, expErr)
		if expErr == nil {
			tcompare(t, addr.String(), expAddr)
		}
	}

	check("From: mjl@mox.example\n", "mjl@mox.example", nil)
	check("From: Mechiel <mjl@mox.example>\n", "mjl@mox.example", nil)

	// Exactly one from header, with exactly one address. ../rfc/5322:1145
	check("Subject: test\n", "", errFromHeaders)
	check("From: mjl@mox.example, other@mox.example\n", "", errFromAddresses)

	// With multiple from headers we would use the first, while DKIM signs the last, so
	// we reject. ../rfc/5322:1993 ../rfc/6376:2320
	check("From: attacker@evil.example\nFrom: ceo@bank.example\n", "", errFromHeaders)
	check("From: ceo@bank.example\nFrom: attacker@evil.example\n", "", errFromHeaders)
	check("From: mjl@mox.example\nFrom: mjl@mox.example\n", "", errFromHeaders)
}
