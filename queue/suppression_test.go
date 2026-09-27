package queue

import (
	"testing"

	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/webapi"
)

func TestBaseAddress(t *testing.T) {
	mustPath := func(s string) smtp.Path {
		t.Helper()
		a, err := smtp.ParseAddress(s)
		tcheck(t, err, "parse address")
		return a.Path()
	}
	base := func(s string) string {
		t.Helper()
		return baseAddress(mustPath(s)).XString(true)
	}

	// Plus-addressing and Gmail-style dots are normalized.
	tcompare(t, base("M.j.l2+catchall@Mox.example"), base("mjl2@mox.example"))

	// Hyphenated localparts stay distinct; "-" is not a subaddress separator.
	tcompare(t, base("user-nam96@example.com"), "user-nam96@example.com")
	tcompare(t, base("user-name96@example.com"), "user-name96@example.com")
	tcompare(t, base("user-nam96@example.com") == base("user-name96@example.com"), false)
	tcompare(t, base("user-nam96@example.com") == base("user@example.com"), false)
}

func TestSuppression(t *testing.T) {
	_, cleanup := setup(t)
	defer cleanup()

	l, err := SuppressionList(ctxbg, "bogus")
	tcheck(t, err, "listing suppressions for unknown account")
	tcompare(t, len(l), 0)

	l, err = SuppressionList(ctxbg, "") // All
	tcheck(t, err, "list suppression for all accounts")
	tcompare(t, len(l), 0) // None yet.

	addr1, err := smtp.ParseAddress("mjl@mox.example")
	tcheck(t, err, "parse address")
	path1 := addr1.Path()
	addr2, err := smtp.ParseAddress("mjl2@mox.example")
	tcheck(t, err, "parse address")
	path2 := addr2.Path()
	addr2b, err := smtp.ParseAddress("M.j.l2+catchall@Mox.example")
	tcheck(t, err, "parse address")
	path2b := addr2b.Path()
	addrHyphenTypo, err := smtp.ParseAddress("user-nam96@example.com")
	tcheck(t, err, "parse address")
	pathHyphenTypo := addrHyphenTypo.Path()
	addrHyphenOk, err := smtp.ParseAddress("user-name96@example.com")
	tcheck(t, err, "parse address")
	pathHyphenOk := addrHyphenOk.Path()

	// No suppression yet.
	sup, err := SuppressionLookup(ctxbg, "mjl", path1)
	tcheck(t, err, "lookup suppression")
	tcompare(t, sup == nil, true)

	// No error if account does not exist.
	sup, err = SuppressionLookup(ctxbg, "bogus", path1)
	tcompare(t, err == nil, true)
	tcompare(t, sup == nil, true)

	// Can add a suppression once.
	err = SuppressionAdd(ctxbg, path1, &webapi.Suppression{Account: "mjl"})
	tcheck(t, err, "add suppression")
	// No duplicates.
	err = SuppressionAdd(ctxbg, path1, &webapi.Suppression{Account: "mjl"})
	tcompare(t, err == nil, false)
	// Account must be set in Suppresion.
	err = SuppressionAdd(ctxbg, path1, &webapi.Suppression{})
	tcompare(t, err == nil, false)

	// Duplicate check is done after making base address.
	err = SuppressionAdd(ctxbg, path2, &webapi.Suppression{Account: "retired"})
	tcheck(t, err, "add suppression")
	err = SuppressionAdd(ctxbg, path2b, &webapi.Suppression{Account: "retired"})
	tcompare(t, err == nil, false) // Duplicate.

	l, err = SuppressionList(ctxbg, "") // All
	tcheck(t, err, "list suppression for all accounts")
	tcompare(t, len(l), 2)
	l, err = SuppressionList(ctxbg, "mjl")
	tcheck(t, err, "list suppression for mjl")
	tcompare(t, len(l), 1)

	// path1 is listed for mjl.
	sup, err = SuppressionLookup(ctxbg, "mjl", path1)
	tcheck(t, err, "lookup")
	tcompare(t, sup == nil, false)

	// Accounts don't influence each other.
	sup, err = SuppressionLookup(ctxbg, "mjl", path2)
	tcheck(t, err, "lookup")
	tcompare(t, sup == nil, true)

	// Simplified address is present.
	sup, err = SuppressionLookup(ctxbg, "retired", path2)
	tcheck(t, err, "lookup")
	tcompare(t, sup == nil, false)

	// Original address is also present.
	sup, err = SuppressionLookup(ctxbg, "retired", path2b)
	tcheck(t, err, "lookup")
	tcompare(t, sup == nil, false)

	// Can remove again.
	err = SuppressionRemove(ctxbg, "mjl", path1)
	tcheck(t, err, "remove")
	// But not twice.
	err = SuppressionRemove(ctxbg, "mjl", path1)
	tcompare(t, err == nil, false)
	// No longer present.
	sup, err = SuppressionLookup(ctxbg, "mjl", path1)
	tcheck(t, err, "lookup")
	tcompare(t, sup == nil, true)

	// Can remove for any form of the address, was added as path2b.
	err = SuppressionRemove(ctxbg, "retired", path2b)
	tcheck(t, err, "lookup")

	// Account names are not validated.
	err = SuppressionAdd(ctxbg, path1, &webapi.Suppression{Account: "bogus"})
	tcheck(t, err, "add suppression")
	err = SuppressionRemove(ctxbg, "bogus", path1)
	tcheck(t, err, "remove suppression")

	// Hyphenated addresses must not share a base address (#478).
	err = SuppressionAdd(ctxbg, pathHyphenTypo, &webapi.Suppression{Account: "mjl"})
	tcheck(t, err, "add hyphenated typo suppression")
	sup, err = SuppressionLookup(ctxbg, "mjl", pathHyphenOk)
	tcheck(t, err, "lookup correct hyphenated address")
	tcompare(t, sup == nil, true) // Must not collide with typo prefix.
	err = SuppressionAdd(ctxbg, pathHyphenOk, &webapi.Suppression{Account: "mjl"})
	tcheck(t, err, "add correct hyphenated address independently")
	err = SuppressionRemove(ctxbg, "mjl", pathHyphenTypo)
	tcheck(t, err, "remove hyphenated typo suppression")
	err = SuppressionRemove(ctxbg, "mjl", pathHyphenOk)
	tcheck(t, err, "remove correct hyphenated suppression")
}
