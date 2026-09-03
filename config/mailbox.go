package config

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// CheckMailboxName checks if name is valid, returning an INBOX-normalized name.
func CheckMailboxName(name string, allowInbox bool) (normalizedName string, isInbox bool, rerr error) {
	t := strings.Split(name, "/")
	if strings.EqualFold(t[0], "inbox") {
		if len(name) == len("inbox") && !allowInbox {
			return "", true, fmt.Errorf("special mailbox name Inbox not allowed")
		}
		name = "Inbox" + name[len("Inbox"):]
	}

	if norm.NFC.String(name) != name {
		return "", false, errors.New("non-unicode-normalized mailbox names not allowed")
	}

	for _, e := range t {
		switch e {
		case "":
			return "", false, errors.New("empty mailbox name")
		case ".":
			return "", false, errors.New(`"." not allowed`)
		case "..":
			return "", false, errors.New(`".." not allowed`)
		}
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return "", false, errors.New("bad slashes in mailbox name")
	}

	// "%" and "*" are difficult to use with the IMAP LIST command, but we allow mostly
	// allow them. ../rfc/3501:1002 ../rfc/9051:983
	if strings.HasPrefix(name, "#") {
		return "", false, errors.New("mailbox name cannot start with hash due to conflict with imap namespaces")
	}

	// "#" and "&" are special in IMAP mailbox names. "#" for namespaces, "&" for
	// IMAP-UTF-7 encoding. We do allow them. ../rfc/3501:1018 ../rfc/9051:991

	for _, c := range name {
		// ../rfc/3501:999 ../rfc/6855:192 ../rfc/9051:979
		if c <= 0x1f || c >= 0x7f && c <= 0x9f || c == 0x2028 || c == 0x2029 {
			return "", false, errors.New("control characters not allowed in mailbox name")
		}
	}
	return name, false, nil
}
