package message

import (
	"strings"

	"github.com/mjl-/mox/smtp"
)

// ReferencedIDs returns the Message-IDs referenced from the References header(s),
// with a fallback to the In-Reply-To header(s). The ids are canonicalized for
// thread-matching, like with MessageIDCanonical. Empty message-id's are skipped.
func ReferencedIDs(references []string, inReplyTo []string) ([]string, error) {
	var refids []string // In thread-canonical form.

	// parse and add 0 or 1 reference, returning the remaining refs string for a next attempt.
	parse1 := func(refs string, one bool) string {
		refs = strings.TrimLeft(refs, " \t\r\n")
		if !strings.HasPrefix(refs, "<") {
			// To make progress, we skip to next space or >.
			i := strings.IndexAny(refs, " >")
			if i < 0 {
				return ""
			}
			return refs[i+1:]
		}
		refs = refs[1:]
		// Look for the ending > or next <. If < is before >, this entry is truncated.
		i := strings.IndexAny(refs, "<>")
		if i < 0 {
			return ""
		}
		if refs[i] == '<' {
			// Truncated entry, we ignore it.
			return refs[i:]
		}
		ref := strings.ToLower(refs[:i])
		// Some MUAs wrap References line in the middle of message-id's, and others
		// recombine them. Take out bare WSP in message-id's.
		ref = strings.ReplaceAll(ref, " ", "")
		ref = strings.ReplaceAll(ref, "\t", "")
		refs = refs[i+1:]
		// Canonicalize the quotedness of the message-id.
		addr, err := smtp.ParseAddress(ref)
		if err == nil {
			// Leave the hostname form intact.
			t := strings.Split(ref, "@")
			ref = addr.Localpart.String() + "@" + t[len(t)-1]
		}
		// log.Errorx("assigning threads: bad reference in references header, using raw value", err, mlog.Field("msgid", mid), mlog.Field("reference", ref))
		if ref != "" {
			refids = append(refids, ref)
		}
		return refs
	}

	// References is the modern way (for a long time already) to reference ancestors.
	// The direct parent is typically at the end of the list.
	for _, refs := range references {
		for refs != "" {
			refs = parse1(refs, false)
		}
	}
	// We only look at the In-Reply-To header if we didn't find any References.
	if len(refids) == 0 {
		for _, s := range inReplyTo {
			parse1(s, true)
			if len(refids) > 0 {
				break
			}
		}
	}

	return refids, nil
}
