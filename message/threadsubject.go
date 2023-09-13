package message

import (
	"strings"
)

// ThreadSubject returns the base subject to use for matching against other
// messages, to see if they belong to the same thread. A matching subject is
// always required to match to an existing thread, both if
// References/In-Reply-To header(s) are present, and if not.
//
// Subject should already be q/b-word-decoded.
//
// If allowNull is true, base subjects with a \0 can be returned. If not set,
// an empty string is returned if a base subject would have a \0.
func ThreadSubject(subject string, allowNull bool) (threadSubject string, isResponse bool) {
	subject = strings.ToLower(subject)

	// ../rfc/5256:101, Step 1.
	var s string
	for _, c := range subject {
		if c == '\r' {
			continue
		} else if c == ' ' || c == '\n' || c == '\t' {
			if !strings.HasSuffix(s, " ") {
				s += " "
			}
		} else {
			s += string(c)
		}
	}

	// ../rfc/5256:107 ../rfc/5256:811, removing mailing list tag "[...]" and reply/forward "re"/"fwd" prefix.
	removeBlob := func(s string) string {
		for i, c := range s {
			if i == 0 {
				if c != '[' {
					return s
				}
			} else if c == '[' {
				return s
			} else if c == ']' {
				s = s[i+1:]                     // Past [...].
				s = strings.TrimRight(s, " \t") // *WSP
				return s
			}
		}
		return s
	}
	// ../rfc/5256:107 ../rfc/5256:811
	removeLeader := func(s string) string {
		if strings.HasPrefix(s, " ") || strings.HasPrefix(s, "\t") {
			s = s[1:] // WSP
		}

		orig := s

		// Remove zero or more subj-blob
		for {
			prevs := s
			s = removeBlob(s)
			if prevs == s {
				break
			}
		}

		if strings.HasPrefix(s, "re") {
			s = s[2:]
		} else if strings.HasPrefix(s, "fwd") {
			s = s[3:]
		} else if strings.HasPrefix(s, "fw") {
			s = s[2:]
		} else {
			return orig
		}
		s = strings.TrimLeft(s, " \t") // *WSP
		s = removeBlob(s)
		if !strings.HasPrefix(s, ":") {
			return orig
		}
		s = s[1:]
		isResponse = true
		return s
	}

	for {
		// ../rfc/5256:104 ../rfc/5256:817, remove trailing "(fwd)" or WSP, Step 2.
		for {
			prevs := s
			s = strings.TrimRight(s, " \t")
			if strings.HasSuffix(s, "(fwd)") {
				s = strings.TrimSuffix(s, "(fwd)")
				isResponse = true
			}
			if s == prevs {
				break
			}
		}

		for {
			prevs := s
			s = removeLeader(s) // Step 3.
			if ns := removeBlob(s); ns != "" {
				s = ns // Step 4.
			}
			// Step 5, ../rfc/5256:123
			if s == prevs {
				break
			}
		}

		// Step 6. ../rfc/5256:128 ../rfc/5256:805
		if strings.HasPrefix(s, "[fwd:") && strings.HasSuffix(s, "]") {
			s = s[len("[fwd:") : len(s)-1]
			isResponse = true
			continue // From step 2 again.
		}
		break
	}
	if !allowNull && strings.ContainsRune(s, 0) {
		s = ""
	}
	return s, isResponse
}
