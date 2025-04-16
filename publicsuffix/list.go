//go:generate sh -c "curl https://publicsuffix.org/list/public_suffix_list.dat >public_suffix_list.txt"

// Package publicsuffix implements a public suffix list to look up the
// organizational domain for a given host name. Organizational domains can be
// registered, one level below a top-level domain.
//
// Example.com has a public suffix ".com", and example.co.uk has a public
// suffix ".co.uk".  The organizational domain of sub.example.com is
// example.com, and the organization domain of sub.example.co.uk is
// example.co.uk.
package publicsuffix

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	_ "embed"

	"golang.org/x/net/idna"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

// todo: automatically fetch new lists periodically? compare it with the old one. refuse it if it changed too much, especially if it contains far fewer entries than before.

// Labels map from utf8 labels to labels for subdomains.
// The end is marked with an empty string as label.
type labels map[string]labels

// List is a public suffix list.
type List struct {
	includes, excludes labels
}

var publicsuffixList List

//go:embed public_suffix_list.txt
var publicsuffixData []byte

func init() {
	log := mlog.New("publicsuffix", nil)
	l, err := ParseList(log.Logger, bytes.NewReader(publicsuffixData))
	if err != nil {
		log.Fatalx("parsing public suffix list", err)
	}
	publicsuffixList = l
}

// ParseList parses a public suffix list.
// Only the "ICANN DOMAINS" are used.
func ParseList(elog *slog.Logger, r io.Reader) (List, error) {
	log := mlog.New("publicsuffix", elog)

	list := List{labels{}, labels{}}
	br := bufio.NewReader(r)

	// Only use ICANN domains. ../rfc/7489-eid6729
	var icannDomains bool
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "// ===BEGIN ICANN DOMAINS===") {
				icannDomains = true
				continue
			} else if strings.HasPrefix(line, "// ===END ICANN DOMAINS===") {
				icannDomains = false
				continue
			} else if line == "" || strings.HasPrefix(line, "//") || !icannDomains {
				continue
			}
			l := list.includes
			var t []string
			oline := line
			if strings.HasPrefix(line, "!") {
				line = line[1:]
				l = list.excludes
				t = strings.Split(line, ".")
				if len(t) == 1 {
					log.Print("exclude rule with single label, skipping", slog.String("line", oline))
					continue
				}
			} else {
				t = strings.Split(line, ".")
			}
			for i := len(t) - 1; i >= 0; i-- {
				w := t[i]
				if w == "" {
					log.Print("empty label in rule, skipping", slog.String("line", oline))
					break
				}
				if w != "" && w != "*" {
					w, err = idna.Lookup.ToUnicode(w)
					if err != nil {
						log.Printx("invalid label, skipping", err, slog.String("line", oline))
					}
				}
				m, ok := l[w]
				if ok {
					if _, dup := m[""]; i == 0 && dup {
						log.Print("duplicate rule", slog.String("line", oline))
					}
					l = m
				} else {
					m = labels{}
					l[w] = m
					l = m
				}
			}
			l[""] = nil // Mark end.
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return List{}, fmt.Errorf("reading public suffix list: %w", err)
		}
	}
	return list, nil
}

// Lookup calls Lookup on the builtin public suffix list, from
// https://publicsuffix.org/list/.
func Lookup(ctx context.Context, elog *slog.Logger, domain dns.Domain) (orgDomain dns.Domain) {
	return publicsuffixList.Lookup(ctx, elog, domain)
}

// Lookup returns the organizational domain. If domain is an organizational
// domain, or higher-level, the same domain is returned.
func (l List) Lookup(ctx context.Context, elog *slog.Logger, domain dns.Domain) (orgDomain dns.Domain) {
	log := mlog.New("publicsuffix", elog)
	defer func() {
		log.Debug("publicsuffix lookup result", slog.Any("reqdom", domain), slog.Any("orgdom", orgDomain))
	}()

	t := strings.Split(domain.Name(), ".")

	var n int
	if nexcl, ok := match(l.excludes, t); ok {
		n = nexcl
	} else if nincl, ok := match(l.includes, t); ok {
		n = nincl + 1
	} else {
		n = 2
	}
	if len(t) < n {
		return domain
	}
	name := strings.Join(t[len(t)-n:], ".")
	if isASCII(name) {
		return dns.Domain{ASCII: name}
	}
	t = strings.Split(domain.ASCII, ".")
	ascii := strings.Join(t[len(t)-n:], ".")
	return dns.Domain{ASCII: ascii, Unicode: name}
}

func isASCII(s string) bool {
	for _, c := range s {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

func match(l labels, t []string) (int, bool) {
	if len(t) == 0 {
		_, ok := l[""]
		return 0, ok
	}
	s := t[len(t)-1]
	t = t[:len(t)-1]
	n := 0
	if m, mok := l[s]; mok {
		if nn, sok := match(m, t); sok {
			n = 1 + nn
		}
	}
	if m, mok := l["*"]; mok {
		if nn, sok := match(m, t); sok && nn >= n {
			n = 1 + nn
		}
	}
	_, mok := l[""]
	return n, n > 0 || mok
}
