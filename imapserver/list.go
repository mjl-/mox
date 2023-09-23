package imapserver

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mjl-/bstore"
	"github.com/mjl-/mox/store"
)

// LIST command, for listing mailboxes with various attributes, including about subscriptions and children.
// We don't have flags Marked, Unmarked, NoSelect and NoInferiors and we don't have REMOTE mailboxes.
//
// State: Authenticated and selected.
func (c *conn) cmdList(tag, cmd string, p *parser) {
	// Command: ../rfc/9051:2224 ../rfc/6154:144 ../rfc/5258:193 ../rfc/3501:2191
	// Examples: ../rfc/9051:2755 ../rfc/6154:347 ../rfc/5258:679 ../rfc/3501:2359

	// Request syntax: ../rfc/9051:6600 ../rfc/6154:478 ../rfc/5258:1095 ../rfc/3501:4793
	p.xspace()
	var isExtended bool
	var listSubscribed bool
	var listRecursive bool
	if p.take("(") {
		// ../rfc/9051:6633
		isExtended = true
		selectOptions := map[string]bool{}
		var nbase int
		for !p.take(")") {
			if len(selectOptions) > 0 {
				p.xspace()
			}
			w := p.xatom()
			W := strings.ToUpper(w)
			switch W {
			case "REMOTE":
			case "RECURSIVEMATCH":
				listRecursive = true
			case "SUBSCRIBED":
				nbase++
				listSubscribed = true
			default:
				// ../rfc/9051:2398
				xsyntaxErrorf("bad list selection option %q", w)
			}
			// Duplicates must be accepted. ../rfc/9051:2399
			selectOptions[W] = true
		}
		if listRecursive && nbase == 0 {
			// ../rfc/9051:6640
			xsyntaxErrorf("cannot have RECURSIVEMATCH selection option without other (base) selection option")
		}
		p.xspace()
	}
	reference := p.xmailbox()
	p.xspace()
	patterns, isList := p.xmboxOrPat()
	isExtended = isExtended || isList
	var retSubscribed, retChildren bool
	var retStatusAttrs []string
	if p.take(" RETURN (") {
		isExtended = true
		// ../rfc/9051:6613 ../rfc/9051:6915 ../rfc/9051:7072 ../rfc/9051:6821 ../rfc/5819:95
		n := 0
		for !p.take(")") {
			if n > 0 {
				p.xspace()
			}
			n++
			w := p.xatom()
			W := strings.ToUpper(w)
			switch W {
			case "SUBSCRIBED":
				retSubscribed = true
			case "CHILDREN":
				// ../rfc/3348:44
				retChildren = true
			case "SPECIAL-USE":
				// ../rfc/6154:478
				// We always include special-use mailbox flags. Mac OS X Mail 16.0 (sept 2023) does
				// not ask for the flags, but does use them when given. ../rfc/6154:146
			case "STATUS":
				// ../rfc/9051:7072 ../rfc/5819:181
				p.xspace()
				p.xtake("(")
				retStatusAttrs = []string{p.xstatusAtt()}
				for p.take(" ") {
					retStatusAttrs = append(retStatusAttrs, p.xstatusAtt())
				}
				p.xtake(")")
			default:
				// ../rfc/9051:2398
				xsyntaxErrorf("bad list return option %q", w)
			}
		}
	}
	p.xempty()

	if !isExtended && reference == "" && patterns[0] == "" {
		// ../rfc/9051:2277 ../rfc/3501:2221
		c.bwritelinef(`* LIST () "/" ""`)
		c.ok(tag, cmd)
		return
	}

	if isExtended {
		// ../rfc/9051:2286
		n := make([]string, 0, len(patterns))
		for _, p := range patterns {
			if p != "" {
				n = append(n, p)
			}
		}
		patterns = n
	}
	re := xmailboxPatternMatcher(reference, patterns)
	var responseLines []string

	c.account.WithRLock(func() {
		c.xdbread(func(tx *bstore.Tx) {
			type info struct {
				mailbox    *store.Mailbox
				subscribed bool
			}
			names := map[string]info{}
			hasSubscribedChild := map[string]bool{}
			hasChild := map[string]bool{}
			var nameList []string

			q := bstore.QueryTx[store.Mailbox](tx)
			err := q.ForEach(func(mb store.Mailbox) error {
				names[mb.Name] = info{mailbox: &mb}
				nameList = append(nameList, mb.Name)
				for p := filepath.Dir(mb.Name); p != "."; p = filepath.Dir(p) {
					hasChild[p] = true
				}
				return nil
			})
			xcheckf(err, "listing mailboxes")

			qs := bstore.QueryTx[store.Subscription](tx)
			err = qs.ForEach(func(sub store.Subscription) error {
				info, ok := names[sub.Name]
				info.subscribed = true
				names[sub.Name] = info
				if !ok {
					nameList = append(nameList, sub.Name)
				}
				for p := filepath.Dir(sub.Name); p != "."; p = filepath.Dir(p) {
					hasSubscribedChild[p] = true
				}
				return nil
			})
			xcheckf(err, "listing subscriptions")

			sort.Strings(nameList) // For predictable order in tests.

			for _, name := range nameList {
				if !re.MatchString(name) {
					continue
				}
				info := names[name]

				var flags listspace
				var extended listspace
				if listRecursive && hasSubscribedChild[name] {
					extended = listspace{bare("CHILDINFO"), listspace{dquote("SUBSCRIBED")}}
				}
				if listSubscribed && info.subscribed {
					flags = append(flags, bare(`\Subscribed`))
					if info.mailbox == nil {
						flags = append(flags, bare(`\NonExistent`))
					}
				}
				if (info.mailbox == nil || listSubscribed) && flags == nil && extended == nil {
					continue
				}

				if retChildren {
					var f string
					if hasChild[name] {
						f = `\HasChildren`
					} else {
						f = `\HasNoChildren`
					}
					flags = append(flags, bare(f))
				}
				if !listSubscribed && retSubscribed && info.subscribed {
					flags = append(flags, bare(`\Subscribed`))
				}
				if info.mailbox != nil {
					if info.mailbox.Archive {
						flags = append(flags, bare(`\Archive`))
					}
					if info.mailbox.Draft {
						flags = append(flags, bare(`\Drafts`))
					}
					if info.mailbox.Junk {
						flags = append(flags, bare(`\Junk`))
					}
					if info.mailbox.Sent {
						flags = append(flags, bare(`\Sent`))
					}
					if info.mailbox.Trash {
						flags = append(flags, bare(`\Trash`))
					}
				}

				var extStr string
				if extended != nil {
					extStr = " " + extended.pack(c)
				}
				line := fmt.Sprintf(`* LIST %s "/" %s%s`, flags.pack(c), astring(name).pack(c), extStr)
				responseLines = append(responseLines, line)

				if retStatusAttrs != nil && info.mailbox != nil {
					responseLines = append(responseLines, c.xstatusLine(tx, *info.mailbox, retStatusAttrs))
				}
			}
		})
	})

	for _, line := range responseLines {
		c.bwritelinef("%s", line)
	}
	c.ok(tag, cmd)
}
