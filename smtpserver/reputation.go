package smtpserver

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

type reputationMethod string

const (
	methodMsgfromFull      reputationMethod = "msgfromfull"
	methodMsgtoFull        reputationMethod = "msgtofull"
	methodMsgfromDomain    reputationMethod = "msgfromdomain"
	methodMsgfromOrgDomain reputationMethod = "msgfromorgdomain"
	methodMsgtoDomain      reputationMethod = "msgtodomain"
	methodMsgtoOrgDomain   reputationMethod = "msgtoorgdomain"
	methodDKIMSPF          reputationMethod = "dkimspf"
	methodIP1              reputationMethod = "ip1"
	methodIP2              reputationMethod = "ip2"
	methodIP3              reputationMethod = "ip3"
	methodNone             reputationMethod = "none"
)

// Reputation returns whether message m is likely junk.
//
// This function is called after checking for a manually configured spf mailfrom
// allow (e.g. for mailing lists), and after checking for a dmarc reject policy.
//
// The decision is made based on historic messages delivered to the same
// destination mailbox, MailboxOrigID. Because each mailbox may have a different
// accept policy. We only use messages that have been marked as either junk or
// non-junk. We help users by automatically marking them as non-junk when moving to
// certain folders in the default config (e.g. the archive folder). We expect users
// to mark junk messages as such when they read it. And to keep it in their inbox,
// regular trash or archive if it is not.
//
// The basic idea is to keep accepting messages that were accepted in the past, and
// keep rejecting those that were rejected. This is relatively easy to check if
// mail passes SPF and/or DKIM with Message-From alignment. Regular email from
// known people will be let in. But spammers are trickier. They will use new IPs,
// (sub)domains, no or newly created SPF and/or DKIM identifiers, new localparts,
// etc. This function likely ends up returning "inconclusive" for such emails. The
// junkfilter will have to take care of a final decision.
//
// In case of doubt, it doesn't hurt much to accept another mail that a user has
// communicated successfully with in the past. If the most recent message is marked
// as junk that could have happened accidentally. If another message is let in, and
// it is again junk, future messages will be rejected.
//
// Actual spammers will probably try to use identifiers, i.e. (sub)domain, dkim/spf
// identifiers and ip addresses for which we have no history. We may only have
// ip-based reputation, perhaps only an ip range, perhaps nothing.
//
// Some profiles of first-time senders:
//
//   - Individuals. They can typically get past the junkfilter if needed.
//   - Transactional emails. They should get past the junkfilter. If they use one of
//     the larger email service providers, their reputation could help. If the
//     junkfilter rejects the message, users can recover the message from the Rejects
//     mailbox. The first message is typically initiated by a user, e.g. by registering.
//   - Desired commercial email will have to get past the junkfilter based on its
//     content. There will typically be earlier communication with the (organizational)
//     domain that would let the message through.
//   - Mailing list. May get past the junkfilter. If delivery is to a separate
//     mailbox, the junkfilter will let it in because of little history. Long enough to
//     build reputation based on DKIM/SPF signals. Users are best off to
//     configure accept rules for messages from mailing lists.
//
// The decision-making process looks at historic messages. The following properties
// are checked until matching messages are found. If they are found, a decision is
// returned, which may be inconclusive. The next property on the list is only
// checked if a step did not match any messages.
//
//   - Messages matching full "message from" address, either with strict/relaxed
//     dkim/spf-verification, or without.
//   - Messages the user sent to the "message from" address.
//   - Messages matching only the domain of the "message from" address (different
//     localpart), again with verification or without.
//   - Messages sent to an address in the domain of the "message from" address.
//   - The previous two checks again, but now checking against the organizational
//     domain instead of the exact domain.
//   - Matching DKIM domains and a matching SPF mailfrom, or mailfrom domain, or ehlo
//     domain.
//   - "Exact" IP, or nearby IPs.
//
// References:
// ../rfc/5863
// ../rfc/7960
// ../rfc/6376:1915
// ../rfc/6376:3716
// ../rfc/7208:2167
func reputation(tx *bstore.Tx, log mlog.Log, m *store.Message, smtputf8 bool) (rjunk *bool, rconclusive bool, rmethod reputationMethod, reasonText string, rerr error) {
	boolptr := func(v bool) *bool {
		return &v
	}
	xfalse := boolptr(false)
	xtrue := boolptr(true)

	type queryError string

	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if xerr, ok := x.(queryError); ok {
			rerr = errors.New(string(xerr))
			return
		}
		panic(x)
	}()

	now := time.Now()

	// messageQuery returns a base query for historic seen messages to the same
	// mailbox, at most maxAge old, and at most maxCount messages.
	messageQuery := func(fm *store.Message, maxAge time.Duration, maxCount int) *bstore.Query[store.Message] {
		q := bstore.QueryTx[store.Message](tx)
		q.FilterEqual("MailboxOrigID", m.MailboxID)
		q.FilterEqual("Expunged", false)
		q.FilterFn(func(m store.Message) bool {
			return m.Junk || m.Notjunk
		})
		if fm != nil {
			q.FilterNonzero(*fm)
		}
		q.FilterGreaterEqual("Received", now.Add(-maxAge))
		q.Limit(maxCount)
		q.SortDesc("Received")
		return q
	}

	// Execute the query, returning messages or returning error through panic.
	xmessageList := func(q *bstore.Query[store.Message], descr string) []store.Message {
		t0 := time.Now()
		l, err := q.List()
		log.Debugx("querying messages for reputation", err,
			slog.Int("msgs", len(l)),
			slog.String("descr", descr),
			slog.Duration("queryduration", time.Since(t0)))
		if err != nil {
			panic(queryError(fmt.Sprintf("listing messages: %v", err)))
		}
		return l
	}

	xrecipientExists := func(q *bstore.Query[store.Recipient]) bool {
		exists, err := q.Exists()
		if err != nil {
			panic(queryError(fmt.Sprintf("checking for recipient: %v", err)))
		}
		return exists
	}

	const year = 365 * 24 * time.Hour

	// Look for historic messages with same "message from" address. We'll
	// treat any validation (strict/dmarc/relaxed) the same, but "none"
	// separately.
	//
	// We only need 1 message, and sometimes look at a second message. If
	// the last message or the message before was an accept, we accept. If
	// the single last or last two were a reject, we reject.
	//
	// If there was no validation, any signal is inconclusive.
	if m.MsgFromDomain != "" {
		q := messageQuery(&store.Message{MsgFromLocalpart: m.MsgFromLocalpart, MsgFromDomain: m.MsgFromDomain}, 3*year, 2)
		q.FilterEqual("MsgFromValidated", m.MsgFromValidated)
		msgs := xmessageList(q, "mgsfromfull")
		if len(msgs) > 0 {
			// todo: we may want to look at dkim/spf in this case.
			spam := msgs[0].Junk && (len(msgs) == 1 || msgs[1].Junk)
			conclusive := m.MsgFromValidated
			return &spam, conclusive, methodMsgfromFull, "reputation of exact message-from address", nil
		}
		if !m.MsgFromValidated {
			// Look for historic messages that were validated. If present, this is likely spam.
			// Only return as conclusively spam if history also says this From-address sent
			// spam.
			q := messageQuery(&store.Message{MsgFromLocalpart: m.MsgFromLocalpart, MsgFromDomain: m.MsgFromDomain, MsgFromValidated: true}, 3*year, 2)
			msgs = xmessageList(q, "msgfromfull-validated")
			if len(msgs) > 0 {
				spam := msgs[0].Junk && (len(msgs) == 1 || msgs[1].Junk)
				return xtrue, spam, methodMsgfromFull, "unvalidated message with validated historic messages with exact message-from address", nil
			}
		}

		// Look if we ever sent to this address. If so, we accept,
		qr := bstore.QueryTx[store.Recipient](tx)
		qr.FilterEqual("Localpart", m.MsgFromLocalpart)
		qr.FilterEqual("Domain", m.MsgFromDomain)
		qr.FilterGreaterEqual("Sent", now.Add(-3*year))
		if xrecipientExists(qr) {
			return xfalse, true, methodMsgtoFull, "exact message-from address was earlier message recipient", nil
		}

		// Look for domain match, then for organizational domain match.
		for _, orgdomain := range []bool{false, true} {
			qm := store.Message{}
			var method reputationMethod
			var source, descr string
			if orgdomain {
				qm.MsgFromOrgDomain = m.MsgFromOrgDomain
				method = methodMsgfromOrgDomain
				source = "organizational domain of message-from address"
				descr = "msgfromorgdomain"
			} else {
				qm.MsgFromDomain = m.MsgFromDomain
				method = methodMsgfromDomain
				source = "exact domain of message-from address"
				descr = "msgfromdomain"
			}

			q := messageQuery(&qm, 2*year, 20)
			q.FilterEqual("MsgFromValidated", m.MsgFromValidated)
			msgs := xmessageList(q, descr)
			if len(msgs) > 0 {
				nonjunk := 0
				for _, m := range msgs {
					if !m.Junk {
						nonjunk++
					}
				}
				if 100*nonjunk/len(msgs) > 80 {
					reasonText = fmt.Sprintf("positive reputation with %s based on %d messages", source, len(msgs))
					return xfalse, true, method, reasonText, nil
				}
				if nonjunk == 0 {
					// Only conclusive with at least 3 different localparts.
					localparts := map[smtp.Localpart]struct{}{}
					for _, m := range msgs {
						localparts[m.MsgFromLocalpart] = struct{}{}
						if len(localparts) == 3 {
							reasonText = fmt.Sprintf("negative reputation of at least 3 addresses with %s based on %d messages", source, len(msgs))
							return xtrue, true, method, reasonText, nil
						}
					}
					reasonText = fmt.Sprintf("negative reputation with %s based on %d messages", source, len(msgs))
					return xtrue, false, method, reasonText, nil
				}
				// Mixed signals from domain. We don't want to block a new sender.
				reasonText = fmt.Sprintf("mixed signals with %s based on %d messages", source, len(msgs))
				return nil, false, method, reasonText, nil
			}
			if !m.MsgFromValidated {
				// Look for historic messages that were validated. If present, this is likely spam.
				// Only return as conclusively spam if history also says this From-address sent
				// spam.
				q := messageQuery(&qm, 2*year, 2)
				q.FilterEqual("MsgFromValidated", true)
				msgs = xmessageList(q, descr+"-validated")
				if len(msgs) > 0 {
					spam := msgs[0].Junk && (len(msgs) == 1 || msgs[1].Junk)
					reasonText = fmt.Sprintf("unvalidated message with %s while we have validated messages from that source", source)
					return xtrue, spam, method, reasonText, nil
				}
			}

			// Look if we ever sent to this address. If so, we accept,
			qr := bstore.QueryTx[store.Recipient](tx)
			if orgdomain {
				qr.FilterEqual("OrgDomain", m.MsgFromOrgDomain)
				method = methodMsgtoOrgDomain
				source = "organizational domain of message-from address"
			} else {
				qr.FilterEqual("Domain", m.MsgFromDomain)
				method = methodMsgtoDomain
				source = "exact domain of message-from address"
			}
			qr.FilterGreaterEqual("Sent", now.Add(-2*year))
			if xrecipientExists(qr) {
				reasonText = fmt.Sprintf("%s was recipient address", source)
				return xfalse, true, method, reasonText, nil
			}
		}
	}

	// DKIM and SPF.
	// We only use identities that passed validation. Failed identities are ignored. ../rfc/6376:2447
	// todo future: we could do something with the DKIM identity (i=) field if it is more specific than just the domain (d=).
	dkimspfsignals := []float64{}
	dkimspfreasondoms := []string{}
	dkimspfmsgs := 0
	for _, dom := range m.DKIMDomains {
		q := messageQuery(nil, year/2, 50)
		q.FilterIn("DKIMDomains", dom)
		msgs := xmessageList(q, "dkimdomain")
		if len(msgs) > 0 {
			nspam := 0
			for _, m := range msgs {
				if m.Junk {
					nspam++
				}
			}
			pspam := float64(nspam) / float64(len(msgs))
			dkimspfsignals = append(dkimspfsignals, pspam)
			dkimspfreasondoms = append(dkimspfreasondoms, dom)
			dkimspfmsgs = len(msgs)
		}
	}
	if m.MailFromValidated || m.EHLOValidated {
		var dom string
		var msgs []store.Message
		if m.MailFromValidated && m.MailFromDomain != "" {
			dom = m.MailFromDomain
			q := messageQuery(&store.Message{MailFromLocalpart: m.MailFromLocalpart, MailFromDomain: m.MailFromDomain}, year/2, 50)
			msgs = xmessageList(q, "mailfrom")
			if len(msgs) == 0 {
				q := messageQuery(&store.Message{MailFromDomain: m.MailFromDomain}, year/2, 50)
				msgs = xmessageList(q, "mailfromdomain")
			}
		}
		if len(msgs) == 0 && m.EHLOValidated && m.EHLODomain != "" {
			dom = m.EHLODomain
			q := messageQuery(&store.Message{EHLODomain: m.EHLODomain}, year/2, 50)
			msgs = xmessageList(q, "ehlodomain")
		}
		if len(msgs) > 0 {
			nspam := 0
			for _, m := range msgs {
				if m.Junk {
					nspam++
				}
			}
			pspam := float64(nspam) / float64(len(msgs))
			dkimspfsignals = append(dkimspfsignals, pspam)
			dkimspfreasondoms = append(dkimspfreasondoms, dom)
			if len(msgs) > dkimspfmsgs {
				dkimspfmsgs = len(msgs)
			}
		}
	}
	if len(dkimspfsignals) > 0 {
		var nham, nspam int
		var hamdoms, spamdoms []string
		for i, p := range dkimspfsignals {
			d, _ := dns.ParseDomain(dkimspfreasondoms[i])
			if p < .1 {
				nham++
				hamdoms = append(hamdoms, d.XName(smtputf8))
			} else if p > .9 {
				nspam++
				spamdoms = append(spamdoms, d.XName(smtputf8))
			}
		}
		if nham > 0 && nspam == 0 {
			reasonText = fmt.Sprintf("positive dkim/spf reputation for domain(s) %s", strings.Join(hamdoms, ","))
			return xfalse, true, methodDKIMSPF, reasonText, nil
		}
		if nspam > 0 && nham == 0 {
			reasonText = fmt.Sprintf("negative dkim/spf reputation for domain(s) %s", strings.Join(hamdoms, ","))
			return xtrue, dkimspfmsgs > 1, methodDKIMSPF, reasonText, nil
		}
		reasonText = fmt.Sprintf("mixed dkim/spf reputation, positive for %s, negative for %s", strings.Join(hamdoms, ","), strings.Join(spamdoms, ","))
		return nil, false, methodDKIMSPF, reasonText, nil
	}

	// IP-based. A wider mask needs more messages to be conclusive.
	// We require the resulting signal to be strong, i.e. likely ham or likely spam.
	var msgs []store.Message
	var need int
	var method reputationMethod
	var ip string
	if m.RemoteIPMasked1 != "" {
		q := messageQuery(&store.Message{RemoteIPMasked1: m.RemoteIPMasked1}, year/4, 50)
		msgs = xmessageList(q, "ip1")
		need = 2
		method = methodIP1
		ip = m.RemoteIPMasked1
	}
	if len(msgs) == 0 && m.RemoteIPMasked2 != "" {
		q := messageQuery(&store.Message{RemoteIPMasked2: m.RemoteIPMasked2}, year/4, 50)
		msgs = xmessageList(q, "ip2")
		need = 5
		method = methodIP2
		ip = m.RemoteIPMasked2
	}
	if len(msgs) == 0 && m.RemoteIPMasked3 != "" {
		q := messageQuery(&store.Message{RemoteIPMasked3: m.RemoteIPMasked3}, year/4, 50)
		msgs = xmessageList(q, "ip3")
		need = 10
		method = methodIP3
		ip = m.RemoteIPMasked3
	}
	if len(msgs) > 0 {
		nspam := 0
		for _, m := range msgs {
			if m.Junk {
				nspam++
			}
		}
		pspam := float64(nspam) / float64(len(msgs))
		var spam *bool
		if pspam < .25 {
			spam = xfalse
		} else if pspam > .75 {
			spam = xtrue
		}
		conclusive := len(msgs) >= need && (pspam <= 0.1 || pspam >= 0.9)
		v6 := strings.Contains(m.RemoteIP, ":")
		reasonText = fmt.Sprintf("reputation for ip %s%s, spam score %.2f", ip, maskclasses[classmask{v6, method}], pspam)
		return spam, conclusive, method, reasonText, nil
	}

	return nil, false, methodNone, "no address/spf/dkim/ip reputation", nil
}

type classmask struct {
	v6     bool
	method reputationMethod
}

var maskclasses = map[classmask]string{
	{false, methodIP1}: "/32",
	{false, methodIP2}: "/26",
	{false, methodIP3}: "/21",
	{true, methodIP1}:  "/64",
	{true, methodIP2}:  "/48",
	{true, methodIP3}:  "/32",
}
