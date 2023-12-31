// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

// For authentication/security results.
const underlineGreen = '#50c40f'
const underlineRed = '#e15d1c'
const underlineBlue = '#09f'
const underlineGrey = '#aaa'
const underlineYellow = 'yellow'

// join elements in l with the results of calls to efn. efn can return
// HTMLElements, which cannot be inserted into the dom multiple times, hence the
// function.
const join = (l: any, efn: () => any): any[] => {
	const r: any[] = []
	const n = l.length
	for (let i = 0; i < n; i++) {
		r.push(l[i])
		if (i < n-1) {
			r.push(efn())
		}
	}
	return r
}

// addLinks turns a line of text into alternating strings and links. Links that
// would end with interpunction followed by whitespace are returned with that
// interpunction moved to the next string instead.
const addLinks = (text: string): (HTMLAnchorElement | string)[] => {
	// todo: look at ../rfc/3986 and fix up regexp. we should probably accept utf-8.
	const re = RegExp('(http|https):\/\/([:%0-9a-zA-Z._~!$&\'/()*+,;=-]+@)?([\\[\\]0-9a-zA-Z.-]+)(:[0-9]+)?([:@%0-9a-zA-Z._~!$&\'/()*+,;=-]*)(\\?[:@%0-9a-zA-Z._~!$&\'/()*+,;=?-]*)?(#[:@%0-9a-zA-Z._~!$&\'/()*+,;=?-]*)?')
	const r = []
	while (text.length > 0) {
		const l = re.exec(text)
		if (!l) {
			r.push(text)
			break
		}
		let s = text.substring(0, l.index)
		let url = l[0]
		text = text.substring(l.index+url.length)
		r.push(s)
		// If URL ends with interpunction, and next character is whitespace or end, don't
		// include the interpunction in the URL.
		if (!text || /^[ \t\r\n]/.test(text)) {
			if (/[)>][!,.:;?]$/.test(url)) {
				text = url.substring(url.length-2)+text
				url = url.substring(0, url.length-2)
			} else if (/[)>!,.:;?]$/.test(url)) {
				text = url.substring(url.length-1)+text
				url = url.substring(0, url.length-1)
			}
		}
		r.push(dom.a(url, attr.href(url), attr.target('_blank'), attr.rel('noopener noreferrer')))
	}
	return r
}

// renderText turns text into a renderable element with ">" interpreted as quoted
// text (with different levels), and URLs replaced by links.
const renderText = (text: string): HTMLElement => {
	return dom.div(text.split('\n').map(line => {
		let q = 0
		for (const c of line) {
			if (c == '>') {
				q++
			} else if (c !== ' ') {
				break
			}
		}

		if (q == 0) {
			return [addLinks(line), '\n']
		}
		q = (q-1)%3 + 1
		return dom.div(dom._class('quoted'+q), addLinks(line))
	}))
}

const displayName = (s: string) => {
	// ../rfc/5322:1216
	// ../rfc/5322:1270
	// todo: need support for group addresses (eg "undisclosed recipients").
	// ../rfc/5322:697
	const specials = /[()<>\[\]:;@\\,."]/
	if (specials.test(s)) {
		return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
	}
	return s
}

// format an address with both name and email address.
const formatAddress = (a: api.MessageAddress): string => {
	let s = '<' + a.User + '@' + a.Domain.ASCII + '>'
	if (a.Name) {
		s = displayName(a.Name) + ' ' + s
	}
	return s
}

// returns an address with all available details, including unicode version if
// available.
const formatAddressFull = (a: api.MessageAddress): string => {
	let s = ''
	if (a.Name) {
		s = a.Name + ' '
	}
	s += '<' + a.User + '@' + a.Domain.ASCII + '>'
	if (a.Domain.Unicode) {
		s += ' (' + a.User + '@' + a.Domain.Unicode + ')'
	}
	return s
}

// like formatAddressFull, but underline domain with dmarc-like validation if appropriate.
const formatAddressFullValidated = (a: api.MessageAddress, m: api.Message, use: boolean): (string | HTMLElement)[] => {
	const domainText = (s: string): HTMLElement | string => {
		if (!use) {
			return s
		}
		// We want to show how "approved" this message is given the message From's domain.
		// We have MsgFromValidation available. It's not the greatest, being a mix of
		// potential strict validations, actual DMARC policy validation, potential relaxed
		// validation, but no explicit fail or (temporary) errors. We also don't know if
		// historic messages were from a mailing list. We could add a heuristic based on
		// List-Id headers, but it would be unreliable...
		// todo: add field to Message with the exact results.
		let color = ''
		let title = ''
		switch (m.MsgFromValidation) {
		case api.Validation.ValidationStrict:
			color = underlineGreen
			title = 'Message would have matched a strict DMARC policy.'
			break
		case api.Validation.ValidationDMARC:
			color = underlineGreen
			title = 'Message matched DMARC policy of domain.'
			break
		case api.Validation.ValidationRelaxed:
			color = underlineGreen
			title = 'Domain did not have a DMARC policy, but message would match a relaxed policy if it had existed.'
			break;
		case api.Validation.ValidationNone:
			if (m.IsForward || m.IsMailingList) {
				color = underlineBlue
				title = 'Message would not pass DMARC policy, but came in through a configured mailing list or forwarding address.'
			} else {
				color = underlineRed
				title = 'Either domain did not have a DMARC policy, or message did not adhere to it.'
			}
			break;
		default:
			// Also for zero value, when unknown. E.g. for sent messages added with IMAP.
			return dom.span(attr.title('Unknown DMARC verification result.'), s)
		}
		return dom.span(attr.title(title), style({borderBottom: '1.5px solid '+color, textDecoration: 'none'}), s)
	}

	let l: (string | HTMLElement)[] = []
	if (a.Name) {
		l.push(a.Name + ' ')
	}
	l.push('<' + a.User + '@')
	l.push(domainText(a.Domain.ASCII))
	l.push('>')
	if (a.Domain.Unicode) {
		// Not underlining because unicode domain may already cause underlining.
		l.push(' (' + a.User + '@' + a.Domain.Unicode+')')
	}
	return l
}

// format just the name if present and it doesn't look like an address, or otherwise just the email address.
const formatAddressShort = (a: api.MessageAddress): string => {
	const n = a.Name
	if (n && !n.includes('<') && !n.includes('@') && !n.includes('>')) {
		return n
	}
	return '<' + a.User + '@' + a.Domain.ASCII + '>'
}

// return just the email address.
const formatEmailASCII = (a: api.MessageAddress): string => {
	return a.User + '@' + a.Domain.ASCII
}

const equalAddress = (a: api.MessageAddress, b: api.MessageAddress) => {
	return (!a.User || !b.User || a.User === b.User) && a.Domain.ASCII === b.Domain.ASCII
}

const addressList = (allAddrs: boolean, l: api.MessageAddress[]) => {
	if (l.length <= 5 || allAddrs) {
		return dom.span(join(l.map(a => formatAddressFull(a)), () => ', '))
	}
	let elem = dom.span(
		join(
			l.slice(0, 4).map(a => formatAddressFull(a)),
			() => ', '
		),
		' ',
		dom.clickbutton('More...', attr.title('More addresses:\n'+l.slice(4).map(a => formatAddressFull(a)).join(',\n')), function click() {
			const nelem = dom.span(
				join(l.map(a => formatAddressFull(a)), () => ', '),
				' ',
				dom.clickbutton('Less...', function click() {
					elem.replaceWith(addressList(allAddrs, l))
				}),
			)
			elem.replaceWith(nelem)
			elem = nelem
		})
	)
	return elem
}

// loadMsgheaderView loads the common message headers into msgheaderelem.
// if refineKeyword is set, labels are shown and a click causes a call to
// refineKeyword.
const loadMsgheaderView = (msgheaderelem: HTMLElement, mi: api.MessageItem, moreHeaders: string[], refineKeyword: null | ((kw: string) => Promise<void>), allAddrs: boolean) => {
	const msgenv = mi.Envelope
	const received = mi.Message.Received
	const receivedlocal = new Date(received.getTime())
	dom._kids(msgheaderelem,
		// todo: make addresses clickable, start search (keep current mailbox if any)
		dom.tr(
			dom.td('From:', style({textAlign: 'right', color: '#555', whiteSpace: 'nowrap'})),
			dom.td(
				style({width: '100%'}),
				dom.div(style({display: 'flex', justifyContent: 'space-between'}),
					dom.div(join((msgenv.From || []).map(a => formatAddressFullValidated(a, mi.Message, !!msgenv.From && msgenv.From.length === 1)), () => ', ')),
					dom.div(
						attr.title('Received: ' + received.toString() + ';\nDate header in message: ' + (msgenv.Date ? msgenv.Date.toString() : '(missing/invalid)')),
						receivedlocal.toDateString() + ' ' + receivedlocal.toTimeString().split(' ')[0],
					),
				)
			),
		),
		(msgenv.ReplyTo || []).length === 0 ? [] : dom.tr(
			dom.td('Reply-To:', style({textAlign: 'right', color: '#555', whiteSpace: 'nowrap'})),
			dom.td(join((msgenv.ReplyTo || []).map(a => formatAddressFull(a)), () => ', ')),
		),
		dom.tr(
			dom.td('To:', style({textAlign: 'right', color: '#555', whiteSpace: 'nowrap'})),
			dom.td(addressList(allAddrs, msgenv.To || [])),
		),
		(msgenv.CC || []).length === 0 ? [] : dom.tr(
			dom.td('Cc:', style({textAlign: 'right', color: '#555', whiteSpace: 'nowrap'})),
			dom.td(addressList(allAddrs, msgenv.CC || [])),
		),
		(msgenv.BCC || []).length === 0 ? [] : dom.tr(
			dom.td('Bcc:', style({textAlign: 'right', color: '#555', whiteSpace: 'nowrap'})),
			dom.td(addressList(allAddrs, msgenv.BCC || [])),
		),
		dom.tr(
			dom.td('Subject:', style({textAlign: 'right', color: '#555', whiteSpace: 'nowrap'})),
			dom.td(
				dom.div(style({display: 'flex', justifyContent: 'space-between'}),
					dom.div(msgenv.Subject || ''),
					dom.div(
						mi.Message.IsForward ? dom.span(style({padding: '0px 0.15em', fontSize: '.9em'}), 'Forwarded', attr.title('Message came in from a forwarded address. Some message authentication policies, like DMARC, were not evaluated.')) : [],
						mi.Message.IsMailingList ? dom.span(style({padding: '0px 0.15em', fontSize: '.9em'}), 'Mailing list', attr.title('Message was received from a mailing list. Some message authentication policies, like DMARC, were not evaluated.')) : [],
						mi.Message.ReceivedTLSVersion === 1 ? dom.span(style({padding: '0px 0.15em', fontSize: '.9em', borderBottom: '1.5px solid #e15d1c'}), 'Without TLS', attr.title('Message received (last hop) without TLS.')) : [],
						mi.Message.ReceivedTLSVersion > 1 && !mi.Message.ReceivedRequireTLS ? dom.span(style({padding: '0px 0.15em', fontSize: '.9em', borderBottom: '1.5px solid #50c40f'}), 'With TLS', attr.title('Message received (last hop) with TLS.')) : [],
						mi.Message.ReceivedRequireTLS ? dom.span(style({padding: '.1em .3em', fontSize: '.9em', backgroundColor: '#d2f791', border: '1px solid #ccc', borderRadius: '3px'}), 'With RequireTLS', attr.title('Transported with RequireTLS, ensuring TLS along the entire delivery path from sender to recipient, with TLS certificate verification through MTA-STS and/or DANE.')) : [],
						mi.IsSigned ? dom.span(style({backgroundColor: '#666', padding: '0px 0.15em', fontSize: '.9em', color: 'white', borderRadius: '.15em'}), 'Message has a signature') : [],
						mi.IsEncrypted ? dom.span(style({backgroundColor: '#666', padding: '0px 0.15em', fontSize: '.9em', color: 'white', borderRadius: '.15em'}), 'Message is encrypted') : [],
						refineKeyword ? (mi.Message.Keywords || []).map(kw =>
							dom.clickbutton(dom._class('keyword'), kw, async function click() {
								await refineKeyword(kw)
							}),
						) : [],
					),
				)
			),
		),
		moreHeaders.map(k =>
			dom.tr(
				dom.td(k+':', style({textAlign: 'right', color: '#555', whiteSpace: 'nowrap'})),
				dom.td(),
			)
		),
	)
}
