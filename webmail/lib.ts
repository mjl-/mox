// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

// We build CSS rules in JS. For several reasons:
// - To keep the style definitions closer to their use.
// - To make it easier to provide both light/regular and dark mode colors.
// - To use class names for styling, instead of the the many inline styles.
//   Makes it easier to look through a DOM, and easier to change the style of all
//   instances of a class.

// We keep the default/regular styles and dark-mode styles in separate stylesheets.
const cssStyle = dom.style(attr.type('text/css'))
document.head.appendChild(cssStyle)
const styleSheet = cssStyle.sheet!

const cssStyleDark = dom.style(attr.type('text/css'))
document.head.appendChild(cssStyleDark)
const styleSheetDark = cssStyleDark.sheet!
styleSheetDark.insertRule('@media (prefers-color-scheme: dark) {}')
const darkModeRule = styleSheetDark.cssRules[0] as CSSMediaRule

let cssRules: { [selector: string]: string} = {} // For ensuring a selector has a single definition.
// Ensure a selector has the given style properties. If a style value is an array,
// it must have 2 elements. The first is the default value, the second used for a
// rule for dark mode.
const ensureCSS = (selector: string, styles: { [prop: string]: string | number | string[] }, important?: boolean) => {
	// Check that a selector isn't added again with different styling. Only during development.
	const checkConsistency = location.hostname === 'localhost'
	if (cssRules[selector]) {
		if (checkConsistency) {
			const exp = JSON.stringify(styles)
			if (cssRules[selector] !== exp) {
				throw new Error('duplicate css rule for selector '+selector+', had '+cssRules[selector] + ', next '+exp)
			}
		}
		return
	}
	cssRules[selector] = checkConsistency ? JSON.stringify(styles) : 'x'

	const index = styleSheet.cssRules.length
	styleSheet.insertRule(selector + ' {}', index)
	const st = (styleSheet.cssRules[index] as CSSStyleRule).style
	let darkst: CSSStyleDeclaration | undefined
	for (let [k, v] of Object.entries(styles)) {
		// We've kept the camel-case in our code which we had from when we did "st[prop] =
		// value". It is more convenient as object keys. So convert to kebab-case.
		k = k.replace(/[A-Z]/g, s => '-'+s.toLowerCase())
		if (Array.isArray(v)) {
			if (v.length !== 2) {
				throw new Error('2 elements required for light/dark mode style, got '+v.length)
			}
			if (!darkst) {
				const darkIndex = darkModeRule.cssRules.length
				darkModeRule.insertRule(selector + ' {}', darkIndex)
				darkst = (darkModeRule.cssRules[darkIndex] as CSSStyleRule).style
			}
			st.setProperty(k, ''+v[0], important ? 'important' : '')
			darkst.setProperty(k, ''+v[1], important ? 'important' : '')
		} else {
			st.setProperty(k, ''+v, important ? 'important' : '')
		}
	}
}

// Ensure CSS styling exists for a class, returning the same kind of object
// returned by dom._class, for use with dom.*-building functions.
const css = (className: string, styles: { [prop: string]: string | number | string[] }, important?: boolean): { _class: string[] } => {
	ensureCSS('.'+className, styles, important)
	return dom._class(className)
}

// todo: reduce number of colors. hopefully we can derive some colors from a few base colors (making them brighter/darker, or shifting hue, etc). then make them configurable through settings.
// todo: add the standard padding and border-radius, perhaps more.
// todo: could make some of these {prop: value} objects and pass them directly to css()
const styles = {
	color: ['black', '#ddd'],
	colorMild: ['#555', '#bbb'],
	colorMilder: ['#666', '#aaa'],
	backgroundColor: ['white', '#222'],
	backgroundColorMild: ['#f8f8f8', '#080808'],
	backgroundColorMilder: ['#999', '#777'],
	borderColor: ['#ccc', '#333'],
	mailboxesTopBackgroundColor: ['#fdfdf1', 'rgb(26, 18, 0)'],
	msglistBackgroundColor: ['#f5ffff', 'rgb(4, 19, 13)'],
	boxShadow: ['0 0 20px rgba(0, 0, 0, 0.1)', '0px 0px 20px #000'],

	buttonBackground: ['#eee', '#222'],
	buttonBorderColor: ['#888', '#666'],
	buttonHoverBackground: ['#ddd', '#333'],

	overlayOpaqueBackgroundColor: ['#eee', '#011'],
	overlayBackgroundColor: ['rgba(0, 0, 0, 0.2)', 'rgba(0, 0, 0, 0.5)'],

	popupColor: ['black', 'white'],
	popupBackgroundColor: ['white', 'rgb(49, 50, 51)'],
	popupBorderColor: ['#ccc', '#555'],

	highlightBackground: ['gold', '#a70167'],
	highlightBorderColor: ['#8c7600', 'rgb(253, 31, 167)'],
	highlightBackgroundHover: ['#ffbd21', 'rgb(113, 4, 71)'],

	mailboxActiveBackground: ['linear-gradient(135deg, #ffc7ab 0%, #ffdeab 100%)', 'linear-gradient(135deg, rgb(182, 61, 0) 0%, rgb(140, 90, 13) 100%)'],
	mailboxHoverBackgroundColor: ['#eee', 'rgb(66, 31, 21)'],

	msgItemActiveBackground: ['linear-gradient(135deg, #8bc8ff 0%, #8ee5ff 100%)', 'linear-gradient(135deg, rgb(4, 92, 172) 0%, rgb(2, 123, 160) 100%)'],
	msgItemHoverBackgroundColor: ['#eee', 'rgb(7, 51, 72)'],
	msgItemFocusBorderColor: ['#2685ff', '#2685ff'],

	buttonTristateOnBackground: ['#c4ffa9', 'rgb(39, 126, 0)'],
	buttonTristateOffBackground: ['#ffb192', 'rgb(191, 65, 15)'],

	warningBackgroundColor: ['#ffca91', 'rgb(168, 87, 0)'],

	successBackground: ['#d2f791', '#1fa204'],
	emphasisBackground: ['#666', '#aaa'],

	// For authentication/security results.
	underlineGreen: '#50c40f',
	underlineRed: '#e15d1c',
	underlineBlue: '#09f',
	underlineGrey: '#888',
}
const styleClasses = {
	// For quoted text, with multiple levels of indentations.
	quoted: [
		css('quoted1', {color: ['#03828f', '#71f2ff']}), // red
		css('quoted2', {color: ['#c7445c', 'rgb(236, 76, 76)']}), // green
		css('quoted3', {color: ['#417c10', 'rgb(115, 230, 20)']}), // blue
	],
	// When text switches between unicode scripts.
	scriptswitch: css('scriptswitch', {textDecoration: 'underline 2px', textDecorationColor: ['#dca053', 'rgb(232, 143, 30)']}),
	textMild: css('textMild', {color: styles.colorMild}),
	// For keywords (also known as flags/labels/tags) on messages.
	keyword: css('keyword', {padding: '0 .15em', borderRadius: '.15em', fontWeight: 'normal', fontSize: '.9em', margin: '0 .15em', whiteSpace: 'nowrap', background: styles.highlightBackground, color: styles.color, border: '1px solid', borderColor: styles.highlightBorderColor}),
	msgHeaders: css('msgHeaders', {marginBottom: '1ex', width: '100%'}),
}

ensureCSS('.msgHeaders td', {wordBreak: 'break-word'}) // Prevent horizontal scroll bar for long header values.
ensureCSS('.keyword.keywordCollapsed', {opacity: .75}),

// Generic styling.
ensureCSS('*', {fontSize: 'inherit', fontFamily: "'ubuntu', 'lato', sans-serif", margin: 0, padding: 0, boxSizing: 'border-box'})
ensureCSS('.mono, .mono *', {fontFamily: "'ubuntu mono', monospace"})
ensureCSS('table td, table th', {padding: '.15em .25em'})
ensureCSS('.pad', {padding: '.5em'})
ensureCSS('iframe', {border: 0})
ensureCSS('img, embed, video, iframe', {backgroundColor: 'white', color: 'black'})
ensureCSS(':root', {backgroundColor: styles.backgroundColor, color: styles.color})
ensureCSS('a', {color: ['rgb(9, 107, 194)', 'rgb(99, 182, 255)']})
ensureCSS('a:visited', {color: ['rgb(7, 4, 193)', 'rgb(199, 99, 255)']})

// For message view with multiple inline elements (often a single text and multiple messages).
ensureCSS('.textmulti > *:nth-child(even)', {backgroundColor: ['#f4f4f4', '#141414']})
ensureCSS('.textmulti > *', {padding: '2ex .5em', margin: '-.5em' /* compensate pad */ })
ensureCSS('.textmulti > *:first-child', {padding: '.5em'})


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

// From https://developer.mozilla.org/en-US/docs/Web/Media/Formats/Image_types
const imageTypes = [
	'image/avif',
	'image/webp',
	'image/gif',
	'image/png',
	'image/jpeg',
	'image/apng',
	'image/svg+xml',
]
const isImage = (a: api.Attachment) => imageTypes.includes((a.Part.MediaType + '/' + a.Part.MediaSubType).toLowerCase())

// addLinks turns a line of text into alternating strings and links. Links that
// would end with interpunction followed by whitespace are returned with that
// interpunction moved to the next string instead.
const addLinks = (text: string): (HTMLAnchorElement | string)[] => {
	// todo: look at ../rfc/3986 and fix up regexp. we should probably accept utf-8.
	const re = RegExp('(?:(http|https):\/\/|mailto:)([:%0-9a-zA-Z._~!$&\'/()*+,;=-]+@)?([\\[\\]0-9a-zA-Z.-]+)(:[0-9]+)?([:@%0-9a-zA-Z._~!$&\'/()*+,;=-]*)(\\?[:@%0-9a-zA-Z._~!$&\'/()*+,;=?-]*)?(#[:@%0-9a-zA-Z._~!$&\'/()*+,;=?-]*)?')
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
		r.push(dom.a(url, attr.href(url), url.startsWith('mailto:') ? [] : [attr.target('_blank'), attr.rel('noopener noreferrer')]))
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
		return dom.div(styleClasses.quoted[q%styleClasses.quoted.length], addLinks(line))
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

const formatDomain = (dom: api.Domain) => dom.Unicode || dom.ASCII

// format an address with both name and email address.
const formatAddress = (a: api.MessageAddress): string => {
	let s = '<' + a.User + '@' + formatDomain(a.Domain) + '>'
	if (a.Name) {
		s = displayName(a.Name) + ' ' + s
	}
	return s
}

// Like formatAddress, but returns an element with a title (for hover) with the ASCII domain, in case of IDN.
const formatAddressElem = (a: api.MessageAddress): string | HTMLElement => {
	if (!a.Domain.Unicode) {
		return formatAddress(a)
	}
	return dom.span(a.Name ? [displayName(a.Name), ' '] : '', '<', a.User, '@', dom.span(attr.title(a.Domain.ASCII), formatDomain(a.Domain)), '>')
}

// like formatAddress, but underline domain with dmarc-like validation if appropriate.
const formatAddressValidated = (a: api.MessageAddress, m: api.Message, use: boolean): (string | HTMLElement)[] => {
	const domainText = (domstr: string, ascii: string): HTMLElement | string => {
		if (!use) {
			return domstr
		}
		const extra = domstr === ascii ? '' : '; domain '+ascii
		// We want to show how "approved" this message is given the message From's domain.
		// We have MsgFromValidation available. It's not the greatest, being a mix of
		// potential strict validations, actual DMARC policy validation, potential relaxed
		// validation, but no explicit fail or (temporary) errors. We also don't know if
		// historic messages were from a mailing list. We could add a heuristic based on
		// List-Id headers, but it would be unreliable...
		// todo: add field to Message with the exact results.
		let name = ''
		let color = ''
		let title = ''
		switch (m.MsgFromValidation) {
		case api.Validation.ValidationStrict:
			name = 'Strict'
			color = styles.underlineGreen
			title = 'Message would have matched a strict DMARC policy.'
			break
		case api.Validation.ValidationDMARC:
			name = 'DMARC'
			color = styles.underlineGreen
			title = 'Message matched DMARC policy of domain.'
			break
		case api.Validation.ValidationRelaxed:
			name = 'Relaxed'
			color = styles.underlineGreen
			title = 'Domain did not have a DMARC policy, but message would match a relaxed policy if it had existed.'
			break;
		case api.Validation.ValidationNone:
			if (m.IsForward || m.IsMailingList) {
				name = 'Forwardlist'
				color = styles.underlineBlue
				title = 'Message would not pass DMARC policy, but came in through a configured mailing list or forwarding address.'
			} else {
				name = 'Bad'
				color = styles.underlineRed
				title = 'Either domain did not have a DMARC policy, or message did not adhere to it.'
			}
			break;
		default:
			// Also for zero value, when unknown. E.g. for sent messages added with IMAP.
			name = 'Unknown'
			title = 'Unknown DMARC verification result.'
			return dom.span(attr.title(title+extra), domstr)
		}
		return dom.span(attr.title(title+extra), css('addressValidation'+name, {borderBottom: '1.5px solid', borderBottomColor: color, textDecoration: 'none'}), domstr)
	}

	let l: (string | HTMLElement)[] = []
	if (a.Name) {
		l.push(a.Name + ' ')
	}
	l.push('<' + a.User + '@')
	l.push(domainText(formatDomain(a.Domain), a.Domain.ASCII))
	l.push('>')
	return l
}

// format just the name if present and it doesn't look like an address, or otherwise just the email address.
const formatAddressShort = (a: api.MessageAddress, junk: boolean): string => {
	const n = a.Name
	if (!junk && n && !n.includes('<') && !n.includes('@') && !n.includes('>')) {
		return n
	}
	return '<' + a.User + '@' + formatDomain(a.Domain) + '>'
}

// return just the email address.
const formatEmail = (a: api.MessageAddress) => a.User + '@' + formatDomain(a.Domain)

const equalAddress = (a: api.MessageAddress, b: api.MessageAddress) => {
	return (!a.User || !b.User || a.User === b.User) && a.Domain.ASCII === b.Domain.ASCII
}

const addressList = (allAddrs: boolean, l: api.MessageAddress[]) => {
	if (l.length <= 5 || allAddrs) {
		return dom.span(join(l.map(a => formatAddressElem(a)), () => ', '))
	}
	let elem = dom.span(
		join(
			l.slice(0, 4).map(a => formatAddressElem(a)),
			() => ', '
		),
		' ',
		dom.clickbutton('More...', attr.title('More addresses:\n'+l.slice(4).map(a => formatAddress(a)).join(',\n')), function click() {
			const nelem = dom.span(
				join(l.map(a => formatAddressElem(a)), () => ', '),
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
	const msgHeaderFieldStyle = css('msgHeaderField', {textAlign: 'right', color: styles.colorMild, whiteSpace: 'nowrap'})
	const msgAttrStyle = css('msgAttr', {padding: '0px 0.15em', fontSize: '.9em'})
	dom._kids(msgheaderelem,
		// todo: make addresses clickable, start search (keep current mailbox if any)
		dom.tr(
			dom.td('From:', msgHeaderFieldStyle),
			dom.td(
				style({width: '100%'}),
				dom.div(css('msgFromReceivedSpread', {display: 'flex', justifyContent: 'space-between'}),
					dom.div(join((msgenv.From || []).map(a => formatAddressValidated(a, mi.Message, !!msgenv.From && msgenv.From.length === 1)), () => ', ')),
					dom.div(
						attr.title('Received: ' + received.toString() + ';\nDate header in message: ' + (msgenv.Date ? msgenv.Date.toString() : '(missing/invalid)')),
						receivedlocal.toDateString() + ' ' + receivedlocal.toTimeString().split(' ')[0],
					),
				)
			),
		),
		(msgenv.ReplyTo || []).length === 0 ? [] : dom.tr(
			dom.td('Reply-To:', msgHeaderFieldStyle),
			dom.td(join((msgenv.ReplyTo || []).map(a => formatAddressElem(a)), () => ', ')),
		),
		dom.tr(
			dom.td('To:', msgHeaderFieldStyle),
			dom.td(addressList(allAddrs, msgenv.To || [])),
		),
		(msgenv.CC || []).length === 0 ? [] : dom.tr(
			dom.td('Cc:', msgHeaderFieldStyle),
			dom.td(addressList(allAddrs, msgenv.CC || [])),
		),
		(msgenv.BCC || []).length === 0 ? [] : dom.tr(
			dom.td('Bcc:', msgHeaderFieldStyle),
			dom.td(addressList(allAddrs, msgenv.BCC || [])),
		),
		dom.tr(
			dom.td('Subject:', msgHeaderFieldStyle),
			dom.td(
				dom.div(css('msgSubjectAttrsSpread', {display: 'flex', justifyContent: 'space-between'}),
					dom.div(msgenv.Subject || ''),
					dom.div(
						mi.Message.IsForward ? dom.span(msgAttrStyle, 'Forwarded', attr.title('Message came in from a forwarded address. Some message authentication policies, like DMARC, were not evaluated.')) : [],
						mi.Message.IsMailingList ? dom.span(msgAttrStyle, 'Mailing list', attr.title('Message was received from a mailing list. Some message authentication policies, like DMARC, were not evaluated.')) : [],
						mi.Message.ReceivedTLSVersion === 1 ? dom.span(msgAttrStyle, css('msgAttrNoTLS', {borderBottom: '1.5px solid', borderBottomColor: styles.underlineRed}), 'Without TLS', attr.title('Message received (last hop) without TLS.')) : [],
						mi.Message.ReceivedTLSVersion > 1 && !mi.Message.ReceivedRequireTLS ? dom.span(msgAttrStyle, css('msgAttrTLS', {borderBottom: '1.5px solid', borderBottomColor: styles.underlineGreen}), 'With TLS', attr.title('Message received (last hop) with TLS.')) : [],
						mi.Message.ReceivedRequireTLS ? dom.span(css('msgAttrRequireTLS', {padding: '.1em .3em', fontSize: '.9em', backgroundColor: styles.successBackground, border: '1px solid', borderColor: styles.borderColor, borderRadius: '3px'}), 'With RequireTLS', attr.title('Transported with RequireTLS, ensuring TLS along the entire delivery path from sender to recipient, with TLS certificate verification through MTA-STS and/or DANE.')) : [],
						mi.IsSigned ? dom.span(msgAttrStyle, css('msgAttrSigned', {backgroundColor: styles.colorMild, color: styles.backgroundColorMild, borderRadius: '.15em'}), 'Message has a signature') : [],
						mi.IsEncrypted ? dom.span(msgAttrStyle, css('msgAttrEncrypted', {backgroundColor: styles.colorMild, color: styles.backgroundColorMild, borderRadius: '.15em'}), 'Message is encrypted') : [],
						refineKeyword ? (mi.Message.Keywords || []).map(kw =>
							dom.clickbutton(styleClasses.keyword, dom._class('keywordButton'), kw, async function click() {
								await refineKeyword(kw)
							}),
						) : [],
					),
				)
			),
		),
		moreHeaders.map(k =>
			dom.tr(
				dom.td(k+':', msgHeaderFieldStyle),
				dom.td(),
			)
		),
	)
}
