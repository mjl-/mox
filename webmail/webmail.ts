// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

/*
Webmail is a self-contained webmail client.

Typescript is used for type safety, but otherwise we try not to rely on any
JS/TS tools/frameworks etc, they often complicate/obscure how things work. The
DOM and styles are directly manipulated, so to develop on this code you need to
know about DOM functions. With a few helper functions in the dom object,
interaction with the DOM is still relatively high-level, but also allows for
more low-level techniques like rendering of text in a way that highlights text
that switches unicode blocks/scripts. We use typescript in strict mode, see
top-level tsc.sh. We often specify types for function parameters, but not
return types, since typescript is good at deriving return types.

There is no mechanism to automatically update a view when properties change. The
UI is split/isolated in components called "views", which expose only their root
HTMLElement for inclusion in another component or the top-level document. A view
has functions that other views (e.g. parents) can call for to propagate updates
or retrieve data. We have these views:

- Mailboxlist, in the bar on the list with all mailboxes.
- Mailbox, a single mailbox in the mailbox list.
- Search, with form for search criteria, opened through search bar.
- Msglist, the list of messages for the selected mailbox or search query.
- Msgitem, a message in Msglist, shown as a single line.
- Msg, showing the contents of a single selected message.
- Compose, when writing a new message (or reply/forward).

Most of the data is transferred over an SSE connection. It sends the initial
list of mailboxes, sends message summaries for the currently selected mailbox or
search query and sends changes as they happen, e.g. added/removed messages,
changed flags, etc. Operations that modify data are done through API calls. The
typescript API is generated from the Go types and functions. Displayed message
contents are also retrieved through an API call.

HTML messages are potentially dangerous. We display them in a separate iframe,
with contents served in a separate HTTP request, with Content-Security-Policy
headers that prevent executing scripts or loading potentially unwanted remote
resources. We cannot load the HTML in an inline iframe, because the iframe "csp"
attribute to set a Content-Security-Policy is not supported by all modern
browsers (safari and firefox don't support it at the time of writing). Text
messages are rendered inside the webmail client, making URLs clickable,
highlighting unicode script/block changes and rendering quoted text in a
different color.

Browsers to test with: Firefox, Chromium, Safari, Edge.

To simulate slow API calls and SSE events:

	localStorage.setItem('sherpats-debug', JSON.stringify({waitMinMsec: 2000, waitMaxMsec: 4000}))

Show additional headers of messages:

	settingsPut({...settings, showHeaders: ['User-Agent', 'X-Mailer', 'Message-Id', 'List-Id', 'List-Post', 'X-Mox-Reason']})

Enable logging and reload afterwards:

	localStorage.setItem('log', 'yes')

Enable consistency checking in UI updates:

	settingsPut({...settings, checkConsistency: true})

- todo: in msglistView, show names of people we have sent to, and address otherwise.
- todo: implement settings stored in the server, such as mailboxCollapsed, keyboard shortcuts. also new settings for displaying email as html by default for configured sender address or domain. name to use for "From", optional default Reply-To and Bcc addresses, signatures (per address), configured labels/keywords with human-readable name, colors and toggling with shortcut keys 1-9.
- todo: in msglist, if our address is in the from header, list addresses in the to/cc/bcc, it's likely a sent folder
- todo: automated tests? perhaps some unit tests, then ui scenario's.
- todo: compose, wrap lines
- todo: composing of html messages. possibly based on contenteditable. would be good if we can include original html, but quoted. must make sure to not include dangerous scripts/resources, or sandbox it.
- todo: make alt up/down keys work on html iframe too. requires loading it from sameorigin, to get access to its inner document.
- todo: reconnect with last known modseq and don't clear the message list, only update it
- todo: resize and move of compose window
- todo: find and use svg icons for flags in the msgitemView. junk (fire), forwarded, replied, attachment (paperclip), flagged (flag), phishing (?). also for special-use mailboxes (junk, trash, archive, draft, sent). should be basic and slim.
- todo: for embedded messages (message/rfc822 or message/global), allow viewing it as message, perhaps in a popup?
- todo: for content-disposition: inline, show images alongside text?
- todo: only show orange underline where it could be a problem? in addresses and anchor texts. we may be lighting up a christmas tree now, desensitizing users.
- todo: saved searches that are displayed below list of mailboxes, for quick access to preset view
- todo: when search on free-form text is active, highlight the searched text in the message view.
- todo: composeView: save as draft, periodically and when closing.
- todo: forwarding of html parts, including inline attachments, so the html version can be rendered like the original by the receiver.
- todo: buttons/mechanism to operate on all messages in a mailbox/search query, without having to list and select all messages. e.g. clearing flags/labels.
- todo: can we detect if browser supports proper CSP? if not, refuse to load html messages?
- todo: more search criteria? Date header field (instead of time received), text vs html (only, either or both), attachment filenames and sizes
- todo: integrate more of the account page into webmail? importing/exporting messages, configuring delivery rules (possibly with sieve). for messages moved out of inbox to non-special-use mailbox, show button that helps make an automatic rule to move such messages again (e.g. based on message From address, message From domain or List-ID header).
- todo: configurable keyboard shortcuts? we use strings like "ctrl p" which we already generate and match on, add a mapping from command name to cmd* functions, and have a map of keys to command names. the commands for up/down with shift/ctrl modifiers may need special attention.
- todo: nicer address input fields like other mail clients do. with tab to autocomplete and turn input into a box and delete removing of the entire address.
- todo: consider composing messages with bcc headers that are kept as message Bcc headers, optionally with checkbox.
- todo: improve accessibility
- todo: threading mode where we don't show messages in Trash/Sent in thread?
- todo: msglistView: preload next message?
- todo: previews of zip files
- todo: undo?
- todo: mobile-friendly version. should perhaps be a completely different app, because it is so different.
- todo: basic vim key bindings in textarea/input. or just let users use a browser plugin.
*/

class ConsistencyError extends Error {
}

const zindexes = {
	splitter: '1',
	compose: '2',
	searchView: '3',
	searchbar: '4',
	popup: '5',
	popover: '5',
	attachments: '5',
	shortcut: '6',
}

// From HTML.
declare let page: HTMLElement
declare let moxversion: string

// All logging goes through log() instead of console.log, except "should not happen" logging.
let log: (...args: any[]) => void = () => {}
try {
	if (localStorage.getItem('log') || location.hostname === 'localhost') {
		log = console.log
	}
} catch (err) {}

const defaultSettings = {
	showShortcuts: true, // Whether to briefly show shortcuts in bottom left when a button is clicked that has a keyboard shortcut.
	mailboxesWidth: 240,
	layout: 'auto', // Automatic switching between left/right and top/bottom layout, based on screen width.
	leftWidthPct: 50, // Split in percentage of remaining width for left/right layout.
	topHeightPct: 40, // Split in percentage of remaining height for top/bottom layout.
	msglistflagsWidth: 40, // Width in pixels of flags column in message list.
	msglistageWidth: 70, // Width in pixels of age column.
	msglistfromPct: 30, // Percentage of remaining width in message list to use for "from" column. The remainder is for the subject.
	refine: '', // Refine filters, e.g. '', 'attachments', 'read', 'unread', 'label:...'.
	orderAsc: false, // Order from most recent to least recent by default.
	ignoreErrorsUntil: 0, // For unhandled javascript errors/rejected promises, we normally show a popup for details, but users can ignore them for a week at a time.
	showHTML: false, // Whether we show HTML version of email instead of plain text if both are present.
	mailboxCollapsed: {} as {[mailboxID: number]: boolean}, // Mailboxes that are collapsed.
	showAllHeaders: false, // Whether to show all message headers.
	showHeaders: [] as string[], // Additional message headers to show.
	threading: api.ThreadMode.ThreadOn,
	checkConsistency: location.hostname === 'localhost', // Enable UI update consistency checks, default only for local development.
}
const parseSettings = (): typeof defaultSettings => {
	try {
		const v = window.localStorage.getItem('settings')
		if (!v) {
			return {...defaultSettings}
		}
		const x = JSON.parse(v)
		const def: {[key: string]: any} = defaultSettings
		const getString = (k: string, ...l: string[]): string => {
			const v = x[k]
			if (typeof v !== 'string' || l.length > 0 && !l.includes(v)) {
				return def[k] as string
			}
			return v
		}
		const getBool = (k: string): boolean => {
			const v = x[k]
			return typeof v === 'boolean' ? v : def[k] as boolean
		}
		const getInt = (k: string): number => {
			const v = x[k]
			return typeof v === 'number' ? v : def[k] as number
		}
		let mailboxCollapsed: {[mailboxID: number]: boolean} = x.mailboxCollapsed
		if (!mailboxCollapsed || typeof mailboxCollapsed !== 'object') {
			mailboxCollapsed = def.mailboxCollapsed
		}
		const getStringArray = (k: string): string[] => {
			const v = x[k]
			if (v && Array.isArray(v) && (v.length === 0 || typeof v[0] === 'string')) {
				return v
			}
			return def[k] as string[]
		}

		return {
			refine: getString('refine'),
			orderAsc: getBool('orderAsc'),
			mailboxesWidth: getInt('mailboxesWidth'),
			leftWidthPct: getInt('leftWidthPct'),
			topHeightPct: getInt('topHeightPct'),
			msglistflagsWidth: getInt('msglistflagsWidth'),
			msglistageWidth: getInt('msglistageWidth'),
			msglistfromPct: getInt('msglistfromPct'),
			ignoreErrorsUntil: getInt('ignoreErrorsUntil'),
			layout: getString('layout', 'auto', 'leftright', 'topbottom'),
			showShortcuts: getBool('showShortcuts'),
			showHTML: getBool('showHTML'),
			mailboxCollapsed: mailboxCollapsed,
			showAllHeaders: getBool('showAllHeaders'),
			showHeaders: getStringArray('showHeaders'),
			threading: getString('threading', api.ThreadMode.ThreadOff, api.ThreadMode.ThreadOn, api.ThreadMode.ThreadUnread) as api.ThreadMode,
			checkConsistency: getBool('checkConsistency'),
		}
	} catch (err) {
		console.log('getting settings from localstorage', err)
		return {...defaultSettings}
	}
}

// Store new settings. Called as settingsPut({...settings, updatedField: newValue}).
const settingsPut = (nsettings: typeof defaultSettings) => {
	settings = nsettings
	try {
		window.localStorage.setItem('settings', JSON.stringify(nsettings))
	} catch (err) {
		console.log('storing settings in localstorage', err)
	}
}

let settings = parseSettings()

// All addresses for this account, can include "@domain" wildcard, User is empty in
// that case. Set when SSE connection is initialized.
let accountAddresses: api.MessageAddress[] = []

// Username/email address of login. Used as default From address when composing
// a new message.
let loginAddress: api.MessageAddress | null = null

// Localpart config (catchall separator and case sensitivity) for each domain
// the account has an address for.
let domainAddressConfigs: {[domainASCII: string]: api.DomainAddressConfig} = {}

const client = new api.Client()

// Link returns a clickable link with rel="noopener noreferrer".
const link = (href: string, anchorOpt?: string): HTMLElement => dom.a(attr.href(href), attr.rel('noopener noreferrer'), attr.target('_blank'), anchorOpt || href)

// Returns first own account address matching an address in l.
const envelopeIdentity = (l: api.MessageAddress[]): api.MessageAddress | null => {
	for (const a of l) {
		const ma = accountAddresses.find(aa => (!aa.User || aa.User === a.User) && aa.Domain.ASCII === a.Domain.ASCII)
		if (ma) {
			return {Name: ma.Name, User: a.User, Domain: a.Domain}
		}
	}
	return null
}

// We can display keyboard shortcuts when a user clicks a button that has a shortcut.
let shortcutElem = dom.div(style({fontSize: '2em', position: 'absolute', left: '.25em', bottom: '.25em', backgroundColor: '#888', padding: '0.25em .5em', color: 'white', borderRadius: '.15em'}))
let shortcutTimer = 0
const showShortcut = (c: string) => {
	if (!settings.showShortcuts) {
		return
	}
	if (shortcutTimer) {
		window.clearTimeout(shortcutTimer)
	}
	shortcutElem.remove()
	dom._kids(shortcutElem, c)
	document.body.appendChild(shortcutElem)
	shortcutTimer = setTimeout(() => {
		shortcutElem.remove()
		shortcutTimer = 0
	}, 1500)
}

// Commands for buttons that can have a shortcut.
type command = () => Promise<void>

// Call cmdfn and display the shortcut for the command if it occurs in shortcuts.
const shortcutCmd = async (cmdfn: command, shortcuts: {[key: string]: command}) => {
	let shortcut = ''
	for (const k in shortcuts) {
		if (shortcuts[k] === cmdfn) {
			shortcut = k
			break
		}
	}
	if (shortcut) {
		showShortcut(shortcut)
	}
	await cmdfn()
}

// clickCmd returns a click handler that runs a cmd and shows its shortcut.
const clickCmd = (cmdfn: command, shortcuts: {[key: string]: command}) => {
	return async function click() {
		shortcutCmd(cmdfn, shortcuts)
	}
}

// enterCmd returns a keydown handler that runs a cmd when Enter is pressed and shows its shortcut.
const enterCmd = (cmdfn: command, shortcuts: {[key: string]: command}) => {
	return async function keydown(e: KeyboardEvent) {
		if (e.key === 'Enter') {
			e.stopPropagation()
			shortcutCmd(cmdfn, shortcuts)
		}
	}
}

// keyHandler returns a function that handles keyboard events for a map of
// shortcuts, calling the shortcut function if found.
const keyHandler = (shortcuts: {[key: string]: command}) => {
	return async (k: string, e: KeyboardEvent) => {
		const fn = shortcuts[k]
		if (fn) {
			e.preventDefault()
			e.stopPropagation()
			fn()
		}
	}
}

// For attachment sizes.
const formatSize = (size: number) => size > 1024*1024 ? (size/(1024*1024)).toFixed(1)+'mb' : Math.ceil(size/1024)+'kb'

// Parse size as used in minsize: and maxsize: in the search bar.
const parseSearchSize = (s: string): [string, number] => {
	s = s.trim()
	if (!s) {
		return ['', 0]
	}
	const digits = s.match(/^([0-9]+)/)?.[1]
	if (!digits) {
		return ['', 0]
	}
	let num = parseInt(digits)
	if (isNaN(num)) {
		return ['', 0]
	}
	const suffix = s.substring(digits.length).trim().toLowerCase()
	if (['b', 'kb', 'mb', 'gb'].includes(suffix)) {
		return [digits+suffix, num*Math.pow(2, 10*['b', 'kb', 'mb', 'gb'].indexOf(suffix))]
	}
	if (['k', 'm', 'g'].includes(suffix)) {
		return [digits+suffix+'b', num*Math.pow(2, 10*(1+['k', 'm', 'g'].indexOf(suffix)))]
	}
	return ['', 0]
}

// JS date does not allow months and days as single digit, it requires a 0
// prefix in those cases, so fix up such dates.
const fixDate = (dt: string): string => {
	const t = dt.split('-')
	if (t.length !== 3) {
		return dt
	}
	if(t[1].length === 1) {
		t[1] = '0'+t[1]
	}
	if(t[2].length === 1) {
		t[2] = '0'+t[2]
	}
	return t.join('-')
}

// Parse date and/or time, for use in searchbarElem with start: and end:.
const parseSearchDateTime = (s: string, isstart: boolean): string | undefined => {
	const t = s.split('T', 2)
	if (t.length === 2) {
		const d = new Date(fixDate(t[0]) + 'T'+t[1])
		return d ? d.toJSON() : undefined
	} else if (t.length === 1) {
		if (isNaN(Date.parse(fixDate(t[0])))) {
			const d = new Date(fixDate(t[0]))
			if (!isstart) {
				d.setDate(d.getDate()+1)
			}
			return d.toJSON()
		} else {
			const tm = t[0]
			const now = new Date()
			const pad0 = (v: number) => v <= 9 ? '0'+v : ''+v
			const d = new Date([now.getFullYear(), pad0(now.getMonth()+1), pad0(now.getDate())].join('-')+'T'+tm)
			return d ? d.toJSON() : undefined
		}
	}
	return undefined
}

// The searchbarElem is parsed into tokens, each with: minus prefix ("not" match),
// a tag (e.g. "minsize" in "minsize:1m"), a string, and whether the string was
// quoted (text that starts with a dash or looks like a tag needs to be quoted). A
// final ending quote is implicit. All input can be parsed into tokens, there is no
// invalid syntax (at most unexpected parsing).
type Token = [boolean, string, boolean, string]

const dquote = (s: string): string => '"' + s.replaceAll('"', '""') + '"'
const needsDquote = (s: string): boolean => /[ \t"]/.test(s)
const packToken = (t: Token): string => (t[0] ? '-' : '') + (t[1] ? t[1]+':' : '') + (t[2] || needsDquote(t[3]) ? dquote(t[3]) : t[3])

// Parse the text from the searchbarElem into tokens. All input is valid.
const parseSearchTokens = (s: string): Token[] => {
	if (!s) {
		return []
	}
	const l: Token[] = [] // Tokens we gathered.

	let not = false
	let quoted = false // If double quote was seen.
	let quoteend = false // Possible closing quote seen. Can also be escaped quote.
	let t = '' // Current token. We only keep non-empty tokens.
	let tquoted = false // If t started out quoted.
	const add = () => {
		if (t && (tquoted || !t.includes(':'))) {
			l.push([not, '', tquoted, t])
		} else if (t) {
			const tag = t.split(':', 1)[0]
			l.push([not, tag, tquoted, t.substring(tag.length+1)])
		}
		t = ''
		quoted = false
		quoteend = false
		tquoted = false
		not = false
	}
	;[...s].forEach(c => {
		if (quoteend) {
			if (c === '"') {
				t += '"'
				quoteend = false
			} else if (t) {
				add()
			}
		} else if (quoted && c === '"') {
			quoteend = true
		} else if (c === '"') {
			quoted = true
			if (!t) {
				tquoted = true
			}
		} else if (!quoted && (c === ' ' || c === '\t')) {
			add()
		} else if (c === '-' && !t && !tquoted && !not) {
			not = true
		} else {
			t += c
		}
	})
	add()
	return l
}

// returns a filter with empty/zero required fields.
const newFilter = (): api.Filter => {
	return {
		MailboxID: 0,
		MailboxChildrenIncluded: false,
		MailboxName: '',
		Attachments: api.AttachmentType.AttachmentIndifferent,
		SizeMin: 0,
		SizeMax: 0,
	}
}
const newNotFilter = (): api.NotFilter => {
	return {
		Attachments: api.AttachmentType.AttachmentIndifferent,
	}
}

// We keep the original strings typed in by the user, we don't send them to the
// backend, so we keep them separately from api.Filter.
type FilterStrs = {
	Oldest: string
	Newest: string
	SizeMin: string
	SizeMax: string
}

// Parse search bar into filters that we can use to populate the form again, or
// send to the server.
const parseSearch = (searchquery: string, mailboxlistView: MailboxlistView): [api.Filter, api.NotFilter, FilterStrs] => {
	const tokens = parseSearchTokens(searchquery)

	const fpos = newFilter()
	fpos.MailboxID = -1 // All mailboxes excluding Trash/Junk/Rejects.
	const notf = newNotFilter()
	const strs = {Oldest: '', Newest: '', SizeMin: '', SizeMax: ''}
	tokens.forEach(t => {
		const [not, tag, _, s] = t
		const f = not ? notf : fpos

		if (!not) {
			if (tag === 'mb' || tag === 'mailbox') {
				const mb = mailboxlistView.findMailboxByName(s)
				if (mb) {
					fpos.MailboxID = mb.ID
				} else if (s === '') {
					fpos.MailboxID = 0 // All mailboxes, including Trash/Junk/Rejects.
				} else {
					fpos.MailboxName = s
					fpos.MailboxID = 0
				}
				return
			} else if (tag === 'submb') {
				fpos.MailboxChildrenIncluded = true
				return
			} else if (tag === 'start') {
				const dt = parseSearchDateTime(s, true)
				if (dt) {
					fpos.Oldest = new Date(dt)
					strs.Oldest = s
					return
				}
			} else if (tag === 'end') {
				const dt = parseSearchDateTime(s, false)
				if (dt) {
					fpos.Newest = new Date(dt)
					strs.Newest = s
					return
				}
			} else if (tag === 'a' || tag === 'attachments') {
				if (s === 'none' || s === 'any' || s === 'image' || s === 'pdf' || s === 'archive' || s === 'zip' || s === 'spreadsheet' || s === 'document' || s === 'presentation') {
					fpos.Attachments = s as api.AttachmentType
					return
				}
			} else if (tag === 'h' || tag === 'header') {
				const k = s.split(':')[0]
				const v = s.substring(k.length+1)
				if (!fpos.Headers) {
					fpos.Headers = [[k, v]]
				} else {
					fpos.Headers.push([k, v])
				}
				return
			} else if (tag === 'minsize') {
				const [str, size] = parseSearchSize(s)
				if (str) {
					fpos.SizeMin = size
					strs.SizeMin = str
					return
				}
			} else if (tag === 'maxsize') {
				const [str, size] = parseSearchSize(s)
				if (str) {
					fpos.SizeMax = size
					strs.SizeMax = str
					return
				}
			}
		}
		if (tag === 'f' || tag === 'from') {
			f.From = f.From || []
			f.From.push(s)
			return
		} else if (tag === 't' || tag === 'to') {
			f.To = f.To || []
			f.To.push(s)
			return
		} else if (tag === 's' || tag === 'subject') {
			f.Subject = f.Subject || []
			f.Subject.push(s)
			return
		} else if (tag === 'l' || tag === 'label') {
			f.Labels = f.Labels || []
			f.Labels.push(s)
			return
		}
		f.Words = f.Words || []
		f.Words.push((tag ? tag+':' : '') + s)
	})
	return [fpos, notf, strs]
}

// Errors in catch statements are of type unknown, we normally want its
// message.
const errmsg = (err: unknown) => ''+((err as any).message || '(no error message)')

// Return keydown handler that creates or updates the datalist of its target with
// autocompletion addresses. The tab key completes with the first selection.
let datalistgen = 1
const newAddressComplete = (): any => {
	let datalist: HTMLElement
	let completeMatches: string[] | null
	let completeSearch: string
	let completeFull: boolean

	return async function keydown(e: KeyboardEvent) {
		const target = e.target as HTMLInputElement
		if (!datalist) {
			datalist = dom.datalist(attr.id('list-'+datalistgen++))
			target.parentNode!.insertBefore(datalist, target)
			target.setAttribute('list', datalist.id)
		}

		const search = target.value

		if (e.key === 'Tab') {
			const matches = (completeMatches || []).filter(s => s.includes(search))
			if (matches.length > 0) {
				target.value = matches[0]
				return
			} else if ((completeMatches || []).length === 0 && !search) {
				return
			}
		}

		if (completeSearch && search.includes(completeSearch) && completeFull) {
			dom._kids(datalist, (completeMatches || []).filter(s => s.includes(search)).map(s => dom.option(s)))
			return
		} else if (search === completeSearch) {
			return
		}
		try {
			[completeMatches, completeFull] = await withStatus('Autocompleting addresses', client.CompleteRecipient(search))
			completeSearch = search
			dom._kids(datalist, (completeMatches || []).map(s => dom.option(s)))
		} catch (err) {
			log('autocomplete error', errmsg(err))
		}
	}
}

const flagList = (miv: MsgitemView): HTMLElement[] => {
	const msgflags: [string, string][] = [] // Flags for message in miv.
	const othermsgflags: [string, string][] = [] // Flags for descendant messages if miv is collapsed. Only flags not in msgflags.
	let l = msgflags

	const seen = new Set<string>()
	const flag = (v: boolean, char: string, name: string) => {
		if (v && !seen.has(name)) {
			l.push([name, char])
			seen.add(name)
		}
	}
	const addFlags = (mi: api.MessageItem) => {
		const m = mi.Message
		flag(m.Answered, 'r', 'Replied/answered')
		flag(m.Flagged, '!', 'Flagged')
		flag(m.Forwarded, 'f', 'Forwarded')
		flag(m.Junk, 'j', 'Junk')
		flag(m.Deleted, 'D', 'Deleted, used in IMAP, message will likely be removed soon.')
		flag(m.Draft, 'd', 'Draft')
		flag(m.Phishing, 'p', 'Phishing')
		flag(!m.Junk && !m.Notjunk, '?', 'Unclassified, neither junk nor not junk: message does not contribute to spam classification of new incoming messages')
		flag(mi.Attachments && mi.Attachments.length > 0 ? true : false, 'a', 'Has at least one attachment')
		if (m.ThreadMuted) {
			flag(true, 'm', 'Muted, new messages are automatically marked as read.')
		}
	}
	addFlags(miv.messageitem)
	if (miv.isCollapsedThreadRoot()) {
		l = othermsgflags
		for (miv of miv.descendants()) {
			addFlags(miv.messageitem)
		}
	}

	return msgflags.map(t => dom.span(dom._class('msgitemflag'), t[1], attr.title(t[0])))
		.concat(othermsgflags.map(t => dom.span(dom._class('msgitemflag'), dom._class('msgitemflagcollapsed'), t[1], attr.title(t[0]))))
}

// Turn filters from the search bar into filters with the refine filters (buttons
// above message list) applied, to send to the server in a request. The original
// filters are not modified.
const refineFilters = (f: api.Filter, notf: api.NotFilter): [api.Filter, api.NotFilter] => {
	const refine = settings.refine
	if (refine) {
		f = {...f}
		notf = {...notf}
		if (refine === 'unread') {
			notf.Labels = [...(notf.Labels || [])]
			notf.Labels = (notf.Labels || []).concat(['\\Seen'])
		} else if (refine === 'read') {
			f.Labels = [...(f.Labels || [])]
			f.Labels = (f.Labels || []).concat(['\\Seen'])
		} else if (refine === 'attachments') {
			f.Attachments = 'any' as api.AttachmentType
		} else if (refine.startsWith('label:')) {
			f.Labels = [...(f.Labels || [])]
			f.Labels = (f.Labels || []).concat([refine.substring('label:'.length)])
		}
	}
	return [f, notf]
}

// For dragging the splitter bars. This function should be called on mousedown. e
// is the mousedown event. Move is the function to call when the bar was dragged,
// typically adjusting styling, e.g. absolutely positioned offsets, possibly based
// on the event.clientX and element bounds offset.
const startDrag = (e: MouseEvent, move: (e: MouseEvent) => void): void => {
	if (e.buttons === 1) {
		e.preventDefault()
		e.stopPropagation()
		const stop = () => {
			document.body.removeEventListener('mousemove', move)
			document.body.removeEventListener('mouseup', stop)
		}
		document.body.addEventListener('mousemove', move)
		document.body.addEventListener('mouseup', stop)
	}
}

// Returns two handler functions: one for focus that sets a placeholder on the
// target element, and one for blur that restores/clears it again. Keeps forms uncluttered,
// only showing contextual help just before you start typing.
const focusPlaceholder = (s: string): any[] => {
	let orig = ''
	return [
		function focus(e: FocusEvent) {
			const target = (e.target! as HTMLElement)
			orig = target.getAttribute('placeholder') || ''
			target.setAttribute('placeholder', s)
		},
		function blur(e: FocusEvent) {
			const target = (e.target! as HTMLElement)
			if (orig) {
				target.setAttribute('placeholder', orig)
			} else {
				target.removeAttribute('placeholder')
			}
		},
	]
}

// Parse a location hash into search terms (if any), selected message id (if
// any) and filters.
// Optional message id at the end, with ",<num>".
// Otherwise mailbox or 'search '-prefix search string: #Inbox or #Inbox,1 or "#search mb:Inbox" or "#search mb:Inbox,1"
const parseLocationHash = (mailboxlistView: MailboxlistView): [string | undefined, number, api.Filter, api.NotFilter] => {
	let hash = decodeURIComponent((window.location.hash || '#').substring(1))
	const m = hash.match(/,([0-9]+)$/)
	let msgid = 0
	if (m) {
		msgid = parseInt(m[1])
		hash = hash.substring(0, hash.length-(','.length+m[1].length))
	}
	let initmailbox, initsearch
	if (hash.startsWith('search ')) {
		initsearch = hash.substring('search '.length).trim()
	}
	let f: api.Filter, notf: api.NotFilter
	if (initsearch) {
		[f, notf, ] = parseSearch(initsearch, mailboxlistView)
	} else {
		initmailbox = hash
		if (!initmailbox) {
			initmailbox = 'Inbox'
		}
		f = newFilter()
		const mb = mailboxlistView.findMailboxByName(initmailbox)
		if (mb) {
			f.MailboxID = mb.ID
		} else {
			f.MailboxName = initmailbox
		}
		notf = newNotFilter()
	}
	return [initsearch, msgid, f, notf]
}

// For HTMLElements like fieldset, input, buttons. We make it easy to disable
// elements while the API call they initiated is still in progress. Prevents
// accidental duplicate API call for twitchy clickers.
interface Disablable {
	disabled: boolean
}

// When API calls are made, we start displaying what we're doing after 1 second.
// Hopefully the command has completed by then, but slow operations, or in case of
// high latency, we'll start showing it. And hide it again when done. This should
// give a non-cluttered instant feeling most of the time, but informs the user when
// needed.
let statusElem: HTMLElement
const withStatus = async <T>(action: string, promise: Promise<T>, disablable?: Disablable, noAlert?: boolean): Promise<T> => {
	let elem: HTMLElement | undefined
	let id = window.setTimeout(() => {
		elem = dom.span(action+'...')
		statusElem.appendChild(elem)
		id = 0
	}, 1000)
	// Could be the element we are going to disable, causing it to lose its focus. We'll restore afterwards.
	let origFocus = document.activeElement
	try {
		if (disablable) {
			disablable.disabled = true
		}
		return await promise
	} catch (err) {
		if (id) {
			window.clearTimeout(id)
			id = 0
		}
		// Generated by client for aborted requests, e.g. for api.ParsedMessage when loading a message.
		if ((err as any).code === 'sherpa:aborted') {
			throw err
		}
		if (!noAlert) {
			window.alert('Error: ' + action + ': ' + errmsg(err))
		}
		// We throw the error again. The ensures callers that await their withStatus call
		// won't continue executing. We have a global handler for uncaught promises, but it
		// only handles javascript-level errors, not api call/operation errors.
		throw err
	} finally {
		if (disablable) {
			disablable.disabled = false
		}
		if (origFocus && document.activeElement !== origFocus && origFocus instanceof HTMLElement) {
			origFocus.focus()
		}
		if (id) {
			window.clearTimeout(id)
		}
		if (elem) {
			elem.remove()
		}
	}
}

// Popover shows kids in a div on top of a mostly transparent overlay on top of
// the document. If transparent is set, the div the kids are in will not get a
// white background. If focus is set, it will be called after adding the
// popover change focus to it, instead of focusing the popover itself.
// Popover returns a function that removes the popover. Clicking the
// transparent overlay, or hitting Escape, closes the popover.
// The div with the kids is positioned around mouse event e, preferably
// towards the right and bottom. But when the position is beyond 2/3's of the
// width or height, it is positioned towards the other direction. The div with
// kids is scrollable if needed.
const popover = (target: HTMLElement, opts: {transparent?: boolean, fullscreen?: boolean}, ...kids: HTMLElement[]) => {
	const origFocus = document.activeElement
	const pos = target.getBoundingClientRect()
	const close = () => {
		if (!root.parentNode) {
			return
		}
		root.remove()
		if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
			origFocus.focus()
		}
	}

	const posx = opts.fullscreen ?
		style({left: 0, right: 0}) :
		(
			pos.x < window.innerWidth/3 ?
				style({left: ''+(pos.x)+'px'}) :
				style({right: ''+(window.innerWidth - pos.x - pos.width)+'px'})
		)
	const posy = opts.fullscreen ?
		style({top: 0, bottom: 0}) :
		(
			pos.y+pos.height > window.innerHeight*2/3 ?
				style({bottom: ''+(window.innerHeight - (pos.y-1))+'px', maxHeight: ''+(pos.y - 1 - 10)+'px'}) :
				style({top: ''+(pos.y+pos.height+1)+'px', maxHeight: ''+(window.innerHeight - (pos.y+pos.height+1) - 10)+'px'})
		)

	let content: HTMLElement
	const root = dom.div(
		style({position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, zIndex: zindexes.popover, backgroundColor: 'rgba(0, 0, 0, 0.2)'}),
		function click(e: MouseEvent) {
			e.stopPropagation()
			close()
		},
		function keydown(e: KeyboardEvent) {
			if (e.key === 'Escape') {
				e.stopPropagation()
				close()
			}
		},
		content=dom.div(
			attr.tabindex('0'),
			style({
				position: 'absolute',
				overflowY: 'auto',
			}),
			posx, posy,
			opts.transparent ? [] : [
				style({
					backgroundColor: 'white',
					padding: '1em',
					borderRadius: '.15em',
					boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)',
				}),
				function click(e: MouseEvent) {
					e.stopPropagation()
				},
			],
			...kids,
		),
	)
	document.body.appendChild(root)
	const first = root.querySelector('input, select, textarea, button')
	if (first && first instanceof HTMLElement) {
		first.focus()
	} else {
		content.focus()
	}
	return close
}

// Popup shows kids in a centered div with white background on top of a
// transparent overlay on top of the window. Clicking the overlay or hitting
// Escape closes the popup. Scrollbars are automatically added to the div with
// kids. Returns a function that removes the popup.
// While a popup is open, no global keyboard shortcuts are handled. Popups get
// to handle keys themselves, e.g. for scrolling.
let popupOpen = false
const popup = (...kids: ElemArg[]) => {
	const origFocus = document.activeElement
	const close = () => {
		if (!root.parentNode) {
			return
		}
		popupOpen = false
		root.remove()
		if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
			origFocus.focus()
		}
	}
	let content: HTMLElement
	const root = dom.div(
		style({position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: 'rgba(0, 0, 0, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: zindexes.popup}),
		function keydown(e: KeyboardEvent) {
			if (e.key === 'Escape') {
				e.stopPropagation()
				close()
			}
		},
		function click(e: MouseEvent) {
			e.stopPropagation()
			close()
		},
		content=dom.div(
			attr.tabindex('0'),
			style({backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto'}),
			function click(e: MouseEvent) {
				e.stopPropagation()
			},
			kids,
		)
	)
	popupOpen = true
	document.body.appendChild(root)
	content.focus()
	return close
}

// Show help popup, with shortcuts and basic explanation.
const cmdHelp = async () => {
	const remove = popup(
		style({padding: '1em 1em 2em 1em'}),
		dom.h1('Help and keyboard shortcuts'),
		dom.div(style({display: 'flex'}),
			dom.div(
				style({width: '40em'}),
				dom.table(
					dom.tr(dom.td(attr.colspan('2'), dom.h2('Global', style({margin: '0'})))),
					[
						['c', 'compose new message'],
						['/', 'search'],
						['i', 'open inbox'],
						['?', 'help'],
						['ctrl ?', 'tooltip for focused element'],
						['ctrl m', 'focus message'],
					].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))),

					dom.tr(dom.td(attr.colspan('2'), dom.h2('Mailbox', style({margin: '0'})))),
					[
						['←', 'collapse'],
						['→', 'expand'],
						['b', 'show more actions'],
					].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))),

					dom.tr(dom.td(attr.colspan('2'), dom.h2('Message list', style({margin: '1ex 0 0 0'})))),
					dom.tr(
						dom.td('↓', ', j'),
						dom.td('down one message'),
						dom.td(attr.rowspan('6'), style({color: '#888', borderLeft: '2px solid #ddd', paddingLeft: '.5em'}), 'hold ctrl to only move focus', dom.br(), 'hold shift to expand selection'),
					),
					[
						[['↑', ', k'], 'up one message'],
						['PageDown, l', 'down one screen'],
						['PageUp, h', 'up one screen'],
						['End, .', 'to last message'],
						['Home, ,', 'to first message'],
						['Space', 'toggle selection of message'],
					].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))),

					[
						['', ''],
						['d, Delete', 'move to trash folder'],
						['D', 'delete permanently'],
						['q', 'move to junk folder'],
						['Q', 'mark not junk'],
						['a', 'move to archive folder'],
						['M', 'mark unread'],
						['m', 'mark read'],
						['u', 'to next unread message'],
						['p', 'to root of thread or previous thread'],
						['n', 'to root of next thread'],
						['S', 'select thread messages'],
						['C', 'toggle thread collapse'],
						['X', 'toggle thread mute, automatically marking new messages as read'],
						['←', 'collapse thread'],
						['→', 'expand thread'],
					].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))),
				),
			),
			dom.div(
				style({width: '40em'}),

				dom.table(
					dom.tr(dom.td(attr.colspan('2'), dom.h2('Compose', style({margin: '0'})))),
					[
						['ctrl Enter', 'send message'],
						['ctrl w', 'cancel message'],
						['ctrl O', 'add To'],
						['ctrl C', 'add Cc'],
						['ctrl B', 'add Bcc'],
						['ctrl Y', 'add Reply-To'],
						['ctrl -', 'remove current address'],
						['ctrl +', 'add address of same type'],
					].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))),

					dom.tr(dom.td(attr.colspan('2'), dom.h2('Message', style({margin: '1ex 0 0 0'})))),
					[
						['r', 'reply or list reply'],
						['R', 'reply all'],
						['f', 'forward message'],
						['v', 'view attachments'],
						['t', 'view text version'],
						['T', 'view HTML version'],
						['o', 'open message in new tab'],
						['O', 'show raw message'],
						['ctrl p', 'print message'],
						['I', 'toggle internals'],
						['ctrl I', 'toggle all headers'],

						['alt k, alt ArrowUp', 'scroll up'],
						['alt j, alt ArrowDown', 'scroll down'],
						['alt K', 'scroll to top'],
						['alt J', 'scroll to end'],
					].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))),

					dom.tr(dom.td(dom.h2('Attachments', style({margin: '1ex 0 0 0'})))),
					[
						['left, h', 'previous attachment'],
						['right, l', 'next attachment'],
						['0', 'first attachment'],
						['$', 'next attachment'],
						['d', 'download'],
					].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))),
				),
				dom.div(style({marginTop: '2ex', marginBottom: '1ex'}), dom.span('Underdotted text', attr.title('Underdotted text shows additional information on hover.')), ' show an explanation or additional information when hovered.'),
				dom.div(style({marginBottom: '1ex'}), 'Multiple messages can be selected by clicking messages while holding the control and/or shift keys. Dragging messages and dropping them on a mailbox moves the messages to that mailbox.'),
				dom.div(style({marginBottom: '1ex'}), 'Text that changes ', dom.span(attr.title('Unicode blocks, e.g. from basic latin to cyrillic, or to emoticons.'), '"character groups"'), ' without whitespace has an ', dom.span(dom._class('scriptswitch'), 'orange underline'), ', which can be a sign of an intent to mislead (e.g. phishing).'),

				settings.showShortcuts ?
					dom.div(style({marginTop: '2ex'}), 'Shortcut keys for mouse operation are shown in the bottom left. ',
						dom.clickbutton('Disable', function click() {
							settingsPut({...settings, showShortcuts: false})
							remove()
							cmdHelp()
						})
					) :
					dom.div(style({marginTop: '2ex'}), 'Shortcut keys for mouse operation are currently not shown. ',
						dom.clickbutton('Enable', function click() {
							settingsPut({...settings, showShortcuts: true})
							remove()
							cmdHelp()
						})
					),
				dom.div(style({marginTop: '2ex'}), 'Mox is open source email server software, this is version '+moxversion+'. Feedback, including bug reports, is appreciated! ', link('https://github.com/mjl-/mox/issues/new'), '.'),
			),
		),
	)
}

// Show tooltips for either the focused element, or otherwise for all elements
// that aren't reachable with tabindex and aren't marked specially to prevent
// them from showing up (e.g. dates in the msglistview, which can also been
// seen by opening a message).
const cmdTooltip = async () => {
	let elems: Element[] = []
	if (document.activeElement && document.activeElement !== document.body) {
		if (document.activeElement.getAttribute('title')) {
			elems = [document.activeElement]
		}
		elems = [...elems, ...document.activeElement.querySelectorAll('[title]')]
	}
	if (elems.length === 0) {
		// Find elements without a parent with tabindex=0.
		const seen: {[title: string]: boolean} = {}
		elems = [...document.body.querySelectorAll('[title]:not(.notooltip):not(.silenttitle)')].filter(e => {
			const title = e.getAttribute('title') || ''
			if (seen[title]) {
				return false
			}
			seen[title] = true
			return !(e instanceof HTMLInputElement || e instanceof HTMLSelectElement || e instanceof HTMLButtonElement || e instanceof HTMLTextAreaElement || e instanceof HTMLAnchorElement || e.getAttribute('tabindex') || e.closest('[tabindex]'))
		})
	}
	if (elems.length === 0) {
		window.alert('No active elements with tooltips found.')
		return
	}
	popover(document.body, {transparent: true, fullscreen: true},
		...elems.map(e => {
			const title = e.getAttribute('title') || ''
			const pos = e.getBoundingClientRect()
			return dom.div(
				style({position: 'absolute', backgroundColor: 'black', color: 'white', borderRadius: '.15em', padding: '.15em .25em', maxWidth: '50em'}),
				pos.x < window.innerWidth/3 ?
					style({left: ''+(pos.x)+'px'}) :
					style({right: ''+(window.innerWidth - pos.x - pos.width)+'px'}),
				pos.y+pos.height > window.innerHeight*2/3 ?
					style({bottom: ''+(window.innerHeight - (pos.y-2))+'px', maxHeight: ''+(pos.y - 2)+'px'}) :
					style({top: ''+(pos.y+pos.height+2)+'px', maxHeight: ''+(window.innerHeight - (pos.y+pos.height+2))+'px'}),
				title,
			)
		})
	)
}

type ComposeOptions = {
	from?: api.MessageAddress[]
	// Addressees should be either directly an email address, or the header form "name
	// <localpart@domain>". They are parsed on the server when the message is
	// submitted.
	to?: string[]
	cc?: string[]
	bcc?: string[]
	replyto?: string
	subject?: string
	isForward?: boolean
	body?: string
	// Message from which to show the attachment to include.
	attachmentsMessageItem?: api.MessageItem
	// Message is marked as replied/answered or forwarded after submitting, and
	// In-Reply-To and References headers are added pointing to this message.
	responseMessageID?: number
}

interface ComposeView {
	root: HTMLElement
	key: (k: string, e: KeyboardEvent) => Promise<void>
}

let composeView: ComposeView | null = null

const compose = (opts: ComposeOptions) => {
	log('compose', opts)

	if (composeView) {
		// todo: should allow multiple
		window.alert('Can only compose one message at a time.')
		return
	}

	type ForwardAttachmentView = {
		root: HTMLElement
		path: number[]
		checkbox: HTMLInputElement
	}

	type AddrView = {
		root: HTMLElement
		input: HTMLInputElement
	}

	let fieldset: HTMLFieldSetElement
	let from: HTMLSelectElement
	let customFrom: HTMLInputElement | null = null
	let subject: HTMLInputElement
	let body: HTMLTextAreaElement
	let attachments: HTMLInputElement

	let toBtn: HTMLButtonElement, ccBtn: HTMLButtonElement, bccBtn: HTMLButtonElement, replyToBtn: HTMLButtonElement, customFromBtn: HTMLButtonElement
	let replyToCell: HTMLElement, toCell: HTMLElement, ccCell: HTMLElement, bccCell: HTMLElement // Where we append new address views.
	let toRow: HTMLElement, replyToRow: HTMLElement, ccRow: HTMLElement, bccRow: HTMLElement // We show/hide rows as needed.
	let toViews: AddrView[] = [], replytoViews: AddrView[] = [], ccViews: AddrView[] = [], bccViews: AddrView[] = []
	let forwardAttachmentViews: ForwardAttachmentView[] = []

	const cmdCancel = async () => {
		composeElem.remove()
		composeView = null
	}

	const submit = async () => {
		const files = await new Promise<api.File[]>((resolve, reject) => {
			const l: api.File[] = []
			if (attachments.files && attachments.files.length === 0) {
				resolve(l)
				return
			}
			[...attachments.files!].forEach(f => {
				const fr = new window.FileReader()
				fr.addEventListener('load', () => {
					l.push({Filename: f.name, DataURI: fr.result as string})
					if (attachments.files && l.length === attachments.files.length) {
						resolve(l)
					}
				})
				fr.addEventListener('error', () => {
					reject(fr.error)
				})
				fr.readAsDataURL(f)
			})
		})

		let replyTo = ''
		if (replytoViews && replytoViews.length === 1 && replytoViews[0].input.value) {
			replyTo = replytoViews[0].input.value
		}

		const forwardAttachmentPaths = forwardAttachmentViews.filter(v => v.checkbox.checked).map(v => v.path)

		const message = {
			From: customFrom ? customFrom.value : from.value,
			To: toViews.map(v => v.input.value).filter(s => s),
			Cc: ccViews.map(v => v.input.value).filter(s => s),
			Bcc: bccViews.map(v => v.input.value).filter(s => s),
			ReplyTo: replyTo,
			UserAgent: 'moxwebmail/'+moxversion,
			Subject: subject.value,
			TextBody: body.value,
			Attachments: files,
			ForwardAttachments: forwardAttachmentPaths.length === 0 ? {MessageID: 0, Paths: []} : {MessageID: opts.attachmentsMessageItem!.Message.ID, Paths: forwardAttachmentPaths},
			IsForward: opts.isForward || false,
			ResponseMessageID: opts.responseMessageID || 0,
		}
		await client.MessageSubmit(message)
		cmdCancel()
	}

	const cmdSend = async () => {
		await withStatus('Sending email', submit(), fieldset)
	}

	const cmdAddTo = async () => { newAddrView('', toViews, toBtn, toCell, toRow) }
	const cmdAddCc = async () => { newAddrView('', ccViews, ccBtn, ccCell, ccRow) }
	const cmdAddBcc = async () => { newAddrView('', bccViews, bccBtn, bccCell, bccRow) }
	const cmdReplyTo = async () => { newAddrView('', replytoViews, replyToBtn, replyToCell, replyToRow, true) }
	const cmdCustomFrom = async () => {
		if (customFrom) {
			return
		}
		customFrom = dom.input(attr.value(from.value), attr.required(''), focusPlaceholder('Jane <jane@example.org>'))
		from.replaceWith(customFrom)
		customFromBtn.remove()
	}

	const shortcuts: {[key: string]: command} = {
		'ctrl Enter': cmdSend,
		'ctrl w': cmdCancel,
		'ctrl O': cmdAddTo,
		'ctrl C': cmdAddCc,
		'ctrl B': cmdAddBcc,
		'ctrl Y': cmdReplyTo,
		// ctrl - and ctrl = (+) not included, they are handled by keydown handlers on in the inputs they remove/add.
	}

	const newAddrView = (addr: string, views: AddrView[], btn: HTMLButtonElement, cell: HTMLElement, row: HTMLElement, single?: boolean) => {
		if (single && views.length !== 0) {
			return
		}

		let input: HTMLInputElement
		const root = dom.span(
			input=dom.input(
				focusPlaceholder('Jane <jane@example.org>'),
				style({width: 'auto'}),
				attr.value(addr),
				newAddressComplete(),
				function keydown(e: KeyboardEvent) {
					if (e.key === '-' && e.ctrlKey) {
						remove()
					} else if (e.key === '=' && e.ctrlKey) {
						newAddrView('', views, btn, cell, row, single)
					} else {
						return
					}
					e.preventDefault()
					e.stopPropagation()
				},
			),
			' ',
			dom.clickbutton('-', style({padding: '0 .25em'}), attr.arialabel('Remove address.'), attr.title('Remove address.'), function click() {
				remove()
				if (single && views.length === 0) {
					btn.style.display = ''
				}
			}),
			' ',
		)

		const remove = () => {
			const i = views.indexOf(v)
			views.splice(i, 1)
			root.remove()
			if (views.length === 0) {
				row.style.display = 'none'
			}
			if (views.length === 0 && single) {
				btn.style.display = ''
			}

			let next = cell.querySelector('input')
			if (!next) {
				let tr = row!.nextSibling as Element
				while (tr) {
					next = tr.querySelector('input')
					if (!next && tr.nextSibling) {
						tr = tr.nextSibling as Element
						continue
					}
					break
				}
			}
			if (next) {
				next.focus()
			}
		}

		const v: AddrView = {root: root, input: input}
		views.push(v)
		cell.appendChild(v.root)
		row.style.display = ''
		if (single) {
			btn.style.display = 'none'
		}
		input.focus()
		return v
	}

	let noAttachmentsWarning: HTMLElement
	const checkAttachments = () => {
		const missingAttachments = !attachments.files?.length && !forwardAttachmentViews.find(v => v.checkbox.checked) && !!body.value.split('\n').find(s => !s.startsWith('>') && s.match(/attach(ed|ment)/))
		noAttachmentsWarning.style.display = missingAttachments ? '' : 'none'
	}

	const normalizeUser = (a: api.MessageAddress) => {
		let user = a.User
		const domconf = domainAddressConfigs[a.Domain.ASCII]
		const localpartCatchallSeparator = domconf.LocalpartCatchallSeparator
		if (localpartCatchallSeparator) {
			user = user.split(localpartCatchallSeparator)[0]
		}
		const localpartCaseSensitive = domconf.LocalpartCaseSensitive
		if (!localpartCaseSensitive) {
			user = user.toLowerCase()
		}
		return user
	}
	// Find own address matching the specified address, taking wildcards, localpart
	// separators and case-sensitivity into account.
	const addressSelf = (addr: api.MessageAddress) => {
		return accountAddresses.find(a => a.Domain.ASCII === addr.Domain.ASCII && (a.User === '' || normalizeUser(a) === normalizeUser(addr)))
	}

	let haveFrom = false
	const fromOptions = accountAddresses.map(a => {
		const selected = opts.from && opts.from.length === 1 && equalAddress(a, opts.from[0]) || loginAddress && equalAddress(a, loginAddress) && (!opts.from || envelopeIdentity(opts.from))
		const o = dom.option(formatAddressFull(a), selected ? attr.selected('') : [])
		if (selected) {
			haveFrom = true
		}
		return o
	})
	if (!haveFrom && opts.from && opts.from.length === 1) {
		const a = addressSelf(opts.from[0])
		if (a) {
			const fromAddr: api.MessageAddress = {Name: a.Name, User: opts.from[0].User, Domain: a.Domain}
			const o = dom.option(formatAddressFull(fromAddr), attr.selected(''))
			fromOptions.unshift(o)
		}
	}

	const composeElem = dom.div(
		style({
			position: 'fixed',
			bottom: '1ex',
			right: '1ex',
			zIndex: zindexes.compose,
			backgroundColor: 'white',
			boxShadow: '0px 0px 20px rgba(0, 0, 0, 0.1)',
			border: '1px solid #ccc',
			padding: '1em',
			minWidth: '40em',
			maxWidth: '70em',
			width: '40%',
			borderRadius: '.25em',
		}),
		dom.form(
			fieldset=dom.fieldset(
				dom.table(
					style({width: '100%'}),
					dom.tr(
						dom.td(
							style({textAlign: 'right', color: '#555'}),
							dom.span('From:'),
						),
						dom.td(
							dom.clickbutton('Cancel', style({float: 'right'}), attr.title('Close window, discarding message.'), clickCmd(cmdCancel, shortcuts)),
							from=dom.select(
								attr.required(''),
								style({width: 'auto'}),
								fromOptions,
							),
							' ',
							toBtn=dom.clickbutton('To', clickCmd(cmdAddTo, shortcuts)), ' ',
							ccBtn=dom.clickbutton('Cc', clickCmd(cmdAddCc, shortcuts)), ' ',
							bccBtn=dom.clickbutton('Bcc', clickCmd(cmdAddBcc, shortcuts)), ' ',
							replyToBtn=dom.clickbutton('ReplyTo', clickCmd(cmdReplyTo, shortcuts)), ' ',
							customFromBtn=dom.clickbutton('From', attr.title('Set custom From address/name.'), clickCmd(cmdCustomFrom, shortcuts)),
						),
					),
					toRow=dom.tr(
						dom.td('To:', style({textAlign: 'right', color: '#555'})),
						toCell=dom.td(style({width: '100%'})),
					),
					replyToRow=dom.tr(
						dom.td('Reply-To:', style({textAlign: 'right', color: '#555'})),
						replyToCell=dom.td(style({width: '100%'})),
					),
					ccRow=dom.tr(
						dom.td('Cc:', style({textAlign: 'right', color: '#555'})),
						ccCell=dom.td(style({width: '100%'})),
					),
					bccRow=dom.tr(
						dom.td('Bcc:', style({textAlign: 'right', color: '#555'})),
						bccCell=dom.td(style({width: '100%'})),
					),
					dom.tr(
						dom.td('Subject:', style({textAlign: 'right', color: '#555'})),
						dom.td(style({width: '100%'}),
							subject=dom.input(focusPlaceholder('subject...'), attr.value(opts.subject || ''), attr.required(''), style({width: '100%'})),
						),
					),
				),
				body=dom.textarea(dom._class('mono'), attr.rows('15'), style({width: '100%'}),
					opts.body || '',
					opts.body && !opts.isForward ? prop({selectionStart: opts.body.length, selectionEnd: opts.body.length}) : [],
					function keyup(e: KeyboardEvent) {
						if (e.key === 'Enter') {
							checkAttachments()
						}
					},
				),
				!(opts.attachmentsMessageItem && opts.attachmentsMessageItem.Attachments && opts.attachmentsMessageItem.Attachments.length > 0) ? [] : dom.div(
					style({margin: '.5em 0'}),
					'Forward attachments: ',
					forwardAttachmentViews=(opts.attachmentsMessageItem?.Attachments || []).map(a => {
						const filename = a.Filename || '(unnamed)'
						const size = formatSize(a.Part.DecodedSize)
						const checkbox = dom.input(attr.type('checkbox'), function change() { checkAttachments() })
						const root = dom.label(checkbox, ' '+filename+' ', dom.span('('+size+') ', style({color: '#666'})))
						const v: ForwardAttachmentView = {
							path: a.Path || [],
							root: root,
							checkbox: checkbox
						}
						return v
					}),
					dom.label(style({color: '#666'}), dom.input(attr.type('checkbox'), function change(e: Event) {
						forwardAttachmentViews.forEach(v => v.checkbox.checked = (e.target! as HTMLInputElement).checked)
					}), ' (Toggle all)')
				),
				noAttachmentsWarning=dom.div(style({display: 'none', backgroundColor: '#fcd284', padding: '0.15em .25em', margin: '.5em 0'}), 'Message mentions attachments, but no files are attached.'),
				dom.div(style({margin: '1ex 0'}), 'Attachments ', attachments=dom.input(attr.type('file'), attr.multiple(''), function change() { checkAttachments() })),
				dom.submitbutton('Send'),
			),
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				shortcutCmd(cmdSend, shortcuts)
			},
		),
	)

	;(opts.to && opts.to.length > 0 ? opts.to : ['']).forEach(s => newAddrView(s, toViews, toBtn, toCell, toRow))
	;(opts.cc || []).forEach(s => newAddrView(s, ccViews, ccBtn, ccCell, ccRow))
	;(opts.bcc || []).forEach(s => newAddrView(s, bccViews, bccBtn, bccCell, bccRow))
	if (opts.replyto) {
		newAddrView(opts.replyto, replytoViews, replyToBtn, replyToCell, replyToRow, true)
	}
	if (!opts.cc || !opts.cc.length) {
		ccRow.style.display = 'none'
	}
	if (!opts.bcc || !opts.bcc.length) {
		bccRow.style.display = 'none'
	}
	if (!opts.replyto) {
		replyToRow.style.display = 'none'
	}

	document.body.appendChild(composeElem)
	if (toViews.length > 0 && !toViews[0].input.value) {
		toViews[0].input.focus()
	} else {
		body.focus()
	}

	composeView = {
		root: composeElem,
		key: keyHandler(shortcuts),
	}
	return composeView
}

// Show popover to edit labels for msgs.
const labelsPopover = (e: MouseEvent, msgs: api.Message[], possibleLabels: possibleLabels): void => {
	if (msgs.length === 0) {
		return // Should not happen.
	}

	const knownLabels = possibleLabels()
	const activeLabels = (msgs[0].Keywords || []).filter(kw => msgs.filter(m => (m.Keywords || []).includes(kw)).length === msgs.length)
	const msgIDs = msgs.map(m => m.ID)
	let fieldsetnew: HTMLFieldSetElement
	let newlabel: HTMLInputElement

	const remove = popover(e.target! as HTMLElement, {},
		dom.div(
			style({display: 'flex', flexDirection: 'column', gap: '1ex'}),
			knownLabels.map(l =>
				dom.div(
					dom.label(
						dom.input(
							attr.type('checkbox'),
							activeLabels.includes(l) ? attr.checked('') : [], style({marginRight: '.5em'}),
							attr.title('Add/remove this label to the message(s), leaving other labels unchanged.'),
							async function change(e: MouseEvent) {
								if (activeLabels.includes(l)) {
									await withStatus('Removing label', client.FlagsClear(msgIDs, [l]), e.target! as HTMLInputElement)
									activeLabels.splice(activeLabels.indexOf(l), 1)
								} else {
									await withStatus('Adding label', client.FlagsAdd(msgIDs, [l]), e.target! as HTMLInputElement)
									activeLabels.push(l)
								}
							},
						),
						' ',
						dom.span(dom._class('keyword'), l),
					),
				)
			),
		),
		dom.hr(style({margin: '2ex 0'})),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				await withStatus('Adding new label', client.FlagsAdd(msgIDs, [newlabel.value]), fieldsetnew)
				remove()
			},
			fieldsetnew=dom.fieldset(
				dom.div(
					newlabel=dom.input(focusPlaceholder('new-label'), attr.required(''), attr.title('New label to add/set on the message(s), must be lower-case, ascii-only, without spaces and without the following special characters: (){%*"\].')),
					' ',
					dom.submitbutton('Add new label', attr.title('Add this label to the message(s), leaving other labels unchanged.')),
				),
			),
		),
	)
}

// Show popover to move messages to a mailbox.
const movePopover = (e: MouseEvent, mailboxes: api.Mailbox[], msgs: api.Message[]) => {
	if (msgs.length === 0) {
		return // Should not happen.
	}
	let msgsMailboxID = (msgs[0].MailboxID && msgs.filter(m => m.MailboxID === msgs[0].MailboxID).length === msgs.length) ? msgs[0].MailboxID : 0

	const remove = popover(e.target! as HTMLElement, {},
		dom.div(
			style({display: 'flex', flexDirection: 'column', gap: '.25em'}),
			mailboxes.map(mb =>
				dom.div(
					dom.clickbutton(
						mb.Name,
						mb.ID === msgsMailboxID ? attr.disabled('') : [],
						async function click() {
							const msgIDs = msgs.filter(m => m.MailboxID !== mb.ID).map(m => m.ID)
							await withStatus('Moving to mailbox', client.MessageMove(msgIDs, mb.ID))
							remove()
						}
					),
				)
			),
		)
	)
}

// MsgitemView is a message-line in the list of messages. Selecting it loads and displays the message, a MsgView.
interface MsgitemView {
	root: HTMLElement // MsglistView toggles active/focus classes on the root element.
	messageitem: api.MessageItem // Can be replaced with an updated version, e.g. with message with different mailbox.

	// Fields for threading.
	//
	// Effective received time. When sorting ascending, the oldest of all children.
	// When sorting descending, the newest of all. Does not change after creating
	// MsgitemView, we don't move threads around when a new message is delivered to a
	// thread.
	receivedTime: number
	// Parent message in thread. May not be the direct replied/forwarded message, e.g.
	// if the direct parent was permanently removed. Thread roots don't have a parent.
	parent: MsgitemView | null
	// Sub messages in thread. Can be further descendants, when an intermediate message
	// is missing.
	kids: MsgitemView[]
	// Whether this thread root is collapsed. If so, the root is visible, all descedants
	// are not. Value is only valid if this is a thread root.
	collapsed: boolean

	// Root MsgitemView for this subtree. Does not necessarily contain all messages in
	// a thread, there can be multiple visible roots. A MsgitemView is visible if it is
	// the threadRoot or otherwise if its threadRoot isn't collapsed.
	threadRoot: () => MsgitemView
	isCollapsedThreadRoot: () => boolean
	descendants: () => MsgitemView[] // Flattened list of all descendents.
	findDescendant: (match: (dmiv: MsgitemView) => boolean) => MsgitemView | null
	lastDescendant: () => MsgitemView | null

	// Removes msgitem from the DOM and cleans up the timer that updates the message
	// age. Must be called when MsgitemView is no longer needed. Typically through
	// msglistView.clear().
	remove: () => void

	// Must be called after initializing kids/parent field for proper rendering.
	render: () => void
}

// Make new MsgitemView, to be added to the list.
const newMsgitemView = (mi: api.MessageItem, msglistView: MsglistView, otherMailbox: otherMailbox, listMailboxes: listMailboxes, receivedTime: number, initialCollapsed: boolean): MsgitemView => {
	// note: mi may be replaced.

	// Timer to update the age of the message.
	let ageTimer = 0

	// Show with a tag if we are in the cc/bcc headers, or - if none.
	const identityTag = (s: string, title: string) => dom.span(dom._class('msgitemidentity'), s, attr.title(title))
	const identityHeader: HTMLElement[] = []
	if (!envelopeIdentity(mi.Envelope.From || []) && !envelopeIdentity(mi.Envelope.To || [])) {
		if (envelopeIdentity(mi.Envelope.CC || [])) {
			identityHeader.push(identityTag('cc', 'You are in the CC header'))
		}
		if (envelopeIdentity(mi.Envelope.BCC || [])) {
			identityHeader.push(identityTag('bcc', 'You are in the BCC header'))
		}
		// todo: don't include this if this is a message to a mailling list, based on list-* headers.
		if (identityHeader.length === 0) {
			identityHeader.push(identityTag('-', 'You are not in any To, From, CC, BCC header. Could message to a mailing list or Bcc without Bcc message header.'))
		}
	}

	const remove = (): void => {
		msgitemView.root.remove()
		if (ageTimer) {
			window.clearTimeout(ageTimer)
			ageTimer = 0
		}
	}

	const age = (date: Date): HTMLElement => {
		const r = dom.span(dom._class('notooltip'), attr.title(date.toString()))

		const set = () => {
			const nowSecs = new Date().getTime()/1000
			let t = nowSecs - date.getTime()/1000
			let negative = ''
			if (t < 0) {
				negative = '-'
				t = -t
			}
			const minute = 60
			const hour = 60*minute
			const day = 24*hour
			const month = 30*day
			const year = 365*day
			const periods = [year, month, day, hour, minute]
			const suffix = ['y', 'mo', 'd', 'h', 'min']
			let s
			let nextSecs = 0
			for (let i = 0; i < periods.length; i++) {
				const p = periods[i]
				if (t >= 2*p || i === periods.length-1) {
					const n = Math.round(t/p)
					s = '' + n + suffix[i]
					const prev = Math.floor(t/p)
					nextSecs = Math.ceil((prev+1)*p - t)
					break
				}
			}
			if (t < 60) {
				s = '<1min'
				nextSecs = 60-t
			}

			dom._kids(r, negative+s)
			// note: Cannot have delays longer than 24.8 days due to storage as 32 bit in
			// browsers. Session is likely closed/reloaded/refreshed before that time anyway.
			if (nextSecs < 14*24*3600) {
				ageTimer = window.setTimeout(set, nextSecs*1000)
			} else {
				ageTimer = 0
			}
		}

		set()
		return r
	}

	const render = () => {
		const mi = msgitemView.messageitem
		const m = mi.Message

		// Set by calling age().
		if (ageTimer) {
			window.clearTimeout(ageTimer)
			ageTimer = 0
		}

		// Keywords are normally shown per message. For collapsed threads, we show the
		// keywords of the thread root message as normal, and any additional keywords from
		// children in a way that draws less attention.
		const keywords = (m.Keywords || []).map(kw => dom.span(dom._class('keyword'), kw))
		if (msgitemView.isCollapsedThreadRoot()) {
			const keywordsSeen = new Set<string>()
			for (const kw of (m.Keywords || [])) {
				keywordsSeen.add(kw)
			}
			for (const miv of msgitemView.descendants()) {
				for (const kw of (miv.messageitem.Message.Keywords || [])) {
					if (!keywordsSeen.has(kw)) {
						keywordsSeen.add(kw)
						keywords.push(dom.span(dom._class('keyword'), dom._class('keywordcollapsed'), kw))
					}
				}
			}
		}

		let threadIndent = 0
		for (let miv = msgitemView; miv.parent; miv = miv.parent) {
			threadIndent++
		}

		// For threaded messages, we draw the subject/first-line indented, and with a
		// charactering indicating the relationship.
		// todo: show different arrow is message is a forward? we can tell by the message flag, it will likely be a message the user sent.
		let threadChar = ''
		let threadCharTitle = ''
		if (msgitemView.parent) {
			threadChar = '↳' // Down-right arrow for direct response (reply/forward).
			if (msgitemView.parent.messageitem.Message.MessageID === mi.Message.MessageID) {
				// Approximately equal, for duplicate message-id, typically in Sent and incoming
				// from mailing list or when sending to self.
				threadChar = '≈'
				threadCharTitle = 'Same Message-ID.'
			} else if (mi.Message.ThreadMissingLink || (mi.Message.ThreadParentIDs || []).length > 0 && (mi.Message.ThreadParentIDs || [])[0] !== msgitemView.parent.messageitem.Message.ID) {
				// Zigzag arrow, e.g. if immediate parent is missing, or when matching was done
				// based on subject.
				threadChar = '↯'
				threadCharTitle = 'Immediate parent message is missing.'
			}
		}

		// Message is unread if it itself is unread, or it is collapsed and has an unread child message.
		const isUnread = () => !mi.Message.Seen || msgitemView.isCollapsedThreadRoot() && !!msgitemView.findDescendant(miv => !miv.messageitem.Message.Seen)

		const isRelevant = () => !mi.Message.ThreadMuted && mi.MatchQuery || (msgitemView.isCollapsedThreadRoot() && msgitemView.findDescendant(miv => !miv.messageitem.Message.ThreadMuted && miv.messageitem.MatchQuery))

		// Effective receive time to display. For collapsed thread roots, we show the time
		// of the newest or oldest message, depending on whether you're viewing
		// newest-first or oldest-first messages.
		const received = () => {
			let r = mi.Message.Received
			if (!msgitemView.isCollapsedThreadRoot()) {
				return r
			}
			msgitemView.descendants().forEach(dmiv => {
				if (settings.orderAsc && dmiv.messageitem.Message.Received.getTime() < r.getTime()) {
					r = dmiv.messageitem.Message.Received
				} else if (!settings.orderAsc && dmiv.messageitem.Message.Received.getTime() > r.getTime()) {
					r = dmiv.messageitem.Message.Received
				}
			})
			return r
		}

		// For drawing half a thread bar for the last message in the thread.
		const isThreadLast = () => {
			let miv = msgitemView.threadRoot()
			while (miv.kids.length > 0) {
				miv = miv.kids[miv.kids.length-1]
			}
			return miv === msgitemView
		}

		// If mailbox of message is not specified in filter (i.e. for a regular mailbox
		// view, or search on a mailbox), we show it on the right-side of the subject. For
		// collapsed thread roots, we show all additional mailboxes of descendants with
		// different style.
		const mailboxtags: HTMLElement[] = []
		const mailboxIDs = new Set<number>()
		const addMailboxTag = (mb: api.Mailbox, isCollapsedKid: boolean) => {
			let name = mb.Name
			mailboxIDs.add(mb.ID)
			if (name.length > 8+1+3+1+8+4) {
				const t = name.split('/')
				const first = t[0]
				const last = t[t.length-1]
				if (first.length + last.length <= 8+8) {
					name = first+'/.../'+last
				} else {
					name = first.substring(0, 8) + '/.../' + last.substring(0, 8)
				}
			}
			const e = dom.span(dom._class('msgitemmailbox'), isCollapsedKid ? dom._class('msgitemmailboxcollapsed') : [],
				name === mb.Name ? [] : attr.title(mb.Name),
				name,
			)
			mailboxtags.push(e)
		}
		const othermb = otherMailbox(m.MailboxID)
		if (othermb) {
			addMailboxTag(othermb, false)
		}
		if (msgitemView.isCollapsedThreadRoot()) {
			for (const miv of msgitemView.descendants()) {
				const m = miv.messageitem.Message
				if (!mailboxIDs.has(m.MailboxID) && otherMailbox(m.MailboxID)) {
					const mb = listMailboxes().find(mb => mb.ID === m.MailboxID)
					if (!mb) {
						throw new ConsistencyError('missing mailbox for message in thread')
					}
					addMailboxTag(mb, true)
				}
			}
		}

		// When rerendering, we remember active & focus states. So we don't have to make
		// the caller also call redraw on MsglistView.
		const active = msgitemView.root && msgitemView.root.classList.contains('active')
		const focus = msgitemView.root && msgitemView.root.classList.contains('focus')
		const elem = dom.div(dom._class('msgitem'),
			active ? dom._class('active') : [],
			focus ? dom._class('focus') : [],
			attr.draggable('true'),
			function dragstart(e: DragEvent) {
				if (!msglistView.selected().includes(msgitemView)) {
					e.preventDefault()
					window.alert('Can only drag items in selection.')
					return
				}
				// We send the Message.ID and MailboxID, so we can decide based on the destination
				// mailbox whether to move. We don't move messages already in the destination
				// mailbox, and also skip messages in the Sent mailbox when there are also messages
				// from other mailboxes.
				e.dataTransfer!.setData('application/vnd.mox.messages', JSON.stringify(msglistView.selected().map(miv => [miv.messageitem.Message.MailboxID, miv.messageitem.Message.ID])))
			},
			// Thread root with kids can be collapsed/expanded with double click.
			settings.threading !== api.ThreadMode.ThreadOff && !msgitemView.parent && msgitemView.kids.length > 0 ?
				function dblclick(e: MouseEvent) {
					e.stopPropagation() // Prevent selection.
					if (settings.threading === api.ThreadMode.ThreadOn) {
						// No await, we don't wait for the result.
						withStatus('Saving thread expand/collapse', client.ThreadCollapse([msgitemView.messageitem.Message.ID], !msgitemView.collapsed))
					}
					if (msgitemView.collapsed) {
						msglistView.threadExpand(msgitemView)
					} else {
						msglistView.threadCollapse(msgitemView)
						msglistView.viewportEnsureMessages()
					}
				} : [],
			isUnread() ? style({fontWeight: 'bold'}) : [],
			// Relevant means not muted and matching the query.
			isRelevant() ? [] : style({opacity: '.4'}),
			dom.div(dom._class('msgitemcell', 'msgitemflags'),
				dom.div(style({display: 'flex', justifyContent: 'space-between'}),
					dom.div(flagList(msgitemView)),
					!msgitemView.parent && msgitemView.kids.length > 0 && msgitemView.collapsed ?
						dom.clickbutton('' + (1+msgitemView.descendants().length), attr.tabindex('-1'), attr.title('Expand thread.'), attr.arialabel('Expand thread.'), function click(e: MouseEvent) {
							e.stopPropagation() // Prevent selection.
							if (settings.threading === api.ThreadMode.ThreadOn) {
								withStatus('Saving thread expanded', client.ThreadCollapse([msgitemView.messageitem.Message.ID], false))
							}
							msglistView.threadExpand(msgitemView)
						}) : [],
					!msgitemView.parent && msgitemView.kids.length > 0 && !msgitemView.collapsed ?
						dom.clickbutton('-', style({width: '1em'}), attr.tabindex('-1'), attr.title('Collapse thread.'), attr.arialabel('Collapse thread.'), function click(e: MouseEvent) {
							e.stopPropagation() // Prevent selection.
							if (settings.threading === api.ThreadMode.ThreadOn) {
								withStatus('Saving thread expanded', client.ThreadCollapse([msgitemView.messageitem.Message.ID], true))
							}
							msglistView.threadCollapse(msgitemView)
							msglistView.viewportEnsureMessages()
						}) : [],
				),
			),
			dom.div(dom._class('msgitemcell', 'msgitemfrom'),
				dom.div(style({display: 'flex', justifyContent: 'space-between'}),
					dom.div(dom._class('msgitemfromtext', 'silenttitle'),
						// todo: for collapsed messages, show all participants in thread?
						attr.title((mi.Envelope.From || []).map(a => formatAddressFull(a)).join(', ')),
						join((mi.Envelope.From || []).map(a => formatAddressShort(a)), () => ', ')
					),
					identityHeader,
				),
				// Thread messages are connected by a vertical bar. The first and last message are
				// only half the height of the item, to indicate start/end, and so it stands out
				// from any thread above/below.
				((msgitemView.parent || msgitemView.kids.length > 0) && !msgitemView.threadRoot().collapsed) ?
					dom.div(dom._class('msgitemfromthreadbar'),
						!msgitemView.parent ? style({top: '50%', bottom: '-1px'}) : (
							isThreadLast() ?
								style({top: '-1px', bottom: '50%'}) :
								style({top: '-1px', bottom: '-1px'})
						)
					) : []
			),
			dom.div(dom._class('msgitemcell', 'msgitemsubject'),
				dom.div(style({display: 'flex', justifyContent: 'space-between', position: 'relative'}),
					dom.div(dom._class('msgitemsubjecttext'),
						threadIndent > 0 ? dom.span(threadChar, style({paddingLeft: (threadIndent/2)+'em', color: '#444', fontWeight: 'normal'}), threadCharTitle ? attr.title(threadCharTitle) : []) : [],
						msgitemView.parent ? [] : mi.Envelope.Subject || '(no subject)',
						dom.span(dom._class('msgitemsubjectsnippet'), ' '+mi.FirstLine),
					),
					dom.div(
						keywords,
						mailboxtags,
					),
				),
			),
			dom.div(dom._class('msgitemcell', 'msgitemage'), age(received())),
			function click(e: MouseEvent) {
				e.preventDefault()
				e.stopPropagation()
				msglistView.click(msgitemView, e.ctrlKey, e.shiftKey)
			}
		)
		msgitemView.root.replaceWith(elem)
		msgitemView.root = elem
	}

	const msgitemView: MsgitemView = {
		root: dom.div(),
		messageitem: mi,
		receivedTime: receivedTime,
		kids: [],
		parent: null,
		collapsed: initialCollapsed,

		threadRoot: () => {
			let miv = msgitemView
			while (miv.parent) {
				miv = miv.parent
			}
			return miv
		},

		isCollapsedThreadRoot: () => !msgitemView.parent && msgitemView.collapsed && msgitemView.kids.length > 0,

		descendants: () => {
			let l: MsgitemView[] = []
			const walk = (miv: MsgitemView) => {
				for (const kmiv of miv.kids) {
					l.push(kmiv)
					walk(kmiv)
				}
			}
			walk(msgitemView)
			return l
		},

		// We often just need to know if a descendant with certain properties exist. No
		// need to create an array, then call find on it.
		findDescendant: (matchfn) => {
			const walk = (miv: MsgitemView): MsgitemView | null => {
				if (matchfn(miv)) {
					return miv
				}
				for (const kmiv of miv.kids) {
					const r = walk(kmiv)
					if (r) {
						return r
					}
				}
				return null
			}
			return walk(msgitemView)
		},

		lastDescendant: () => {
			let l = msgitemView
			if (l.kids.length === 0) {
				return null
			}
			while(l.kids.length > 0) {
				l = l.kids[l.kids.length-1]
			}
			return l
		},

		remove: remove,
		render: render,
	}

	return msgitemView
}

interface MsgView {
	root: HTMLElement
	messageitem: api.MessageItem
	// Called when keywords for a message have changed, to rerender them.
	updateKeywords: (modseq: number, keywords: string[]) => Promise<void>
	// Abort loading the message.
	aborter: { abort: () => void }
	key: (key: string, e: KeyboardEvent) => Promise<void>
}

// If attachmentView is open, keyboard shortcuts go there.
let attachmentView: {key: (k: string, e: KeyboardEvent) => Promise<void>} | null = null

// MsgView is the display of a single message.
// refineKeyword is called when a user clicks a label, to filter on those.
const newMsgView = (miv: MsgitemView, msglistView: MsglistView, listMailboxes: listMailboxes, possibleLabels: possibleLabels, messageLoaded: () => void, refineKeyword: (kw: string) => Promise<void>, parsedMessageOpt?: api.ParsedMessage): MsgView => {
	const mi = miv.messageitem
	const m = mi.Message

	const formatEmailAddress = (a: api.MessageAddress) => a.User + '@' + a.Domain.ASCII
	const fromAddress = mi.Envelope.From && mi.Envelope.From.length === 1 ? formatEmailAddress(mi.Envelope.From[0]) : ''

	// Some operations below, including those that can be reached through shortcuts,
	// need a parsed message. So we keep a promise around for having that parsed
	// message. Operations always await it. Once we have the parsed message, the await
	// completes immediately.
	// Typescript doesn't know the function passed to new Promise runs immediately and
	// has set the Resolve and Reject variables before returning. Is there a better
	// solution?
	let parsedMessageResolve: (pm: api.ParsedMessage) => void = () => {}
	let parsedMessageReject: (err: Error) => void = () => {}
	let parsedMessagePromise = new Promise<api.ParsedMessage>((resolve, reject) => {
		parsedMessageResolve = resolve
		parsedMessageReject = reject
	})

	const react = async (to: api.MessageAddress[] | null, forward: boolean, all: boolean) => {
		const pm = await parsedMessagePromise
		let body = ''
		const sel = window.getSelection()
		if (sel && sel.toString()) {
			body = sel.toString()
		} else if (pm.Texts && pm.Texts.length > 0) {
			body = pm.Texts[0]
		}
		body = body.replace(/\r/g, '').replace(/\n\n\n\n*/g, '\n\n').trim()
		if (forward) {
			body = '\n\n---- Forwarded Message ----\n\n'+body
		} else {
			body = body.split('\n').map(line => '> ' + line).join('\n') + '\n\n'
		}
		const subjectPrefix = forward ? 'Fwd:' : 'Re:'
		let subject = mi.Envelope.Subject || ''
		subject = (RegExp('^'+subjectPrefix, 'i').test(subject) ? '' : subjectPrefix+' ') + subject
		const opts: ComposeOptions = {
			from: mi.Envelope.To || undefined,
			to: (to || []).map(a => formatAddress(a)),
			cc: [],
			bcc: [],
			subject: subject,
			body: body,
			isForward: forward,
			attachmentsMessageItem: forward ? mi : undefined,
			responseMessageID: m.ID,
		}
		if (all) {
			opts.to = (to || []).concat((mi.Envelope.To || []).filter(a => !envelopeIdentity([a]))).map(a => formatAddress(a))
			opts.cc = (mi.Envelope.CC || []).map(a => formatAddress(a))
			opts.bcc = (mi.Envelope.BCC || []).map(a => formatAddress(a))
		}
		compose(opts)
	}

	const reply = async (all: boolean, toOpt?: api.MessageAddress[]) => {
		await react(toOpt || ((mi.Envelope.ReplyTo || []).length > 0 ? mi.Envelope.ReplyTo : mi.Envelope.From) || null, false, all)
	}
	const cmdForward = async () => { react([], true, false) }
	const cmdReplyList = async () => {
		const pm = await parsedMessagePromise
		if (pm.ListReplyAddress) {
			await reply(false, [pm.ListReplyAddress])
		}
	}
	const cmdReply = async () => { await reply(false) }
	const cmdReplyAll = async () => { await reply(true) }
	const cmdPrint = async () => {
		if (urlType) {
			window.open('msg/'+m.ID+'/msg'+urlType+'#print', '_blank')
		}
	}
	const cmdOpenNewTab = async () => {
		if (urlType) {
			window.open('msg/'+m.ID+'/msg'+urlType, '_blank')
		}
	}
	const cmdOpenRaw = async () => { window.open('msg/'+m.ID+'/raw', '_blank') }
	const cmdViewAttachments = async () => {
		if (attachments.length > 0) {
			view(attachments[0])
		}
	}

	const cmdToggleHeaders = async () => {
		settingsPut({...settings, showAllHeaders: !settings.showAllHeaders})
		const pm = await parsedMessagePromise
		loadHeaderDetails(pm)
	}

	let textbtn: HTMLButtonElement, htmlbtn: HTMLButtonElement, htmlextbtn: HTMLButtonElement
	const activeBtn = (b: HTMLButtonElement) => {
		for (const xb of [textbtn, htmlbtn, htmlextbtn]) {
			if (xb) {
				xb.classList.toggle('active', xb === b)
			}
		}
	}

	const cmdShowText = async () => {
		if (!textbtn) {
			return
		}
		loadText(await parsedMessagePromise)
		settingsPut({...settings, showHTML: false})
		activeBtn(textbtn)
	}
	const cmdShowHTML = async () => {
		if (!htmlbtn || !htmlextbtn) {
			return
		}
		loadHTML()
		activeBtn(htmlbtn)
	}
	const cmdShowHTMLExternal = async () => {
		if (!htmlbtn || !htmlextbtn) {
			return
		}
		loadHTMLexternal()
		activeBtn(htmlextbtn)
	}
	const cmdShowHTMLCycle = async () => {
		if (urlType === 'html') {
			await cmdShowHTMLExternal()
		} else {
			await cmdShowHTML()
		}
	}
	const cmdShowInternals = async () => {
		const pm = await parsedMessagePromise
		const mimepart = (p: api.Part): HTMLElement => dom.li(
			(p.MediaType + '/' + p.MediaSubType).toLowerCase(),
			p.ContentTypeParams ? ' '+JSON.stringify(p.ContentTypeParams) : [],
			p.Parts && p.Parts.length === 0 ? [] : dom.ul(
				style({listStyle: 'disc', marginLeft: '1em'}),
				(p.Parts || []).map(pp => mimepart(pp))
			)
		)
		popup(
			style({display: 'flex', gap: '1em'}),
			dom.div(dom.h1('Mime structure'), dom.ul(style({listStyle: 'disc', marginLeft: '1em'}), mimepart(pm.Part))),
			dom.div(style({whiteSpace: 'pre-wrap', tabSize: 4, maxWidth: '50%'}), dom.h1('Message'), JSON.stringify(m, undefined, '\t')),
			dom.div(style({whiteSpace: 'pre-wrap', tabSize: 4, maxWidth: '50%'}), dom.h1('Part'), JSON.stringify(pm.Part, undefined, '\t')),
		)
	}

	const cmdUp = async () => { msgscrollElem.scrollTo({top: msgscrollElem.scrollTop - 3*msgscrollElem.getBoundingClientRect().height / 4, behavior: 'smooth'}) }
	const cmdDown = async () => { msgscrollElem.scrollTo({top: msgscrollElem.scrollTop + 3*msgscrollElem.getBoundingClientRect().height / 4, behavior: 'smooth'}) }
	const cmdHome = async () => { msgscrollElem.scrollTo({top: 0 }) }
	const cmdEnd = async () => { msgscrollElem.scrollTo({top: msgscrollElem.scrollHeight}) }

	const shortcuts: {[key: string]: command} = {
		I: cmdShowInternals,
		o: cmdOpenNewTab,
		O: cmdOpenRaw,
		'ctrl p': cmdPrint,
		f: cmdForward,
		r: cmdReply,
		R: cmdReplyAll,
		v: cmdViewAttachments,
		t: cmdShowText,
		T: cmdShowHTMLCycle,
		'ctrl I': cmdToggleHeaders,

		'alt j': cmdDown,
		'alt k': cmdUp,
		'alt ArrowDown': cmdDown,
		'alt ArrowUp': cmdUp,
		'alt J': cmdEnd,
		'alt K': cmdHome,

		// For showing shortcuts only, handled in msglistView.
		a: msglistView.cmdArchive,
		d: msglistView.cmdTrash,
		D: msglistView.cmdDelete,
		q: msglistView.cmdJunk,
		Q: msglistView.cmdMarkNotJunk,
		m: msglistView.cmdMarkRead,
		M: msglistView.cmdMarkUnread,
	}

	let urlType: string // text, html, htmlexternal; for opening in new tab/print

	let msgbuttonElem: HTMLElement, msgheaderElem: HTMLElement, msgattachmentElem: HTMLElement, msgmodeElem: HTMLElement
	let msgheaderdetailsElem: HTMLElement | null = null // When full headers are visible, or some headers are requested through settings.

	const msgmetaElem = dom.div(
		style({backgroundColor: '#f8f8f8', borderBottom: '1px solid #ccc', maxHeight: '90%', overflowY: 'auto'}),
		attr.role('region'), attr.arialabel('Buttons and headers for message'),
		msgbuttonElem=dom.div(),
		dom.div(
			attr.arialive('assertive'),
			msgheaderElem=dom.table(style({marginBottom: '1ex', width: '100%'})),
			msgattachmentElem=dom.div(),
			msgmodeElem=dom.div(),
		),
	)

	const msgscrollElem = dom.div(dom._class('pad', 'yscrollauto'),
		attr.role('region'), attr.arialabel('Message body'),
		style({backgroundColor: 'white'}),
	)
	const msgcontentElem = dom.div(dom._class('scrollparent'),
		style({flexGrow: '1'}),
	)

	const trashMailboxID = listMailboxes().find(mb => mb.Trash)?.ID

	// Initially called with potentially null pm, once loaded called again with pm set.
	const loadButtons = (pm: api.ParsedMessage | null) => {
		dom._kids(msgbuttonElem,
			dom.div(dom._class('pad'),
				(!pm || !pm.ListReplyAddress) ? [] : dom.clickbutton('Reply to list', attr.title('Compose a reply to this mailing list.'), clickCmd(cmdReplyList, shortcuts)), ' ',
				(pm && pm.ListReplyAddress && formatEmailAddress(pm.ListReplyAddress) === fromAddress) ? [] : dom.clickbutton('Reply', attr.title('Compose a reply to the sender of this message.'), clickCmd(cmdReply, shortcuts)), ' ',
				(mi.Envelope.To || []).length <= 1 && (mi.Envelope.CC || []).length === 0 && (mi.Envelope.BCC || []).length === 0 ? [] :
					dom.clickbutton('Reply all', attr.title('Compose a reply to all participants of this message.'), clickCmd(cmdReplyAll, shortcuts)), ' ',
				dom.clickbutton('Forward', attr.title('Compose a forwarding message, optionally including attachments.'), clickCmd(cmdForward, shortcuts)), ' ',
				dom.clickbutton('Archive', attr.title('Move to the Archive mailbox.'), clickCmd(msglistView.cmdArchive, shortcuts)), ' ',
				m.MailboxID === trashMailboxID ?
					dom.clickbutton('Delete', attr.title('Permanently delete message.'), clickCmd(msglistView.cmdDelete, shortcuts)) :
					dom.clickbutton('Trash', attr.title('Move to the Trash mailbox.'), clickCmd(msglistView.cmdTrash, shortcuts)),
				' ',
				dom.clickbutton('Junk', attr.title('Move to Junk mailbox, marking as junk and causing this message to be used in spam classification of new incoming messages.'), clickCmd(msglistView.cmdJunk, shortcuts)), ' ',
				dom.clickbutton('Move to...', function click(e: MouseEvent) {
					movePopover(e, listMailboxes(), [m])
				}), ' ',
				dom.clickbutton('Labels...', attr.title('Add/remove labels.'), function click(e: MouseEvent) {
					labelsPopover(e, [m], possibleLabels)
				}), ' ',
				dom.clickbutton('More...', attr.title('Show more actions.'), function click(e: MouseEvent) {
					popover(e.target! as HTMLElement, {transparent: true},
						dom.div(
							style({display: 'flex', flexDirection: 'column', gap: '.5ex', textAlign: 'right'}),
							[
								dom.clickbutton('Print', attr.title('Print message, opens in new tab and opens print dialog.'), clickCmd(cmdPrint, shortcuts)),
								dom.clickbutton('Mark Not Junk', attr.title('Mark as not junk, causing this message to be used in spam classification of new incoming messages.'), clickCmd(msglistView.cmdMarkNotJunk, shortcuts)),
								dom.clickbutton('Mark Read', clickCmd(msglistView.cmdMarkRead, shortcuts)),
								dom.clickbutton('Mark Unread', clickCmd(msglistView.cmdMarkUnread, shortcuts)),
								dom.clickbutton('Mute thread', clickCmd(msglistView.cmdMute, shortcuts)),
								dom.clickbutton('Unmute thread', clickCmd(msglistView.cmdUnmute, shortcuts)),
								dom.clickbutton('Open in new tab', clickCmd(cmdOpenNewTab, shortcuts)),
								dom.clickbutton('Show raw original message in new tab', clickCmd(cmdOpenRaw, shortcuts)),
								dom.clickbutton('Show internals in popup', clickCmd(cmdShowInternals, shortcuts)),
							].map(b => dom.div(b)),
						),
					)
				}),
			)
		)
	}
	loadButtons(parsedMessageOpt || null)

	loadMsgheaderView(msgheaderElem, miv.messageitem, settings.showHeaders, refineKeyword)

	const loadHeaderDetails = (pm: api.ParsedMessage) => {
		if (msgheaderdetailsElem) {
			msgheaderdetailsElem.remove()
			msgheaderdetailsElem = null
		}
		if (!settings.showAllHeaders) {
			return
		}
		msgheaderdetailsElem = dom.table(
			style({marginBottom: '1ex', width: '100%'}),
			Object.entries(pm.Headers || {}).sort().map(t =>
				(t[1] || []).map(v =>
					dom.tr(
						dom.td(t[0]+':', style({textAlign: 'right', color: '#555'})),
						dom.td(v),
					)
				)
			)
		)
		msgattachmentElem.parentNode!.insertBefore(msgheaderdetailsElem, msgattachmentElem)
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
	const isText = (a: api.Attachment) => a.Part.MediaType.toLowerCase() === 'text'
	const isImage = (a: api.Attachment) => imageTypes.includes((a.Part.MediaType + '/' + a.Part.MediaSubType).toLowerCase())
	const isPDF = (a: api.Attachment) => (a.Part.MediaType+'/'+a.Part.MediaSubType).toLowerCase() === 'application/pdf'
	const isViewable = (a: api.Attachment) => isText(a) || isImage(a) || isPDF(a)
	const attachments: api.Attachment[] = (mi.Attachments || [])

	let beforeViewFocus: Element | null
	const view = (a: api.Attachment) => {
		if (!beforeViewFocus) {
			beforeViewFocus = document.activeElement
		}

		const pathStr = [0].concat(a.Path || []).join('.')
		const index = attachments.indexOf(a)

		const cmdViewPrev = async () => {
			if (index > 0) {
				popupRoot.remove()
				view(attachments[index-1])
			}
		}
		const cmdViewNext = async () => {
			if (index < attachments.length-1) {
				popupRoot.remove()
				view(attachments[index+1])
			}
		}
		const cmdViewFirst = async () => {
			popupRoot.remove()
			view(attachments[0])
		}
		const cmdViewLast = async () => {
			popupRoot.remove()
			view(attachments[attachments.length-1])
		}
		const cmdViewClose = async () => {
			popupRoot.remove()
			if (beforeViewFocus && beforeViewFocus instanceof HTMLElement && beforeViewFocus.parentNode) {
				beforeViewFocus.focus()
			}
			attachmentView = null
			beforeViewFocus = null
		}

		const attachShortcuts = {
			h: cmdViewPrev,
			ArrowLeft: cmdViewPrev,
			l: cmdViewNext,
			ArrowRight: cmdViewNext,
			'0': cmdViewFirst,
			'$': cmdViewLast,
			Escape: cmdViewClose,
		}

		let content: HTMLElement
		const popupRoot = dom.div(
			style({position: 'fixed', left: 0, right: 0, top: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.2)', display: 'flex', flexDirection: 'column', alignContent: 'stretch', padding: '1em', zIndex: zindexes.attachments}),
			function click(e: MouseEvent) {
				e.stopPropagation()
				cmdViewClose()
			},
			attr.tabindex('0'),
			!(index > 0) ? [] : dom.div(
				style({position: 'absolute', left: '1em', top: 0, bottom: 0, fontSize: '1.5em', width: '2em', display: 'flex', alignItems: 'center', cursor: 'pointer'}),
				dom.div(dom._class('silenttitle'),
					style({backgroundColor: 'rgba(0, 0, 0, .8)', color: 'white', width: '2em', height: '2em', borderRadius: '1em', lineHeight: '2em', textAlign: 'center', fontWeight: 'bold'}),
					attr.title('To previous viewable attachment.'),
					'←',
				),
				attr.tabindex('0'),
				clickCmd(cmdViewPrev, attachShortcuts),
				enterCmd(cmdViewPrev, attachShortcuts),
			),
			dom.div(
				style({textAlign: 'center', paddingBottom: '30px'}),
				dom.span(dom._class('pad'),
					function click(e: MouseEvent) {
						e.stopPropagation()
					},
					style({backgroundColor: 'white', borderRadius: '.25em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd'}),
					a.Filename || '(unnamed)', ' - ',
					formatSize(a.Part.DecodedSize), ' - ',
					dom.a('Download', attr.download(''), attr.href('msg/'+m.ID+'/download/'+pathStr), function click(e: MouseEvent) { e.stopPropagation() }),
				),
			),
			isImage(a) ?
				dom.div(
					style({flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 5em'}),
					dom.img(
						attr.src('msg/'+m.ID+'/view/'+pathStr),
						style({backgroundColor: 'white', maxWidth: '100%', maxHeight: '100%', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', margin: '0 30px'})
					),
				) : (
					isText(a) ?
						dom.iframe(
							attr.title('Attachment shown as text.'),
							style({flexGrow: 1, boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', backgroundColor: 'white', margin: '0 5em'}),
							attr.src('msg/'+m.ID+'/viewtext/'+pathStr)
						) : (
							isPDF(a) ?
								dom.iframe(
									style({flexGrow: 1, boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', backgroundColor: 'white', margin: '0 5em'}),
									attr.title('Attachment as PDF.'),
									attr.src('msg/'+m.ID+'/view/'+pathStr)
								) :
								content=dom.div(
									function click(e: MouseEvent) {
										e.stopPropagation()
									},
									style({minWidth: '30em', padding: '2ex', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', backgroundColor: 'white', margin: '0 5em', textAlign: 'center'}),
									dom.div(style({marginBottom: '2ex'}), 'Attachment could be a binary file.'),
									dom.clickbutton('View as text', function click() {
										content.replaceWith(
											dom.iframe(
												attr.title('Attachment shown as text, though it could be a binary file.'),
												style({flexGrow: 1, boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', backgroundColor: 'white', margin: '0 5em'}),
												attr.src('msg/'+m.ID+'/viewtext/'+pathStr)
											)
										)
									}),
						)
					)
				),
			!(index < attachments.length-1) ? [] : dom.div(
				style({position: 'absolute', right: '1em', top: 0, bottom: 0, fontSize: '1.5em', width: '2em', display: 'flex', alignItems: 'center', cursor: 'pointer'}),
				dom.div(dom._class('silenttitle'),
					style({backgroundColor: 'rgba(0, 0, 0, .8)', color: 'white', width: '2em', height: '2em', borderRadius: '1em', lineHeight: '2em', textAlign: 'center', fontWeight: 'bold'}),
					attr.title('To next viewable attachment.'),
					'→',
				),
				attr.tabindex('0'),
				clickCmd(cmdViewNext, attachShortcuts),
				enterCmd(cmdViewNext, attachShortcuts),
			),
		)
		document.body.appendChild(popupRoot)
		popupRoot.focus()
		attachmentView = {key: keyHandler(attachShortcuts)}
	}

	dom._kids(msgattachmentElem,
		(mi.Attachments && mi.Attachments.length === 0) ? [] : dom.div(
			style({borderTop: '1px solid #ccc'}),
			dom.div(dom._class('pad'),
				'Attachments: ',
				(mi.Attachments || []).map(a => {
					const name = a.Filename || '(unnamed)'
					const viewable = isViewable(a)
					const size = formatSize(a.Part.DecodedSize)
					const eye = '👁'
					const dl = '⤓' // \u2913, actually ⭳ \u2b73 would be better, but in fewer fonts (at least macos)
					const dlurl = 'msg/'+m.ID+'/download/'+[0].concat(a.Path || []).join('.')
					const viewbtn = dom.clickbutton(eye, viewable ? ' '+name : style({padding: '0px 0.25em'}), attr.title('View this file. Size: '+size), style({lineHeight: '1.5'}), function click() {
						view(a)
					})
					const dlbtn = dom.a(dom._class('button'), attr.download(''), attr.href(dlurl), dl, viewable ? style({padding: '0px 0.25em'}) : ' '+name, attr.title('Download this file. Size: '+size), style({lineHeight: '1.5'}))
					if (viewable) {
						return [dom.span(dom._class('btngroup'), viewbtn, dlbtn), ' ']
					}
					return [dom.span(dom._class('btngroup'), dlbtn, viewbtn), ' ']
				}),
				dom.a('Download all as zip', attr.download(''), style({color: 'inherit'}), attr.href('msg/'+m.ID+'/attachments.zip')),
			),
		)
	)

	const root = dom.div(style({position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, display: 'flex', flexDirection: 'column'}))
	dom._kids(root, msgmetaElem, msgcontentElem)

	const loadText = (pm: api.ParsedMessage): void => {
		// We render text ourselves so we can make links clickable and get any selected
		// text to use when writing a reply. We still set url so the text content can be
		// opened in a separate tab, even though it will look differently.
		urlType = 'text'
		const elem = dom.div(dom._class('mono'),
			style({whiteSpace: 'pre-wrap'}),
			join((pm.Texts || []).map(t => renderText(t.replace(/\r\n/g, '\n'))), () => dom.hr(style({margin: '2ex 0'}))),
		)
		dom._kids(msgcontentElem)
		dom._kids(msgscrollElem, elem)
		dom._kids(msgcontentElem, msgscrollElem)
	}
	const loadHTML = (): void => {
		urlType = 'html'
		dom._kids(msgcontentElem,
			dom.iframe(
				attr.tabindex('0'),
				attr.title('HTML version of message with images inlined, without external resources loaded.'),
				attr.src('msg/'+m.ID+'/'+urlType),
				style({border: '0', position: 'absolute', width: '100%', height: '100%', backgroundColor: 'white'}),
			)
		)
	}
	const loadHTMLexternal = (): void => {
		urlType = 'htmlexternal'
		dom._kids(msgcontentElem,
			dom.iframe(
				attr.tabindex('0'),
				attr.title('HTML version of message with images inlined and with external resources loaded.'),
				attr.src('msg/'+m.ID+'/'+urlType),
				style({border: '0', position: 'absolute', width: '100%', height: '100%', backgroundColor: 'white'}),
			)
		)
	}

	const loadMoreHeaders = (pm: api.ParsedMessage) => {
		if (settings.showHeaders.length === 0) {
			return
		}
		for (let i = 0; i < settings.showHeaders.length; i++) {
			msgheaderElem.children[msgheaderElem.children.length-1].remove()
		}
		settings.showHeaders.forEach(k => {
			const vl = pm.Headers?.[k]
			if (!vl || vl.length === 0) {
				return
			}
			vl.forEach(v => {
				const e = dom.tr(
					dom.td(k+':', style({textAlign: 'right', color: '#555', whiteSpace: 'nowrap'})),
					dom.td(v),
				)
				msgheaderElem.appendChild(e)
			})
		})
	}

	const mv: MsgView = {
		root: root,
		messageitem: mi,
		key: keyHandler(shortcuts),
		aborter: { abort: () => {} },
		updateKeywords: async (modseq: number, keywords: string[]) => {
			mi.Message.ModSeq = modseq
			mi.Message.Keywords = keywords
			loadMsgheaderView(msgheaderElem, miv.messageitem, settings.showHeaders, refineKeyword)
			loadMoreHeaders(await parsedMessagePromise)
		},
	}

	;(async () => {
		let pm: api.ParsedMessage
		if (parsedMessageOpt) {
			pm = parsedMessageOpt
			parsedMessageResolve(pm)
		} else {
			const promise = withStatus('Loading message', client.withOptions({aborter: mv.aborter}).ParsedMessage(m.ID))
			try {
				pm = await promise
			} catch (err) {
				if (err instanceof Error) {
					parsedMessageReject(err)
				} else {
					parsedMessageReject(new Error('fetching message failed'))
				}
				throw err
			}
			parsedMessageResolve(pm)
		}

		loadButtons(pm)
		loadHeaderDetails(pm)
		loadMoreHeaders(pm)

		const htmlNote = 'In the HTML viewer, the following potentially dangerous functionality is disabled: submitting forms, starting a download from a link, navigating away from this page by clicking a link. If a link does not work, try explicitly opening it in a new tab.'
		const haveText = pm.Texts && pm.Texts.length > 0
		if (!haveText && !pm.HasHTML) {
			dom._kids(msgcontentElem)
			dom._kids(msgmodeElem,
				dom.div(dom._class('pad'),
					style({borderTop: '1px solid #ccc'}),
					dom.span('No textual content', style({backgroundColor: '#ffca91', padding: '0 .15em'})),
				),
			)
		} else if (haveText && !pm.HasHTML) {
			loadText(pm)
			dom._kids(msgmodeElem)
		} else {
			const text = haveText && !settings.showHTML
			dom._kids(msgmodeElem,
				dom.div(dom._class('pad'),
					style({borderTop: '1px solid #ccc'}),
					!haveText ? dom.span('HTML-only message', attr.title(htmlNote), style({backgroundColor: '#ffca91', padding: '0 .15em', marginRight: '.25em'})) : [],
					dom.span(dom._class('btngroup'),
						haveText ? textbtn=dom.clickbutton(text ? dom._class('active') : [], 'Text', clickCmd(cmdShowText, shortcuts)) : [],
						htmlbtn=dom.clickbutton(text ? [] : dom._class('active'), 'HTML', attr.title(htmlNote), async function click() {
							// Shortcuts has a function that cycles through html and htmlexternal.
							showShortcut('T')
							await cmdShowHTML()
						}),
						htmlextbtn=dom.clickbutton('HTML with external resources', attr.title(htmlNote), clickCmd(cmdShowHTMLExternal, shortcuts)),
					),
				)
			)
			if (text) {
				loadText(pm)
			} else {
				loadHTML()
			}
		}

		messageLoaded()

		if (!miv.messageitem.Message.Seen) {
			window.setTimeout(async () => {
				if (!miv.messageitem.Message.Seen && miv.messageitem.Message.ID === msglistView.activeMessageID()) {
					await withStatus('Marking current message as read', client.FlagsAdd([miv.messageitem.Message.ID], ['\\seen']))
				}
			}, 500)
		}
		if (!miv.messageitem.Message.Junk && !miv.messageitem.Message.Notjunk) {
			window.setTimeout(async () => {
				if (!miv.messageitem.Message.Junk && !miv.messageitem.Message.Notjunk && miv.messageitem.Message.ID === msglistView.activeMessageID()) {
					await withStatus('Marking current message as not junk', client.FlagsAdd([miv.messageitem.Message.ID], ['$notjunk']))
				}
			}, 5*1000)
		}
	})()

	return mv
}

// MsglistView holds the list of messages for a mailbox/search query. Zero or more
// messages can be selected (active). If one message is selected, its contents are shown.
// With multiple selected, they can all be operated on, e.g. moved to
// archive/trash/junk. Focus is typically on the last clicked message, but can be
// changed with keyboard interaction without changing selected messages.
//
// With threading enabled, we show the messages in a thread below each other. A
// thread can have multiple "thread roots": messages without a parent message. This
// can occur if a parent message with multiple kids is permanently removed. We also
// show messages from the same thread but a different mailbox. A thread root can be
// collapsed, independently of collapsed state of other thread roots. We order
// thread roots, and kids/siblings, by received timestamp.
//
// For incoming changes (add/remove of messages), we update the thread view in a
// way that resembles a fresh mailbox load as much as possible. Exceptions: If a
// message is removed, and there are thread messages remaining, but they are all in
// other mailboxes (or don't match the search query), we still show the remaining
// messages. If you would load the mailbox/search query again, you would not see
// those remaining messages. Also, if a new message is delivered to a thread, the
// thread isn't moved. After a refresh, the thread would be the most recent (at the
// top for the default sorting).
//
// When updating the UI for threaded messages, we often take this simple approach:
// Remove a subtree of messages from the UI, sort their data structures, and add
// them to the UI again. That saves tricky code that would need to make just the
// exact changes needed.
//
// We just have one MsglistView, that is updated when a different mailbox/search
// query is opened.
interface MsglistView {
	root: HTMLElement
	updateFlags: (mailboxID: number, uid: number, modseq: number, mask: api.Flags, flags: api.Flags, keywords: string[]) => void
	addMessageItems: (messageItems: (api.MessageItem[] | null)[], isChange: boolean, requestMsgID: number) => void
	removeUIDs: (mailboxID: number, uids: number[]) => void
	updateMessageThreadFields: (messageIDs: number[], muted: boolean, collapsed: boolean) => void
	activeMessageID: () => number // For single message selected, otherwise returns 0.
	redraw: (miv: MsgitemView) => void // To be called after updating flags or focus/active state, rendering it again.
	clear: () => void // Clear all messages, reset focus/active state.
	unselect: () => void
	select: (miv: MsgitemView) => void
	selected: () => MsgitemView[]
	openMessage: (parsedMessage: api.ParsedMessage) => boolean
	click: (miv: MsgitemView, ctrl: boolean, shift: boolean) => void
	key: (k: string, e: KeyboardEvent) => void
	mailboxes: () => api.Mailbox[]
	itemHeight: () => number // For calculating how many messageitems to request to load next view.
	threadExpand: (miv: MsgitemView) => void
	threadCollapse: (miv: MsgitemView) => void
	threadToggle: () => void // Toggle threads based on state.
	viewportEnsureMessages: () => Promise<void> // Load more messages if last message is near the end of the viewport.

	// Exported for MsgView.
	cmdArchive: () => Promise<void>
	cmdDelete: () => Promise<void>
	cmdTrash: () => Promise<void>
	cmdJunk: () => Promise<void>
	cmdMarkNotJunk: () => Promise<void>
	cmdMarkRead: () => Promise<void>
	cmdMarkUnread: () => Promise<void>
	cmdMute: () => Promise<void>
	cmdUnmute: () => Promise<void>
}

const newMsglistView = (msgElem: HTMLElement, listMailboxes: listMailboxes, setLocationHash: setLocationHash, otherMailbox: otherMailbox, possibleLabels: possibleLabels, scrollElemHeight: () => number, refineKeyword: (kw: string) => Promise<void>, viewportEnsureMessages: () => Promise<void>): MsglistView => {
	// msgitemViews holds all visible item views: All thread roots, and kids only if
	// the thread is expanded, in order of descendants. All descendants of a collapsed
	// root are in collapsedMsgitemViews, unsorted. Having msgitemViews as a list is
	// convenient for reasoning about the visible items, and handling changes to the
	// selected messages.
	// When messages for a thread are all non-matching the query, we no longer show it
	// (e.g. when moving a thread to Archive), but we keep the messages around in
	// oldThreadMessageItems, so an update to the thread (e.g. new delivery) can
	// resurrect the messages.
	let msgitemViews: MsgitemView[] = [] // Only visible msgitems, in order on screen.
	let collapsedMsgitemViews: MsgitemView[] = [] // Invisible messages because collapsed, unsorted.
	let oldThreadMessageItems: api.MessageItem[] = [] // Messages from threads removed from view.

	// selected holds the messages that are selected, zero or more. If there is a
	// single message, its content is shown. If there are multiple, just the count is
	// shown. These are in order of being added, not in order of how they are shown in
	// the list. This is needed to handle selection changes with the shift key. For
	// collapsed thread roots, only that root will be in this list. The effective
	// selection must always expand descendants, use mlv.selected() to gather all.
	let selected: MsgitemView[] = []

	// Focus is the message last interacted with, or the first when messages are
	// loaded. Always set when there is a message. Used for shift+click to expand
	// selection.
	let focus: MsgitemView | null = null

	let msgView: MsgView | null = null

	// Messages for actions like "archive", "trash", "move to...". We skip messages
	// that are (already) in skipMBID. And we skip messages that are in the designated
	// Sent mailbox, unless there is only one selected message or the view is for the
	// Sent mailbox, then it must be intentional.
	const moveActionMsgIDs = (skipMBID: number) => {
		const sentMailboxID = listMailboxes().find(mb => mb.Sent)?.ID
		const effselected = mlv.selected()
		return effselected
			.filter(miv => miv.messageitem.Message.MailboxID !== skipMBID)
			.map(miv => miv.messageitem.Message)
			.filter(m => effselected.length === 1 || !sentMailboxID || m.MailboxID !== sentMailboxID || !otherMailbox(sentMailboxID))
			.map(m => m.ID)
	}

	const cmdArchive = async () => {
		const mb = listMailboxes().find(mb => mb.Archive)
		if (mb) {
			await withStatus('Moving to archive mailbox', client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID))
		} else {
			window.alert('No mailbox configured for archiving yet.')
		}
	}
	const cmdDelete = async () => {
		if (!confirm('Are you sure you want to permanently delete?')) {
			return
		}
		await withStatus('Permanently deleting messages', client.MessageDelete(mlv.selected().map(miv => miv.messageitem.Message.ID)))
	}
	const cmdTrash = async () => {
		const mb = listMailboxes().find(mb => mb.Trash)
		if (mb) {
			await withStatus('Moving to trash mailbox', client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID))
		} else {
			window.alert('No mailbox configured for trash yet.')
		}
	}
	const cmdJunk = async () => {
		const mb = listMailboxes().find(mb => mb.Junk)
		if (mb) {
			await withStatus('Moving to junk mailbox', client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID))
		} else {
			window.alert('No mailbox configured for junk yet.')
		}
	}
	const cmdMarkNotJunk = async () => { await withStatus('Marking as not junk', client.FlagsAdd(mlv.selected().map(miv => miv.messageitem.Message.ID), ['$notjunk'])) }
	const cmdMarkRead = async () => { await withStatus('Marking as read', client.FlagsAdd(mlv.selected().map(miv => miv.messageitem.Message.ID), ['\\seen'])) }
	const cmdMarkUnread = async () => { await withStatus('Marking as not read', client.FlagsClear(mlv.selected().map(miv => miv.messageitem.Message.ID), ['\\seen'])) }
	const cmdMute = async () => {
		const l = mlv.selected()
		await withStatus('Muting thread', client.ThreadMute(l.map(miv => miv.messageitem.Message.ID), true))
		const oldstate = state()
		for (const miv of l) {
			if (!miv.parent && miv.kids.length > 0 && !miv.collapsed) {
				threadCollapse(miv, false)
			}
		}
		updateState(oldstate)
		viewportEnsureMessages()
	}
	const cmdUnmute = async () => { await withStatus('Unmuting thread', client.ThreadMute(mlv.selected().map(miv => miv.messageitem.Message.ID), false)) }

	const seletedRoots = () => {
		const mivs: MsgitemView[] = []
		mlv.selected().forEach(miv => {
			const mivroot = miv.threadRoot()
			if (!mivs.includes(mivroot)) {
				mivs.push(mivroot)
			}
		})
		return mivs
	}

	const cmdToggleMute = async () => {
		if (settings.threading === api.ThreadMode.ThreadOff) {
			alert('Toggle muting threads is only available when threading is enabled.')
			return
		}
		const rootmivs = seletedRoots()
		const unmuted = !!rootmivs.find(miv => !miv.messageitem.Message.ThreadMuted)
		await withStatus(unmuted ? 'Muting' : 'Unmuting', client.ThreadMute(rootmivs.map(miv => miv.messageitem.Message.ID), unmuted ? true : false))
		if (unmuted) {
			const oldstate = state()
			rootmivs.forEach(miv => {
				if (!miv.collapsed) {
					threadCollapse(miv, false)
				}
			})
			updateState(oldstate)
			viewportEnsureMessages()
		}
	}

	const cmdToggleCollapse = async () => {
		if (settings.threading === api.ThreadMode.ThreadOff) {
			alert('Toggling thread collapse/expand is only available when threading is enabled.')
			return
		}

		const rootmivs = seletedRoots()
		const collapse = !!rootmivs.find(miv => !miv.collapsed)

		const oldstate = state()
		if (collapse) {
			rootmivs.forEach(miv => {
				if (!miv.collapsed) {
					threadCollapse(miv, false)
				}
			})
			selected = rootmivs
			if (focus) {
				focus = focus.threadRoot()
			}
			viewportEnsureMessages()
		} else {
			rootmivs.forEach(miv => {
				if (miv.collapsed) {
					threadExpand(miv, false)
				}
			})
		}
		updateState(oldstate)

		if (settings.threading === api.ThreadMode.ThreadOn) {
			const action = collapse ? 'Collapsing' : 'Expanding'
			await withStatus(action, client.ThreadCollapse(rootmivs.map(miv => miv.messageitem.Message.ID), collapse))
		}
	}

	const cmdSelectThread = async () => {
		if (!focus) {
			return
		}

		const oldstate = state()
		selected = msgitemViews.filter(miv => miv.messageitem.Message.ThreadID === focus!.messageitem.Message.ThreadID)
		updateState(oldstate)
	}

	const cmdCollapseExpand = async (collapse: boolean) => {
		if (settings.threading === api.ThreadMode.ThreadOff) {
			alert('Toggling thread collapse/expand is only available when threading is enabled.')
			return
		}
		const oldstate = state()
		const rootmivs = seletedRoots()
		rootmivs.forEach(miv => {
			if (miv.collapsed !== collapse) {
				if (collapse) {
					threadCollapse(miv, false)
				} else {
					threadExpand(miv, false)
				}
			}
		})
		if (collapse) {
			selected = rootmivs
			if (focus) {
				focus = focus.threadRoot()
			}
		}
		viewportEnsureMessages()
		updateState(oldstate)
		if (settings.threading === api.ThreadMode.ThreadOn) {
			const action = collapse ? 'Collapsing' : 'Expanding'
			await withStatus(action, client.ThreadCollapse(rootmivs.map(miv => miv.messageitem.Message.ID), collapse))
		}
	}
	const cmdCollapse = async () => cmdCollapseExpand(true)
	const cmdExpand = async () => cmdCollapseExpand(false)

	const shortcuts: {[key: string]: command} = {
		d: cmdTrash,
		Delete: cmdTrash,
		D: cmdDelete,
		a: cmdArchive,
		q: cmdJunk,
		Q: cmdMarkNotJunk,
		m: cmdMarkRead,
		M: cmdMarkUnread,
		X: cmdToggleMute,
		C: cmdToggleCollapse,
		S: cmdSelectThread,
		ArrowLeft: cmdCollapse,
		ArrowRight: cmdExpand,
	}

	// After making changes, this function looks through the data structure for
	// inconsistencies. Useful during development.
	const checkConsistency = (checkSelection: boolean) => {
		if (!settings.checkConsistency) {
			return
		}

		// Check for duplicates in msgitemViews.
		const mivseen = new Set<number>()
		const threadActive = new Set<number>()
		for (const miv of msgitemViews) {
			const id = miv.messageitem.Message.ID
			if (mivseen.has(id)) {
				log('duplicate Message.ID', {id: id, mivseenSize: mivseen.size})
				throw new ConsistencyError('duplicate Message.ID in msgitemViews')
			}
			mivseen.add(id)
			if (!miv.root.parentNode) {
				throw new ConsistencyError('msgitemView.root not in dom')
			}
			threadActive.add(miv.messageitem.Message.ThreadID)
		}

		// Check for duplicates in collapsedMsgitemViews, and whether also in msgitemViews.
		const colseen = new Set<number>()
		for (const miv of collapsedMsgitemViews) {
			const id = miv.messageitem.Message.ID
			if (colseen.has(id)) {
				throw new ConsistencyError('duplicate Message.ID in collapsedMsgitemViews')
			}
			colseen.add(id)
			if (mivseen.has(id)) {
				throw new ConsistencyError('Message.ID in both collapsedMsgitemViews and msgitemViews')
			}
			threadActive.add(miv.messageitem.Message.ThreadID)
		}

		if (settings.threading !== api.ThreadMode.ThreadOff) {
			const oldseen = new Set<number>()
			for (const mi of oldThreadMessageItems) {
				const id = mi.Message.ID
				if (oldseen.has(id)) {
					throw new ConsistencyError('duplicate Message.ID in oldThreadMessageItems')
				}
				oldseen.add(id)
				if (mivseen.has(id)) {
					throw new ConsistencyError('Message.ID in both msgitemViews and oldThreadMessageItems')
				}
				if (colseen.has(id)) {
					throw new ConsistencyError('Message.ID in both collapsedMsgitemViews and oldThreadMessageItems')
				}

				if (threadActive.has(mi.Message.ThreadID)) {
					throw new ConsistencyError('threadid both in active and in old thread list')
				}
			}
		}

		// Walk all (collapsed) msgitemViews, check each and their descendants are in
		// msgitemViews at the correct position, or in collapsedmsgitemViews.
		msgitemViews.forEach((miv, i) => {
			if (miv.collapsed) {
				for (const dmiv of miv.descendants()) {
					if (!colseen.has(dmiv.messageitem.Message.ID)) {
						throw new ConsistencyError('descendant message id missing from collapsedMsgitemViews')
					}
				}
				return
			}
			for (const dmiv of miv.descendants()) {
				i++
				if (!mivseen.has(dmiv.messageitem.Message.ID)) {
					throw new ConsistencyError('descendant missing from msgitemViews')
				}
				if (msgitemViews[i] !== dmiv) {
					throw new ConsistencyError('descendant not at expected position in msgitemViews')
				}
			}
		})

		if (!checkSelection) {
			return
		}

		// Check all selected & focus exists.
		const selseen = new Set<number>()
		for (const miv of selected) {
			const id = miv.messageitem.Message.ID
			if (selseen.has(id)) {
				throw new ConsistencyError('duplicate miv in selected')
			}
			selseen.add(id)
			if (!mivseen.has(id)) {
				throw new ConsistencyError('selected id not in msgitemViews')
			}
		}
		if (focus) {
			const id = focus.messageitem.Message.ID
			if (!mivseen.has(id)) {
				throw new ConsistencyError('focus set to unknown miv')
			}
		}
	}

	type state = {
		active: {[id: string]: MsgitemView},
		focus: MsgitemView | null
	}

	// Return active & focus state, and update the UI after changing state.
	const state = (): state => {
		const active: {[key: string]: MsgitemView} = {}
		for (const miv of mlv.selected()) {
			active[miv.messageitem.Message.ID] = miv
		}
		return {active: active, focus: focus}
	}
	const updateState = async (oldstate: state, initial?: boolean, parsedMessageOpt?: api.ParsedMessage): Promise<void> => {
		// Set new focus & active classes.
		const newstate = state()
		if (oldstate.focus !== newstate.focus) {
			if (oldstate.focus) {
				oldstate.focus.root.classList.toggle('focus', false)
			}
			if (newstate.focus) {
				newstate.focus.root.classList.toggle('focus', true)
				newstate.focus.root.scrollIntoView({block: initial ? 'center' : 'nearest'})
			}
		}
		let activeChanged = false
		for (const id in oldstate.active) {
			if (!newstate.active[id]) {
				oldstate.active[id].root.classList.toggle('active', false)
				activeChanged = true
			}
		}
		for (const id in newstate.active) {
			if (!oldstate.active[id]) {
				newstate.active[id].root.classList.toggle('active', true)
				activeChanged = true
			}
		}

		const effselected = mlv.selected()
		if (initial && effselected.length === 1) {
			mlv.redraw(effselected[0])
		}

		checkConsistency(true)

		if (!activeChanged) {
			return
		}
		if (msgView) {
			msgView.aborter.abort()
		}
		msgView = null

		if (effselected.length === 0) {
			dom._kids(msgElem)
		} else if (effselected.length === 1) {
			msgElem.classList.toggle('loading', true)
			const loaded = () => { msgElem.classList.toggle('loading', false) }
			msgView = newMsgView(effselected[0], mlv, listMailboxes, possibleLabels, loaded, refineKeyword, parsedMessageOpt)
			dom._kids(msgElem, msgView)
		} else {
			const trashMailboxID = listMailboxes().find(mb => mb.Trash)?.ID
			const allTrash = trashMailboxID && !effselected.find(miv => miv.messageitem.Message.MailboxID !== trashMailboxID)
			dom._kids(msgElem,
				dom.div(
					attr.role('region'), attr.arialabel('Buttons for multiple messages'),
					style({position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, display: 'flex', alignItems: 'center', justifyContent: 'center'}),
					dom.div(
						style({padding: '4ex', backgroundColor: 'white', borderRadius: '.25em', border: '1px solid #ccc'}),
						dom.div(
							style({textAlign: 'center', marginBottom: '4ex'}),
							''+effselected.length+' messages selected',
						),
						dom.div(
							dom.clickbutton('Archive', attr.title('Move to the Archive mailbox. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox.'), clickCmd(cmdArchive, shortcuts)), ' ',
							allTrash ?
								dom.clickbutton('Delete', attr.title('Permanently delete messages.'), clickCmd(cmdDelete, shortcuts)) :
								dom.clickbutton('Trash', attr.title('Move to the Trash mailbox. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox.'), clickCmd(cmdTrash, shortcuts)),
							' ',
							dom.clickbutton('Junk', attr.title('Move to Junk mailbox, marking as junk and causing this message to be used in spam classification of new incoming messages. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox.'), clickCmd(cmdJunk, shortcuts)), ' ',
							dom.clickbutton('Move to...', function click(e: MouseEvent) {
								const sentMailboxID = listMailboxes().find(mb => mb.Sent)?.ID
								movePopover(e, listMailboxes(), effselected.map(miv => miv.messageitem.Message).filter(m => effselected.length === 1 || !sentMailboxID || m.MailboxID !== sentMailboxID || !otherMailbox(sentMailboxID)))
							}), ' ',
							dom.clickbutton('Labels...', attr.title('Add/remove labels ...'), function click(e: MouseEvent) {
								labelsPopover(e, effselected.map(miv => miv.messageitem.Message), possibleLabels)
							}), ' ',
							dom.clickbutton('Mark Not Junk', attr.title('Mark as not junk, causing this message to be used in spam classification of new incoming messages.'), clickCmd(cmdMarkNotJunk, shortcuts)), ' ',
							dom.clickbutton('Mark Read', clickCmd(cmdMarkRead, shortcuts)), ' ',
							dom.clickbutton('Mark Unread', clickCmd(cmdMarkUnread, shortcuts)), ' ',
							dom.clickbutton('Mute thread', clickCmd(cmdMute, shortcuts)), ' ',
							dom.clickbutton('Unmute thread', clickCmd(cmdUnmute, shortcuts)),
						),
					),
				),
			)
		}
		setLocationHash()
	}

	// Moves the currently focused msgitemView, without changing selection.
	const moveFocus = (miv: MsgitemView) => {
		const oldstate = state()
		focus = miv
		updateState(oldstate)
	}

	const threadExpand = (miv: MsgitemView, changeState: boolean) => {
		if (miv.parent) {
			throw new ConsistencyError('cannot expand non-root')
		}

		const oldstate = state()

		miv.collapsed = false
		const mivl = miv.descendants()
		miv.render()
		mivl.forEach(dmiv => dmiv.render())
		for (const miv of mivl) {
			collapsedMsgitemViews.splice(collapsedMsgitemViews.indexOf(miv), 1)
		}
		const pi = msgitemViews.indexOf(miv)
		msgitemViews.splice(pi+1, 0, ...mivl)
		const next = miv.root.nextSibling
		for (const miv of mivl) {
			mlv.root.insertBefore(miv.root, next)
		}

		if (changeState) {
			updateState(oldstate)
		}
	}
	const threadCollapse = (miv: MsgitemView, changeState: boolean) => {
		if (miv.parent) {
			throw new ConsistencyError('cannot expand non-root')
		}
		const oldstate = state()

		miv.collapsed = true
		const mivl = miv.descendants()

		collapsedMsgitemViews.push(...mivl)
		// If miv or any child was selected, ensure collapsed thread root is also selected.
		let select = [miv, ...mivl].find(xmiv => selected.indexOf(xmiv) >= 0)
		let seli = selected.length // Track first index of already selected miv, which is where we insert the thread root if needed, to keep order.
		msgitemViews.splice(msgitemViews.indexOf(miv)+1, mivl.length)
		for (const dmiv of mivl) {
			dmiv.remove()

			if (focus === dmiv) {
				focus = miv
			}
			const si = selected.indexOf(dmiv)
			if (si >= 0) {
				if (si < seli) {
					seli = si
				}
				selected.splice(si, 1)
			}
		}
		if (select) {
			const si = selected.indexOf(miv)
			if (si < 0) {
				selected.splice(seli, 0, miv)
			}
		}

		// Selected messages may have changed.
		if (changeState) {
			updateState(oldstate)
		}

		// Render remaining thread root, with tree size, effective received age/unread state.
		miv.render()
	}

	const threadToggle = () => {
		const oldstate = state()
		const roots = msgitemViews.filter(miv => !miv.parent && miv.kids.length > 0)
		roots.forEach(miv => {
			let wantCollapsed = miv.messageitem.Message.ThreadCollapsed
			if (settings.threading === api.ThreadMode.ThreadUnread) {
				wantCollapsed = !miv.messageitem.Message.Seen && !miv.findDescendant(miv => !miv.messageitem.Message.Seen)
			}
			if (miv.collapsed === wantCollapsed) {
				return
			}
			if (wantCollapsed) {
				threadCollapse(miv, false)
			} else {
				threadExpand(miv, false)
			}
		})
		updateState(oldstate)
		viewportEnsureMessages()
	}

	const removeSelected = (miv: MsgitemView) => {
		const si = selected.indexOf(miv)
		if (si >= 0) {
			selected.splice(si, 1)
		}
		if (focus === miv) {
			const i = msgitemViews.indexOf(miv)
			if (i > 0) {
				focus = msgitemViews[i-1]
			} else if (i+1 < msgitemViews.length) {
				focus = msgitemViews[i+1]
			} else {
				focus = null
			}
		}
	}

	// Removes message from either msgitemViews, collapsedMsgitemViews,
	// oldThreadMessageItems, and updates UI.
	// Returns ThreadID of removed message if active (expanded or collapsed), or 0 otherwise.
	const removeUID = (mailboxID: number, uid: number) => {
		const match = (miv: MsgitemView) => miv.messageitem.Message.MailboxID === mailboxID && miv.messageitem.Message.UID === uid

		const ci = collapsedMsgitemViews.findIndex(match)
		if (ci >= 0) {
			const miv = collapsedMsgitemViews[ci]
			removeCollapsed(ci)
			return miv.messageitem.Message.ThreadID
		}

		const i = msgitemViews.findIndex(match)
		if (i >= 0) {
			const miv = msgitemViews[i]
			removeExpanded(i)
			return miv.messageitem.Message.ThreadID
		}

		const ti = oldThreadMessageItems.findIndex(mi => mi.Message.MailboxID === mailboxID && mi.Message.UID === uid)
		if (ti >= 0) {
			oldThreadMessageItems.splice(ti, 1)
		}
		return 0
	}

	// Removes message from collapsedMsgitemView and UI at given index, placing
	// messages in oldThreadMessageItems.
	const removeCollapsed = (ci: number) => {
		// Message is collapsed. That means it isn't visible, and neither are its children,
		// and it has a parent. So we just merge the kids with those of the parent.
		const miv = collapsedMsgitemViews[ci]
		collapsedMsgitemViews.splice(ci, 1)
		removeSelected(miv)
		const trmiv = miv.threadRoot() // To rerender, below.
		const pmiv = miv.parent
		if (!pmiv) {
			throw new ConsistencyError('removing collapsed miv, but has no parent')
		}
		miv.parent = null // Strict cleanup.
		const pki = pmiv.kids.indexOf(miv)
		if (pki < 0) {
			throw new ConsistencyError('miv not in parent.kids')
		}
		pmiv.kids.splice(pki, 1, ...miv.kids) // In parent, replace miv with its kids.
		miv.kids.forEach(kmiv => kmiv.parent = pmiv) // Give kids their new parent.
		miv.kids = [] // Strict cleanup.
		pmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime()) // Sort new list of kids.
		trmiv.render() // For count, unread state.
		return
	}

	// Remove message from msgitemViews and UI at the index i.
	const removeExpanded = (i: number) => {
		log('removeExpanded', {i})
		// Note: If we remove a message we may be left with only messages from another
		// mailbox. We'll leave it, new messages could be delivered for that thread. It
		// would be strange to see the remaining messages of the thread disappear.

		const miv = msgitemViews[i]
		removeSelected(miv)
		const pmiv = miv.parent
		miv.parent = null
		if (miv.kids.length === 0) {
			// No kids, easy case, just remove this leaf message.
			miv.remove()
			msgitemViews.splice(i, 1)
			if (pmiv) {
				const pki = pmiv.kids.indexOf(miv)
				if (pki < 0) {
					throw new ConsistencyError('miv not in parent.kids')
				}
				pmiv.kids.splice(pki, 1) // Remove miv from parent's kids.
				miv.parent = null // Strict cleanup.
				pmiv.render() // Update counts.
			}
			return
		}
		if (!pmiv) {
			// If the kids no longer have a parent and become thread roots we leave them in
			// their original location.
			const next = miv.root.nextSibling
			miv.remove()
			msgitemViews.splice(i, 1)
			if (miv.collapsed) {
				msgitemViews.splice(i, 0, ...miv.kids)
				for (const kmiv of miv.kids) {
					const pki = collapsedMsgitemViews.indexOf(kmiv)
					if (pki < 0) {
						throw new ConsistencyError('cannot find collapsed kid in collapsedMsgitemViews')
					}
					collapsedMsgitemViews.splice(pki, 1)
					kmiv.collapsed = true
					kmiv.parent = null
					kmiv.render()
					mlv.root.insertBefore(kmiv.root, next)
				}
			} else {
				// Note: if not collapsed, we leave the kids in the original position in msgitemViews.
				miv.kids.forEach(kmiv => {
					kmiv.collapsed = false
					kmiv.parent = null
					kmiv.render()
					const lastDesc = kmiv.lastDescendant()
					if (lastDesc) {
						// Update end of thread bar.
						lastDesc.render()
					}
				})
			}
			miv.kids = [] // Strict cleanup.
			return
		}

		// If the kids will have a parent, we insert them at the expected location in
		// between parent's existing kids. It is easiest just to take out all kids, add the
		// new ones, sort kids, and add back the subtree.
		const odmivs = pmiv.descendants() // Old direct descendants of parent. This includes miv and kids, and other kids, and miv siblings.
		const pi = msgitemViews.indexOf(pmiv)
		if (pi < 0) {
			throw new ConsistencyError('cannot find parent of removed miv')
		}
		msgitemViews.splice(pi+1, odmivs.length) // Remove all old descendants, we'll add an updated list later.
		const pki = pmiv.kids.indexOf(miv)
		if (pki < 0) {
			throw new Error('did not find miv in parent.kids')
		}
		pmiv.kids.splice(pki, 1) // Remove miv from parent's kids.
		pmiv.kids.push(...miv.kids) // Add miv.kids to parent's kids.
		miv.kids.forEach(kmiv => { kmiv.parent = pmiv }) // Set new parent for miv kids.
		miv.kids = [] // Strict cleanup.
		pmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime())
		const ndmivs = pmiv.descendants() // Excludes miv, that we are removing.
		if (ndmivs.length !== odmivs.length-1) {
			throw new ConsistencyError('unexpected new descendants counts during remove')
		}
		msgitemViews.splice(pi+1, 0, ...ndmivs) // Add all new/current descedants. There is one less than in odmivs.
		odmivs.forEach(ndimv => ndimv.remove())
		const next = pmiv.root.nextSibling
		for (const ndmiv of ndmivs) {
			mlv.root.insertBefore(ndmiv.root, next)
		}
		pmiv.render()
		ndmivs.forEach(dmiv => dmiv.render())
	}


	// If there are no query-matching messages left for this thread, remove the
	// remaining messages from view and keep them around for future deliveries for the
	// thread.
	const possiblyTakeoutOldThreads = (threadIDs: Set<number>) => {
		const hasMatch = (mivs: MsgitemView[], threadID: number) => mivs.find(miv => miv.messageitem.Message.ThreadID === threadID && miv.messageitem.MatchQuery)
		const takeoutOldThread = (mivs: MsgitemView[], threadID: number, visible: boolean) => {
			let i = 0
			while (i < mivs.length) {
				const miv = mivs[i]
				const mi = miv.messageitem
				const m = mi.Message
				if (threadID !== m.ThreadID) {
					i++
					continue
				}
				mivs.splice(i, 1)
				if (visible) {
					miv.remove()
				}
				if (focus === miv) {
					focus = null
					if (i < mivs.length) {
						focus = mivs[i]
					} else if (i > 0) {
						focus = mivs[i-1]
					}
				}
				const si = selected.indexOf(miv)
				if (si >= 0) {
					selected.splice(si, 1)
				}
				// Strict cleanup.
				miv.parent = null
				miv.kids = []
				oldThreadMessageItems.push(mi)
				log('took out old thread message', {mi})
			}
		}

		for (const threadID of threadIDs) {
			if (hasMatch(msgitemViews, threadID) || hasMatch(collapsedMsgitemViews, threadID)) {
				log('still have query-matching message for thread', {threadID})
				continue
			}
			takeoutOldThread(msgitemViews, threadID, true)
			takeoutOldThread(collapsedMsgitemViews, threadID, false)
		}
	}

	const mlv: MsglistView = {
		root: dom.div(),

		updateFlags: (mailboxID: number, uid: number, modseq: number, mask: api.Flags, flags: api.Flags, keywords: string[]) => {
			const updateMessageFlags = (m: api.Message) => {
				m.ModSeq = modseq
				const maskobj = mask as unknown as {[key: string]: boolean}
				const flagsobj = flags as unknown as {[key: string]: boolean}
				const mobj = m as unknown as {[key: string]: boolean}
				for (const k in maskobj) {
					if (maskobj[k]) {
						mobj[k] = flagsobj[k]
					}
				}
				m.Keywords = keywords
			}

			// todo optimize: keep mapping of uid to msgitemView for performance. instead of using Array.find
			let miv = msgitemViews.find(miv => miv.messageitem.Message.MailboxID === mailboxID && miv.messageitem.Message.UID === uid)
			if (!miv) {
				miv = collapsedMsgitemViews.find(miv => miv.messageitem.Message.MailboxID === mailboxID && miv.messageitem.Message.UID === uid)
			}
			if (miv) {
				updateMessageFlags(miv.messageitem.Message)
				miv.render()
				if (miv.parent) {
					const tr = miv.threadRoot()
					if (tr.collapsed) {
						tr.render()
					}
				}
				if (msgView && msgView.messageitem.Message.ID === miv.messageitem.Message.ID) {
					msgView.updateKeywords(modseq, keywords)
				}
				return
			}
			const mi = oldThreadMessageItems.find(mi => mi.Message.MailboxID === mailboxID && mi.Message.UID === uid)
			if (mi) {
				updateMessageFlags(mi.Message)
			} else {
				// Happens for messages outside of view.
				log('could not find msgitemView for uid', uid)
			}
		},

		// Add messages to view, either messages to fill the view with complete threads, or
		// individual messages delivered later.
		addMessageItems: (messageItems: (api.MessageItem[] | null)[], isChange: boolean, requestMsgID: number) => {
			if (messageItems.length === 0) {
				return
			}

			// Each "mil" is a thread, possibly with multiple thread roots. The thread may
			// already be present.
			messageItems.forEach(mil => {
				if (!mil) {
					return // For types, should not happen.
				}

				const threadID = mil[0].Message.ThreadID

				const hasMatch = !!mil.find(mi => mi.MatchQuery)
				if (hasMatch) {
					// This may be a message for a thread that had query-matching matches at some
					// point, but then no longer, causing its messages to have been moved to
					// oldThreadMessageItems. We add back those messages.
					let i = 0
					while (i < oldThreadMessageItems.length) {
						const omi = oldThreadMessageItems[i]
						if (omi.Message.ThreadID === threadID) {
							oldThreadMessageItems.splice(i, 1)
							if (!mil.find(mi => mi.Message.ID === omi.Message.ID)) {
								mil.push(omi)
								log('resurrected old message')
							} else {
								log('dropped old thread message')
							}
						} else {
							i++
						}
					}
				} else {
					// New message(s) are not matching query. If there are no "active" messages for
					// this thread, update/add oldThreadMessageItems.
					const match = (miv: MsgitemView) => miv.messageitem.Message.ThreadID === threadID
					if (!msgitemViews.find(match) && !collapsedMsgitemViews.find(match)) {
						log('adding new message(s) to oldTheadMessageItems')
						for (const mi of mil) {
							const ti = oldThreadMessageItems.findIndex(tmi => tmi.Message.ID === mi.Message.ID)
							if (ti) {
								oldThreadMessageItems[ti] = mi
							} else {
								oldThreadMessageItems.push(mi)
							}
						}
						return
					}
				}

				if (isChange) {
					// This could be an "add" for a message from another mailbox that we are already
					// displaying because of threads. If so, it may have new properties such as the
					// mailbox, so update it.
					const threadIDs = new Set<number>()
					let i = 0
					while (i < mil.length) {
						const mi = mil[i]
						let miv = msgitemViews.find(miv => miv.messageitem.Message.ID === mi.Message.ID)
						if (!miv) {
							miv = collapsedMsgitemViews.find(miv => miv.messageitem.Message.ID === mi.Message.ID)
						}
						if (miv) {
							miv.messageitem = mi
							miv.render()
							mil.splice(i, 1)
							miv.threadRoot().render()
							threadIDs.add(mi.Message.ThreadID)
						} else {
							i++
						}
					}
					log('processed changes for messages with thread', {threadIDs, mil})
					if (mil.length === 0) {
						const oldstate = state()
						possiblyTakeoutOldThreads(threadIDs)
						updateState(oldstate)
						return
					}
				}

				// Find effective receive time for messages. We'll insert at that point.
				let receivedTime = mil[0].Message.Received.getTime()
				const tmiv = msgitemViews.find(miv => miv.messageitem.Message.ThreadID === mil[0].Message.ThreadID)
				if (tmiv) {
					receivedTime = tmiv.receivedTime
				} else {
					for (const mi of mil) {
						const t = mi.Message.Received.getTime()
						if (settings.orderAsc && t < receivedTime || !settings.orderAsc && t > receivedTime) {
							receivedTime = t
						}
					}
				}

				// Create new MsgitemViews.
				const m = new Map<number, MsgitemView>()
				for (const mi of mil) {
					m.set(mi.Message.ID, newMsgitemView(mi, mlv, otherMailbox, listMailboxes, receivedTime, false))
				}

				// Assign miv's to parents or add them to the potential roots.
				let roots: MsgitemView[] = []
				if (settings.threading === api.ThreadMode.ThreadOff) {
					roots = [...m.values()]
				} else {
				nextmiv:
					for (const [_, miv] of m) {
						for (const pid of (miv.messageitem.Message.ThreadParentIDs || [])) {
							const pmiv = m.get(pid)
							if (pmiv) {
								pmiv.kids.push(miv)
								miv.parent = pmiv
								continue nextmiv
							}
						}
						roots.push(miv)
					}
				}

				// Ensure all kids are properly sorted, always ascending by time received.
				for (const [_, miv] of m) {
					miv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime())
				}

				// Add the potential roots as kids to existing parents, if they exist. Only with threading enabled.
				if (settings.threading !== api.ThreadMode.ThreadOff) {
				nextroot:
					for (let i = 0; i < roots.length; ) {
						const miv = roots[i]
						for (const pid of (miv.messageitem.Message.ThreadParentIDs || [])) {
							const pi = msgitemViews.findIndex(xmiv => xmiv.messageitem.Message.ID === pid)
							let parentmiv: MsgitemView | undefined
							let collapsed: boolean
							if (pi >= 0) {
								parentmiv = msgitemViews[pi]
								collapsed = parentmiv.collapsed
								log('found parent', {pi})
							} else {
								parentmiv = collapsedMsgitemViews.find(xmiv => xmiv.messageitem.Message.ID === pid)
								collapsed = true
							}
							if (!parentmiv) {
								log('no parentmiv', pid)
								continue
							}

							const trmiv = parentmiv.threadRoot()
							if (collapsed !== trmiv.collapsed) {
								log('collapsed mismatch', {collapsed: collapsed, 'trmiv.collapsed': trmiv.collapsed, trmiv: trmiv})
								throw new ConsistencyError('mismatch between msgitemViews/collapsedMsgitemViews and threadroot collapsed')
							}
							let prevLastDesc: MsgitemView | null = null
							if (!trmiv.collapsed) {
								// Remove current parent, we'll insert again after linking parent/kids.
								const ndesc = parentmiv.descendants().length
								log('removing descendants temporarily', {ndesc})
								prevLastDesc = parentmiv.lastDescendant()
								msgitemViews.splice(pi+1, ndesc)
							}

							// Link parent & kid, sort kids.
							miv.parent = parentmiv
							parentmiv.kids.push(miv)
							parentmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime())

							if (trmiv.collapsed) {
								// Thread root is collapsed.
								collapsedMsgitemViews.push(miv, ...miv.descendants())

								// Ensure mivs have a root.
								miv.render()
								miv.descendants().forEach(miv => miv.render())

								// Update count/unread status.
								trmiv.render()
							} else {
								const desc = parentmiv.descendants()
								log('inserting parent descendants again', {pi, desc})
								msgitemViews.splice(pi+1, 0, ...desc) // We had removed the old tree, now adding the updated tree.

								// Insert at correct position in dom.
								const i = msgitemViews.indexOf(miv)
								if (i < 0) {
									throw new ConsistencyError('cannot find miv just inserted')
								}
								const l = [miv, ...miv.descendants()]
								// Ensure mivs have valid root.
								l.forEach(miv => miv.render())
								const next = i+1 < msgitemViews.length ? msgitemViews[i+1].root : null
								log('inserting l before next, or appending', {next, l})
								if (next) {
									for (const miv of l) {
										log('inserting miv', {root: miv.root, before: next})
										mlv.root.insertBefore(miv.root, next)
									}
								} else {
									mlv.root.append(...l.map(e => e.root))
								}
								// For beginning/end of thread bar.
								msgitemViews[i-1].render()
								if (prevLastDesc) {
									prevLastDesc.render()
								}
							}
							roots.splice(i, 1)
							continue nextroot
						}
						i++
					}
				}

				// Sort the remaining new roots by their receive times.
				const sign = settings.threading === api.ThreadMode.ThreadOff && settings.orderAsc ? -1 : 1
				roots.sort((miva, mivb) => sign * (mivb.messageitem.Message.Received.getTime() - miva.messageitem.Message.Received.getTime()))

				// Find place to insert, based on thread receive time.
				let nextmivindex: number
				if (tmiv) {
					nextmivindex = msgitemViews.indexOf(tmiv.threadRoot())
				} else {
					nextmivindex = msgitemViews.findIndex(miv => !settings.orderAsc && miv.receivedTime <= receivedTime || settings.orderAsc && receivedTime <= miv.receivedTime)
				}

				for (const miv of roots) {
					miv.collapsed = settings.threading === api.ThreadMode.ThreadOn && miv.messageitem.Message.ThreadCollapsed
					if (settings.threading === api.ThreadMode.ThreadUnread) {
						miv.collapsed = miv.messageitem.Message.Seen && !miv.findDescendant(dmiv => !dmiv.messageitem.Message.Seen)
					}
					if (requestMsgID > 0 && miv.collapsed) {
						miv.collapsed = !miv.findDescendant(dmiv => dmiv.messageitem.Message.ID === requestMsgID)
					}

					const takeThreadRoot = (xmiv: MsgitemView): number => {
						log('taking threadRoot', {id: xmiv.messageitem.Message.ID})
						// Remove subtree from dom.
						const xdmiv = xmiv.descendants()
						xdmiv.forEach(xdmiv => xdmiv.remove())
						xmiv.remove()
						// Link to new parent.
						miv.kids.push(xmiv)
						xmiv.parent = miv
						miv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime())
						return 1+xdmiv.length
					}

					if (settings.threading !== api.ThreadMode.ThreadOff) {
						// We may have to take out existing threadroots and place them under this new root.
						// Because when we move a threadroot, we first remove it, then add it again.
						for (let i = 0; i < msgitemViews.length; ) {
							const xmiv = msgitemViews[i]
							if (!xmiv.parent && xmiv.messageitem.Message.ThreadID === miv.messageitem.Message.ThreadID && (xmiv.messageitem.Message.ThreadParentIDs || []).includes(miv.messageitem.Message.ID)) {
								msgitemViews.splice(i, takeThreadRoot(xmiv))
								nextmivindex = i
							} else {
								i++
							}
						}
						for (let i = 0; i < collapsedMsgitemViews.length; ) {
							const xmiv = collapsedMsgitemViews[i]
							if (!xmiv.parent && xmiv.messageitem.Message.ThreadID === miv.messageitem.Message.ThreadID && (xmiv.messageitem.Message.ThreadParentIDs || []).includes(miv.messageitem.Message.ID)) {
								takeThreadRoot(xmiv)
								collapsedMsgitemViews.splice(i, 1)
							} else {
								i++
							}
						}
					}

					let l = miv.descendants()

					miv.render()
					l.forEach(kmiv => kmiv.render())

					if (miv.collapsed) {
						collapsedMsgitemViews.push(...l)
						l = [miv]
					} else {
						l = [miv, ...l]
					}

					if (nextmivindex < 0) {
						mlv.root.append(...l.map(miv => miv.root))
						msgitemViews.push(...l)
					} else {
						const next = msgitemViews[nextmivindex].root
						for (const miv of l) {
							mlv.root.insertBefore(miv.root, next)
						}
						msgitemViews.splice(nextmivindex, 0, ...l)
					}
				}
			})

			if (!isChange) {
				return
			}

			const oldstate = state()
			if (!focus) {
				focus = msgitemViews[0]
			}
			if (selected.length === 0) {
				if (focus) {
					selected = [focus]
				} else if (msgitemViews.length > 0) {
					selected = [msgitemViews[0]]
				}
			}
			updateState(oldstate)
		},

		// Remove messages, they can be in different threads.
		removeUIDs: (mailboxID: number, uids: number[]) => {
			const oldstate = state()
			const hadSelected = selected.length > 0
			const threadIDs = new Set<number>()
			uids.forEach(uid => {
				const threadID = removeUID(mailboxID, uid)
				log('removed message with thread', {threadID})
				if (threadID) {
					threadIDs.add(threadID)
				}
			})

			possiblyTakeoutOldThreads(threadIDs)

			if (hadSelected && focus && selected.length === 0) {
				selected = [focus]
			}
			updateState(oldstate)
		},

		// Set new muted/collapsed flags for messages in thread.
		updateMessageThreadFields: (messageIDs: number[], muted: boolean, collapsed: boolean) => {
			for (const id of messageIDs) {
				let miv = msgitemViews.find(miv => miv.messageitem.Message.ID === id)
				if (!miv) {
					miv = collapsedMsgitemViews.find(miv => miv.messageitem.Message.ID === id)
				}
				if (miv) {
					miv.messageitem.Message.ThreadMuted = muted
					miv.messageitem.Message.ThreadCollapsed = collapsed
					const mivthr = miv.threadRoot()
					if (mivthr.collapsed) {
						mivthr.render()
					} else {
						miv.render()
					}
				} else {
					const mi = oldThreadMessageItems.find(mi => mi.Message.ID === id)
					if (mi) {
						mi.Message.ThreadMuted = muted
						mi.Message.ThreadCollapsed = collapsed
					}
				}
			}
		},

		// For location hash.
		activeMessageID: () => selected.length === 1 ? selected[0].messageitem.Message.ID : 0,

		redraw: (miv: MsgitemView) => {
			miv.root.classList.toggle('focus', miv === focus)
			miv.root.classList.toggle('active', selected.indexOf(miv) >= 0)
		},

		clear: (): void => {
			dom._kids(mlv.root)
			msgitemViews.forEach(miv => miv.remove())
			msgitemViews = []
			collapsedMsgitemViews = []
			oldThreadMessageItems = []
			focus = null
			selected = []
			dom._kids(msgElem)
			setLocationHash()
		},

		unselect: (): void => {
			const oldstate = state()
			selected = []
			updateState(oldstate)
		},

		select: (miv: MsgitemView): void => {
			const oldstate = state()
			focus = miv
			selected = [miv]
			updateState(oldstate)
		},
		selected: () => {
			const l = []
			for (const miv of selected) {
				l.push(miv)
				if (miv.collapsed) {
					l.push(...miv.descendants())
				}
			}
			return l
		},
		openMessage: (parsedMessage: api.ParsedMessage) => {
			let miv = msgitemViews.find(miv => miv.messageitem.Message.ID === parsedMessage.ID)
			if (!miv) {
				// todo: could move focus to the nearest expanded message in this thread, if any?
				return false
			}
			const oldstate = state()
			focus = miv
			selected = [miv]
			updateState(oldstate, true, parsedMessage)
			return true
		},

		click: (miv: MsgitemView, ctrl: boolean, shift: boolean) => {
			if (msgitemViews.length === 0) {
				return
			}

			const oldstate = state()
			if (shift) {
				const mivindex = msgitemViews.indexOf(miv)
				// Set selection from start of most recent range.
				let recentindex
				if (selected.length > 0) {
					let o = selected.length-1
					recentindex = msgitemViews.indexOf(selected[o])
					while (o > 0) {
						if (selected[o-1] === msgitemViews[recentindex-1]) {
							recentindex--
						} else if(selected[o-1] === msgitemViews[recentindex+1]) {
							recentindex++
						} else {
							break
						}
						o--
					}
				} else {
					recentindex = mivindex
				}
				const oselected = selected
				if (mivindex < recentindex) {
					selected = msgitemViews.slice(mivindex, recentindex+1)
					selected.reverse()
				} else {
					selected = msgitemViews.slice(recentindex, mivindex+1)
				}
				if (ctrl) {
					selected = oselected.filter(e => !selected.includes(e)).concat(selected)
				}
			} else if (ctrl) {
				const index = selected.indexOf(miv)
				if (index < 0) {
					selected.push(miv)
				} else {
					selected.splice(index, 1)
				}
			} else {
				selected = [miv]
			}
			focus = miv
			updateState(oldstate)
		},

		key: async (k: string, e: KeyboardEvent) => {
			const moveKeys = [
				' ', 'ArrowUp', 'ArrowDown',
				'PageUp', 'h', 'H',
				'PageDown', 'l', 'L',
				'j', 'J',
				'k', 'K',
				'Home', ',', '<',
				'End', '.', '>',
				'n', 'N',
				'p', 'P',
				'u', 'U',
			]
			if (!e.altKey && moveKeys.includes(e.key)) {
				const moveclick = (index: number, clip: boolean) => {
					if (clip && index < 0) {
						index = 0
					} else if (clip && index >= msgitemViews.length) {
						index = msgitemViews.length-1
					}
					if (index < 0 || index >= msgitemViews.length) {
						return
					}
					if (e.ctrlKey) {
						moveFocus(msgitemViews[index])
					} else {
						mlv.click(msgitemViews[index], false, e.shiftKey)
					}
				}

				let i = msgitemViews.findIndex(miv => miv === focus)
				if (e.key === ' ') {
					if (i >= 0) {
						mlv.click(msgitemViews[i], e.ctrlKey, e.shiftKey)
					}
				} else if (e.key === 'ArrowUp' || e.key === 'k' || e.key === 'K') {
					moveclick(i-1, e.key === 'K')
				} else if (e.key === 'ArrowDown' || e.key === 'j' || e.key === 'J') {
					moveclick(i+1, e.key === 'J')
				} else if (e.key === 'PageUp' || e.key === 'h' || e.key === 'H' || e.key === 'PageDown' || e.key === 'l' || e.key === 'L') {
					if (msgitemViews.length > 0) {
						let n = Math.max(1, Math.floor(scrollElemHeight()/mlv.itemHeight())-1)
						if (e.key === 'PageUp' || e.key === 'h' || e.key === 'H') {
							n = -n
						}
						moveclick(i + n, true)
					}
				} else if (e.key === 'Home' || e.key === ',' || e.key === '<') {
					moveclick(0, true)
				} else if (e.key === 'End' || e.key === '.' || e.key === '>') {
					moveclick(msgitemViews.length-1, true)
				} else if (e.key === 'n' || e.key === 'N') {
					if (i < 0) {
						moveclick(0, true)
					} else {
						const tid = msgitemViews[i].messageitem.Message.ThreadID
						for (; i < msgitemViews.length; i++) {
							if (msgitemViews[i].messageitem.Message.ThreadID !== tid) {
								moveclick(i, true)
								break
							}
						}
					}
				} else if (e.key === 'p' || e.key === 'P') {
					if (i < 0) {
						moveclick(0, true)
					} else {
						let thrmiv = msgitemViews[i].threadRoot()
						if (thrmiv === msgitemViews[i]) {
							if (i-1 >= 0) {
								thrmiv = msgitemViews[i-1].threadRoot()
							}
						}
						moveclick(msgitemViews.indexOf(thrmiv), true)
					}
				} else if (e.key === 'u' || e.key === 'U') {
					for (i = i < 0 ? 0 : i+1; i < msgitemViews.length; i += 1) {
						if (!msgitemViews[i].messageitem.Message.Seen || msgitemViews[i].collapsed && msgitemViews[i].findDescendant(miv => !miv.messageitem.Message.Seen)) {
							moveclick(i, true)
							break
						}
					}
				}
				e.preventDefault()
				e.stopPropagation()
				return
			}
			const fn = shortcuts[k]
			if (fn) {
				e.preventDefault()
				e.stopPropagation()
				fn()
			} else if (msgView) {
				msgView.key(k, e)
			} else {
				log('key not handled', k)
			}
		},
		mailboxes: () => listMailboxes(),
		itemHeight: () => msgitemViews.length > 0 ? msgitemViews[0].root.getBoundingClientRect().height : 25,
		threadExpand: (miv: MsgitemView) => threadExpand(miv, true),
		threadCollapse: (miv: MsgitemView) => threadCollapse(miv, true),
		threadToggle: threadToggle,
		viewportEnsureMessages: viewportEnsureMessages,

		cmdArchive: cmdArchive,
		cmdTrash: cmdTrash,
		cmdDelete: cmdDelete,
		cmdJunk: cmdJunk,
		cmdMarkNotJunk: cmdMarkNotJunk,
		cmdMarkRead: cmdMarkRead,
		cmdMarkUnread: cmdMarkUnread,
		cmdMute: cmdMute,
		cmdUnmute: cmdUnmute,
	}

	return mlv
}

// MailboxView is a single mailbox item in the list of mailboxes. It is a drag and
// drop target for messages. It can be hidden, when a parent/ancestor is collapsed.
// It can be collapsed itself, causing it to still be visible, but its children
// hidden.
interface MailboxView {
	root: HTMLElement

	// Changed by the MailboxlistView.
	shortname: string // Just the last part of the slash-separated name.
	parents: number // How many parents/ancestors, for indenting.
	hidden: boolean // If currently hidden.

	mailbox: api.Mailbox
	update: () => void // Render again, e.g. after toggling hiddenness.
	open: (load: boolean) => Promise<void> // Open mailbox, clearing MsglistView and, if load is set, requesting messages.
	setCounts: (total:number, unread: number) => void
	setSpecialUse: (specialUse: api.SpecialUse) => void
	setKeywords: (keywords: string[]) => void
}

const newMailboxView = (xmb: api.Mailbox, mailboxlistView: MailboxlistView, otherMailbox: otherMailbox): MailboxView => {
	const plusbox = '⊞'
	const minusbox = '⊟'
	const cmdCollapse = async () => {
		settings.mailboxCollapsed[mbv.mailbox.ID] = true
		settingsPut(settings)
		mailboxlistView.updateHidden()
		mbv.root.focus()
	}
	const cmdExpand = async () => {
		delete(settings.mailboxCollapsed[mbv.mailbox.ID])
		settingsPut(settings)
		mailboxlistView.updateHidden()
		mbv.root.focus()
	}
	const collapseElem = dom.span(dom._class('mailboxcollapse'), minusbox, function click(e: MouseEvent) {
		e.stopPropagation()
		cmdCollapse()
	})
	const expandElem = dom.span(plusbox, function click(e: MouseEvent) {
		e.stopPropagation()
		cmdExpand()
	})

	let name: HTMLElement, unread: HTMLElement
	let actionBtn: HTMLButtonElement

	const cmdOpenActions = async () => {
		const trashmb = mailboxlistView.mailboxes().find(mb => mb.Trash)

		const remove = popover(actionBtn, {transparent: true},
			dom.div(style({display: 'flex', flexDirection: 'column', gap: '.5ex'}),
				dom.div(
					dom.clickbutton('Move to trash', attr.title('Move mailbox, its messages and its mailboxes to the trash.'), async function click() {
						if (!trashmb) {
							window.alert('No mailbox configured for trash yet.')
							return
						}
						if (!window.confirm('Are you sure you want to move this mailbox, its messages and its mailboxes to the trash?')) {
							return
						}
						remove()
						await withStatus('Moving mailbox to trash', client.MailboxRename(mbv.mailbox.ID, trashmb.Name + '/' + mbv.mailbox.Name))
					}),
				),
				dom.div(
					dom.clickbutton('Delete mailbox', attr.title('Permanently delete this mailbox and all its messages.'), async function click() {
						if (!window.confirm('Are you sure you want to permanently delete this mailbox and all its messages?')) {
							return
						}
						remove()
						await withStatus('Deleting mailbox', client.MailboxDelete(mbv.mailbox.ID))
					}),
				),
				dom.div(
					dom.clickbutton('Empty mailbox', async function click() {
						if (!window.confirm('Are you sure you want to empty this mailbox, permanently removing its messages? Mailboxes inside this mailbox are not affected.')) {
							return
						}
						remove()
						await withStatus('Emptying mailbox', client.MailboxEmpty(mbv.mailbox.ID))
					}),
				),
				dom.div(
					dom.clickbutton('Rename mailbox', function click() {
						remove()

						let fieldset: HTMLFieldSetElement, name: HTMLInputElement

						const remove2 = popover(actionBtn, {},
							dom.form(
								async function submit(e: SubmitEvent) {
									e.preventDefault()
									await withStatus('Renaming mailbox', client.MailboxRename(mbv.mailbox.ID, name.value), fieldset)
									remove2()
								},
								fieldset=dom.fieldset(
									dom.label(
										'Name ',
										name=dom.input(attr.required(''), attr.value(mbv.mailbox.Name), prop({selectionStart: 0, selectionEnd: mbv.mailbox.Name.length})),
									),
									' ',
									dom.submitbutton('Rename'),
								),
							),
						)
					}),
				),
				dom.div(
					dom.clickbutton('Set role for mailbox...', attr.title('Set a special-use role on the mailbox, making it the designated mailbox for either Archived, Sent, Draft, Trashed or Junk messages.'), async function click() {
						remove()

						const setUse = async (set: (mb: api.Mailbox) => void) => {
							const mb = {...mbv.mailbox}
							mb.Archive = mb.Draft = mb.Junk = mb.Sent = mb.Trash = false
							set(mb)
							await withStatus('Marking mailbox as special use', client.MailboxSetSpecialUse(mb))
						}
						popover(actionBtn, {transparent: true},
							dom.div(style({display: 'flex', flexDirection: 'column', gap: '.5ex'}),
								dom.div(dom.clickbutton('Archive', async function click() { await setUse((mb: api.Mailbox) => { mb.Archive = true }) })),
								dom.div(dom.clickbutton('Draft', async function click() { await setUse((mb: api.Mailbox) => { mb.Draft = true }) })),
								dom.div(dom.clickbutton('Junk', async function click() { await setUse((mb: api.Mailbox) => { mb.Junk = true }) })),
								dom.div(dom.clickbutton('Sent', async function click() { await setUse((mb: api.Mailbox) => { mb.Sent = true }) })),
								dom.div(dom.clickbutton('Trash', async function click() { await setUse((mb: api.Mailbox) => { mb.Trash = true }) })),
							),
						)
					}),
				),
			),
		)
	}

	// Keep track of dragenter/dragleave ourselves, we don't get a neat 1 enter and 1
	// leave event from browsers, we get events for multiple of this elements children.
	let drags = 0

	const root = dom.div(dom._class('mailboxitem'),
		attr.tabindex('0'),
		async function keydown(e: KeyboardEvent) {
			if (e.key === 'Enter') {
				e.stopPropagation()
				await withStatus('Opening mailbox', mbv.open(true))
			} else if (e.key === 'ArrowLeft') {
				e.stopPropagation()
				if (!mailboxlistView.mailboxLeaf(mbv)) {
					cmdCollapse()
				}
			} else if (e.key === 'ArrowRight') {
				e.stopPropagation()
				if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
					cmdExpand()
				}
			} else if (e.key === 'b') {
				cmdOpenActions()
			}
		},
		async function dblclick() {
			if (mailboxlistView.mailboxLeaf(mbv)) {
				return
			}
			if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
				cmdExpand()
			} else {
				cmdCollapse()
			}
		},
		async function click() {
			mbv.root.focus()
			await withStatus('Opening mailbox', mbv.open(true))
		},
		function dragover(e: DragEvent) {
			e.preventDefault()
			e.dataTransfer!.dropEffect = 'move'
		},
		function dragenter(e: DragEvent) {
			e.stopPropagation()
			drags++
			mbv.root.classList.toggle('dropping', true)
		},
		function dragleave(e: DragEvent) {
			e.stopPropagation()
			drags--
			if (drags <= 0) {
				mbv.root.classList.toggle('dropping', false)
			}
		},
		async function drop(e: DragEvent) {
			e.preventDefault()
			mbv.root.classList.toggle('dropping', false)
			const sentMailboxID = mailboxlistView.mailboxes().find(mb => mb.Sent)?.ID
			const mailboxMsgIDs = JSON.parse(e.dataTransfer!.getData('application/vnd.mox.messages')) as number[][]
			const msgIDs = mailboxMsgIDs
				.filter(mbMsgID => mbMsgID[0] !== xmb.ID)
				.filter(mbMsgID => mailboxMsgIDs.length === 1 || !sentMailboxID || mbMsgID[0] !== sentMailboxID || !otherMailbox(sentMailboxID))
				.map(mbMsgID => mbMsgID[1])
			await withStatus('Moving to '+xmb.Name, client.MessageMove(msgIDs, xmb.ID))
		},
		dom.div(dom._class('mailbox'),
			style({display: 'flex', justifyContent: 'space-between'}),
			name=dom.div(style({whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'})),
			dom.div(
				style({whiteSpace: 'nowrap'}),
				actionBtn=dom.clickbutton(dom._class('mailboxhoveronly'),
					'...',
					attr.tabindex('-1'), // Without, tab breaks because this disappears when mailbox loses focus.
					attr.arialabel('Mailbox actions'),
					attr.title('Actions on mailbox, like deleting, emptying, renaming.'),
					function click(e: MouseEvent) {
						e.stopPropagation()
						cmdOpenActions()
					},
				),
				' ',
				unread=dom.b(dom._class('silenttitle')),
			),
		),
	)

	const update = () => {
		let moreElems: any[] = []
		if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
			moreElems = [' ', expandElem]
		} else if (!mailboxlistView.mailboxLeaf(mbv)) {
			moreElems = [' ', collapseElem]
		}
		let ntotal = mbv.mailbox.Total
		let nunread = mbv.mailbox.Unread
		if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
			const prefix = mbv.mailbox.Name+'/'
			for (const mb of mailboxlistView.mailboxes()) {
				if (mb.Name.startsWith(prefix)) {
					ntotal += mb.Total
					nunread += mb.Unread
				}
			}
		}
		dom._kids(name, dom.span(mbv.parents > 0 ? style({paddingLeft: ''+(mbv.parents*2/3)+'em'}) : [], mbv.shortname, attr.title('Total messages: ' + ntotal), moreElems))
		dom._kids(unread, nunread === 0 ? ['', attr.title('')] : [''+nunread, attr.title(''+nunread+' unread')])
	}

	const mbv = {
		root: root,

		// Set by update(), typically through MailboxlistView updateMailboxNames after inserting.
		shortname: '',
		parents: 0,
		hidden: false,

		update: update,
		mailbox: xmb,
		open: async (load: boolean) => {
			await mailboxlistView.openMailboxView(mbv, load, false)
		},
		setCounts: (total: number, unread: number) => {
			mbv.mailbox.Total = total
			mbv.mailbox.Unread = unread
			// If mailbox is collapsed, parent needs updating.
			// todo optimize: only update parents, not all.
			mailboxlistView.updateCounts()
		},
		setSpecialUse: (specialUse: api.SpecialUse) => {
			mbv.mailbox.Archive = specialUse.Archive
			mbv.mailbox.Draft = specialUse.Draft
			mbv.mailbox.Junk = specialUse.Junk
			mbv.mailbox.Sent = specialUse.Sent
			mbv.mailbox.Trash = specialUse.Trash
		},
		setKeywords: (keywords: string[]) => {
			mbv.mailbox.Keywords = keywords
		},
	}
	return mbv
}

// MailboxlistView is the list on the left with all mailboxes. It holds MailboxViews.
interface MailboxlistView {
	root: HTMLElement

	loadMailboxes: (mailboxes: api.Mailbox[], mbnameOpt?: string) => void
	closeMailbox: () => void
	openMailboxView: (mbv: MailboxView, load: boolean, focus: boolean) => Promise<void>
	mailboxLeaf: (mbv: MailboxView) => boolean
	updateHidden: () => void

	updateCounts: () => void
	activeMailbox: () => api.Mailbox | null
	mailboxes: () => api.Mailbox[]
	findMailboxByID: (id: number) => api.Mailbox | null
	findMailboxByName: (name: string) => api.Mailbox | null

	openMailboxID: (id: number, focus: boolean) => Promise<void>

	// For change events.
	addMailbox: (mb: api.Mailbox) => void
	renameMailbox: (mailboxID: number, newName: string) => void
	removeMailbox: (mailboxID: number) => void
	setMailboxCounts: (mailboxID: number, total: number, unread: number) => void
	setMailboxSpecialUse: (mailboxID: number, specialUse: api.SpecialUse) => void
	setMailboxKeywords: (mailboxID: number, keywords: string[]) => void
}

const newMailboxlistView = (msglistView: MsglistView, requestNewView: requestNewView, updatePageTitle: updatePageTitle, setLocationHash: setLocationHash, unloadSearch: unloadSearch, otherMailbox: otherMailbox): MailboxlistView => {
	let mailboxViews: MailboxView[] = []
	let mailboxViewActive: MailboxView | null

	// Reorder mailboxes and assign new short names and indenting. Called after changing the list.
	const updateMailboxNames = () => {
		const draftmb = mailboxViews.find(mbv => mbv.mailbox.Draft)?.mailbox
		const sentmb = mailboxViews.find(mbv => mbv.mailbox.Sent)?.mailbox
		const archivemb = mailboxViews.find(mbv => mbv.mailbox.Archive)?.mailbox
		const trashmb = mailboxViews.find(mbv => mbv.mailbox.Trash)?.mailbox
		const junkmb = mailboxViews.find(mbv => mbv.mailbox.Junk)?.mailbox
		const stem = (s: string) => s.split('/')[0]
		const specialUse = [
			(mb: api.Mailbox) => stem(mb.Name) === 'Inbox',
			(mb: api.Mailbox) => draftmb && stem(mb.Name) === stem(draftmb.Name),
			(mb: api.Mailbox) => sentmb && stem(mb.Name) === stem(sentmb.Name),
			(mb: api.Mailbox) => archivemb && stem(mb.Name) === stem(archivemb.Name),
			(mb: api.Mailbox) => trashmb && stem(mb.Name) === stem(trashmb.Name),
			(mb: api.Mailbox) => junkmb && stem(mb.Name) === stem(junkmb.Name),
		]
		mailboxViews.sort((mbva, mbvb) => {
			const ai = specialUse.findIndex(fn => fn(mbva.mailbox))
			const bi = specialUse.findIndex(fn => fn(mbvb.mailbox))
			if (ai < 0 && bi >= 0) {
				return 1
			} else if (ai >= 0 && bi < 0) {
				return -1
			} else if (ai >= 0 && bi >= 0 && ai !== bi) {
				return ai < bi ? -1 : 1
			}
			const la = mbva.mailbox.Name.split('/')
			const lb = mbvb.mailbox.Name.split('/')
			let n = Math.min(la.length, lb.length)
			for (let i = 0; i < n; i++) {
				if (la[i] === lb[i]) {
					continue
				}
				return la[i] < lb[i] ? -1 : 1
			}
			return mbva.mailbox.Name < mbvb.mailbox.Name ? -1 : 1
		})

		let prevmailboxname: string = ''
		mailboxViews.forEach(mbv => {
			const mb = mbv.mailbox
			let shortname = mb.Name
			let parents = 0
			if (prevmailboxname) {
				let prefix = ''
				for (const s of prevmailboxname.split('/')) {
					const nprefix = prefix + s + '/'
					if (mb.Name.startsWith(nprefix)) {
						prefix = nprefix
						parents++
					} else {
						break
					}
				}
				shortname = mb.Name.substring(prefix.length)
			}
			mbv.shortname = shortname
			mbv.parents = parents
			mbv.update() // Render name.
			prevmailboxname = mb.Name
		})

		updateHidden()
	}

	const mailboxHidden = (mb: api.Mailbox, mailboxesMap: {[key: string]: api.Mailbox}) => {
		let s = ''
		for (const e of mb.Name.split('/')) {
			if (s) {
				s += '/'
			}
			s += e
			const pmb = mailboxesMap[s]
			if (pmb && settings.mailboxCollapsed[pmb.ID] && s !== mb.Name) {
				return true
			}
		}
		return false
	}

	const mailboxLeaf = (mbv: MailboxView) => {
		const index = mailboxViews.findIndex(v => v === mbv)
		const prefix = mbv.mailbox.Name+'/'
		const r = index < 0 || index+1 >= mailboxViews.length || !mailboxViews[index+1].mailbox.Name.startsWith(prefix)
		return r
	}

	const updateHidden = () => {
		const mailboxNameMap: {[key: string]: api.Mailbox} = {}
		mailboxViews.forEach((mbv) => mailboxNameMap[mbv.mailbox.Name] = mbv.mailbox)
		for(const mbv of mailboxViews) {
			mbv.hidden = mailboxHidden(mbv.mailbox, mailboxNameMap)
		}
		mailboxViews.forEach(mbv => mbv.update())
		dom._kids(mailboxesElem, mailboxViews.filter(mbv => !mbv.hidden))
	}

	const root = dom.div()
	const mailboxesElem = dom.div()

	dom._kids(root,
		dom.div(attr.role('region'), attr.arialabel('Mailboxes'),
			dom.div(
				dom.h1('Mailboxes', style({display: 'inline', fontSize: 'inherit'})),
				' ',
				dom.clickbutton('+', attr.arialabel('Create new mailbox.'), attr.title('Create new mailbox.'), style({padding: '0 .25em'}), function click(e: MouseEvent) {
					let fieldset: HTMLFieldSetElement, name: HTMLInputElement

					const remove = popover(e.target! as HTMLElement, {},
						dom.form(
							async function submit(e: SubmitEvent) {
								e.preventDefault()
								await withStatus('Creating mailbox', client.MailboxCreate(name.value), fieldset)
								remove()
							},
							fieldset=dom.fieldset(
								dom.label(
									'Name ',
									name=dom.input(attr.required('yes'), focusPlaceholder('Lists/Go/Nuts')),
								),
								' ',
								dom.submitbutton('Create'),
							),
						),
					)
				}),
			),
			mailboxesElem,
		),
	)

	const loadMailboxes = (mailboxes: api.Mailbox[], mbnameOpt?: string) => {
		mailboxViews = mailboxes.map(mb => newMailboxView(mb, mblv, otherMailbox))
		updateMailboxNames()
		if (mbnameOpt) {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.Name === mbnameOpt)
			if (mbv) {
				openMailboxView(mbv, false, false)
			}
		}
	}

	const closeMailbox = () => {
		if (!mailboxViewActive) {
			return
		}
		mailboxViewActive.root.classList.toggle('active', false)
		mailboxViewActive = null
		updatePageTitle()
	}

	const openMailboxView = async (mbv: MailboxView, load: boolean, focus: boolean): Promise<void> => {

		// Ensure searchbarElem is in inactive state.
		unloadSearch()

		if (mailboxViewActive) {
			mailboxViewActive.root.classList.toggle('active', false)
		}

		mailboxViewActive = mbv
		mbv.root.classList.toggle('active', true)

		updatePageTitle()

		if (load) {
			setLocationHash()
			const f = newFilter()
			f.MailboxID = mbv.mailbox.ID
			await withStatus('Requesting messages', requestNewView(true, f, newNotFilter()))
		} else {
			msglistView.clear()
			setLocationHash()
		}
		if (focus) {
			mbv.root.focus()
		}
	}

	const mblv = {
		root: root,
		loadMailboxes: loadMailboxes,
		closeMailbox: closeMailbox,
		openMailboxView: openMailboxView,
		mailboxLeaf: mailboxLeaf,
		updateHidden: updateHidden,

		updateCounts: (): void => mailboxViews.forEach(mbv => mbv.update()),

		activeMailbox: () => mailboxViewActive ? mailboxViewActive.mailbox : null,
		mailboxes: (): api.Mailbox[] => mailboxViews.map(mbv => mbv.mailbox),
		findMailboxByID: (id: number): api.Mailbox | null => mailboxViews.find(mbv => mbv.mailbox.ID === id)?.mailbox || null,
		findMailboxByName: (name: string): api.Mailbox | null => mailboxViews.find(mbv => mbv.mailbox.Name === name)?.mailbox || null,

		openMailboxID: async (id: number, focus: boolean): Promise<void> => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === id)
			if (mbv) {
				await openMailboxView(mbv, false, focus)
			} else {
				throw new Error('unknown mailbox')
			}
		},

		addMailbox: (mb: api.Mailbox): void => {
			const mbv = newMailboxView(mb, mblv, otherMailbox)
			mailboxViews.push(mbv)
			updateMailboxNames()
		},

		renameMailbox: (mailboxID: number, newName: string): void => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID)
			if (!mbv) {
				throw new Error('rename event: unknown mailbox')
			}
			mbv.mailbox.Name = newName
			updateMailboxNames()
		},

		removeMailbox: (mailboxID: number): void => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID)
			if (!mbv) {
				throw new Error('remove event: unknown mailbox')
			}
			if (mbv === mailboxViewActive) {
				const inboxv = mailboxViews.find(mbv => mbv.mailbox.Name === 'Inbox')
				if (inboxv) {
					openMailboxView(inboxv, true, false) // note: async function
				}
			}
			const index = mailboxViews.findIndex(mbv => mbv.mailbox.ID === mailboxID)
			mailboxViews.splice(index, 1)
			updateMailboxNames()
		},

		setMailboxCounts: (mailboxID: number, total: number, unread: number): void => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID)
			if (!mbv) {
				throw new Error('mailbox message/unread count changed: unknown mailbox')
			}
			mbv.setCounts(total, unread)
			if (mbv === mailboxViewActive) {
				updatePageTitle()
			}
		},

		setMailboxSpecialUse: (mailboxID: number, specialUse: api.SpecialUse): void => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID)
			if (!mbv) {
				throw new Error('special-use flags changed: unknown mailbox')
			}
			mbv.setSpecialUse(specialUse)
			updateMailboxNames()
		},

		setMailboxKeywords: (mailboxID: number, keywords: string[]): void => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID)
			if (!mbv) {
				throw new Error('keywords changed: unknown mailbox')
			}
			mbv.setKeywords(keywords)
		},
	}
	return mblv
}

interface SearchView {
	root: HTMLElement
	submit: () => Promise<void>
	ensureLoaded: () => void // For loading mailboxes into the select dropdown, after SSE connection sent list of mailboxes.
	updateForm: () => void
}

const newSearchView = (searchbarElem: HTMLInputElement, mailboxlistView: MailboxlistView, startSearch: (f: api.Filter, notf: api.NotFilter) => Promise<void>, searchViewClose: () => void) => {
	interface FlagView {
		active: boolean | null
		flag: string
		root: HTMLElement
		update: () => void
	}

	let form: HTMLFormElement
	let words: HTMLInputElement, mailbox: HTMLSelectElement, mailboxkids: HTMLInputElement, from: HTMLInputElement, to: HTMLInputElement, oldestDate: HTMLInputElement, oldestTime: HTMLInputElement, newestDate: HTMLInputElement, newestTime: HTMLInputElement, subject: HTMLInputElement, flagViews: FlagView[], labels: HTMLInputElement, minsize: HTMLInputElement, maxsize: HTMLInputElement
	let attachmentNone: HTMLInputElement, attachmentAny: HTMLInputElement, attachmentImage: HTMLInputElement, attachmentPDF: HTMLInputElement, attachmentArchive: HTMLInputElement, attachmentSpreadsheet: HTMLInputElement, attachmentDocument: HTMLInputElement, attachmentPresentation: HTMLInputElement

	const makeDateTime = (dt: string, tm: string): string => {
		if (!dt && !tm) {
			return ''
		}
		if (!dt) {
			const now = new Date()
			const pad0 = (v: number) => v <= 9 ? '0'+v : ''+v
			dt = [now.getFullYear(), pad0(now.getMonth()+1), pad0(now.getDate())].join('-')
		}
		if (dt && tm) {
			return dt+'T'+tm
		}
		return dt
	}

	const packString = (s: string): string => needsDquote(s) ? dquote(s) : s
	const packNotString = (s: string): string => '-' + (needsDquote(s) || s.startsWith('-') ? dquote(s) : s)

	// Sync the form fields back into the searchbarElem. We process in order of the form,
	// so we may rearrange terms. We also canonicalize quoting and space and remove
	// empty strings.
	const updateSearchbar = (): void => {
		let tokens: Token[] = []
		if (mailbox.value && mailbox.value !== '-1') {
			const v = mailbox.value === '0' ? '' : mailbox.selectedOptions[0].text // '0' is "All mailboxes", represented as "mb:".
			tokens.push([false, 'mb', false, v])
		}
		if (mailboxkids.checked) {
			tokens.push([false, 'submb', false, ''])
		}
		tokens.push(...parseSearchTokens(words.value))
		tokens.push(...parseSearchTokens(from.value).map(t => [t[0], 'f', false, t[3]] as Token))
		tokens.push(...parseSearchTokens(to.value).map(t => [t[0], 't', false, t[3]] as Token))
		const start = makeDateTime(oldestDate.value, oldestTime.value)
		if (start) {
			tokens.push([false, 'start', false, start])
		}
		const end = makeDateTime(newestDate.value, newestTime.value)
		if (end) {
			tokens.push([false, 'end', false, end])
		}
		tokens.push(...parseSearchTokens(subject.value).map(t => [t[0], 's', false, t[3]] as Token))
		const check = (elem: HTMLInputElement, tag: string, value: string): void => {
			if (elem.checked) {
				tokens.push([false, tag, false, value])
			}
		}
		check(attachmentNone, 'a', 'none')
		check(attachmentAny, 'a', 'any')
		check(attachmentImage, 'a', 'image')
		check(attachmentPDF, 'a', 'pdf')
		check(attachmentArchive, 'a', 'archive')
		check(attachmentSpreadsheet, 'a', 'spreadsheet')
		check(attachmentDocument, 'a', 'document')
		check(attachmentPresentation, 'a', 'presentation')

		tokens.push(...flagViews.filter(fv => fv.active !== null).map(fv => {
			return [!fv.active, 'l', false, fv.flag] as Token
		}))
		tokens.push(...parseSearchTokens(labels.value).map(t => [t[0], 'l', t[2], t[3]] as Token))

		tokens.push(...headerViews.filter(hv => hv.key.value).map(hv => [false, 'h', false, hv.key.value+':'+hv.value.value] as Token))
		const minstr = parseSearchSize(minsize.value)[0]
		if (minstr) {
			tokens.push([false, 'minsize', false, minstr])
		}
		const maxstr = parseSearchSize(maxsize.value)[0]
		if (maxstr) {
			tokens.push([false, 'maxsize', false, maxstr])
		}

		searchbarElem.value = tokens.map(packToken).join(' ')
	}

	const setDateTime = (s: string | null | undefined, dateElem: HTMLInputElement, timeElem: HTMLInputElement) => {
		if (!s) {
			return
		}
		const t = s.split('T', 2)
		const dt = t.length === 2 || t[0].includes('-') ? t[0] : ''
		const tm = t.length === 2 ? t[1] : (t[0].includes(':') ? t[0] : '')
		if (dt) {
			dateElem.value = dt
		}
		if (tm) {
			timeElem.value = tm
		}
	}

	// Update form based on searchbarElem. We parse the searchbarElem into a filter. Then reset
	// and populate the form.
	const updateForm = (): void => {
		const [f, notf, strs] = parseSearch(searchbarElem.value, mailboxlistView)
		form.reset()

		const packTwo = (l: string[] | null | undefined, lnot: string[] | null | undefined) => (l || []).map(packString).concat((lnot || []).map(packNotString)).join(' ')

		if (f.MailboxName) {
			const o = [...mailbox.options].find(o => o.text === f.MailboxName) || mailbox.options[0]
			if (o) {
				o.selected = true
			}
		} else if (f.MailboxID === -1) {
			// "All mailboxes except ...".
			mailbox.options[0].selected = true
		} else {
			const id = ''+f.MailboxID
			const o = [...mailbox.options].find(o => o.value === id) || mailbox.options[0]
			o.selected = true
		}
		mailboxkids.checked = f.MailboxChildrenIncluded
		words.value = packTwo(f.Words, notf.Words)
		from.value = packTwo(f.From, notf.From)
		to.value = packTwo(f.To, notf.To)
		setDateTime(strs.Oldest, oldestDate, oldestTime)
		setDateTime(strs.Newest, newestDate, newestTime)
		subject.value = packTwo(f.Subject, notf.Subject)

		const elem = (<{[k: string]: HTMLInputElement}>{
			none: attachmentNone,
			any: attachmentAny,
			image: attachmentImage,
			pdf: attachmentPDF,
			archive: attachmentArchive,
			spreadsheet: attachmentSpreadsheet,
			document: attachmentDocument,
			presentation: attachmentPresentation,
		})[f.Attachments]
		if (elem) {
			attachmentChecks(elem, true)
		}

		const otherlabels: string[] = []
		const othernotlabels: string[] = []
		flagViews.forEach(fv => fv.active = null)
		const setLabels = (flabels: string[] | null | undefined, other: string[], not: boolean) => {
			(flabels || []).forEach(l => {
				l = l.toLowerCase()
				// Find if this is a well-known flag.
				const fv = flagViews.find(fv => fv.flag.toLowerCase() === l)
				if (fv) {
					fv.active = !not
					fv.update()
				} else {
					other.push(l)
				}
			})
		}
		setLabels(f.Labels, otherlabels, false)
		setLabels(notf.Labels, othernotlabels, true)
		labels.value = packTwo(otherlabels, othernotlabels)

		headerViews.slice(1).forEach(hv => hv.root.remove())
		headerViews = [headerViews[0]]
		if (f.Headers && f.Headers.length > 0) {
			(f.Headers || []).forEach((kv, index) => {
				const [k, v] = kv || ['', '']
				if (index > 0) {
					addHeaderView()
				}
				headerViews[index].key.value = k
				headerViews[index].value.value = v
			})
		}

		if (strs.SizeMin) {
			minsize.value = strs.SizeMin
		}
		if (strs.SizeMax) {
			maxsize.value = strs.SizeMax
		}
	}

	const attachmentChecks = (elem: HTMLInputElement, set?: boolean): void => {
		if (elem.checked || set) {
			for (const e of [attachmentNone, attachmentAny, attachmentImage, attachmentPDF, attachmentArchive, attachmentSpreadsheet, attachmentDocument, attachmentPresentation]) {
				if (e !== elem) {
					e.checked = false
				} else if (set) {
					e.checked = true
				}
			}
		}
	}

	const changeHandlers = [
		function change() {
			updateSearchbar()
		},
		function keyup() {
			updateSearchbar()
		},
	]

	const attachmentHandlers = [
		function change(e: Event) {
			attachmentChecks(e.target! as HTMLInputElement)
		},
		function mousedown(e: MouseEvent) {
			// Radiobuttons cannot be deselected normally. With this handler a user can push
			// down on the button, then move pointer out of button and release the button to
			// clear the radiobutton.
			const target = e.target! as HTMLInputElement
			if (e.buttons === 1 && target.checked) {
				target.checked = false
				e.preventDefault()
			}
		},
		...changeHandlers,
	]

	interface HeaderView {
		root: HTMLElement,
		key: HTMLInputElement,
		value: HTMLInputElement,
	}

	let headersCell: HTMLElement // Where we add headerViews.
	let headerViews: HeaderView[]

	const newHeaderView = (first: boolean) => {
		let key: HTMLInputElement, value: HTMLInputElement
		const root = dom.div(
			style({display: 'flex'}),
			key=dom.input(focusPlaceholder('Header name'), style({width: '40%'}), changeHandlers),
			dom.div(style({width: '.5em'})),
			value=dom.input(focusPlaceholder('Header value'), style({flexGrow: 1}), changeHandlers),
			dom.div(
				style({width: '2.5em', paddingLeft: '.25em'}),
				dom.clickbutton('+', style({padding: '0 .25em'}), attr.arialabel('Add row for another header filter.'), attr.title('Add row for another header filter.'), function click() {
					addHeaderView()
				}),
				' ',
				first ? [] : dom.clickbutton('-', style({padding: '0 .25em'}), attr.arialabel('Remove row.'), attr.title('Remove row.'), function click() {
					root.remove()
					const index = headerViews.findIndex(v => v === hv)
					headerViews.splice(index, 1)
					updateSearchbar()
				}),
			),
		)
		const hv: HeaderView = {root: root, key: key, value: value}
		return hv
	}

	const addHeaderView = (): void => {
		const hv = newHeaderView(false)
		headersCell.appendChild(hv.root)
		headerViews.push(hv)
	}

	const setPeriod = (d: Date): void => {
		newestDate.value = ''
		newestTime.value = ''
		const pad0 = (v: number) => v <= 9 ? '0'+v : ''+v
		const dt = [d.getFullYear(), pad0(d.getMonth()+1), pad0(d.getDate())].join('-')
		const tm = ''+pad0(d.getHours())+':'+pad0(d.getMinutes())
		oldestDate.value = dt
		oldestTime.value = tm
		updateSearchbar()
	}

	const root = dom.div(
		style({position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.2)', zIndex: zindexes.compose}),
		function click(e: MouseEvent) {
			e.stopPropagation()
			searchViewClose()
		},
		function keyup(e: KeyboardEvent) {
			if (e.key === 'Escape') {
				e.stopPropagation()
				searchViewClose()
			}
		},
		dom.search(
			style({position: 'absolute', width: '50em', padding: '.5ex', backgroundColor: 'white', boxShadow: '0px 0px 20px rgba(0, 0, 0, 0.1)', borderRadius: '.15em'}),
			function click(e: MouseEvent) {
				e.stopPropagation()
			},
			// This is a separate form, inside the form with the overall search field because
			// when updating the form based on the parsed searchbar, we first need to reset it.
			form=dom.form(
				dom.table(dom._class('search'), style({width: '100%'}),
					dom.tr(
						dom.td(dom.label('Mailbox', attr.for('searchMailbox')), attr.title('Filter by mailbox, including children of the mailbox.')),
						dom.td(
							mailbox=dom.select(attr.id('searchMailbox'), style({width: '100%'}),
								dom.option('All mailboxes except Trash/Junk/Rejects', attr.value('-1')),
								dom.option('All mailboxes', attr.value('0')),
								changeHandlers,
							),
							dom.div(style({paddingTop: '.5ex'}), dom.label(mailboxkids=dom.input(attr.type('checkbox'), changeHandlers), ' Also search in mailboxes below the selected mailbox.')),
						),
					),
					dom.tr(
						dom.td(dom.label('Text', attr.for('searchWords'))),
						dom.td(
							words=dom.input(attr.id('searchWords'), attr.title('Filter by text, case-insensitive, substring match, not necessarily whole words.'), focusPlaceholder('word "exact match" -notword'), style({width: '100%'}), changeHandlers),
						),
					),
					dom.tr(
						dom.td(dom.label('From', attr.for('searchFrom'))),
						dom.td(
							from=dom.input(attr.id('searchFrom'), style({width: '100%'}), focusPlaceholder('Address or name'), newAddressComplete(), changeHandlers)
						),
					),
					dom.tr(
						dom.td(dom.label('To', attr.for('searchTo')), attr.title('Search on addressee, including Cc and Bcc headers.')),
						dom.td(
							to=dom.input(attr.id('searchTo'), focusPlaceholder('Address or name, also matches Cc and Bcc addresses'), style({width: '100%'}), newAddressComplete(), changeHandlers),
						),
					),
					dom.tr(
						dom.td(dom.label('Subject', attr.for('searchSubject'))),
						dom.td(
							subject=dom.input(attr.id('searchSubject'), style({width: '100%'}), focusPlaceholder('"exact match"'), changeHandlers)
						),
					),
					dom.tr(
						dom.td('Received between', style({whiteSpace: 'nowrap'})),
						dom.td(
							style({lineHeight: 2}),
							dom.div(
								oldestDate=dom.input(attr.type('date'), focusPlaceholder('2023-07-20'), changeHandlers),
								oldestTime=dom.input(attr.type('time'), focusPlaceholder('23:10'), changeHandlers),
								' ',
								dom.clickbutton('x', style({padding: '0 .3em'}), attr.arialabel('Clear start date.'), attr.title('Clear start date.'), function click() {
									oldestDate.value = ''
									oldestTime.value = ''
									updateSearchbar()
								}),
								' and ',
								newestDate=dom.input(attr.type('date'), focusPlaceholder('2023-07-20'), changeHandlers),
								newestTime=dom.input(attr.type('time'), focusPlaceholder('23:10'), changeHandlers),
								' ',
								dom.clickbutton('x', style({padding: '0 .3em'}), attr.arialabel('Clear end date.'), attr.title('Clear end date.'), function click() {
									newestDate.value = ''
									newestTime.value = ''
									updateSearchbar()
								}),
							),
							dom.div(
								dom.clickbutton('1 day', function click() {
									setPeriod(new Date(new Date().getTime() - 24*3600*1000))
								}),
								' ',
								dom.clickbutton('1 week', function click() {
									setPeriod(new Date(new Date().getTime() - 7*24*3600*1000))
								}),
								' ',
								dom.clickbutton('1 month', function click() {
									setPeriod(new Date(new Date().getTime() - 31*24*3600*1000))
								}),
								' ',
								dom.clickbutton('1 year', function click() {
									setPeriod(new Date(new Date().getTime() - 365*24*3600*1000))
								}),
							),
						),
					),
					dom.tr(
						dom.td('Attachments'),
						dom.td(
							dom.label(style({whiteSpace: 'nowrap'}), attachmentNone=dom.input(attr.type('radio'), attr.name('attachments'), attr.value('none'), attachmentHandlers), ' None'), ' ',
							dom.label(style({whiteSpace: 'nowrap'}), attachmentAny=dom.input(attr.type('radio'), attr.name('attachments'), attr.value('any'), attachmentHandlers), ' Any'), ' ',
							dom.label(style({whiteSpace: 'nowrap'}), attachmentImage=dom.input(attr.type('radio'), attr.name('attachments'), attr.value('image'), attachmentHandlers), ' Images'), ' ',
							dom.label(style({whiteSpace: 'nowrap'}), attachmentPDF=dom.input(attr.type('radio'), attr.name('attachments'), attr.value('pdf'), attachmentHandlers), ' PDFs'), ' ',
							dom.label(style({whiteSpace: 'nowrap'}), attachmentArchive=dom.input(attr.type('radio'), attr.name('attachments'), attr.value('archive'), attachmentHandlers), ' Archives'), ' ',
							dom.label(style({whiteSpace: 'nowrap'}), attachmentSpreadsheet=dom.input(attr.type('radio'), attr.name('attachments'), attr.value('spreadsheet'), attachmentHandlers), ' Spreadsheets'), ' ',
							dom.label(style({whiteSpace: 'nowrap'}), attachmentDocument=dom.input(attr.type('radio'), attr.name('attachments'), attr.value('document'), attachmentHandlers), ' Documents'), ' ',
							dom.label(style({whiteSpace: 'nowrap'}), attachmentPresentation=dom.input(attr.type('radio'), attr.name('attachments'), attr.value('presentation'), attachmentHandlers), ' Presentations'), ' ',
						),
					),
					dom.tr(
						dom.td('Labels'),
						dom.td(
							style({lineHeight: 2}),
							join(flagViews=Object.entries({Read: '\\Seen', Replied: '\\Answered', Flagged: '\\Flagged', Deleted: '\\Deleted', Draft: '\\Draft', Forwarded: '$Forwarded', Junk: '$Junk', NotJunk: '$NotJunk', Phishing: '$Phishing', MDNSent: '$MDNSent'}).map(t => {
								const [name, flag] = t
								const v: FlagView = {
									active: null,
									flag: flag,
									root: dom.clickbutton(name, function click() {
										if (v.active === null) {
											v.active = true
										} else if (v.active === true) {
											v.active = false
										} else {
											v.active = null
										}
										v.update()
										updateSearchbar()
									}),
									update: () => {
										v.root.style.backgroundColor = v.active === true ? '#c4ffa9' : (v.active === false ? '#ffb192' : '')
									},
								}
								return v
							}), () => ' '),
							' ',
							labels=dom.input(focusPlaceholder('todo -done "-dashingname"'), attr.title('User-defined labels.'), changeHandlers),
						),
					),
					dom.tr(
						dom.td('Headers'),
						headersCell=dom.td(headerViews=[newHeaderView(true)]),
					),
					dom.tr(
						dom.td('Size between'),
						dom.td(
							minsize=dom.input(style({width: '6em'}), focusPlaceholder('10kb'), changeHandlers),
							' and ',
							maxsize=dom.input(style({width: '6em'}), focusPlaceholder('1mb'), changeHandlers),
						),
					),
				),
				dom.div(
					style({padding: '1ex', textAlign: 'right'}),
					dom.submitbutton('Search'),
				),
				async function submit(e: SubmitEvent) {
					e.preventDefault()
					await searchView.submit()
				},
			),
		),
	)

	const submit = async (): Promise<void> => {
		const [f, notf, _] = parseSearch(searchbarElem.value, mailboxlistView)
		await startSearch(f, notf)
	}

	let loaded = false

	const searchView: SearchView = {
		root: root,
		submit: submit,
		ensureLoaded: () => {
			if (loaded || mailboxlistView.mailboxes().length === 0) {
				return
			}
			loaded = true
			dom._kids(mailbox,
				dom.option('All mailboxes except Trash/Junk/Rejects', attr.value('-1')),
				dom.option('All mailboxes', attr.value('0')),
				mailboxlistView.mailboxes().map(mb => dom.option(mb.Name, attr.value(''+mb.ID))),
			)
			searchView.updateForm()
		},
		updateForm: updateForm,
	}
	return searchView
}

// Functions we pass to various views, to access functionality encompassing all views.
type requestNewView = (clearMsgID: boolean, filterOpt?: api.Filter, notFilterOpt?: api.NotFilter) => Promise<void>
type updatePageTitle = () => void
type setLocationHash = () => void
type unloadSearch = () => void
type otherMailbox = (mailboxID: number) => api.Mailbox | null
type possibleLabels = () => string[]
type listMailboxes = () => api.Mailbox[]

const init = async () => {
	let connectionElem: HTMLElement // SSE connection status/error. Empty when connected.
	let layoutElem: HTMLSelectElement // Select dropdown for layout.

	let msglistscrollElem: HTMLElement
	let queryactivityElem: HTMLElement // We show ... when a query is active and data is forthcoming.

	// Shown at the bottom of msglistscrollElem, immediately below the msglistView, when appropriate.
	const listendElem = dom.div(style({borderTop: '1px solid #ccc', color: '#666', margin: '1ex'}))
	const listloadingElem = dom.div(style({textAlign: 'center', padding: '.15em 0', color: '#333', border: '1px solid #ccc', margin: '1ex', backgroundColor: '#f8f8f8'}), 'loading...')
	const listerrElem = dom.div(style({textAlign: 'center', padding: '.15em 0', color: '#333', border: '1px solid #ccc', margin: '1ex', backgroundColor: '#f8f8f8'}))

	let sseID = 0 // Sent by server in initial SSE response. We use it in API calls to make the SSE endpoint return new data we need.
	let viewSequence = 0 // Counter for assigning viewID.
	let viewID = 0 // Updated when a new view is started, e.g. when opening another mailbox or starting a search.
	let search = {
		active: false, // Whether a search is active.
		query: '', // The query, as shown in the searchbar. Used in location hash.
	}
	let requestSequence = 0 // Counter for assigning requestID.
	let requestID = 0 // Current request, server will mirror it in SSE data. If we get data for a different id, we ignore it.
	let requestAnchorMessageID = 0 // For pagination.
	let requestViewEnd = false // If true, there is no more data to fetch, no more page needed for this view.
	let requestFilter = newFilter()
	let requestNotFilter = newNotFilter()
	let requestMsgID = 0 // If > 0, we are still expecting a parsed message for the view, coming from the query. Either we get it and set msgitemViewActive and clear this, or we get to the end of the data and clear it.

	const updatePageTitle = () => {
		const mb = mailboxlistView && mailboxlistView.activeMailbox()
		const addr = loginAddress ? loginAddress.User+'@'+(loginAddress.Domain.Unicode || loginAddress.Domain.ASCII) : ''
		if (!mb) {
			document.title = [addr, 'Mox Webmail'].join(' - ')
		} else {
			document.title = ['('+mb.Unread+') '+mb.Name, addr, 'Mox Webmail'].join(' - ')
		}
	}

	const setLocationHash = () => {
		const msgid = requestMsgID || msglistView.activeMessageID()
		const msgidstr = msgid ? ','+msgid : ''
		let hash
		const mb = mailboxlistView && mailboxlistView.activeMailbox()
		if (mb) {
			hash = '#'+mb.Name + msgidstr
		} else if (search.active) {
			hash = '#search ' + search.query + msgidstr
		} else {
			hash = '#'
		}
		// We need to set the full URL or we would get errors about insecure operations for
		// plain http with firefox.
		const l = window.location
		const url = l.protocol + '//' + l.host + l.pathname + l.search + hash
		window.history.replaceState(undefined, '', url)
	}

	const loadSearch = (q: string) => {
		search = {active: true, query: q}
		searchbarElem.value = q
		searchbarElem.style.background = 'linear-gradient(135deg, #ffc7ab 0%, #ffdeab 100%)' // Cleared when another view is loaded.
		searchbarElemBox.style.flexGrow = '4'
	}
	const unloadSearch = () => {
		searchbarElem.value = ''
		searchbarElem.style.background = ''
		searchbarElem.style.zIndex = ''
		searchbarElemBox.style.flexGrow = '' // Make search bar smaller again.
		search = {active: false, query: ''}
		searchView.root.remove()
	}
	const clearList = () => {
		msglistView.clear()
		listendElem.remove()
		listloadingElem.remove()
		listerrElem.remove()
	}

	const requestNewView = async (clearMsgID: boolean, filterOpt?: api.Filter, notFilterOpt?: api.NotFilter) => {
		if (!sseID) {
			throw new Error('not connected')
		}

		if (clearMsgID) {
			requestMsgID = 0
		}

		msglistView.root.classList.toggle('loading', true)
		clearList()

		viewSequence++
		viewID = viewSequence
		if (filterOpt) {
			requestFilter = filterOpt
			requestNotFilter = notFilterOpt || newNotFilter()
		}

		requestAnchorMessageID = 0
		requestViewEnd = false
		const bounds = msglistscrollElem.getBoundingClientRect()
		await requestMessages(bounds, requestMsgID)
	}

	const requestMessages = async (scrollBounds: DOMRect, destMessageID: number) => {
		const fetchCount = Math.max(50, 3*Math.ceil(scrollBounds.height/msglistView.itemHeight()))
		const page = {
			AnchorMessageID: requestAnchorMessageID,
			Count: fetchCount,
			DestMessageID: destMessageID,
		}
		requestSequence++
		requestID = requestSequence
		const [f, notf] = refineFilters(requestFilter, requestNotFilter)
		const query = {
			OrderAsc: settings.orderAsc,
			Threading: settings.threading,
			Filter: f,
			NotFilter: notf,
		}
		const request = {
			ID: requestID,
			SSEID: sseID,
			ViewID: viewID,
			Cancel: false,
			Query: query,
			Page: page,
		}
		dom._kids(queryactivityElem, 'loading...')
		msglistscrollElem.appendChild(listloadingElem)
		await client.Request(request)
	}

	// msgElem can show a message, show actions on multiple messages, or be empty.
	let msgElem = dom.div(
		style({position: 'absolute', right: 0, left: 0, top: 0, bottom: 0}),
		style({backgroundColor: '#f8f8f8'}),
	)

	// Returns possible labels based, either from active mailbox (possibly from search), or all mailboxes.
	const possibleLabels = (): string[] => {
		if (requestFilter.MailboxID > 0) {
			const mb = mailboxlistView.findMailboxByID(requestFilter.MailboxID)
			if (mb) {
				return mb.Keywords || []
			}
		}
		const all: {[key: string]: undefined} = {}
		mailboxlistView.mailboxes().forEach(mb => {
			for (const k of (mb.Keywords || [])) {
				all[k] = undefined
			}
		})
		const l = Object.keys(all)
		l.sort()
		return l
	}

	const refineKeyword = async (kw: string) => {
		settingsPut({...settings, refine: 'label:'+kw})
		refineToggleActive(refineLabelBtn as HTMLButtonElement)
		dom._kids(refineLabelBtn, 'Label: '+kw)
		await withStatus('Requesting messages', requestNewView(false))
	}

	const viewportEnsureMessages = async () => {
		// We know how many entries we have, and how many screenfulls. So we know when we
		// only have 2 screen fulls left. That's when we request the next data.
		const bounds = msglistscrollElem.getBoundingClientRect()
		if (msglistscrollElem.scrollTop < msglistscrollElem.scrollHeight-3*bounds.height) {
			return
		}

		// log('new request for scroll')
		await withStatus('Requesting more messages', requestMessages(bounds, 0))
	}

	const otherMailbox = (mailboxID: number): api.Mailbox | null => requestFilter.MailboxID !== mailboxID ? (mailboxlistView.findMailboxByID(mailboxID) || null) : null
	const listMailboxes = () => mailboxlistView.mailboxes()
	const msglistView = newMsglistView(msgElem, listMailboxes, setLocationHash, otherMailbox, possibleLabels, () => msglistscrollElem ? msglistscrollElem.getBoundingClientRect().height : 0, refineKeyword, viewportEnsureMessages)
	const mailboxlistView = newMailboxlistView(msglistView, requestNewView, updatePageTitle, setLocationHash, unloadSearch, otherMailbox)

	let refineUnreadBtn: HTMLButtonElement, refineReadBtn: HTMLButtonElement, refineAttachmentsBtn: HTMLButtonElement, refineLabelBtn: HTMLButtonElement
	const refineToggleActive = (btn: HTMLButtonElement | null): void => {
		for (const e of [refineUnreadBtn, refineReadBtn, refineAttachmentsBtn, refineLabelBtn]) {
			e.classList.toggle('active', e === btn)
		}
		if (btn !== null && btn !== refineLabelBtn) {
			dom._kids(refineLabelBtn, 'Label')
		}
	}

	let threadMode: HTMLSelectElement

	let msglistElem = dom.div(dom._class('msglist'),
		style({position: 'absolute', left: '0', right: 0, top: 0, bottom: 0, display: 'flex', flexDirection: 'column'}),
		dom.div(
			attr.role('region'), attr.arialabel('Filter and sorting buttons for message list'),
			style({display: 'flex', justifyContent: 'space-between', backgroundColor: '#f8f8f8', borderBottom: '1px solid #ccc', padding: '.25em .5em'}),
			dom.div(
				dom.h1('Refine:', style({fontWeight: 'normal', fontSize: 'inherit', display: 'inline', margin: 0}), attr.title('Refine message listing with quick filters. These refinement filters are in addition to any search criteria, but the refine attachment filter overrides a search attachment criteria.')),
				' ',
				dom.span(dom._class('btngroup'),
					refineUnreadBtn=dom.clickbutton(settings.refine === 'unread' ? dom._class('active') : [],
						'Unread',
						attr.title('Only show messages marked as unread.'),
						async function click(e: MouseEvent) {
							settingsPut({...settings, refine: 'unread'})
							refineToggleActive(e.target! as HTMLButtonElement)
							await withStatus('Requesting messages', requestNewView(false))
						},
					),
					refineReadBtn=dom.clickbutton(settings.refine === 'read' ? dom._class('active') : [],
						'Read',
						attr.title('Only show messages marked as read.'),
						async function click(e: MouseEvent) {
							settingsPut({...settings, refine: 'read'})
							refineToggleActive(e.target! as HTMLButtonElement)
							await withStatus('Requesting messages', requestNewView(false))
						},
					),
					refineAttachmentsBtn=dom.clickbutton(settings.refine === 'attachments' ? dom._class('active') : [],
						'Attachments',
						attr.title('Only show messages with attachments.'),
						async function click(e: MouseEvent) {
							settingsPut({...settings, refine: 'attachments'})
							refineToggleActive(e.target! as HTMLButtonElement)
							await withStatus('Requesting messages', requestNewView(false))
						},
					),
					refineLabelBtn=dom.clickbutton(settings.refine.startsWith('label:') ? [dom._class('active'), 'Label: '+settings.refine.substring('label:'.length)] : 'Label',
						attr.title('Only show messages with the selected label.'),
						async function click(e: MouseEvent) {
							const labels = possibleLabels()
							const remove = popover(e.target! as HTMLElement, {},
								dom.div(
									style({display: 'flex', flexDirection: 'column', gap: '1ex'}),
									labels.map(l => {
										const selectLabel = async () => {
											settingsPut({...settings, refine: 'label:'+l})
											refineToggleActive(e.target! as HTMLButtonElement)
											dom._kids(refineLabelBtn, 'Label: '+l)
											await withStatus('Requesting messages', requestNewView(false))
											remove()
										}
										return dom.div(
											dom.clickbutton(dom._class('keyword'), l, async function click() {
												await selectLabel()
											}),
										)
									}),
									labels.length === 0 ? dom.div('No labels yet, set one on a message first.') : [],
								)
							)
						},
					),
				),
				' ',
				dom.clickbutton(
					'x',
					style({padding: '0 .25em'}),
					attr.arialabel('Clear refinement filters.'),
					attr.title('Clear refinement filters.'),
					async function click(e: MouseEvent) {
						settingsPut({...settings, refine: ''})
						refineToggleActive(e.target! as HTMLButtonElement)
						await withStatus('Requesting messages', requestNewView(false))
					},
				),
			),
			dom.div(
				queryactivityElem=dom.span(),
				' ',
				threadMode=dom.select(
					attr.arialabel('Thread modes.'),
					attr.title('Off: Threading disabled, messages are shown individually.\nOn: Group messages in threads, expanded by default except when (previously) manually collapsed.\nUnread: Only expand thread with unread messages, ignoring and not saving whether they were manually collapsed.'),
					dom.option('Threads: Off', attr.value(api.ThreadMode.ThreadOff), settings.threading === api.ThreadMode.ThreadOff ? attr.selected('') : []),
					dom.option('Threads: On', attr.value(api.ThreadMode.ThreadOn), settings.threading === api.ThreadMode.ThreadOn ? attr.selected('') : []),
					dom.option('Threads: Unread', attr.value(api.ThreadMode.ThreadUnread), settings.threading === api.ThreadMode.ThreadUnread ? attr.selected('') : []),
					async function change() {
						let reset = settings.threading === api.ThreadMode.ThreadOff
						settingsPut({...settings, threading: threadMode.value as api.ThreadMode})
						reset = reset || settings.threading === api.ThreadMode.ThreadOff
						if (reset) {
							await withStatus('Requesting messages', requestNewView(false))
						} else {
							msglistView.threadToggle()
						}
					},
				),
				' ',
				dom.clickbutton('↑↓', attr.title('Toggle sorting by date received.'), settings.orderAsc ? dom._class('invert') : [], async function click(e: MouseEvent) {
					settingsPut({...settings, orderAsc: !settings.orderAsc})
					;(e.target! as HTMLButtonElement).classList.toggle('invert', settings.orderAsc)
					// We don't want to include the currently selected message because it could cause a
					// huge amount of messages to be fetched. e.g. when first message in large mailbox
					// was selected, it would now be the last message.
					await withStatus('Requesting messages', requestNewView(true))
				}),
			),
		),
		dom.div(
			style({height: '1ex', position: 'relative'}),
			dom.div(dom._class('msgitemflags')),
			dom.div(dom._class('msgitemflagsoffset'), style({position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize'}),
				dom.div(style({position: 'absolute', top: 0, bottom: 0, width: '1px', backgroundColor: '#aaa', left: '2.5px'})),
				function mousedown(e: MouseEvent) {
					startDrag(e, (e) => {
						const bounds = msglistscrollElem.getBoundingClientRect()
						const width = Math.round(e.clientX - bounds.x)
						settingsPut({...settings, msglistflagsWidth: width})
						updateMsglistWidths()
					})
				}
			),
			dom.div(dom._class('msgitemfrom')),
			dom.div(dom._class('msgitemfromoffset'), style({position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize'}),
				dom.div(style({position: 'absolute', top: 0, bottom: 0, width: '1px', backgroundColor: '#aaa', left: '2.5px'})),
				function mousedown(e: MouseEvent) {
					startDrag(e, (e) => {
						const bounds = msglistscrollElem.getBoundingClientRect()
						const x = Math.round(e.clientX - bounds.x - lastflagswidth)
						const width = bounds.width - lastflagswidth - lastagewidth
						const pct = 100*x/width
						settingsPut({...settings, msglistfromPct: pct})
						updateMsglistWidths()
					})
				}
			),
			dom.div(dom._class('msgitemsubject')),
			dom.div(dom._class('msgitemsubjectoffset'), style({position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize'}),
				dom.div(style({position: 'absolute', top: 0, bottom: 0, width: '1px', backgroundColor: '#aaa', left: '2.5px'})),
				function mousedown(e: MouseEvent) {
					startDrag(e, (e) => {
						const bounds = msglistscrollElem.getBoundingClientRect()
						const width = Math.round(bounds.x+bounds.width - e.clientX)
						settingsPut({...settings, msglistageWidth: width})
						updateMsglistWidths()
					})
				}
			),
			dom.div(dom._class('msgitemage')),
		),
		dom.div(
			style({flexGrow: '1', position: 'relative'}),
			msglistscrollElem=dom.div(dom._class('yscroll'),
				attr.role('region'), attr.arialabel('Message list'),
				async function scroll() {
					if (!sseID || requestViewEnd || requestID) {
						return
					}

					await viewportEnsureMessages()
				},
				dom.div(
					style({width: '100%', borderSpacing: '0'}),
					msglistView,
				),
			),
		),
	)

	let searchbarElem: HTMLInputElement // Input field for search

	// Called by searchView when user executes the search.
	const startSearch = async (f: api.Filter, notf: api.NotFilter): Promise<void> => {
		if (!sseID) {
			window.alert('Error: not connect')
			return
		}

		// If search has an attachment filter, clear it from the quick filter or we will
		// confuse the user with no matches. The refinement would override the selection.
		if (f.Attachments !== '' && settings.refine === 'attachments') {
			settingsPut({...settings, refine: ''})
			refineToggleActive(null)
		}
		search = {active: true, query: searchbarElem.value}
		mailboxlistView.closeMailbox()
		setLocationHash()
		searchbarElem.style.background = 'linear-gradient(135deg, #ffc7ab 0%, #ffdeab 100%)' // Cleared when another view is loaded.
		searchView.root.remove()
		searchbarElem.blur()
		document.body.focus()
		await withStatus('Requesting messages', requestNewView(true, f, notf))
	}

	// Called by searchView when it is closed, due to escape key or click on background.
	const searchViewClose = () => {
		if (!search.active) {
			unloadSearch()
		} else {
			searchbarElem.value = search.query
			searchView.root.remove()
		}
	}

	// For dragging.
	let mailboxesElem: HTMLElement, topcomposeboxElem: HTMLElement, mailboxessplitElem: HTMLElement
	let splitElem: HTMLElement

	let searchbarElemBox: HTMLElement // Detailed search form, opened when searchbarElem gets focused.

	const searchbarInitial = () => {
		const mailboxActive = mailboxlistView.activeMailbox()
		if (mailboxActive && mailboxActive.Name !== 'Inbox') {
			return packToken([false, 'mb', false, mailboxActive.Name]) + ' '
		}
		return ''
	}

	const ensureSearchView = () => {
		if (searchView.root.parentElement) {
			// Already open.
			return
		}
		searchView.ensureLoaded()
		const pos = searchbarElem.getBoundingClientRect()
		const child = searchView.root.firstChild! as HTMLElement
		child.style.left = ''+pos.x+'px'
		child.style.top = ''+(pos.y+pos.height+2)+'px'
		// Append to just after search input so next tabindex is at form.
		searchbarElem.parentElement!.appendChild(searchView.root)

		// Make search bar as wide as possible. Made smaller when searchView is hidden again.
		searchbarElemBox.style.flexGrow = '4'

		searchbarElem.style.zIndex = zindexes.searchbar
	}

	const cmdSearch = async () => {
		searchbarElem.focus()
		if (!searchbarElem.value) {
			searchbarElem.value = searchbarInitial()
		}
		ensureSearchView()
		searchView.updateForm()
	}

	const cmdCompose = async () => { compose({}) }
	const cmdOpenInbox = async () => {
		const mb = mailboxlistView.findMailboxByName('Inbox')
		if (mb) {
			await mailboxlistView.openMailboxID(mb.ID, true)
			const f = newFilter()
			f.MailboxID = mb.ID
			await withStatus('Requesting messages', requestNewView(true, f, newNotFilter()))
		}
	}
	const cmdFocusMsg = async() => {
		const btn = msgElem.querySelector('button')
		if (btn && btn instanceof HTMLElement) {
			btn.focus()
		}
	}

	const shortcuts: {[key: string]: command} = {
		i: cmdOpenInbox,
		'/': cmdSearch,
		'?': cmdHelp,
		'ctrl ?': cmdTooltip,
		c: cmdCompose,
		'ctrl m': cmdFocusMsg,
	}

	const webmailroot = dom.div(
		style({display: 'flex', flexDirection: 'column', alignContent: 'stretch', height: '100dvh'}),
		dom.div(dom._class('topbar'),
			style({display: 'flex'}),
			attr.role('region'), attr.arialabel('Top bar'),
			topcomposeboxElem=dom.div(dom._class('pad'),
				style({width: settings.mailboxesWidth + 'px', textAlign: 'center'}),
				dom.clickbutton('Compose', attr.title('Compose new email message.'), function click() {
					shortcutCmd(cmdCompose, shortcuts)
				}),
			),
			dom.div(dom._class('pad'),
				style({paddingLeft: 0, display: 'flex', flexGrow: 1}),
				searchbarElemBox=dom.search(
					style({display: 'flex', marginRight: '.5em'}),
					dom.form(
						style({display: 'flex', flexGrow: 1}),
						searchbarElem=dom.input(
							attr.placeholder('Search...'),
							style({position: 'relative', width: '100%'}),
							attr.title('Search messages based on criteria like matching free-form text, in a mailbox, labels, addressees.'),
							focusPlaceholder('word "with space" -notword mb:Inbox f:from@x.example t:rcpt@x.example start:2023-7-1 end:2023-7-8 s:"subject" a:images l:$Forwarded h:Reply-To:other@x.example minsize:500kb'),
							function click() {
								cmdSearch()
								showShortcut('/')
							},
							function focus() {
								// Make search bar as wide as possible. Made smaller when searchView is hidden again.
								searchbarElemBox.style.flexGrow = '4'
								if (!searchbarElem.value) {
									searchbarElem.value = searchbarInitial()
								}
							},
							function blur() {
								if (searchbarElem.value === searchbarInitial()) {
									searchbarElem.value = ''
								}
								if (!search.active) {
									searchbarElemBox.style.flexGrow = ''
								}
							},
							function change() {
								searchView.updateForm()
							},
							function keyup(e: KeyboardEvent) {
								if (e.key === 'Escape') {
									e.stopPropagation()
									searchViewClose()
									return
								}
								if (searchbarElem.value && searchbarElem.value !== searchbarInitial()) {
									ensureSearchView()
								}
								searchView.updateForm()
							},
						),
						dom.clickbutton('x',
							attr.arialabel('Cancel and clear search and open Inbox.'),
							attr.title('Cancel and clear search and open Inbox.'),
							style({marginLeft: '.25em', padding: '0 .3em'}),
							async function click() {
								searchbarElem.value = ''
								if (!search.active) {
									return
								}

								const mb = mailboxlistView.findMailboxByName('Inbox')
								if (!mb) {
									window.alert('Cannot find inbox.')
									return
								}
								await mailboxlistView.openMailboxID(mb.ID, true)
								const f = newFilter()
								f.MailboxID = mb.ID
								await withStatus('Requesting messages', requestNewView(true, f, newNotFilter()))
							},
						),
						async function submit(e: SubmitEvent) {
							e.preventDefault()
							await searchView.submit()
						},
					),
				),
				connectionElem=dom.div(),
				statusElem=dom.div(style({marginLeft: '.5em', flexGrow: '1'}), attr.role('status')),
				dom.div(
					style({paddingLeft: '1em'}),
					layoutElem=dom.select(
						attr.title('Layout of message list and message panes. Top/bottom has message list above message view. Left/Right has message list left, message view right. Auto selects based on window width and automatically switches on resize. Wide screens get left/right, smaller screens get top/bottom.'),
						dom.option('Auto layout', attr.value('auto'), settings.layout === 'auto' ? attr.selected('') : []),
						dom.option('Top/bottom', attr.value('topbottom'), settings.layout === 'topbottom' ? attr.selected('') : []),
						dom.option('Left/right', attr.value('leftright'), settings.layout === 'leftright' ? attr.selected('') : []),
						function change() {
							settingsPut({...settings, layout: layoutElem.value})
							if (layoutElem.value === 'auto') {
								autoselectLayout()
							} else {
								selectLayout(layoutElem.value)
							}
						},
					), ' ',
					dom.clickbutton('Tooltip', attr.title('Show tooltips, based on the title attributes (underdotted text) for the focused element and all user interface elements below it. Use the keyboard shortcut "ctrl ?" instead of clicking on the tooltip button, which changes focus to the tooltip button.'), clickCmd(cmdTooltip, shortcuts)),
					' ',
					dom.clickbutton('Help', attr.title('Show popup with basic usage information and a keyboard shortcuts.'), clickCmd(cmdHelp, shortcuts)),
					' ',
					link('https://github.com/mjl-/mox', 'mox'),
				),
			),
		),
		dom.div(
			style({flexGrow: '1'}),
			style({position: 'relative'}),
			mailboxesElem=dom.div(dom._class('mailboxesbar'),
				style({position: 'absolute', left: 0, width: settings.mailboxesWidth + 'px', top: 0, bottom: 0}),
				style({display: 'flex', flexDirection: 'column', alignContent: 'stretch'}),
				dom.div(dom._class('pad', 'yscrollauto'),
					style({flexGrow: '1'}),
					style({position: 'relative'}),
					mailboxlistView.root,
				),
			),
			mailboxessplitElem=dom.div(
				style({position: 'absolute', left: 'calc('+settings.mailboxesWidth +'px - 2px)', width: '5px', top: 0, bottom: 0, cursor: 'ew-resize', zIndex: zindexes.splitter}),
				dom.div(
					style({position: 'absolute', width: '1px', top: 0, bottom: 0, left: '2px', right: '2px', backgroundColor: '#aaa'}),
				),
				function mousedown(e: MouseEvent) {
					startDrag(e, (e) => {
						mailboxesElem.style.width = Math.round(e.clientX)+'px'
						topcomposeboxElem.style.width = Math.round(e.clientX)+'px'
						mailboxessplitElem.style.left = 'calc('+e.clientX+'px - 2px)'
						splitElem.style.left = 'calc('+e.clientX+'px + 1px)'
						settingsPut({...settings, mailboxesWidth: Math.round(e.clientX)})
					})
				}
			),
			splitElem=dom.div(style({position: 'absolute', left: 'calc(' + settings.mailboxesWidth+'px + 1px)', right: 0, top: 0, bottom: 0, borderTop: '1px solid #bbb'})),
		),
	)

	// searchView is shown when search gets focus.
	const searchView = newSearchView(searchbarElem, mailboxlistView, startSearch, searchViewClose)

	document.body.addEventListener('keydown', async (e: KeyboardEvent) => {
		// Don't do anything for just the press of the modifiers.
		switch (e.key) {
		case 'OS':
		case 'Control':
		case 'Shift':
		case 'Alt':
			return
		}

		// Popup have their own handlers, e.g. for scrolling.
		if (popupOpen) {
			return
		}

		// Prevent many regular key presses from being processed, some possibly unintended.
		if ((e.target instanceof window.HTMLInputElement || e.target instanceof window.HTMLTextAreaElement || e.target instanceof window.HTMLSelectElement) && !e.ctrlKey && !e.altKey && !e.metaKey) {
			// log('skipping key without modifiers on input/textarea')
			return
		}
		let l = []
		if (e.ctrlKey) {
			l.push('ctrl')
		}
		if (e.altKey) {
			l.push('alt')
		}
		if (e.metaKey) {
			l.push('meta')
		}
		l.push(e.key)
		const k = l.join(' ')

		if (attachmentView) {
			attachmentView.key(k, e)
			return
		}
		if (composeView) {
			await composeView.key(k, e)
			return
		}
		const cmdfn = shortcuts[k]
		if (cmdfn) {
			e.preventDefault()
			e.stopPropagation()
			await cmdfn()
			return
		}
		msglistView.key(k, e)
	})

	let currentLayout: string = ''

	const selectLayout = (want: string) => {
		if (want === currentLayout) {
			return
		}

		if (want === 'leftright') {
			let left: HTMLElement, split: HTMLElement, right: HTMLElement
			dom._kids(splitElem,
				left=dom.div(
					style({position: 'absolute', left: 0, width: 'calc(' + settings.leftWidthPct + '% - 1px)', top: 0, bottom: 0}),
					msglistElem,
				),
				split=dom.div(
					style({position: 'absolute', left: 'calc(' + settings.leftWidthPct + '% - 2px)', width: '5px', top: 0, bottom: 0, cursor: 'ew-resize', zIndex: zindexes.splitter}),
					dom.div(style({position: 'absolute', backgroundColor: '#aaa', top: 0, bottom: 0, width: '1px', left: '2px', right: '2px'})),
					function mousedown(e: MouseEvent) {
						startDrag(e, (e) => {
							const bounds = left.getBoundingClientRect()
							const x = Math.round(e.clientX - bounds.x)
							left.style.width = 'calc(' + x +'px - 1px)'
							split.style.left = 'calc(' + x +'px - 2px)'
							right.style.left = 'calc(' + x+'px + 1px)'
							settingsPut({...settings, leftWidthPct: Math.round(100*bounds.width/splitElem.getBoundingClientRect().width)})
							updateMsglistWidths()
						})
					}
				),
				right=dom.div(
					style({position: 'absolute', right: 0, left: 'calc(' + settings.leftWidthPct + '% + 1px)', top: 0, bottom: 0}),
					msgElem,
				),
			)
		} else {
			let top: HTMLElement, split: HTMLElement, bottom: HTMLElement
			dom._kids(splitElem,
				top=dom.div(
					style({position: 'absolute', top: 0, height: 'calc(' + settings.topHeightPct + '% - 1px)', left: 0, right: 0}),
					msglistElem,
				),
				split=dom.div(
					style({position: 'absolute', top: 'calc(' + settings.topHeightPct + '% - 2px)', height: '5px', left: '0', right: '0', cursor: 'ns-resize', zIndex: zindexes.splitter}),
					dom.div(style({position: 'absolute', backgroundColor: '#aaa', left: 0, right: 0, height: '1px', top: '2px', bottom: '2px'})),
					function mousedown(e: MouseEvent) {
						startDrag(e, (e) => {
							const bounds = top.getBoundingClientRect()
							const y = Math.round(e.clientY - bounds.y)
							top.style.height = 'calc(' + y + 'px - 1px)'
							split.style.top = 'calc(' + y + 'px - 2px)'
							bottom.style.top = 'calc(' + y +'px + 1px)'
							settingsPut({...settings, topHeightPct: Math.round(100*bounds.height/splitElem.getBoundingClientRect().height)})
						})
					}
				),
				bottom=dom.div(
					style({position: 'absolute', bottom: 0, top: 'calc(' + settings.topHeightPct + '% + 1px)', left: 0, right: 0}),
					msgElem,
				),
			)
		}
		currentLayout = want
		checkMsglistWidth()
	}

	const autoselectLayout = () => {
		const want = window.innerWidth <= 2*2560/3 ? 'topbottom' : 'leftright'
		selectLayout(want)
	}

	// When the window size or layout changes, we recalculate the desired widths for
	// the msglist "table". It is a list of divs, each with flex layout with 4 elements
	// of fixed size.
	// Cannot use the CSSStyleSheet constructor with its replaceSync method because
	// safari only started implementing it in 2023q1. So we do it the old-fashioned
	// way, inserting a style element and updating its style.
	const styleElem = dom.style(attr.type('text/css'))
	document.head.appendChild(styleElem)
	const stylesheet = styleElem.sheet!

	let lastmsglistwidth = -1
	const checkMsglistWidth = () => {
		const width = msglistscrollElem.getBoundingClientRect().width
		if (lastmsglistwidth === width || width <= 0) {
			return
		}

		updateMsglistWidths()
	}
	let lastflagswidth: number, lastagewidth: number
	let rulesInserted = false
	const updateMsglistWidths = () => {
		const width = msglistscrollElem.clientWidth - 2 // Borders.
		lastmsglistwidth = width

		let flagswidth = settings.msglistflagsWidth
		let agewidth = settings.msglistageWidth
		let frompct = settings.msglistfromPct // Of remaining space.
		if (flagswidth + agewidth > width) {
			flagswidth = Math.floor(width/2)
			agewidth = width-flagswidth
		}
		const remain = width - (flagswidth+agewidth)
		const fromwidth = Math.floor(frompct * remain / 100)
		const subjectwidth = Math.floor(remain - fromwidth)
		const cssRules: [string, {[style: string]: number}][] = [
			['.msgitemflags', {width: flagswidth}],
			['.msgitemfrom', {width: fromwidth}],
			['.msgitemsubject', {width: subjectwidth}],
			['.msgitemage', {width: agewidth}],
			['.msgitemflagsoffset', {left: flagswidth}],
			['.msgitemfromoffset', {left: flagswidth + fromwidth}],
			['.msgitemsubjectoffset', {left: flagswidth + fromwidth + subjectwidth}],
		]
		if (!rulesInserted) {
			cssRules.forEach((rule, i) => { stylesheet.insertRule(rule[0] + '{}', i) })
			rulesInserted = true
		}
		cssRules.forEach((rule, i) => {
			const r = stylesheet.cssRules[i] as CSSStyleRule
			for (const k in rule[1]) {
				r.style.setProperty(k, ''+rule[1][k]+'px')
			}
		})
		lastflagswidth = flagswidth
		lastagewidth = agewidth
	}

	// Select initial layout.
	if (layoutElem.value === 'auto') {
		autoselectLayout()
	} else {
		selectLayout(layoutElem.value)
	}
	dom._kids(page, webmailroot)
	checkMsglistWidth()

	window.addEventListener('resize', function() {
		if (layoutElem.value === 'auto') {
			autoselectLayout()
		}
		checkMsglistWidth()
	})

	window.addEventListener('hashchange', async () => {
		const [search, msgid, f, notf] = parseLocationHash(mailboxlistView)

		requestMsgID = msgid
		if (search) {
			mailboxlistView.closeMailbox()
			loadSearch(search)
		} else {
			unloadSearch()
			await mailboxlistView.openMailboxID(f.MailboxID, false)
		}
		await withStatus('Requesting messages', requestNewView(false, f, notf))
	})


	let eventSource: EventSource | null = null // If set, we have a connection.
	let connecting = false // Check before reconnecting.
	let noreconnect = false // Set after one reconnect attempt fails.
	let noreconnectTimer = 0 // Timer ID for resetting noreconnect.

	// Don't show disconnection just before user navigates away.
	let leaving = false
	window.addEventListener('beforeunload', () => {
		leaving = true
		if (eventSource) {
			eventSource.close()
			eventSource = null
			sseID = 0
		}
	})

	// On chromium, we may get restored when user hits the back button ("bfcache"). We
	// have left, closed the connection, so we should restore it.
	window.addEventListener('pageshow', async (e: PageTransitionEvent) => {
		if (e.persisted && !eventSource && !connecting) {
			noreconnect = false
			connect(false)
		}
	})

	// If user comes back to tab/window, and we are disconnected, try another reconnect.
	window.addEventListener('focus', () => {
		if (!eventSource && !connecting) {
			noreconnect = false
			connect(true)
		}
	})

	const showNotConnected = () => {
		dom._kids(connectionElem,
			attr.role('status'),
			dom.span(style({backgroundColor: '#ffa9a9', padding: '0 .15em', borderRadius: '.15em'}), 'Not connected', attr.title('Not receiving real-time updates, including of new deliveries.')),
			' ',
			dom.clickbutton('Reconnect', function click() {
				if (!eventSource && !connecting) {
					noreconnect = false
					connect(true)
				}
			}),
		)
	}

	const capitalizeFirst = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

	const connect = async (isreconnect: boolean) => {
		connectionElem.classList.toggle('loading', true)
		dom._kids(connectionElem)
		connectionElem.classList.toggle('loading', false)

		// We'll clear noreconnect when we've held a connection for 10 mins.
		noreconnect = isreconnect
		connecting = true

		let token: string
		try {
			token = await withStatus('Fetching token for connection with real-time updates', client.Token(), undefined, true)
		} catch (err) {
			connecting = false
			noreconnect = true
			dom._kids(statusElem, (capitalizeFirst((err as any).message || 'Error fetching connection token'))+', not automatically retrying. ')
			showNotConnected()
			return
		}

		let [searchQuery, msgid, f, notf] = parseLocationHash(mailboxlistView)
		requestMsgID = msgid
		requestFilter = f
		requestNotFilter = notf
		if (searchQuery) {
			loadSearch(searchQuery)
		}
		[f, notf] = refineFilters(requestFilter, requestNotFilter)
		const fetchCount = Math.max(50, 3*Math.ceil(msglistscrollElem.getBoundingClientRect().height/msglistView.itemHeight()))
		const query = {
			OrderAsc: settings.orderAsc,
			Threading: settings.threading,
			Filter: f,
			NotFilter: notf,
		}
		const page = {
			AnchorMessageID: 0,
			Count: fetchCount,
			DestMessageID: msgid,
		}

		viewSequence++
		viewID = viewSequence

		// We get an implicit query for the automatically selected mailbox or query.
		requestSequence++
		requestID = requestSequence
		requestAnchorMessageID = 0
		requestViewEnd = false
		clearList()

		const request = {
			ID: requestID,
			// A new SSEID is created by the server, sent in the initial response message.
			ViewID: viewID,
			Query: query,
			Page: page,
		}

		let slow = ''
		try {
			const debug = JSON.parse(localStorage.getItem('sherpats-debug') || 'null')
			if (debug && debug.waitMinMsec && debug.waitMaxMsec) {
				slow = '&waitMinMsec='+debug.waitMinMsec + '&waitMaxMsec='+debug.waitMaxMsec
			}
		} catch (err) {}

		eventSource = new window.EventSource('events?token=' + encodeURIComponent(token)+'&request='+encodeURIComponent(JSON.stringify(request))+slow)
		let eventID = window.setTimeout(() => dom._kids(statusElem, 'Connecting... '), 1000)
		eventSource.addEventListener('open', (e: Event) => {
			log('eventsource open', {e})
			if (eventID) {
				window.clearTimeout(eventID)
				eventID = 0
			}
			dom._kids(statusElem)
			dom._kids(connectionElem)
		})

		const sseError = (errmsg: string) => {
			sseID = 0
			eventSource!.close()
			eventSource = null
			connecting = false
			if (noreconnectTimer) {
				clearTimeout(noreconnectTimer)
				noreconnectTimer = 0
			}
			if (leaving) {
				return
			}
			if (eventID) {
				window.clearTimeout(eventID)
				eventID = 0
			}
			document.title = ['(not connected)', loginAddress ? (loginAddress.User+'@'+(loginAddress.Domain.Unicode || loginAddress.Domain.ASCII)) : '', 'Mox Webmail'].filter(s => s).join(' - ')
			dom._kids(connectionElem)
			if (noreconnect) {
				dom._kids(statusElem, capitalizeFirst(errmsg)+', not automatically retrying. ')
				showNotConnected()
				listloadingElem.remove()
				listendElem.remove()
			} else {
				connect(true)
			}
		}
		// EventSource-connection error. No details.
		eventSource.addEventListener('error', (e: Event) => {
			log('eventsource error', {e}, JSON.stringify(e))
			sseError('Connection failed')
		})
		// Fatal error on the server side, error message propagated, but connection needs to be closed.
		eventSource.addEventListener('fatalErr', (e: MessageEvent) => {
			const errmsg = JSON.parse(e.data) as string || '(no error message)'
			sseError('Server error: "' + errmsg + '"')
		})

		const checkParse = <T>(fn: () => T): T => {
			try {
				return fn()
			} catch (err) {
				window.alert('invalid event from server: ' + ((err as any).message || '(no message)'))
				throw err
			}
		}

		eventSource.addEventListener('start', (e: MessageEvent) => {
			const start = checkParse(() => api.parser.EventStart(JSON.parse(e.data)))
			log('event start', start)

			connecting = false
			sseID = start.SSEID
			loginAddress = start.LoginAddress
			const loginAddr = formatEmailASCII(loginAddress)
			accountAddresses = start.Addresses || []
			accountAddresses.sort((a, b) => {
				if (formatEmailASCII(a) === loginAddr) {
					return -1
				}
				if (formatEmailASCII(b) === loginAddr) {
					return 1
				}
				if (a.Domain.ASCII !== b.Domain.ASCII) {
					return a.Domain.ASCII < b.Domain.ASCII ? -1 : 1
				}
				return a.User < b.User ? -1 : 1
			})
			domainAddressConfigs = start.DomainAddressConfigs || {}

			clearList()

			let mailboxName = start.MailboxName
			let mb = (start.Mailboxes || []).find(mb => mb.Name === start.MailboxName)
			if (mb) {
				requestFilter.MailboxID = mb.ID // For check to display mailboxname in msgitemView.
			}
			if (mailboxName === '') {
				mailboxName = (start.Mailboxes || []).find(mb => mb.ID === requestFilter.MailboxID)?.Name || ''
			}
			mailboxlistView.loadMailboxes(start.Mailboxes || [], search.active ? undefined : mailboxName)
			if (searchView.root.parentElement) {
				searchView.ensureLoaded()
			}

			if (!mb) {
				updatePageTitle()
			}
			dom._kids(queryactivityElem, 'loading...')
			msglistscrollElem.appendChild(listloadingElem)

			noreconnectTimer = setTimeout(() => {
				noreconnect = false
				noreconnectTimer = 0
			}, 10*60*1000)
		})
		eventSource.addEventListener('viewErr', async (e: MessageEvent) => {
			const viewErr = checkParse(() => api.parser.EventViewErr(JSON.parse(e.data)))
			log('event viewErr', viewErr)
			if (viewErr.ViewID !== viewID || viewErr.RequestID !== requestID) {
				log('received viewErr for other viewID or requestID', {expected: {viewID, requestID}, got: {viewID: viewErr.ViewID, requestID: viewErr.RequestID}})
				return
			}

			viewID = 0
			requestID = 0

			dom._kids(queryactivityElem)
			listloadingElem.remove()
			listerrElem.remove()
			dom._kids(listerrElem, 'Error from server during request for messages: '+viewErr.Err)
			msglistscrollElem.appendChild(listerrElem)
			window.alert('Error from server during request for messages: '+viewErr.Err)
		})
		eventSource.addEventListener('viewReset', async (e: MessageEvent) => {
			const viewReset = checkParse(() => api.parser.EventViewReset(JSON.parse(e.data)))
			log('event viewReset', viewReset)
			if (viewReset.ViewID !== viewID || viewReset.RequestID !== requestID) {
				log('received viewReset for other viewID or requestID', {expected: {viewID, requestID}, got: {viewID: viewReset.ViewID, requestID: viewReset.RequestID}})
				return
			}

			clearList()
			dom._kids(queryactivityElem, 'loading...')
			msglistscrollElem.appendChild(listloadingElem)
			window.alert('Could not find message to continue scrolling, resetting the view.')
		})
		eventSource.addEventListener('viewMsgs', async (e: MessageEvent) => {
			const viewMsgs = checkParse(() => api.parser.EventViewMsgs(JSON.parse(e.data)))
			log('event viewMsgs', viewMsgs)
			if (viewMsgs.ViewID !== viewID || viewMsgs.RequestID !== requestID) {
				log('received viewMsgs for other viewID or requestID', {expected: {viewID, requestID}, got: {viewID: viewMsgs.ViewID, requestID: viewMsgs.RequestID}})
				return
			}

			msglistView.root.classList.toggle('loading', false)
			if (viewMsgs.MessageItems) {
				msglistView.addMessageItems(viewMsgs.MessageItems || [], false, requestMsgID)
			}

			if (viewMsgs.ParsedMessage) {
				const ok = msglistView.openMessage(viewMsgs.ParsedMessage)
				if (!ok) {
					// Should not happen, server would be sending a parsedmessage while not including the message itself.
					requestMsgID = 0
					setLocationHash()
				}
			}

			if (viewMsgs.MessageItems && viewMsgs.MessageItems.length > 0) {
				requestAnchorMessageID = viewMsgs.MessageItems[viewMsgs.MessageItems.length-1]![0]!.Message.ID
			}
			requestViewEnd = viewMsgs.ViewEnd
			if (requestViewEnd) {
				msglistscrollElem.appendChild(listendElem)
			}
			if ((viewMsgs.MessageItems || []).length === 0 || requestViewEnd) {
				dom._kids(queryactivityElem)
				listloadingElem.remove()
				requestID = 0
				if (requestMsgID) {
					requestMsgID = 0
					setLocationHash()
				}
			}
		})
		eventSource.addEventListener('viewChanges', async (e: MessageEvent) => {
			const viewChanges = checkParse(() => api.parser.EventViewChanges(JSON.parse(e.data)))
			log('event viewChanges', viewChanges)
			if (viewChanges.ViewID !== viewID) {
				log('received viewChanges for other viewID', {expected: viewID, got: viewChanges.ViewID})
				return
			}

			try {
				(viewChanges.Changes || []).forEach(tc => {
					if (!tc) {
						return
					}
					const [tag, x] = tc
					if (tag === 'ChangeMailboxCounts') {
						const c = api.parser.ChangeMailboxCounts(x)
						mailboxlistView.setMailboxCounts(c.MailboxID, c.Total, c.Unread)
					} else if (tag === 'ChangeMailboxSpecialUse') {
						const c = api.parser.ChangeMailboxSpecialUse(x)
						mailboxlistView.setMailboxSpecialUse(c.MailboxID, c.SpecialUse)
					} else if (tag === 'ChangeMailboxKeywords') {
						const c = api.parser.ChangeMailboxKeywords(x)
						mailboxlistView.setMailboxKeywords(c.MailboxID, c.Keywords || [])
					} else if (tag === 'ChangeMsgAdd') {
						const c = api.parser.ChangeMsgAdd(x)
						msglistView.addMessageItems([c.MessageItems || []], true, 0)
					} else if (tag === 'ChangeMsgRemove') {
						const c = api.parser.ChangeMsgRemove(x)
						msglistView.removeUIDs(c.MailboxID, c.UIDs || [])
					} else if (tag === 'ChangeMsgFlags') {
						const c = api.parser.ChangeMsgFlags(x)
						msglistView.updateFlags(c.MailboxID, c.UID, c.ModSeq, c.Mask, c.Flags, c.Keywords || [])
					} else if (tag === 'ChangeMsgThread') {
						const c = api.parser.ChangeMsgThread(x)
						if (c.MessageIDs) {
							msglistView.updateMessageThreadFields(c.MessageIDs, c.Muted, c.Collapsed)
						}
					} else if (tag === 'ChangeMailboxRemove') {
						const c = api.parser.ChangeMailboxRemove(x)
						mailboxlistView.removeMailbox(c.MailboxID)
					} else if (tag === 'ChangeMailboxAdd') {
						const c = api.parser.ChangeMailboxAdd(x)
						mailboxlistView.addMailbox(c.Mailbox)
					} else if (tag === 'ChangeMailboxRename') {
						const c = api.parser.ChangeMailboxRename(x)
						mailboxlistView.renameMailbox(c.MailboxID, c.NewName)
					} else {
						throw new Error('unknown change tag ' + tag)
					}
				})
			} catch (err) {
				window.alert('Error processing changes (reloading advised): ' + errmsg(err))
			}
		})
	}
	connect(false)
}

window.addEventListener('load', async () => {
	try {
		await init()
	} catch (err) {
		window.alert('Error: ' + errmsg(err))
	}
})

// Keep original URL of page load, so we can remove it from stack trace if we need to.
const origLocation = {
	href: window.location.href,
	protocol: window.location.protocol,
	host: window.location.host,
	pathname: window.location.pathname,
	search: window.location.search,
}

// If a JS error happens, show a box in the lower left corner, with a button to
// show details, in a popup. The popup shows the error message and a link to github
// to create an issue. We want to lower the barrier to give feedback.
const showUnhandledError = (err: Error, lineno: number, colno: number) => {
	console.log('unhandled error', err)
	if (settings.ignoreErrorsUntil > new Date().getTime()/1000) {
		return
	}
	let stack = err.stack || ''
	if (stack) {
		log({stack})
		// At the time of writing, Firefox has stacks with full location.href of original
		// page load including hash. Chromium has location.href without hash.
		const loc = origLocation
		stack = '\n'+stack.replaceAll(loc.href, 'webmail.html').replaceAll(loc.protocol + '//' + loc.host + loc.pathname + loc.search, 'webmail.html')
	} else {
		stack = ' (not available)'
	}
	const xerrmsg = err.toString()
	const box = dom.div(
		style({position: 'absolute', bottom: '1ex', left: '1ex', backgroundColor: 'rgba(249, 191, 191, .9)', maxWidth: '14em', padding: '.25em .5em', borderRadius: '.25em', fontSize: '.8em', wordBreak: 'break-all', zIndex: zindexes.shortcut}),
		dom.div(style({marginBottom: '.5ex'}), ''+xerrmsg),
		dom.clickbutton('Details', function click() {
			box.remove()
			let msg = `Mox version: ${moxversion}
Browser: ${window.navigator.userAgent}
File: webmail.html
Lineno: ${lineno || '-'}
Colno: ${colno || '-'}
Message: ${xerrmsg}

Stack trace: ${stack}
`

			const body = `[Hi! Please replace this text with an explanation of what you did to trigger this errors. It will help us reproduce the problem. The more details, the more likely it is we can find and fix the problem. If you don't know how or why it happened, that's ok, it is still useful to report the problem. If no stack trace was found and included below, and you are a developer, you can probably find more details about the error in the browser developer console. Thanks!]

Details of the error and browser:

`+'```\n'+msg+'```\n'

			const remove = popup(
				style({maxWidth: '60em'}),
				dom.h1('A JavaScript error occurred'),
				dom.pre(dom._class('mono'),
					style({backgroundColor: '#f8f8f8', padding: '1ex', borderRadius: '.15em', border: '1px solid #ccc', whiteSpace: 'pre-wrap'}),
					msg,
				),
				dom.br(),
				dom.div('There is a good chance this is a bug in Mox Webmail.'),
				dom.div('Consider filing a bug report ("issue") at ', link('https://github.com/mjl-/mox/issues/new?title='+encodeURIComponent('mox webmail js error: "'+xerrmsg+'"')+'&body='+encodeURIComponent(body), 'https://github.com/mjl-/mox/issues/new'), '. The link includes the error details.'),
				dom.div('Before reporting you could check previous ', link('https://github.com/mjl-/mox/issues?q=is%3Aissue+"mox+webmail+js+error%3A"', 'webmail bug reports'), '.'),
				dom.br(),
				dom.div('Your feedback will help improve mox, thanks!'),
				dom.br(),
				dom.div(
					style({textAlign: 'right'}),
					dom.clickbutton('Close and silence errors for 1 week', function click() {
						remove()
						settingsPut({...settings, ignoreErrorsUntil: Math.round(new Date().getTime()/1000 + 7*24*3600)})
					}),
					' ',
					dom.clickbutton('Close', function click() {
						remove()
					}),
				),
			)
		}), ' ',
		dom.clickbutton('Ignore', function click() {
			box.remove()
		}),
	)
	document.body.appendChild(box)
}

// We don't catch all errors, we use throws to not continue executing javascript.
// But for JavaScript-level errors, we want to show a warning to helpfully get the
// user to submit a bug report.
window.addEventListener('unhandledrejection', (e: PromiseRejectionEvent) => {
	if (!e.reason) {
		return
	}
	const err = e.reason
	if (err instanceof EvalError || err instanceof RangeError || err instanceof ReferenceError || err instanceof SyntaxError || err instanceof TypeError || err instanceof URIError || err instanceof ConsistencyError) {
		showUnhandledError(err, 0, 0)
	} else {
		console.log('unhandled promiserejection', err, e.promise)
	}
})
// Window-level errors aren't that likely, since all code is in the init promise,
// but doesn't hurt to register an handler.
window.addEventListener('error', e => {
	showUnhandledError(e.error, e.lineno, e.colno)
})
