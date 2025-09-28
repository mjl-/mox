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

Enable logging and reload afterwards:

	localStorage.setItem('log', 'yes')

Enable consistency checking in UI updates:

	settingsPut({...settings, checkConsistency: true})

- todo: in msglistView, show names of people we have sent to, and address otherwise. or at don't show names for first-time senders.
- todo: implement settings stored in the server, such as mailboxCollapsed, keyboard shortcuts. name to use for "From", optional default Reply-To and Bcc addresses, signatures (per address), configured labels/keywords with human-readable name, colors and toggling with shortcut keys 1-9.
- todo: automated tests? perhaps some unit tests, then ui scenario's.
- todo: composing of html messages. possibly based on contenteditable. would be good if we can include original html, but quoted. must make sure to not include dangerous scripts/resources, or sandbox it.
- todo: make alt up/down keys work on html iframe too. requires loading it from sameorigin, to get access to its inner document.
- todo: reconnect with last known modseq and don't clear the message list, only update it
- todo: find and use svg icons for flags in the msgitemView. junk (fire), forwarded, replied, attachment (paperclip), flagged (flag), phishing (?). also for special-use mailboxes (junk, trash, archive, draft, sent). should be basic and slim.
- todo: for embedded messages (message/rfc822 or message/global), allow viewing it as message, perhaps in a popup?
- todo: only show orange underline where it could be a problem? in addresses and anchor texts. we may be lighting up a christmas tree now, desensitizing users.
- todo: saved searches that are displayed below list of mailboxes, for quick access to preset view
- todo: when search on free-form text is active, highlight the searched text in the message view.
- todo: forwarding of html parts, including inline attachments, so the html version can be rendered like the original by the receiver.
- todo: buttons/mechanism to operate on all messages in a mailbox/search query, without having to list and select all messages. e.g. clearing flags/labels.
- todo: can we detect if browser supports proper CSP? if not, refuse to load html messages?
- todo: more search criteria? Date header field (instead of time received), text vs html (only, either or both), attachment filenames and sizes
- todo: import messages into specific mailbox?
- todo: configurable keyboard shortcuts? we use strings like "ctrl p" which we already generate and match on, add a mapping from command name to cmd* functions, and have a map of keys to command names. the commands for up/down with shift/ctrl modifiers may need special attention.
- todo: consider composing messages with bcc headers that are sent as message Bcc headers to the bcc-addressees, optionally with checkbox.
- todo: improve accessibility
- todo: msglistView: preload next message?
- todo: previews of zip files
- todo: undo?
- todo: mobile-friendly version. should perhaps be a completely different app, because it is so different.
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
	login: '7',
}

// Buttons and input elements.
ensureCSS('.button', {display: 'inline-block'})
ensureCSS('button, .button, select', {backgroundColor: styles.buttonBackground, border: '1px solid', borderColor: styles.buttonBorderColor, borderRadius: '.15em', padding: '0 .15em'})
ensureCSS('button, .button, select, a.button:visited', {color: styles.color})
ensureCSS('button.active, .button.active, button.active:hover, .button.active:hover', {backgroundColor: styles.highlightBackground})
ensureCSS('button:hover:not(:disabled), .button:hover:not(:disabled), select:hover:not(:disabled)', {backgroundColor: styles.buttonHoverBackground})
ensureCSS('button:disabled, .button:disabled, select:disabled', {opacity: .5})
ensureCSS('input, textarea', {backgroundColor: styles.backgroundColor, color: styles.color, border: '1px solid', borderColor: '#888', borderRadius: '.15em', padding: '0 .15em'})
ensureCSS('input:hover:not(:disabled), textarea:hover:not(:disabled)', {borderColor: styles.colorMilder})

ensureCSS('.btngroup button, .btngroup .button', {borderRadius: 0, borderRightWidth: 0 })
ensureCSS('.btngroup button:first-child, .btngroup .button:first-child', {borderRadius: '.15em 0 0 .15em'})
ensureCSS('.btngroup button:last-child, .btngroup .button:last-child', {borderRadius: '0 .15em .15em 0', borderRightWidth: '1px'})

const keywordButtonStyle = css('keywordButton', {cursor: 'pointer'})
ensureCSS('.keywordButton:hover:not(:disabled)', {backgroundColor: styles.highlightBackgroundHover})


const yscrollStyle = css('yscroll', {overflowY: 'scroll', position: 'absolute', top: 0, bottom: 0, left: 0, right: 0})
const yscrollAutoStyle = css('yscrollAuto', {overflowY: 'auto', position: 'absolute', top: 0, bottom: 0, left: 0, right: 0})

// Input elements that automatically grow based on input, with additional JS.
const autosizeStyle = css('autosize', {display: 'inline-grid', maxWidth: '90vw'})
ensureCSS('.autosize.input', {gridArea: '1 / 2'})
ensureCSS('.autosize::after', {content: 'attr(data-value)', marginRight: '1em', lineHeight: 0, visibility: 'hidden', whiteSpace: 'pre-wrap', overflowX: 'hidden'})


// From HTML.
declare let page: HTMLElement
// From customization script.
declare let moxBeforeDisplay: (root: HTMLElement) => void

let moxversion: string
let moxgoos: string
let moxgoarch: string

// All logging goes through log() instead of console.log, except "should not happen" logging.
let log: (...args: any[]) => void = () => {}
try {
	if (localStorage.getItem('log') || location.hostname === 'localhost') {
		log = console.log
	}
} catch (err) {}

let accountSettings: api.Settings

const defaultSettings = {
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
	mailboxCollapsed: {} as {[mailboxID: number]: boolean}, // Mailboxes that are collapsed.
	showAllHeaders: false, // Whether to show all message headers.
	threading: api.ThreadMode.ThreadOn,
	checkConsistency: location.hostname === 'localhost', // Enable UI update consistency checks, default only for local development.
	composeWidth: 0,
	composeViewportWidth: 0,
	composeHeight: 0,
	composeViewportHeight: 0,
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
			mailboxCollapsed: mailboxCollapsed,
			showAllHeaders: getBool('showAllHeaders'),
			threading: getString('threading', api.ThreadMode.ThreadOff, api.ThreadMode.ThreadOn, api.ThreadMode.ThreadUnread) as api.ThreadMode,
			checkConsistency: getBool('checkConsistency'),
			composeWidth: getInt('composeWidth'),
			composeViewportWidth: getInt('composeViewportWidth'),
			composeHeight: getInt('composeHeight'),
			composeViewportHeight: getInt('composeViewportHeight'),
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

// Mailbox containing rejects.
let rejectsMailbox: string = ''

// Last known server version. For asking to reload.
let lastServerVersion: string = ''

const login = async (reason: string) => {
	popupOpen = true // Prevent global key event handler from consuming keys.
	return new Promise<string>((resolve: (v: string) => void, _) => {
		const origFocus = document.activeElement
		let reasonElem: HTMLElement
		let fieldset: HTMLFieldSetElement
		let autosize: HTMLElement
		let username: HTMLInputElement
		let password: HTMLInputElement
		const root = dom.div(
			css('loginOverlay', {position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: styles.overlayOpaqueBackgroundColor, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: zindexes.login, animation: 'fadein .15s ease-in'}),
			dom.div(
				style({display: 'flex', flexDirection: 'column', alignItems: 'center'}),
				reasonElem=reason ? dom.div(css('sessionError', {marginBottom: '2ex', textAlign: 'center'}), reason) : dom.div(),
				dom.div(
					css('loginPopup', {
						backgroundColor: styles.popupBackgroundColor,
						boxShadow: styles.boxShadow,
						border: '1px solid',
						borderColor: styles.popupBorderColor,
						borderRadius: '.25em',
						padding: '1em',
						maxWidth: '95vw',
						overflowX: 'auto',
						maxHeight: '95vh',
						overflowY: 'auto',
						marginBottom: '20vh',
					}),
					dom.form(
						async function submit(e: SubmitEvent) {
							e.preventDefault()
							e.stopPropagation()

							reasonElem.remove()

							try {
								fieldset.disabled = true
								const loginToken = await client.LoginPrep()
								const token = await client.Login(loginToken, username.value, password.value)
								try {
									window.localStorage.setItem('webmailcsrftoken', token)
								} catch (err) {
									console.log('saving csrf token in localStorage', err)
								}
								root.remove()
								if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
									origFocus.focus()
								}
								popupOpen = false
								resolve(token)
							} catch (err) {
								console.log('login error', err)
								window.alert('Error: ' + errmsg(err))
							} finally {
								fieldset.disabled = false
							}
						},
						fieldset=dom.fieldset(
							dom.h1('Mail'),
							dom.label(
								style({display: 'block', marginBottom: '2ex'}),
								dom.div('Email address', style({marginBottom: '.5ex'})),
								autosize=dom.span(dom._class('autosize'),
									username=dom.input(
										attr.type('email'),
										attr.required(''),
										attr.autocomplete('username'),
										attr.placeholder('jane@example.org'),
										function change() { autosize.dataset.value = username.value },
										function input() { autosize.dataset.value = username.value },
									),
								),
							),
							dom.label(
								style({display: 'block', marginBottom: '2ex'}),
								dom.div('Password', style({marginBottom: '.5ex'})),
								password=dom.input(attr.type('password'), attr.autocomplete('current-password'), attr.required('')),
							),
							dom.div(
								style({textAlign: 'center'}),
								dom.submitbutton('Login'),
							),
						),
					)
				)
			)
		)
		document.body.appendChild(root)
		username.focus()
	})
}

const localStorageGet = (k: string): string | null => {
	try {
		return window.localStorage.getItem(k)
	} catch (err) {
		return null
	}
}

const localStorageRemove = (k: string) => {
	try {
		return window.localStorage.removeItem(k)
	} catch (err) {
	}
}

const client = new api.Client().withOptions({csrfHeader: 'x-mox-csrf', login: login}).withAuthToken(localStorageGet('webmailcsrftoken') || '')

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
let shortcutElem = dom.div(css('shortcutFlash', {fontSize: '2em', position: 'absolute', left: '.25em', bottom: '.25em', backgroundColor: '#888', padding: '0.25em .5em', color: 'white', borderRadius: '.15em'}))
let shortcutTimer = 0
const showShortcut = (c: string) => {
	if (accountSettings?.NoShowShortcuts) {
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
		const fds = fixDate(t[0])
		if (!isNaN(Date.parse(fds))) {
			const d = new Date(fds)
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

	let aborter: {abort?: () => void} = {}

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
		if (aborter.abort) {
			aborter.abort()
		}
		aborter = {}
		try {
			[completeMatches, completeFull] = await withStatus('Autocompleting addresses', client.withOptions({aborter: aborter}).CompleteRecipient(search))
			completeSearch = search
			dom._kids(datalist, (completeMatches || []).map(s => dom.option(s)))
		} catch (err) {
			log('autocomplete error', errmsg(err))
		} finally {
			aborter = {}
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

	const msgItemFlagStyle = css('msgItemFlag', {marginRight: '1px', fontWeight: 'normal', fontSize: '.9em'})
	return msgflags.map(t => dom.span(msgItemFlagStyle, t[1], attr.title(t[0])))
		.concat(othermsgflags.map(t => dom.span(msgItemFlagStyle, css('msgItemFlagCollapsed', {color: styles.colorMilder}), t[1], attr.title(t[0]))))
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
// The returned promise is resolved when dragging is done (and immediately if
// dragging wasn't activated).
const startDrag = (e: MouseEvent, move: (e: MouseEvent) => void): Promise<void> => {
	if (e.buttons !== 1) {
		return Promise.resolve()
	}
	return new Promise((resolve, _) => {
		e.preventDefault()
		e.stopPropagation()
		const stop = () => {
			document.body.removeEventListener('mousemove', move)
			document.body.removeEventListener('mouseup', stop)
			resolve()
		}
		document.body.addEventListener('mousemove', move)
		document.body.addEventListener('mouseup', stop)
	})
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

// Parse a location hash, with either mailbox or search terms, and optional
// selected message id. The special "#compose " hash, used for handling
// "mailto:"-links, must be handled before calling this function.
//
// Examples:
// #Inbox
// #Inbox,1
// #search mb:Inbox
// #search mb:Inbox,1
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
		elem = dom.span(action+'... ')
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
		if (disablable && origFocus && document.activeElement !== origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
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

const withDisabled = async <T>(elem: {disabled: boolean}, p: Promise<T>): Promise<T> => {
	try {
		elem.disabled = true
		return await p
	} catch (err) {
		console.log({err})
		window.alert('Error: ' + errmsg(err))
		throw err
	} finally {
		elem.disabled = false
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
		css('popoverOverlay', {position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, zIndex: zindexes.popover, backgroundColor: styles.overlayBackgroundColor}),
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
			css('popoverContent', {
				position: 'absolute',
				overflowY: 'auto',
			}),
			posx, posy,
			opts.transparent ? [] : [
				css('popoverContentOpaque', {
					backgroundColor: styles.popupBackgroundColor,
					padding: '1em',
					borderRadius: '.15em',
					boxShadow: styles.boxShadow,
					border: '1px solid',
					borderColor: styles.popupBorderColor,
					color: styles.popupColor,
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
		css('popupOverlay', {position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: styles.overlayBackgroundColor, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: zindexes.popup}),
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
			css('popupContent', {backgroundColor: styles.popupBackgroundColor, boxShadow: styles.boxShadow, border: '1px solid', borderColor: styles.popupBorderColor, borderRadius: '.25em', padding: '1em', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto'}),
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

// Show settings screen.
const cmdSettings = async () => {
	let fieldset: HTMLFieldSetElement
	let signature: HTMLTextAreaElement
	let quoting: HTMLSelectElement
	let showAddressSecurity: HTMLInputElement
	let showHTML: HTMLInputElement
	let showShortcuts: HTMLInputElement
	let showHeaders: HTMLTextAreaElement

	if (!accountSettings) {
		throw new Error('No account settings fetched yet.')
	}

	const remove = popup(
		css('popupSettings', {minWidth: '30em'}),
		style({maxWidth: '50em'}),
		dom.h1('Settings'),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()
				const accSet: api.Settings = {
					ID: accountSettings.ID,
					Signature: signature.value,
					Quoting: quoting.value as api.Quoting,
					ShowAddressSecurity: showAddressSecurity.checked,
					ShowHTML: showHTML.checked,
					NoShowShortcuts: !showShortcuts.checked,
					ShowHeaders: showHeaders.value.split('\n').map(s => s.trim()).filter(s => !!s),
				}
				await withDisabled(fieldset, client.SettingsSave(accSet))
				accountSettings = accSet
				remove()
			},
			fieldset=dom.fieldset(
				dom.label(
					style({margin: '1ex 0', display: 'block'}),
					dom.div('Signature'),
					signature=dom.textarea(
						new String(accountSettings.Signature),
						style({width: '100%'}),
						attr.rows(''+Math.max(3, 1+accountSettings.Signature.split('\n').length)),
					),
				),
				dom.label(
					style({margin: '1ex 0', display: 'block'}),
					dom.div('Reply above/below original'),
					attr.title('Auto: If text is selected, only the replied text is quoted and editing starts below. Otherwise, the full message is quoted and editing starts at the top.'),
					quoting=dom.select(
						dom.option(attr.value(''), 'Auto'),
						dom.option(attr.value('bottom'), 'Bottom', accountSettings.Quoting === api.Quoting.Bottom ? attr.selected('') : []),
						dom.option(attr.value('top'), 'Top', accountSettings.Quoting === api.Quoting.Top ? attr.selected('') : []),
					),
				),
				dom.label(
					style({margin: '1ex 0', display: 'block'}),
					showAddressSecurity=dom.input(attr.type('checkbox'), accountSettings.ShowAddressSecurity ? attr.checked('') : []),
					' Show address security indications',
					attr.title('Show bars underneath address input fields, indicating support for STARTTLS/DNSSEC/DANE/MTA-STS/RequireTLS.'),
				),
				dom.label(
					style({margin: '1ex 0', display: 'block'}),
					showHTML=dom.input(attr.type('checkbox'), accountSettings.ShowHTML ? attr.checked('') : []),
					' Show email as HTML instead of text by default for first-time senders',
					attr.title('Whether to show HTML or text is remembered per sender. This sets the default for unknown correspondents.'),
				),

				dom.label(
					style({margin: '1ex 0', display: 'block'}),
					showShortcuts=dom.input(attr.type('checkbox'), accountSettings.NoShowShortcuts ? [] : attr.checked('')),
					' Show shortcut keys in bottom left after interaction with mouse',
				),

				dom.label(
					style({margin: '1ex 0', display: 'block'}),
					dom.div('Show additional headers'),
					showHeaders=dom.textarea(
						new String((accountSettings.ShowHeaders || []).join('\n')),
						style({width: '100%'}),
						attr.rows(''+Math.max(3, 1+(accountSettings.ShowHeaders || []).length)),
					),
					dom.div(style({fontStyle: 'italic'}), 'One header name per line, for example Delivered-To, X-Mox-Reason, User-Agent, ...; Refresh mailbox view for changes to take effect.'),
				),


				dom.div(
					style({marginTop: '2ex'}),
					'Register "mailto:" links with the browser/operating system to compose a message in webmail.',
					dom.br(),
					dom.clickbutton('Register', attr.title('In most browsers, registering is only allowed on HTTPS URLs. Your browser may ask for confirmation. If nothing appears to happen, the registration may already have been present.'), function click() {
						if (!window.navigator.registerProtocolHandler) {
							window.alert('Registering a protocol handler ("mailto:") is not supported by your browser.')
							return
						}
						try {
							window.navigator.registerProtocolHandler('mailto', '#compose %s')
							window.alert('"mailto:"-links have been registered')
						} catch (err) {
							window.alert('Error registering "mailto:" protocol handler: '+errmsg(err))
						}
					}),
					' ',
					dom.clickbutton('Unregister', attr.title('Not all browsers implement unregistering via JavaScript.'), function click() {
						// Not supported on firefox at the time of writing, and the signature is not in the types.
						if (!(window.navigator as any).unregisterProtocolHandler) {
							window.alert('Unregistering a protocol handler ("mailto:") via JavaScript is not supported by your browser. See your browser settings to unregister.')
							return
						}
						try {
							(window.navigator as any).unregisterProtocolHandler('mailto', '#compose %s')
						} catch (err) {
							window.alert('Error unregistering "mailto:" protocol handler: '+errmsg(err))
							return
						}
						window.alert('"mailto:" protocol handler unregistered.')
					}),
				),

				dom.br(),
				dom.div(
					dom.submitbutton('Save'),
				),
			),
		),
	)
}

// Show help popup, with shortcuts and basic explanation.
const cmdHelp = async () => {
	popup(
		css('popupHelp', {padding: '1em 1em 2em 1em'}),
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
						dom.td(
							attr.rowspan('6'),
							css('helpSideNote', {color: '#888', borderLeft: '2px solid', borderLeftColor: '#888', paddingLeft: '.5em'}),
							dom.div('hold ctrl to only move focus', attr.title('ctrl-l and ctrl-u are left for the browser the handle')),
							dom.div('hold shift to expand selection'),
						),
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
						['M', 'mark unread and clear (non)junk flags'],
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
						['ctrl shift Enter', 'send message and archive thread'],
						['ctrl w', 'close message'],
						['ctrl O', 'add To'],
						['ctrl C', 'add Cc'],
						['ctrl B', 'add Bcc'],
						['ctrl Y', 'add Reply-To'],
						['ctrl Backspace', 'remove current address if empty'],
						['ctrl +', 'add address of same type'],
					].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))),

					dom.tr(dom.td(attr.colspan('2'), dom.h2('Message', style({margin: '1ex 0 0 0'})))),
					[
						['r', 'reply or list reply'],
						['R', 'reply all'],
						['f', 'forward message'],
						['e', 'edit draft'],
						['v', 'view attachments'],
						['t', 'view text version'],
						['T', 'view HTML version'],
						['o', 'open message in new tab'],
						['O', 'show raw message'],
						['ctrl p', 'print message'],
						['I', 'toggle internals'],
						['ctrl i', 'toggle all headers'],

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

				dom.div(style({marginTop: '2ex'}), 'Mox is open source email server software, this is version ', moxversion, ', see ', dom.a(attr.href('licenses.txt'), 'licenses'), '.', dom.br(), 'Feedback, including bug reports, is appreciated! ', link('https://github.com/mjl-/mox/issues/new')),
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
				css('tooltipContent', {position: 'absolute', backgroundColor: ['black', 'white'], color: ['white', 'black'], borderRadius: '.15em', padding: '.15em .25em', maxWidth: '50em'}),
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
	// Whether message is to a list, due to List-Id header.
	isList?: boolean
	editOffset?: number // For cursor, default at start.
	draftMessageID?: number // For composing for existing draft message, to be removed when message is sent.
	archiveReferenceMailboxID?: number // For "send and archive", the mailbox from which to move messages to the archive mailbox.
}

interface ComposeView {
	root: HTMLElement
	key: (k: string, e: KeyboardEvent) => Promise<void>
	unsavedChanges: () => boolean
}

let composeView: ComposeView | null = null

const compose = (opts: ComposeOptions, listMailboxes: listMailboxes) => {
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
		isRecipient: boolean
		recipientSecurity: null | api.RecipientSecurity
	}

	let fieldset: HTMLFieldSetElement
	let from: HTMLSelectElement
	let customFrom: HTMLInputElement | null = null
	let subjectAutosize: HTMLElement
	let subject: HTMLInputElement
	let body: HTMLTextAreaElement
	let attachments: HTMLInputElement
	let requiretls: HTMLSelectElement

	let toBtn: HTMLButtonElement, ccBtn: HTMLButtonElement, bccBtn: HTMLButtonElement, replyToBtn: HTMLButtonElement, customFromBtn: HTMLButtonElement
	let replyToCell: HTMLElement, toCell: HTMLElement, ccCell: HTMLElement, bccCell: HTMLElement // Where we append new address views.
	let toRow: HTMLElement, replyToRow: HTMLElement, ccRow: HTMLElement, bccRow: HTMLElement // We show/hide rows as needed.
	let toViews: AddrView[] = [], replytoViews: AddrView[] = [], ccViews: AddrView[] = [], bccViews: AddrView[] = []
	let forwardAttachmentViews: ForwardAttachmentView[] = []

	// todo future: upload attachments with draft messages. would mean we let users remove them again too.

	// We automatically save drafts 1m after a change. When closing window, we ask to
	// save unsaved change to draft.
	let draftMessageID = opts.draftMessageID || 0
	let draftSaveTimer = 0
	let draftSavePromise = Promise.resolve(0)
	let draftLastText = opts.body

	const draftCancelSaveTimer = () => {
		if (draftSaveTimer) {
			window.clearTimeout(draftSaveTimer)
			draftSaveTimer = 0
		}
	}

	const draftScheduleSave = () => {
		if (draftSaveTimer || body.value === draftLastText) {
			return
		}
		draftSaveTimer = window.setTimeout(async () => {
			draftSaveTimer = 0
			await withStatus('Saving draft', draftSave())
			draftScheduleSave()
		}, 60*1000)
	}

	const draftSave = async () => {
		draftCancelSaveTimer()
		let replyTo = ''
		if (replytoViews && replytoViews.length === 1 && replytoViews[0].input.value) {
			replyTo = replytoViews[0].input.value
		}
		const cm: api.ComposeMessage = {
			From: customFrom ? customFrom.value : from.value,
			To: toViews.map(v => v.input.value).filter(s => s),
			Cc: ccViews.map(v => v.input.value).filter(s => s),
			Bcc: bccViews.map(v => v.input.value).filter(s => s),
			ReplyTo: replyTo,
			Subject: subject.value,
			TextBody: body.value,
			ResponseMessageID: opts.responseMessageID || 0,
			DraftMessageID: draftMessageID,
		}
		const mbdrafts = listMailboxes().find(mb => mb.Draft)
		if (!mbdrafts) {
			throw new Error('no designated drafts mailbox')
		}
		draftSavePromise = client.MessageCompose(cm, mbdrafts.ID)
		try {
			draftMessageID = await draftSavePromise
		} finally {
			draftSavePromise = Promise.resolve(0)
		}
		draftLastText = cm.TextBody
	}

	// todo future: on visibilitychange with visibilityState "hidden", use navigator.sendBeacon to save latest modified draft message?

	// When window is closed, ask user to cancel due to unsaved changes.
	const unsavedChanges = () => opts.body !== body.value && (!draftMessageID || draftLastText !== body.value)

	// In Firefox, ctrl-w doesn't seem interceptable when focus is on a button. It is
	// when focus is on a textarea or not any specific UI element. So this isn't always
	// triggered. But we still have the beforeunload handler that checks for
	// unsavedChanges to protect the user in such cases.
	const cmdClose = async () => {
		draftCancelSaveTimer()
		await draftSavePromise
		if (unsavedChanges()) {
			const action = await new Promise<string>((resolve) => {
				const remove = popup(
					dom.p(dom.b('Message has unsaved changes')),
					dom.br(),
					dom.div(
						dom.clickbutton('Save draft', function click() {
							resolve('save')
							remove()
						}), ' ',
						draftMessageID ? dom.clickbutton('Remove draft', function click() {
							resolve('remove')
							remove()
						}) : [], ' ',
						dom.clickbutton('Discard changes', function click() {
							resolve('discard')
							remove()
						}), ' ',
						dom.clickbutton('Cancel', function click() {
							resolve('cancel')
							remove()
						}),
					)
				)
			})
			if (action === 'save') {
				await withStatus('Saving draft', draftSave())
			} else if (action === 'remove') {
				if (draftMessageID) {
					await withStatus('Removing draft', client.MessageDelete([draftMessageID]))
				}
			} else if (action === 'cancel') {
				return
			}
		}
		composeElem.remove()
		composeView = null
	}

	const cmdSave = async () => {
		draftCancelSaveTimer()
		await draftSavePromise
		await withStatus('Saving draft', draftSave())
	}

	const submit = async (archive: boolean) => {
		draftCancelSaveTimer()
		await draftSavePromise

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
			RequireTLS: requiretls.value === '' ? null : requiretls.value === 'yes',
			FutureRelease: scheduleTime.value ? new Date(scheduleTime.value) : null,
			ArchiveThread: archive,
			ArchiveReferenceMailboxID: opts.archiveReferenceMailboxID || 0,
			DraftMessageID: draftMessageID,
		}
		await client.MessageSubmit(message)
		composeElem.remove()
		composeView = null
	}

	const cmdSend = async () => {
		await withStatus('Sending email', submit(false), fieldset)
	}
	const cmdSendArchive = async () => {
		await withStatus('Sending email and archive', submit(true), fieldset)
	}

	const cmdAddTo = async () => { newAddrView('', true, true, toViews, toBtn, toCell, toRow) }
	const cmdAddCc = async () => { newAddrView('', true, false, ccViews, ccBtn, ccCell, ccRow) }
	const cmdAddBcc = async () => { newAddrView('', true, false, bccViews, bccBtn, bccCell, bccRow) }
	const cmdReplyTo = async () => { newAddrView('', false, false, replytoViews, replyToBtn, replyToCell, replyToRow, true) }
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
		'ctrl shift Enter': cmdSendArchive,
		'ctrl w': cmdClose,
		'ctrl O': cmdAddTo,
		'ctrl C': cmdAddCc,
		'ctrl B': cmdAddBcc,
		'ctrl Y': cmdReplyTo,
		'ctrl s': cmdSave,
		'ctrl S': cmdClose,
		// ctrl Backspace and ctrl = (+) not included, they are handled by keydown handlers on in the inputs they remove/add.
	}

	const newAddrView = (addr: string, isRecipient: boolean, isTo: boolean, views: AddrView[], btn: HTMLButtonElement, cell: HTMLElement, row: HTMLElement, single?: boolean) => {
		if (single && views.length !== 0) {
			return
		}

		let rcptSecPromise: Promise<api.RecipientSecurity> | null = null
		let rcptSecAddr: string = ''
		let rcptSecAborter: {abort?: () => void} = {}

		let autosizeElem: HTMLElement, inputElem: HTMLInputElement, securityBar: HTMLElement

		const fetchRecipientSecurity = () => {
			if (!accountSettings?.ShowAddressSecurity) {
				return
			}
			if (inputElem.value === rcptSecAddr) {
				return
			}
			securityBar.style.borderImage = ''
			rcptSecAddr = inputElem.value
			if (!inputElem.value) {
				return
			}

			if (rcptSecAborter.abort) {
				rcptSecAborter.abort()
				rcptSecAborter.abort = undefined
			}

			const color = (v: api.SecurityResult) => {
				if (v === api.SecurityResult.SecurityResultYes) {
					return styles.underlineGreen
				} else if (v === api.SecurityResult.SecurityResultNo) {
					return styles.underlineRed
				} else if (v === api.SecurityResult.SecurityResultUnknown) {
					return 'transparent'
				}
				return styles.underlineGrey
			}
			const setBar = (c0: string, c1: string, c2: string, c3: string, c4: string) => {
				const stops = [
					c0 + ' 0%', c0 + ' 19%', 'transparent 19%', 'transparent 20%',
					c1 + ' 20%', c1 + ' 39%', 'transparent 39%', 'transparent 40%',
					c2 + ' 40%', c2 + ' 59%', 'transparent 59%', 'transparent 60%',
					c3 + ' 60%', c3 + ' 79%', 'transparent 79%', 'transparent 80%',
					c4 + ' 80%', c4 + ' 100%',
				].join(', ')
				securityBar.style.borderImage = 'linear-gradient(to right, ' + stops + ') 1'
			}

			const aborter: {abort?: () => void} = {}
			rcptSecAborter = aborter
			rcptSecPromise = client.withOptions({aborter: aborter}).RecipientSecurity(inputElem.value)
			rcptSecPromise.then((rs) => {
				setBar(color(rs.STARTTLS), color(rs.MTASTS), color(rs.DNSSEC), color(rs.DANE), color(rs.RequireTLS))

				const implemented: string[] = []
				const check = (v: boolean, s: string) => {
					if (v) {
						implemented.push(s)
					}
				}
				check(rs.STARTTLS === api.SecurityResult.SecurityResultYes, 'STARTTLS')
				check(rs.MTASTS === api.SecurityResult.SecurityResultYes, 'MTASTS')
				check(rs.DNSSEC === api.SecurityResult.SecurityResultYes, 'DNSSEC')
				check(rs.DANE === api.SecurityResult.SecurityResultYes, 'DANE')
				check(rs.RequireTLS === api.SecurityResult.SecurityResultYes, 'RequireTLS')
				const status = 'Security mechanisms known to be implemented by the recipient domain: '+ (implemented.length === 0 ? '(none)' : implemented.join(', ')) + '.'
				inputElem.setAttribute('title', status+'\n\n'+recipientSecurityTitle)

				aborter.abort = undefined
				v.recipientSecurity = rs
				if (isRecipient) {
					// If we are not replying to a message from a mailing list, and all recipients
					// implement REQUIRETLS, we enable it.
					let reqtls = opts.isList !== true
					const walk = (l: AddrView[]) => {
						for (const v of l) {
							if (v.recipientSecurity?.RequireTLS !== api.SecurityResult.SecurityResultYes || v.recipientSecurity?.MTASTS !== api.SecurityResult.SecurityResultYes && v.recipientSecurity?.DANE !== api.SecurityResult.SecurityResultYes) {
								reqtls = false
								break
							}
						}
					}
					walk(toViews)
					walk(ccViews)
					walk(bccViews)
					if (requiretls.value === '' || requiretls.value === 'yes') {
						requiretls.value = reqtls ? 'yes' : ''
					}
				}
			}, () => {
				setBar('#888', '#888', '#888', '#888', '#888')
				inputElem.setAttribute('title', 'Error fetching security mechanisms known to be implemented by the recipient domain...\n\n'+recipientSecurityTitle)
				aborter.abort = undefined
				if (requiretls.value === 'yes') {
					requiretls.value = ''
				}
			})
		}

		const recipientSecurityTitle = 'Description of security mechanisms recipient domains may implement:\n1. STARTTLS: Opportunistic (unverified) TLS with STARTTLS, successfully negotiated during the most recent delivery attempt.\n2. MTA-STS: For PKIX/WebPKI-verified TLS.\n3. DNSSEC: MX DNS records are DNSSEC-signed.\n4. DANE: First delivery destination host implements DANE for verified TLS.\n5. RequireTLS: SMTP extension for verified TLS delivery into recipient mailbox, support detected during the most recent delivery attempt.\n\nChecks STARTTLS, DANE and RequireTLS cover the most recently used delivery path, not necessarily all possible delivery paths.\n\nThe bars below the input field indicate implementation status by the recipient domain:\n- Red, not implemented/unsupported\n- Green, implemented/supported\n- Gray, error while determining\n- Absent/white, unknown or skipped (e.g. no previous delivery attempt, or DANE check skipped due to DNSSEC-lookup error)'
		const root = dom.span(
			autosizeElem=dom.span(
				dom._class('autosize'),
				inputElem=dom.input(
					focusPlaceholder('Jane <jane@example.org>'),
					style({width: 'auto'}),
					attr.value(addr),
					newAddressComplete(),
					accountSettings?.ShowAddressSecurity ? attr.title(recipientSecurityTitle) : [],
					function keydown(e: KeyboardEvent) {
						// Backspace removes address except when it's the only To address left.
						if (e.key === 'Backspace' && e.ctrlKey && inputElem.value === '' && !(isTo && views.length === 1)) {
							remove()
						} else if (e.key === '=' && e.ctrlKey) {
							newAddrView('', isRecipient, isTo, views, btn, cell, row, single)
						} else {
							return
						}
						e.preventDefault()
						e.stopPropagation()
					},
					function input() {
						// data-value is used for size of ::after css pseudo-element to stretch input field.
						autosizeElem.dataset.value = inputElem.value
					},
					function change() {
						autosizeElem.dataset.value = inputElem.value
						fetchRecipientSecurity()
					},
					function paste(e: ClipboardEvent) {
						const data = e.clipboardData?.getData('text/plain')
						if (typeof data !== 'string' || data === '') {
							return
						}
						const split = data.split(',')
						if (split.length <= 1) {
							return
						}
						autosizeElem.dataset.value = inputElem.value = split[0]
						let last
						for (const rest of split.splice(1)) {
							last = newAddrView(rest.trim(), isRecipient, isTo, views, btn, cell, row, single)
						}
						last!!.input.focus()
						e.preventDefault()
						e.stopPropagation()
					},
				),
				securityBar=dom.span(
					css('securitybar', {
						margin: '0 1px',
						borderBottom: '1.5px solid',
						borderBottomColor: 'transparent',
					}),
				),
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
		autosizeElem.dataset.value = inputElem.value

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

		const v: AddrView = {root: root, input: inputElem, isRecipient: isRecipient, recipientSecurity: null}

		fetchRecipientSecurity()

		views.push(v)
		cell.appendChild(v.root)
		row.style.display = ''
		if (single) {
			btn.style.display = 'none'
		}
		inputElem.focus()
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
		for (const sep of (domconf.LocalpartCatchallSeparators || [])) {
			user = user.split(sep)[0]
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
	const fromOptions = accountAddresses.filter(a => a.User).map(a => {
		const selected = opts.from && opts.from.length === 1 && equalAddress(a, opts.from[0]) || loginAddress && equalAddress(a, loginAddress) && (!opts.from || envelopeIdentity(opts.from))
		const o = dom.option(formatAddress(a), selected ? attr.selected('') : [])
		if (selected) {
			haveFrom = true
		}
		return o
	})
	if (!haveFrom && opts.from && opts.from.length === 1) {
		const a = addressSelf(opts.from[0])
		if (a) {
			const fromAddr: api.MessageAddress = {Name: a.Name, User: opts.from[0].User, Domain: a.Domain}
			const o = dom.option(formatAddress(fromAddr), attr.selected(''))
			fromOptions.unshift(o)
		}
	}

	let scheduleLink: HTMLElement
	let scheduleElem: HTMLElement
	let scheduleTime: HTMLInputElement
	let scheduleWeekday: HTMLElement
	const pad0 = (v: number) => v >= 10 ? ''+v : '0'+v
	const localdate = (d: Date) => [d.getFullYear(), pad0(d.getMonth()+1), pad0(d.getDate())].join('-')
	const localdatetime = (d: Date) => localdate(d) + 'T' + pad0(d.getHours()) + ':' + pad0(d.getMinutes()) + ':00'
	const weekdays = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
	const scheduleTimeChanged = () => {
		console.log('datetime change', scheduleTime.value)
		dom._kids(scheduleWeekday, weekdays[new Date(scheduleTime.value).getDay()])
	}

	let resizeLast: {x: number, y: number} | null = null
	let resizeTimer: number = 0
	const initWidth = window.innerWidth === settings.composeViewportWidth ? settings.composeWidth : 0
	const initHeight = window.innerHeight === settings.composeViewportHeight ? settings.composeHeight : 0

	const composeTextMildStyle = css('composeTextMild', {textAlign: 'right', color: styles.colorMild})
	const composeCellStyle = css('composeCell', {lineHeight: '1.5'})

	const composeElem = dom.div(
		css('composePopup', {
			position: 'fixed',
			bottom: '1ex',
			right: '1ex',
			zIndex: zindexes.compose,
			backgroundColor: styles.popupBackgroundColor,
			boxShadow: styles.boxShadow,
			border: '1px solid',
			borderColor: styles.popupBorderColor,
			padding: '1em',
			minWidth: '40em',
			maxWidth: '95vw',
			borderRadius: '.25em',
			display: 'flex',
			flexDirection: 'column',
		}),
		initWidth ? style({width: initWidth+'px'}) : [],
		initHeight ? style({height: initHeight+'px'}) : [],
		dom.div(
			css('composeResizeGrab', {position: 'absolute', marginTop: '-1em', marginLeft: '-1em', width: '1em', height: '1em', cursor: 'nw-resize'}),
			async function mousedown(e: MouseEvent) {
				// Disable pointer events on the message view. If it has an iframe with a message,
				// mouse events while dragging would be consumed by the iframe, breaking our
				// resize.
				page.style.pointerEvents = 'none'
				resizeLast = null
				await startDrag(e, (e: MouseEvent) => {
					if (resizeLast) {
						const bounds = composeElem.getBoundingClientRect()
						const width = Math.round(bounds.width + resizeLast.x - e.clientX)
						const height = Math.round(bounds.height + resizeLast.y - e.clientY)
						composeElem.style.width = width+'px'
						composeElem.style.height = height+'px'
						body.removeAttribute('rows')
						if (resizeTimer) {
							window.clearTimeout(resizeTimer)
						}
						resizeTimer = window.setTimeout(() => {
							settingsPut({...settings, composeWidth: width, composeHeight: height, composeViewportWidth: window.innerWidth, composeViewportHeight: window.innerHeight})
						}, 1000)
					}
					resizeLast = {x: e.clientX, y: e.clientY}
				})
				page.style.pointerEvents = ''
			},
		),
		dom.form(
			css('composeForm', {
				flexGrow: '1',
				display: 'flex',
				flexDirection: 'column',
			}),
			fieldset=dom.fieldset(
				css('composeFields', {
					flexGrow: '1',
					display: 'flex',
					flexDirection: 'column',
				}),
				dom.table(
					style({width: '100%'}),
					dom.tr(
						dom.td(
							composeTextMildStyle,
							dom.span('From:'),
						),
						dom.td(
							dom.div(
								css('composeButtonsSpread', {display: 'flex', gap: '1em', justifyContent: 'space-between'}),
								dom.div(
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
								dom.div(
									listMailboxes().find(mb => mb.Draft) ? [
										dom.clickbutton('Save', attr.title('Save draft message.'), clickCmd(cmdSave, shortcuts)), ' ',
									] : [],
									dom.clickbutton('Close', attr.title('Close window, saving draft message if body has changed or a draft was saved earlier.'), clickCmd(cmdClose, shortcuts)),
								),
							),
						),
					),
					toRow=dom.tr(
						dom.td('To:', composeTextMildStyle),
						toCell=dom.td(composeCellStyle),
					),
					replyToRow=dom.tr(
						dom.td('Reply-To:', composeTextMildStyle),
						replyToCell=dom.td(composeCellStyle),
					),
					ccRow=dom.tr(
						dom.td('Cc:', composeTextMildStyle),
						ccCell=dom.td(composeCellStyle),
					),
					bccRow=dom.tr(
						dom.td('Bcc:', composeTextMildStyle),
						bccCell=dom.td(composeCellStyle),
					),
					dom.tr(
						dom.td('Subject:', composeTextMildStyle),
						dom.td(
							subjectAutosize=dom.span(
								dom._class('autosize'),
								style({width: '100%'}), // Without 100% width, the span takes minimal width for input, we want the full table cell.
								subject=dom.input(
									style({width: '100%'}),
									attr.value(opts.subject || ''),
									attr.required(''),
									focusPlaceholder('subject...'),
									function input() {
										subjectAutosize.dataset.value = subject.value
									},
								),
							),
						),
					),
				),
				body=dom.textarea(
					dom._class('mono'),
					style({
						flexGrow: '1',
						width: '100%',
					}),
					initHeight === 0 ? attr.rows('15') : [], // Drives default size, removed on compose window resize.
					// Explicit string object so it doesn't get the highlight-unicode-block-changes
					// treatment, which would cause characters to disappear.
					new String(opts.body || ''),
					prop({selectionStart: opts.editOffset || 0, selectionEnd: opts.editOffset || 0}),
					function keyup(e: KeyboardEvent) {
						if (e.key === 'Enter') {
							checkAttachments()
						}
					},
					!listMailboxes().find(mb => mb.Draft) ? [] : function input() {
						draftScheduleSave()
					},
				),
				!(opts.attachmentsMessageItem && opts.attachmentsMessageItem.Attachments && opts.attachmentsMessageItem.Attachments.length > 0) ? [] : dom.div(
					style({margin: '.5em 0'}),
					'Forward attachments: ',
					forwardAttachmentViews=(opts.attachmentsMessageItem?.Attachments || []).map(a => {
						const filename = a.Filename || '(unnamed)'
						const size = formatSize(a.Part.DecodedSize)
						const checkbox = dom.input(attr.type('checkbox'), function change() { checkAttachments() })
						const root = dom.label(checkbox, ' '+filename+' ', dom.span('('+size+') ', styleClasses.textMild))
						const v: ForwardAttachmentView = {
							path: a.Path || [],
							root: root,
							checkbox: checkbox
						}
						return v
					}),
					dom.label(styleClasses.textMild, dom.input(attr.type('checkbox'), function change(e: Event) {
						forwardAttachmentViews.forEach(v => v.checkbox.checked = (e.target! as HTMLInputElement).checked)
					}), ' (Toggle all)')
				),
				noAttachmentsWarning=dom.div(style({display: 'none'}), css('composeNoAttachmentsWarning', {backgroundColor: styles.warningBackgroundColor, padding: '0.15em .25em', margin: '.5em 0'}), 'Message mentions attachments, but no files are attached.'),
				dom.label(style({margin: '1ex 0', display: 'block'}), 'Attachments ', attachments=dom.input(attr.type('file'), attr.multiple(''), function change() { checkAttachments() })),
				dom.label(
					style({margin: '1ex 0', display: 'block'}),
					attr.title('How to use TLS for message delivery over SMTP:\n\nDefault: Delivery attempts follow the policies published by the recipient domain: Verification with MTA-STS and/or DANE, or optional opportunistic unverified STARTTLS if the domain does not specify a policy.\n\nWith RequireTLS: For sensitive messages, you may want to require verified TLS. The recipient destination domain SMTP server must support the REQUIRETLS SMTP extension for delivery to succeed. It is automatically chosen when the destination domain mail servers of all recipients are known to support it.\n\nFallback to insecure: If delivery fails due to MTA-STS and/or DANE policies specified by the recipient domain, and the content is not sensitive, you may choose to ignore the recipient domain TLS policies so delivery can succeed.'),
					'TLS ',
					requiretls=dom.select(
						dom.option(attr.value(''), 'Default'),
						dom.option(attr.value('yes'), 'With RequireTLS'),
						dom.option(attr.value('no'), 'Fallback to insecure'),
					),
				),
				dom.div(
					scheduleLink=dom.a(attr.href(''), 'Schedule', function click(e: MouseEvent) {
						e.preventDefault()
						scheduleTime.value = localdatetime(new Date())
						scheduleTimeChanged()
						scheduleLink.style.display = 'none'
						scheduleElem.style.display = ''
						scheduleTime.setAttribute('required', '')
					}),
					scheduleElem=dom.div(
						style({display: 'none'}),
						dom.clickbutton('Start of next day', function click(e: MouseEvent) {
							e.preventDefault()
							const d = new Date(scheduleTime.value)
							const nextday = new Date(d.getTime() + 24*3600*1000)
							scheduleTime.value = localdate(nextday) + 'T09:00:00'
							scheduleTimeChanged()
						}), ' ',
						dom.clickbutton('+1 hour', function click(e: MouseEvent) {
							e.preventDefault()
							const d = new Date(scheduleTime.value)
							scheduleTime.value = localdatetime(new Date(d.getTime() + 3600*1000))
							scheduleTimeChanged()
						}), ' ',
						dom.clickbutton('+1 day', function click(e: MouseEvent) {
							e.preventDefault()
							const d = new Date(scheduleTime.value)
							scheduleTime.value = localdatetime(new Date(d.getTime() + 24*3600*1000))
							scheduleTimeChanged()
						}), ' ',
						dom.clickbutton('Now', function click(e: MouseEvent) {
							e.preventDefault()
							scheduleTime.value = localdatetime(new Date())
							scheduleTimeChanged()
						}), ' ',
						dom.clickbutton('Cancel', function click(e: MouseEvent) {
							e.preventDefault()
							scheduleLink.style.display = ''
							scheduleElem.style.display = 'none'
							scheduleTime.removeAttribute('required')
							scheduleTime.value = ''
						}),
						dom.div(
							style({marginTop: '1ex'}),
							scheduleTime=dom.input(attr.type('datetime-local'), function change() {
								scheduleTimeChanged()
							}),
							' in local timezone ' + (Intl.DateTimeFormat().resolvedOptions().timeZone || '') + ', ',
							scheduleWeekday=dom.span(),
						),
					),
				),
				dom.div(
					style({margin: '3ex 0 1ex 0', display: 'block'}),
					dom.submitbutton('Send'),
					' ',
					opts.responseMessageID && listMailboxes().find(mb => mb.Archive) ? dom.clickbutton('Send and archive thread', clickCmd(cmdSendArchive, shortcuts)) : [],
				),
			),
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				shortcutCmd(cmdSend, shortcuts)
			},
		),
	)

	subjectAutosize.dataset.value = subject.value

	;(opts.to && opts.to.length > 0 ? opts.to : ['']).forEach(s => newAddrView(s, true, true, toViews, toBtn, toCell, toRow))
	;(opts.cc || []).forEach(s => newAddrView(s, true,  false, ccViews, ccBtn, ccCell, ccRow))
	;(opts.bcc || []).forEach(s => newAddrView(s, true, false, bccViews, bccBtn, bccCell, bccRow))
	if (opts.replyto) {
		newAddrView(opts.replyto, false, false, replytoViews, replyToBtn, replyToCell, replyToRow, true)
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
		unsavedChanges: unsavedChanges,
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
			css('popoverLabels', {display: 'flex', flexDirection: 'column', gap: '1ex'}),
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
						dom.span(styleClasses.keyword, l),
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
			css('popoverMove', {display: 'flex', flexDirection: 'column', gap: '.25em'}),
			mailboxes.map(mb =>
				dom.div(
					dom.clickbutton(
						mb.Name,
						mb.ID === msgsMailboxID ? attr.disabled('') : [],
						async function click() {
							const moveMsgs = msgs.filter(m => m.MailboxID !== mb.ID)
							const msgIDs = moveMsgs.map(m => m.ID)
							await withStatus('Moving to mailbox', client.MessageMove(msgIDs, mb.ID))
							if (moveMsgs.length === 1) {
								await moveAskRuleset(moveMsgs[0].ID, moveMsgs[0].MailboxID, mb, mailboxes)
							}
							remove()
						}
					),
				)
			),
		)
	)
}

// We've moved a single message. If the source or destination mailbox is not a
// "special-use" mailbox (other than inbox), and there isn't a rule yet or there is
// one we may want to delete, and we haven't asked about adding/removing this
// ruleset before, ask the user to add/remove a ruleset for moving. If the message
// has a list-id header, we ask to create a ruleset treating it as a mailing list
// message matching on future list-id header and spf/dkim verified domain,
// otherwise we make a rule based on message "from" address.
const moveAskRuleset = async (msgID: number, mbSrcID: number, mbDst: api.Mailbox, mailboxes: api.Mailbox[]) => {
	const mbSrc = mailboxes.find(mb => mb.ID === mbSrcID)
	if (!mbSrc || isSpecialUse(mbDst) || isSpecialUse(mbSrc)) {
		return
	}

	const [listID, msgFrom, isRemove, rcptTo, ruleset] = await withStatus('Checking rulesets', client.RulesetSuggestMove(msgID, mbSrc.ID, mbDst.ID))
	if (!ruleset) {
		return
	}

	const what = listID ? ['list with id "', listID, '"'] : ['address "', msgFrom, '"']

	if (isRemove) {
		const remove = popup(
			dom.h1('Remove rule?'),
			dom.p(
				style({maxWidth: '30em'}),
				'Would you like to remove the server-side rule that automatically delivers messages from ', what, ' to mailbox "', mbDst.Name, '"?',
			),
			dom.br(),
			dom.div(
				dom.clickbutton('Yes, remove rule', async function click() {
					await withStatus('Remove ruleset', client.RulesetRemove(rcptTo, ruleset))
					remove()
				}), ' ',
				dom.clickbutton('Not now', async function click() {
					remove()
				}),
			),
			dom.br(),
			dom.div(
			style({marginBottom: '1ex'}),
				dom.clickbutton("No, and don't ask again for ", what, async function click() {
					await withStatus('Store ruleset response', client.RulesetMessageNever(rcptTo, listID, msgFrom, true))
					remove()
				}),
			),
			dom.div(
				dom.clickbutton("No, and don't ask again when moving messages out of \"", mbSrc.Name, '"', async function click() {
					await withStatus('Store ruleset response', client.RulesetMailboxNever(mbSrc.ID, false))
					remove()
				}),
			),
		)
		return
	}
	const remove = popup(
		dom.h1('Add rule?'),
		dom.p(
			style({maxWidth: '30em'}),
			'Would you like to create a server-side ruleset that automatically delivers future messages from ', what, ' to mailbox "', mbDst.Name, '"?',
		),
		dom.br(),
		dom.div(
			dom.clickbutton('Yes, add rule', async function click() {
				await withStatus('Add ruleset', client.RulesetAdd(rcptTo, ruleset))
				remove()
			}), ' ',
			dom.clickbutton('Not now', async function click() {
				remove()
			}),
		),
		dom.br(),
		dom.div(
			style({marginBottom: '1ex'}),
			dom.clickbutton("No, and don't ask again for ", what, async function click() {
				await withStatus('Store ruleset response', client.RulesetMessageNever(rcptTo, listID, msgFrom, false))
				remove()
			}),
		),
		dom.div(
			dom.clickbutton("No, and don't ask again when moving messages to \"", mbDst.Name, '"', async function click() {
				await withStatus('Store ruleset response', client.RulesetMailboxNever(mbDst.ID, true))
				remove()
			}),
		),
	)
}

const isSpecialUse = (mb: api.Mailbox) => mb.Archive || mb.Draft || mb.Junk || mb.Sent || mb.Trash

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
	// Whether this thread root is collapsed. If so, the root is visible, all descendants
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
	const identityTag = (s: string, title: string) =>
		dom.span(
			css('msgItemIdentity', {padding: '0 .15em', marginLeft: '.15em', borderRadius: '.15em', fontWeight: 'normal', fontSize: '.9em', whiteSpace: 'nowrap', backgroundColor: styles.backgroundColorMilder, color: styles.color, border: '1px solid', borderColor: styles.colorMilder}),
			s,
			attr.title(title),
		)
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
				// Prevent showing '-<1min' when browser and server have relatively small time drift of max 1 minute.
				negative = ''
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
		const keywords = (m.Keywords || []).map(kw => dom.span(styleClasses.keyword, kw))
		if (msgitemView.isCollapsedThreadRoot()) {
			const keywordsSeen = new Set<string>()
			for (const kw of (m.Keywords || [])) {
				keywordsSeen.add(kw)
			}
			for (const miv of msgitemView.descendants()) {
				for (const kw of (miv.messageitem.Message.Keywords || [])) {
					if (!keywordsSeen.has(kw)) {
						keywordsSeen.add(kw)
						keywords.push(dom.span(styleClasses.keyword, dom._class('keywordCollapsed'), kw))
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
			const e = dom.span(
				css('msgItemMailbox', {padding: '0 .15em', marginLeft: '.15em', borderRadius: '.15em', fontWeight: 'normal', fontSize: '.9em', whiteSpace: 'nowrap', background: styles.backgroundColorMilder, color: ['white', '#ddd'], border: '1px solid', borderColor: styles.colorMilder}),
				isCollapsedKid ? css('msgItemMailboxCollapsed', {background: '#eee', color: '#333'}, true) : [],
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

		const correspondentAddrs = (miv: MsgitemView): [api.MessageAddress[], api.MessageAddress[]] => {
			let fromAddrs = miv.messageitem.Envelope.From || []
			let toAddrs: api.MessageAddress[] = []
			if (listMailboxes().find(mb => mb.ID === miv.messageitem.Message.MailboxID)?.Sent) {
				toAddrs = [...(miv.messageitem.Envelope.To || []), ...(miv.messageitem.Envelope.CC || []), ...(miv.messageitem.Envelope.BCC || [])]
			}
			return [fromAddrs, toAddrs]
		}

		// Correspondents for a message, possibly a collapsed thread root.
		const correspondents = () => {
			let fromAddrs: api.MessageAddress[] = []
			let toAddrs: api.MessageAddress[] = []
			let junk = m.Junk || !!listMailboxes().find(mb => mb.ID === m.MailboxID && (mb.Name === rejectsMailbox || mb.Junk))
			if (msgitemView.isCollapsedThreadRoot()) {
				// Gather both all correspondents in thread.
				;[msgitemView, ...(msgitemView.descendants())].forEach(miv => {
					const [fa, ta] = correspondentAddrs(miv)
					fromAddrs = [...fromAddrs, ...fa]
					toAddrs = [...toAddrs, ...ta]
					junk = junk || miv.messageitem.Message.Junk
				})
			} else {
				[fromAddrs, toAddrs] = correspondentAddrs(msgitemView)
			}

			const seen = new Set<string>()
			let fa: api.MessageAddress[] = []
			let ta: api.MessageAddress[] = []
			for (const a of fromAddrs) {
				const k = a.User+'@'+a.Domain.ASCII
				if (!seen.has(k)) {
					seen.add(k)
					fa.push(a)
				}
			}
			for (const a of toAddrs) {
				const k = a.User+'@'+a.Domain.ASCII
				if (!seen.has(k)) {
					seen.add(k)
					ta.push(a)
				}
			}
			let title = fa.map(a => formatAddress(a)).join(', ')
			if (ta.length > 0) {
				if (title) {
					title += ',\n'
				}
				title += 'addressed: '+ta.map(a => formatAddress(a)).join(', ')
			}
			return [
				attr.title(title),
				join(
					[
						...fa.map(a => formatAddressShort(a, junk)),
						...ta.map(a => dom.span(style({fontStyle: 'italic'}), formatAddressShort(a, junk))),
					],
					() => ', '
				),
			]
		}

		const msgItemCellStyle = css('msgItemCell', {padding: '2px 4px'})

		const msgItemStyle = css('msgItem', {display: 'flex', userSelect: 'none', cursor: 'pointer', borderRadius: '.15em', border: '1px solid transparent'})
		ensureCSS('.msgItem.focus', {borderColor: styles.msgItemFocusBorderColor, border: '1px solid'})
		ensureCSS('.msgItem:hover', {backgroundColor: styles.msgItemHoverBackgroundColor})
		ensureCSS('.msgItem.active', {background: styles.msgItemActiveBackground})

		// When rerendering, we remember active & focus states. So we don't have to make
		// the caller also call redraw on MsglistView.
		const active = msgitemView.root && msgitemView.root.classList.contains('active')
		const focus = msgitemView.root && msgitemView.root.classList.contains('focus')
		const elem = dom.div(
			msgItemStyle,
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
			isUnread() ? css('msgItemUnread', {fontWeight: 'bold'}) : [],
			// Relevant means not muted and matching the query.
			isRelevant() ? [] : css('msgItemNotRelevant', {opacity: '.4'}),
			dom.div(msgItemCellStyle, dom._class('msgItemFlags'),
				dom.div(
					css('msgItemFlagsSpread', {display: 'flex', justifyContent: 'space-between'}),
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
			dom.div(msgItemCellStyle, dom._class('msgItemFrom'),
				dom.div(css('msgItemFromSpread', {display: 'flex', justifyContent: 'space-between'}),
					dom.div(
						dom._class('silenttitle'),
						css('msgItemFromText', {whiteSpace: 'nowrap', overflow: 'hidden'}),
						correspondents(),
					),
					identityHeader,
				),
				// Thread messages are connected by a vertical bar. The first and last message are
				// only half the height of the item, to indicate start/end, and so it stands out
				// from any thread above/below.
				((msgitemView.parent || msgitemView.kids.length > 0) && !msgitemView.threadRoot().collapsed) ?
					dom.div(css('msgItemThreadBar', {position: 'absolute', right: 0, top: 0, bottom: 0, borderRight: '2px solid', borderRightColor: styles.colorMilder}),
						!msgitemView.parent ? css('msgItemThreadBarFirst', {top: '50%', bottom: '-1px'}) : (
							isThreadLast() ?
								css('msgItemThreadBarLast', {top: '-1px', bottom: '50%'}) :
								css('msgItemThreadBarMiddle', {top: '-1px', bottom: '-1px'})
						)
					) : []
			),
			dom.div(msgItemCellStyle, css('msgItemSubject', {position: 'relative'}),
				dom.div(css('msgItemSubjectSpread', {display: 'flex', justifyContent: 'space-between', position: 'relative'}),
					dom.div(
						css('msgItemSubjectText', {whiteSpace: 'nowrap', overflow: 'hidden'}),
						threadIndent > 0 ? dom.span(threadChar, style({paddingLeft: (threadIndent/2)+'em'}), css('msgItemThreadChar', {opacity: '.75', fontWeight: 'normal'}), threadCharTitle ? attr.title(threadCharTitle) : []) : [],
						msgitemView.parent ? [] : mi.Envelope.Subject || '(no subject)',
						dom.span(css('msgItemSubjectSnippet', {fontWeight: 'normal', color: styles.colorMilder}), ' '+(mi.Message.Preview || '')),
					),
					dom.div(
						keywords,
						mailboxtags,
					),
				),
			),
			dom.div(msgItemCellStyle, dom._class('msgItemAge'), age(received())),
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

	const fromAddress = mi.Envelope.From && mi.Envelope.From.length === 1 ? formatEmail(mi.Envelope.From[0]) : ''

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

	const react = async (to: api.MessageAddress[], cc: api.MessageAddress[], bcc: api.MessageAddress[], forward: boolean) => {
		const pm = await parsedMessagePromise
		let body = ''
		const sel = window.getSelection()
		let haveSel = false
		if (sel && sel.toString()) {
			body = sel.toString()
			haveSel = true
		} else if (pm.Texts && pm.Texts.length > 0) {
			body = pm.Texts[0]
		}
		body = body.replace(/\r/g, '').replace(/\n\n\n\n*/g, '\n\n').trim()
		let editOffset = 0
		if (forward) {
			let prefix = `\n\n---- Forwarded Message ----\n`
			const keys = ['Subject', 'Date', 'From', 'Reply-To', 'To', 'Cc']
			const padspace = (s: string, size: number) => s + ' '.repeat(size-s.length)
			for (const k of keys) {
				for (const v of (pm.Headers?.[k] || [])) {
					prefix += padspace(k + ':', 10) + v+'\n'
				}
			}
			body = prefix+'\n'+body
		} else {
			body = body.split('\n').map(line => '> ' + line).join('\n')
			let sig = accountSettings?.Signature || ''
			if (!accountSettings?.Quoting && haveSel || accountSettings?.Quoting === api.Quoting.Bottom) {
				body += '\n\n'
				editOffset = body.length
				body += '\n\n' + sig
			} else {
				let onWroteLine = ''
				if (mi.Envelope.Date && mi.Envelope.From && mi.Envelope.From.length === 1) {
					const from = mi.Envelope.From[0]
					const name = from.Name || formatEmail(from)
					const datetime = mi.Envelope.Date.toLocaleDateString(undefined, {weekday: "short", year: "numeric", month: "short", day: "numeric"}) + ' at ' + mi.Envelope.Date.toLocaleTimeString()
					onWroteLine = 'On ' + datetime + ', ' + name + ' wrote:\n'
				}
				body = '\n\n' + sig + '\n' + onWroteLine + body
			}
		}
		const subjectPrefix = forward ? 'Fwd:' : 'Re:'
		let subject = mi.Envelope.Subject || ''
		subject = (RegExp('^'+subjectPrefix, 'i').test(subject) ? '' : subjectPrefix+' ') + subject
		const opts: ComposeOptions = {
			from: mi.Envelope.To || undefined,
			to: to.map(a => formatAddress(a)),
			cc: cc.map(a => formatAddress(a)),
			bcc: bcc.map(a => formatAddress(a)),
			subject: subject,
			body: body,
			isForward: forward,
			attachmentsMessageItem: forward ? mi : undefined,
			responseMessageID: m.ID,
			isList: m.IsMailingList,
			editOffset: editOffset,
			// For "send and archive", we only move messages from the current open mailbox
			// (fallback to mailbox of response message for search results) to the archive
			// mailbox. We don't want to move messages in other mailboxes, like Sent, Trash, or
			// for cross-posted messages in other mailboxes.
			archiveReferenceMailboxID: msglistView.activeMailbox()?.ID || m.MailboxID,
		}
		compose(opts, listMailboxes)
	}

	const reply = async (all: boolean) => {
		const contains = (l: api.MessageAddress[], a: api.MessageAddress): boolean => !!l.find(e => equalAddress(e, a))

		let to: api.MessageAddress[] = []
		let cc: api.MessageAddress[] = []
		let bcc: api.MessageAddress[] = []
		if ((mi.Envelope.From || []).length === 1 && envelopeIdentity(mi.Envelope.From || [])) {
			// Replying to our own message, copy the original cc/bcc.
			to = mi.Envelope.To || []
		} else {
			if (mi.Envelope.ReplyTo && mi.Envelope.ReplyTo.length > 0) {
				to = mi.Envelope.ReplyTo
			} else {
				to = mi.Envelope.From || []
			}
			if (all) {
				for (const a of (mi.Envelope.To || [])) {
					if (!contains(to, a) && !envelopeIdentity([a])) {
						to.push(a)
					}
				}
			}
		}
		if (all) {
			cc = mi.Envelope.CC || []
			bcc = mi.Envelope.BCC || []
		}
		cc = cc.filter((a, i) => !envelopeIdentity([a]) && !contains(to, a) && !contains(cc.slice(0, i), a))
		bcc = bcc.filter(a => !envelopeIdentity([a]))
		await react(to, cc, bcc, false)
	}
	const cmdForward = async () => { react([], [], [], true) }
	const cmdReplyList = async () => {
		const pm = await parsedMessagePromise
		if (pm.ListReplyAddress) {
			await react([pm.ListReplyAddress], [], [], false)
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
	const cmdOpenRawPart = async () => {
		const pm = await parsedMessagePromise
		let path: number[] | null = null
		if (urlType === 'text' && pm.TextPaths && pm.TextPaths.length > 0) {
			path = pm.TextPaths[0]
		} else if ((urlType === 'html' || urlType === 'htmlexternal') && pm.HTMLPath) {
			path = pm.HTMLPath
		}
		if (!path) {
			window.alert('Part not found.')
			return
		}
		window.open('msg/'+m.ID+'/viewtext/'+[0, ...path].join('.'), '_blank')
	}
	const cmdDownloadRaw = async () => { window.open('msg/'+m.ID+'/rawdl', '_blank') }
	const cmdViewAttachments = async () => {
		if (attachments.length > 0) {
			view(attachments[0])
		}
	}
	const cmdComposeDraft = async () => {
		if (m.MailboxID !== draftMailboxID) {
			return
		}

		// Compose based on message. Most information is available, we just need to find
		// the ID of the stored message this is a reply/forward to, based in In-Reply-To
		// header.
		const env = mi.Envelope
		let refMsgID = 0
		if (env.InReplyTo) {
			refMsgID = await withStatus('Looking up referenced message', client.MessageFindMessageID(env.InReplyTo))
		}

		const pm = await parsedMessagePromise
		const isForward = !!env.Subject.match(/^\[?fwd?:/i) || !!env.Subject.match(/\(fwd\)[ \t]*$/i)
		const opts: ComposeOptions = {
			from: (env.From || []),
			to: (env.To || []).map(a => formatAddress(a)),
			cc: (env.CC || []).map(a => formatAddress(a)),
			bcc: (env.BCC || []).map(a => formatAddress(a)),
			replyto: env.ReplyTo && env.ReplyTo.length > 0 ? formatAddress(env.ReplyTo[0]) : '',
			subject: env.Subject,
			isForward: isForward,
			body: pm.Texts && pm.Texts.length > 0 ? pm.Texts[0].replace(/\r/g, '') : '',
			responseMessageID: refMsgID,
			draftMessageID: m.ID,
		}
		compose(opts, listMailboxes)
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

	const fromAddressSettingsSave = async (mode: api.ViewMode) => {
		const froms = mi.Envelope.From || []
		if (froms.length === 1) {
			await withStatus('Saving view mode settings for address', client.FromAddressSettingsSave({FromAddress: froms[0].User + "@" + (froms[0].Domain.Unicode || froms[0].Domain.ASCII), ViewMode: mode}))
		}
	}

	const cmdShowText = async () => {
		if (!textbtn) {
			return
		}
		loadText(await parsedMessagePromise)
		activeBtn(textbtn)
		await fromAddressSettingsSave(api.ViewMode.ModeText)
	}
	const cmdShowHTML = async () => {
		if (!htmlbtn || !htmlextbtn) {
			return
		}
		loadHTML()
		activeBtn(htmlbtn)
		await fromAddressSettingsSave(api.ViewMode.ModeHTML)
	}
	const cmdShowHTMLExternal = async () => {
		if (!htmlbtn || !htmlextbtn) {
			return
		}
		loadHTMLexternal()
		activeBtn(htmlextbtn)
		await fromAddressSettingsSave(api.ViewMode.ModeHTMLExt)
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
				css('internalsList', {listStyle: 'disc', marginLeft: '1em'}),
				(p.Parts || []).map(pp => mimepart(pp))
			)
		)
		popup(
			css('popupInternals', {display: 'flex', gap: '1em'}),
			dom.div(dom.h1('Mime structure'), dom.ul(css('internalsList', {listStyle: 'disc', marginLeft: '1em'}), mimepart(pm.Part))),
			dom.div(css('internalsMessage', {whiteSpace: 'pre-wrap', tabSize: 4, maxWidth: '50%'}), dom.h1('Message'), JSON.stringify(m, undefined, '\t')),
			dom.div(css('internalsParts', {whiteSpace: 'pre-wrap', tabSize: 4, maxWidth: '50%'}), dom.h1('Part'), JSON.stringify(pm.Part, undefined, '\t')),
		)
	}

	const cmdUp = async () => { msgscrollElem.scrollTo({top: msgscrollElem.scrollTop - 3*msgscrollElem.getBoundingClientRect().height / 4, behavior: 'smooth'}) }
	const cmdDown = async () => { msgscrollElem.scrollTo({top: msgscrollElem.scrollTop + 3*msgscrollElem.getBoundingClientRect().height / 4, behavior: 'smooth'}) }
	const cmdHome = async () => { msgscrollElem.scrollTo({top: 0 }) }
	const cmdEnd = async () => { msgscrollElem.scrollTo({top: msgscrollElem.scrollHeight}) }

	const shortcuts: {[key: string]: command} = {
		e: cmdComposeDraft,
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
		'ctrl i': cmdToggleHeaders,

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

	let msgbuttonElem: HTMLElement, msgheaderElem: HTMLTableSectionElement, msgattachmentElem: HTMLElement, msgmodeElem: HTMLElement
	let msgheaderFullElem: HTMLTableElement // Full headers, when enabled.

	const msgmetaElem = dom.div(
		css('msgmeta', {backgroundColor: styles.backgroundColorMild, borderBottom: '5px solid', borderBottomColor: ['white', 'black'], maxHeight: '90%', overflowY: 'auto'}),
		attr.role('region'), attr.arialabel('Buttons and headers for message'),
		msgbuttonElem=dom.div(),
		dom.div(
			attr.arialive('assertive'),
			dom.table(
				styleClasses.msgHeaders,
				msgheaderElem=dom.tbody(),
			),
			msgheaderFullElem=dom.table(),
			msgattachmentElem=dom.div(),
			msgmodeElem=dom.div(),
		),
		// Explicit separator that separates headers from body, to
		// prevent HTML messages from faking UI elements.
		dom.div(css('headerBodySeparator', {height: '2px', backgroundColor: styles.borderColor})),
	)

	const msgscrollElem = dom.div(dom._class('pad'), yscrollAutoStyle,
		attr.role('region'), attr.arialabel('Message body'),
		css('msgscroll', {backgroundColor: styles.backgroundColor}),
	)
	const msgcontentElem = dom.div(
		css('scrollparent', {position: 'relative', flexGrow: '1'}),
	)

	const trashMailboxID = listMailboxes().find(mb => mb.Trash)?.ID
	const draftMailboxID = listMailboxes().find(mb => mb.Draft)?.ID

	// Initially called with potentially null pm, once loaded called again with pm set.
	const loadButtons = (pm: api.ParsedMessage | null) => {
		dom._kids(msgbuttonElem,
			dom.div(dom._class('pad'),
				m.MailboxID === draftMailboxID ? dom.clickbutton('Edit', attr.title('Continue editing this draft message.'), clickCmd(cmdComposeDraft, shortcuts)) : [], ' ',
				(!pm || !pm.ListReplyAddress) ? [] : dom.clickbutton('Reply to list', attr.title('Compose a reply to this mailing list.'), clickCmd(cmdReplyList, shortcuts)), ' ',
				(pm && pm.ListReplyAddress && formatEmail(pm.ListReplyAddress) === fromAddress) ? [] : dom.clickbutton('Reply', attr.title('Compose a reply to the sender of this message.'), clickCmd(cmdReply, shortcuts)), ' ',
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
							css('popupMore', {display: 'flex', flexDirection: 'column', gap: '.5ex', textAlign: 'right'}),
							[
								dom.clickbutton('Print', attr.title('Print message, opens in new tab and opens print dialog.'), clickCmd(cmdPrint, shortcuts)),
								dom.clickbutton('Mark Not Junk', attr.title('Mark as not junk, causing this message to be used in spam classification of new incoming messages.'), clickCmd(msglistView.cmdMarkNotJunk, shortcuts)),
								dom.clickbutton('Mark Read', clickCmd(msglistView.cmdMarkRead, shortcuts)),
								dom.clickbutton('Mark Unread', clickCmd(msglistView.cmdMarkUnread, shortcuts)),
								dom.clickbutton('Mute thread', clickCmd(msglistView.cmdMute, shortcuts)),
								dom.clickbutton('Unmute thread', clickCmd(msglistView.cmdUnmute, shortcuts)),
								dom.clickbutton('Open in new tab', clickCmd(cmdOpenNewTab, shortcuts)),
								dom.clickbutton('Download raw original message', clickCmd(cmdDownloadRaw, shortcuts)),
								dom.clickbutton('Export as ...', function click(e: {target: HTMLElement}) {
									popoverExport(e.target, '', [m.ID])
								}),
								dom.clickbutton('Show raw original message in new tab', clickCmd(cmdOpenRaw, shortcuts)),
								dom.clickbutton('Show currently displayed part as decoded text', clickCmd(cmdOpenRawPart, shortcuts)),
								dom.clickbutton('Show internals in popup', clickCmd(cmdShowInternals, shortcuts)),
							].map(b => dom.div(b)),
						),
					)
				}),
			)
		)
	}
	loadButtons(parsedMessageOpt || null)

	loadMsgheaderView(msgheaderElem, miv.messageitem, accountSettings.ShowHeaders || [], refineKeyword, false)

	// Similar to lib.ts:/msgHeaderFieldStyle
	const headerTextMildStyle = css('headerTextMild', {textAlign: 'right', color: styles.colorMild})
	const loadHeaderDetails = (pm: api.ParsedMessage) => {
		const table = dom.table(
			css('msgHeaderDetails', {width: '100%'}),
			!settings.showAllHeaders ? [] :
				Object.entries(pm.Headers || {}).sort().map(t =>
					(t[1] || []).map(v =>
						dom.tr(
							dom.td(t[0]+':', headerTextMildStyle),
							dom.td(v),
						)
					)
				)
		)
		msgheaderFullElem.replaceWith(table)
		msgheaderFullElem = table
	}

	const isText = (a: api.Attachment) => ['text', 'message'].includes(a.Part.MediaType.toLowerCase())
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

		const attachmentsArrowStyle = css('attachmentsArrow', {color: styles.backgroundColor, backgroundColor: styles.color, width: '2em', height: '2em', borderRadius: '1em', lineHeight: '2em', textAlign: 'center', fontWeight: 'bold'})
		const attachmentsIframeStyle = css('attachmentsIframe', {flexGrow: 1, boxShadow: styles.boxShadow, margin: '0 5em'})

		let content: HTMLElement
		const popupRoot = dom.div(
			css('attachmentsOverlay', {position: 'fixed', left: 0, right: 0, top: 0, bottom: 0, backgroundColor: styles.overlayBackgroundColor, display: 'flex', flexDirection: 'column', alignContent: 'stretch', padding: '1em', zIndex: zindexes.attachments}),
			function click(e: MouseEvent) {
				e.stopPropagation()
				cmdViewClose()
			},
			attr.tabindex('0'),
			!(index > 0) ? [] : dom.div(
				css('attachmentsPrevious', {position: 'absolute', left: '1em', top: 0, bottom: 0, fontSize: '1.5em', width: '2em', display: 'flex', alignItems: 'center', cursor: 'pointer'}),
				dom.div(dom._class('silenttitle'),
					attachmentsArrowStyle,
					attr.title('To previous viewable attachment.'),
					'←',
				),
				attr.tabindex('0'),
				clickCmd(cmdViewPrev, attachShortcuts),
				enterCmd(cmdViewPrev, attachShortcuts),
			),
			dom.div(
				css('attachmentsDownloadHeaderBox', {textAlign: 'center', paddingBottom: '30px'}),
				dom.span(dom._class('pad'),
					function click(e: MouseEvent) {
						e.stopPropagation()
					},
					css('attachmentsDownloadHeader', {backgroundColor: styles.popupBackgroundColor, color: styles.popupColor, boxShadow: styles.boxShadow, border: '1px solid', borderColor: styles.popupBorderColor, borderRadius: '.25em'}),
					a.Filename || '(unnamed)', ' - ',
					formatSize(a.Part.DecodedSize), ' - ',
					dom.a('Download', attr.download(''), attr.href('msg/'+m.ID+'/download/'+pathStr), function click(e: MouseEvent) { e.stopPropagation() }),
				),
			),
			isImage(a) ?
				dom.div(
					css('attachmentsImageBox', {flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', maxHeight: 'calc(100% - 50px)', margin: '0 5em'}),
					dom.img(
						css('attachmentsImage', {maxWidth: '100%', maxHeight: '100%', boxShadow: styles.boxShadow , margin: '0 30px'}),
						attr.src('msg/'+m.ID+'/view/'+pathStr)
					),
				) : (
					isText(a) ?
						dom.iframe(
							attr.title('Attachment shown as text.'),
							attachmentsIframeStyle,
							attr.src('msg/'+m.ID+'/viewtext/'+pathStr)
						) : (
							isPDF(a) ?
								dom.iframe(
									attr.title('Attachment as PDF.'),
									attachmentsIframeStyle,
									attr.src('msg/'+m.ID+'/view/'+pathStr)
								) :
								content=dom.div(
									function click(e: MouseEvent) {
										e.stopPropagation()
									},
									css('attachmentsBinary', {minWidth: '30em', padding: '2ex', boxShadow: styles.boxShadow, backgroundColor: styles.popupBackgroundColor, margin: '0 5em', textAlign: 'center'}),
									dom.div(style({marginBottom: '2ex'}), 'Attachment could be a binary file.'),
									dom.clickbutton('View as text', function click() {
										content.replaceWith(
											dom.iframe(
												attr.title('Attachment shown as text, though it could be a binary file.'),
												attachmentsIframeStyle,
												attr.src('msg/'+m.ID+'/viewtext/'+pathStr)
											)
										)
									}),
						)
					)
				),
			!(index < attachments.length-1) ? [] : dom.div(
				css('attachmentsNext', {position: 'absolute', right: '1em', top: 0, bottom: 0, fontSize: '1.5em', width: '2em', display: 'flex', alignItems: 'center', cursor: 'pointer'}),
				dom.div(dom._class('silenttitle'),
					attachmentsArrowStyle,
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

	var filesAll = false
	const renderAttachments = () => {
		const l = mi.Attachments || []
		dom._kids(msgattachmentElem,
			(l && l.length === 0) ? [] : dom.div(
				css('inlineAttachmentsSeparator', {borderTop: '1px solid', borderTopColor: styles.borderColor}),
				dom.div(dom._class('pad'),
					'Attachments: ',
					l.slice(0, filesAll ? l.length : 4).map(a => {
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
							return [dom.span(dom._class('btngroup'), urlType === 'text' && isImage(a) ? style({opacity: '.6'}) : [], viewbtn, dlbtn), ' ']
						}
						return [dom.span(dom._class('btngroup'), dlbtn, viewbtn), ' ']
					}),
					filesAll || l.length < 6 ? [] : dom.clickbutton('More...', function click() {
						filesAll = true
						renderAttachments()
					}), ' ',
					dom.a('Download all as zip', attr.download(''), style({color: 'inherit'}), attr.href('msg/'+m.ID+'/attachments.zip')),
				),
			)
		)
	}
	renderAttachments()

	const root = dom.div(css('msgViewRoot', {position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, display: 'flex', flexDirection: 'column'}))
	dom._kids(root, msgmetaElem, msgcontentElem)

	const loadText = (pm: api.ParsedMessage): void => {
		// We render text ourselves so we can make links clickable and get any selected
		// text to use when writing a reply. We still set url so the text content can be
		// opened in a separate tab, even though it will look differently.
		urlType = 'text'
		const elem = dom.div(dom._class('mono', 'textmulti'),
			style({whiteSpace: 'pre-wrap'}),
			(pm.Texts || []).map(t => renderText(t.replace(/\r\n/g, '\n'))),
			(mi.Attachments || []).filter(f => isImage(f)).map(f => {
				const pathStr = [0].concat(f.Path || []).join('.')
				return dom.div(
					dom.div(
						css('msgAttachmentBox', {flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', maxHeight: 'calc(100% - 50px)'}),
						dom.img(
							attr.src('msg/'+m.ID+'/view/'+pathStr),
							attr.title(f.Filename),
							css('msgInlineImage', {boxShadow: styles.boxShadow, maxWidth: '100%', maxHeight: '100%'})
						),
					)
				)
			}),
		)
		dom._kids(msgcontentElem)
		dom._kids(msgscrollElem, elem)
		dom._kids(msgcontentElem, msgscrollElem)
		renderAttachments() // Rerender opaciy on inline images.
	}
	const loadHTML = (): void => {
		urlType = 'html'
		dom._kids(msgcontentElem,
			dom.iframe(
				attr.tabindex('0'),
				attr.title('HTML version of message with images inlined, without external resources loaded.'),
				attr.src('msg/'+m.ID+'/'+urlType),
				css('msgIframeHTML', {position: 'absolute', width: '100%', height: '100%'}),
			)
		)
		renderAttachments() // Rerender opaciy on inline images.
	}
	const loadHTMLexternal = (): void => {
		urlType = 'htmlexternal'
		dom._kids(msgcontentElem,
			dom.iframe(
				attr.tabindex('0'),
				attr.title('HTML version of message with images inlined and with external resources loaded.'),
				attr.src('msg/'+m.ID+'/'+urlType),
				css('msgIframeHTML', {position: 'absolute', width: '100%', height: '100%'}),
			)
		)
		renderAttachments() // Rerender opaciy on inline images.
	}

	const mv: MsgView = {
		root: root,
		messageitem: mi,
		key: keyHandler(shortcuts),
		aborter: { abort: () => {} },
		updateKeywords: async (modseq: number, keywords: string[]) => {
			mi.Message.ModSeq = modseq
			mi.Message.Keywords = keywords
			loadMsgheaderView(msgheaderElem, miv.messageitem, accountSettings.ShowHeaders || [], refineKeyword, false)
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

		const msgHeaderSeparatorStyle = css('msgHeaderSeparator', {borderTop: '1px solid', borderTopColor: styles.borderColor})
		const msgModeWarningStyle = css('msgModeWarning', {backgroundColor: styles.warningBackgroundColor, padding: '0 .15em'})

		const htmlNote = 'In the HTML viewer, the following potentially dangerous functionality is disabled: submitting forms, starting a download from a link, navigating away from this page by clicking a link. If a link does not work, try explicitly opening it in a new tab.'
		const haveText = pm.Texts && pm.Texts.length > 0
		if (!haveText && !pm.HasHTML) {
			dom._kids(msgcontentElem)
			dom._kids(msgmodeElem,
				dom.div(dom._class('pad'),
					msgHeaderSeparatorStyle,
					dom.span('No textual content', msgModeWarningStyle),
				),
			)
		} else if (haveText && !pm.HasHTML) {
			loadText(pm)
			dom._kids(msgmodeElem)
		} else {
			const text = haveText && pm.ViewMode == api.ViewMode.ModeText
			dom._kids(msgmodeElem,
				dom.div(dom._class('pad'),
					msgHeaderSeparatorStyle,
					!haveText ? dom.span('HTML-only message', attr.title(htmlNote), msgModeWarningStyle, style({marginRight: '.25em'})) : [],
					dom.span(dom._class('btngroup'),
						haveText ? textbtn=dom.clickbutton(text ? dom._class('active') : [], 'Text', clickCmd(cmdShowText, shortcuts)) : [],
						htmlbtn=dom.clickbutton(text || !text && pm.ViewMode == api.ViewMode.ModeHTMLExt ? [] : dom._class('active'), 'HTML', attr.title(htmlNote), async function click() {
							// Shortcuts has a function that cycles through html and htmlexternal.
							showShortcut('T')
							await cmdShowHTML()
						}),
						htmlextbtn=dom.clickbutton(text || !text && pm.ViewMode != api.ViewMode.ModeHTMLExt ? [] : dom._class('active'), 'HTML with external resources', attr.title(htmlNote), clickCmd(cmdShowHTMLExternal, shortcuts)),
					),
				)
			)
			if (text) {
				loadText(pm)
			} else if (pm.ViewMode == api.ViewMode.ModeHTMLExt) {
				loadHTMLexternal()
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
				const mailboxIsReject = () => !!listMailboxes().find(mb => mb.ID === miv.messageitem.Message.MailboxID && mb.Name === rejectsMailbox)
				if (!miv.messageitem.Message.Junk && !miv.messageitem.Message.Notjunk && miv.messageitem.Message.Seen && miv.messageitem.Message.ID === msglistView.activeMessageID() && !mailboxIsReject()) {
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
	activeMailbox: () => api.Mailbox | null
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

const newMsglistView = (msgElem: HTMLElement, activeMailbox: () => api.Mailbox | null, listMailboxes: listMailboxes, setLocationHash: setLocationHash, otherMailbox: otherMailbox, possibleLabels: possibleLabels, scrollElemHeight: () => number, refineKeyword: (kw: string) => Promise<void>, viewportEnsureMessages: () => Promise<void>): MsglistView => {
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
		if (!window.confirm('Are you sure you want to permanently delete?')) {
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
	const cmdMarkUnread = async () => { await withStatus('Marking as not read', client.FlagsClear(mlv.selected().map(miv => miv.messageitem.Message.ID), ['\\seen', '$junk', '$notjunk'])) }
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
					css('multimsgBg', {position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, display: 'flex', alignItems: 'center', justifyContent: 'center'}),
					dom.div(
						css('multimsgBox', {backgroundColor: styles.backgroundColor, border: '1px solid', borderColor: styles.borderColor, padding: '4ex', borderRadius: '.25em'}),
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
							dom.clickbutton('Unmute thread', clickCmd(cmdUnmute, shortcuts)), ' ',
							dom.clickbutton('Export as...', function click(e: {target: HTMLElement}) {
								popoverExport(e.target, '', effselected.map(miv => miv.messageitem.Message.ID))
							}),

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
					// Commonly bound to "focus to browser address bar", moving cursor to one page down
					// without opening isn't useful enough.
					if (e.key === 'l' && e.ctrlKey) {
						return
					}

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
					// Commonly bound to "view source", moving cursor to next unread message without
					// opening isn't useful enough.
					if (e.key === 'u' && e.ctrlKey) {
						return
					}

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
		activeMailbox: () => activeMailbox(),
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

// Export messages to maildir/mbox in tar/tgz/zip/no container. Either all
// messages, messages in from 1 mailbox, or explicit message ids.
const popoverExport = (reference: HTMLElement, mailboxName: string, messageIDs: number[] | null) => {
	let format: HTMLInputElement
	let archive: HTMLInputElement
	let mboxbtn: HTMLButtonElement
	const removeExport = popover(reference, {},
		dom.h1('Export'),
		dom.form(
			function submit() {
				// If we would remove the popup immediately, the form would be deleted too and never submitted.
				window.setTimeout(() => removeExport(), 100)
			},
			attr.target('_blank'), attr.method('POST'), attr.action('export'),
			dom.input(attr.type('hidden'), attr.name('csrf'), attr.value(localStorageGet('webmailcsrftoken') || '')),
			dom.input(attr.type('hidden'), attr.name('mailbox'), attr.value(mailboxName)),
			dom.input(attr.type('hidden'), attr.name('messageids'), attr.value((messageIDs || []).join(','))),
			format=dom.input(attr.type('hidden'), attr.name('format')),
			archive=dom.input(attr.type('hidden'), attr.name('archive')),

			dom.div(css('exportFields', {display: 'flex', flexDirection: 'column', gap: '.5ex'}),
				mailboxName ? dom.div(dom.label(dom.input(attr.type('checkbox'), attr.name('recursive'), attr.value('on'), function change(e: {target: HTMLInputElement}) { mboxbtn.disabled = e.target.checked }), ' Recursive')) : [],
				dom.div(
					!mailboxName && !messageIDs ? 'Mbox ' : mboxbtn=dom.submitbutton('Mbox', attr.title('Export as mbox file, not wrapped in an archive.'), function click() {
						format.value = 'mbox'
						archive.value = 'none'
					}), ' ',
					dom.submitbutton('zip', function click() {
						format.value = 'mbox'
						archive.value = 'zip'
					}), ' ',
					dom.submitbutton('tgz', function click() {
						format.value = 'mbox'
						archive.value = 'tgz'
					}), ' ',
					dom.submitbutton('tar', function click() {
						format.value = 'mbox'
						archive.value = 'tar'
					}),
				),
				dom.div(
					'Maildir ',
					dom.submitbutton('zip', function click() {
						format.value = 'maildir'
						archive.value = 'zip'
					}), ' ',
					dom.submitbutton('tgz', function click() {
						format.value = 'maildir'
						archive.value = 'tgz'
					}), ' ',
					dom.submitbutton('tar', function click() {
						format.value = 'maildir'
						archive.value = 'tar'
					}),
				),
			),
		),
	)
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
	const collapseElem = dom.span(dom._class('mailboxCollapse'), minusbox, function click(e: MouseEvent) {
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
					dom.clickbutton('Mark as read', attr.title('Mark all messages in the mailbox and its sub mailboxes as read.'), async function click() {
						remove()
						const mailboxIDs = [mbv.mailbox.ID, ...mailboxlistView.mailboxes().filter(mb => mb.Name.startsWith(mbv.mailbox.Name+'/')).map(mb => mb.ID)]
						await withStatus('Marking mailboxes as read', client.MailboxesMarkRead(mailboxIDs))
					}),
				),
				dom.div(
					dom.clickbutton('Create mailbox', attr.title('Create new mailbox within this mailbox.'), function click(e: MouseEvent) {
						let fieldset: HTMLFieldSetElement
						let name: HTMLInputElement
						const ref = e.target! as HTMLElement
						const removeCreate = popover(ref, {},
							dom.form(
								async function submit(e: SubmitEvent) {
									e.preventDefault()
									await withStatus('Creating mailbox', client.MailboxCreate(mbv.mailbox.Name + '/' + name.value), fieldset)
									removeCreate()
								},
								fieldset=dom.fieldset(
									dom.label(
										'Name ',
										name=dom.input(attr.required('yes')),
									),
									' ',
									dom.submitbutton('Create'),
								),
							),
						)
						remove()
						name.focus()
					}),
				),
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
					dom.clickbutton('Empty mailbox', attr.title('Remove all messages from the mailbox, but not mailboxes inside this mailbox or their messages.'), async function click() {
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
						name.focus()
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
				dom.div(
					dom.clickbutton('Export as...', function click() {
						popoverExport(actionBtn, mbv.mailbox.Name, null)
						remove()
					}),
				),
			),
		)
	}

	// Keep track of dragenter/dragleave ourselves, we don't get a neat 1 enter and 1
	// leave event from browsers, we get events for multiple of this elements children.
	let drags = 0

	const mailboxItemStyle = css('mailboxItem', {cursor: 'pointer', borderRadius: '.15em', userSelect: 'none'})
	ensureCSS('.mailboxItem.dropping', {background: styles.highlightBackground}, true)
	ensureCSS('.mailboxItem:hover', {backgroundColor: styles.mailboxHoverBackgroundColor})
	ensureCSS('.mailboxItem.active', { background: styles.mailboxActiveBackground})
	ensureCSS('.mailboxHoverOnly', {visibility: 'hidden'})
	ensureCSS('.mailboxItem:hover .mailboxHoverOnly, .mailboxItem:focus .mailboxHoverOnly', {visibility: 'visible'})
	ensureCSS('.mailboxCollapse', {visibility: 'hidden'})
	ensureCSS('.mailboxItem:hover .mailboxCollapse, .mailboxItem:focus .mailboxCollapse', {visibility: 'visible'})

	const root = dom.div(
		mailboxItemStyle,
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
			if (msgIDs.length === 1) {
				const msgID = msgIDs[0]
				const mbSrcID = mailboxMsgIDs.find(mbMsgID => mbMsgID[1] === msgID)![0]
				await moveAskRuleset(msgID, mbSrcID, xmb, mailboxlistView.mailboxes())
			}
		},
		dom.div(
			css('mailbox', {padding: '.15em .25em', display: 'flex', justifyContent: 'space-between'}),
			name=dom.div(css('mailboxName', {whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'})),
			dom.div(
				style({whiteSpace: 'nowrap'}),
				actionBtn=dom.clickbutton(dom._class('mailboxHoverOnly'),
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
				dom.h1('Mailboxes', css('mailboxesTitle', {display: 'inline', fontSize: 'inherit'})),
				' ',

				dom.clickbutton(
					'...',
					attr.arialabel('Mailboxes actions'),
					attr.title('Actions on mailboxes like creating a new mailbox or exporting all email.'),
					function click(e: MouseEvent) {
						e.stopPropagation()

						const remove = popover(e.target! as HTMLElement, {transparent: true},
							dom.div(css('mailboxesActions', {display: 'flex', flexDirection: 'column', gap: '.5ex'}),
								dom.div(
									dom.clickbutton('Create mailbox', attr.arialabel('Create new mailbox.'), attr.title('Create new mailbox.'), style({padding: '0 .25em'}), function click(e: MouseEvent) {
										let fieldset: HTMLFieldSetElement
										let name: HTMLInputElement
										const ref = e.target! as HTMLElement
										const removeCreate = popover(ref, {},
											dom.form(
												async function submit(e: SubmitEvent) {
													e.preventDefault()
													await withStatus('Creating mailbox', client.MailboxCreate(name.value), fieldset)
													removeCreate()
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
										remove()
										name.focus()
									}),
								),
								dom.div(
									dom.clickbutton('Export as...', function click(e: MouseEvent) {
										const ref = e.target! as HTMLElement
										popoverExport(ref, '', null)
										remove()
									}),
								),
							)
						)
					},
				),
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

	const searchTableStyle = css('searchTable', {width: '100%'})
	ensureCSS('.searchTable td', {padding: '.25em'})

	const root = dom.div(
		css('searchOverlay', {position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, backgroundColor: styles.overlayBackgroundColor, zIndex: zindexes.compose}),
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
			css('searchContent', {position: 'absolute', width: '50em', padding: '.5ex', backgroundColor: styles.popupBackgroundColor, boxShadow: styles.boxShadow, border: '1px solid', borderColor: styles.popupBorderColor, color: styles.popupColor, borderRadius: '.15em'}),
			function click(e: MouseEvent) {
				e.stopPropagation()
			},
			// This is a separate form, inside the form with the overall search field because
			// when updating the form based on the parsed searchbar, we first need to reset it.
			form=dom.form(
				dom.table(searchTableStyle,
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
										css('searchFlagTrue', {backgroundColor: styles.buttonTristateOnBackground}, true)
										css('searchFlagFalse', {backgroundColor: styles.buttonTristateOffBackground}, true)
										v.root.classList.toggle('searchFlagTrue', v.active===true)
										v.root.classList.toggle('searchFlagFalse', v.active===false)
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

// parse the "mailto:..." part (already decoded) of a "#compose mailto:..." url hash.
const parseComposeMailto = (mailto: string): ComposeOptions => {
	const u = new URL(mailto)

	const addresses = (s: string) => s.split(',').filter(s => !!s)
	const opts: ComposeOptions = {}
	opts.to = addresses(u.pathname).map(s => decodeURIComponent(s))
	for (const [xk, v] of new URLSearchParams(u.search)) {
		const k = xk.toLowerCase()
		if (k === 'to') {
			opts.to = [...opts.to, ...addresses(v)]
		} else if (k === 'cc') {
			opts.cc = [...(opts.cc || []), ...addresses(v)]
		} else if (k === 'bcc') {
			opts.bcc = [...(opts.bcc || []), ...addresses(v)]
		} else if (k === 'subject') {
			// q/b-word encoding is allowed, we let the server decode when we start composoing,
			// only if needed. ../rfc/6068:267
			opts.subject = v
		} else if (k === 'body') {
			opts.body = v
		}
		// todo: we ignore other headers for now. we should handle in-reply-to and references at some point. but we don't allow any custom headers at the time of writing.
	}
	return opts
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
	let accountElem: HTMLElement
	let loginAddressElem: HTMLElement

	let msglistscrollElem: HTMLElement
	let queryactivityElem: HTMLElement // We show ... when a query is active and data is forthcoming.

	// Shown at the bottom of msglistscrollElem, immediately below the msglistView, when appropriate.
	const listendElem = dom.div(css('msgListEnd', {borderTop: '1px solid', borderColor: styles.borderColor, color: styles.colorMilder, margin: '1ex'}))
	const listloadingElem = dom.div(css('msgListLoading', {textAlign: 'center', padding: '.15em 0', color: styles.colorMild, border: '1px solid', borderColor: styles.borderColor, margin: '1ex', backgroundColor: styles.backgroundColorMild}), 'loading...')
	const listerrElem = dom.div(css('msgListErr', {textAlign: 'center', padding: '.15em 0', color: styles.colorMild, border: '1px solid', borderColor: styles.borderColor, margin: '1ex', backgroundColor: styles.backgroundColorMild}))

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

	;[moxversion, moxgoos, moxgoarch] = await client.Version()

	const updatePageTitle = () => {
		const mb = mailboxlistView && mailboxlistView.activeMailbox()
		const addr = loginAddress ? loginAddress.User+'@'+formatDomain(loginAddress.Domain) : ''
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
		searchbarElem.classList.toggle('searchbarActive', true) // Cleared when another view is loaded.
		searchbarElemBox.style.flexGrow = '4'
	}
	const unloadSearch = () => {
		searchbarElem.value = ''
		searchbarElem.classList.toggle('searchbarActive', false)
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
		css('msgElem', {position: 'absolute', right: 0, left: 0, top: 0, bottom: 0, backgroundColor: styles.backgroundColorMild}),
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
	const activeMailbox = () => mailboxlistView.activeMailbox()
	const msglistView = newMsglistView(msgElem, activeMailbox, listMailboxes, setLocationHash, otherMailbox, possibleLabels, () => msglistscrollElem ? msglistscrollElem.getBoundingClientRect().height : 0, refineKeyword, viewportEnsureMessages)
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

	const msgColumnDraggerStyle = css('msgColumnDragger', {position: 'absolute', top: 0, bottom: 0, width: '1px', backgroundColor: styles.popupBorderColor, left: '2.5px'})

	let msglistElem = dom.div(css('msgList', {backgroundColor: styles.msglistBackgroundColor, position: 'absolute', left: '0', right: 0, top: 0, bottom: 0, display: 'flex', flexDirection: 'column'}),
		dom.div(
			attr.role('region'), attr.arialabel('Filter and sorting buttons for message list'),
			css('msgListFilterSorting', {display: 'flex', justifyContent: 'space-between', backgroundColor: styles.backgroundColorMild, borderBottom: '1px solid', borderBottomColor: styles.borderColor, padding: '.25em .5em'}),
			dom.div(
				dom.h1('Refine:', css('refineTitle', {fontWeight: 'normal', fontSize: 'inherit', display: 'inline', margin: 0}), attr.title('Refine message listing with quick filters. These refinement filters are in addition to any search criteria, but the refine attachment filter overrides a search attachment criteria.')),
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
											dom.clickbutton(styleClasses.keyword, keywordButtonStyle, l, async function click() {
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
			dom.div(dom._class('msgItemFlags')),
			dom.div(dom._class('msgItemFlagsOffset'), css('msgItemFlagsGrab', {position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize'}),
				dom.div(msgColumnDraggerStyle),
				function mousedown(e: MouseEvent) {
					startDrag(e, (e) => {
						const bounds = msglistscrollElem.getBoundingClientRect()
						const width = Math.round(e.clientX - bounds.x)
						settingsPut({...settings, msglistflagsWidth: width})
						updateMsglistWidths()
					})
				}
			),
			dom.div(dom._class('msgItemFrom')),
			dom.div(dom._class('msgItemFromOffset'), css('msgItemFlagsGrab', {position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize'}),
				dom.div(msgColumnDraggerStyle),
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
			dom.div(dom._class('msgItemSubject')),
			dom.div(dom._class('msgItemSubjectOffset'), css('msgItemFlagsGrab', {position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize'}),
				dom.div(msgColumnDraggerStyle),
				function mousedown(e: MouseEvent) {
					startDrag(e, (e) => {
						const bounds = msglistscrollElem.getBoundingClientRect()
						const width = Math.round(bounds.x+bounds.width - e.clientX)
						settingsPut({...settings, msglistageWidth: width})
						updateMsglistWidths()
					})
				}
			),
			dom.div(dom._class('msgItemAge')),
		),
		dom.div(
			style({flexGrow: '1', position: 'relative'}),
			msglistscrollElem=dom.div(yscrollStyle,
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
		searchbarElem.classList.toggle('searchbarActive', true) // Cleared when another view is loaded.
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

	const cmdCompose = async () => {
		let body = ''
		let sig = accountSettings?.Signature || ''
		if (sig) {
			body += '\n\n' + sig
		}
		compose({body: body, editOffset: 0}, listMailboxes)
	}
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
		'ctrl !': cmdSettings,
	}

	const topMailboxesStyle = css('topMailboxes', {backgroundColor: styles.mailboxesTopBackgroundColor})
	css('searchbarActive', {background: styles.mailboxActiveBackground}) // class set on searchbarElem when active.

	const webmailroot = dom.div(
		css('webmailRoot', {display: 'flex', flexDirection: 'column', alignContent: 'stretch', height: '100dvh'}),
		dom.div(topMailboxesStyle,
			style({display: 'flex'}),
			attr.role('region'), attr.arialabel('Top bar'),
			topcomposeboxElem=dom.div(dom._class('pad'),
				style({width: settings.mailboxesWidth + 'px', textAlign: 'center'}),
				dom.clickbutton('Compose', attr.title('Compose new email message.'), function click() {
					shortcutCmd(cmdCompose, shortcuts)
				}),
			),
			dom.div(dom._class('pad'),
				css('searchbarBox', {paddingLeft: 0, display: 'flex', flexGrow: 1}),
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
				statusElem=dom.div(css('status', {marginLeft: '.5em', flexGrow: '1'}), attr.role('status')),
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
					dom.clickbutton('Settings', attr.title('Change settings for composing messages.'), clickCmd(cmdSettings, shortcuts)),
					' ',
					accountElem=dom.span(),
					' ',
					loginAddressElem=dom.span(),
					' ',
					dom.clickbutton('Logout', attr.title('Logout, invalidating this session.'), async function click(e: MouseEvent) {
						await withStatus('Logging out', client.Logout(), e.target! as HTMLButtonElement)
						localStorageRemove('webmailcsrftoken')
						if (eventSource) {
							eventSource.close()
							eventSource = null
						}
						// Reload so all state is cleared from memory.
						window.location.reload()
					}),
				),
			),
		),
		dom.div(
			css('mailboxesListMsgBox', {flexGrow: '1', position: 'relative'}),
			mailboxesElem=dom.div(topMailboxesStyle,
				style({width: settings.mailboxesWidth + 'px'}),
				css('mailboxesBox', {display: 'flex', flexDirection: 'column', alignContent: 'stretch', position: 'absolute', left: 0,top: 0, bottom: 0}),
				dom.div(dom._class('pad'), yscrollAutoStyle,
					style({flexGrow: '1', position: 'relative'}),
					mailboxlistView.root,
				),
			),
			mailboxessplitElem=dom.div(
				css('mailboxesListGrab', {position: 'absolute', width: '5px', top: 0, bottom: 0, cursor: 'ew-resize', zIndex: zindexes.splitter}),
				style({left: 'calc('+settings.mailboxesWidth +'px - 2px)'}),
				dom.div(
					css('mailboxesListLine', {position: 'absolute', width: '1px', top: 0, bottom: 0, left: '2px', right: '2px', backgroundColor: styles.popupBorderColor}),
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
			splitElem=dom.div(css('listMsgBox', {position: 'absolute', left: 'calc(' + settings.mailboxesWidth+'px + 1px)', right: 0, top: 0, bottom: 0, borderTop: '1px solid', borderTopColor: styles.borderColor})),
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
		// Assume regular keys generate a 1 character e.key, and others are special for
		// which we may want to treat shift specially too.
		if (e.key.length > 1 && e.shiftKey) {
			l.push('shift')
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
					css('layoutLeft', {position: 'absolute', left: 0, top: 0, bottom: 0}),
					style({width: 'calc(' + settings.leftWidthPct + '% - 1px)'}),
					msglistElem,
				),
				split=dom.div(
					css('listMsgLeftRightGrab', {position: 'absolute', width: '5px', top: 0, bottom: 0, cursor: 'ew-resize', zIndex: zindexes.splitter}),
					style({left: 'calc(' + settings.leftWidthPct + '% - 2px)'}),
					dom.div(css('listMsgLeftRightLine', {position: 'absolute', backgroundColor: styles.popupBorderColor, top: 0, bottom: 0, width: '1px', left: '2px', right: '2px'})),
					async function mousedown(e: MouseEvent) {
						// Disable pointer events on the message view. If it has an iframe with a message,
						// mouse events while dragging would be consumed by the iframe, breaking our
						// resize.
						right.style.pointerEvents = 'none'
						await startDrag(e, (e) => {
							const bounds = left.getBoundingClientRect()
							const x = Math.round(e.clientX - bounds.x)
							left.style.width = 'calc(' + x +'px - 1px)'
							split.style.left = 'calc(' + x +'px - 2px)'
							right.style.left = 'calc(' + x+'px + 1px)'
							settingsPut({...settings, leftWidthPct: Math.round(100*bounds.width/splitElem.getBoundingClientRect().width)})
							updateMsglistWidths()
						})
						right.style.pointerEvents = ''
					}
				),
				right=dom.div(
					css('layoutRight', {position: 'absolute', right: 0, top: 0, bottom: 0}),
					style({left: 'calc(' + settings.leftWidthPct + '% + 1px)'}),
					msgElem,
				),
			)
		} else {
			let top: HTMLElement, split: HTMLElement, bottom: HTMLElement
			dom._kids(splitElem,
				top=dom.div(
					css('layoutTop', {position: 'absolute', top: 0, left: 0, right: 0}),
					style({height: 'calc(' + settings.topHeightPct + '% - 1px)'}),
					msglistElem,
				),
				split=dom.div(
					css('listMsgTopBottomGrab', {position: 'absolute', height: '5px', left: '0', right: '0', cursor: 'ns-resize', zIndex: zindexes.splitter}),
					style({top: 'calc(' + settings.topHeightPct + '% - 2px)'}),
					dom.div(css('listmsgTopBottomLine', {position: 'absolute', backgroundColor: styles.popupBorderColor, left: 0, right: 0, height: '1px', top: '2px', bottom: '2px'})),
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
					css('layoutBottom', {position: 'absolute', bottom: 0, left: 0, right: 0}),
					style({top: 'calc(' + settings.topHeightPct + '% + 1px)'}),
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
		const cssRules: [string, {[style: string]: number | string}][] = [
			['.msgItemFlags', {width: flagswidth}],
			['.msgItemFrom', {width: fromwidth, position: 'relative'}],
			['.msgItemSubject', {width: subjectwidth}],
			['.msgItemAge', {width: agewidth, 'text-align': 'right'}],
			['.msgItemFlagsOffset', {left: flagswidth}],
			['.msgItemFromOffset', {left: flagswidth + fromwidth}],
			['.msgItemSubjectOffset', {left: flagswidth + fromwidth + subjectwidth}],
		]
		if (!rulesInserted) {
			cssRules.forEach((rule, i) => { stylesheet.insertRule(rule[0] + '{}', i) })
			rulesInserted = true
		}
		cssRules.forEach((rule, i) => {
			const r = stylesheet.cssRules[i] as CSSStyleRule
			for (const k in rule[1]) {
				let v = rule[1][k]
				if (typeof v !== 'string') {
					v = ''+v+'px'
				}
				r.style.setProperty(k, v)
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
	if ((window as any).moxBeforeDisplay) {
		moxBeforeDisplay(webmailroot)
	}
	dom._kids(page, webmailroot)
	checkMsglistWidth()

	window.addEventListener('resize', function() {
		if (layoutElem.value === 'auto') {
			autoselectLayout()
		}
		checkMsglistWidth()
	})

	window.addEventListener('hashchange', async (e: HashChangeEvent) => {
		const hash = decodeURIComponent(window.location.hash)
		if (hash.startsWith('#compose ')) {
			try {
				const opts = parseComposeMailto(hash.substring('#compose '.length))

				// Restore previous hash.
				if (e.oldURL) {
					const ou = new URL(e.oldURL)
					window.location.hash = ou.hash
				} else {
					window.location.hash = ''
				}

				(async () => {
					// Resolve Q/B-word mime encoding for subject. ../rfc/6068:267 ../rfc/2047:180
					if (opts.subject && opts.subject.includes('=?')) {
						opts.subject = await withStatus('Decoding MIME words for subject', client.DecodeMIMEWords(opts.subject))
					}
					compose(opts, listMailboxes)
				})()
			} catch (err) {
				window.alert('Error parsing compose mailto URL: '+errmsg(err))
				window.location.hash = ''
			}
			return
		}

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
	window.addEventListener('beforeunload', (e: BeforeUnloadEvent) => {
		if (composeView && composeView.unsavedChanges()) {
			e.preventDefault()
		} else {
			leaving = true
			if (eventSource) {
				eventSource.close()
				eventSource = null
				sseID = 0
			}
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
			dom.span(css('connectionStatus', {backgroundColor: styles.warningBackgroundColor, padding: '0 .15em', borderRadius: '.15em'}), 'Not connected', attr.title('Not receiving real-time updates, including of new deliveries.')),
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

	// Set to compose options when we were opened with a mailto URL. We open the
	// compose window after we received the "start" message with our addresses.
	let openComposeOptions: ComposeOptions | undefined

	const connect = async (isreconnect: boolean) => {
		connectionElem.classList.toggle('loading', true)
		dom._kids(connectionElem)
		connectionElem.classList.toggle('loading', false)

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

		const h = decodeURIComponent(window.location.hash)
		if (h.startsWith('#compose ')) {
			try {
				// The compose window is opened when we get the "start" event, which gives us our
				// configuration.
				openComposeOptions = parseComposeMailto(h.substring('#compose '.length))
			} catch (err) {
				window.alert('Error parsing mailto URL: '+errmsg(err))
			}
			window.location.hash = ''
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

		eventSource = new window.EventSource('events?singleUseToken=' + encodeURIComponent(token)+'&request='+encodeURIComponent(JSON.stringify(request))+slow)
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
			document.title = ['(not connected)', loginAddress ? (loginAddress.User+'@'+formatDomain(loginAddress.Domain)) : '', 'Mox Webmail'].filter(s => s).join(' - ')
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
			const data = JSON.parse(e.data)
			if (lastServerVersion && data.Version !== lastServerVersion) {
				if (window.confirm('Server has been updated to a new version. Reload?')) {
					window.location.reload()
					return
				}
			}
			lastServerVersion = data.Version

			const start = checkParse(() => api.parser.EventStart(data))
			log('event start', start)

			accountSettings = start.Settings
			connecting = false
			sseID = start.SSEID
			loginAddress = start.LoginAddress
			dom._kids(accountElem, start.AccountPath ? dom.a(attr.href(start.AccountPath), 'Account') : [])
			const loginAddr = formatEmail(loginAddress)
			dom._kids(loginAddressElem, loginAddr)
			accountAddresses = start.Addresses || []
			accountAddresses.sort((a, b) => {
				if (formatEmail(a) === loginAddr) {
					return -1
				}
				if (formatEmail(b) === loginAddr) {
					return 1
				}
				if (a.Domain.ASCII !== b.Domain.ASCII) {
					return a.Domain.ASCII < b.Domain.ASCII ? -1 : 1
				}
				return a.User < b.User ? -1 : 1
			})
			domainAddressConfigs = start.DomainAddressConfigs || {}
			rejectsMailbox = start.RejectsMailbox

			clearList()

			// If we were opened through a mailto: link, it's time to open the compose window.
			if (openComposeOptions) {
				(async () => {
					// Resolve Q/B-word mime encoding for subject. ../rfc/6068:267 ../rfc/2047:180
					if (openComposeOptions.subject && openComposeOptions.subject.includes('=?')) {
						openComposeOptions.subject = await withStatus('Decoding MIME words for subject', client.DecodeMIMEWords(openComposeOptions.subject))
					}
					compose(openComposeOptions, listMailboxes)
					openComposeOptions = undefined
				})()
			}

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

			// We'll clear noreconnect when we've held a connection for 5 seconds. Firefox
			// disconnects often, on any network change including with docker container starts,
			// such as for integration tests.
			noreconnectTimer = setTimeout(() => {
				noreconnect = false
				noreconnectTimer = 0
			}, 5*1000)
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
		css('unhandledErrorBox', {position: 'absolute', bottom: '1ex', left: '1ex', backgroundColor: 'rgba(255, 110, 110, .9)', maxWidth: '14em', padding: '.25em .5em', borderRadius: '.25em', fontSize: '.8em', wordBreak: 'break-all', zIndex: zindexes.shortcut}),
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
					css('unhandledErrorMsg', {backgroundColor: styles.backgroundColorMild, padding: '1ex', borderRadius: '.15em', border: '1px solid', borderColor: styles.borderColor, whiteSpace: 'pre-wrap'}),
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
