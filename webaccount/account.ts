// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

// From HTML.
declare let page: HTMLElement
declare let moxversion: string

const login = async (reason: string) => {
	return new Promise<string>((resolve: (v: string) => void, _) => {
		const origFocus = document.activeElement
		let reasonElem: HTMLElement
		let fieldset: HTMLFieldSetElement
		let autosize: HTMLElement
		let username: HTMLInputElement
		let password: HTMLInputElement

		const root = dom.div(
			style({position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: '#eee', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: '1', animation: 'fadein .15s ease-in'}),
			dom.div(
				reasonElem=reason ? dom.div(style({marginBottom: '2ex', textAlign: 'center'}), reason) : dom.div(),
				dom.div(
					style({backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto', marginBottom: '20vh'}),
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
									window.localStorage.setItem('webaccountaddress', username.value)
									window.localStorage.setItem('webaccountcsrftoken', token)
								} catch (err) {
									console.log('saving csrf token in localStorage', err)
								}
								root.remove()
								if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
									origFocus.focus()
								}
								resolve(token)
							} catch (err) {
								console.log('login error', err)
								window.alert('Error: ' + errmsg(err))
							} finally {
								fieldset.disabled = false
							}
						},
						fieldset=dom.fieldset(
							dom.h1('Account'),
							dom.label(
								style({display: 'block', marginBottom: '2ex'}),
								dom.div('Email address', style({marginBottom: '.5ex'})),
								autosize=dom.span(dom._class('autosize'),
									username=dom.input(
										attr.required(''),
										attr.placeholder('jane@example.org'),
										function change() { autosize.dataset.value = username.value },
										function input() { autosize.dataset.value = username.value },
									),
								),
							),
							dom.label(
								style({display: 'block', marginBottom: '2ex'}),
								dom.div('Password', style({marginBottom: '.5ex'})),
								password=dom.input(attr.type('password'), attr.required('')),
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

const client = new api.Client().withOptions({csrfHeader: 'x-mox-csrf', login: login}).withAuthToken(localStorageGet('webaccountcsrftoken') || '')

const link = (href: string, anchorOpt: string) => dom.a(attr.href(href), attr.rel('noopener noreferrer'), anchorOpt || href)

const crumblink = (text: string, link: string) => dom.a(text, attr.href(link))
const crumbs = (...l: ElemArg[]) => [
	dom.div(
		style({float: 'right'}),
		localStorageGet('webaccountaddress') || '(unknown)',
		' ',
		dom.clickbutton('Logout', attr.title('Logout, invalidating this session.'), async function click(e: MouseEvent) {
			const b = e.target! as HTMLButtonElement
			try {
				b.disabled = true
				await client.Logout()
			} catch (err) {
				console.log('logout', err)
				window.alert('Error: ' + errmsg(err))
			} finally {
				b.disabled = false
			}

			localStorageRemove('webaccountaddress')
			localStorageRemove('webaccountcsrftoken')
			// Reload so all state is cleared from memory.
			window.location.reload()
		}),
	),
	dom.h1(l.map((e, index) => index === 0 ? e : [' / ', e])),
	dom.br()
]

const errmsg = (err: unknown) => ''+((err as any).message || '(no error message)')

const footer = dom.div(
	style({marginTop: '6ex', opacity: 0.75}),
	link('https://www.xmox.nl', 'mox'),
	' ',
	moxversion,
)

const domainName = (d: api.Domain) => {
	return d.Unicode || d.ASCII
}

const domainString = (d: api.Domain) => {
	if (d.Unicode) {
		return d.Unicode+" ("+d.ASCII+")"
	}
	return d.ASCII
}

const box = (color: string, ...l: ElemArg[]) => [
	dom.div(
		style({
			display: 'inline-block',
			padding: '.25em .5em',
			backgroundColor: color,
			borderRadius: '3px',
			margin: '.5ex 0',
		}),
		l,
	),
	dom.br(),
]

const green = '#1dea20'
const yellow = '#ffe400'
const red = '#ff7443'
const blue = '#8bc8ff'

const index = async () => {
	const [accountFullName, domain, destinations] = await client.Account()

	let fullNameForm: HTMLFormElement
	let fullNameFieldset: HTMLFieldSetElement
	let fullName: HTMLInputElement
	let passwordForm: HTMLFormElement
	let passwordFieldset: HTMLFieldSetElement
	let password1: HTMLInputElement
	let password2: HTMLInputElement
	let passwordHint: HTMLElement

	let importForm: HTMLFormElement
	let importFieldset: HTMLFieldSetElement
	let mailboxFileHint: HTMLElement
	let mailboxPrefixHint: HTMLElement
	let importProgress: HTMLElement
	let importAbortBox: HTMLElement

	const importTrack = async (token: string) => {
		const importConnection = dom.div('Waiting for updates...')
		importProgress.appendChild(importConnection)

		let countsTbody: HTMLElement
		let counts = new Map<string, HTMLElement>() // mailbox -> elem

		let problems: HTMLElement // element

		await new Promise((resolve, reject) => {
			const eventSource = new window.EventSource('importprogress?token=' + encodeURIComponent(token))
			eventSource.addEventListener('open', function(e) {
				console.log('eventsource open', {e})
				dom._kids(importConnection, dom.div('Waiting for updates, connected...'))

				dom._kids(importAbortBox,
					dom.clickbutton('Abort import', attr.title('If the import is not yet finished, it can be aborted and no messages will have been imported.'), async function click() {
						try {
							await client.ImportAbort(token)
						} catch (err) {
							console.log({err})
							window.alert('Error: ' + errmsg(err))
						}
						// On success, the event source will get an aborted notification and shutdown the connection.
					})
				)
			})
			eventSource.addEventListener('error', function(e) {
				console.log('eventsource error', {e})
				dom._kids(importConnection, box(red, 'Connection error'))
				reject({message: 'Connection error'})
			})
			eventSource.addEventListener('count', (e) => {
				const data = JSON.parse(e.data) // {Mailbox: ..., Count: ...}
				console.log('import count event', {e, data})
				if (!countsTbody) {
					importProgress.appendChild(
						dom.div(
							dom.br(),
							dom.h3('Importing mailboxes and messages...'),
							dom.table(
								dom.thead(
									dom.tr(dom.th('Mailbox'), dom.th('Messages')),
								),
								countsTbody=dom.tbody(),
							),
						)
					)
				}
				let elem = counts.get(data.Mailbox)
				if (!elem) {
					countsTbody.appendChild(
						dom.tr(
							dom.td(data.Mailbox),
							elem=dom.td(style({textAlign: 'right'}), ''+data.Count),
						),
					)
					counts.set(data.Mailbox, elem)
				}
				dom._kids(elem, ''+data.Count)
			})
			eventSource.addEventListener('problem', (e) => {
				const data = JSON.parse(e.data) // {Message: ...}
				console.log('import problem event', {e, data})
				if (!problems) {
					importProgress.appendChild(
						dom.div(
							dom.br(),
							dom.h3('Problems during import'),
							problems=dom.div(),
						),
					)
				}
				problems.appendChild(dom.div(box(yellow, data.Message)))
			})
			eventSource.addEventListener('step', (e) => {
				const data = JSON.parse(e.data) // {Title: ...}
				console.log('import step event', {e, data})
				importProgress.appendChild(dom.div(dom.br(), box(blue, 'Step: '+data.Title)))
			})
			eventSource.addEventListener('done', (e) => {
				console.log('import done event', {e})
				importProgress.appendChild(dom.div(dom.br(), box(blue, 'Import finished')))

				eventSource.close()
				dom._kids(importConnection)
				dom._kids(importAbortBox)
				window.sessionStorage.removeItem('ImportToken')

				resolve(null)
			})
			eventSource.addEventListener('aborted', function(e) {
				console.log('import aborted event', {e})

				importProgress.appendChild(dom.div(dom.br(), box(red, 'Import aborted, no message imported')))

				eventSource.close()
				dom._kids(importConnection)
				dom._kids(importAbortBox)
				window.sessionStorage.removeItem('ImportToken')

				reject({message: 'Import aborted'})
			})
		})
	}

	const exportForm = (filename: string) => {
		return dom.form(
			attr.target('_blank'), attr.method('POST'), attr.action('export/'+filename),
			dom.input(attr.type('hidden'), attr.name('csrf'), attr.value(localStorageGet('webaccountcsrftoken') || '')),
			dom.submitbutton('Export'),
		)
	}

	dom._kids(page,
		crumbs('Mox Account'),
		dom.p('NOTE: Not all account settings can be configured through these pages yet. See the configuration file for more options.'),
		dom.div(
			'Default domain: ',
			domain.ASCII ? domainString(domain) : '(none)',
		),
		dom.br(),

		fullNameForm=dom.form(
			fullNameFieldset=dom.fieldset(
				dom.label(
					style({display: 'inline-block'}),
					'Full name',
					dom.br(),
					fullName=dom.input(attr.value(accountFullName), attr.title('Name to use in From header when composing messages. Can be overridden per configured address.')),

				),
				' ',
				dom.submitbutton('Save'),
			),
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				fullNameFieldset.disabled = true
				try {
					await client.AccountSaveFullName(fullName.value)
					fullName.setAttribute('value', fullName.value)
					fullNameForm.reset()
					window.alert('Full name has been changed.')
				} catch (err) {
					console.log({err})
					window.alert('Error: ' + errmsg(err))
				} finally {
					fullNameFieldset.disabled = false
				}
			},
		),
		dom.br(),

		dom.h2('Addresses'),
		dom.ul(
			Object.entries(destinations).sort().map(t =>
				dom.li(
					dom.a(t[0], attr.href('#destinations/'+t[0])),
					t[0].startsWith('@') ? ' (catchall)' : [],
				),
			),
		),
		dom.br(),
		dom.h2('Change password'),
		passwordForm=dom.form(
			passwordFieldset=dom.fieldset(
				dom.label(
					style({display: 'inline-block'}),
					'New password',
					dom.br(),
					password1=dom.input(attr.type('password'), attr.autocomplete('new-password'), attr.required(''), function focus() {
						passwordHint.style.display = ''
					}),
				),
				' ',
				dom.label(
					style({display: 'inline-block'}),
					'New password repeat',
					dom.br(),
					password2=dom.input(attr.type('password'), attr.autocomplete('new-password'), attr.required('')),
				),
				' ',
				dom.submitbutton('Change password'),
			),
			passwordHint=dom.div(
				style({display: 'none', marginTop: '.5ex'}),
				dom.clickbutton('Generate random password', function click(e: MouseEvent) {
					e.preventDefault()
					let b = new Uint8Array(1)
					let s = ''
					const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_;:,<.>/'
					while (s.length < 12) {
						self.crypto.getRandomValues(b)
						if (Math.ceil(b[0]/chars.length)*chars.length > 255) {
							continue // Prevent bias.
						}
						s += chars[b[0]%chars.length]
					}
					password1.type = 'text'
					password2.type = 'text'
					password1.value = s
					password2.value = s
				}),
				dom.div(dom._class('text'),
					box(yellow, 'Important: Bots will try to bruteforce your password. Connections with failed authentication attempts will be rate limited but attackers WILL find weak passwords. If your account is compromised, spammers are likely to abuse your system, spamming your address and the wider internet in your name. So please pick a random, unguessable password, preferrably at least 12 characters.'),
				),
			),
			async function submit(e: SubmitEvent) {
				e.stopPropagation()
				e.preventDefault()
				if (!password1.value || password1.value !== password2.value) {
					window.alert('Passwords do not match.')
					return
				}
				passwordFieldset.disabled = true
				try {
					await client.SetPassword(password1.value)
					window.alert('Password has been changed.')
					passwordForm.reset()
				} catch (err) {
					console.log({err})
					window.alert('Error: ' + errmsg(err))
				} finally {
					passwordFieldset.disabled = false
				}
			},
		),
		dom.br(),
		dom.h2('Export'),
		dom.p('Export all messages in all mailboxes. In maildir or mbox format, as .zip or .tgz file.'),
		dom.table(dom._class('slim'),
			dom.tr(
				dom.td('Maildirs in .tgz'),
				dom.td(exportForm('mail-export-maildir.tgz')),
			),
			dom.tr(
				dom.td('Maildirs in .zip'),
				dom.td(exportForm('mail-export-maildir.zip')),
			),
			dom.tr(
				dom.td('Mbox files in .tgz'),
				dom.td(exportForm('mail-export-mbox.tgz')),
			),
			dom.tr(
				dom.td('Mbox files in .zip'),
				dom.td(exportForm('mail-export-mbox.zip')),
			),
		),
		dom.br(),
		dom.h2('Import'),
		dom.p('Import messages from a .zip or .tgz file with maildirs and/or mbox files.'),
		importForm=dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()

				const request = async (): Promise<api.ImportProgress> => {
					return new Promise((resolve, reject) => {
						// Browsers can do everything. Except show a progress bar while uploading...
						let progressPercentage: HTMLElement
						dom._kids(importProgress,
							dom.div(
								dom.div('Uploading... ', progressPercentage=dom.span()),
							),
						)
						importProgress.style.display = ''

						const xhr = new window.XMLHttpRequest()
						xhr.open('POST', 'import', true)
						xhr.setRequestHeader('x-mox-csrf', localStorageGet('webaccountcsrftoken') || '')
						xhr.upload.addEventListener('progress', (e) => {
							if (!e.lengthComputable) {
								return
							}
							const pct = Math.floor(100*e.loaded/e.total)
							dom._kids(progressPercentage, pct+'%')
						})
						xhr.addEventListener('load', () => {
							console.log('upload done', {xhr: xhr, status: xhr.status})
							if (xhr.status !== 200) {
								reject({message: xhr.status === 400 || xhr.status === 500 ? xhr.responseText : 'status '+xhr.status})
								return
							}
							let resp: api.ImportProgress
							try {
								resp = api.parser.ImportProgress(JSON.parse(xhr.responseText))
							} catch (err) {
								reject({message: 'parsing response json: '+errmsg(err)})
								return
							}
							resolve(resp)
						})
						xhr.addEventListener('error', (e) => reject({message: 'upload error', event: e}))
						xhr.addEventListener('abort', (e) => reject({message: 'upload aborted', event: e}))
						xhr.send(new window.FormData(importForm))
					})
				}
				try {
					const p = request()
					importFieldset.disabled = true
					const result = await p

					try {
						window.sessionStorage.setItem('ImportToken', result.Token)
					} catch (err) {
						console.log('storing import token in session storage', {err})
						// Ignore error, could be some browser security thing like private browsing.
					}

					await importTrack(result.Token)
				} catch (err) {
					console.log({err})
					window.alert('Error: ' + errmsg(err))
				} finally {
					importFieldset.disabled = false
				}
			},
			importFieldset=dom.fieldset(
				dom.div(
					style({marginBottom: '1ex'}),
					dom.label(
						dom.div(style({marginBottom: '.5ex'}), 'File'),
						dom.input(attr.type('file'), attr.required(''), attr.name('file'), function focus() {
							mailboxFileHint.style.display = ''
						}),
					),
					mailboxFileHint=dom.p(style({display: 'none', fontStyle: 'italic', marginTop: '.5ex'}), 'This file must either be a zip file or a gzipped tar file with mbox and/or maildir mailboxes. For maildirs, an optional file "dovecot-keywords" is read additional keywords, like Forwarded/Junk/NotJunk. If an imported mailbox already exists by name, messages are added to the existing mailbox. If a mailbox does not yet exist it will be created.'),
				),
				dom.div(
					style({marginBottom: '1ex'}),
					dom.label(
						dom.div(style({marginBottom: '.5ex'}), 'Skip mailbox prefix (optional)'),
						dom.input(attr.name('skipMailboxPrefix'), function focus() {
							mailboxPrefixHint.style.display = ''
						}),
					),
					mailboxPrefixHint=dom.p(style({display: 'none', fontStyle: 'italic', marginTop: '.5ex'}), 'If set, any mbox/maildir path with this prefix will have it stripped before importing. For example, if all mailboxes are in a directory "Takeout", specify that path in the field above so mailboxes like "Takeout/Inbox.mbox" are imported into a mailbox called "Inbox" instead of "Takeout/Inbox".'),
				),
				dom.div(
					dom.submitbutton('Upload and import'),
					dom.p(style({fontStyle: 'italic', marginTop: '.5ex'}), 'The file is uploaded first, then its messages are imported, finally messages are matched for threading. Importing is done in a transaction, you can abort the entire import before it is finished.'),
				),
			),
		),
		importAbortBox=dom.div(), // Outside fieldset because it gets disabled, above progress because may be scrolling it down quickly with problems.
		importProgress=dom.div(
			style({display: 'none'}),
		),
		footer,
	)

	// Try to show the progress of an earlier import session. The user may have just
	// refreshed the browser.
	let importToken: string
	try {
		importToken = window.sessionStorage.getItem('ImportToken') || ''
	} catch (err) {
		console.log('looking up ImportToken in session storage', {err})
		return
	}
	if (!importToken) {
		return
	}
	importFieldset.disabled = true
	dom._kids(importProgress,
		dom.div(
			dom.div('Reconnecting to import...'),
		),
	)
	importProgress.style.display = ''
	importTrack(importToken)
	.catch(() => {
		if (window.confirm('Error reconnecting to import. Remove this import session?')) {
			window.sessionStorage.removeItem('ImportToken')
			dom._kids(importProgress)
			importProgress.style.display = 'none'
		}
	})
	.finally(() => {
		importFieldset.disabled = false
	})
}

const destination = async (name: string) => {
	const [_, domain, destinations] = await client.Account()
	let dest = destinations[name]
	if (!dest) {
		throw new Error('destination not found')
	}

	type Header = {
		root: HTMLElement

		key: HTMLInputElement
		value: HTMLInputElement
	}

	type Row = {
		root: HTMLElement

		smtpMailFromRegexp: HTMLInputElement
		verifiedDomain: HTMLInputElement
		headers: Header[]
		isForward: HTMLInputElement // Checkbox
		listAllowDomain: HTMLInputElement
		acceptRejectsToMailbox: HTMLInputElement
		mailbox: HTMLInputElement
	}

	let rulesetsTbody = dom.tbody()
	let rulesetsRows: Row[] = []

	const addRulesetsRow = (rs: api.Ruleset) => {
		let row: Row
		let headersCell = dom.td()

		const addHeader = (k: string, v: string) => {
			let h: Header
			let key: HTMLInputElement
			let value: HTMLInputElement

			const root = dom.div(
				key=dom.input(attr.value(k)),
				' ',
				value=dom.input(attr.value(v)),
				' ',
				dom.clickbutton('-', style({width: '1.5em'}), function click() {
					h.root.remove()
					row.headers = row.headers.filter(x => x !== h)
					if (row.headers.length === 0) {
						const b = dom.clickbutton('+', style({width: '1.5em'}), function click() {
							b.remove()
							addHeader('', '')
						})
						headersCell.appendChild(dom.div(style({textAlign: 'right'}), b))
					}
				}),
				' ',
				dom.clickbutton('+', style({width: '1.5em'}), function click() {
					addHeader('', '')
				}),
			)
			h = {root: root, key: key, value: value}
			row.headers.push(h)
			headersCell.appendChild(root)
		}

		let smtpMailFromRegexp: HTMLInputElement
		let verifiedDomain: HTMLInputElement
		let isForward: HTMLInputElement // Checkbox
		let listAllowDomain: HTMLInputElement
		let acceptRejectsToMailbox: HTMLInputElement
		let mailbox: HTMLInputElement

		const root = dom.tr(
			dom.td(smtpMailFromRegexp=dom.input(attr.value(rs.SMTPMailFromRegexp || ''))),
			dom.td(verifiedDomain=dom.input(attr.value(rs.VerifiedDomain || ''))),
			headersCell,
			dom.td(dom.label(isForward=dom.input(attr.type('checkbox'), rs.IsForward ? attr.checked('') : [] ))),
			dom.td(listAllowDomain=dom.input(attr.value(rs.ListAllowDomain || ''))),
			dom.td(acceptRejectsToMailbox=dom.input(attr.value(rs.AcceptRejectsToMailbox || ''))),
			dom.td(mailbox=dom.input(attr.value(rs.Mailbox || ''))),
			dom.td(
				dom.clickbutton('Remove ruleset', function click() {
					row.root.remove()
					rulesetsRows = rulesetsRows.filter(e => e !== row)
				}),
			),
		)
		row = {
			root: root,
			smtpMailFromRegexp: smtpMailFromRegexp,
			verifiedDomain: verifiedDomain,
			headers: [],
			isForward: isForward,
			listAllowDomain: listAllowDomain,
			acceptRejectsToMailbox: acceptRejectsToMailbox,
			mailbox: mailbox,
		}
		rulesetsRows.push(row)

		Object.entries(rs.HeadersRegexp || {}).sort().forEach(t =>
			addHeader(t[0], t[1])
		)
		if (Object.entries(rs.HeadersRegexp || {}).length === 0) {
			const b = dom.clickbutton('+', style({width: '1.5em'}), function click() {
				b.remove()
				addHeader('', '')
			})
			headersCell.appendChild(dom.div(style({textAlign: 'right'}), b))
		}

		rulesetsTbody.appendChild(row.root)
	}

	(dest.Rulesets || []).forEach(rs => {
		addRulesetsRow(rs)
	})

	let defaultMailbox: HTMLInputElement
	let fullName: HTMLInputElement
	let saveButton: HTMLButtonElement

	const addresses = [name, ...Object.keys(destinations).filter(a => !a.startsWith('@') && a !== name)]

	dom._kids(page,
		crumbs(
			crumblink('Mox Account', '#'),
			'Destination ' + name,
		),
		dom.div(
			dom.span('Default mailbox', attr.title('Default mailbox where email for this recipient is delivered to if it does not match any ruleset. Default is Inbox.')),
			dom.br(),
			defaultMailbox=dom.input(attr.value(dest.Mailbox), attr.placeholder('Inbox')),
		),
		dom.br(),
		dom.div(
			dom.span('Full name', attr.title('Name to use in From header when composing messages. If not set, the account default full name is used.')),
			dom.br(),
			fullName=dom.input(attr.value(dest.FullName)),
		),
		dom.br(),
		dom.h2('Rulesets'),
		dom.p('Incoming messages are checked against the rulesets. If a ruleset matches, the message is delivered to the mailbox configured for the ruleset instead of to the default mailbox.'),
		dom.p('"Is Forward" does not affect matching, but changes prevents the sending mail server from being included in future junk classifications by clearing fields related to the forwarding email server (IP address, EHLO domain, MAIL FROM domain and a matching DKIM domain), and prevents DMARC rejects for forwarded messages.'),
		dom.p('"List allow domain" does not affect matching, but skips the regular spam checks if one of the verified domains is a (sub)domain of the domain mentioned here.'),
		dom.p('"Accept rejects to mailbox" does not affect matching, but causes messages classified as junk to be accepted and delivered to this mailbox, instead of being rejected during the SMTP transaction. Useful for incoming forwarded messages where rejecting incoming messages may cause the forwarding server to stop forwarding.'),
		dom.table(
			dom.thead(
				dom.tr(
					dom.th('SMTP "MAIL FROM" regexp', attr.title('Matches if this regular expression matches (a substring of) the SMTP MAIL FROM address (not the message From-header). E.g. user@example.org.')),
					dom.th('Verified domain', attr.title('Matches if this domain matches an SPF- and/or DKIM-verified (sub)domain.')),
					dom.th('Headers regexp', attr.title('Matches if these header field/value regular expressions all match (substrings of) the message headers. Header fields and valuees are converted to lower case before matching. Whitespace is trimmed from the value before matching. A header field can occur multiple times in a message, only one instance has to match. For mailing lists, you could match on ^list-id$ with the value typically the mailing list address in angled brackets with @ replaced with a dot, e.g. <name\\.lists\\.example\\.org>.')),
					dom.th('Is Forward', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. Can only be used together with SMTPMailFromRegexp and VerifiedDomain. SMTPMailFromRegexp must be set to the address used to deliver the forwarded message, e.g. '^user(|\\+.*)@forward\\.example$'. Changes to junk analysis: 1. Messages are not rejected for failing a DMARC policy, because a legitimate forwarded message without valid/intact/aligned DKIM signature would be rejected because any verified SPF domain will be 'unaligned', of the forwarding mail server. 2. The sending mail server IP address, and sending EHLO and MAIL FROM domains and matching DKIM domain aren't used in future reputation-based spam classifications (but other verified DKIM domains are) because the forwarding server is not a useful spam signal for future messages.")),
					dom.th('List allow domain', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If this domain matches an SPF- and/or DKIM-verified (sub)domain, the message is accepted without further spam checks, such as a junk filter or DMARC reject evaluation. DMARC rejects should not apply for mailing lists that are not configured to rewrite the From-header of messages that don't have a passing DKIM signature of the From-domain. Otherwise, by rejecting messages, you may be automatically unsubscribed from the mailing list. The assumption is that mailing lists do their own spam filtering/moderation.")),
					dom.th('Allow rejects to mailbox', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If a message is classified as spam, it isn't rejected during the SMTP transaction (the normal behaviour), but accepted during the SMTP transaction and delivered to the specified mailbox. The specified mailbox is not automatically cleaned up like the account global Rejects mailbox, unless set to that Rejects mailbox.")),
					dom.th('Mailbox', attr.title('Mailbox to deliver to if this ruleset matches.')),
					dom.th('Action'),
				)
			),
			rulesetsTbody,
			dom.tfoot(
				dom.tr(
					dom.td(attr.colspan('7')),
					dom.td(
						dom.clickbutton('Add ruleset', function click() {
							addRulesetsRow({
								SMTPMailFromRegexp: '',
								VerifiedDomain: '',
								HeadersRegexp: {},
								IsForward: false,
								ListAllowDomain: '',
								AcceptRejectsToMailbox: '',
								Mailbox: '',
								VerifiedDNSDomain: {ASCII: '', Unicode: ''},
								ListAllowDNSDomain: {ASCII: '', Unicode: ''},
							})
						}),
					),
				),
			),
		),
		dom.br(),
		saveButton=dom.clickbutton('Save', async function click() {
			saveButton.disabled = true
			try {
				const newDest = {
					Mailbox: defaultMailbox.value,
					FullName: fullName.value,
					Rulesets: rulesetsRows.map(row => {
						return {
							SMTPMailFromRegexp: row.smtpMailFromRegexp.value,
							VerifiedDomain: row.verifiedDomain.value,
							HeadersRegexp: Object.fromEntries(row.headers.map(h => [h.key.value, h.value.value])),
							IsForward: row.isForward.checked,
							ListAllowDomain: row.listAllowDomain.value,
							AcceptRejectsToMailbox: row.acceptRejectsToMailbox.value,
							Mailbox: row.mailbox.value,
							VerifiedDNSDomain: {ASCII: '', Unicode: ''},
							ListAllowDNSDomain: {ASCII: '', Unicode: ''},
						}
					}),
				}
				page.classList.add('loading')
				await client.DestinationSave(name, dest, newDest)
				window.location.reload() // todo: only refresh part of ui
			} catch (err) {
				console.log({err})
				window.alert('Error: ' + errmsg(err))
				page.classList.remove('loading')
				return
			} finally {
				saveButton.disabled = false
			}
		}),
		dom.br(),
		dom.br(),
		dom.br(),
		dom.p("Apple's mail applications don't do account autoconfiguration, and when adding an account it can choose defaults that don't work with modern email servers. Adding an account through a \"mobileconfig\" profile file can be more convenient: It contains the IMAP/SMTP settings such as host name, port, TLS, authentication mechanism and user name. This profile does not contain a login password. Opening the profile adds it under Profiles in System Preferences (macOS) or Settings (iOS), where you can install it. These profiles are not signed, so users will have to ignore the warnings about them being unsigned. ",
			dom.br(),
			dom.a(attr.href('https://autoconfig.'+domainName(domain)+'/profile.mobileconfig?addresses='+encodeURIComponent(addresses.join(','))+'&name='+encodeURIComponent(dest.FullName)), attr.download(''), 'Download .mobileconfig email account profile'),
			dom.br(),
			dom.a(attr.href('https://autoconfig.'+domainName(domain)+'/profile.mobileconfig.qrcode.png?addresses='+encodeURIComponent(addresses.join(','))+'&name='+encodeURIComponent(dest.FullName)), attr.download(''), 'Open QR-code with link to .mobileconfig profile'),
		),
	)
}

const init = async () => {
	let curhash: string | undefined

	const hashChange = async () => {
		if (curhash === window.location.hash) {
			return
		}
		let h = decodeURIComponent(window.location.hash)
		if (h !== '' && h.substring(0, 1) == '#') {
			h = h.substring(1)
		}
		const t = h.split('/')
		page.classList.add('loading')
		try {
			if (h === '') {
				await index()
			} else if (t[0] === 'destinations' && t.length === 2) {
				await destination(t[1])
			} else {
				dom._kids(page, 'page not found')
			}
		} catch (err) {
			console.log({err})
			window.alert('Error: ' + errmsg(err))
			window.location.hash = curhash || ''
			curhash = window.location.hash
			return
		}
		curhash = window.location.hash
		page.classList.remove('loading')
	}
	window.addEventListener('hashchange', hashChange)
	hashChange()
}

window.addEventListener('load', async () => {
	try {
		await init()
	} catch (err) {
		window.alert('Error: ' + errmsg(err))
	}
})
