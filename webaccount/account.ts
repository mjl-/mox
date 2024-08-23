// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

// From HTML.
declare let page: HTMLElement
declare let moxversion: string
declare let moxgoversion: string
declare let moxgoos: string
declare let moxgoarch: string

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
				style({display: 'flex', flexDirection: 'column', alignItems: 'center'}),
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

// Popup shows kids in a centered div with white background on top of a
// transparent overlay on top of the window. Clicking the overlay or hitting
// Escape closes the popup. Scrollbars are automatically added to the div with
// kids. Returns a function that removes the popup.
const popup = (...kids: ElemArg[]) => {
	const origFocus = document.activeElement
	const close = () => {
		if (!root.parentNode) {
			return
		}
		root.remove()
		if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
			origFocus.focus()
		}
	}
	let content: HTMLElement
	const root = dom.div(
		style({position: 'fixed', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: 'rgba(0, 0, 0, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: '1'}),
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
	document.body.appendChild(root)
	content.focus()
	return close
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

const check = async <T>(elem: {disabled: boolean}, p: Promise<T>): Promise<T> => {
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

// When white-space is relevant, e.g. for email addresses (e.g. "  "@example.org).
const prewrap = (...l: string[]) => dom.span(style({whiteSpace: 'pre-wrap'}), l)

const client = new api.Client().withOptions({csrfHeader: 'x-mox-csrf', login: login}).withAuthToken(localStorageGet('webaccountcsrftoken') || '')

const link = (href: string, anchorOpt: string) => dom.a(attr.href(href), attr.rel('noopener noreferrer'), anchorOpt || href)

const crumblink = (text: string, path: string) => {
	return {
		text: text,
		path: path
	}
}
const crumbs = (...l: ({text: string, path: string} | string)[]) => {
	const crumbtext = (e: {text: string, path: string} | string) => typeof e === 'string' ? e : e.text
	document.title = l.map(e => crumbtext(e)).join(' - ')

	const crumblink = (e: {text: string, path: string} | string) =>
		typeof e === 'string' ? prewrap(e) : dom.a(e.text, attr.href(e.path))
	return [
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
		dom.h1(l.map((e, index) => index === 0 ? crumblink(e) : [' / ', crumblink(e)])),
		dom.br()
	]
}

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

const age = (date: Date) => {
	const r = dom.span(dom._class('notooltip'), attr.title(date.toString()))
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
	for (let i = 0; i < periods.length; i++) {
		const p = periods[i]
		if (t >= 2*p || i === periods.length-1) {
			const n = Math.round(t/p)
			s = '' + n + suffix[i]
			break
		}
	}
	if (t < 60) {
		s = '<1min'
		// Prevent showing '-<1min' when browser and server have relatively small time drift of max 1 minute.
		negative = ''
	}

	dom._kids(r, negative+s)
	return r
}


const formatQuotaSize = (v: number) => {
	if (v === 0) {
		return '0'
	}
	const m = 1024*1024
	const g = m*1024
	const t = g*1024
	if (Math.floor(v/t)*t === v) {
		return ''+(v/t)+'t'
	} else if (Math.floor(v/g)*g === v) {
		return ''+(v/g)+'g'
	} else if (Math.floor(v/m)*m === v) {
		return ''+(v/m)+'m'
	}
	return ''+v
}

const index = async () => {
	const [acc, storageUsed, storageLimit, suppressions] = await client.Account()

	let fullNameForm: HTMLFormElement
	let fullNameFieldset: HTMLFieldSetElement
	let fullName: HTMLInputElement
	let passwordForm: HTMLFormElement
	let passwordFieldset: HTMLFieldSetElement
	let password1: HTMLInputElement
	let password2: HTMLInputElement
	let passwordHint: HTMLElement

	let autoJunkFlagsFieldset: HTMLFieldSetElement
	let autoJunkFlagsEnabled: HTMLInputElement
	let junkMailboxRegexp: HTMLInputElement
	let neutralMailboxRegexp: HTMLInputElement
	let notJunkMailboxRegexp: HTMLInputElement

	let junkFilterFields: HTMLFieldSetElement
	let junkFilterEnabled: HTMLInputElement
	let junkThreshold: HTMLInputElement
	let junkOnegrams: HTMLInputElement
	let junkTwograms: HTMLInputElement
	let junkMaxPower: HTMLInputElement
	let junkTopWords: HTMLInputElement
	let junkIgnoreWords: HTMLInputElement
	let junkRareWords: HTMLInputElement

	let rejectsFieldset: HTMLFieldSetElement
	let rejectsMailbox: HTMLInputElement
	let keepRejects: HTMLInputElement

	let outgoingWebhookFieldset: HTMLFieldSetElement
	let outgoingWebhookURL: HTMLInputElement
	let outgoingWebhookAuthorization: HTMLInputElement
	let outgoingWebhookEvents: HTMLSelectElement

	let incomingWebhookFieldset: HTMLFieldSetElement
	let incomingWebhookURL: HTMLInputElement
	let incomingWebhookAuthorization: HTMLInputElement

	let keepRetiredPeriodsFieldset: HTMLFieldSetElement
	let keepRetiredMessagePeriod: HTMLInputElement
	let keepRetiredWebhookPeriod: HTMLInputElement

	let fromIDLoginAddressesFieldset: HTMLFieldSetElement

	const second = 1000*1000*1000
	const minute = 60*second
	const hour = 60*minute
	const day = 24*hour
	const week = 7*day
	const parseDuration = (s: string) => {
		if (!s) { return 0 }
		const xparseint = () => {
			const v = parseInt(s.substring(0, s.length-1))
			if (isNaN(v) || Math.round(v) !== v) {
				throw new Error('bad number in duration')
			}
			return v
		}
		if (s.endsWith('w')) { return xparseint()*week }
		if (s.endsWith('d')) { return xparseint()*day }
		if (s.endsWith('h')) { return xparseint()*hour }
		if (s.endsWith('m')) { return xparseint()*minute }
		if (s.endsWith('s')) { return xparseint()*second }
		throw new Error('bad duration '+s)
	}
	const formatDuration = (v: number) => {
		if (v === 0) {
			return ''
		}
		const is = (period: number) => v > 0 && Math.round(v/period) === v/period
		const format = (period: number, s: string) => ''+(v/period)+s
		if (is(week)) { return format(week, 'w') }
		if (is(day)) { return format(day, 'd') }
		if (is(hour)) { return format(hour, 'h') }
		if (is(minute)) { return format(minute, 'm') }
		return format(second, 's')
	}

	let importForm: HTMLFormElement
	let importFieldset: HTMLFieldSetElement
	let mailboxFileHint: HTMLElement
	let mailboxPrefixHint: HTMLElement
	let importProgress: HTMLElement
	let importAbortBox: HTMLElement

	let suppressionAddress: HTMLInputElement
	let suppressionReason: HTMLInputElement

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

	const authorizationPopup = (dest: HTMLInputElement) => {
		let username: HTMLInputElement
		let password: HTMLInputElement
		const close = popup(
			dom.form(
				function submit(e: SubmitEvent) {
					e.preventDefault()
					e.stopPropagation()
					dest.value = 'Basic '+window.btoa(username.value+':'+password.value)
					close()
				},
				dom.p('Compose HTTP Basic authentication header'),
				dom.div(
					style({marginBottom: '1ex'}),
					dom.div(dom.label('Username')),
					username=dom.input(attr.required('')),
				),
				dom.div(
					style({marginBottom: '1ex'}),
					dom.div(dom.label('Password (shown in clear)')),
					password=dom.input(attr.required('')),
				),
				dom.div(
					style({marginBottom: '1ex'}),
					dom.submitbutton('Set'),
				),
				dom.div('A HTTP Basic authorization header contains the password in plain text, as base64.'),
			),
		)
		username.focus()
	}

	const popupTestOutgoing = () => {
		let fieldset: HTMLFieldSetElement
		let event: HTMLSelectElement
		let dsn: HTMLInputElement
		let suppressing: HTMLInputElement
		let queueMsgID: HTMLInputElement
		let fromID: HTMLInputElement
		let messageID: HTMLInputElement
		let error: HTMLInputElement
		let extra: HTMLInputElement
		let body: HTMLTextAreaElement
		let curl: HTMLElement
		let result: HTMLElement

		let data: api.Outgoing = {
			Version: 0,
			Event: api.OutgoingEvent.EventDelivered,
			DSN: false,
			Suppressing: false,
			QueueMsgID: 123,
			FromID: 'MDEyMzQ1Njc4OWFiY2RlZg',
			MessageID: '<QnxzgulZK51utga6agH_rg@mox.example>',
			Subject: 'test from mox web pages',
			WebhookQueued: new Date(),
			SMTPCode: 0,
			SMTPEnhancedCode: '',
			Error: '',
			Extra: {},
		}
		const onchange = function change() {
			data = {
				Version: 0,
				Event: event.value as api.OutgoingEvent,
				DSN: dsn.checked,
				Suppressing: suppressing.checked,
				QueueMsgID: parseInt(queueMsgID.value),
				FromID: fromID.value,
				MessageID: messageID.value,
				Subject: 'test from mox web pages',
				WebhookQueued: new Date(),
				SMTPCode: 0,
				SMTPEnhancedCode: '',
				Error: error.value,
				Extra: JSON.parse(extra.value),
			}
			const curlStr = "curl " + (outgoingWebhookAuthorization.value ? "-H 'Authorization: "+outgoingWebhookAuthorization.value+"' " : "") + "-H 'X-Mox-Webhook-ID: 1' -H 'X-Mox-Webhook-Attempt: 1' --json '"+JSON.stringify(data)+"' '"+outgoingWebhookURL.value+"'"
			dom._kids(curl, style({maxWidth: '45em', wordBreak: 'break-all'}), curlStr)
			body.value = JSON.stringify(data, undefined, "\t")
		}

		popup(
			dom.h1('Test webhook for outgoing delivery'),
			dom.form(
				async function submit(e: SubmitEvent) {
					e.preventDefault()
					e.stopPropagation()
					result.classList.add('loadstart')
					const [code, response, errmsg] = await check(fieldset, client.OutgoingWebhookTest(outgoingWebhookURL.value, outgoingWebhookAuthorization.value, data))
					const nresult = dom.div(
						dom._class('loadend'),
						dom.table(
							dom.tr(dom.td('HTTP status code'), dom.td(''+code)),
							dom.tr(dom.td('Error message'), dom.td(errmsg)),
							dom.tr(dom.td('Response'), dom.td(response)),
						),
					)
					result.replaceWith(nresult)
					result = nresult
				},
				fieldset=dom.fieldset(
					dom.p('Make a test call to ', dom.b(outgoingWebhookURL.value), '.'),
					dom.div(style({display: 'flex', gap: '1em'}),
						dom.div(
							dom.h2('Parameters'),
							dom.div(
								style({marginBottom: '.5ex'}), 
								dom.label(
									'Event',
									dom.div(
										event=dom.select(onchange,
											["delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"].map(s => dom.option(s.substring(0, 1).toUpperCase()+s.substring(1), attr.value(s))),
										),
									),
								),
							),
							dom.div(style({marginBottom: '.5ex'}), dom.label(dsn=dom.input(attr.type('checkbox')), ' DSN', onchange)),
							dom.div(style({marginBottom: '.5ex'}), dom.label(suppressing=dom.input(attr.type('checkbox')), ' Suppressing', onchange)),
							dom.div(style({marginBottom: '.5ex'}), dom.label('Queue message ID ', dom.div(queueMsgID=dom.input(attr.required(''), attr.type('number'), attr.value('123'), onchange)))),
							dom.div(style({marginBottom: '.5ex'}), dom.label('From ID ', dom.div(fromID=dom.input(attr.required(''), attr.value(data.FromID), onchange)))),
							dom.div(style({marginBottom: '.5ex'}), dom.label('MessageID', dom.div(messageID=dom.input(attr.required(''), attr.value(data.MessageID), onchange)))),
							dom.div(style({marginBottom: '.5ex'}), dom.label('Error', dom.div(error=dom.input(onchange)))),
							dom.div(style({marginBottom: '.5ex'}), dom.label('Extra', dom.div(extra=dom.input(attr.required(''), attr.value('{}'), onchange)))),
						),
						dom.div(
							dom.h2('Headers'),
							dom.pre('X-Mox-Webhook-ID: 1\nX-Mox-Webhook-Attempt: 1'),
							dom.br(),
							dom.h2('JSON'),
							body=dom.textarea(attr.disabled(''), attr.rows('15'), style({width: '30em'})),
							dom.br(),
							dom.h2('curl'),
							curl=dom.div(dom._class('literal')),
						),
					),
					dom.br(),
					dom.div(style({textAlign: 'right'}), dom.submitbutton('Post')),
					dom.br(),
					result=dom.div(),
				),
			),
		)

		onchange()
	}

	const popupTestIncoming = () => {
		let fieldset: HTMLFieldSetElement
		let body: HTMLTextAreaElement
		let curl: HTMLElement
		let result: HTMLElement

		let data: api.Incoming = {
			Version: 0,
			From: [{Name: 'remote', Address: 'remote@remote.example'}],
			To: [{Name: 'mox', Address: 'mox@mox.example'}],
			CC: [],
			BCC: [],
			ReplyTo: [],
			Subject: 'test webhook for incoming message',
			MessageID: '<QnxzgulZK51utga6agH_rg@mox.example>',
			InReplyTo: '',
			References: [],
			Date: new Date(),
			Text: 'hi ☺\n',
			HTML: '',
			Structure: {
				ContentType: 'text/plain',
				ContentTypeParams: {charset: 'utf-8'},
				ContentID: '',
				DecodedSize: 8,
				Parts: [],
			},
			Meta: {
				MsgID: 1,
				MailFrom: 'remote@remote.example',
				MailFromValidated: true,
				MsgFromValidated: true,
				RcptTo: 'mox@localhost',
				DKIMVerifiedDomains: ['remote.example'],
				RemoteIP: '127.0.0.1',
				Received: new Date(),
				MailboxName: 'Inbox',
				Automated: false,
			},
		}

		const onchange = function change() {
			try {
				api.parser.Incoming(JSON.parse(body.value))
			} catch (err) {
				console.log({err})
				window.alert('Error parsing data: '+errmsg(err))
			}
			const curlStr = "curl " + (incomingWebhookAuthorization.value ? "-H 'Authorization: "+incomingWebhookAuthorization.value+"' " : "") + "-H 'X-Mox-Webhook-ID: 1' -H 'X-Mox-Webhook-Attempt: 1' --json '"+JSON.stringify(data)+"' '"+incomingWebhookURL.value+"'"
			dom._kids(curl, style({maxWidth: '45em', wordBreak: 'break-all'}), curlStr)
		}

		popup(
			dom.h1('Test webhook for incoming delivery'),
			dom.form(
				async function submit(e: SubmitEvent) {
					e.preventDefault()
					e.stopPropagation()
					result.classList.add('loadstart')
					const [code, response, errmsg] = await check(fieldset, (async () => await client.IncomingWebhookTest(incomingWebhookURL.value, incomingWebhookAuthorization.value, api.parser.Incoming(JSON.parse(body.value))))())
					const nresult = dom.div(
						dom._class('loadend'),
						dom.table(
							dom.tr(dom.td('HTTP status code'), dom.td(''+code)),
							dom.tr(dom.td('Error message'), dom.td(errmsg)),
							dom.tr(dom.td('Response'), dom.td(response)),
						),
					)
					result.replaceWith(nresult)
					result = nresult
				},
				fieldset=dom.fieldset(
					dom.p('Make a test call to ', dom.b(incomingWebhookURL.value), '.'),
					dom.div(style({display: 'flex', gap: '1em'}),
						dom.div(
							dom.h2('JSON'),
							body=dom.textarea(style({maxHeight: '90vh'}), style({width: '30em'}), onchange),
						),
						dom.div(
							dom.h2('Headers'),
							dom.pre('X-Mox-Webhook-ID: 1\nX-Mox-Webhook-Attempt: 1'),
							dom.br(),

							dom.h2('curl'),
							curl=dom.div(dom._class('literal')),
						),
					),
					dom.br(),
					dom.div(style({textAlign: 'right'}), dom.submitbutton('Post')),
					dom.br(),
					result=dom.div(),
				),
			),
		)
		body.value = JSON.stringify(data, undefined, '\t')
		body.setAttribute('rows', ''+Math.min(40, (body.value.split('\n').length+1)))
		onchange()
	}

	dom._kids(page,
		crumbs('Mox Account'),
		dom.div(
			'Default domain: ',
			acc.DNSDomain.ASCII ? domainString(acc.DNSDomain) : '(none)',
		),
		dom.br(),

		fullNameForm=dom.form(
			fullNameFieldset=dom.fieldset(
				dom.label(
					style({display: 'inline-block'}),
					'Full name',
					dom.br(),
					fullName=dom.input(attr.value(acc.FullName), attr.title('Name to use in From header when composing messages. Can be overridden per configured address.')),

				),
				' ',
				dom.submitbutton('Save'),
			),
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				await check(fullNameFieldset, client.AccountSaveFullName(fullName.value))
				fullName.setAttribute('value', fullName.value)
				fullNameForm.reset()
			},
		),
		dom.br(),

		dom.h2('Addresses'),
		dom.ul(
			Object.entries(acc.Destinations || {}).length === 0 ? dom.li('(None, login disabled)') : [],
			Object.entries(acc.Destinations || {}).sort().map(t =>
				dom.li(
					dom.a(prewrap(t[0]), attr.href('#destinations/'+encodeURIComponent(t[0]))),
					t[0].startsWith('@') ? ' (catchall)' : [],
				),
			),
		),
		dom.br(),

		dom.h2('Aliases/lists'),
		dom.table(
			dom.thead(
				dom.tr(
					dom.th('Alias address', attr.title('Messages sent to this address will be delivered to all members of the alias/list.')),
					dom.th('Subscription address', attr.title('Address subscribed to the alias/list.')),
					dom.th('Allowed senders', attr.title('Whether only members can send through the alias/list, or anyone.')),
					dom.th('Send as alias address', attr.title('If enabled, messages can be sent with the alias address in the message "From" header.')),
					dom.th(),
				),
			),
			(acc.Aliases || []).length === 0 ? dom.tr(dom.td(attr.colspan('5'), 'None')) : [],
			(acc.Aliases || []).sort((a, b) => a.Alias.LocalpartStr < b.Alias.LocalpartStr ? -1 : (domainName(a.Alias.Domain) < domainName(b.Alias.Domain) ? -1 : 1)).map(a =>
				dom.tr(
					dom.td(prewrap(a.Alias.LocalpartStr, '@', domainName(a.Alias.Domain))),
					dom.td(prewrap(a.SubscriptionAddress)),
					dom.td(a.Alias.PostPublic ? 'Anyone' : 'Members only'),
					dom.td(a.Alias.AllowMsgFrom ? 'Yes' : 'No'),
					dom.td(
						(a.MemberAddresses || []).length === 0 ? [] :
							dom.clickbutton('Show members', function click() {
								popup(
									dom.h1('Members of alias ', prewrap(a.Alias.LocalpartStr, '@', domainName(a.Alias.Domain))),
									dom.ul(
										(a.MemberAddresses || []).map(addr => dom.li(prewrap(addr))),
									),
								)
							}),
					),
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
				await check(passwordFieldset, client.SetPassword(password1.value))
				passwordForm.reset()
			},
		),
		dom.br(),

		dom.h2('Disk usage'),
		dom.p('Storage used is ', dom.b(formatQuotaSize(Math.floor(storageUsed/(1024*1024))*1024*1024)),
			storageLimit > 0 ? [
				dom.b('/', formatQuotaSize(storageLimit)),
				' (',
				''+Math.floor(100*storageUsed/storageLimit),
				'%).',
			] : [', no explicit limit is configured.']),

		dom.h2('Automatic junk flags', attr.title('For the junk filter to work properly, it needs to be trained: Messages need to be marked as junk or nonjunk. Not all email clients help you set those flags. Automatic junk flags set the junk or nonjunk flags when messages are moved/copied to mailboxes matching configured regular expressions.')),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()

				await check(autoJunkFlagsFieldset, client.AutomaticJunkFlagsSave(autoJunkFlagsEnabled.checked, junkMailboxRegexp.value, neutralMailboxRegexp.value, notJunkMailboxRegexp.value))
			},
			autoJunkFlagsFieldset=dom.fieldset(
				dom.div(style({display: 'flex', gap: '1em'}),
					dom.label(
						'Enabled',
						attr.title("If enabled, junk/nonjunk flags will be set automatically if they match a regular expression below. When two of the three mailbox regular expressions are set, the remaining one will match all unmatched messages. Messages are matched in order 'junk', 'neutral', 'not junk', and the search stops on the first match. Mailboxes are lowercased before matching."),
						dom.div(autoJunkFlagsEnabled=dom.input(attr.type('checkbox'), acc.AutomaticJunkFlags.Enabled ? attr.checked('') : [])),
					),
					dom.label(
						'Junk mailbox regexp',
						dom.div(junkMailboxRegexp=dom.input(attr.value(acc.AutomaticJunkFlags.JunkMailboxRegexp))),
					),
					dom.label(
						'Neutral mailbox regexp',
						dom.div(neutralMailboxRegexp=dom.input(attr.value(acc.AutomaticJunkFlags.NeutralMailboxRegexp))),
					),
					dom.label(
						'Not Junk mailbox regexp',
						dom.div(notJunkMailboxRegexp=dom.input(attr.value(acc.AutomaticJunkFlags.NotJunkMailboxRegexp))),
					),
					dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save'))),
				),
			),
		),
		dom.br(),

		dom.h2('Junk filter', attr.title('Content-based filtering, using the junk-status of individual messages to rank words in such messages as spam or ham. It is recommended you always set the applicable (non)-junk status on messages, and that you do not empty your Trash because those messages contain valuable ham/spam training information.')),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()

				const xjunkFilter = () => {
					if (!junkFilterEnabled.checked) {
						return null
					}
					const r: api.JunkFilter = {
						Threshold: parseFloat(junkThreshold.value),
						Onegrams: junkOnegrams.checked,
						Twograms: junkTwograms.checked,
						Threegrams: acc.JunkFilter?.Threegrams || false, // Ignored on server.
						MaxPower: parseFloat(junkMaxPower.value),
						TopWords: parseInt(junkTopWords.value),
						IgnoreWords: parseFloat(junkIgnoreWords.value),
						RareWords: parseInt(junkRareWords.value),
					}
					return r
				}
				await check(junkFilterFields, (async () => await client.JunkFilterSave(xjunkFilter()))())
			},
			junkFilterFields=dom.fieldset(
				dom.div(style({display: 'flex', gap: '1em'}),
					dom.label(
						'Enabled',
						attr.title("If enabled, the junk filter is used to classify incoming email from first-time senders. The result, along with other checks, determines if the message will be accepted or rejected"),
						dom.div(junkFilterEnabled=dom.input(attr.type('checkbox'), acc.JunkFilter ? attr.checked('') : [])),
					),
					dom.label(
						'Threshold',
						attr.title('Approximate spaminess score between 0 and 1 above which emails are rejected as spam. Each delivery attempt adds a little noise to make it slightly harder for spammers to identify words that strongly indicate non-spaminess and use it to bypass the filter. E.g. 0.95.'),
						dom.div(junkThreshold=dom.input(attr.value(''+(acc.JunkFilter?.Threshold || '0.95')))),
					),
					dom.label(
						'Onegrams',
						attr.title('Track ham/spam ranking for single words.'),
						dom.div(junkOnegrams=dom.input(attr.type('checkbox'), acc.JunkFilter?.Onegrams ? attr.checked('') : [])),
					),
					dom.label(
						'Twograms',
						attr.title('Track ham/spam ranking for each two consecutive words.'),
						dom.div(junkTwograms=dom.input(attr.type('checkbox'), acc.JunkFilter?.Twograms ? attr.checked('') : [])),
					),
					dom.label(
						'Threegrams',
						attr.title('Track ham/spam ranking for each three consecutive words. Can only be changed by admin.'),
						dom.div(dom.input(attr.type('checkbox'), attr.disabled(''), acc.JunkFilter?.Threegrams ? attr.checked('') : [])),
					),
					dom.label(
						'Max power',
						attr.title('Maximum power a word (combination) can have. If spaminess is 0.99, and max power is 0.1, spaminess of the word will be set to 0.9. Similar for ham words.'),
						dom.div(junkMaxPower=dom.input(attr.value('' + (acc.JunkFilter?.MaxPower || 0.01)))),
					),
					dom.label(
						'Top words',
						attr.title('Number of most spammy/hammy words to use for calculating probability. E.g. 10.'),
						dom.div(junkTopWords=dom.input(attr.value('' + (acc.JunkFilter?.TopWords || 10)))),
					),
					dom.label(
						'Ignore words',
						attr.title('Ignore words that are this much away from 0.5 haminess/spaminess. E.g. 0.1, causing word (combinations) of 0.4 to 0.6 to be ignored.'),
						dom.div(junkIgnoreWords=dom.input(attr.value('' + (acc.JunkFilter?.IgnoreWords || 0.1)))),
					),
					dom.label(
						'Rare words',
						attr.title('Occurrences in word database until a word is considered rare and its influence in calculating probability reduced. E.g. 1 or 2.'),
						dom.div(junkRareWords=dom.input(attr.value('' + (acc.JunkFilter?.RareWords || 2)))),
					),
					dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save'))),
				),
			),
		),
		dom.br(),

		dom.h2('Rejects'),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()

				await check(rejectsFieldset, client.RejectsSave(rejectsMailbox.value, keepRejects.checked))
			},
			rejectsFieldset=dom.fieldset(
				dom.div(style({display: 'flex', gap: '1em'}),
					dom.label(
						'Mailbox',
						attr.title("Mail that looks like spam will be rejected, but a copy can be stored temporarily in a mailbox, e.g. Rejects. If mail isn't coming in when you expect, you can look there. The mail still isn't accepted, so the remote mail server may retry (hopefully, if legitimate), or give up (hopefully, if indeed a spammer). Messages are automatically removed from this mailbox, so do not set it to a mailbox that has messages you want to keep."),
						dom.div(rejectsMailbox=dom.input(attr.value(acc.RejectsMailbox))),
					),
					dom.label(
						"No cleanup",
						attr.title("Don't automatically delete mail in the RejectsMailbox listed above. This can be useful, e.g. for future spam training. It can also cause storage to fill up."),
						dom.div(keepRejects=dom.input(attr.type('checkbox'), acc.KeepRejects ? attr.checked('') : [])),
					),
					dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save'))),
				),
			),
		),
		dom.br(),

		dom.h2('Webhooks'),
		dom.h3('Outgoing', attr.title('Webhooks for outgoing messages are called for each attempt to deliver a message in the outgoing queue, e.g. when the queue has delivered a message to the next hop, when a single attempt failed with a temporary error, when delivery permanently failed, or when DSN (delivery status notification) messages were received about a previously sent message.')),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()

				await check(outgoingWebhookFieldset, client.OutgoingWebhookSave(outgoingWebhookURL.value, outgoingWebhookAuthorization.value, [...outgoingWebhookEvents.selectedOptions].map(o => o.value)))
			},
			outgoingWebhookFieldset=dom.fieldset(
				dom.div(style({display: 'flex', gap: '1em'}),
					dom.div(
						dom.label(
							dom.div('URL', attr.title('URL to do an HTTP POST to for each event. Webhooks are disabled if empty.')),
							outgoingWebhookURL=dom.input(attr.value(acc.OutgoingWebhook?.URL || ''), style({width: '30em'})),
						),
					),
					dom.div(
						dom.label(
							dom.div(
								'Authorization header ',
								dom.a(
									'Basic',
									attr.href(''),
									function click(e: MouseEvent) {
										e.preventDefault()
										authorizationPopup(outgoingWebhookAuthorization)
									},
								),
								attr.title('If non-empty, HTTP requests have this value as Authorization header, e.g. Basic <base64-encoded-username-password>.'),
							),
							outgoingWebhookAuthorization=dom.input(attr.value(acc.OutgoingWebhook?.Authorization || '')),
						),
					),
					dom.div(
						dom.label(
							style({verticalAlign: 'top'}),
							dom.div('Events', attr.title('Either limit to specific events, or receive all events (default).')),
							outgoingWebhookEvents=dom.select(
								style({verticalAlign: 'bottom'}),
								attr.multiple(''),
								attr.size('8'), // Number of options.
								["delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"].map(s => dom.option(s.substring(0, 1).toUpperCase()+s.substring(1), attr.value(s), acc.OutgoingWebhook?.Events?.includes(s) ? attr.selected('') : [])),
							),
						),
					),
					dom.div(
						dom.div(dom.label('\u00a0')),
						dom.submitbutton('Save'), ' ',
						dom.clickbutton('Test', function click() {
							popupTestOutgoing()
						}),
					),
				),
			),
		),
		dom.br(),
		dom.h3('Incoming', attr.title('Webhooks for incoming messages are called for each message received over SMTP, excluding DSN messages about previous deliveries.')),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()

				await check(incomingWebhookFieldset, client.IncomingWebhookSave(incomingWebhookURL.value, incomingWebhookAuthorization.value))
			},
			incomingWebhookFieldset=dom.fieldset(
				dom.div(
					style({display: 'flex', gap: '1em'}),
					dom.div(
						dom.label(
							dom.div('URL'),
							incomingWebhookURL=dom.input(attr.value(acc.IncomingWebhook?.URL || ''), style({width: '30em'})),
						),
					),
					dom.div(
						dom.label(
							dom.div(
								'Authorization header ',
								dom.a(
									'Basic',
									attr.href(''),
									function click(e: MouseEvent) {
										e.preventDefault()
										authorizationPopup(incomingWebhookAuthorization)
									},
								),
								attr.title('If non-empty, HTTP requests have this value as Authorization header, e.g. Basic <base64-encoded-username-password>.'),
							),
							incomingWebhookAuthorization=dom.input(attr.value(acc.IncomingWebhook?.Authorization || '')),
						),
					),
					dom.div(
						dom.div(dom.label('\u00a0')),
						dom.submitbutton('Save'), ' ',
						dom.clickbutton('Test', function click() {
							popupTestIncoming()
						}),
					),
				),
			),
		),
		dom.br(),

		dom.h2('Keep messages/webhooks retired from queue', attr.title('After delivering a message or webhook from the queue it is removed by default. But you can also keep these "retired" messages/webhooks around for a while. With unique SMTP MAIL FROM addresses configured below, this allows relating incoming delivery status notification messages (DSNs) to previously sent messages and their original recipients, which is needed for automatic management of recipient suppression lists, which is important for managing the reputation of your mail server. For both messages and webhooks, this can be useful for debugging. Use values like "3d" for 3 days, or units "s" for second, "m" for minute, "h" for hour, "w" for week.')),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()

				await check(keepRetiredPeriodsFieldset, (async () => await client.KeepRetiredPeriodsSave(parseDuration(keepRetiredMessagePeriod.value), parseDuration(keepRetiredWebhookPeriod.value)))())
			},
			keepRetiredPeriodsFieldset=dom.fieldset(
				dom.div(
					style({display: 'flex', gap: '1em', alignItems: 'flex-end'}),
					dom.div(
						dom.label(
							'Messages deliveries',
							dom.br(),
							keepRetiredMessagePeriod=dom.input(attr.value(formatDuration(acc.KeepRetiredMessagePeriod))),
						),
					),
					dom.div(
						dom.label(
							'Webhook deliveries',
							dom.br(),
							keepRetiredWebhookPeriod=dom.input(attr.value(formatDuration(acc.KeepRetiredWebhookPeriod))),
						),
					),
					dom.div(
						dom.submitbutton('Save'),
					),
				),
			),
		),
		dom.br(),

		dom.h2('Unique SMTP MAIL FROM login addresses ("FromID")', attr.title('Login addresses that cause outgoing email to be sent with SMTP MAIL FROM addresses with a unique id after the localpart catchall separator (which must be enabled when addresses are specified here). Any delivery status notifications (DSN, e.g. for bounces), can be related to the original message and recipient with unique id\'s. You can login to an account with any valid email address, including variants with the localpart catchall separator. You can use this mechanism to both send outgoing messages with and without unique fromid for a given email address. With the webapi and webmail, a unique id will be generated. For submission, the id from the SMTP MAIL FROM command is used if present, and a unique id is generated otherwise. Corresponds to field FromIDLoginAddresses in the Account configuration in domains.conf.')),
		(() => {
			let inputs: HTMLInputElement[] = []
			let elem: HTMLElement

			const render = () => {
				inputs = []

				const e = dom.form(
					async function submit(e: SubmitEvent) {
						e.preventDefault()
						e.stopPropagation()

						await check(fromIDLoginAddressesFieldset, client.FromIDLoginAddressesSave(inputs.map(e => e.value)))
					},
					fromIDLoginAddressesFieldset=dom.fieldset(
						dom.table(
							dom.tbody(
								(acc.FromIDLoginAddresses || []).length === 0 ? dom.tr(dom.td('(None)'), dom.td()) : [],
								(acc.FromIDLoginAddresses || []).map((s, index) => {
									const input = dom.input(attr.required(''), attr.value(s))
									inputs.push(input)
									const x = dom.tr(
										dom.td(input),
										dom.td(
											dom.clickbutton('Remove', function click() {
												acc.FromIDLoginAddresses!.splice(index, 1)
												render()
											}),
										),
									)
									return x
								}),
							),
							dom.tfoot(
								dom.tr(
									dom.td(),
									dom.td(
										dom.clickbutton('Add', function click() {
											acc.FromIDLoginAddresses = (acc.FromIDLoginAddresses || []).concat([''])
											render()
										}),
									),
								),
								dom.tr(
									dom.td(attr.colspan('2'), dom.submitbutton('Save')),
								),
							),
						),
					),
				)
				if (elem) {
					elem.replaceWith(e)
					elem = e
				}
				return e
			}
			elem = render()
			return elem
		})(),
		dom.br(),

		dom.h2('Suppression list'),
		dom.p('Messages queued for delivery to recipients on the suppression list will immediately fail. If delivery to a recipient fails repeatedly, it can be added to the suppression list automatically. Repeated rejected delivery attempts can have a negative influence of mail server reputation. Applications sending email can implement their own handling of delivery failure notifications, but not all do.'),
		dom.form(
			attr.id('suppressionAdd'),
			async function submit(e: SubmitEvent) {
				e.preventDefault()
				e.stopPropagation()

				await check(e.target! as HTMLButtonElement, client.SuppressionAdd(suppressionAddress.value, true, suppressionReason.value))
				window.location.reload() // todo: reload less
			},
		),
		dom.table(
			dom.thead(
				dom.tr(
					dom.th('Address', attr.title('Address that caused this entry to be added to the list. The title (shown on hover) displays an address with a fictional simplified localpart, with lower-cased, dots removed, only first part before "+" or "-" (typicaly catchall separators). When checking if an address is on the suppression list, it is checked against this address.')),
					dom.th('Manual', attr.title('Whether suppression was added manually, instead of automatically based on bounces.')),
					dom.th('Reason'),
					dom.th('Since'),
					dom.th('Action'),
				),
			),
			dom.tbody(
				(suppressions || []).length === 0 ? dom.tr(dom.td(attr.colspan('5'), '(None)')) : [],
				(suppressions || []).map(s =>
					dom.tr(
						dom.td(prewrap(s.OriginalAddress), attr.title(s.BaseAddress)),
						dom.td(s.Manual ? '✓' : ''),
						dom.td(s.Reason),
						dom.td(age(s.Created)),
						dom.td(
							dom.clickbutton('Remove', async function click(e: MouseEvent) {
								await check(e.target! as HTMLButtonElement, client.SuppressionRemove(s.OriginalAddress))
								window.location.reload() // todo: reload less
							})
						),
					),
				),
			),
			dom.tfoot(
				dom.tr(
					dom.td(suppressionAddress=dom.input(attr.type('required'), attr.form('suppressionAdd'))),
					dom.td(),
					dom.td(suppressionReason=dom.input(style({width: '100%'}), attr.form('suppressionAdd'))),
					dom.td(),
					dom.td(dom.submitbutton('Add suppression', attr.form('suppressionAdd'))),
				),
			),
		),
		dom.br(),

		dom.h2('Export'),
		dom.p('Export all messages in all mailboxes.'),
		dom.form(
			attr.target('_blank'), attr.method('POST'), attr.action('export'),
			dom.input(attr.type('hidden'), attr.name('csrf'), attr.value(localStorageGet('webaccountcsrftoken') || '')),
			dom.input(attr.type('hidden'), attr.name('mailbox'), attr.value('')),
			dom.input(attr.type('hidden'), attr.name('recursive'), attr.value('on')),

			dom.div(style({display: 'flex', flexDirection: 'column', gap: '.5ex'}),
				dom.div(
					dom.label(dom.input(attr.type('radio'), attr.name('format'), attr.value('maildir'), attr.checked('')), ' Maildir'), ' ',
					dom.label(dom.input(attr.type('radio'), attr.name('format'), attr.value('mbox')), ' Mbox'),
				),
				dom.div(
					dom.label(dom.input(attr.type('radio'), attr.name('archive'), attr.value('tar')), ' Tar'), ' ',
					dom.label(dom.input(attr.type('radio'), attr.name('archive'), attr.value('tgz'), attr.checked('')), ' Tgz'), ' ',
					dom.label(dom.input(attr.type('radio'), attr.name('archive'), attr.value('zip')), ' Zip'), ' ',
				),
				dom.div(style({marginTop: '1ex'}), dom.submitbutton('Export')),
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
					mailboxFileHint=dom.p(style({display: 'none', fontStyle: 'italic', marginTop: '.5ex'}), 'This file must either be a zip file or a gzipped tar file with mbox and/or maildir mailboxes. For maildirs, an optional file "dovecot-keywords" is read additional keywords, like Forwarded/Junk/NotJunk. If an imported mailbox already exists by name, messages are added to the existing mailbox. If a mailbox does not yet exist it will be created. Messages are not deduplicated, importing them twice will result in duplicates.'),
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
		dom.br(),

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
	const [acc] = await client.Account()
	let dest = (acc.Destinations || {})[name]
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
		msgFromRegexp: HTMLInputElement
		verifiedDomain: HTMLInputElement
		headers: Header[]
		isForward: HTMLInputElement // Checkbox
		listAllowDomain: HTMLInputElement
		acceptRejectsToMailbox: HTMLInputElement
		mailbox: HTMLInputElement
		comment: HTMLInputElement
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
		let msgFromRegexp: HTMLInputElement
		let verifiedDomain: HTMLInputElement
		let isForward: HTMLInputElement // Checkbox
		let listAllowDomain: HTMLInputElement
		let acceptRejectsToMailbox: HTMLInputElement
		let mailbox: HTMLInputElement
		let comment: HTMLInputElement

		const root = dom.tr(
			dom.td(smtpMailFromRegexp=dom.input(attr.value(rs.SMTPMailFromRegexp || ''))),
			dom.td(msgFromRegexp=dom.input(attr.value(rs.MsgFromRegexp || ''))),
			dom.td(verifiedDomain=dom.input(attr.value(rs.VerifiedDomain || ''))),
			headersCell,
			dom.td(dom.label(isForward=dom.input(attr.type('checkbox'), rs.IsForward ? attr.checked('') : [] ))),
			dom.td(listAllowDomain=dom.input(attr.value(rs.ListAllowDomain || ''))),
			dom.td(acceptRejectsToMailbox=dom.input(attr.value(rs.AcceptRejectsToMailbox || ''))),
			dom.td(mailbox=dom.input(attr.value(rs.Mailbox || ''))),
			dom.td(comment=dom.input(attr.value(rs.Comment || ''))),
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
			msgFromRegexp: msgFromRegexp,
			verifiedDomain: verifiedDomain,
			headers: [],
			isForward: isForward,
			listAllowDomain: listAllowDomain,
			acceptRejectsToMailbox: acceptRejectsToMailbox,
			mailbox: mailbox,
			comment: comment,
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

	const addresses = [name, ...Object.keys(acc.Destinations || {}).filter(a => !a.startsWith('@') && a !== name)]

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
					dom.th('Message "From" address regexp', attr.title('Matches if this regular expression matches (a substring of) the single address in the message From header.')),
					dom.th('Verified domain', attr.title('Matches if this domain matches an SPF- and/or DKIM-verified (sub)domain.')),
					dom.th('Headers regexp', attr.title('Matches if these header field/value regular expressions all match (substrings of) the message headers. Header fields and valuees are converted to lower case before matching. Whitespace is trimmed from the value before matching. A header field can occur multiple times in a message, only one instance has to match. For mailing lists, you could match on ^list-id$ with the value typically the mailing list address in angled brackets with @ replaced with a dot, e.g. <name\\.lists\\.example\\.org>.')),
					dom.th('Is Forward', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. Can only be used together with SMTPMailFromRegexp and VerifiedDomain. SMTPMailFromRegexp must be set to the address used to deliver the forwarded message, e.g. '^user(|\\+.*)@forward\\.example$'. Changes to junk analysis: 1. Messages are not rejected for failing a DMARC policy, because a legitimate forwarded message without valid/intact/aligned DKIM signature would be rejected because any verified SPF domain will be 'unaligned', of the forwarding mail server. 2. The sending mail server IP address, and sending EHLO and MAIL FROM domains and matching DKIM domain aren't used in future reputation-based spam classifications (but other verified DKIM domains are) because the forwarding server is not a useful spam signal for future messages.")),
					dom.th('List allow domain', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If this domain matches an SPF- and/or DKIM-verified (sub)domain, the message is accepted without further spam checks, such as a junk filter or DMARC reject evaluation. DMARC rejects should not apply for mailing lists that are not configured to rewrite the From-header of messages that don't have a passing DKIM signature of the From-domain. Otherwise, by rejecting messages, you may be automatically unsubscribed from the mailing list. The assumption is that mailing lists do their own spam filtering/moderation.")),
					dom.th('Allow rejects to mailbox', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If a message is classified as spam, it isn't rejected during the SMTP transaction (the normal behaviour), but accepted during the SMTP transaction and delivered to the specified mailbox. The specified mailbox is not automatically cleaned up like the account global Rejects mailbox, unless set to that Rejects mailbox.")),
					dom.th('Mailbox', attr.title('Mailbox to deliver to if this ruleset matches.')),
					dom.th('Comment', attr.title('Free-form comments.')),
					dom.th('Action'),
				)
			),
			rulesetsTbody,
			dom.tfoot(
				dom.tr(
					dom.td(attr.colspan('9')),
					dom.td(
						dom.clickbutton('Add ruleset', function click() {
							addRulesetsRow({
								SMTPMailFromRegexp: '',
								MsgFromRegexp: '',
								VerifiedDomain: '',
								HeadersRegexp: {},
								IsForward: false,
								ListAllowDomain: '',
								AcceptRejectsToMailbox: '',
								Mailbox: '',
								Comment: '',
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
			const newDest = {
				Mailbox: defaultMailbox.value,
				FullName: fullName.value,
				Rulesets: rulesetsRows.map(row => {
					return {
						SMTPMailFromRegexp: row.smtpMailFromRegexp.value,
						MsgFromRegexp: row.msgFromRegexp.value,
						VerifiedDomain: row.verifiedDomain.value,
						HeadersRegexp: Object.fromEntries(row.headers.map(h => [h.key.value, h.value.value])),
						IsForward: row.isForward.checked,
						ListAllowDomain: row.listAllowDomain.value,
						AcceptRejectsToMailbox: row.acceptRejectsToMailbox.value,
						Mailbox: row.mailbox.value,
						Comment: row.comment.value,
						VerifiedDNSDomain: {ASCII: '', Unicode: ''},
						ListAllowDNSDomain: {ASCII: '', Unicode: ''},
					}
				}),
			}
			await check(saveButton, client.DestinationSave(name, dest, newDest))
			window.location.reload() // todo: only refresh part of ui
		}),
		dom.br(),
		dom.br(),
		dom.br(),
		dom.p("Apple's mail applications don't do account autoconfiguration, and when adding an account it can choose defaults that don't work with modern email servers. Adding an account through a \"mobileconfig\" profile file can be more convenient: It contains the IMAP/SMTP settings such as host name, port, TLS, authentication mechanism and user name. This profile does not contain a login password. Opening the profile adds it under Profiles in System Preferences (macOS) or Settings (iOS), where you can install it. These profiles are not signed, so users will have to ignore the warnings about them being unsigned. ",
			dom.br(),
			dom.a(attr.href('https://autoconfig.'+domainName(acc.DNSDomain)+'/profile.mobileconfig?addresses='+encodeURIComponent(addresses.join(','))+'&name='+encodeURIComponent(dest.FullName)), attr.download(''), 'Download .mobileconfig email account profile'),
			dom.br(),
			dom.a(attr.href('https://autoconfig.'+domainName(acc.DNSDomain)+'/profile.mobileconfig.qrcode.png?addresses='+encodeURIComponent(addresses.join(','))+'&name='+encodeURIComponent(dest.FullName)), attr.download(''), 'Open QR-code with link to .mobileconfig profile'),
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
