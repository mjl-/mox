// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

// Loaded from synchronous javascript.
declare let messageItem: api.MessageItem

const init = () => {
	const mi = api.parser.MessageItem(messageItem)
	document.title = '"' + mi.Envelope.Subject + '"- from '+((mi.Envelope.From || []).map(a => formatAddress(a)).join(', ') || '-') + ' (id '+mi.Message.ID+')'

	let msgattachmentview = dom.div()
	if (mi.Attachments && mi.Attachments.length > 0) {
		dom._kids(msgattachmentview,
			dom.div(
				css('msgAttachments', {borderTop: '1px solid', borderTopColor: styles.borderColor}),
				dom.div(dom._class('pad'),
					'Attachments: ',
					join(mi.Attachments.map(a => a.Filename || '(unnamed)'), () => ', '),
				),
			)
		)
	}

	const msgheaderview = dom.table(styleClasses.msgHeaders)
	loadMsgheaderView(msgheaderview, mi, [], null, true)

	const l = window.location.pathname.split('/')
	const w = l[l.length-1]
	let iframepath: string
	if (w === 'msgtext') {
		iframepath = 'text'
	} else if (w === 'msghtml') {
		iframepath = 'html'
	} else if (w === 'msghtmlexternal') {
		iframepath = 'htmlexternal'
	} else {
		window.alert('Unknown message type '+w)
		return
	}
	iframepath += '?sameorigin=true'

	let iframe: HTMLIFrameElement
	const page = document.getElementById('page')!
	dom._kids(page,
		dom.div(
			css('msgMeta', {backgroundColor: styles.backgroundColorMild, borderBottom: '1px solid', borderBottomColor: styles.borderColor}),
			msgheaderview,
			msgattachmentview,
		),
		iframe=dom.iframe(
			attr.title('Message body.'),
			attr.src(iframepath),
			css('msgIframe', {width: '100%', height: '100%'}),
			function load() {
				// Note: we load the iframe content specifically in a way that fires the load event only when the content is fully rendered.
				iframe.style.height = iframe.contentDocument!.documentElement.scrollHeight+'px'
				if (window.location.hash === '#print') {
					window.print()
				}
			},
		)
	)
}

try {
	init()
} catch (err) {
	window.alert('Error: ' + ((err as any).message || '(no message)'))
}
