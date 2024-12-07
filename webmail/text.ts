// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

// Loaded from synchronous javascript.
declare let messageItem: api.MessageItem
declare let parsedMessage: api.ParsedMessage
// From customization script.
declare let moxBeforeDisplay: (root: HTMLElement) => void

const init = async () => {
	const pm = api.parser.ParsedMessage(parsedMessage)
	const mi = api.parser.MessageItem(messageItem)
	const root = dom.div(
		dom.div(dom._class('pad', 'mono', 'textmulti'),
			css('msgTextPreformatted', {whiteSpace: 'pre-wrap'}),
			(pm.Texts || []).map(t => renderText(t.replace(/\r\n/g, '\n'))),
			(mi.Attachments || []).filter(f => isImage(f)).map(f => {
				const pathStr = [0].concat(f.Path || []).join('.')
				return dom.div(
					dom.div(
						css('msgAttachment', {flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', maxHeight: 'calc(100% - 50px)'}),
						dom.img(
							attr.src('view/'+pathStr),
							attr.title(f.Filename),
							css('msgAttachmentImage', {maxWidth: '100%', maxHeight: '100%', boxShadow: styles.boxShadow})
						),
					)
				)
			}),
		)
	)
	if (typeof moxBeforeDisplay !== 'undefined') {
		moxBeforeDisplay(root)
	}
	dom._kids(document.body, root)
}

init()
.catch((err) => {
	window.alert('Error: ' + ((err as any).message || '(no message)'))
})
