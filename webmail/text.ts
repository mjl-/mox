// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

// Loaded from synchronous javascript.
declare let parsedMessage: api.ParsedMessage

const init = async () => {
	const pm = api.parser.ParsedMessage(parsedMessage)
	dom._kids(document.body,
		dom.div(dom._class('pad', 'mono'),
			style({whiteSpace: 'pre-wrap'}),
			join((pm.Texts || []).map(t => renderText(t)), () => dom.hr(style({margin: '2ex 0'}))),
		)
	)
}

init()
.catch((err) => {
	window.alert('Error: ' + ((err as any).message || '(no message)'))
})
