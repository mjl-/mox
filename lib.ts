// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

type ElemArg = string | String | Element | Function | {_class: string[]} | {_attrs: {[k: string]: string}} | {_styles: {[k: string]: string | number}} | {_props: {[k: string]: any}} | {root: HTMLElement} | ElemArg[]

const [dom, style, attr, prop] = (function() {

// Start of unicode block (rough approximation of script), from https://www.unicode.org/Public/UNIDATA/Blocks.txt
const scriptblocks = [0x0000, 0x0080, 0x0100, 0x0180, 0x0250, 0x02B0, 0x0300, 0x0370, 0x0400, 0x0500, 0x0530, 0x0590, 0x0600, 0x0700, 0x0750, 0x0780, 0x07C0, 0x0800, 0x0840, 0x0860, 0x0870, 0x08A0, 0x0900, 0x0980, 0x0A00, 0x0A80, 0x0B00, 0x0B80, 0x0C00, 0x0C80, 0x0D00, 0x0D80, 0x0E00, 0x0E80, 0x0F00, 0x1000, 0x10A0, 0x1100, 0x1200, 0x1380, 0x13A0, 0x1400, 0x1680, 0x16A0, 0x1700, 0x1720, 0x1740, 0x1760, 0x1780, 0x1800, 0x18B0, 0x1900, 0x1950, 0x1980, 0x19E0, 0x1A00, 0x1A20, 0x1AB0, 0x1B00, 0x1B80, 0x1BC0, 0x1C00, 0x1C50, 0x1C80, 0x1C90, 0x1CC0, 0x1CD0, 0x1D00, 0x1D80, 0x1DC0, 0x1E00, 0x1F00, 0x2000, 0x2070, 0x20A0, 0x20D0, 0x2100, 0x2150, 0x2190, 0x2200, 0x2300, 0x2400, 0x2440, 0x2460, 0x2500, 0x2580, 0x25A0, 0x2600, 0x2700, 0x27C0, 0x27F0, 0x2800, 0x2900, 0x2980, 0x2A00, 0x2B00, 0x2C00, 0x2C60, 0x2C80, 0x2D00, 0x2D30, 0x2D80, 0x2DE0, 0x2E00, 0x2E80, 0x2F00, 0x2FF0, 0x3000, 0x3040, 0x30A0, 0x3100, 0x3130, 0x3190, 0x31A0, 0x31C0, 0x31F0, 0x3200, 0x3300, 0x3400, 0x4DC0, 0x4E00, 0xA000, 0xA490, 0xA4D0, 0xA500, 0xA640, 0xA6A0, 0xA700, 0xA720, 0xA800, 0xA830, 0xA840, 0xA880, 0xA8E0, 0xA900, 0xA930, 0xA960, 0xA980, 0xA9E0, 0xAA00, 0xAA60, 0xAA80, 0xAAE0, 0xAB00, 0xAB30, 0xAB70, 0xABC0, 0xAC00, 0xD7B0, 0xD800, 0xDB80, 0xDC00, 0xE000, 0xF900, 0xFB00, 0xFB50, 0xFE00, 0xFE10, 0xFE20, 0xFE30, 0xFE50, 0xFE70, 0xFF00, 0xFFF0, 0x10000, 0x10080, 0x10100, 0x10140, 0x10190, 0x101D0, 0x10280, 0x102A0, 0x102E0, 0x10300, 0x10330, 0x10350, 0x10380, 0x103A0, 0x10400, 0x10450, 0x10480, 0x104B0, 0x10500, 0x10530, 0x10570, 0x10600, 0x10780, 0x10800, 0x10840, 0x10860, 0x10880, 0x108E0, 0x10900, 0x10920, 0x10980, 0x109A0, 0x10A00, 0x10A60, 0x10A80, 0x10AC0, 0x10B00, 0x10B40, 0x10B60, 0x10B80, 0x10C00, 0x10C80, 0x10D00, 0x10E60, 0x10E80, 0x10EC0, 0x10F00, 0x10F30, 0x10F70, 0x10FB0, 0x10FE0, 0x11000, 0x11080, 0x110D0, 0x11100, 0x11150, 0x11180, 0x111E0, 0x11200, 0x11280, 0x112B0, 0x11300, 0x11400, 0x11480, 0x11580, 0x11600, 0x11660, 0x11680, 0x11700, 0x11800, 0x118A0, 0x11900, 0x119A0, 0x11A00, 0x11A50, 0x11AB0, 0x11AC0, 0x11B00, 0x11C00, 0x11C70, 0x11D00, 0x11D60, 0x11EE0, 0x11F00, 0x11FB0, 0x11FC0, 0x12000, 0x12400, 0x12480, 0x12F90, 0x13000, 0x13430, 0x14400, 0x16800, 0x16A40, 0x16A70, 0x16AD0, 0x16B00, 0x16E40, 0x16F00, 0x16FE0, 0x17000, 0x18800, 0x18B00, 0x18D00, 0x1AFF0, 0x1B000, 0x1B100, 0x1B130, 0x1B170, 0x1BC00, 0x1BCA0, 0x1CF00, 0x1D000, 0x1D100, 0x1D200, 0x1D2C0, 0x1D2E0, 0x1D300, 0x1D360, 0x1D400, 0x1D800, 0x1DF00, 0x1E000, 0x1E030, 0x1E100, 0x1E290, 0x1E2C0, 0x1E4D0, 0x1E7E0, 0x1E800, 0x1E900, 0x1EC70, 0x1ED00, 0x1EE00, 0x1F000, 0x1F030, 0x1F0A0, 0x1F100, 0x1F200, 0x1F300, 0x1F600, 0x1F650, 0x1F680, 0x1F700, 0x1F780, 0x1F800, 0x1F900, 0x1FA00, 0x1FA70, 0x1FB00, 0x20000, 0x2A700, 0x2B740, 0x2B820, 0x2CEB0, 0x2F800, 0x30000, 0x31350, 0xE0000, 0xE0100, 0xF0000, 0x100000]

// Find block code belongs in.
const findBlock = (code: number): number => {
	let s = 0
	let e = scriptblocks.length
	while (s < e-1) {
		let i = Math.floor((s+e)/2)
		if (code < scriptblocks[i]) {
			e = i
		} else {
			s = i
		}
	}
	return s
}

// formatText adds s to element e, in a way that makes switching unicode scripts
// clear, with alternating DOM TextNode and span elements with a "switchscript"
// class. Useful for highlighting look alikes, e.g. a (ascii 0x61) and а (cyrillic
// 0x430).
//
// This is only called one string at a time, so the UI can still display strings
// without highlighting switching scripts, by calling formatText on the parts.
const formatText = (e: HTMLElement, s: string): void => {
	// Handle some common cases quickly.
	if (!s) {
		return
	}
	let ascii = true
	for (const c of s) {
		const cp = c.codePointAt(0) // For typescript, to check for undefined.
		if (cp !== undefined && cp >= 0x0080) {
			ascii = false
			break
		}
	}
	if (ascii) {
		e.appendChild(document.createTextNode(s))
		return
	}

	// todo: handle grapheme clusters? wait for Intl.Segmenter?

	let n = 0 // Number of text/span parts added.
	let str = '' // Collected so far.
	let block = -1 // Previous block/script.
	let mod = 1
	const put = (nextblock: number) => {
		if (n === 0 && nextblock === 0) {
			// Start was non-ascii, second block is ascii, we'll start marked as switched.
			mod = 0
		}
		if (n % 2 === mod) {
			const x = document.createElement('span')
			x.classList.add('scriptswitch')
			x.appendChild(document.createTextNode(str))
			e.appendChild(x)
		} else {
			e.appendChild(document.createTextNode(str))
		}
		n++
		str = ''
	}
	for (const c of s) {
		// Basic whitespace does not switch blocks. Will probably need to extend with more
		// punctuation in the future. Possibly for digits too. But perhaps not in all
		// scripts.
		if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
			str += c
			continue
		}
		const code: number = c.codePointAt(0) as number
		if (block < 0 || !(code >= scriptblocks[block] && (code < scriptblocks[block+1] || block === scriptblocks.length-1))) {
			const nextblock = code < 0x0080 ? 0 : findBlock(code)
			if (block >= 0) {
				put(nextblock)
			}
			block = nextblock
		}
		str += c
	}
	put(-1)
}

const _domKids = <T extends HTMLElement>(e: T, l: ElemArg[]): T => {
	l.forEach((c) => {
		const xc = c as {[k: string]: any}
		if (typeof c === 'string') {
			formatText(e, c)
		} else if (c instanceof String) {
			// String is an escape-hatch for text that should not be formatted with
			// unicode-block-change-highlighting, e.g. for textarea values.
			e.appendChild(document.createTextNode(''+c))
		} else if (c instanceof Element) {
			e.appendChild(c)
		} else if (c instanceof Function) {
			if (!c.name) {
				throw new Error('function without name')
			}
			e.addEventListener(c.name as string, c as EventListener)
		} else if (Array.isArray(xc)) {
			_domKids(e, c as ElemArg[])
		} else if (xc._class) {
			for (const s of xc._class) {
				e.classList.toggle(s, true)
			}
		} else if (xc._attrs) {
			for (const k in xc._attrs) {
				e.setAttribute(k, xc._attrs[k])
			}
		} else if (xc._styles) {
			for (const k in xc._styles) {
				const estyle: {[k: string]: any} = e.style
				estyle[k as string] = xc._styles[k]
			}
		} else if (xc._props) {
			for (const k in xc._props) {
				const eprops: {[k: string]: any} = e
				eprops[k] = xc._props[k]
			}
		} else if (xc.root) {
			e.appendChild(xc.root)
		} else {
			console.log('bad kid', c)
			throw new Error('bad kid')
		}
	})
	return e
}
const dom = {
	_kids: function(e: HTMLElement, ...kl: ElemArg[]) {
		while(e.firstChild) {
			e.removeChild(e.firstChild)
		}
		_domKids(e, kl)
	},
	_attrs: (x: {[k: string]: string}) => { return {_attrs: x}},
	_class: (...x: string[]) => { return {_class: x}},
	// The createElement calls are spelled out so typescript can derive function
	// signatures with a specific HTML*Element return type.
	div: (...l: ElemArg[]) => _domKids(document.createElement('div'), l),
	span: (...l: ElemArg[]) => _domKids(document.createElement('span'), l),
	a: (...l: ElemArg[]) => _domKids(document.createElement('a'), l),
	input: (...l: ElemArg[]) => _domKids(document.createElement('input'), l),
	textarea: (...l: ElemArg[]) => _domKids(document.createElement('textarea'), l),
	select: (...l: ElemArg[]) => _domKids(document.createElement('select'), l),
	option: (...l: ElemArg[]) => _domKids(document.createElement('option'), l),
	clickbutton: (...l: ElemArg[]) => _domKids(document.createElement('button'), [attr.type('button'), ...l]),
	submitbutton: (...l: ElemArg[]) => _domKids(document.createElement('button'), [attr.type('submit'), ...l]),
	form: (...l: ElemArg[]) => _domKids(document.createElement('form'), l),
	fieldset: (...l: ElemArg[]) => _domKids(document.createElement('fieldset'), l),
	table: (...l: ElemArg[]) => _domKids(document.createElement('table'), l),
	thead: (...l: ElemArg[]) => _domKids(document.createElement('thead'), l),
	tbody: (...l: ElemArg[]) => _domKids(document.createElement('tbody'), l),
	tfoot: (...l: ElemArg[]) => _domKids(document.createElement('tfoot'), l),
	tr: (...l: ElemArg[]) => _domKids(document.createElement('tr'), l),
	td: (...l: ElemArg[]) => _domKids(document.createElement('td'), l),
	th: (...l: ElemArg[]) => _domKids(document.createElement('th'), l),
	datalist: (...l: ElemArg[]) => _domKids(document.createElement('datalist'), l),
	h1: (...l: ElemArg[]) => _domKids(document.createElement('h1'), l),
	h2: (...l: ElemArg[]) => _domKids(document.createElement('h2'), l),
	h3: (...l: ElemArg[]) => _domKids(document.createElement('h3'), l),
	br: (...l: ElemArg[]) => _domKids(document.createElement('br'), l),
	hr: (...l: ElemArg[]) => _domKids(document.createElement('hr'), l),
	pre: (...l: ElemArg[]) => _domKids(document.createElement('pre'), l),
	label: (...l: ElemArg[]) => _domKids(document.createElement('label'), l),
	ul: (...l: ElemArg[]) => _domKids(document.createElement('ul'), l),
	li: (...l: ElemArg[]) => _domKids(document.createElement('li'), l),
	iframe: (...l: ElemArg[]) => _domKids(document.createElement('iframe'), l),
	b: (...l: ElemArg[]) => _domKids(document.createElement('b'), l),
	img: (...l: ElemArg[]) => _domKids(document.createElement('img'), l),
	style: (...l: ElemArg[]) => _domKids(document.createElement('style'), l),
	search: (...l: ElemArg[]) => _domKids(document.createElement('search'), l),
	p: (...l: ElemArg[]) => _domKids(document.createElement('p'), l),
}
const _attr = (k: string, v: string) => { const o: {[key: string]: string} = {}; o[k] = v; return {_attrs: o} }
const attr = {
	title: (s: string) => _attr('title', s),
	value: (s: string) => _attr('value', s),
	type: (s: string) => _attr('type', s),
	tabindex: (s: string) => _attr('tabindex', s),
	src: (s: string) => _attr('src', s),
	placeholder: (s: string) => _attr('placeholder', s),
	href: (s: string) => _attr('href', s),
	checked: (s: string) => _attr('checked', s),
	selected: (s: string) => _attr('selected', s),
	id: (s: string) => _attr('id', s),
	datalist: (s: string) => _attr('datalist', s),
	rows: (s: string) => _attr('rows', s),
	target: (s: string) => _attr('target', s),
	rel: (s: string) => _attr('rel', s),
	required: (s: string) => _attr('required', s),
	multiple: (s: string) => _attr('multiple', s),
	download: (s: string) => _attr('download', s),
	disabled: (s: string) => _attr('disabled', s),
	draggable: (s: string) => _attr('draggable', s),
	rowspan: (s: string) => _attr('rowspan', s),
	colspan: (s: string) => _attr('colspan', s),
	for: (s: string) => _attr('for', s),
	role: (s: string) => _attr('role', s),
	arialabel: (s: string) => _attr('aria-label', s),
	arialive: (s: string) => _attr('aria-live', s),
	name: (s: string) => _attr('name', s),
	min: (s: string) => _attr('min', s),
	max: (s: string) => _attr('max', s),
	action: (s: string) => _attr('action', s),
	method: (s: string) => _attr('method', s),
	autocomplete: (s: string) => _attr('autocomplete', s),
}
const style = (x: {[k: string]: string | number}) => { return {_styles: x}}
const prop = (x: {[k: string]: any}) => { return {_props: x}}
return [dom, style, attr, prop]
})()
