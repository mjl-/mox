"use strict";
// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.
const [dom, style, attr, prop] = (function () {
	// Start of unicode block (rough approximation of script), from https://www.unicode.org/Public/UNIDATA/Blocks.txt
	const scriptblocks = [0x0000, 0x0080, 0x0100, 0x0180, 0x0250, 0x02B0, 0x0300, 0x0370, 0x0400, 0x0500, 0x0530, 0x0590, 0x0600, 0x0700, 0x0750, 0x0780, 0x07C0, 0x0800, 0x0840, 0x0860, 0x0870, 0x08A0, 0x0900, 0x0980, 0x0A00, 0x0A80, 0x0B00, 0x0B80, 0x0C00, 0x0C80, 0x0D00, 0x0D80, 0x0E00, 0x0E80, 0x0F00, 0x1000, 0x10A0, 0x1100, 0x1200, 0x1380, 0x13A0, 0x1400, 0x1680, 0x16A0, 0x1700, 0x1720, 0x1740, 0x1760, 0x1780, 0x1800, 0x18B0, 0x1900, 0x1950, 0x1980, 0x19E0, 0x1A00, 0x1A20, 0x1AB0, 0x1B00, 0x1B80, 0x1BC0, 0x1C00, 0x1C50, 0x1C80, 0x1C90, 0x1CC0, 0x1CD0, 0x1D00, 0x1D80, 0x1DC0, 0x1E00, 0x1F00, 0x2000, 0x2070, 0x20A0, 0x20D0, 0x2100, 0x2150, 0x2190, 0x2200, 0x2300, 0x2400, 0x2440, 0x2460, 0x2500, 0x2580, 0x25A0, 0x2600, 0x2700, 0x27C0, 0x27F0, 0x2800, 0x2900, 0x2980, 0x2A00, 0x2B00, 0x2C00, 0x2C60, 0x2C80, 0x2D00, 0x2D30, 0x2D80, 0x2DE0, 0x2E00, 0x2E80, 0x2F00, 0x2FF0, 0x3000, 0x3040, 0x30A0, 0x3100, 0x3130, 0x3190, 0x31A0, 0x31C0, 0x31F0, 0x3200, 0x3300, 0x3400, 0x4DC0, 0x4E00, 0xA000, 0xA490, 0xA4D0, 0xA500, 0xA640, 0xA6A0, 0xA700, 0xA720, 0xA800, 0xA830, 0xA840, 0xA880, 0xA8E0, 0xA900, 0xA930, 0xA960, 0xA980, 0xA9E0, 0xAA00, 0xAA60, 0xAA80, 0xAAE0, 0xAB00, 0xAB30, 0xAB70, 0xABC0, 0xAC00, 0xD7B0, 0xD800, 0xDB80, 0xDC00, 0xE000, 0xF900, 0xFB00, 0xFB50, 0xFE00, 0xFE10, 0xFE20, 0xFE30, 0xFE50, 0xFE70, 0xFF00, 0xFFF0, 0x10000, 0x10080, 0x10100, 0x10140, 0x10190, 0x101D0, 0x10280, 0x102A0, 0x102E0, 0x10300, 0x10330, 0x10350, 0x10380, 0x103A0, 0x10400, 0x10450, 0x10480, 0x104B0, 0x10500, 0x10530, 0x10570, 0x10600, 0x10780, 0x10800, 0x10840, 0x10860, 0x10880, 0x108E0, 0x10900, 0x10920, 0x10980, 0x109A0, 0x10A00, 0x10A60, 0x10A80, 0x10AC0, 0x10B00, 0x10B40, 0x10B60, 0x10B80, 0x10C00, 0x10C80, 0x10D00, 0x10E60, 0x10E80, 0x10EC0, 0x10F00, 0x10F30, 0x10F70, 0x10FB0, 0x10FE0, 0x11000, 0x11080, 0x110D0, 0x11100, 0x11150, 0x11180, 0x111E0, 0x11200, 0x11280, 0x112B0, 0x11300, 0x11400, 0x11480, 0x11580, 0x11600, 0x11660, 0x11680, 0x11700, 0x11800, 0x118A0, 0x11900, 0x119A0, 0x11A00, 0x11A50, 0x11AB0, 0x11AC0, 0x11B00, 0x11C00, 0x11C70, 0x11D00, 0x11D60, 0x11EE0, 0x11F00, 0x11FB0, 0x11FC0, 0x12000, 0x12400, 0x12480, 0x12F90, 0x13000, 0x13430, 0x14400, 0x16800, 0x16A40, 0x16A70, 0x16AD0, 0x16B00, 0x16E40, 0x16F00, 0x16FE0, 0x17000, 0x18800, 0x18B00, 0x18D00, 0x1AFF0, 0x1B000, 0x1B100, 0x1B130, 0x1B170, 0x1BC00, 0x1BCA0, 0x1CF00, 0x1D000, 0x1D100, 0x1D200, 0x1D2C0, 0x1D2E0, 0x1D300, 0x1D360, 0x1D400, 0x1D800, 0x1DF00, 0x1E000, 0x1E030, 0x1E100, 0x1E290, 0x1E2C0, 0x1E4D0, 0x1E7E0, 0x1E800, 0x1E900, 0x1EC70, 0x1ED00, 0x1EE00, 0x1F000, 0x1F030, 0x1F0A0, 0x1F100, 0x1F200, 0x1F300, 0x1F600, 0x1F650, 0x1F680, 0x1F700, 0x1F780, 0x1F800, 0x1F900, 0x1FA00, 0x1FA70, 0x1FB00, 0x20000, 0x2A700, 0x2B740, 0x2B820, 0x2CEB0, 0x2F800, 0x30000, 0x31350, 0xE0000, 0xE0100, 0xF0000, 0x100000];
	// Find block code belongs in.
	const findBlock = (code) => {
		let s = 0;
		let e = scriptblocks.length;
		while (s < e - 1) {
			let i = Math.floor((s + e) / 2);
			if (code < scriptblocks[i]) {
				e = i;
			}
			else {
				s = i;
			}
		}
		return s;
	};
	// formatText adds s to element e, in a way that makes switching unicode scripts
	// clear, with alternating DOM TextNode and span elements with a "switchscript"
	// class. Useful for highlighting look alikes, e.g. a (ascii 0x61) and а (cyrillic
	// 0x430).
	//
	// This is only called one string at a time, so the UI can still display strings
	// without highlighting switching scripts, by calling formatText on the parts.
	const formatText = (e, s) => {
		// Handle some common cases quickly.
		if (!s) {
			return;
		}
		let ascii = true;
		for (const c of s) {
			const cp = c.codePointAt(0); // For typescript, to check for undefined.
			if (cp !== undefined && cp >= 0x0080) {
				ascii = false;
				break;
			}
		}
		if (ascii) {
			e.appendChild(document.createTextNode(s));
			return;
		}
		// todo: handle grapheme clusters? wait for Intl.Segmenter?
		let n = 0; // Number of text/span parts added.
		let str = ''; // Collected so far.
		let block = -1; // Previous block/script.
		let mod = 1;
		const put = (nextblock) => {
			if (n === 0 && nextblock === 0) {
				// Start was non-ascii, second block is ascii, we'll start marked as switched.
				mod = 0;
			}
			if (n % 2 === mod) {
				const x = document.createElement('span');
				x.classList.add('scriptswitch');
				x.appendChild(document.createTextNode(str));
				e.appendChild(x);
			}
			else {
				e.appendChild(document.createTextNode(str));
			}
			n++;
			str = '';
		};
		for (const c of s) {
			// Basic whitespace does not switch blocks. Will probably need to extend with more
			// punctuation in the future. Possibly for digits too. But perhaps not in all
			// scripts.
			if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
				str += c;
				continue;
			}
			const code = c.codePointAt(0);
			if (block < 0 || !(code >= scriptblocks[block] && (code < scriptblocks[block + 1] || block === scriptblocks.length - 1))) {
				const nextblock = code < 0x0080 ? 0 : findBlock(code);
				if (block >= 0) {
					put(nextblock);
				}
				block = nextblock;
			}
			str += c;
		}
		put(-1);
	};
	const _domKids = (e, l) => {
		l.forEach((c) => {
			const xc = c;
			if (typeof c === 'string') {
				formatText(e, c);
			}
			else if (c instanceof String) {
				// String is an escape-hatch for text that should not be formatted with
				// unicode-block-change-highlighting, e.g. for textarea values.
				e.appendChild(document.createTextNode('' + c));
			}
			else if (c instanceof Element) {
				e.appendChild(c);
			}
			else if (c instanceof Function) {
				if (!c.name) {
					throw new Error('function without name');
				}
				e.addEventListener(c.name, c);
			}
			else if (Array.isArray(xc)) {
				_domKids(e, c);
			}
			else if (xc._class) {
				for (const s of xc._class) {
					e.classList.toggle(s, true);
				}
			}
			else if (xc._attrs) {
				for (const k in xc._attrs) {
					e.setAttribute(k, xc._attrs[k]);
				}
			}
			else if (xc._styles) {
				for (const k in xc._styles) {
					const estyle = e.style;
					estyle[k] = xc._styles[k];
				}
			}
			else if (xc._props) {
				for (const k in xc._props) {
					const eprops = e;
					eprops[k] = xc._props[k];
				}
			}
			else if (xc.root) {
				e.appendChild(xc.root);
			}
			else {
				console.log('bad kid', c);
				throw new Error('bad kid');
			}
		});
		return e;
	};
	const dom = {
		_kids: function (e, ...kl) {
			while (e.firstChild) {
				e.removeChild(e.firstChild);
			}
			_domKids(e, kl);
		},
		_attrs: (x) => { return { _attrs: x }; },
		_class: (...x) => { return { _class: x }; },
		// The createElement calls are spelled out so typescript can derive function
		// signatures with a specific HTML*Element return type.
		div: (...l) => _domKids(document.createElement('div'), l),
		span: (...l) => _domKids(document.createElement('span'), l),
		a: (...l) => _domKids(document.createElement('a'), l),
		input: (...l) => _domKids(document.createElement('input'), l),
		textarea: (...l) => _domKids(document.createElement('textarea'), l),
		select: (...l) => _domKids(document.createElement('select'), l),
		option: (...l) => _domKids(document.createElement('option'), l),
		clickbutton: (...l) => _domKids(document.createElement('button'), [attr.type('button'), ...l]),
		submitbutton: (...l) => _domKids(document.createElement('button'), [attr.type('submit'), ...l]),
		form: (...l) => _domKids(document.createElement('form'), l),
		fieldset: (...l) => _domKids(document.createElement('fieldset'), l),
		table: (...l) => _domKids(document.createElement('table'), l),
		thead: (...l) => _domKids(document.createElement('thead'), l),
		tbody: (...l) => _domKids(document.createElement('tbody'), l),
		tfoot: (...l) => _domKids(document.createElement('tfoot'), l),
		tr: (...l) => _domKids(document.createElement('tr'), l),
		td: (...l) => _domKids(document.createElement('td'), l),
		th: (...l) => _domKids(document.createElement('th'), l),
		datalist: (...l) => _domKids(document.createElement('datalist'), l),
		h1: (...l) => _domKids(document.createElement('h1'), l),
		h2: (...l) => _domKids(document.createElement('h2'), l),
		h3: (...l) => _domKids(document.createElement('h3'), l),
		br: (...l) => _domKids(document.createElement('br'), l),
		hr: (...l) => _domKids(document.createElement('hr'), l),
		pre: (...l) => _domKids(document.createElement('pre'), l),
		label: (...l) => _domKids(document.createElement('label'), l),
		ul: (...l) => _domKids(document.createElement('ul'), l),
		li: (...l) => _domKids(document.createElement('li'), l),
		iframe: (...l) => _domKids(document.createElement('iframe'), l),
		b: (...l) => _domKids(document.createElement('b'), l),
		img: (...l) => _domKids(document.createElement('img'), l),
		style: (...l) => _domKids(document.createElement('style'), l),
		search: (...l) => _domKids(document.createElement('search'), l),
		p: (...l) => _domKids(document.createElement('p'), l),
	};
	const _attr = (k, v) => { const o = {}; o[k] = v; return { _attrs: o }; };
	const attr = {
		title: (s) => _attr('title', s),
		value: (s) => _attr('value', s),
		type: (s) => _attr('type', s),
		tabindex: (s) => _attr('tabindex', s),
		src: (s) => _attr('src', s),
		placeholder: (s) => _attr('placeholder', s),
		href: (s) => _attr('href', s),
		checked: (s) => _attr('checked', s),
		selected: (s) => _attr('selected', s),
		id: (s) => _attr('id', s),
		datalist: (s) => _attr('datalist', s),
		rows: (s) => _attr('rows', s),
		target: (s) => _attr('target', s),
		rel: (s) => _attr('rel', s),
		required: (s) => _attr('required', s),
		multiple: (s) => _attr('multiple', s),
		download: (s) => _attr('download', s),
		disabled: (s) => _attr('disabled', s),
		draggable: (s) => _attr('draggable', s),
		rowspan: (s) => _attr('rowspan', s),
		colspan: (s) => _attr('colspan', s),
		for: (s) => _attr('for', s),
		role: (s) => _attr('role', s),
		arialabel: (s) => _attr('aria-label', s),
		arialive: (s) => _attr('aria-live', s),
		name: (s) => _attr('name', s),
		min: (s) => _attr('min', s),
		max: (s) => _attr('max', s),
		action: (s) => _attr('action', s),
		method: (s) => _attr('method', s),
		autocomplete: (s) => _attr('autocomplete', s),
		list: (s) => _attr('list', s),
		form: (s) => _attr('form', s),
		size: (s) => _attr('size', s),
	};
	const style = (x) => { return { _styles: x }; };
	const prop = (x) => { return { _props: x }; };
	return [dom, style, attr, prop];
})();
// NOTE: GENERATED by github.com/mjl-/sherpats, DO NOT MODIFY
var api;
(function (api) {
	// Validation of "message From" domain.
	let Validation;
	(function (Validation) {
		Validation[Validation["ValidationUnknown"] = 0] = "ValidationUnknown";
		Validation[Validation["ValidationStrict"] = 1] = "ValidationStrict";
		Validation[Validation["ValidationDMARC"] = 2] = "ValidationDMARC";
		Validation[Validation["ValidationRelaxed"] = 3] = "ValidationRelaxed";
		Validation[Validation["ValidationPass"] = 4] = "ValidationPass";
		Validation[Validation["ValidationNeutral"] = 5] = "ValidationNeutral";
		Validation[Validation["ValidationTemperror"] = 6] = "ValidationTemperror";
		Validation[Validation["ValidationPermerror"] = 7] = "ValidationPermerror";
		Validation[Validation["ValidationFail"] = 8] = "ValidationFail";
		Validation[Validation["ValidationSoftfail"] = 9] = "ValidationSoftfail";
		Validation[Validation["ValidationNone"] = 10] = "ValidationNone";
	})(Validation = api.Validation || (api.Validation = {}));
	let ThreadMode;
	(function (ThreadMode) {
		ThreadMode["ThreadOff"] = "off";
		ThreadMode["ThreadOn"] = "on";
		ThreadMode["ThreadUnread"] = "unread";
	})(ThreadMode = api.ThreadMode || (api.ThreadMode = {}));
	// AttachmentType is for filtering by attachment type.
	let AttachmentType;
	(function (AttachmentType) {
		AttachmentType["AttachmentIndifferent"] = "";
		AttachmentType["AttachmentNone"] = "none";
		AttachmentType["AttachmentAny"] = "any";
		AttachmentType["AttachmentImage"] = "image";
		AttachmentType["AttachmentPDF"] = "pdf";
		AttachmentType["AttachmentArchive"] = "archive";
		AttachmentType["AttachmentSpreadsheet"] = "spreadsheet";
		AttachmentType["AttachmentDocument"] = "document";
		AttachmentType["AttachmentPresentation"] = "presentation";
	})(AttachmentType = api.AttachmentType || (api.AttachmentType = {}));
	// ViewMode how a message should be viewed: its text parts, html parts, or html
	// with loading external resources.
	let ViewMode;
	(function (ViewMode) {
		ViewMode["ModeText"] = "text";
		ViewMode["ModeHTML"] = "html";
		ViewMode["ModeHTMLExt"] = "htmlext";
	})(ViewMode = api.ViewMode || (api.ViewMode = {}));
	// SecurityResult indicates whether a security feature is supported.
	let SecurityResult;
	(function (SecurityResult) {
		SecurityResult["SecurityResultError"] = "error";
		SecurityResult["SecurityResultNo"] = "no";
		SecurityResult["SecurityResultYes"] = "yes";
		// Unknown whether supported. Finding out may only be (reasonably) possible when
		// trying (e.g. SMTP STARTTLS). Once tried, the result may be cached for future
		// lookups.
		SecurityResult["SecurityResultUnknown"] = "unknown";
	})(SecurityResult = api.SecurityResult || (api.SecurityResult = {}));
	// Quoting is a setting for how to quote in replies/forwards.
	let Quoting;
	(function (Quoting) {
		Quoting["Default"] = "";
		Quoting["Bottom"] = "bottom";
		Quoting["Top"] = "top";
	})(Quoting = api.Quoting || (api.Quoting = {}));
	api.structTypes = { "Address": true, "Attachment": true, "ChangeMailboxAdd": true, "ChangeMailboxCounts": true, "ChangeMailboxKeywords": true, "ChangeMailboxRemove": true, "ChangeMailboxRename": true, "ChangeMailboxSpecialUse": true, "ChangeMsgAdd": true, "ChangeMsgFlags": true, "ChangeMsgRemove": true, "ChangeMsgThread": true, "ComposeMessage": true, "Domain": true, "DomainAddressConfig": true, "Envelope": true, "EventStart": true, "EventViewChanges": true, "EventViewErr": true, "EventViewMsgs": true, "EventViewReset": true, "File": true, "Filter": true, "Flags": true, "ForwardAttachments": true, "FromAddressSettings": true, "Mailbox": true, "Message": true, "MessageAddress": true, "MessageEnvelope": true, "MessageItem": true, "NotFilter": true, "Page": true, "ParsedMessage": true, "Part": true, "Query": true, "RecipientSecurity": true, "Request": true, "Ruleset": true, "Settings": true, "SpecialUse": true, "SubmitMessage": true };
	api.stringsTypes = { "AttachmentType": true, "CSRFToken": true, "Localpart": true, "Quoting": true, "SecurityResult": true, "ThreadMode": true, "ViewMode": true };
	api.intsTypes = { "ModSeq": true, "UID": true, "Validation": true };
	api.types = {
		"Request": { "Name": "Request", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "SSEID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Cancel", "Docs": "", "Typewords": ["bool"] }, { "Name": "Query", "Docs": "", "Typewords": ["Query"] }, { "Name": "Page", "Docs": "", "Typewords": ["Page"] }] },
		"Query": { "Name": "Query", "Docs": "", "Fields": [{ "Name": "OrderAsc", "Docs": "", "Typewords": ["bool"] }, { "Name": "Threading", "Docs": "", "Typewords": ["ThreadMode"] }, { "Name": "Filter", "Docs": "", "Typewords": ["Filter"] }, { "Name": "NotFilter", "Docs": "", "Typewords": ["NotFilter"] }] },
		"Filter": { "Name": "Filter", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxChildrenIncluded", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Words", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Oldest", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Newest", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["AttachmentType"] }, { "Name": "Labels", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Headers", "Docs": "", "Typewords": ["[]", "[]", "string"] }, { "Name": "SizeMin", "Docs": "", "Typewords": ["int64"] }, { "Name": "SizeMax", "Docs": "", "Typewords": ["int64"] }] },
		"NotFilter": { "Name": "NotFilter", "Docs": "", "Fields": [{ "Name": "Words", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["AttachmentType"] }, { "Name": "Labels", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Page": { "Name": "Page", "Docs": "", "Fields": [{ "Name": "AnchorMessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Count", "Docs": "", "Typewords": ["int32"] }, { "Name": "DestMessageID", "Docs": "", "Typewords": ["int64"] }] },
		"ParsedMessage": { "Name": "ParsedMessage", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Part", "Docs": "", "Typewords": ["Part"] }, { "Name": "Headers", "Docs": "", "Typewords": ["{}", "[]", "string"] }, { "Name": "ViewMode", "Docs": "", "Typewords": ["ViewMode"] }, { "Name": "Texts", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "HasHTML", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListReplyAddress", "Docs": "", "Typewords": ["nullable", "MessageAddress"] }, { "Name": "TextPaths", "Docs": "", "Typewords": ["[]", "[]", "int32"] }, { "Name": "HTMLPath", "Docs": "", "Typewords": ["[]", "int32"] }] },
		"Part": { "Name": "Part", "Docs": "", "Fields": [{ "Name": "BoundaryOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "HeaderOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "BodyOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "EndOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "RawLineCount", "Docs": "", "Typewords": ["int64"] }, { "Name": "DecodedSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "MediaType", "Docs": "", "Typewords": ["string"] }, { "Name": "MediaSubType", "Docs": "", "Typewords": ["string"] }, { "Name": "ContentTypeParams", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "ContentID", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentDescription", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentTransferEncoding", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentDisposition", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentMD5", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentLanguage", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentLocation", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Envelope", "Docs": "", "Typewords": ["nullable", "Envelope"] }, { "Name": "Parts", "Docs": "", "Typewords": ["[]", "Part"] }, { "Name": "Message", "Docs": "", "Typewords": ["nullable", "Part"] }] },
		"Envelope": { "Name": "Envelope", "Docs": "", "Fields": [{ "Name": "Date", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "Sender", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "CC", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "BCC", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "InReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }] },
		"Address": { "Name": "Address", "Docs": "", "Fields": [{ "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "User", "Docs": "", "Typewords": ["string"] }, { "Name": "Host", "Docs": "", "Typewords": ["string"] }] },
		"MessageAddress": { "Name": "MessageAddress", "Docs": "", "Fields": [{ "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "User", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }] },
		"Domain": { "Name": "Domain", "Docs": "", "Fields": [{ "Name": "ASCII", "Docs": "", "Typewords": ["string"] }, { "Name": "Unicode", "Docs": "", "Typewords": ["string"] }] },
		"FromAddressSettings": { "Name": "FromAddressSettings", "Docs": "", "Fields": [{ "Name": "FromAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "ViewMode", "Docs": "", "Typewords": ["ViewMode"] }] },
		"ComposeMessage": { "Name": "ComposeMessage", "Docs": "", "Fields": [{ "Name": "From", "Docs": "", "Typewords": ["string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Cc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Bcc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "TextBody", "Docs": "", "Typewords": ["string"] }, { "Name": "ResponseMessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "DraftMessageID", "Docs": "", "Typewords": ["int64"] }] },
		"SubmitMessage": { "Name": "SubmitMessage", "Docs": "", "Fields": [{ "Name": "From", "Docs": "", "Typewords": ["string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Cc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Bcc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "TextBody", "Docs": "", "Typewords": ["string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["[]", "File"] }, { "Name": "ForwardAttachments", "Docs": "", "Typewords": ["ForwardAttachments"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "ResponseMessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UserAgent", "Docs": "", "Typewords": ["string"] }, { "Name": "RequireTLS", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "FutureRelease", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "ArchiveThread", "Docs": "", "Typewords": ["bool"] }, { "Name": "ArchiveReferenceMailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "DraftMessageID", "Docs": "", "Typewords": ["int64"] }] },
		"File": { "Name": "File", "Docs": "", "Fields": [{ "Name": "Filename", "Docs": "", "Typewords": ["string"] }, { "Name": "DataURI", "Docs": "", "Typewords": ["string"] }] },
		"ForwardAttachments": { "Name": "ForwardAttachments", "Docs": "", "Fields": [{ "Name": "MessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Paths", "Docs": "", "Typewords": ["[]", "[]", "int32"] }] },
		"Mailbox": { "Name": "Mailbox", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "CreateSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Expunged", "Docs": "", "Typewords": ["bool"] }, { "Name": "ParentID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "UIDValidity", "Docs": "", "Typewords": ["uint32"] }, { "Name": "UIDNext", "Docs": "", "Typewords": ["UID"] }, { "Name": "Archive", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Sent", "Docs": "", "Typewords": ["bool"] }, { "Name": "Trash", "Docs": "", "Typewords": ["bool"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "HaveCounts", "Docs": "", "Typewords": ["bool"] }, { "Name": "Total", "Docs": "", "Typewords": ["int64"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unread", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unseen", "Docs": "", "Typewords": ["int64"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }] },
		"RecipientSecurity": { "Name": "RecipientSecurity", "Docs": "", "Fields": [{ "Name": "STARTTLS", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "MTASTS", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "DNSSEC", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "DANE", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "RequireTLS", "Docs": "", "Typewords": ["SecurityResult"] }] },
		"Settings": { "Name": "Settings", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["uint8"] }, { "Name": "Signature", "Docs": "", "Typewords": ["string"] }, { "Name": "Quoting", "Docs": "", "Typewords": ["Quoting"] }, { "Name": "ShowAddressSecurity", "Docs": "", "Typewords": ["bool"] }, { "Name": "ShowHTML", "Docs": "", "Typewords": ["bool"] }, { "Name": "NoShowShortcuts", "Docs": "", "Typewords": ["bool"] }, { "Name": "ShowHeaders", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Ruleset": { "Name": "Ruleset", "Docs": "", "Fields": [{ "Name": "SMTPMailFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "HeadersRegexp", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListAllowDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "AcceptRejectsToMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Comment", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "ListAllowDNSDomain", "Docs": "", "Typewords": ["Domain"] }] },
		"EventStart": { "Name": "EventStart", "Docs": "", "Fields": [{ "Name": "SSEID", "Docs": "", "Typewords": ["int64"] }, { "Name": "LoginAddress", "Docs": "", "Typewords": ["MessageAddress"] }, { "Name": "Addresses", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "DomainAddressConfigs", "Docs": "", "Typewords": ["{}", "DomainAddressConfig"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailboxes", "Docs": "", "Typewords": ["[]", "Mailbox"] }, { "Name": "RejectsMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Settings", "Docs": "", "Typewords": ["Settings"] }, { "Name": "AccountPath", "Docs": "", "Typewords": ["string"] }, { "Name": "Version", "Docs": "", "Typewords": ["string"] }] },
		"DomainAddressConfig": { "Name": "DomainAddressConfig", "Docs": "", "Fields": [{ "Name": "LocalpartCatchallSeparators", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "LocalpartCaseSensitive", "Docs": "", "Typewords": ["bool"] }] },
		"EventViewErr": { "Name": "EventViewErr", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Err", "Docs": "", "Typewords": ["string"] }] },
		"EventViewReset": { "Name": "EventViewReset", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }] },
		"EventViewMsgs": { "Name": "EventViewMsgs", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MessageItems", "Docs": "", "Typewords": ["[]", "[]", "MessageItem"] }, { "Name": "ParsedMessage", "Docs": "", "Typewords": ["nullable", "ParsedMessage"] }, { "Name": "ViewEnd", "Docs": "", "Typewords": ["bool"] }] },
		"MessageItem": { "Name": "MessageItem", "Docs": "", "Fields": [{ "Name": "Message", "Docs": "", "Typewords": ["Message"] }, { "Name": "Envelope", "Docs": "", "Typewords": ["MessageEnvelope"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["[]", "Attachment"] }, { "Name": "IsSigned", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsEncrypted", "Docs": "", "Typewords": ["bool"] }, { "Name": "MatchQuery", "Docs": "", "Typewords": ["bool"] }, { "Name": "MoreHeaders", "Docs": "", "Typewords": ["[]", "[]", "string"] }] },
		"Message": { "Name": "Message", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UID", "Docs": "", "Typewords": ["UID"] }, { "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "CreateSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Expunged", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsReject", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailboxOrigID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxDestinedID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Received", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "SaveDate", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "RemoteIP", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked1", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked2", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked3", "Docs": "", "Typewords": ["string"] }, { "Name": "EHLODomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFromLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "MailFromDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "RcptToLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "RcptToDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "MsgFromDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromOrgDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "EHLOValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "MsgFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "EHLOValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "MailFromValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "MsgFromValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "DKIMDomains", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "OrigEHLODomain", "Docs": "", "Typewords": ["string"] }, { "Name": "OrigDKIMDomains", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "SubjectBase", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageHash", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ThreadID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ThreadParentIDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "ThreadMissingLink", "Docs": "", "Typewords": ["bool"] }, { "Name": "ThreadMuted", "Docs": "", "Typewords": ["bool"] }, { "Name": "ThreadCollapsed", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsMailingList", "Docs": "", "Typewords": ["bool"] }, { "Name": "DSN", "Docs": "", "Typewords": ["bool"] }, { "Name": "ReceivedTLSVersion", "Docs": "", "Typewords": ["uint16"] }, { "Name": "ReceivedTLSCipherSuite", "Docs": "", "Typewords": ["uint16"] }, { "Name": "ReceivedRequireTLS", "Docs": "", "Typewords": ["bool"] }, { "Name": "Seen", "Docs": "", "Typewords": ["bool"] }, { "Name": "Answered", "Docs": "", "Typewords": ["bool"] }, { "Name": "Flagged", "Docs": "", "Typewords": ["bool"] }, { "Name": "Forwarded", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Notjunk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Phishing", "Docs": "", "Typewords": ["bool"] }, { "Name": "MDNSent", "Docs": "", "Typewords": ["bool"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }, { "Name": "TrainedJunk", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "MsgPrefix", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Preview", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ParsedBuf", "Docs": "", "Typewords": ["nullable", "string"] }] },
		"MessageEnvelope": { "Name": "MessageEnvelope", "Docs": "", "Fields": [{ "Name": "Date", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "Sender", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "CC", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "BCC", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "InReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }] },
		"Attachment": { "Name": "Attachment", "Docs": "", "Fields": [{ "Name": "Path", "Docs": "", "Typewords": ["[]", "int32"] }, { "Name": "Filename", "Docs": "", "Typewords": ["string"] }, { "Name": "Part", "Docs": "", "Typewords": ["Part"] }] },
		"EventViewChanges": { "Name": "EventViewChanges", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Changes", "Docs": "", "Typewords": ["[]", "[]", "any"] }] },
		"ChangeMsgAdd": { "Name": "ChangeMsgAdd", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UID", "Docs": "", "Typewords": ["UID"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Flags", "Docs": "", "Typewords": ["Flags"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "MessageCountIMAP", "Docs": "", "Typewords": ["uint32"] }, { "Name": "Unseen", "Docs": "", "Typewords": ["uint32"] }, { "Name": "MessageItems", "Docs": "", "Typewords": ["[]", "MessageItem"] }] },
		"Flags": { "Name": "Flags", "Docs": "", "Fields": [{ "Name": "Seen", "Docs": "", "Typewords": ["bool"] }, { "Name": "Answered", "Docs": "", "Typewords": ["bool"] }, { "Name": "Flagged", "Docs": "", "Typewords": ["bool"] }, { "Name": "Forwarded", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Notjunk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Phishing", "Docs": "", "Typewords": ["bool"] }, { "Name": "MDNSent", "Docs": "", "Typewords": ["bool"] }] },
		"ChangeMsgRemove": { "Name": "ChangeMsgRemove", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UIDs", "Docs": "", "Typewords": ["[]", "UID"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "MsgIDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "UIDNext", "Docs": "", "Typewords": ["UID"] }, { "Name": "MessageCountIMAP", "Docs": "", "Typewords": ["uint32"] }, { "Name": "Unseen", "Docs": "", "Typewords": ["uint32"] }] },
		"ChangeMsgFlags": { "Name": "ChangeMsgFlags", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UID", "Docs": "", "Typewords": ["UID"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Mask", "Docs": "", "Typewords": ["Flags"] }, { "Name": "Flags", "Docs": "", "Typewords": ["Flags"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "UIDValidity", "Docs": "", "Typewords": ["uint32"] }, { "Name": "Unseen", "Docs": "", "Typewords": ["uint32"] }] },
		"ChangeMsgThread": { "Name": "ChangeMsgThread", "Docs": "", "Fields": [{ "Name": "MessageIDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "Muted", "Docs": "", "Typewords": ["bool"] }, { "Name": "Collapsed", "Docs": "", "Typewords": ["bool"] }] },
		"ChangeMailboxRemove": { "Name": "ChangeMailboxRemove", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }] },
		"ChangeMailboxAdd": { "Name": "ChangeMailboxAdd", "Docs": "", "Fields": [{ "Name": "Mailbox", "Docs": "", "Typewords": ["Mailbox"] }] },
		"ChangeMailboxRename": { "Name": "ChangeMailboxRename", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "OldName", "Docs": "", "Typewords": ["string"] }, { "Name": "NewName", "Docs": "", "Typewords": ["string"] }, { "Name": "Flags", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }] },
		"ChangeMailboxCounts": { "Name": "ChangeMailboxCounts", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Total", "Docs": "", "Typewords": ["int64"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unread", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unseen", "Docs": "", "Typewords": ["int64"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }] },
		"ChangeMailboxSpecialUse": { "Name": "ChangeMailboxSpecialUse", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "SpecialUse", "Docs": "", "Typewords": ["SpecialUse"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }] },
		"SpecialUse": { "Name": "SpecialUse", "Docs": "", "Fields": [{ "Name": "Archive", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Sent", "Docs": "", "Typewords": ["bool"] }, { "Name": "Trash", "Docs": "", "Typewords": ["bool"] }] },
		"ChangeMailboxKeywords": { "Name": "ChangeMailboxKeywords", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }] },
		"ModSeq": { "Name": "ModSeq", "Docs": "", "Values": null },
		"UID": { "Name": "UID", "Docs": "", "Values": null },
		"Validation": { "Name": "Validation", "Docs": "", "Values": [{ "Name": "ValidationUnknown", "Value": 0, "Docs": "" }, { "Name": "ValidationStrict", "Value": 1, "Docs": "" }, { "Name": "ValidationDMARC", "Value": 2, "Docs": "" }, { "Name": "ValidationRelaxed", "Value": 3, "Docs": "" }, { "Name": "ValidationPass", "Value": 4, "Docs": "" }, { "Name": "ValidationNeutral", "Value": 5, "Docs": "" }, { "Name": "ValidationTemperror", "Value": 6, "Docs": "" }, { "Name": "ValidationPermerror", "Value": 7, "Docs": "" }, { "Name": "ValidationFail", "Value": 8, "Docs": "" }, { "Name": "ValidationSoftfail", "Value": 9, "Docs": "" }, { "Name": "ValidationNone", "Value": 10, "Docs": "" }] },
		"CSRFToken": { "Name": "CSRFToken", "Docs": "", "Values": null },
		"ThreadMode": { "Name": "ThreadMode", "Docs": "", "Values": [{ "Name": "ThreadOff", "Value": "off", "Docs": "" }, { "Name": "ThreadOn", "Value": "on", "Docs": "" }, { "Name": "ThreadUnread", "Value": "unread", "Docs": "" }] },
		"AttachmentType": { "Name": "AttachmentType", "Docs": "", "Values": [{ "Name": "AttachmentIndifferent", "Value": "", "Docs": "" }, { "Name": "AttachmentNone", "Value": "none", "Docs": "" }, { "Name": "AttachmentAny", "Value": "any", "Docs": "" }, { "Name": "AttachmentImage", "Value": "image", "Docs": "" }, { "Name": "AttachmentPDF", "Value": "pdf", "Docs": "" }, { "Name": "AttachmentArchive", "Value": "archive", "Docs": "" }, { "Name": "AttachmentSpreadsheet", "Value": "spreadsheet", "Docs": "" }, { "Name": "AttachmentDocument", "Value": "document", "Docs": "" }, { "Name": "AttachmentPresentation", "Value": "presentation", "Docs": "" }] },
		"ViewMode": { "Name": "ViewMode", "Docs": "", "Values": [{ "Name": "ModeText", "Value": "text", "Docs": "" }, { "Name": "ModeHTML", "Value": "html", "Docs": "" }, { "Name": "ModeHTMLExt", "Value": "htmlext", "Docs": "" }] },
		"SecurityResult": { "Name": "SecurityResult", "Docs": "", "Values": [{ "Name": "SecurityResultError", "Value": "error", "Docs": "" }, { "Name": "SecurityResultNo", "Value": "no", "Docs": "" }, { "Name": "SecurityResultYes", "Value": "yes", "Docs": "" }, { "Name": "SecurityResultUnknown", "Value": "unknown", "Docs": "" }] },
		"Quoting": { "Name": "Quoting", "Docs": "", "Values": [{ "Name": "Default", "Value": "", "Docs": "" }, { "Name": "Bottom", "Value": "bottom", "Docs": "" }, { "Name": "Top", "Value": "top", "Docs": "" }] },
		"Localpart": { "Name": "Localpart", "Docs": "", "Values": null },
	};
	api.parser = {
		Request: (v) => api.parse("Request", v),
		Query: (v) => api.parse("Query", v),
		Filter: (v) => api.parse("Filter", v),
		NotFilter: (v) => api.parse("NotFilter", v),
		Page: (v) => api.parse("Page", v),
		ParsedMessage: (v) => api.parse("ParsedMessage", v),
		Part: (v) => api.parse("Part", v),
		Envelope: (v) => api.parse("Envelope", v),
		Address: (v) => api.parse("Address", v),
		MessageAddress: (v) => api.parse("MessageAddress", v),
		Domain: (v) => api.parse("Domain", v),
		FromAddressSettings: (v) => api.parse("FromAddressSettings", v),
		ComposeMessage: (v) => api.parse("ComposeMessage", v),
		SubmitMessage: (v) => api.parse("SubmitMessage", v),
		File: (v) => api.parse("File", v),
		ForwardAttachments: (v) => api.parse("ForwardAttachments", v),
		Mailbox: (v) => api.parse("Mailbox", v),
		RecipientSecurity: (v) => api.parse("RecipientSecurity", v),
		Settings: (v) => api.parse("Settings", v),
		Ruleset: (v) => api.parse("Ruleset", v),
		EventStart: (v) => api.parse("EventStart", v),
		DomainAddressConfig: (v) => api.parse("DomainAddressConfig", v),
		EventViewErr: (v) => api.parse("EventViewErr", v),
		EventViewReset: (v) => api.parse("EventViewReset", v),
		EventViewMsgs: (v) => api.parse("EventViewMsgs", v),
		MessageItem: (v) => api.parse("MessageItem", v),
		Message: (v) => api.parse("Message", v),
		MessageEnvelope: (v) => api.parse("MessageEnvelope", v),
		Attachment: (v) => api.parse("Attachment", v),
		EventViewChanges: (v) => api.parse("EventViewChanges", v),
		ChangeMsgAdd: (v) => api.parse("ChangeMsgAdd", v),
		Flags: (v) => api.parse("Flags", v),
		ChangeMsgRemove: (v) => api.parse("ChangeMsgRemove", v),
		ChangeMsgFlags: (v) => api.parse("ChangeMsgFlags", v),
		ChangeMsgThread: (v) => api.parse("ChangeMsgThread", v),
		ChangeMailboxRemove: (v) => api.parse("ChangeMailboxRemove", v),
		ChangeMailboxAdd: (v) => api.parse("ChangeMailboxAdd", v),
		ChangeMailboxRename: (v) => api.parse("ChangeMailboxRename", v),
		ChangeMailboxCounts: (v) => api.parse("ChangeMailboxCounts", v),
		ChangeMailboxSpecialUse: (v) => api.parse("ChangeMailboxSpecialUse", v),
		SpecialUse: (v) => api.parse("SpecialUse", v),
		ChangeMailboxKeywords: (v) => api.parse("ChangeMailboxKeywords", v),
		ModSeq: (v) => api.parse("ModSeq", v),
		UID: (v) => api.parse("UID", v),
		Validation: (v) => api.parse("Validation", v),
		CSRFToken: (v) => api.parse("CSRFToken", v),
		ThreadMode: (v) => api.parse("ThreadMode", v),
		AttachmentType: (v) => api.parse("AttachmentType", v),
		ViewMode: (v) => api.parse("ViewMode", v),
		SecurityResult: (v) => api.parse("SecurityResult", v),
		Quoting: (v) => api.parse("Quoting", v),
		Localpart: (v) => api.parse("Localpart", v),
	};
	let defaultOptions = { slicesNullable: true, mapsNullable: true, nullableOptional: true };
	class Client {
		baseURL;
		authState;
		options;
		constructor() {
			this.authState = {};
			this.options = { ...defaultOptions };
			this.baseURL = this.options.baseURL || api.defaultBaseURL;
		}
		withAuthToken(token) {
			const c = new Client();
			c.authState.token = token;
			c.options = this.options;
			return c;
		}
		withOptions(options) {
			const c = new Client();
			c.authState = this.authState;
			c.options = { ...this.options, ...options };
			return c;
		}
		// LoginPrep returns a login token, and also sets it as cookie. Both must be
		// present in the call to Login.
		async LoginPrep() {
			const fn = "LoginPrep";
			const paramTypes = [];
			const returnTypes = [["string"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Login returns a session token for the credentials, or fails with error code
		// "user:badLogin". Call LoginPrep to get a loginToken.
		async Login(loginToken, username, password) {
			const fn = "Login";
			const paramTypes = [["string"], ["string"], ["string"]];
			const returnTypes = [["CSRFToken"]];
			const params = [loginToken, username, password];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Logout invalidates the session token.
		async Logout() {
			const fn = "Logout";
			const paramTypes = [];
			const returnTypes = [];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Version returns the version, goos and goarch.
		async Version() {
			const fn = "Version";
			const paramTypes = [];
			const returnTypes = [["string"], ["string"], ["string"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Token returns a single-use token to use for an SSE connection. A token can only
		// be used for a single SSE connection. Tokens are stored in memory for a maximum
		// of 1 minute, with at most 10 unused tokens (the most recently created) per
		// account.
		async Token() {
			const fn = "Token";
			const paramTypes = [];
			const returnTypes = [["string"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Requests sends a new request for an open SSE connection. Any currently active
		// request for the connection will be canceled, but this is done asynchrously, so
		// the SSE connection may still send results for the previous request. Callers
		// should take care to ignore such results. If req.Cancel is set, no new request is
		// started.
		async Request(req) {
			const fn = "Request";
			const paramTypes = [["Request"]];
			const returnTypes = [];
			const params = [req];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// ParsedMessage returns enough to render the textual body of a message. It is
		// assumed the client already has other fields through MessageItem.
		async ParsedMessage(msgID) {
			const fn = "ParsedMessage";
			const paramTypes = [["int64"]];
			const returnTypes = [["ParsedMessage"]];
			const params = [msgID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// FromAddressSettingsSave saves per-"From"-address settings.
		async FromAddressSettingsSave(fas) {
			const fn = "FromAddressSettingsSave";
			const paramTypes = [["FromAddressSettings"]];
			const returnTypes = [];
			const params = [fas];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MessageFindMessageID looks up a message by Message-Id header, and returns the ID
		// of the message in storage. Used when opening a previously saved draft message
		// for editing again.
		// If no message is find, zero is returned, not an error.
		async MessageFindMessageID(messageID) {
			const fn = "MessageFindMessageID";
			const paramTypes = [["string"]];
			const returnTypes = [["int64"]];
			const params = [messageID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MessageCompose composes a message and saves it to the mailbox. Used for
		// saving draft messages.
		async MessageCompose(m, mailboxID) {
			const fn = "MessageCompose";
			const paramTypes = [["ComposeMessage"], ["int64"]];
			const returnTypes = [["int64"]];
			const params = [m, mailboxID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MessageSubmit sends a message by submitting it the outgoing email queue. The
		// message is sent to all addresses listed in the To, Cc and Bcc addresses, without
		// Bcc message header.
		// 
		// If a Sent mailbox is configured, messages are added to it after submitting
		// to the delivery queue. If Bcc addresses were present, a header is prepended
		// to the message stored in the Sent mailbox.
		async MessageSubmit(m) {
			const fn = "MessageSubmit";
			const paramTypes = [["SubmitMessage"]];
			const returnTypes = [];
			const params = [m];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MessageMove moves messages to another mailbox. If the message is already in
		// the mailbox an error is returned.
		async MessageMove(messageIDs, mailboxID) {
			const fn = "MessageMove";
			const paramTypes = [["[]", "int64"], ["int64"]];
			const returnTypes = [];
			const params = [messageIDs, mailboxID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MessageDelete permanently deletes messages, without moving them to the Trash mailbox.
		async MessageDelete(messageIDs) {
			const fn = "MessageDelete";
			const paramTypes = [["[]", "int64"]];
			const returnTypes = [];
			const params = [messageIDs];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// FlagsAdd adds flags, either system flags like \Seen or custom keywords. The
		// flags should be lower-case, but will be converted and verified.
		async FlagsAdd(messageIDs, flaglist) {
			const fn = "FlagsAdd";
			const paramTypes = [["[]", "int64"], ["[]", "string"]];
			const returnTypes = [];
			const params = [messageIDs, flaglist];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// FlagsClear clears flags, either system flags like \Seen or custom keywords.
		async FlagsClear(messageIDs, flaglist) {
			const fn = "FlagsClear";
			const paramTypes = [["[]", "int64"], ["[]", "string"]];
			const returnTypes = [];
			const params = [messageIDs, flaglist];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MailboxesMarkRead marks all messages in mailboxes as read. Child mailboxes are
		// not automatically included, they must explicitly be included in the list of IDs.
		async MailboxesMarkRead(mailboxIDs) {
			const fn = "MailboxesMarkRead";
			const paramTypes = [["[]", "int64"]];
			const returnTypes = [];
			const params = [mailboxIDs];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MailboxCreate creates a new mailbox.
		async MailboxCreate(name) {
			const fn = "MailboxCreate";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [name];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MailboxDelete deletes a mailbox and all its messages and annotations.
		async MailboxDelete(mailboxID) {
			const fn = "MailboxDelete";
			const paramTypes = [["int64"]];
			const returnTypes = [];
			const params = [mailboxID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MailboxEmpty empties a mailbox, removing all messages from the mailbox, but not
		// its child mailboxes.
		async MailboxEmpty(mailboxID) {
			const fn = "MailboxEmpty";
			const paramTypes = [["int64"]];
			const returnTypes = [];
			const params = [mailboxID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MailboxRename renames a mailbox, possibly moving it to a new parent. The mailbox
		// ID and its messages are unchanged.
		async MailboxRename(mailboxID, newName) {
			const fn = "MailboxRename";
			const paramTypes = [["int64"], ["string"]];
			const returnTypes = [];
			const params = [mailboxID, newName];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// CompleteRecipient returns autocomplete matches for a recipient, returning the
		// matches, most recently used first, and whether this is the full list and further
		// requests for longer prefixes aren't necessary.
		async CompleteRecipient(search) {
			const fn = "CompleteRecipient";
			const paramTypes = [["string"]];
			const returnTypes = [["[]", "string"], ["bool"]];
			const params = [search];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MailboxSetSpecialUse sets the special use flags of a mailbox.
		async MailboxSetSpecialUse(mb) {
			const fn = "MailboxSetSpecialUse";
			const paramTypes = [["Mailbox"]];
			const returnTypes = [];
			const params = [mb];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// ThreadCollapse saves the ThreadCollapse field for the messages and its
		// children. The messageIDs are typically thread roots. But not all roots
		// (without parent) of a thread need to have the same collapsed state.
		async ThreadCollapse(messageIDs, collapse) {
			const fn = "ThreadCollapse";
			const paramTypes = [["[]", "int64"], ["bool"]];
			const returnTypes = [];
			const params = [messageIDs, collapse];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// ThreadMute saves the ThreadMute field for the messages and their children.
		// If messages are muted, they are also marked collapsed.
		async ThreadMute(messageIDs, mute) {
			const fn = "ThreadMute";
			const paramTypes = [["[]", "int64"], ["bool"]];
			const returnTypes = [];
			const params = [messageIDs, mute];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// RecipientSecurity looks up security properties of the address in the
		// single-address message addressee (as it appears in a To/Cc/Bcc/etc header).
		async RecipientSecurity(messageAddressee) {
			const fn = "RecipientSecurity";
			const paramTypes = [["string"]];
			const returnTypes = [["RecipientSecurity"]];
			const params = [messageAddressee];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DecodeMIMEWords decodes Q/B-encoded words for a mime headers into UTF-8 text.
		async DecodeMIMEWords(text) {
			const fn = "DecodeMIMEWords";
			const paramTypes = [["string"]];
			const returnTypes = [["string"]];
			const params = [text];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// SettingsSave saves settings, e.g. for composing.
		async SettingsSave(settings) {
			const fn = "SettingsSave";
			const paramTypes = [["Settings"]];
			const returnTypes = [];
			const params = [settings];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async RulesetSuggestMove(msgID, mbSrcID, mbDstID) {
			const fn = "RulesetSuggestMove";
			const paramTypes = [["int64"], ["int64"], ["int64"]];
			const returnTypes = [["string"], ["string"], ["bool"], ["string"], ["nullable", "Ruleset"]];
			const params = [msgID, mbSrcID, mbDstID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async RulesetAdd(rcptTo, ruleset) {
			const fn = "RulesetAdd";
			const paramTypes = [["string"], ["Ruleset"]];
			const returnTypes = [];
			const params = [rcptTo, ruleset];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async RulesetRemove(rcptTo, ruleset) {
			const fn = "RulesetRemove";
			const paramTypes = [["string"], ["Ruleset"]];
			const returnTypes = [];
			const params = [rcptTo, ruleset];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async RulesetMessageNever(rcptTo, listID, msgFrom, toInbox) {
			const fn = "RulesetMessageNever";
			const paramTypes = [["string"], ["string"], ["string"], ["bool"]];
			const returnTypes = [];
			const params = [rcptTo, listID, msgFrom, toInbox];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async RulesetMailboxNever(mailboxID, toMailbox) {
			const fn = "RulesetMailboxNever";
			const paramTypes = [["int64"], ["bool"]];
			const returnTypes = [];
			const params = [mailboxID, toMailbox];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// SSETypes exists to ensure the generated API contains the types, for use in SSE events.
		async SSETypes() {
			const fn = "SSETypes";
			const paramTypes = [];
			const returnTypes = [["EventStart"], ["EventViewErr"], ["EventViewReset"], ["EventViewMsgs"], ["EventViewChanges"], ["ChangeMsgAdd"], ["ChangeMsgRemove"], ["ChangeMsgFlags"], ["ChangeMsgThread"], ["ChangeMailboxRemove"], ["ChangeMailboxAdd"], ["ChangeMailboxRename"], ["ChangeMailboxCounts"], ["ChangeMailboxSpecialUse"], ["ChangeMailboxKeywords"], ["Flags"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
	}
	api.Client = Client;
	api.defaultBaseURL = (function () {
		let p = location.pathname;
		if (p && p[p.length - 1] !== '/') {
			let l = location.pathname.split('/');
			l = l.slice(0, l.length - 1);
			p = '/' + l.join('/') + '/';
		}
		return location.protocol + '//' + location.host + p + 'api/';
	})();
	// NOTE: code below is shared between github.com/mjl-/sherpaweb and github.com/mjl-/sherpats.
	// KEEP IN SYNC.
	api.supportedSherpaVersion = 1;
	// verifyArg typechecks "v" against "typewords", returning a new (possibly modified) value for JSON-encoding.
	// toJS indicate if the data is coming into JS. If so, timestamps are turned into JS Dates. Otherwise, JS Dates are turned into strings.
	// allowUnknownKeys configures whether unknown keys in structs are allowed.
	// types are the named types of the API.
	api.verifyArg = (path, v, typewords, toJS, allowUnknownKeys, types, opts) => {
		return new verifier(types, toJS, allowUnknownKeys, opts).verify(path, v, typewords);
	};
	api.parse = (name, v) => api.verifyArg(name, v, [name], true, false, api.types, defaultOptions);
	class verifier {
		types;
		toJS;
		allowUnknownKeys;
		opts;
		constructor(types, toJS, allowUnknownKeys, opts) {
			this.types = types;
			this.toJS = toJS;
			this.allowUnknownKeys = allowUnknownKeys;
			this.opts = opts;
		}
		verify(path, v, typewords) {
			typewords = typewords.slice(0);
			const ww = typewords.shift();
			const error = (msg) => {
				if (path != '') {
					msg = path + ': ' + msg;
				}
				throw new Error(msg);
			};
			if (typeof ww !== 'string') {
				error('bad typewords');
				return; // should not be necessary, typescript doesn't see error always throws an exception?
			}
			const w = ww;
			const ensure = (ok, expect) => {
				if (!ok) {
					error('got ' + JSON.stringify(v) + ', expected ' + expect);
				}
				return v;
			};
			switch (w) {
				case 'nullable':
					if (v === null || v === undefined && this.opts.nullableOptional) {
						return v;
					}
					return this.verify(path, v, typewords);
				case '[]':
					if (v === null && this.opts.slicesNullable || v === undefined && this.opts.slicesNullable && this.opts.nullableOptional) {
						return v;
					}
					ensure(Array.isArray(v), "array");
					return v.map((e, i) => this.verify(path + '[' + i + ']', e, typewords));
				case '{}':
					if (v === null && this.opts.mapsNullable || v === undefined && this.opts.mapsNullable && this.opts.nullableOptional) {
						return v;
					}
					ensure(v !== null || typeof v === 'object', "object");
					const r = {};
					for (const k in v) {
						r[k] = this.verify(path + '.' + k, v[k], typewords);
					}
					return r;
			}
			ensure(typewords.length == 0, "empty typewords");
			const t = typeof v;
			switch (w) {
				case 'any':
					return v;
				case 'bool':
					ensure(t === 'boolean', 'bool');
					return v;
				case 'int8':
				case 'uint8':
				case 'int16':
				case 'uint16':
				case 'int32':
				case 'uint32':
				case 'int64':
				case 'uint64':
					ensure(t === 'number' && Number.isInteger(v), 'integer');
					return v;
				case 'float32':
				case 'float64':
					ensure(t === 'number', 'float');
					return v;
				case 'int64s':
				case 'uint64s':
					ensure(t === 'number' && Number.isInteger(v) || t === 'string', 'integer fitting in float without precision loss, or string');
					return '' + v;
				case 'string':
					ensure(t === 'string', 'string');
					return v;
				case 'timestamp':
					if (this.toJS) {
						ensure(t === 'string', 'string, with timestamp');
						const d = new Date(v);
						if (d instanceof Date && !isNaN(d.getTime())) {
							return d;
						}
						error('invalid date ' + v);
					}
					else {
						ensure(t === 'object' && v !== null, 'non-null object');
						ensure(v.__proto__ === Date.prototype, 'Date');
						return v.toISOString();
					}
			}
			// We're left with named types.
			const nt = this.types[w];
			if (!nt) {
				error('unknown type ' + w);
			}
			if (v === null) {
				error('bad value ' + v + ' for named type ' + w);
			}
			if (api.structTypes[nt.Name]) {
				const t = nt;
				if (typeof v !== 'object') {
					error('bad value ' + v + ' for struct ' + w);
				}
				const r = {};
				for (const f of t.Fields) {
					r[f.Name] = this.verify(path + '.' + f.Name, v[f.Name], f.Typewords);
				}
				// If going to JSON also verify no unknown fields are present.
				if (!this.allowUnknownKeys) {
					const known = {};
					for (const f of t.Fields) {
						known[f.Name] = true;
					}
					Object.keys(v).forEach((k) => {
						if (!known[k]) {
							error('unknown key ' + k + ' for struct ' + w);
						}
					});
				}
				return r;
			}
			else if (api.stringsTypes[nt.Name]) {
				const t = nt;
				if (typeof v !== 'string') {
					error('mistyped value ' + v + ' for named strings ' + t.Name);
				}
				if (!t.Values || t.Values.length === 0) {
					return v;
				}
				for (const sv of t.Values) {
					if (sv.Value === v) {
						return v;
					}
				}
				error('unknown value ' + v + ' for named strings ' + t.Name);
			}
			else if (api.intsTypes[nt.Name]) {
				const t = nt;
				if (typeof v !== 'number' || !Number.isInteger(v)) {
					error('mistyped value ' + v + ' for named ints ' + t.Name);
				}
				if (!t.Values || t.Values.length === 0) {
					return v;
				}
				for (const sv of t.Values) {
					if (sv.Value === v) {
						return v;
					}
				}
				error('unknown value ' + v + ' for named ints ' + t.Name);
			}
			else {
				throw new Error('unexpected named type ' + nt);
			}
		}
	}
	const _sherpaCall = async (baseURL, authState, options, paramTypes, returnTypes, name, params) => {
		if (!options.skipParamCheck) {
			if (params.length !== paramTypes.length) {
				return Promise.reject({ message: 'wrong number of parameters in sherpa call, saw ' + params.length + ' != expected ' + paramTypes.length });
			}
			params = params.map((v, index) => api.verifyArg('params[' + index + ']', v, paramTypes[index], false, false, api.types, options));
		}
		const simulate = async (json) => {
			const config = JSON.parse(json || 'null') || {};
			const waitMinMsec = config.waitMinMsec || 0;
			const waitMaxMsec = config.waitMaxMsec || 0;
			const wait = Math.random() * (waitMaxMsec - waitMinMsec);
			const failRate = config.failRate || 0;
			return new Promise((resolve, reject) => {
				if (options.aborter) {
					options.aborter.abort = () => {
						reject({ message: 'call to ' + name + ' aborted by user', code: 'sherpa:aborted' });
						reject = resolve = () => { };
					};
				}
				setTimeout(() => {
					const r = Math.random();
					if (r < failRate) {
						reject({ message: 'injected failure on ' + name, code: 'server:injected' });
					}
					else {
						resolve();
					}
					reject = resolve = () => { };
				}, waitMinMsec + wait);
			});
		};
		// Only simulate when there is a debug string. Otherwise it would always interfere
		// with setting options.aborter.
		let json = '';
		try {
			json = window.localStorage.getItem('sherpats-debug') || '';
		}
		catch (err) { }
		if (json) {
			await simulate(json);
		}
		const fn = (resolve, reject) => {
			let resolve1 = (v) => {
				resolve(v);
				resolve1 = () => { };
				reject1 = () => { };
			};
			let reject1 = (v) => {
				if ((v.code === 'user:noAuth' || v.code === 'user:badAuth') && options.login) {
					const login = options.login;
					if (!authState.loginPromise) {
						authState.loginPromise = new Promise((aresolve, areject) => {
							login(v.code === 'user:badAuth' ? (v.message || '') : '')
								.then((token) => {
								authState.token = token;
								authState.loginPromise = undefined;
								aresolve();
							}, (err) => {
								authState.loginPromise = undefined;
								areject(err);
							});
						});
					}
					authState.loginPromise
						.then(() => {
						fn(resolve, reject);
					}, (err) => {
						reject(err);
					});
					return;
				}
				reject(v);
				resolve1 = () => { };
				reject1 = () => { };
			};
			const url = baseURL + name;
			const req = new window.XMLHttpRequest();
			if (options.aborter) {
				options.aborter.abort = () => {
					req.abort();
					reject1({ code: 'sherpa:aborted', message: 'request aborted' });
				};
			}
			req.open('POST', url, true);
			if (options.csrfHeader && authState.token) {
				req.setRequestHeader(options.csrfHeader, authState.token);
			}
			if (options.timeoutMsec) {
				req.timeout = options.timeoutMsec;
			}
			req.onload = () => {
				if (req.status !== 200) {
					if (req.status === 404) {
						reject1({ code: 'sherpa:badFunction', message: 'function does not exist' });
					}
					else {
						reject1({ code: 'sherpa:http', message: 'error calling function, HTTP status: ' + req.status });
					}
					return;
				}
				let resp;
				try {
					resp = JSON.parse(req.responseText);
				}
				catch (err) {
					reject1({ code: 'sherpa:badResponse', message: 'bad JSON from server' });
					return;
				}
				if (resp && resp.error) {
					const err = resp.error;
					reject1({ code: err.code, message: err.message });
					return;
				}
				else if (!resp || !resp.hasOwnProperty('result')) {
					reject1({ code: 'sherpa:badResponse', message: "invalid sherpa response object, missing 'result'" });
					return;
				}
				if (options.skipReturnCheck) {
					resolve1(resp.result);
					return;
				}
				let result = resp.result;
				try {
					if (returnTypes.length === 0) {
						if (result) {
							throw new Error('function ' + name + ' returned a value while prototype says it returns "void"');
						}
					}
					else if (returnTypes.length === 1) {
						result = api.verifyArg('result', result, returnTypes[0], true, true, api.types, options);
					}
					else {
						if (result.length != returnTypes.length) {
							throw new Error('wrong number of values returned by ' + name + ', saw ' + result.length + ' != expected ' + returnTypes.length);
						}
						result = result.map((v, index) => api.verifyArg('result[' + index + ']', v, returnTypes[index], true, true, api.types, options));
					}
				}
				catch (err) {
					let errmsg = 'bad types';
					if (err instanceof Error) {
						errmsg = err.message;
					}
					reject1({ code: 'sherpa:badTypes', message: errmsg });
				}
				resolve1(result);
			};
			req.onerror = () => {
				reject1({ code: 'sherpa:connection', message: 'connection failed' });
			};
			req.ontimeout = () => {
				reject1({ code: 'sherpa:timeout', message: 'request timeout' });
			};
			req.setRequestHeader('Content-Type', 'application/json');
			try {
				req.send(JSON.stringify({ params: params }));
			}
			catch (err) {
				reject1({ code: 'sherpa:badData', message: 'cannot marshal to JSON' });
			}
		};
		return await new Promise(fn);
	};
})(api || (api = {}));
// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.
// We build CSS rules in JS. For several reasons:
// - To keep the style definitions closer to their use.
// - To make it easier to provide both light/regular and dark mode colors.
// - To use class names for styling, instead of the the many inline styles.
//   Makes it easier to look through a DOM, and easier to change the style of all
//   instances of a class.
const cssStyleDark = dom.style(attr.type('text/css'));
document.head.prepend(cssStyleDark);
const styleSheetDark = cssStyleDark.sheet;
styleSheetDark.insertRule('@media (prefers-color-scheme: dark) {}');
const darkModeRule = styleSheetDark.cssRules[0];
// We keep the default/regular styles and dark-mode styles in separate stylesheets.
const cssStyle = dom.style(attr.type('text/css'));
document.head.prepend(cssStyle);
const styleSheet = cssStyle.sheet;
let cssRules = {}; // For ensuring a selector has a single definition.
// Ensure a selector has the given style properties. If a style value is an array,
// it must have 2 elements. The first is the default value, the second used for a
// rule for dark mode.
const ensureCSS = (selector, styles, important) => {
	// Check that a selector isn't added again with different styling. Only during development.
	const checkConsistency = location.hostname === 'localhost';
	if (cssRules[selector]) {
		if (checkConsistency) {
			const exp = JSON.stringify(styles);
			if (cssRules[selector] !== exp) {
				throw new Error('duplicate css rule for selector ' + selector + ', had ' + cssRules[selector] + ', next ' + exp);
			}
		}
		return;
	}
	cssRules[selector] = checkConsistency ? JSON.stringify(styles) : 'x';
	const index = styleSheet.cssRules.length;
	styleSheet.insertRule(selector + ' {}', index);
	const st = styleSheet.cssRules[index].style;
	let darkst;
	for (let [k, v] of Object.entries(styles)) {
		// We've kept the camel-case in our code which we had from when we did "st[prop] =
		// value". It is more convenient as object keys. So convert to kebab-case, but only
		// if this is not a css property.
		if (!k.startsWith('--')) {
			k = k.replace(/[A-Z]/g, s => '-' + s.toLowerCase());
		}
		if (Array.isArray(v)) {
			if (v.length !== 2) {
				throw new Error('2 elements required for light/dark mode style, got ' + v.length);
			}
			if (!darkst) {
				const darkIndex = darkModeRule.cssRules.length;
				darkModeRule.insertRule(selector + ' {}', darkIndex);
				darkst = darkModeRule.cssRules[darkIndex].style;
			}
			st.setProperty(k, '' + v[0], important ? 'important' : '');
			darkst.setProperty(k, '' + v[1], important ? 'important' : '');
		}
		else {
			st.setProperty(k, '' + v, important ? 'important' : '');
		}
	}
};
// Ensure CSS styling exists for a class, returning the same kind of object
// returned by dom._class, for use with dom.*-building functions.
const css = (className, styles, important) => {
	ensureCSS('.' + className, styles, important);
	return dom._class(className);
};
// todo: reduce number of colors. hopefully we can derive some colors from a few base colors (making them brighter/darker, or shifting hue, etc). then make them configurable through settings.
// todo: add the standard padding and border-radius, perhaps more.
// We define css variables, making them easy to override.
ensureCSS(':root', {
	'--color': ['black', '#ddd'],
	'--colorMild': ['#555', '#bbb'],
	'--colorMilder': ['#666', '#aaa'],
	'--backgroundColor': ['white', '#222'],
	'--backgroundColorMild': ['#f8f8f8', '#080808'],
	'--backgroundColorMilder': ['#999', '#777'],
	'--borderColor': ['#ccc', '#333'],
	'--mailboxesTopBackgroundColor': ['#fdfdf1', '#1a1200'],
	'--msglistBackgroundColor': ['#f5ffff', '#04130d'],
	'--boxShadow': ['0 0 20px rgba(0, 0, 0, 0.1)', '0px 0px 20px #000'],
	'--buttonBackground': ['#eee', '#222'],
	'--buttonBorderColor': ['#888', '#666'],
	'--buttonHoverBackground': ['#ddd', '#333'],
	'--overlayOpaqueBackgroundColor': ['#eee', '#011'],
	'--overlayBackgroundColor': ['rgba(0, 0, 0, 0.2)', 'rgba(0, 0, 0, 0.5)'],
	'--popupColor': ['black', 'white'],
	'--popupBackgroundColor': ['white', '#313233'],
	'--popupBorderColor': ['#ccc', '#555'],
	'--highlightBackground': ['gold', '#a70167'],
	'--highlightBorderColor': ['#8c7600', '#fd1fa7'],
	'--highlightBackgroundHover': ['#ffbd21', '#710447'],
	'--mailboxActiveBackground': ['linear-gradient(135deg, #ffc7ab 0%, #ffdeab 100%)', 'linear-gradient(135deg, #b63d00 0%, #8c5a0d 100%)'],
	'--mailboxHoverBackgroundColor': ['#eee', '#421f15'],
	'--msgItemActiveBackground': ['linear-gradient(135deg, #8bc8ff 0%, #8ee5ff 100%)', 'linear-gradient(135deg, #045cac 0%, #027ba0 100%)'],
	'--msgItemHoverBackgroundColor': ['#eee', '#073348'],
	'--msgItemFocusBorderColor': ['#2685ff', '#2685ff'],
	'--buttonTristateOnBackground': ['#c4ffa9', '#277e00'],
	'--buttonTristateOffBackground': ['#ffb192', '#bf410f'],
	'--warningBackgroundColor': ['#ffca91', '#a85700'],
	'--successBackground': ['#d2f791', '#1fa204'],
	'--emphasisBackground': ['#666', '#aaa'],
	// For authentication/security results.
	'--underlineGreen': '#50c40f',
	'--underlineRed': '#e15d1c',
	'--underlineBlue': '#09f',
	'--underlineGrey': '#888',
	'--quoted1Color': ['#03828f', '#71f2ff'],
	'--quoted2Color': ['#c7445c', '#ec4c4c'],
	'--quoted3Color': ['#417c10', '#73e614'],
	'--scriptSwitchUnderlineColor': ['#dca053', '#e88f1e'],
	'--linkColor': ['#096bc2', '#63b6ff'],
	'--linkVisitedColor': ['#0704c1', '#c763ff'],
});
// Typed way to reference a css variables. Kept from before used variables.
const styles = {
	color: 'var(--color)',
	colorMild: 'var(--colorMild)',
	colorMilder: 'var(--colorMilder)',
	backgroundColor: 'var(--backgroundColor)',
	backgroundColorMild: 'var(--backgroundColorMild)',
	backgroundColorMilder: 'var(--backgroundColorMilder)',
	borderColor: 'var(--borderColor)',
	mailboxesTopBackgroundColor: 'var(--mailboxesTopBackgroundColor)',
	msglistBackgroundColor: 'var(--msglistBackgroundColor)',
	boxShadow: 'var(--boxShadow)',
	buttonBackground: 'var(--buttonBackground)',
	buttonBorderColor: 'var(--buttonBorderColor)',
	buttonHoverBackground: 'var(--buttonHoverBackground)',
	overlayOpaqueBackgroundColor: 'var(--overlayOpaqueBackgroundColor)',
	overlayBackgroundColor: 'var(--overlayBackgroundColor)',
	popupColor: 'var(--popupColor)',
	popupBackgroundColor: 'var(--popupBackgroundColor)',
	popupBorderColor: 'var(--popupBorderColor)',
	highlightBackground: 'var(--highlightBackground)',
	highlightBorderColor: 'var(--highlightBorderColor)',
	highlightBackgroundHover: 'var(--highlightBackgroundHover)',
	mailboxActiveBackground: 'var(--mailboxActiveBackground)',
	mailboxHoverBackgroundColor: 'var(--mailboxHoverBackgroundColor)',
	msgItemActiveBackground: 'var(--msgItemActiveBackground)',
	msgItemHoverBackgroundColor: 'var(--msgItemHoverBackgroundColor)',
	msgItemFocusBorderColor: 'var(--msgItemFocusBorderColor)',
	buttonTristateOnBackground: 'var(--buttonTristateOnBackground)',
	buttonTristateOffBackground: 'var(--buttonTristateOffBackground)',
	warningBackgroundColor: 'var(--warningBackgroundColor)',
	successBackground: 'var(--successBackground)',
	emphasisBackground: 'var(--emphasisBackground)',
	// For authentication/security results.
	underlineGreen: 'var(--underlineGreen)',
	underlineRed: 'var(--underlineRed)',
	underlineBlue: 'var(--underlineBlue)',
	underlineGrey: 'var(--underlineGrey)',
	quoted1Color: 'var(--quoted1Color)',
	quoted2Color: 'var(--quoted2Color)',
	quoted3Color: 'var(--quoted3Color)',
	scriptSwitchUnderlineColor: 'var(--scriptSwitchUnderlineColor)',
	linkColor: 'var(--linkColor)',
	linkVisitedColor: 'var(--linkVisitedColor)',
};
const styleClasses = {
	// For quoted text, with multiple levels of indentations.
	quoted: [
		css('quoted1', { color: styles.quoted1Color }),
		css('quoted2', { color: styles.quoted2Color }),
		css('quoted3', { color: styles.quoted3Color }),
	],
	// When text switches between unicode scripts.
	scriptswitch: css('scriptswitch', { textDecoration: 'underline 2px', textDecorationColor: styles.scriptSwitchUnderlineColor }),
	textMild: css('textMild', { color: styles.colorMild }),
	// For keywords (also known as flags/labels/tags) on messages.
	keyword: css('keyword', { padding: '0 .15em', borderRadius: '.15em', fontWeight: 'normal', fontSize: '.9em', margin: '0 .15em', whiteSpace: 'nowrap', background: styles.highlightBackground, color: styles.color, border: '1px solid', borderColor: styles.highlightBorderColor }),
	msgHeaders: css('msgHeaders', { marginBottom: '1ex', width: '100%' }),
};
ensureCSS('.msgHeaders td', { wordBreak: 'break-word' }); // Prevent horizontal scroll bar for long header values.
ensureCSS('.keyword.keywordCollapsed', { opacity: .75 }),
	// Generic styling.
	ensureCSS('html', { backgroundColor: 'var(--backgroundColor)', color: 'var(--color)' });
ensureCSS('*', { fontSize: 'inherit', fontFamily: "'ubuntu', 'lato', sans-serif", margin: 0, padding: 0, boxSizing: 'border-box' });
ensureCSS('.mono, .mono *', { fontFamily: "'ubuntu mono', monospace" });
ensureCSS('table td, table th', { padding: '.15em .25em' });
ensureCSS('.pad', { padding: '.5em' });
ensureCSS('iframe', { border: 0 });
ensureCSS('img, embed, video, iframe', { backgroundColor: 'white', color: 'black' });
ensureCSS('a', { color: styles.linkColor });
ensureCSS('a:visited', { color: styles.linkVisitedColor });
// For message view with multiple inline elements (often a single text and multiple messages).
ensureCSS('.textmulti > *:nth-child(even)', { backgroundColor: ['#f4f4f4', '#141414'] });
ensureCSS('.textmulti > *', { padding: '2ex .5em', margin: '-.5em' /* compensate pad */ });
ensureCSS('.textmulti > *:first-child', { padding: '.5em' });
// join elements in l with the results of calls to efn. efn can return
// HTMLElements, which cannot be inserted into the dom multiple times, hence the
// function.
const join = (l, efn) => {
	const r = [];
	const n = l.length;
	for (let i = 0; i < n; i++) {
		r.push(l[i]);
		if (i < n - 1) {
			r.push(efn());
		}
	}
	return r;
};
// From https://developer.mozilla.org/en-US/docs/Web/Media/Formats/Image_types
const imageTypes = [
	'image/avif',
	'image/webp',
	'image/gif',
	'image/png',
	'image/jpeg',
	'image/apng',
	'image/svg+xml',
];
const isImage = (a) => imageTypes.includes((a.Part.MediaType + '/' + a.Part.MediaSubType).toLowerCase());
// addLinks turns a line of text into alternating strings and links. Links that
// would end with interpunction followed by whitespace are returned with that
// interpunction moved to the next string instead.
const addLinks = (text) => {
	// todo: look at ../rfc/3986 and fix up regexp. we should probably accept utf-8.
	const re = RegExp('(?:(http|https):\/\/|mailto:)([:%0-9a-zA-Z._~!$&\'/()*+,;=-]+@)?([\\[\\]0-9a-zA-Z.-]+)(:[0-9]+)?([:@%0-9a-zA-Z._~!$&\'/()*+,;=-]*)(\\?[:@%0-9a-zA-Z._~!$&\'/()*+,;=?-]*)?(#[:@%0-9a-zA-Z._~!$&\'/()*+,;=?-]*)?');
	const r = [];
	while (text.length > 0) {
		const l = re.exec(text);
		if (!l) {
			r.push(text);
			break;
		}
		let s = text.substring(0, l.index);
		let url = l[0];
		text = text.substring(l.index + url.length);
		r.push(s);
		// If URL ends with interpunction, and next character is whitespace or end, don't
		// include the interpunction in the URL.
		if (!text || /^[ \t\r\n]/.test(text)) {
			if (/[)>][!,.:;?]$/.test(url)) {
				text = url.substring(url.length - 2) + text;
				url = url.substring(0, url.length - 2);
			}
			else if (/[)>!,.:;?]$/.test(url)) {
				text = url.substring(url.length - 1) + text;
				url = url.substring(0, url.length - 1);
			}
		}
		r.push(dom.a(url, attr.href(url), url.startsWith('mailto:') ? [] : [attr.target('_blank'), attr.rel('noopener noreferrer')]));
	}
	return r;
};
// renderText turns text into a renderable element with ">" interpreted as quoted
// text (with different levels), and URLs replaced by links.
const renderText = (text) => {
	return dom.div(text.split('\n').map(line => {
		let q = 0;
		for (const c of line) {
			if (c == '>') {
				q++;
			}
			else if (c !== ' ') {
				break;
			}
		}
		if (q == 0) {
			return [addLinks(line), '\n'];
		}
		return dom.div(styleClasses.quoted[q % styleClasses.quoted.length], addLinks(line));
	}));
};
const displayName = (s) => {
	// ../rfc/5322:1216
	// ../rfc/5322:1270
	// todo: need support for group addresses (eg "undisclosed recipients").
	// ../rfc/5322:697
	const specials = /[()<>\[\]:;@\\,."]/;
	if (specials.test(s)) {
		return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"';
	}
	return s;
};
const formatDomain = (dom) => dom.Unicode || dom.ASCII;
// format an address with both name and email address.
const formatAddress = (a) => {
	let s = '<' + a.User + '@' + formatDomain(a.Domain) + '>';
	if (a.Name) {
		s = displayName(a.Name) + ' ' + s;
	}
	return s;
};
// Like formatAddress, but returns an element with a title (for hover) with the ASCII domain, in case of IDN.
const formatAddressElem = (a) => {
	if (!a.Domain.Unicode) {
		return formatAddress(a);
	}
	return dom.span(a.Name ? [displayName(a.Name), ' '] : '', '<', a.User, '@', dom.span(attr.title(a.Domain.ASCII), formatDomain(a.Domain)), '>');
};
// like formatAddress, but underline domain with dmarc-like validation if appropriate.
const formatAddressValidated = (a, m, use) => {
	const domainText = (domstr, ascii) => {
		if (!use) {
			return domstr;
		}
		const extra = domstr === ascii ? '' : '; domain ' + ascii;
		// We want to show how "approved" this message is given the message From's domain.
		// We have MsgFromValidation available. It's not the greatest, being a mix of
		// potential strict validations, actual DMARC policy validation, potential relaxed
		// validation, but no explicit fail or (temporary) errors. We also don't know if
		// historic messages were from a mailing list. We could add a heuristic based on
		// List-Id headers, but it would be unreliable...
		// todo: add field to Message with the exact results.
		let name = '';
		let color = '';
		let title = '';
		switch (m.MsgFromValidation) {
			case api.Validation.ValidationStrict:
				name = 'Strict';
				color = styles.underlineGreen;
				title = 'Message would have matched a strict DMARC policy.';
				break;
			case api.Validation.ValidationDMARC:
				name = 'DMARC';
				color = styles.underlineGreen;
				title = 'Message matched DMARC policy of domain.';
				break;
			case api.Validation.ValidationRelaxed:
				name = 'Relaxed';
				color = styles.underlineGreen;
				title = 'Domain did not have a DMARC policy, but message would match a relaxed policy if it had existed.';
				break;
			case api.Validation.ValidationNone:
				if (m.IsForward || m.IsMailingList) {
					name = 'Forwardlist';
					color = styles.underlineBlue;
					title = 'Message would not pass DMARC policy, but came in through a configured mailing list or forwarding address.';
				}
				else {
					name = 'Bad';
					color = styles.underlineRed;
					title = 'Either domain did not have a DMARC policy, or message did not adhere to it.';
				}
				break;
			default:
				// Also for zero value, when unknown. E.g. for sent messages added with IMAP.
				name = 'Unknown';
				title = 'Unknown DMARC verification result.';
				return dom.span(attr.title(title + extra), domstr);
		}
		return dom.span(attr.title(title + extra), css('addressValidation' + name, { borderBottom: '1.5px solid', borderBottomColor: color, textDecoration: 'none' }), domstr);
	};
	let l = [];
	if (a.Name) {
		l.push(a.Name + ' ');
	}
	l.push('<' + a.User + '@');
	l.push(domainText(formatDomain(a.Domain), a.Domain.ASCII));
	l.push('>');
	return l;
};
// format just the name if present and it doesn't look like an address, or otherwise just the email address.
const formatAddressShort = (a, junk) => {
	const n = a.Name;
	if (!junk && n && !n.includes('<') && !n.includes('@') && !n.includes('>')) {
		return n;
	}
	return '<' + a.User + '@' + formatDomain(a.Domain) + '>';
};
// return just the email address.
const formatEmail = (a) => a.User + '@' + formatDomain(a.Domain);
const equalAddress = (a, b) => {
	return (!a.User || !b.User || a.User === b.User) && a.Domain.ASCII === b.Domain.ASCII;
};
const addressList = (allAddrs, l) => {
	if (l.length <= 5 || allAddrs) {
		return dom.span(join(l.map(a => formatAddressElem(a)), () => ', '));
	}
	let elem = dom.span(join(l.slice(0, 4).map(a => formatAddressElem(a)), () => ', '), ' ', dom.clickbutton('More...', attr.title('More addresses:\n' + l.slice(4).map(a => formatAddress(a)).join(',\n')), function click() {
		const nelem = dom.span(join(l.map(a => formatAddressElem(a)), () => ', '), ' ', dom.clickbutton('Less...', function click() {
			elem.replaceWith(addressList(allAddrs, l));
		}));
		elem.replaceWith(nelem);
		elem = nelem;
	}));
	return elem;
};
// loadMsgheaderView loads the common message headers into msgheaderelem.
// if refineKeyword is set, labels are shown and a click causes a call to
// refineKeyword.
const loadMsgheaderView = (msgheaderelem, mi, moreHeaders, refineKeyword, allAddrs) => {
	const msgenv = mi.Envelope;
	const received = mi.Message.Received;
	const receivedlocal = new Date(received.getTime());
	// Similar to webmail.ts:/headerTextMildStyle
	const msgHeaderFieldStyle = css('msgHeaderField', { textAlign: 'right', color: styles.colorMild, whiteSpace: 'nowrap' });
	const msgAttrStyle = css('msgAttr', { padding: '0px 0.15em', fontSize: '.9em' });
	dom._kids(msgheaderelem, 
	// todo: make addresses clickable, start search (keep current mailbox if any)
	dom.tr(dom.td('From:', msgHeaderFieldStyle), dom.td(style({ width: '100%' }), dom.div(css('msgFromReceivedSpread', { display: 'flex', justifyContent: 'space-between' }), dom.div(join((msgenv.From || []).map(a => formatAddressValidated(a, mi.Message, !!msgenv.From && msgenv.From.length === 1)), () => ', ')), dom.div(attr.title('Received: ' + received.toString() + ';\nDate header in message: ' + (msgenv.Date ? msgenv.Date.toString() : '(missing/invalid)')), receivedlocal.toDateString() + ' ' + receivedlocal.toTimeString().split(' ')[0])))), (msgenv.ReplyTo || []).length === 0 ? [] : dom.tr(dom.td('Reply-To:', msgHeaderFieldStyle), dom.td(join((msgenv.ReplyTo || []).map(a => formatAddressElem(a)), () => ', '))), dom.tr(dom.td('To:', msgHeaderFieldStyle), dom.td(addressList(allAddrs, msgenv.To || []))), (msgenv.CC || []).length === 0 ? [] : dom.tr(dom.td('Cc:', msgHeaderFieldStyle), dom.td(addressList(allAddrs, msgenv.CC || []))), (msgenv.BCC || []).length === 0 ? [] : dom.tr(dom.td('Bcc:', msgHeaderFieldStyle), dom.td(addressList(allAddrs, msgenv.BCC || []))), dom.tr(dom.td('Subject:', msgHeaderFieldStyle), dom.td(dom.div(css('msgSubjectAttrsSpread', { display: 'flex', justifyContent: 'space-between' }), dom.div(msgenv.Subject || ''), dom.div(mi.Message.IsForward ? dom.span(msgAttrStyle, 'Forwarded', attr.title('Message came in from a forwarded address. Some message authentication policies, like DMARC, were not evaluated.')) : [], mi.Message.IsMailingList ? dom.span(msgAttrStyle, 'Mailing list', attr.title('Message was received from a mailing list. Some message authentication policies, like DMARC, were not evaluated.')) : [], mi.Message.ReceivedTLSVersion === 1 ? dom.span(msgAttrStyle, css('msgAttrNoTLS', { borderBottom: '1.5px solid', borderBottomColor: styles.underlineRed }), 'Without TLS', attr.title('Message received (last hop) without TLS.')) : [], mi.Message.ReceivedTLSVersion > 1 && !mi.Message.ReceivedRequireTLS ? dom.span(msgAttrStyle, css('msgAttrTLS', { borderBottom: '1.5px solid', borderBottomColor: styles.underlineGreen }), 'With TLS', attr.title('Message received (last hop) with TLS.')) : [], mi.Message.ReceivedRequireTLS ? dom.span(css('msgAttrRequireTLS', { padding: '.1em .3em', fontSize: '.9em', backgroundColor: styles.successBackground, border: '1px solid', borderColor: styles.borderColor, borderRadius: '3px' }), 'With RequireTLS', attr.title('Transported with RequireTLS, ensuring TLS along the entire delivery path from sender to recipient, with TLS certificate verification through MTA-STS and/or DANE.')) : [], mi.IsSigned ? dom.span(msgAttrStyle, css('msgAttrSigned', { backgroundColor: styles.colorMild, color: styles.backgroundColorMild, borderRadius: '.15em' }), 'Message has a signature') : [], mi.IsEncrypted ? dom.span(msgAttrStyle, css('msgAttrEncrypted', { backgroundColor: styles.colorMild, color: styles.backgroundColorMild, borderRadius: '.15em' }), 'Message is encrypted') : [], refineKeyword ? (mi.Message.Keywords || []).map(kw => dom.clickbutton(styleClasses.keyword, dom._class('keywordButton'), kw, async function click() {
		await refineKeyword(kw);
	})) : [])))), (mi.MoreHeaders || []).map(t => dom.tr(dom.td(t[0] + ':', msgHeaderFieldStyle), dom.td(t[1]))), 
	// Ensure width of all possible additional headers is taken into account, to
	// prevent different layout between messages when not all headers are present.
	dom.tr(dom.td(moreHeaders.map(s => dom.div(s + ':', msgHeaderFieldStyle, style({ visibility: 'hidden', height: 0 })))), dom.td()));
};
// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.
const init = () => {
	const mi = api.parser.MessageItem(messageItem);
	document.title = '"' + mi.Envelope.Subject + '"- from ' + ((mi.Envelope.From || []).map(a => formatAddress(a)).join(', ') || '-') + ' (id ' + mi.Message.ID + ')';
	let msgattachmentview = dom.div();
	if (mi.Attachments && mi.Attachments.length > 0) {
		dom._kids(msgattachmentview, dom.div(css('msgAttachments', { borderTop: '1px solid', borderTopColor: styles.borderColor }), dom.div(dom._class('pad'), 'Attachments: ', join(mi.Attachments.map(a => a.Filename || '(unnamed)'), () => ', '))));
	}
	const msgheaderview = dom.tbody();
	loadMsgheaderView(msgheaderview, mi, [], null, true);
	const l = window.location.pathname.split('/');
	const w = l[l.length - 1];
	let iframepath;
	if (w === 'msgtext') {
		iframepath = 'text';
	}
	else if (w === 'msghtml') {
		iframepath = 'html';
	}
	else if (w === 'msghtmlexternal') {
		iframepath = 'htmlexternal';
	}
	else {
		window.alert('Unknown message type ' + w);
		return;
	}
	iframepath += '?sameorigin=true';
	let iframe;
	const page = document.getElementById('page');
	const root = dom.div(dom.div(css('msgMeta', { backgroundColor: styles.backgroundColorMild, borderBottom: '1px solid', borderBottomColor: styles.borderColor }), dom.table(styleClasses.msgHeaders, msgheaderview), msgattachmentview), iframe = dom.iframe(attr.title('Message body.'), attr.src(iframepath), css('msgIframe', { width: '100%', height: '100%' }), function load() {
		// Note: we load the iframe content specifically in a way that fires the load event only when the content is fully rendered.
		iframe.style.height = iframe.contentDocument.documentElement.scrollHeight + 'px';
		if (window.location.hash === '#print') {
			window.print();
		}
	}));
	if (typeof moxBeforeDisplay !== 'undefined') {
		moxBeforeDisplay(root);
	}
	dom._kids(page, root);
};
try {
	init();
}
catch (err) {
	window.alert('Error: ' + (err.message || '(no message)'));
}
