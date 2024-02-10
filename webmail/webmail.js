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
	api.structTypes = { "Address": true, "Attachment": true, "ChangeMailboxAdd": true, "ChangeMailboxCounts": true, "ChangeMailboxKeywords": true, "ChangeMailboxRemove": true, "ChangeMailboxRename": true, "ChangeMailboxSpecialUse": true, "ChangeMsgAdd": true, "ChangeMsgFlags": true, "ChangeMsgRemove": true, "ChangeMsgThread": true, "Domain": true, "DomainAddressConfig": true, "Envelope": true, "EventStart": true, "EventViewChanges": true, "EventViewErr": true, "EventViewMsgs": true, "EventViewReset": true, "File": true, "Filter": true, "Flags": true, "ForwardAttachments": true, "Mailbox": true, "Message": true, "MessageAddress": true, "MessageEnvelope": true, "MessageItem": true, "NotFilter": true, "Page": true, "ParsedMessage": true, "Part": true, "Query": true, "RecipientSecurity": true, "Request": true, "SpecialUse": true, "SubmitMessage": true };
	api.stringsTypes = { "AttachmentType": true, "CSRFToken": true, "Localpart": true, "SecurityResult": true, "ThreadMode": true };
	api.intsTypes = { "ModSeq": true, "UID": true, "Validation": true };
	api.types = {
		"Request": { "Name": "Request", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "SSEID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Cancel", "Docs": "", "Typewords": ["bool"] }, { "Name": "Query", "Docs": "", "Typewords": ["Query"] }, { "Name": "Page", "Docs": "", "Typewords": ["Page"] }] },
		"Query": { "Name": "Query", "Docs": "", "Fields": [{ "Name": "OrderAsc", "Docs": "", "Typewords": ["bool"] }, { "Name": "Threading", "Docs": "", "Typewords": ["ThreadMode"] }, { "Name": "Filter", "Docs": "", "Typewords": ["Filter"] }, { "Name": "NotFilter", "Docs": "", "Typewords": ["NotFilter"] }] },
		"Filter": { "Name": "Filter", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxChildrenIncluded", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Words", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Oldest", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Newest", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["AttachmentType"] }, { "Name": "Labels", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Headers", "Docs": "", "Typewords": ["[]", "[]", "string"] }, { "Name": "SizeMin", "Docs": "", "Typewords": ["int64"] }, { "Name": "SizeMax", "Docs": "", "Typewords": ["int64"] }] },
		"NotFilter": { "Name": "NotFilter", "Docs": "", "Fields": [{ "Name": "Words", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["AttachmentType"] }, { "Name": "Labels", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Page": { "Name": "Page", "Docs": "", "Fields": [{ "Name": "AnchorMessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Count", "Docs": "", "Typewords": ["int32"] }, { "Name": "DestMessageID", "Docs": "", "Typewords": ["int64"] }] },
		"ParsedMessage": { "Name": "ParsedMessage", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Part", "Docs": "", "Typewords": ["Part"] }, { "Name": "Headers", "Docs": "", "Typewords": ["{}", "[]", "string"] }, { "Name": "Texts", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "HasHTML", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListReplyAddress", "Docs": "", "Typewords": ["nullable", "MessageAddress"] }] },
		"Part": { "Name": "Part", "Docs": "", "Fields": [{ "Name": "BoundaryOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "HeaderOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "BodyOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "EndOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "RawLineCount", "Docs": "", "Typewords": ["int64"] }, { "Name": "DecodedSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "MediaType", "Docs": "", "Typewords": ["string"] }, { "Name": "MediaSubType", "Docs": "", "Typewords": ["string"] }, { "Name": "ContentTypeParams", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "ContentID", "Docs": "", "Typewords": ["string"] }, { "Name": "ContentDescription", "Docs": "", "Typewords": ["string"] }, { "Name": "ContentTransferEncoding", "Docs": "", "Typewords": ["string"] }, { "Name": "Envelope", "Docs": "", "Typewords": ["nullable", "Envelope"] }, { "Name": "Parts", "Docs": "", "Typewords": ["[]", "Part"] }, { "Name": "Message", "Docs": "", "Typewords": ["nullable", "Part"] }] },
		"Envelope": { "Name": "Envelope", "Docs": "", "Fields": [{ "Name": "Date", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "Sender", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "CC", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "BCC", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "InReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }] },
		"Address": { "Name": "Address", "Docs": "", "Fields": [{ "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "User", "Docs": "", "Typewords": ["string"] }, { "Name": "Host", "Docs": "", "Typewords": ["string"] }] },
		"MessageAddress": { "Name": "MessageAddress", "Docs": "", "Fields": [{ "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "User", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }] },
		"Domain": { "Name": "Domain", "Docs": "", "Fields": [{ "Name": "ASCII", "Docs": "", "Typewords": ["string"] }, { "Name": "Unicode", "Docs": "", "Typewords": ["string"] }] },
		"SubmitMessage": { "Name": "SubmitMessage", "Docs": "", "Fields": [{ "Name": "From", "Docs": "", "Typewords": ["string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Cc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Bcc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "TextBody", "Docs": "", "Typewords": ["string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["[]", "File"] }, { "Name": "ForwardAttachments", "Docs": "", "Typewords": ["ForwardAttachments"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "ResponseMessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "UserAgent", "Docs": "", "Typewords": ["string"] }, { "Name": "RequireTLS", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "FutureRelease", "Docs": "", "Typewords": ["nullable", "timestamp"] }] },
		"File": { "Name": "File", "Docs": "", "Fields": [{ "Name": "Filename", "Docs": "", "Typewords": ["string"] }, { "Name": "DataURI", "Docs": "", "Typewords": ["string"] }] },
		"ForwardAttachments": { "Name": "ForwardAttachments", "Docs": "", "Fields": [{ "Name": "MessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Paths", "Docs": "", "Typewords": ["[]", "[]", "int32"] }] },
		"Mailbox": { "Name": "Mailbox", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "UIDValidity", "Docs": "", "Typewords": ["uint32"] }, { "Name": "UIDNext", "Docs": "", "Typewords": ["UID"] }, { "Name": "Archive", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Sent", "Docs": "", "Typewords": ["bool"] }, { "Name": "Trash", "Docs": "", "Typewords": ["bool"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "HaveCounts", "Docs": "", "Typewords": ["bool"] }, { "Name": "Total", "Docs": "", "Typewords": ["int64"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unread", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unseen", "Docs": "", "Typewords": ["int64"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }] },
		"RecipientSecurity": { "Name": "RecipientSecurity", "Docs": "", "Fields": [{ "Name": "STARTTLS", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "MTASTS", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "DNSSEC", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "DANE", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "RequireTLS", "Docs": "", "Typewords": ["SecurityResult"] }] },
		"EventStart": { "Name": "EventStart", "Docs": "", "Fields": [{ "Name": "SSEID", "Docs": "", "Typewords": ["int64"] }, { "Name": "LoginAddress", "Docs": "", "Typewords": ["MessageAddress"] }, { "Name": "Addresses", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "DomainAddressConfigs", "Docs": "", "Typewords": ["{}", "DomainAddressConfig"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailboxes", "Docs": "", "Typewords": ["[]", "Mailbox"] }, { "Name": "RejectsMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Version", "Docs": "", "Typewords": ["string"] }] },
		"DomainAddressConfig": { "Name": "DomainAddressConfig", "Docs": "", "Fields": [{ "Name": "LocalpartCatchallSeparator", "Docs": "", "Typewords": ["string"] }, { "Name": "LocalpartCaseSensitive", "Docs": "", "Typewords": ["bool"] }] },
		"EventViewErr": { "Name": "EventViewErr", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Err", "Docs": "", "Typewords": ["string"] }] },
		"EventViewReset": { "Name": "EventViewReset", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }] },
		"EventViewMsgs": { "Name": "EventViewMsgs", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MessageItems", "Docs": "", "Typewords": ["[]", "[]", "MessageItem"] }, { "Name": "ParsedMessage", "Docs": "", "Typewords": ["nullable", "ParsedMessage"] }, { "Name": "ViewEnd", "Docs": "", "Typewords": ["bool"] }] },
		"MessageItem": { "Name": "MessageItem", "Docs": "", "Fields": [{ "Name": "Message", "Docs": "", "Typewords": ["Message"] }, { "Name": "Envelope", "Docs": "", "Typewords": ["MessageEnvelope"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["[]", "Attachment"] }, { "Name": "IsSigned", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsEncrypted", "Docs": "", "Typewords": ["bool"] }, { "Name": "FirstLine", "Docs": "", "Typewords": ["string"] }, { "Name": "MatchQuery", "Docs": "", "Typewords": ["bool"] }] },
		"Message": { "Name": "Message", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UID", "Docs": "", "Typewords": ["UID"] }, { "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "CreateSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Expunged", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsReject", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailboxOrigID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxDestinedID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Received", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "RemoteIP", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked1", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked2", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked3", "Docs": "", "Typewords": ["string"] }, { "Name": "EHLODomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFromLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "MailFromDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "RcptToLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "RcptToDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "MsgFromDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromOrgDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "EHLOValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "MsgFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "EHLOValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "MailFromValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "MsgFromValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "DKIMDomains", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "OrigEHLODomain", "Docs": "", "Typewords": ["string"] }, { "Name": "OrigDKIMDomains", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "SubjectBase", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageHash", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ThreadID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ThreadParentIDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "ThreadMissingLink", "Docs": "", "Typewords": ["bool"] }, { "Name": "ThreadMuted", "Docs": "", "Typewords": ["bool"] }, { "Name": "ThreadCollapsed", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsMailingList", "Docs": "", "Typewords": ["bool"] }, { "Name": "ReceivedTLSVersion", "Docs": "", "Typewords": ["uint16"] }, { "Name": "ReceivedTLSCipherSuite", "Docs": "", "Typewords": ["uint16"] }, { "Name": "ReceivedRequireTLS", "Docs": "", "Typewords": ["bool"] }, { "Name": "Seen", "Docs": "", "Typewords": ["bool"] }, { "Name": "Answered", "Docs": "", "Typewords": ["bool"] }, { "Name": "Flagged", "Docs": "", "Typewords": ["bool"] }, { "Name": "Forwarded", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Notjunk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Phishing", "Docs": "", "Typewords": ["bool"] }, { "Name": "MDNSent", "Docs": "", "Typewords": ["bool"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }, { "Name": "TrainedJunk", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "MsgPrefix", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ParsedBuf", "Docs": "", "Typewords": ["nullable", "string"] }] },
		"MessageEnvelope": { "Name": "MessageEnvelope", "Docs": "", "Fields": [{ "Name": "Date", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "Sender", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "CC", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "BCC", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "InReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }] },
		"Attachment": { "Name": "Attachment", "Docs": "", "Fields": [{ "Name": "Path", "Docs": "", "Typewords": ["[]", "int32"] }, { "Name": "Filename", "Docs": "", "Typewords": ["string"] }, { "Name": "Part", "Docs": "", "Typewords": ["Part"] }] },
		"EventViewChanges": { "Name": "EventViewChanges", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Changes", "Docs": "", "Typewords": ["[]", "[]", "any"] }] },
		"ChangeMsgAdd": { "Name": "ChangeMsgAdd", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UID", "Docs": "", "Typewords": ["UID"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Flags", "Docs": "", "Typewords": ["Flags"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "MessageItems", "Docs": "", "Typewords": ["[]", "MessageItem"] }] },
		"Flags": { "Name": "Flags", "Docs": "", "Fields": [{ "Name": "Seen", "Docs": "", "Typewords": ["bool"] }, { "Name": "Answered", "Docs": "", "Typewords": ["bool"] }, { "Name": "Flagged", "Docs": "", "Typewords": ["bool"] }, { "Name": "Forwarded", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Notjunk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Phishing", "Docs": "", "Typewords": ["bool"] }, { "Name": "MDNSent", "Docs": "", "Typewords": ["bool"] }] },
		"ChangeMsgRemove": { "Name": "ChangeMsgRemove", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UIDs", "Docs": "", "Typewords": ["[]", "UID"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }] },
		"ChangeMsgFlags": { "Name": "ChangeMsgFlags", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UID", "Docs": "", "Typewords": ["UID"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Mask", "Docs": "", "Typewords": ["Flags"] }, { "Name": "Flags", "Docs": "", "Typewords": ["Flags"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }] },
		"ChangeMsgThread": { "Name": "ChangeMsgThread", "Docs": "", "Fields": [{ "Name": "MessageIDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "Muted", "Docs": "", "Typewords": ["bool"] }, { "Name": "Collapsed", "Docs": "", "Typewords": ["bool"] }] },
		"ChangeMailboxRemove": { "Name": "ChangeMailboxRemove", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Name", "Docs": "", "Typewords": ["string"] }] },
		"ChangeMailboxAdd": { "Name": "ChangeMailboxAdd", "Docs": "", "Fields": [{ "Name": "Mailbox", "Docs": "", "Typewords": ["Mailbox"] }] },
		"ChangeMailboxRename": { "Name": "ChangeMailboxRename", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "OldName", "Docs": "", "Typewords": ["string"] }, { "Name": "NewName", "Docs": "", "Typewords": ["string"] }, { "Name": "Flags", "Docs": "", "Typewords": ["[]", "string"] }] },
		"ChangeMailboxCounts": { "Name": "ChangeMailboxCounts", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Total", "Docs": "", "Typewords": ["int64"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unread", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unseen", "Docs": "", "Typewords": ["int64"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }] },
		"ChangeMailboxSpecialUse": { "Name": "ChangeMailboxSpecialUse", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "SpecialUse", "Docs": "", "Typewords": ["SpecialUse"] }] },
		"SpecialUse": { "Name": "SpecialUse", "Docs": "", "Fields": [{ "Name": "Archive", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Sent", "Docs": "", "Typewords": ["bool"] }, { "Name": "Trash", "Docs": "", "Typewords": ["bool"] }] },
		"ChangeMailboxKeywords": { "Name": "ChangeMailboxKeywords", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }] },
		"UID": { "Name": "UID", "Docs": "", "Values": null },
		"ModSeq": { "Name": "ModSeq", "Docs": "", "Values": null },
		"Validation": { "Name": "Validation", "Docs": "", "Values": [{ "Name": "ValidationUnknown", "Value": 0, "Docs": "" }, { "Name": "ValidationStrict", "Value": 1, "Docs": "" }, { "Name": "ValidationDMARC", "Value": 2, "Docs": "" }, { "Name": "ValidationRelaxed", "Value": 3, "Docs": "" }, { "Name": "ValidationPass", "Value": 4, "Docs": "" }, { "Name": "ValidationNeutral", "Value": 5, "Docs": "" }, { "Name": "ValidationTemperror", "Value": 6, "Docs": "" }, { "Name": "ValidationPermerror", "Value": 7, "Docs": "" }, { "Name": "ValidationFail", "Value": 8, "Docs": "" }, { "Name": "ValidationSoftfail", "Value": 9, "Docs": "" }, { "Name": "ValidationNone", "Value": 10, "Docs": "" }] },
		"CSRFToken": { "Name": "CSRFToken", "Docs": "", "Values": null },
		"ThreadMode": { "Name": "ThreadMode", "Docs": "", "Values": [{ "Name": "ThreadOff", "Value": "off", "Docs": "" }, { "Name": "ThreadOn", "Value": "on", "Docs": "" }, { "Name": "ThreadUnread", "Value": "unread", "Docs": "" }] },
		"AttachmentType": { "Name": "AttachmentType", "Docs": "", "Values": [{ "Name": "AttachmentIndifferent", "Value": "", "Docs": "" }, { "Name": "AttachmentNone", "Value": "none", "Docs": "" }, { "Name": "AttachmentAny", "Value": "any", "Docs": "" }, { "Name": "AttachmentImage", "Value": "image", "Docs": "" }, { "Name": "AttachmentPDF", "Value": "pdf", "Docs": "" }, { "Name": "AttachmentArchive", "Value": "archive", "Docs": "" }, { "Name": "AttachmentSpreadsheet", "Value": "spreadsheet", "Docs": "" }, { "Name": "AttachmentDocument", "Value": "document", "Docs": "" }, { "Name": "AttachmentPresentation", "Value": "presentation", "Docs": "" }] },
		"SecurityResult": { "Name": "SecurityResult", "Docs": "", "Values": [{ "Name": "SecurityResultError", "Value": "error", "Docs": "" }, { "Name": "SecurityResultNo", "Value": "no", "Docs": "" }, { "Name": "SecurityResultYes", "Value": "yes", "Docs": "" }, { "Name": "SecurityResultUnknown", "Value": "unknown", "Docs": "" }] },
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
		SubmitMessage: (v) => api.parse("SubmitMessage", v),
		File: (v) => api.parse("File", v),
		ForwardAttachments: (v) => api.parse("ForwardAttachments", v),
		Mailbox: (v) => api.parse("Mailbox", v),
		RecipientSecurity: (v) => api.parse("RecipientSecurity", v),
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
		UID: (v) => api.parse("UID", v),
		ModSeq: (v) => api.parse("ModSeq", v),
		Validation: (v) => api.parse("Validation", v),
		CSRFToken: (v) => api.parse("CSRFToken", v),
		ThreadMode: (v) => api.parse("ThreadMode", v),
		AttachmentType: (v) => api.parse("AttachmentType", v),
		SecurityResult: (v) => api.parse("SecurityResult", v),
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
		// Token returns a token to use for an SSE connection. A token can only be used for
		// a single SSE connection. Tokens are stored in memory for a maximum of 1 minute,
		// with at most 10 unused tokens (the most recently created) per account.
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
		// MessageSubmit sends a message by submitting it the outgoing email queue. The
		// message is sent to all addresses listed in the To, Cc and Bcc addresses, without
		// Bcc message header.
		// 
		// If a Sent mailbox is configured, messages are added to it after submitting
		// to the delivery queue.
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
		// MailboxCreate creates a new mailbox.
		async MailboxCreate(name) {
			const fn = "MailboxCreate";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [name];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MailboxDelete deletes a mailbox and all its messages.
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
				error('unknkown value ' + v + ' for named strings ' + t.Name);
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
				error('unknkown value ' + v + ' for named ints ' + t.Name);
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
// For authentication/security results.
const underlineGreen = '#50c40f';
const underlineRed = '#e15d1c';
const underlineBlue = '#09f';
const underlineGrey = '#aaa';
const underlineYellow = 'yellow';
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
		q = (q - 1) % 3 + 1;
		return dom.div(dom._class('quoted' + q), addLinks(line));
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
		let color = '';
		let title = '';
		switch (m.MsgFromValidation) {
			case api.Validation.ValidationStrict:
				color = underlineGreen;
				title = 'Message would have matched a strict DMARC policy.';
				break;
			case api.Validation.ValidationDMARC:
				color = underlineGreen;
				title = 'Message matched DMARC policy of domain.';
				break;
			case api.Validation.ValidationRelaxed:
				color = underlineGreen;
				title = 'Domain did not have a DMARC policy, but message would match a relaxed policy if it had existed.';
				break;
			case api.Validation.ValidationNone:
				if (m.IsForward || m.IsMailingList) {
					color = underlineBlue;
					title = 'Message would not pass DMARC policy, but came in through a configured mailing list or forwarding address.';
				}
				else {
					color = underlineRed;
					title = 'Either domain did not have a DMARC policy, or message did not adhere to it.';
				}
				break;
			default:
				// Also for zero value, when unknown. E.g. for sent messages added with IMAP.
				title = 'Unknown DMARC verification result.';
				return dom.span(attr.title(title + extra), domstr);
		}
		return dom.span(attr.title(title + extra), style({ borderBottom: '1.5px solid ' + color, textDecoration: 'none' }), domstr);
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
const formatAddressShort = (a) => {
	const n = a.Name;
	if (n && !n.includes('<') && !n.includes('@') && !n.includes('>')) {
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
	dom._kids(msgheaderelem, 
	// todo: make addresses clickable, start search (keep current mailbox if any)
	dom.tr(dom.td('From:', style({ textAlign: 'right', color: '#555', whiteSpace: 'nowrap' })), dom.td(style({ width: '100%' }), dom.div(style({ display: 'flex', justifyContent: 'space-between' }), dom.div(join((msgenv.From || []).map(a => formatAddressValidated(a, mi.Message, !!msgenv.From && msgenv.From.length === 1)), () => ', ')), dom.div(attr.title('Received: ' + received.toString() + ';\nDate header in message: ' + (msgenv.Date ? msgenv.Date.toString() : '(missing/invalid)')), receivedlocal.toDateString() + ' ' + receivedlocal.toTimeString().split(' ')[0])))), (msgenv.ReplyTo || []).length === 0 ? [] : dom.tr(dom.td('Reply-To:', style({ textAlign: 'right', color: '#555', whiteSpace: 'nowrap' })), dom.td(join((msgenv.ReplyTo || []).map(a => formatAddressElem(a)), () => ', '))), dom.tr(dom.td('To:', style({ textAlign: 'right', color: '#555', whiteSpace: 'nowrap' })), dom.td(addressList(allAddrs, msgenv.To || []))), (msgenv.CC || []).length === 0 ? [] : dom.tr(dom.td('Cc:', style({ textAlign: 'right', color: '#555', whiteSpace: 'nowrap' })), dom.td(addressList(allAddrs, msgenv.CC || []))), (msgenv.BCC || []).length === 0 ? [] : dom.tr(dom.td('Bcc:', style({ textAlign: 'right', color: '#555', whiteSpace: 'nowrap' })), dom.td(addressList(allAddrs, msgenv.BCC || []))), dom.tr(dom.td('Subject:', style({ textAlign: 'right', color: '#555', whiteSpace: 'nowrap' })), dom.td(dom.div(style({ display: 'flex', justifyContent: 'space-between' }), dom.div(msgenv.Subject || ''), dom.div(mi.Message.IsForward ? dom.span(style({ padding: '0px 0.15em', fontSize: '.9em' }), 'Forwarded', attr.title('Message came in from a forwarded address. Some message authentication policies, like DMARC, were not evaluated.')) : [], mi.Message.IsMailingList ? dom.span(style({ padding: '0px 0.15em', fontSize: '.9em' }), 'Mailing list', attr.title('Message was received from a mailing list. Some message authentication policies, like DMARC, were not evaluated.')) : [], mi.Message.ReceivedTLSVersion === 1 ? dom.span(style({ padding: '0px 0.15em', fontSize: '.9em', borderBottom: '1.5px solid #e15d1c' }), 'Without TLS', attr.title('Message received (last hop) without TLS.')) : [], mi.Message.ReceivedTLSVersion > 1 && !mi.Message.ReceivedRequireTLS ? dom.span(style({ padding: '0px 0.15em', fontSize: '.9em', borderBottom: '1.5px solid #50c40f' }), 'With TLS', attr.title('Message received (last hop) with TLS.')) : [], mi.Message.ReceivedRequireTLS ? dom.span(style({ padding: '.1em .3em', fontSize: '.9em', backgroundColor: '#d2f791', border: '1px solid #ccc', borderRadius: '3px' }), 'With RequireTLS', attr.title('Transported with RequireTLS, ensuring TLS along the entire delivery path from sender to recipient, with TLS certificate verification through MTA-STS and/or DANE.')) : [], mi.IsSigned ? dom.span(style({ backgroundColor: '#666', padding: '0px 0.15em', fontSize: '.9em', color: 'white', borderRadius: '.15em' }), 'Message has a signature') : [], mi.IsEncrypted ? dom.span(style({ backgroundColor: '#666', padding: '0px 0.15em', fontSize: '.9em', color: 'white', borderRadius: '.15em' }), 'Message is encrypted') : [], refineKeyword ? (mi.Message.Keywords || []).map(kw => dom.clickbutton(dom._class('keyword'), kw, async function click() {
		await refineKeyword(kw);
	})) : [])))), moreHeaders.map(k => dom.tr(dom.td(k + ':', style({ textAlign: 'right', color: '#555', whiteSpace: 'nowrap' })), dom.td())));
};
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

	settingsPut({...settings, showHeaders: ['Delivered-To', 'User-Agent', 'X-Mailer', 'Message-Id', 'List-Id', 'List-Post', 'X-Mox-Reason', 'TLS-Required']})

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
	login: '7',
};
// All logging goes through log() instead of console.log, except "should not happen" logging.
let log = () => { };
try {
	if (localStorage.getItem('log') || location.hostname === 'localhost') {
		log = console.log;
	}
}
catch (err) { }
const defaultSettings = {
	showShortcuts: true,
	mailboxesWidth: 240,
	layout: 'auto',
	leftWidthPct: 50,
	topHeightPct: 40,
	msglistflagsWidth: 40,
	msglistageWidth: 70,
	msglistfromPct: 30,
	refine: '',
	orderAsc: false,
	ignoreErrorsUntil: 0,
	showHTML: false,
	mailboxCollapsed: {},
	showAllHeaders: false,
	showHeaders: [],
	threading: api.ThreadMode.ThreadOn,
	checkConsistency: location.hostname === 'localhost', // Enable UI update consistency checks, default only for local development.
};
const parseSettings = () => {
	try {
		const v = window.localStorage.getItem('settings');
		if (!v) {
			return { ...defaultSettings };
		}
		const x = JSON.parse(v);
		const def = defaultSettings;
		const getString = (k, ...l) => {
			const v = x[k];
			if (typeof v !== 'string' || l.length > 0 && !l.includes(v)) {
				return def[k];
			}
			return v;
		};
		const getBool = (k) => {
			const v = x[k];
			return typeof v === 'boolean' ? v : def[k];
		};
		const getInt = (k) => {
			const v = x[k];
			return typeof v === 'number' ? v : def[k];
		};
		let mailboxCollapsed = x.mailboxCollapsed;
		if (!mailboxCollapsed || typeof mailboxCollapsed !== 'object') {
			mailboxCollapsed = def.mailboxCollapsed;
		}
		const getStringArray = (k) => {
			const v = x[k];
			if (v && Array.isArray(v) && (v.length === 0 || typeof v[0] === 'string')) {
				return v;
			}
			return def[k];
		};
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
			threading: getString('threading', api.ThreadMode.ThreadOff, api.ThreadMode.ThreadOn, api.ThreadMode.ThreadUnread),
			checkConsistency: getBool('checkConsistency'),
		};
	}
	catch (err) {
		console.log('getting settings from localstorage', err);
		return { ...defaultSettings };
	}
};
// Store new settings. Called as settingsPut({...settings, updatedField: newValue}).
const settingsPut = (nsettings) => {
	settings = nsettings;
	try {
		window.localStorage.setItem('settings', JSON.stringify(nsettings));
	}
	catch (err) {
		console.log('storing settings in localstorage', err);
	}
};
let settings = parseSettings();
// All addresses for this account, can include "@domain" wildcard, User is empty in
// that case. Set when SSE connection is initialized.
let accountAddresses = [];
// Username/email address of login. Used as default From address when composing
// a new message.
let loginAddress = null;
// Localpart config (catchall separator and case sensitivity) for each domain
// the account has an address for.
let domainAddressConfigs = {};
// Mailbox containing rejects.
let rejectsMailbox = '';
// Last known server version. For asking to reload.
let lastServerVersion = '';
const login = async (reason) => {
	return new Promise((resolve, _) => {
		const origFocus = document.activeElement;
		let reasonElem;
		let fieldset;
		let autosize;
		let username;
		let password;
		const root = dom.div(style({ position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: '#eee', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: zindexes.login, animation: 'fadein .15s ease-in' }), dom.div(reasonElem = reason ? dom.div(style({ marginBottom: '2ex', textAlign: 'center' }), reason) : dom.div(), dom.div(style({ backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto', marginBottom: '20vh' }), dom.form(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			reasonElem.remove();
			try {
				fieldset.disabled = true;
				const loginToken = await client.LoginPrep();
				const token = await client.Login(loginToken, username.value, password.value);
				try {
					window.localStorage.setItem('webmailcsrftoken', token);
				}
				catch (err) {
					console.log('saving csrf token in localStorage', err);
				}
				root.remove();
				if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
					origFocus.focus();
				}
				resolve(token);
			}
			catch (err) {
				console.log('login error', err);
				window.alert('Error: ' + errmsg(err));
			}
			finally {
				fieldset.disabled = false;
			}
		}, fieldset = dom.fieldset(dom.h1('Mail'), dom.label(style({ display: 'block', marginBottom: '2ex' }), dom.div('Email address', style({ marginBottom: '.5ex' })), autosize = dom.span(dom._class('autosize'), username = dom.input(attr.required(''), attr.placeholder('jane@example.org'), function change() { autosize.dataset.value = username.value; }, function input() { autosize.dataset.value = username.value; }))), dom.label(style({ display: 'block', marginBottom: '2ex' }), dom.div('Password', style({ marginBottom: '.5ex' })), password = dom.input(attr.type('password'), attr.required(''))), dom.div(style({ textAlign: 'center' }), dom.submitbutton('Login')))))));
		document.body.appendChild(root);
		username.focus();
	});
};
const localStorageGet = (k) => {
	try {
		return window.localStorage.getItem(k);
	}
	catch (err) {
		return null;
	}
};
const localStorageRemove = (k) => {
	try {
		return window.localStorage.removeItem(k);
	}
	catch (err) {
	}
};
const client = new api.Client().withOptions({ csrfHeader: 'x-mox-csrf', login: login }).withAuthToken(localStorageGet('webmailcsrftoken') || '');
// Link returns a clickable link with rel="noopener noreferrer".
const link = (href, anchorOpt) => dom.a(attr.href(href), attr.rel('noopener noreferrer'), attr.target('_blank'), anchorOpt || href);
// Returns first own account address matching an address in l.
const envelopeIdentity = (l) => {
	for (const a of l) {
		const ma = accountAddresses.find(aa => (!aa.User || aa.User === a.User) && aa.Domain.ASCII === a.Domain.ASCII);
		if (ma) {
			return { Name: ma.Name, User: a.User, Domain: a.Domain };
		}
	}
	return null;
};
// We can display keyboard shortcuts when a user clicks a button that has a shortcut.
let shortcutElem = dom.div(style({ fontSize: '2em', position: 'absolute', left: '.25em', bottom: '.25em', backgroundColor: '#888', padding: '0.25em .5em', color: 'white', borderRadius: '.15em' }));
let shortcutTimer = 0;
const showShortcut = (c) => {
	if (!settings.showShortcuts) {
		return;
	}
	if (shortcutTimer) {
		window.clearTimeout(shortcutTimer);
	}
	shortcutElem.remove();
	dom._kids(shortcutElem, c);
	document.body.appendChild(shortcutElem);
	shortcutTimer = setTimeout(() => {
		shortcutElem.remove();
		shortcutTimer = 0;
	}, 1500);
};
// Call cmdfn and display the shortcut for the command if it occurs in shortcuts.
const shortcutCmd = async (cmdfn, shortcuts) => {
	let shortcut = '';
	for (const k in shortcuts) {
		if (shortcuts[k] === cmdfn) {
			shortcut = k;
			break;
		}
	}
	if (shortcut) {
		showShortcut(shortcut);
	}
	await cmdfn();
};
// clickCmd returns a click handler that runs a cmd and shows its shortcut.
const clickCmd = (cmdfn, shortcuts) => {
	return async function click() {
		shortcutCmd(cmdfn, shortcuts);
	};
};
// enterCmd returns a keydown handler that runs a cmd when Enter is pressed and shows its shortcut.
const enterCmd = (cmdfn, shortcuts) => {
	return async function keydown(e) {
		if (e.key === 'Enter') {
			e.stopPropagation();
			shortcutCmd(cmdfn, shortcuts);
		}
	};
};
// keyHandler returns a function that handles keyboard events for a map of
// shortcuts, calling the shortcut function if found.
const keyHandler = (shortcuts) => {
	return async (k, e) => {
		const fn = shortcuts[k];
		if (fn) {
			e.preventDefault();
			e.stopPropagation();
			fn();
		}
	};
};
// For attachment sizes.
const formatSize = (size) => size > 1024 * 1024 ? (size / (1024 * 1024)).toFixed(1) + 'mb' : Math.ceil(size / 1024) + 'kb';
// Parse size as used in minsize: and maxsize: in the search bar.
const parseSearchSize = (s) => {
	s = s.trim();
	if (!s) {
		return ['', 0];
	}
	const digits = s.match(/^([0-9]+)/)?.[1];
	if (!digits) {
		return ['', 0];
	}
	let num = parseInt(digits);
	if (isNaN(num)) {
		return ['', 0];
	}
	const suffix = s.substring(digits.length).trim().toLowerCase();
	if (['b', 'kb', 'mb', 'gb'].includes(suffix)) {
		return [digits + suffix, num * Math.pow(2, 10 * ['b', 'kb', 'mb', 'gb'].indexOf(suffix))];
	}
	if (['k', 'm', 'g'].includes(suffix)) {
		return [digits + suffix + 'b', num * Math.pow(2, 10 * (1 + ['k', 'm', 'g'].indexOf(suffix)))];
	}
	return ['', 0];
};
// JS date does not allow months and days as single digit, it requires a 0
// prefix in those cases, so fix up such dates.
const fixDate = (dt) => {
	const t = dt.split('-');
	if (t.length !== 3) {
		return dt;
	}
	if (t[1].length === 1) {
		t[1] = '0' + t[1];
	}
	if (t[2].length === 1) {
		t[2] = '0' + t[2];
	}
	return t.join('-');
};
// Parse date and/or time, for use in searchbarElem with start: and end:.
const parseSearchDateTime = (s, isstart) => {
	const t = s.split('T', 2);
	if (t.length === 2) {
		const d = new Date(fixDate(t[0]) + 'T' + t[1]);
		return d ? d.toJSON() : undefined;
	}
	else if (t.length === 1) {
		if (isNaN(Date.parse(fixDate(t[0])))) {
			const d = new Date(fixDate(t[0]));
			if (!isstart) {
				d.setDate(d.getDate() + 1);
			}
			return d.toJSON();
		}
		else {
			const tm = t[0];
			const now = new Date();
			const pad0 = (v) => v <= 9 ? '0' + v : '' + v;
			const d = new Date([now.getFullYear(), pad0(now.getMonth() + 1), pad0(now.getDate())].join('-') + 'T' + tm);
			return d ? d.toJSON() : undefined;
		}
	}
	return undefined;
};
const dquote = (s) => '"' + s.replaceAll('"', '""') + '"';
const needsDquote = (s) => /[ \t"]/.test(s);
const packToken = (t) => (t[0] ? '-' : '') + (t[1] ? t[1] + ':' : '') + (t[2] || needsDquote(t[3]) ? dquote(t[3]) : t[3]);
// Parse the text from the searchbarElem into tokens. All input is valid.
const parseSearchTokens = (s) => {
	if (!s) {
		return [];
	}
	const l = []; // Tokens we gathered.
	let not = false;
	let quoted = false; // If double quote was seen.
	let quoteend = false; // Possible closing quote seen. Can also be escaped quote.
	let t = ''; // Current token. We only keep non-empty tokens.
	let tquoted = false; // If t started out quoted.
	const add = () => {
		if (t && (tquoted || !t.includes(':'))) {
			l.push([not, '', tquoted, t]);
		}
		else if (t) {
			const tag = t.split(':', 1)[0];
			l.push([not, tag, tquoted, t.substring(tag.length + 1)]);
		}
		t = '';
		quoted = false;
		quoteend = false;
		tquoted = false;
		not = false;
	};
	[...s].forEach(c => {
		if (quoteend) {
			if (c === '"') {
				t += '"';
				quoteend = false;
			}
			else if (t) {
				add();
			}
		}
		else if (quoted && c === '"') {
			quoteend = true;
		}
		else if (c === '"') {
			quoted = true;
			if (!t) {
				tquoted = true;
			}
		}
		else if (!quoted && (c === ' ' || c === '\t')) {
			add();
		}
		else if (c === '-' && !t && !tquoted && !not) {
			not = true;
		}
		else {
			t += c;
		}
	});
	add();
	return l;
};
// returns a filter with empty/zero required fields.
const newFilter = () => {
	return {
		MailboxID: 0,
		MailboxChildrenIncluded: false,
		MailboxName: '',
		Attachments: api.AttachmentType.AttachmentIndifferent,
		SizeMin: 0,
		SizeMax: 0,
	};
};
const newNotFilter = () => {
	return {
		Attachments: api.AttachmentType.AttachmentIndifferent,
	};
};
// Parse search bar into filters that we can use to populate the form again, or
// send to the server.
const parseSearch = (searchquery, mailboxlistView) => {
	const tokens = parseSearchTokens(searchquery);
	const fpos = newFilter();
	fpos.MailboxID = -1; // All mailboxes excluding Trash/Junk/Rejects.
	const notf = newNotFilter();
	const strs = { Oldest: '', Newest: '', SizeMin: '', SizeMax: '' };
	tokens.forEach(t => {
		const [not, tag, _, s] = t;
		const f = not ? notf : fpos;
		if (!not) {
			if (tag === 'mb' || tag === 'mailbox') {
				const mb = mailboxlistView.findMailboxByName(s);
				if (mb) {
					fpos.MailboxID = mb.ID;
				}
				else if (s === '') {
					fpos.MailboxID = 0; // All mailboxes, including Trash/Junk/Rejects.
				}
				else {
					fpos.MailboxName = s;
					fpos.MailboxID = 0;
				}
				return;
			}
			else if (tag === 'submb') {
				fpos.MailboxChildrenIncluded = true;
				return;
			}
			else if (tag === 'start') {
				const dt = parseSearchDateTime(s, true);
				if (dt) {
					fpos.Oldest = new Date(dt);
					strs.Oldest = s;
					return;
				}
			}
			else if (tag === 'end') {
				const dt = parseSearchDateTime(s, false);
				if (dt) {
					fpos.Newest = new Date(dt);
					strs.Newest = s;
					return;
				}
			}
			else if (tag === 'a' || tag === 'attachments') {
				if (s === 'none' || s === 'any' || s === 'image' || s === 'pdf' || s === 'archive' || s === 'zip' || s === 'spreadsheet' || s === 'document' || s === 'presentation') {
					fpos.Attachments = s;
					return;
				}
			}
			else if (tag === 'h' || tag === 'header') {
				const k = s.split(':')[0];
				const v = s.substring(k.length + 1);
				if (!fpos.Headers) {
					fpos.Headers = [[k, v]];
				}
				else {
					fpos.Headers.push([k, v]);
				}
				return;
			}
			else if (tag === 'minsize') {
				const [str, size] = parseSearchSize(s);
				if (str) {
					fpos.SizeMin = size;
					strs.SizeMin = str;
					return;
				}
			}
			else if (tag === 'maxsize') {
				const [str, size] = parseSearchSize(s);
				if (str) {
					fpos.SizeMax = size;
					strs.SizeMax = str;
					return;
				}
			}
		}
		if (tag === 'f' || tag === 'from') {
			f.From = f.From || [];
			f.From.push(s);
			return;
		}
		else if (tag === 't' || tag === 'to') {
			f.To = f.To || [];
			f.To.push(s);
			return;
		}
		else if (tag === 's' || tag === 'subject') {
			f.Subject = f.Subject || [];
			f.Subject.push(s);
			return;
		}
		else if (tag === 'l' || tag === 'label') {
			f.Labels = f.Labels || [];
			f.Labels.push(s);
			return;
		}
		f.Words = f.Words || [];
		f.Words.push((tag ? tag + ':' : '') + s);
	});
	return [fpos, notf, strs];
};
// Errors in catch statements are of type unknown, we normally want its
// message.
const errmsg = (err) => '' + (err.message || '(no error message)');
// Return keydown handler that creates or updates the datalist of its target with
// autocompletion addresses. The tab key completes with the first selection.
let datalistgen = 1;
const newAddressComplete = () => {
	let datalist;
	let completeMatches;
	let completeSearch;
	let completeFull;
	let aborter = {};
	return async function keydown(e) {
		const target = e.target;
		if (!datalist) {
			datalist = dom.datalist(attr.id('list-' + datalistgen++));
			target.parentNode.insertBefore(datalist, target);
			target.setAttribute('list', datalist.id);
		}
		const search = target.value;
		if (e.key === 'Tab') {
			const matches = (completeMatches || []).filter(s => s.includes(search));
			if (matches.length > 0) {
				target.value = matches[0];
				return;
			}
			else if ((completeMatches || []).length === 0 && !search) {
				return;
			}
		}
		if (completeSearch && search.includes(completeSearch) && completeFull) {
			dom._kids(datalist, (completeMatches || []).filter(s => s.includes(search)).map(s => dom.option(s)));
			return;
		}
		else if (search === completeSearch) {
			return;
		}
		if (aborter.abort) {
			aborter.abort();
		}
		aborter = {};
		try {
			[completeMatches, completeFull] = await withStatus('Autocompleting addresses', client.withOptions({ aborter: aborter }).CompleteRecipient(search));
			completeSearch = search;
			dom._kids(datalist, (completeMatches || []).map(s => dom.option(s)));
		}
		catch (err) {
			log('autocomplete error', errmsg(err));
		}
		finally {
			aborter = {};
		}
	};
};
const flagList = (miv) => {
	const msgflags = []; // Flags for message in miv.
	const othermsgflags = []; // Flags for descendant messages if miv is collapsed. Only flags not in msgflags.
	let l = msgflags;
	const seen = new Set();
	const flag = (v, char, name) => {
		if (v && !seen.has(name)) {
			l.push([name, char]);
			seen.add(name);
		}
	};
	const addFlags = (mi) => {
		const m = mi.Message;
		flag(m.Answered, 'r', 'Replied/answered');
		flag(m.Flagged, '!', 'Flagged');
		flag(m.Forwarded, 'f', 'Forwarded');
		flag(m.Junk, 'j', 'Junk');
		flag(m.Deleted, 'D', 'Deleted, used in IMAP, message will likely be removed soon.');
		flag(m.Draft, 'd', 'Draft');
		flag(m.Phishing, 'p', 'Phishing');
		flag(!m.Junk && !m.Notjunk, '?', 'Unclassified, neither junk nor not junk: message does not contribute to spam classification of new incoming messages');
		flag(mi.Attachments && mi.Attachments.length > 0 ? true : false, 'a', 'Has at least one attachment');
		if (m.ThreadMuted) {
			flag(true, 'm', 'Muted, new messages are automatically marked as read.');
		}
	};
	addFlags(miv.messageitem);
	if (miv.isCollapsedThreadRoot()) {
		l = othermsgflags;
		for (miv of miv.descendants()) {
			addFlags(miv.messageitem);
		}
	}
	return msgflags.map(t => dom.span(dom._class('msgitemflag'), t[1], attr.title(t[0])))
		.concat(othermsgflags.map(t => dom.span(dom._class('msgitemflag'), dom._class('msgitemflagcollapsed'), t[1], attr.title(t[0]))));
};
// Turn filters from the search bar into filters with the refine filters (buttons
// above message list) applied, to send to the server in a request. The original
// filters are not modified.
const refineFilters = (f, notf) => {
	const refine = settings.refine;
	if (refine) {
		f = { ...f };
		notf = { ...notf };
		if (refine === 'unread') {
			notf.Labels = [...(notf.Labels || [])];
			notf.Labels = (notf.Labels || []).concat(['\\Seen']);
		}
		else if (refine === 'read') {
			f.Labels = [...(f.Labels || [])];
			f.Labels = (f.Labels || []).concat(['\\Seen']);
		}
		else if (refine === 'attachments') {
			f.Attachments = 'any';
		}
		else if (refine.startsWith('label:')) {
			f.Labels = [...(f.Labels || [])];
			f.Labels = (f.Labels || []).concat([refine.substring('label:'.length)]);
		}
	}
	return [f, notf];
};
// For dragging the splitter bars. This function should be called on mousedown. e
// is the mousedown event. Move is the function to call when the bar was dragged,
// typically adjusting styling, e.g. absolutely positioned offsets, possibly based
// on the event.clientX and element bounds offset.
const startDrag = (e, move) => {
	if (e.buttons === 1) {
		e.preventDefault();
		e.stopPropagation();
		const stop = () => {
			document.body.removeEventListener('mousemove', move);
			document.body.removeEventListener('mouseup', stop);
		};
		document.body.addEventListener('mousemove', move);
		document.body.addEventListener('mouseup', stop);
	}
};
// Returns two handler functions: one for focus that sets a placeholder on the
// target element, and one for blur that restores/clears it again. Keeps forms uncluttered,
// only showing contextual help just before you start typing.
const focusPlaceholder = (s) => {
	let orig = '';
	return [
		function focus(e) {
			const target = e.target;
			orig = target.getAttribute('placeholder') || '';
			target.setAttribute('placeholder', s);
		},
		function blur(e) {
			const target = e.target;
			if (orig) {
				target.setAttribute('placeholder', orig);
			}
			else {
				target.removeAttribute('placeholder');
			}
		},
	];
};
// Parse a location hash, with either mailbox or search terms, and optional
// selected message id. The special "#compose " hash, used for handling
// "mailto:"-links, must be handled before calling this function.
//
// Examples:
// #Inbox
// #Inbox,1
// #search mb:Inbox
// #search mb:Inbox,1
const parseLocationHash = (mailboxlistView) => {
	let hash = decodeURIComponent((window.location.hash || '#').substring(1));
	const m = hash.match(/,([0-9]+)$/);
	let msgid = 0;
	if (m) {
		msgid = parseInt(m[1]);
		hash = hash.substring(0, hash.length - (','.length + m[1].length));
	}
	let initmailbox, initsearch;
	if (hash.startsWith('search ')) {
		initsearch = hash.substring('search '.length).trim();
	}
	let f, notf;
	if (initsearch) {
		[f, notf,] = parseSearch(initsearch, mailboxlistView);
	}
	else {
		initmailbox = hash;
		if (!initmailbox) {
			initmailbox = 'Inbox';
		}
		f = newFilter();
		const mb = mailboxlistView.findMailboxByName(initmailbox);
		if (mb) {
			f.MailboxID = mb.ID;
		}
		else {
			f.MailboxName = initmailbox;
		}
		notf = newNotFilter();
	}
	return [initsearch, msgid, f, notf];
};
// When API calls are made, we start displaying what we're doing after 1 second.
// Hopefully the command has completed by then, but slow operations, or in case of
// high latency, we'll start showing it. And hide it again when done. This should
// give a non-cluttered instant feeling most of the time, but informs the user when
// needed.
let statusElem;
const withStatus = async (action, promise, disablable, noAlert) => {
	let elem;
	let id = window.setTimeout(() => {
		elem = dom.span(action + '... ');
		statusElem.appendChild(elem);
		id = 0;
	}, 1000);
	// Could be the element we are going to disable, causing it to lose its focus. We'll restore afterwards.
	let origFocus = document.activeElement;
	try {
		if (disablable) {
			disablable.disabled = true;
		}
		return await promise;
	}
	catch (err) {
		if (id) {
			window.clearTimeout(id);
			id = 0;
		}
		// Generated by client for aborted requests, e.g. for api.ParsedMessage when loading a message.
		if (err.code === 'sherpa:aborted') {
			throw err;
		}
		if (!noAlert) {
			window.alert('Error: ' + action + ': ' + errmsg(err));
		}
		// We throw the error again. The ensures callers that await their withStatus call
		// won't continue executing. We have a global handler for uncaught promises, but it
		// only handles javascript-level errors, not api call/operation errors.
		throw err;
	}
	finally {
		if (disablable) {
			disablable.disabled = false;
		}
		if (origFocus && document.activeElement !== origFocus && origFocus instanceof HTMLElement) {
			origFocus.focus();
		}
		if (id) {
			window.clearTimeout(id);
		}
		if (elem) {
			elem.remove();
		}
	}
};
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
const popover = (target, opts, ...kids) => {
	const origFocus = document.activeElement;
	const pos = target.getBoundingClientRect();
	const close = () => {
		if (!root.parentNode) {
			return;
		}
		root.remove();
		if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
			origFocus.focus();
		}
	};
	const posx = opts.fullscreen ?
		style({ left: 0, right: 0 }) :
		(pos.x < window.innerWidth / 3 ?
			style({ left: '' + (pos.x) + 'px' }) :
			style({ right: '' + (window.innerWidth - pos.x - pos.width) + 'px' }));
	const posy = opts.fullscreen ?
		style({ top: 0, bottom: 0 }) :
		(pos.y + pos.height > window.innerHeight * 2 / 3 ?
			style({ bottom: '' + (window.innerHeight - (pos.y - 1)) + 'px', maxHeight: '' + (pos.y - 1 - 10) + 'px' }) :
			style({ top: '' + (pos.y + pos.height + 1) + 'px', maxHeight: '' + (window.innerHeight - (pos.y + pos.height + 1) - 10) + 'px' }));
	let content;
	const root = dom.div(style({ position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, zIndex: zindexes.popover, backgroundColor: 'rgba(0, 0, 0, 0.2)' }), function click(e) {
		e.stopPropagation();
		close();
	}, function keydown(e) {
		if (e.key === 'Escape') {
			e.stopPropagation();
			close();
		}
	}, content = dom.div(attr.tabindex('0'), style({
		position: 'absolute',
		overflowY: 'auto',
	}), posx, posy, opts.transparent ? [] : [
		style({
			backgroundColor: 'white',
			padding: '1em',
			borderRadius: '.15em',
			boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)',
		}),
		function click(e) {
			e.stopPropagation();
		},
	], ...kids));
	document.body.appendChild(root);
	const first = root.querySelector('input, select, textarea, button');
	if (first && first instanceof HTMLElement) {
		first.focus();
	}
	else {
		content.focus();
	}
	return close;
};
// Popup shows kids in a centered div with white background on top of a
// transparent overlay on top of the window. Clicking the overlay or hitting
// Escape closes the popup. Scrollbars are automatically added to the div with
// kids. Returns a function that removes the popup.
// While a popup is open, no global keyboard shortcuts are handled. Popups get
// to handle keys themselves, e.g. for scrolling.
let popupOpen = false;
const popup = (...kids) => {
	const origFocus = document.activeElement;
	const close = () => {
		if (!root.parentNode) {
			return;
		}
		popupOpen = false;
		root.remove();
		if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
			origFocus.focus();
		}
	};
	let content;
	const root = dom.div(style({ position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: 'rgba(0, 0, 0, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: zindexes.popup }), function keydown(e) {
		if (e.key === 'Escape') {
			e.stopPropagation();
			close();
		}
	}, function click(e) {
		e.stopPropagation();
		close();
	}, content = dom.div(attr.tabindex('0'), style({ backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto' }), function click(e) {
		e.stopPropagation();
	}, kids));
	popupOpen = true;
	document.body.appendChild(root);
	content.focus();
	return close;
};
// Show help popup, with shortcuts and basic explanation.
const cmdHelp = async () => {
	const remove = popup(style({ padding: '1em 1em 2em 1em' }), dom.h1('Help and keyboard shortcuts'), dom.div(style({ display: 'flex' }), dom.div(style({ width: '40em' }), dom.table(dom.tr(dom.td(attr.colspan('2'), dom.h2('Global', style({ margin: '0' })))), [
		['c', 'compose new message'],
		['/', 'search'],
		['i', 'open inbox'],
		['?', 'help'],
		['ctrl ?', 'tooltip for focused element'],
		['ctrl m', 'focus message'],
	].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))), dom.tr(dom.td(attr.colspan('2'), dom.h2('Mailbox', style({ margin: '0' })))), [
		['←', 'collapse'],
		['→', 'expand'],
		['b', 'show more actions'],
	].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))), dom.tr(dom.td(attr.colspan('2'), dom.h2('Message list', style({ margin: '1ex 0 0 0' })))), dom.tr(dom.td('↓', ', j'), dom.td('down one message'), dom.td(attr.rowspan('6'), style({ color: '#888', borderLeft: '2px solid #ddd', paddingLeft: '.5em' }), 'hold ctrl to only move focus', dom.br(), 'hold shift to expand selection')), [
		[['↑', ', k'], 'up one message'],
		['PageDown, l', 'down one screen'],
		['PageUp, h', 'up one screen'],
		['End, .', 'to last message'],
		['Home, ,', 'to first message'],
		['Space', 'toggle selection of message'],
	].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))), [
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
	].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))))), dom.div(style({ width: '40em' }), dom.table(dom.tr(dom.td(attr.colspan('2'), dom.h2('Compose', style({ margin: '0' })))), [
		['ctrl Enter', 'send message'],
		['ctrl w', 'cancel message'],
		['ctrl O', 'add To'],
		['ctrl C', 'add Cc'],
		['ctrl B', 'add Bcc'],
		['ctrl Y', 'add Reply-To'],
		['ctrl -', 'remove current address'],
		['ctrl +', 'add address of same type'],
	].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))), dom.tr(dom.td(attr.colspan('2'), dom.h2('Message', style({ margin: '1ex 0 0 0' })))), [
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
	].map(t => dom.tr(dom.td(t[0]), dom.td(t[1]))), dom.tr(dom.td(dom.h2('Attachments', style({ margin: '1ex 0 0 0' })))), [
		['left, h', 'previous attachment'],
		['right, l', 'next attachment'],
		['0', 'first attachment'],
		['$', 'next attachment'],
		['d', 'download'],
	].map(t => dom.tr(dom.td(t[0]), dom.td(t[1])))), dom.div(style({ marginTop: '2ex', marginBottom: '1ex' }), dom.span('Underdotted text', attr.title('Underdotted text shows additional information on hover.')), ' show an explanation or additional information when hovered.'), dom.div(style({ marginBottom: '1ex' }), 'Multiple messages can be selected by clicking messages while holding the control and/or shift keys. Dragging messages and dropping them on a mailbox moves the messages to that mailbox.'), dom.div(style({ marginBottom: '1ex' }), 'Text that changes ', dom.span(attr.title('Unicode blocks, e.g. from basic latin to cyrillic, or to emoticons.'), '"character groups"'), ' without whitespace has an ', dom.span(dom._class('scriptswitch'), 'orange underline'), ', which can be a sign of an intent to mislead (e.g. phishing).'), settings.showShortcuts ?
		dom.div(style({ marginTop: '2ex' }), 'Shortcut keys for mouse operation are shown in the bottom left. ', dom.clickbutton('Disable', function click() {
			settingsPut({ ...settings, showShortcuts: false });
			remove();
			cmdHelp();
		})) :
		dom.div(style({ marginTop: '2ex' }), 'Shortcut keys for mouse operation are currently not shown. ', dom.clickbutton('Enable', function click() {
			settingsPut({ ...settings, showShortcuts: true });
			remove();
			cmdHelp();
		})), dom.div(style({ marginTop: '2ex' }), 'To start composing a message when opening a "mailto:" link, register this application with your browser/system. ', dom.clickbutton('Register', attr.title('In most browsers, registering is only allowed on HTTPS URLs. Your browser may ask for confirmation. If nothing appears to happen, the registration may already have been present.'), function click() {
		if (!window.navigator.registerProtocolHandler) {
			window.alert('Registering a protocol handler ("mailto:") is not supported by your browser.');
			return;
		}
		try {
			window.navigator.registerProtocolHandler('mailto', '#compose %s');
		}
		catch (err) {
			window.alert('Error registering "mailto:" protocol handler: ' + errmsg(err));
		}
	}), ' ', dom.clickbutton('Unregister', attr.title('Not all browsers implement unregistering via JavaScript.'), function click() {
		// Not supported on firefox at the time of writing, and the signature is not in the types.
		if (!window.navigator.unregisterProtocolHandler) {
			window.alert('Unregistering a protocol handler ("mailto:") via JavaScript is not supported by your browser. See your browser settings to unregister.');
			return;
		}
		try {
			window.navigator.unregisterProtocolHandler('mailto', '#compose %s');
		}
		catch (err) {
			window.alert('Error unregistering "mailto:" protocol handler: ' + errmsg(err));
			return;
		}
		window.alert('"mailto:" protocol handler unregistered.');
	})), dom.div(style({ marginTop: '2ex' }), 'Mox is open source email server software, this is version ' + moxversion + '. Feedback, including bug reports, is appreciated! ', link('https://github.com/mjl-/mox/issues/new'), '.'))));
};
// Show tooltips for either the focused element, or otherwise for all elements
// that aren't reachable with tabindex and aren't marked specially to prevent
// them from showing up (e.g. dates in the msglistview, which can also been
// seen by opening a message).
const cmdTooltip = async () => {
	let elems = [];
	if (document.activeElement && document.activeElement !== document.body) {
		if (document.activeElement.getAttribute('title')) {
			elems = [document.activeElement];
		}
		elems = [...elems, ...document.activeElement.querySelectorAll('[title]')];
	}
	if (elems.length === 0) {
		// Find elements without a parent with tabindex=0.
		const seen = {};
		elems = [...document.body.querySelectorAll('[title]:not(.notooltip):not(.silenttitle)')].filter(e => {
			const title = e.getAttribute('title') || '';
			if (seen[title]) {
				return false;
			}
			seen[title] = true;
			return !(e instanceof HTMLInputElement || e instanceof HTMLSelectElement || e instanceof HTMLButtonElement || e instanceof HTMLTextAreaElement || e instanceof HTMLAnchorElement || e.getAttribute('tabindex') || e.closest('[tabindex]'));
		});
	}
	if (elems.length === 0) {
		window.alert('No active elements with tooltips found.');
		return;
	}
	popover(document.body, { transparent: true, fullscreen: true }, ...elems.map(e => {
		const title = e.getAttribute('title') || '';
		const pos = e.getBoundingClientRect();
		return dom.div(style({ position: 'absolute', backgroundColor: 'black', color: 'white', borderRadius: '.15em', padding: '.15em .25em', maxWidth: '50em' }), pos.x < window.innerWidth / 3 ?
			style({ left: '' + (pos.x) + 'px' }) :
			style({ right: '' + (window.innerWidth - pos.x - pos.width) + 'px' }), pos.y + pos.height > window.innerHeight * 2 / 3 ?
			style({ bottom: '' + (window.innerHeight - (pos.y - 2)) + 'px', maxHeight: '' + (pos.y - 2) + 'px' }) :
			style({ top: '' + (pos.y + pos.height + 2) + 'px', maxHeight: '' + (window.innerHeight - (pos.y + pos.height + 2)) + 'px' }), title);
	}));
};
let composeView = null;
const compose = (opts) => {
	log('compose', opts);
	if (composeView) {
		// todo: should allow multiple
		window.alert('Can only compose one message at a time.');
		return;
	}
	let fieldset;
	let from;
	let customFrom = null;
	let subjectAutosize;
	let subject;
	let body;
	let attachments;
	let requiretls;
	let toBtn, ccBtn, bccBtn, replyToBtn, customFromBtn;
	let replyToCell, toCell, ccCell, bccCell; // Where we append new address views.
	let toRow, replyToRow, ccRow, bccRow; // We show/hide rows as needed.
	let toViews = [], replytoViews = [], ccViews = [], bccViews = [];
	let forwardAttachmentViews = [];
	const cmdCancel = async () => {
		composeElem.remove();
		composeView = null;
	};
	const submit = async () => {
		const files = await new Promise((resolve, reject) => {
			const l = [];
			if (attachments.files && attachments.files.length === 0) {
				resolve(l);
				return;
			}
			[...attachments.files].forEach(f => {
				const fr = new window.FileReader();
				fr.addEventListener('load', () => {
					l.push({ Filename: f.name, DataURI: fr.result });
					if (attachments.files && l.length === attachments.files.length) {
						resolve(l);
					}
				});
				fr.addEventListener('error', () => {
					reject(fr.error);
				});
				fr.readAsDataURL(f);
			});
		});
		let replyTo = '';
		if (replytoViews && replytoViews.length === 1 && replytoViews[0].input.value) {
			replyTo = replytoViews[0].input.value;
		}
		const forwardAttachmentPaths = forwardAttachmentViews.filter(v => v.checkbox.checked).map(v => v.path);
		const message = {
			From: customFrom ? customFrom.value : from.value,
			To: toViews.map(v => v.input.value).filter(s => s),
			Cc: ccViews.map(v => v.input.value).filter(s => s),
			Bcc: bccViews.map(v => v.input.value).filter(s => s),
			ReplyTo: replyTo,
			UserAgent: 'moxwebmail/' + moxversion,
			Subject: subject.value,
			TextBody: body.value,
			Attachments: files,
			ForwardAttachments: forwardAttachmentPaths.length === 0 ? { MessageID: 0, Paths: [] } : { MessageID: opts.attachmentsMessageItem.Message.ID, Paths: forwardAttachmentPaths },
			IsForward: opts.isForward || false,
			ResponseMessageID: opts.responseMessageID || 0,
			RequireTLS: requiretls.value === '' ? null : requiretls.value === 'yes',
			FutureRelease: scheduleTime.value ? new Date(scheduleTime.value) : null,
		};
		await client.MessageSubmit(message);
		cmdCancel();
	};
	const cmdSend = async () => {
		await withStatus('Sending email', submit(), fieldset);
	};
	const cmdAddTo = async () => { newAddrView('', true, toViews, toBtn, toCell, toRow); };
	const cmdAddCc = async () => { newAddrView('', true, ccViews, ccBtn, ccCell, ccRow); };
	const cmdAddBcc = async () => { newAddrView('', true, bccViews, bccBtn, bccCell, bccRow); };
	const cmdReplyTo = async () => { newAddrView('', false, replytoViews, replyToBtn, replyToCell, replyToRow, true); };
	const cmdCustomFrom = async () => {
		if (customFrom) {
			return;
		}
		customFrom = dom.input(attr.value(from.value), attr.required(''), focusPlaceholder('Jane <jane@example.org>'));
		from.replaceWith(customFrom);
		customFromBtn.remove();
	};
	const shortcuts = {
		'ctrl Enter': cmdSend,
		'ctrl w': cmdCancel,
		'ctrl O': cmdAddTo,
		'ctrl C': cmdAddCc,
		'ctrl B': cmdAddBcc,
		'ctrl Y': cmdReplyTo,
		// ctrl - and ctrl = (+) not included, they are handled by keydown handlers on in the inputs they remove/add.
	};
	const newAddrView = (addr, isRecipient, views, btn, cell, row, single) => {
		if (single && views.length !== 0) {
			return;
		}
		let rcptSecPromise = null;
		let rcptSecAddr = '';
		let rcptSecAborter = {};
		let autosizeElem, inputElem, securityBar;
		const fetchRecipientSecurity = () => {
			if (inputElem.value === rcptSecAddr) {
				return;
			}
			securityBar.style.borderImage = '';
			rcptSecAddr = inputElem.value;
			if (!inputElem.value) {
				return;
			}
			if (rcptSecAborter.abort) {
				rcptSecAborter.abort();
				rcptSecAborter.abort = undefined;
			}
			const color = (v) => {
				if (v === api.SecurityResult.SecurityResultYes) {
					return underlineGreen;
				}
				else if (v === api.SecurityResult.SecurityResultNo) {
					return underlineRed;
				}
				else if (v === api.SecurityResult.SecurityResultUnknown) {
					return 'white';
				}
				return underlineGrey;
			};
			const setBar = (c0, c1, c2, c3, c4) => {
				const stops = [
					c0 + ' 0%', c0 + ' 19%', 'white 19%', 'white 20%',
					c1 + ' 20%', c1 + ' 39%', 'white 39%', 'white 40%',
					c2 + ' 40%', c2 + ' 59%', 'white 59%', 'white 60%',
					c3 + ' 60%', c3 + ' 79%', 'white 79%', 'white 80%',
					c4 + ' 80%', c4 + ' 100%',
				].join(', ');
				securityBar.style.borderImage = 'linear-gradient(to right, ' + stops + ') 1';
			};
			const aborter = {};
			rcptSecAborter = aborter;
			rcptSecPromise = client.withOptions({ aborter: aborter }).RecipientSecurity(inputElem.value);
			rcptSecPromise.then((rs) => {
				setBar(color(rs.STARTTLS), color(rs.MTASTS), color(rs.DNSSEC), color(rs.DANE), color(rs.RequireTLS));
				const implemented = [];
				const check = (v, s) => {
					if (v) {
						implemented.push(s);
					}
				};
				check(rs.STARTTLS === api.SecurityResult.SecurityResultYes, 'STARTTLS');
				check(rs.MTASTS === api.SecurityResult.SecurityResultYes, 'MTASTS');
				check(rs.DNSSEC === api.SecurityResult.SecurityResultYes, 'DNSSEC');
				check(rs.DANE === api.SecurityResult.SecurityResultYes, 'DANE');
				check(rs.RequireTLS === api.SecurityResult.SecurityResultYes, 'RequireTLS');
				const status = 'Security mechanisms known to be implemented by the recipient domain: ' + (implemented.length === 0 ? '(none)' : implemented.join(', ')) + '.';
				inputElem.setAttribute('title', status + '\n\n' + recipientSecurityTitle);
				aborter.abort = undefined;
				v.recipientSecurity = rs;
				if (isRecipient) {
					// If we are not replying to a message from a mailing list, and all recipients
					// implement REQUIRETLS, we enable it.
					let reqtls = opts.isList !== true;
					const walk = (l) => {
						for (const v of l) {
							if (v.recipientSecurity?.RequireTLS !== api.SecurityResult.SecurityResultYes || v.recipientSecurity?.MTASTS !== api.SecurityResult.SecurityResultYes && v.recipientSecurity?.DANE !== api.SecurityResult.SecurityResultYes) {
								reqtls = false;
								break;
							}
						}
					};
					walk(toViews);
					walk(ccViews);
					walk(bccViews);
					if (requiretls.value === '' || requiretls.value === 'yes') {
						requiretls.value = reqtls ? 'yes' : '';
					}
				}
			}, () => {
				setBar('#888', '#888', '#888', '#888', '#888');
				inputElem.setAttribute('title', 'Error fetching security mechanisms known to be implemented by the recipient domain...\n\n' + recipientSecurityTitle);
				aborter.abort = undefined;
				if (requiretls.value === 'yes') {
					requiretls.value = '';
				}
			});
		};
		const recipientSecurityTitle = 'Description of security mechanisms recipient domains may implement:\n1. STARTTLS: Opportunistic (unverified) TLS with STARTTLS, successfully negotiated during the most recent delivery attempt.\n2. MTA-STS: For PKIX/WebPKI-verified TLS.\n3. DNSSEC: MX DNS records are DNSSEC-signed.\n4. DANE: First delivery destination host implements DANE for verified TLS.\n5. RequireTLS: SMTP extension for verified TLS delivery into recipient mailbox, support detected during the most recent delivery attempt.\n\nChecks STARTTLS, DANE and RequireTLS cover the most recently used delivery path, not necessarily all possible delivery paths.\n\nThe bars below the input field indicate implementation status by the recipient domain:\n- Red, not implemented/unsupported\n- Green, implemented/supported\n- Gray, error while determining\n- Absent/white, unknown or skipped (e.g. no previous delivery attempt, or DANE check skipped due to DNSSEC-lookup error)';
		const root = dom.span(autosizeElem = dom.span(dom._class('autosize'), inputElem = dom.input(focusPlaceholder('Jane <jane@example.org>'), style({ width: 'auto' }), attr.value(addr), newAddressComplete(), attr.title(recipientSecurityTitle), function keydown(e) {
			if (e.key === '-' && e.ctrlKey) {
				remove();
			}
			else if (e.key === '=' && e.ctrlKey) {
				newAddrView('', isRecipient, views, btn, cell, row, single);
			}
			else {
				return;
			}
			e.preventDefault();
			e.stopPropagation();
		}, function input() {
			// data-value is used for size of ::after css pseudo-element to stretch input field.
			autosizeElem.dataset.value = inputElem.value;
		}, function change() {
			autosizeElem.dataset.value = inputElem.value;
			fetchRecipientSecurity();
		}), securityBar = dom.span(dom._class('securitybar'), style({
			margin: '0 1px',
			borderBottom: '1.5px solid',
			borderBottomColor: 'transparent',
		}))), ' ', dom.clickbutton('-', style({ padding: '0 .25em' }), attr.arialabel('Remove address.'), attr.title('Remove address.'), function click() {
			remove();
			if (single && views.length === 0) {
				btn.style.display = '';
			}
		}), ' ');
		autosizeElem.dataset.value = inputElem.value;
		const remove = () => {
			const i = views.indexOf(v);
			views.splice(i, 1);
			root.remove();
			if (views.length === 0) {
				row.style.display = 'none';
			}
			if (views.length === 0 && single) {
				btn.style.display = '';
			}
			let next = cell.querySelector('input');
			if (!next) {
				let tr = row.nextSibling;
				while (tr) {
					next = tr.querySelector('input');
					if (!next && tr.nextSibling) {
						tr = tr.nextSibling;
						continue;
					}
					break;
				}
			}
			if (next) {
				next.focus();
			}
		};
		const v = { root: root, input: inputElem, isRecipient: isRecipient, recipientSecurity: null };
		fetchRecipientSecurity();
		views.push(v);
		cell.appendChild(v.root);
		row.style.display = '';
		if (single) {
			btn.style.display = 'none';
		}
		inputElem.focus();
		return v;
	};
	let noAttachmentsWarning;
	const checkAttachments = () => {
		const missingAttachments = !attachments.files?.length && !forwardAttachmentViews.find(v => v.checkbox.checked) && !!body.value.split('\n').find(s => !s.startsWith('>') && s.match(/attach(ed|ment)/));
		noAttachmentsWarning.style.display = missingAttachments ? '' : 'none';
	};
	const normalizeUser = (a) => {
		let user = a.User;
		const domconf = domainAddressConfigs[a.Domain.ASCII];
		const localpartCatchallSeparator = domconf.LocalpartCatchallSeparator;
		if (localpartCatchallSeparator) {
			user = user.split(localpartCatchallSeparator)[0];
		}
		const localpartCaseSensitive = domconf.LocalpartCaseSensitive;
		if (!localpartCaseSensitive) {
			user = user.toLowerCase();
		}
		return user;
	};
	// Find own address matching the specified address, taking wildcards, localpart
	// separators and case-sensitivity into account.
	const addressSelf = (addr) => {
		return accountAddresses.find(a => a.Domain.ASCII === addr.Domain.ASCII && (a.User === '' || normalizeUser(a) === normalizeUser(addr)));
	};
	let haveFrom = false;
	const fromOptions = accountAddresses.map(a => {
		const selected = opts.from && opts.from.length === 1 && equalAddress(a, opts.from[0]) || loginAddress && equalAddress(a, loginAddress) && (!opts.from || envelopeIdentity(opts.from));
		const o = dom.option(formatAddress(a), selected ? attr.selected('') : []);
		if (selected) {
			haveFrom = true;
		}
		return o;
	});
	if (!haveFrom && opts.from && opts.from.length === 1) {
		const a = addressSelf(opts.from[0]);
		if (a) {
			const fromAddr = { Name: a.Name, User: opts.from[0].User, Domain: a.Domain };
			const o = dom.option(formatAddress(fromAddr), attr.selected(''));
			fromOptions.unshift(o);
		}
	}
	let scheduleLink;
	let scheduleElem;
	let scheduleTime;
	let scheduleWeekday;
	const pad0 = (v) => v >= 10 ? '' + v : '0' + v;
	const localdate = (d) => [d.getFullYear(), pad0(d.getMonth() + 1), pad0(d.getDate())].join('-');
	const localdatetime = (d) => localdate(d) + 'T' + pad0(d.getHours()) + ':' + pad0(d.getMinutes()) + ':00';
	const weekdays = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
	const scheduleTimeChanged = () => {
		console.log('datetime change', scheduleTime.value);
		dom._kids(scheduleWeekday, weekdays[new Date(scheduleTime.value).getDay()]);
	};
	const composeElem = dom.div(style({
		position: 'fixed',
		bottom: '1ex',
		right: '1ex',
		zIndex: zindexes.compose,
		backgroundColor: 'white',
		boxShadow: '0px 0px 20px rgba(0, 0, 0, 0.1)',
		border: '1px solid #ccc',
		padding: '1em',
		minWidth: '40em',
		maxWidth: '95vw',
		borderRadius: '.25em',
	}), dom.form(fieldset = dom.fieldset(dom.table(style({ width: '100%' }), dom.tr(dom.td(style({ textAlign: 'right', color: '#555' }), dom.span('From:')), dom.td(dom.clickbutton('Cancel', style({ float: 'right', marginLeft: '1em', marginTop: '.15em' }), attr.title('Close window, discarding message.'), clickCmd(cmdCancel, shortcuts)), from = dom.select(attr.required(''), style({ width: 'auto' }), fromOptions), ' ', toBtn = dom.clickbutton('To', clickCmd(cmdAddTo, shortcuts)), ' ', ccBtn = dom.clickbutton('Cc', clickCmd(cmdAddCc, shortcuts)), ' ', bccBtn = dom.clickbutton('Bcc', clickCmd(cmdAddBcc, shortcuts)), ' ', replyToBtn = dom.clickbutton('ReplyTo', clickCmd(cmdReplyTo, shortcuts)), ' ', customFromBtn = dom.clickbutton('From', attr.title('Set custom From address/name.'), clickCmd(cmdCustomFrom, shortcuts)))), toRow = dom.tr(dom.td('To:', style({ textAlign: 'right', color: '#555' })), toCell = dom.td(style({ lineHeight: '1.5' }))), replyToRow = dom.tr(dom.td('Reply-To:', style({ textAlign: 'right', color: '#555' })), replyToCell = dom.td(style({ lineHeight: '1.5' }))), ccRow = dom.tr(dom.td('Cc:', style({ textAlign: 'right', color: '#555' })), ccCell = dom.td(style({ lineHeight: '1.5' }))), bccRow = dom.tr(dom.td('Bcc:', style({ textAlign: 'right', color: '#555' })), bccCell = dom.td(style({ lineHeight: '1.5' }))), dom.tr(dom.td('Subject:', style({ textAlign: 'right', color: '#555' })), dom.td(subjectAutosize = dom.span(dom._class('autosize'), style({ width: '100%' }), // Without 100% width, the span takes minimal width for input, we want the full table cell.
	subject = dom.input(style({ width: '100%' }), attr.value(opts.subject || ''), attr.required(''), focusPlaceholder('subject...'), function input() {
		subjectAutosize.dataset.value = subject.value;
	}))))), body = dom.textarea(dom._class('mono'), attr.rows('15'), style({ width: '100%' }), 
	// Explicit string object so it doesn't get the highlight-unicode-block-changes
	// treatment, which would cause characters to disappear.
	new String(opts.body || ''), opts.body && !opts.isForward && !opts.body.startsWith('\n\n') ? prop({ selectionStart: opts.body.length, selectionEnd: opts.body.length }) : [], function keyup(e) {
		if (e.key === 'Enter') {
			checkAttachments();
		}
	}), !(opts.attachmentsMessageItem && opts.attachmentsMessageItem.Attachments && opts.attachmentsMessageItem.Attachments.length > 0) ? [] : dom.div(style({ margin: '.5em 0' }), 'Forward attachments: ', forwardAttachmentViews = (opts.attachmentsMessageItem?.Attachments || []).map(a => {
		const filename = a.Filename || '(unnamed)';
		const size = formatSize(a.Part.DecodedSize);
		const checkbox = dom.input(attr.type('checkbox'), function change() { checkAttachments(); });
		const root = dom.label(checkbox, ' ' + filename + ' ', dom.span('(' + size + ') ', style({ color: '#666' })));
		const v = {
			path: a.Path || [],
			root: root,
			checkbox: checkbox
		};
		return v;
	}), dom.label(style({ color: '#666' }), dom.input(attr.type('checkbox'), function change(e) {
		forwardAttachmentViews.forEach(v => v.checkbox.checked = e.target.checked);
	}), ' (Toggle all)')), noAttachmentsWarning = dom.div(style({ display: 'none', backgroundColor: '#fcd284', padding: '0.15em .25em', margin: '.5em 0' }), 'Message mentions attachments, but no files are attached.'), dom.label(style({ margin: '1ex 0', display: 'block' }), 'Attachments ', attachments = dom.input(attr.type('file'), attr.multiple(''), function change() { checkAttachments(); })), dom.label(style({ margin: '1ex 0', display: 'block' }), attr.title('How to use TLS for message delivery over SMTP:\n\nDefault: Delivery attempts follow the policies published by the recipient domain: Verification with MTA-STS and/or DANE, or optional opportunistic unverified STARTTLS if the domain does not specify a policy.\n\nWith RequireTLS: For sensitive messages, you may want to require verified TLS. The recipient destination domain SMTP server must support the REQUIRETLS SMTP extension for delivery to succeed. It is automatically chosen when the destination domain mail servers of all recipients are known to support it.\n\nFallback to insecure: If delivery fails due to MTA-STS and/or DANE policies specified by the recipient domain, and the content is not sensitive, you may choose to ignore the recipient domain TLS policies so delivery can succeed.'), 'TLS ', requiretls = dom.select(dom.option(attr.value(''), 'Default'), dom.option(attr.value('yes'), 'With RequireTLS'), dom.option(attr.value('no'), 'Fallback to insecure'))), dom.div(scheduleLink = dom.a(attr.href(''), 'Schedule', function click(e) {
		e.preventDefault();
		scheduleTime.value = localdatetime(new Date());
		scheduleTimeChanged();
		scheduleLink.style.display = 'none';
		scheduleElem.style.display = '';
		scheduleTime.setAttribute('required', '');
	}), scheduleElem = dom.div(style({ display: 'none' }), dom.clickbutton('Start of next day', function click(e) {
		e.preventDefault();
		const d = new Date(scheduleTime.value);
		const nextday = new Date(d.getTime() + 24 * 3600 * 1000);
		scheduleTime.value = localdate(nextday) + 'T09:00:00';
		scheduleTimeChanged();
	}), ' ', dom.clickbutton('+1 hour', function click(e) {
		e.preventDefault();
		const d = new Date(scheduleTime.value);
		scheduleTime.value = localdatetime(new Date(d.getTime() + 3600 * 1000));
		scheduleTimeChanged();
	}), ' ', dom.clickbutton('+1 day', function click(e) {
		e.preventDefault();
		const d = new Date(scheduleTime.value);
		scheduleTime.value = localdatetime(new Date(d.getTime() + 24 * 3600 * 1000));
		scheduleTimeChanged();
	}), ' ', dom.clickbutton('Now', function click(e) {
		e.preventDefault();
		scheduleTime.value = localdatetime(new Date());
		scheduleTimeChanged();
	}), ' ', dom.clickbutton('Cancel', function click(e) {
		e.preventDefault();
		scheduleLink.style.display = '';
		scheduleElem.style.display = 'none';
		scheduleTime.removeAttribute('required');
		scheduleTime.value = '';
	}), dom.div(style({ marginTop: '1ex' }), scheduleTime = dom.input(attr.type('datetime-local'), function change() {
		scheduleTimeChanged();
	}), ' in local timezone ' + (Intl.DateTimeFormat().resolvedOptions().timeZone || '') + ', ', scheduleWeekday = dom.span()))), dom.div(style({ margin: '3ex 0 1ex 0', display: 'block' }), dom.submitbutton('Send'))), async function submit(e) {
		e.preventDefault();
		shortcutCmd(cmdSend, shortcuts);
	}));
	subjectAutosize.dataset.value = subject.value;
	(opts.to && opts.to.length > 0 ? opts.to : ['']).forEach(s => newAddrView(s, true, toViews, toBtn, toCell, toRow));
	(opts.cc || []).forEach(s => newAddrView(s, true, ccViews, ccBtn, ccCell, ccRow));
	(opts.bcc || []).forEach(s => newAddrView(s, true, bccViews, bccBtn, bccCell, bccRow));
	if (opts.replyto) {
		newAddrView(opts.replyto, false, replytoViews, replyToBtn, replyToCell, replyToRow, true);
	}
	if (!opts.cc || !opts.cc.length) {
		ccRow.style.display = 'none';
	}
	if (!opts.bcc || !opts.bcc.length) {
		bccRow.style.display = 'none';
	}
	if (!opts.replyto) {
		replyToRow.style.display = 'none';
	}
	document.body.appendChild(composeElem);
	if (toViews.length > 0 && !toViews[0].input.value) {
		toViews[0].input.focus();
	}
	else {
		body.focus();
	}
	composeView = {
		root: composeElem,
		key: keyHandler(shortcuts),
	};
	return composeView;
};
// Show popover to edit labels for msgs.
const labelsPopover = (e, msgs, possibleLabels) => {
	if (msgs.length === 0) {
		return; // Should not happen.
	}
	const knownLabels = possibleLabels();
	const activeLabels = (msgs[0].Keywords || []).filter(kw => msgs.filter(m => (m.Keywords || []).includes(kw)).length === msgs.length);
	const msgIDs = msgs.map(m => m.ID);
	let fieldsetnew;
	let newlabel;
	const remove = popover(e.target, {}, dom.div(style({ display: 'flex', flexDirection: 'column', gap: '1ex' }), knownLabels.map(l => dom.div(dom.label(dom.input(attr.type('checkbox'), activeLabels.includes(l) ? attr.checked('') : [], style({ marginRight: '.5em' }), attr.title('Add/remove this label to the message(s), leaving other labels unchanged.'), async function change(e) {
		if (activeLabels.includes(l)) {
			await withStatus('Removing label', client.FlagsClear(msgIDs, [l]), e.target);
			activeLabels.splice(activeLabels.indexOf(l), 1);
		}
		else {
			await withStatus('Adding label', client.FlagsAdd(msgIDs, [l]), e.target);
			activeLabels.push(l);
		}
	}), ' ', dom.span(dom._class('keyword'), l))))), dom.hr(style({ margin: '2ex 0' })), dom.form(async function submit(e) {
		e.preventDefault();
		await withStatus('Adding new label', client.FlagsAdd(msgIDs, [newlabel.value]), fieldsetnew);
		remove();
	}, fieldsetnew = dom.fieldset(dom.div(newlabel = dom.input(focusPlaceholder('new-label'), attr.required(''), attr.title('New label to add/set on the message(s), must be lower-case, ascii-only, without spaces and without the following special characters: (){%*"\].')), ' ', dom.submitbutton('Add new label', attr.title('Add this label to the message(s), leaving other labels unchanged.'))))));
};
// Show popover to move messages to a mailbox.
const movePopover = (e, mailboxes, msgs) => {
	if (msgs.length === 0) {
		return; // Should not happen.
	}
	let msgsMailboxID = (msgs[0].MailboxID && msgs.filter(m => m.MailboxID === msgs[0].MailboxID).length === msgs.length) ? msgs[0].MailboxID : 0;
	const remove = popover(e.target, {}, dom.div(style({ display: 'flex', flexDirection: 'column', gap: '.25em' }), mailboxes.map(mb => dom.div(dom.clickbutton(mb.Name, mb.ID === msgsMailboxID ? attr.disabled('') : [], async function click() {
		const msgIDs = msgs.filter(m => m.MailboxID !== mb.ID).map(m => m.ID);
		await withStatus('Moving to mailbox', client.MessageMove(msgIDs, mb.ID));
		remove();
	})))));
};
// Make new MsgitemView, to be added to the list.
const newMsgitemView = (mi, msglistView, otherMailbox, listMailboxes, receivedTime, initialCollapsed) => {
	// note: mi may be replaced.
	// Timer to update the age of the message.
	let ageTimer = 0;
	// Show with a tag if we are in the cc/bcc headers, or - if none.
	const identityTag = (s, title) => dom.span(dom._class('msgitemidentity'), s, attr.title(title));
	const identityHeader = [];
	if (!envelopeIdentity(mi.Envelope.From || []) && !envelopeIdentity(mi.Envelope.To || [])) {
		if (envelopeIdentity(mi.Envelope.CC || [])) {
			identityHeader.push(identityTag('cc', 'You are in the CC header'));
		}
		if (envelopeIdentity(mi.Envelope.BCC || [])) {
			identityHeader.push(identityTag('bcc', 'You are in the BCC header'));
		}
		// todo: don't include this if this is a message to a mailling list, based on list-* headers.
		if (identityHeader.length === 0) {
			identityHeader.push(identityTag('-', 'You are not in any To, From, CC, BCC header. Could message to a mailing list or Bcc without Bcc message header.'));
		}
	}
	const remove = () => {
		msgitemView.root.remove();
		if (ageTimer) {
			window.clearTimeout(ageTimer);
			ageTimer = 0;
		}
	};
	const age = (date) => {
		const r = dom.span(dom._class('notooltip'), attr.title(date.toString()));
		const set = () => {
			const nowSecs = new Date().getTime() / 1000;
			let t = nowSecs - date.getTime() / 1000;
			let negative = '';
			if (t < 0) {
				negative = '-';
				t = -t;
			}
			const minute = 60;
			const hour = 60 * minute;
			const day = 24 * hour;
			const month = 30 * day;
			const year = 365 * day;
			const periods = [year, month, day, hour, minute];
			const suffix = ['y', 'mo', 'd', 'h', 'min'];
			let s;
			let nextSecs = 0;
			for (let i = 0; i < periods.length; i++) {
				const p = periods[i];
				if (t >= 2 * p || i === periods.length - 1) {
					const n = Math.round(t / p);
					s = '' + n + suffix[i];
					const prev = Math.floor(t / p);
					nextSecs = Math.ceil((prev + 1) * p - t);
					break;
				}
			}
			if (t < 60) {
				s = '<1min';
				nextSecs = 60 - t;
				// Prevent showing '-<1min' when browser and server have relatively small time drift of max 1 minute.
				negative = '';
			}
			dom._kids(r, negative + s);
			// note: Cannot have delays longer than 24.8 days due to storage as 32 bit in
			// browsers. Session is likely closed/reloaded/refreshed before that time anyway.
			if (nextSecs < 14 * 24 * 3600) {
				ageTimer = window.setTimeout(set, nextSecs * 1000);
			}
			else {
				ageTimer = 0;
			}
		};
		set();
		return r;
	};
	const render = () => {
		const mi = msgitemView.messageitem;
		const m = mi.Message;
		// Set by calling age().
		if (ageTimer) {
			window.clearTimeout(ageTimer);
			ageTimer = 0;
		}
		// Keywords are normally shown per message. For collapsed threads, we show the
		// keywords of the thread root message as normal, and any additional keywords from
		// children in a way that draws less attention.
		const keywords = (m.Keywords || []).map(kw => dom.span(dom._class('keyword'), kw));
		if (msgitemView.isCollapsedThreadRoot()) {
			const keywordsSeen = new Set();
			for (const kw of (m.Keywords || [])) {
				keywordsSeen.add(kw);
			}
			for (const miv of msgitemView.descendants()) {
				for (const kw of (miv.messageitem.Message.Keywords || [])) {
					if (!keywordsSeen.has(kw)) {
						keywordsSeen.add(kw);
						keywords.push(dom.span(dom._class('keyword'), dom._class('keywordcollapsed'), kw));
					}
				}
			}
		}
		let threadIndent = 0;
		for (let miv = msgitemView; miv.parent; miv = miv.parent) {
			threadIndent++;
		}
		// For threaded messages, we draw the subject/first-line indented, and with a
		// charactering indicating the relationship.
		// todo: show different arrow is message is a forward? we can tell by the message flag, it will likely be a message the user sent.
		let threadChar = '';
		let threadCharTitle = '';
		if (msgitemView.parent) {
			threadChar = '↳'; // Down-right arrow for direct response (reply/forward).
			if (msgitemView.parent.messageitem.Message.MessageID === mi.Message.MessageID) {
				// Approximately equal, for duplicate message-id, typically in Sent and incoming
				// from mailing list or when sending to self.
				threadChar = '≈';
				threadCharTitle = 'Same Message-ID.';
			}
			else if (mi.Message.ThreadMissingLink || (mi.Message.ThreadParentIDs || []).length > 0 && (mi.Message.ThreadParentIDs || [])[0] !== msgitemView.parent.messageitem.Message.ID) {
				// Zigzag arrow, e.g. if immediate parent is missing, or when matching was done
				// based on subject.
				threadChar = '↯';
				threadCharTitle = 'Immediate parent message is missing.';
			}
		}
		// Message is unread if it itself is unread, or it is collapsed and has an unread child message.
		const isUnread = () => !mi.Message.Seen || msgitemView.isCollapsedThreadRoot() && !!msgitemView.findDescendant(miv => !miv.messageitem.Message.Seen);
		const isRelevant = () => !mi.Message.ThreadMuted && mi.MatchQuery || (msgitemView.isCollapsedThreadRoot() && msgitemView.findDescendant(miv => !miv.messageitem.Message.ThreadMuted && miv.messageitem.MatchQuery));
		// Effective receive time to display. For collapsed thread roots, we show the time
		// of the newest or oldest message, depending on whether you're viewing
		// newest-first or oldest-first messages.
		const received = () => {
			let r = mi.Message.Received;
			if (!msgitemView.isCollapsedThreadRoot()) {
				return r;
			}
			msgitemView.descendants().forEach(dmiv => {
				if (settings.orderAsc && dmiv.messageitem.Message.Received.getTime() < r.getTime()) {
					r = dmiv.messageitem.Message.Received;
				}
				else if (!settings.orderAsc && dmiv.messageitem.Message.Received.getTime() > r.getTime()) {
					r = dmiv.messageitem.Message.Received;
				}
			});
			return r;
		};
		// For drawing half a thread bar for the last message in the thread.
		const isThreadLast = () => {
			let miv = msgitemView.threadRoot();
			while (miv.kids.length > 0) {
				miv = miv.kids[miv.kids.length - 1];
			}
			return miv === msgitemView;
		};
		// If mailbox of message is not specified in filter (i.e. for a regular mailbox
		// view, or search on a mailbox), we show it on the right-side of the subject. For
		// collapsed thread roots, we show all additional mailboxes of descendants with
		// different style.
		const mailboxtags = [];
		const mailboxIDs = new Set();
		const addMailboxTag = (mb, isCollapsedKid) => {
			let name = mb.Name;
			mailboxIDs.add(mb.ID);
			if (name.length > 8 + 1 + 3 + 1 + 8 + 4) {
				const t = name.split('/');
				const first = t[0];
				const last = t[t.length - 1];
				if (first.length + last.length <= 8 + 8) {
					name = first + '/.../' + last;
				}
				else {
					name = first.substring(0, 8) + '/.../' + last.substring(0, 8);
				}
			}
			const e = dom.span(dom._class('msgitemmailbox'), isCollapsedKid ? dom._class('msgitemmailboxcollapsed') : [], name === mb.Name ? [] : attr.title(mb.Name), name);
			mailboxtags.push(e);
		};
		const othermb = otherMailbox(m.MailboxID);
		if (othermb) {
			addMailboxTag(othermb, false);
		}
		if (msgitemView.isCollapsedThreadRoot()) {
			for (const miv of msgitemView.descendants()) {
				const m = miv.messageitem.Message;
				if (!mailboxIDs.has(m.MailboxID) && otherMailbox(m.MailboxID)) {
					const mb = listMailboxes().find(mb => mb.ID === m.MailboxID);
					if (!mb) {
						throw new ConsistencyError('missing mailbox for message in thread');
					}
					addMailboxTag(mb, true);
				}
			}
		}
		const correspondentAddrs = (miv) => {
			let fromAddrs = miv.messageitem.Envelope.From || [];
			let toAddrs = [];
			if (listMailboxes().find(mb => mb.ID === miv.messageitem.Message.MailboxID)?.Sent) {
				toAddrs = [...(miv.messageitem.Envelope.To || []), ...(miv.messageitem.Envelope.CC || []), ...(miv.messageitem.Envelope.BCC || [])];
			}
			return [fromAddrs, toAddrs];
		};
		// Correspondents for a message, possibly a collapsed thread root.
		const correspondents = () => {
			let fromAddrs = [];
			let toAddrs = [];
			if (msgitemView.isCollapsedThreadRoot()) {
				// Gather both all correspondents in thread.
				;
				[msgitemView, ...(msgitemView.descendants())].forEach(miv => {
					const [fa, ta] = correspondentAddrs(miv);
					fromAddrs = [...fromAddrs, ...fa];
					toAddrs = [...toAddrs, ...ta];
				});
			}
			else {
				[fromAddrs, toAddrs] = correspondentAddrs(msgitemView);
			}
			const seen = new Set();
			let fa = [];
			let ta = [];
			for (const a of fromAddrs) {
				const k = a.User + '@' + a.Domain.ASCII;
				if (!seen.has(k)) {
					seen.add(k);
					fa.push(a);
				}
			}
			for (const a of toAddrs) {
				const k = a.User + '@' + a.Domain.ASCII;
				if (!seen.has(k)) {
					seen.add(k);
					ta.push(a);
				}
			}
			let title = fa.map(a => formatAddress(a)).join(', ');
			if (ta.length > 0) {
				if (title) {
					title += ',\n';
				}
				title += 'addressed: ' + ta.map(a => formatAddress(a)).join(', ');
			}
			return [
				attr.title(title),
				join([
					...fa.map(a => formatAddressShort(a)),
					...ta.map(a => dom.span(style({ fontStyle: 'italic' }), formatAddressShort(a))),
				], () => ', '),
			];
		};
		// When rerendering, we remember active & focus states. So we don't have to make
		// the caller also call redraw on MsglistView.
		const active = msgitemView.root && msgitemView.root.classList.contains('active');
		const focus = msgitemView.root && msgitemView.root.classList.contains('focus');
		const elem = dom.div(dom._class('msgitem'), active ? dom._class('active') : [], focus ? dom._class('focus') : [], attr.draggable('true'), function dragstart(e) {
			if (!msglistView.selected().includes(msgitemView)) {
				e.preventDefault();
				window.alert('Can only drag items in selection.');
				return;
			}
			// We send the Message.ID and MailboxID, so we can decide based on the destination
			// mailbox whether to move. We don't move messages already in the destination
			// mailbox, and also skip messages in the Sent mailbox when there are also messages
			// from other mailboxes.
			e.dataTransfer.setData('application/vnd.mox.messages', JSON.stringify(msglistView.selected().map(miv => [miv.messageitem.Message.MailboxID, miv.messageitem.Message.ID])));
		}, 
		// Thread root with kids can be collapsed/expanded with double click.
		settings.threading !== api.ThreadMode.ThreadOff && !msgitemView.parent && msgitemView.kids.length > 0 ?
			function dblclick(e) {
				e.stopPropagation(); // Prevent selection.
				if (settings.threading === api.ThreadMode.ThreadOn) {
					// No await, we don't wait for the result.
					withStatus('Saving thread expand/collapse', client.ThreadCollapse([msgitemView.messageitem.Message.ID], !msgitemView.collapsed));
				}
				if (msgitemView.collapsed) {
					msglistView.threadExpand(msgitemView);
				}
				else {
					msglistView.threadCollapse(msgitemView);
					msglistView.viewportEnsureMessages();
				}
			} : [], isUnread() ? style({ fontWeight: 'bold' }) : [], 
		// Relevant means not muted and matching the query.
		isRelevant() ? [] : style({ opacity: '.4' }), dom.div(dom._class('msgitemcell', 'msgitemflags'), dom.div(style({ display: 'flex', justifyContent: 'space-between' }), dom.div(flagList(msgitemView)), !msgitemView.parent && msgitemView.kids.length > 0 && msgitemView.collapsed ?
			dom.clickbutton('' + (1 + msgitemView.descendants().length), attr.tabindex('-1'), attr.title('Expand thread.'), attr.arialabel('Expand thread.'), function click(e) {
				e.stopPropagation(); // Prevent selection.
				if (settings.threading === api.ThreadMode.ThreadOn) {
					withStatus('Saving thread expanded', client.ThreadCollapse([msgitemView.messageitem.Message.ID], false));
				}
				msglistView.threadExpand(msgitemView);
			}) : [], !msgitemView.parent && msgitemView.kids.length > 0 && !msgitemView.collapsed ?
			dom.clickbutton('-', style({ width: '1em' }), attr.tabindex('-1'), attr.title('Collapse thread.'), attr.arialabel('Collapse thread.'), function click(e) {
				e.stopPropagation(); // Prevent selection.
				if (settings.threading === api.ThreadMode.ThreadOn) {
					withStatus('Saving thread expanded', client.ThreadCollapse([msgitemView.messageitem.Message.ID], true));
				}
				msglistView.threadCollapse(msgitemView);
				msglistView.viewportEnsureMessages();
			}) : [])), dom.div(dom._class('msgitemcell', 'msgitemfrom'), dom.div(style({ display: 'flex', justifyContent: 'space-between' }), dom.div(dom._class('msgitemfromtext', 'silenttitle'), correspondents()), identityHeader), 
		// Thread messages are connected by a vertical bar. The first and last message are
		// only half the height of the item, to indicate start/end, and so it stands out
		// from any thread above/below.
		((msgitemView.parent || msgitemView.kids.length > 0) && !msgitemView.threadRoot().collapsed) ?
			dom.div(dom._class('msgitemfromthreadbar'), !msgitemView.parent ? style({ top: '50%', bottom: '-1px' }) : (isThreadLast() ?
				style({ top: '-1px', bottom: '50%' }) :
				style({ top: '-1px', bottom: '-1px' }))) : []), dom.div(dom._class('msgitemcell', 'msgitemsubject'), dom.div(style({ display: 'flex', justifyContent: 'space-between', position: 'relative' }), dom.div(dom._class('msgitemsubjecttext'), threadIndent > 0 ? dom.span(threadChar, style({ paddingLeft: (threadIndent / 2) + 'em', color: '#444', fontWeight: 'normal' }), threadCharTitle ? attr.title(threadCharTitle) : []) : [], msgitemView.parent ? [] : mi.Envelope.Subject || '(no subject)', dom.span(dom._class('msgitemsubjectsnippet'), ' ' + mi.FirstLine)), dom.div(keywords, mailboxtags))), dom.div(dom._class('msgitemcell', 'msgitemage'), age(received())), function click(e) {
			e.preventDefault();
			e.stopPropagation();
			msglistView.click(msgitemView, e.ctrlKey, e.shiftKey);
		});
		msgitemView.root.replaceWith(elem);
		msgitemView.root = elem;
	};
	const msgitemView = {
		root: dom.div(),
		messageitem: mi,
		receivedTime: receivedTime,
		kids: [],
		parent: null,
		collapsed: initialCollapsed,
		threadRoot: () => {
			let miv = msgitemView;
			while (miv.parent) {
				miv = miv.parent;
			}
			return miv;
		},
		isCollapsedThreadRoot: () => !msgitemView.parent && msgitemView.collapsed && msgitemView.kids.length > 0,
		descendants: () => {
			let l = [];
			const walk = (miv) => {
				for (const kmiv of miv.kids) {
					l.push(kmiv);
					walk(kmiv);
				}
			};
			walk(msgitemView);
			return l;
		},
		// We often just need to know if a descendant with certain properties exist. No
		// need to create an array, then call find on it.
		findDescendant: (matchfn) => {
			const walk = (miv) => {
				if (matchfn(miv)) {
					return miv;
				}
				for (const kmiv of miv.kids) {
					const r = walk(kmiv);
					if (r) {
						return r;
					}
				}
				return null;
			};
			return walk(msgitemView);
		},
		lastDescendant: () => {
			let l = msgitemView;
			if (l.kids.length === 0) {
				return null;
			}
			while (l.kids.length > 0) {
				l = l.kids[l.kids.length - 1];
			}
			return l;
		},
		remove: remove,
		render: render,
	};
	return msgitemView;
};
// If attachmentView is open, keyboard shortcuts go there.
let attachmentView = null;
// MsgView is the display of a single message.
// refineKeyword is called when a user clicks a label, to filter on those.
const newMsgView = (miv, msglistView, listMailboxes, possibleLabels, messageLoaded, refineKeyword, parsedMessageOpt) => {
	const mi = miv.messageitem;
	const m = mi.Message;
	const fromAddress = mi.Envelope.From && mi.Envelope.From.length === 1 ? formatEmail(mi.Envelope.From[0]) : '';
	// Some operations below, including those that can be reached through shortcuts,
	// need a parsed message. So we keep a promise around for having that parsed
	// message. Operations always await it. Once we have the parsed message, the await
	// completes immediately.
	// Typescript doesn't know the function passed to new Promise runs immediately and
	// has set the Resolve and Reject variables before returning. Is there a better
	// solution?
	let parsedMessageResolve = () => { };
	let parsedMessageReject = () => { };
	let parsedMessagePromise = new Promise((resolve, reject) => {
		parsedMessageResolve = resolve;
		parsedMessageReject = reject;
	});
	const react = async (to, cc, bcc, forward, all) => {
		const pm = await parsedMessagePromise;
		let body = '';
		const sel = window.getSelection();
		let haveSel = false;
		if (sel && sel.toString()) {
			body = sel.toString();
			haveSel = true;
		}
		else if (pm.Texts && pm.Texts.length > 0) {
			body = pm.Texts[0];
		}
		body = body.replace(/\r/g, '').replace(/\n\n\n\n*/g, '\n\n').trim();
		if (forward) {
			body = '\n\n---- Forwarded Message ----\n\n' + body;
		}
		else {
			body = body.split('\n').map(line => '> ' + line).join('\n');
			if (haveSel) {
				body += '\n\n';
			}
			else {
				let onWroteLine = '';
				if (mi.Envelope.Date && mi.Envelope.From && mi.Envelope.From.length === 1) {
					const from = mi.Envelope.From[0];
					const name = from.Name || formatEmail(from);
					const datetime = mi.Envelope.Date.toLocaleDateString(undefined, { weekday: "short", year: "numeric", month: "short", day: "numeric" }) + ' at ' + mi.Envelope.Date.toLocaleTimeString();
					onWroteLine = 'On ' + datetime + ', ' + name + ' wrote:\n';
				}
				body = '\n\n' + onWroteLine + body;
			}
		}
		const subjectPrefix = forward ? 'Fwd:' : 'Re:';
		let subject = mi.Envelope.Subject || '';
		subject = (RegExp('^' + subjectPrefix, 'i').test(subject) ? '' : subjectPrefix + ' ') + subject;
		const opts = {
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
		};
		if (all) {
			opts.to = (to || []).concat((mi.Envelope.To || []).filter(a => !envelopeIdentity([a]))).map(a => formatAddress(a));
			opts.cc = (mi.Envelope.CC || []).map(a => formatAddress(a));
			opts.bcc = (mi.Envelope.BCC || []).map(a => formatAddress(a));
		}
		compose(opts);
	};
	const reply = async (all, toOpt) => {
		if (!all && !toOpt && (mi.Envelope.From || []).length === 1 && envelopeIdentity(mi.Envelope.From || [])) {
			await react(mi.Envelope.To || [], mi.Envelope.CC || [], mi.Envelope.BCC || [], false, all);
		}
		else {
			await react(toOpt || ((mi.Envelope.ReplyTo || []).length > 0 ? mi.Envelope.ReplyTo : mi.Envelope.From) || [], [], [], false, all);
		}
	};
	const cmdForward = async () => { react([], [], [], true, false); };
	const cmdReplyList = async () => {
		const pm = await parsedMessagePromise;
		if (pm.ListReplyAddress) {
			await reply(false, [pm.ListReplyAddress]);
		}
	};
	const cmdReply = async () => { await reply(false); };
	const cmdReplyAll = async () => { await reply(true); };
	const cmdPrint = async () => {
		if (urlType) {
			window.open('msg/' + m.ID + '/msg' + urlType + '#print', '_blank');
		}
	};
	const cmdOpenNewTab = async () => {
		if (urlType) {
			window.open('msg/' + m.ID + '/msg' + urlType, '_blank');
		}
	};
	const cmdOpenRaw = async () => { window.open('msg/' + m.ID + '/raw', '_blank'); };
	const cmdViewAttachments = async () => {
		if (attachments.length > 0) {
			view(attachments[0]);
		}
	};
	const cmdToggleHeaders = async () => {
		settingsPut({ ...settings, showAllHeaders: !settings.showAllHeaders });
		const pm = await parsedMessagePromise;
		loadHeaderDetails(pm);
	};
	let textbtn, htmlbtn, htmlextbtn;
	const activeBtn = (b) => {
		for (const xb of [textbtn, htmlbtn, htmlextbtn]) {
			if (xb) {
				xb.classList.toggle('active', xb === b);
			}
		}
	};
	const cmdShowText = async () => {
		if (!textbtn) {
			return;
		}
		loadText(await parsedMessagePromise);
		settingsPut({ ...settings, showHTML: false });
		activeBtn(textbtn);
	};
	const cmdShowHTML = async () => {
		if (!htmlbtn || !htmlextbtn) {
			return;
		}
		loadHTML();
		activeBtn(htmlbtn);
	};
	const cmdShowHTMLExternal = async () => {
		if (!htmlbtn || !htmlextbtn) {
			return;
		}
		loadHTMLexternal();
		activeBtn(htmlextbtn);
	};
	const cmdShowHTMLCycle = async () => {
		if (urlType === 'html') {
			await cmdShowHTMLExternal();
		}
		else {
			await cmdShowHTML();
		}
	};
	const cmdShowInternals = async () => {
		const pm = await parsedMessagePromise;
		const mimepart = (p) => dom.li((p.MediaType + '/' + p.MediaSubType).toLowerCase(), p.ContentTypeParams ? ' ' + JSON.stringify(p.ContentTypeParams) : [], p.Parts && p.Parts.length === 0 ? [] : dom.ul(style({ listStyle: 'disc', marginLeft: '1em' }), (p.Parts || []).map(pp => mimepart(pp))));
		popup(style({ display: 'flex', gap: '1em' }), dom.div(dom.h1('Mime structure'), dom.ul(style({ listStyle: 'disc', marginLeft: '1em' }), mimepart(pm.Part))), dom.div(style({ whiteSpace: 'pre-wrap', tabSize: 4, maxWidth: '50%' }), dom.h1('Message'), JSON.stringify(m, undefined, '\t')), dom.div(style({ whiteSpace: 'pre-wrap', tabSize: 4, maxWidth: '50%' }), dom.h1('Part'), JSON.stringify(pm.Part, undefined, '\t')));
	};
	const cmdUp = async () => { msgscrollElem.scrollTo({ top: msgscrollElem.scrollTop - 3 * msgscrollElem.getBoundingClientRect().height / 4, behavior: 'smooth' }); };
	const cmdDown = async () => { msgscrollElem.scrollTo({ top: msgscrollElem.scrollTop + 3 * msgscrollElem.getBoundingClientRect().height / 4, behavior: 'smooth' }); };
	const cmdHome = async () => { msgscrollElem.scrollTo({ top: 0 }); };
	const cmdEnd = async () => { msgscrollElem.scrollTo({ top: msgscrollElem.scrollHeight }); };
	const shortcuts = {
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
	};
	let urlType; // text, html, htmlexternal; for opening in new tab/print
	let msgbuttonElem, msgheaderElem, msgattachmentElem, msgmodeElem;
	let msgheaderdetailsElem = null; // When full headers are visible, or some headers are requested through settings.
	const msgmetaElem = dom.div(style({ backgroundColor: '#f8f8f8', borderBottom: '5px solid white', maxHeight: '90%', overflowY: 'auto' }), attr.role('region'), attr.arialabel('Buttons and headers for message'), msgbuttonElem = dom.div(), dom.div(attr.arialive('assertive'), msgheaderElem = dom.table(dom._class('msgheaders'), style({ marginBottom: '1ex', width: '100%' })), msgattachmentElem = dom.div(), msgmodeElem = dom.div()), 
	// Explicit gray line with white border below that separates headers from body, to
	// prevent HTML messages from faking UI elements.
	dom.div(style({ height: '2px', backgroundColor: '#ccc' })));
	const msgscrollElem = dom.div(dom._class('pad', 'yscrollauto'), attr.role('region'), attr.arialabel('Message body'), style({ backgroundColor: 'white' }));
	const msgcontentElem = dom.div(dom._class('scrollparent'), style({ flexGrow: '1' }));
	const trashMailboxID = listMailboxes().find(mb => mb.Trash)?.ID;
	// Initially called with potentially null pm, once loaded called again with pm set.
	const loadButtons = (pm) => {
		dom._kids(msgbuttonElem, dom.div(dom._class('pad'), (!pm || !pm.ListReplyAddress) ? [] : dom.clickbutton('Reply to list', attr.title('Compose a reply to this mailing list.'), clickCmd(cmdReplyList, shortcuts)), ' ', (pm && pm.ListReplyAddress && formatEmail(pm.ListReplyAddress) === fromAddress) ? [] : dom.clickbutton('Reply', attr.title('Compose a reply to the sender of this message.'), clickCmd(cmdReply, shortcuts)), ' ', (mi.Envelope.To || []).length <= 1 && (mi.Envelope.CC || []).length === 0 && (mi.Envelope.BCC || []).length === 0 ? [] :
			dom.clickbutton('Reply all', attr.title('Compose a reply to all participants of this message.'), clickCmd(cmdReplyAll, shortcuts)), ' ', dom.clickbutton('Forward', attr.title('Compose a forwarding message, optionally including attachments.'), clickCmd(cmdForward, shortcuts)), ' ', dom.clickbutton('Archive', attr.title('Move to the Archive mailbox.'), clickCmd(msglistView.cmdArchive, shortcuts)), ' ', m.MailboxID === trashMailboxID ?
			dom.clickbutton('Delete', attr.title('Permanently delete message.'), clickCmd(msglistView.cmdDelete, shortcuts)) :
			dom.clickbutton('Trash', attr.title('Move to the Trash mailbox.'), clickCmd(msglistView.cmdTrash, shortcuts)), ' ', dom.clickbutton('Junk', attr.title('Move to Junk mailbox, marking as junk and causing this message to be used in spam classification of new incoming messages.'), clickCmd(msglistView.cmdJunk, shortcuts)), ' ', dom.clickbutton('Move to...', function click(e) {
			movePopover(e, listMailboxes(), [m]);
		}), ' ', dom.clickbutton('Labels...', attr.title('Add/remove labels.'), function click(e) {
			labelsPopover(e, [m], possibleLabels);
		}), ' ', dom.clickbutton('More...', attr.title('Show more actions.'), function click(e) {
			popover(e.target, { transparent: true }, dom.div(style({ display: 'flex', flexDirection: 'column', gap: '.5ex', textAlign: 'right' }), [
				dom.clickbutton('Print', attr.title('Print message, opens in new tab and opens print dialog.'), clickCmd(cmdPrint, shortcuts)),
				dom.clickbutton('Mark Not Junk', attr.title('Mark as not junk, causing this message to be used in spam classification of new incoming messages.'), clickCmd(msglistView.cmdMarkNotJunk, shortcuts)),
				dom.clickbutton('Mark Read', clickCmd(msglistView.cmdMarkRead, shortcuts)),
				dom.clickbutton('Mark Unread', clickCmd(msglistView.cmdMarkUnread, shortcuts)),
				dom.clickbutton('Mute thread', clickCmd(msglistView.cmdMute, shortcuts)),
				dom.clickbutton('Unmute thread', clickCmd(msglistView.cmdUnmute, shortcuts)),
				dom.clickbutton('Open in new tab', clickCmd(cmdOpenNewTab, shortcuts)),
				dom.clickbutton('Show raw original message in new tab', clickCmd(cmdOpenRaw, shortcuts)),
				dom.clickbutton('Show internals in popup', clickCmd(cmdShowInternals, shortcuts)),
			].map(b => dom.div(b))));
		})));
	};
	loadButtons(parsedMessageOpt || null);
	loadMsgheaderView(msgheaderElem, miv.messageitem, settings.showHeaders, refineKeyword, false);
	const loadHeaderDetails = (pm) => {
		if (msgheaderdetailsElem) {
			msgheaderdetailsElem.remove();
			msgheaderdetailsElem = null;
		}
		if (!settings.showAllHeaders) {
			return;
		}
		msgheaderdetailsElem = dom.table(style({ marginBottom: '1ex', width: '100%' }), Object.entries(pm.Headers || {}).sort().map(t => (t[1] || []).map(v => dom.tr(dom.td(t[0] + ':', style({ textAlign: 'right', color: '#555' })), dom.td(v)))));
		msgattachmentElem.parentNode.insertBefore(msgheaderdetailsElem, msgattachmentElem);
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
	const isText = (a) => ['text', 'message'].includes(a.Part.MediaType.toLowerCase());
	const isImage = (a) => imageTypes.includes((a.Part.MediaType + '/' + a.Part.MediaSubType).toLowerCase());
	const isPDF = (a) => (a.Part.MediaType + '/' + a.Part.MediaSubType).toLowerCase() === 'application/pdf';
	const isViewable = (a) => isText(a) || isImage(a) || isPDF(a);
	const attachments = (mi.Attachments || []);
	let beforeViewFocus;
	const view = (a) => {
		if (!beforeViewFocus) {
			beforeViewFocus = document.activeElement;
		}
		const pathStr = [0].concat(a.Path || []).join('.');
		const index = attachments.indexOf(a);
		const cmdViewPrev = async () => {
			if (index > 0) {
				popupRoot.remove();
				view(attachments[index - 1]);
			}
		};
		const cmdViewNext = async () => {
			if (index < attachments.length - 1) {
				popupRoot.remove();
				view(attachments[index + 1]);
			}
		};
		const cmdViewFirst = async () => {
			popupRoot.remove();
			view(attachments[0]);
		};
		const cmdViewLast = async () => {
			popupRoot.remove();
			view(attachments[attachments.length - 1]);
		};
		const cmdViewClose = async () => {
			popupRoot.remove();
			if (beforeViewFocus && beforeViewFocus instanceof HTMLElement && beforeViewFocus.parentNode) {
				beforeViewFocus.focus();
			}
			attachmentView = null;
			beforeViewFocus = null;
		};
		const attachShortcuts = {
			h: cmdViewPrev,
			ArrowLeft: cmdViewPrev,
			l: cmdViewNext,
			ArrowRight: cmdViewNext,
			'0': cmdViewFirst,
			'$': cmdViewLast,
			Escape: cmdViewClose,
		};
		let content;
		const popupRoot = dom.div(style({ position: 'fixed', left: 0, right: 0, top: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.2)', display: 'flex', flexDirection: 'column', alignContent: 'stretch', padding: '1em', zIndex: zindexes.attachments }), function click(e) {
			e.stopPropagation();
			cmdViewClose();
		}, attr.tabindex('0'), !(index > 0) ? [] : dom.div(style({ position: 'absolute', left: '1em', top: 0, bottom: 0, fontSize: '1.5em', width: '2em', display: 'flex', alignItems: 'center', cursor: 'pointer' }), dom.div(dom._class('silenttitle'), style({ backgroundColor: 'rgba(0, 0, 0, .8)', color: 'white', width: '2em', height: '2em', borderRadius: '1em', lineHeight: '2em', textAlign: 'center', fontWeight: 'bold' }), attr.title('To previous viewable attachment.'), '←'), attr.tabindex('0'), clickCmd(cmdViewPrev, attachShortcuts), enterCmd(cmdViewPrev, attachShortcuts)), dom.div(style({ textAlign: 'center', paddingBottom: '30px' }), dom.span(dom._class('pad'), function click(e) {
			e.stopPropagation();
		}, style({ backgroundColor: 'white', borderRadius: '.25em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd' }), a.Filename || '(unnamed)', ' - ', formatSize(a.Part.DecodedSize), ' - ', dom.a('Download', attr.download(''), attr.href('msg/' + m.ID + '/download/' + pathStr), function click(e) { e.stopPropagation(); }))), isImage(a) ?
			dom.div(style({ flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', maxHeight: 'calc(100% - 50px)', margin: '0 5em' }), dom.img(attr.src('msg/' + m.ID + '/view/' + pathStr), style({ backgroundColor: 'white', maxWidth: '100%', maxHeight: '100%', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', margin: '0 30px' }))) : (isText(a) ?
			dom.iframe(attr.title('Attachment shown as text.'), style({ flexGrow: 1, boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', backgroundColor: 'white', margin: '0 5em' }), attr.src('msg/' + m.ID + '/viewtext/' + pathStr)) : (isPDF(a) ?
			dom.iframe(style({ flexGrow: 1, boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', backgroundColor: 'white', margin: '0 5em' }), attr.title('Attachment as PDF.'), attr.src('msg/' + m.ID + '/view/' + pathStr)) :
			content = dom.div(function click(e) {
				e.stopPropagation();
			}, style({ minWidth: '30em', padding: '2ex', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', backgroundColor: 'white', margin: '0 5em', textAlign: 'center' }), dom.div(style({ marginBottom: '2ex' }), 'Attachment could be a binary file.'), dom.clickbutton('View as text', function click() {
				content.replaceWith(dom.iframe(attr.title('Attachment shown as text, though it could be a binary file.'), style({ flexGrow: 1, boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', backgroundColor: 'white', margin: '0 5em' }), attr.src('msg/' + m.ID + '/viewtext/' + pathStr)));
			})))), !(index < attachments.length - 1) ? [] : dom.div(style({ position: 'absolute', right: '1em', top: 0, bottom: 0, fontSize: '1.5em', width: '2em', display: 'flex', alignItems: 'center', cursor: 'pointer' }), dom.div(dom._class('silenttitle'), style({ backgroundColor: 'rgba(0, 0, 0, .8)', color: 'white', width: '2em', height: '2em', borderRadius: '1em', lineHeight: '2em', textAlign: 'center', fontWeight: 'bold' }), attr.title('To next viewable attachment.'), '→'), attr.tabindex('0'), clickCmd(cmdViewNext, attachShortcuts), enterCmd(cmdViewNext, attachShortcuts)));
		document.body.appendChild(popupRoot);
		popupRoot.focus();
		attachmentView = { key: keyHandler(attachShortcuts) };
	};
	dom._kids(msgattachmentElem, (mi.Attachments && mi.Attachments.length === 0) ? [] : dom.div(style({ borderTop: '1px solid #ccc' }), dom.div(dom._class('pad'), 'Attachments: ', (mi.Attachments || []).map(a => {
		const name = a.Filename || '(unnamed)';
		const viewable = isViewable(a);
		const size = formatSize(a.Part.DecodedSize);
		const eye = '👁';
		const dl = '⤓'; // \u2913, actually ⭳ \u2b73 would be better, but in fewer fonts (at least macos)
		const dlurl = 'msg/' + m.ID + '/download/' + [0].concat(a.Path || []).join('.');
		const viewbtn = dom.clickbutton(eye, viewable ? ' ' + name : style({ padding: '0px 0.25em' }), attr.title('View this file. Size: ' + size), style({ lineHeight: '1.5' }), function click() {
			view(a);
		});
		const dlbtn = dom.a(dom._class('button'), attr.download(''), attr.href(dlurl), dl, viewable ? style({ padding: '0px 0.25em' }) : ' ' + name, attr.title('Download this file. Size: ' + size), style({ lineHeight: '1.5' }));
		if (viewable) {
			return [dom.span(dom._class('btngroup'), viewbtn, dlbtn), ' '];
		}
		return [dom.span(dom._class('btngroup'), dlbtn, viewbtn), ' '];
	}), dom.a('Download all as zip', attr.download(''), style({ color: 'inherit' }), attr.href('msg/' + m.ID + '/attachments.zip')))));
	const root = dom.div(style({ position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, display: 'flex', flexDirection: 'column' }));
	dom._kids(root, msgmetaElem, msgcontentElem);
	const loadText = (pm) => {
		// We render text ourselves so we can make links clickable and get any selected
		// text to use when writing a reply. We still set url so the text content can be
		// opened in a separate tab, even though it will look differently.
		urlType = 'text';
		const elem = dom.div(dom._class('mono'), style({ whiteSpace: 'pre-wrap' }), join((pm.Texts || []).map(t => renderText(t.replace(/\r\n/g, '\n'))), () => dom.hr(style({ margin: '2ex 0' }))));
		dom._kids(msgcontentElem);
		dom._kids(msgscrollElem, elem);
		dom._kids(msgcontentElem, msgscrollElem);
	};
	const loadHTML = () => {
		urlType = 'html';
		dom._kids(msgcontentElem, dom.iframe(attr.tabindex('0'), attr.title('HTML version of message with images inlined, without external resources loaded.'), attr.src('msg/' + m.ID + '/' + urlType), style({ border: '0', position: 'absolute', width: '100%', height: '100%', backgroundColor: 'white' })));
	};
	const loadHTMLexternal = () => {
		urlType = 'htmlexternal';
		dom._kids(msgcontentElem, dom.iframe(attr.tabindex('0'), attr.title('HTML version of message with images inlined and with external resources loaded.'), attr.src('msg/' + m.ID + '/' + urlType), style({ border: '0', position: 'absolute', width: '100%', height: '100%', backgroundColor: 'white' })));
	};
	const loadMoreHeaders = (pm) => {
		if (settings.showHeaders.length === 0) {
			return;
		}
		for (let i = 0; i < settings.showHeaders.length; i++) {
			msgheaderElem.children[msgheaderElem.children.length - 1].remove();
		}
		settings.showHeaders.forEach(k => {
			const vl = pm.Headers?.[k];
			if (!vl || vl.length === 0) {
				return;
			}
			vl.forEach(v => {
				const e = dom.tr(dom.td(k + ':', style({ textAlign: 'right', color: '#555', whiteSpace: 'nowrap' })), dom.td(v));
				msgheaderElem.appendChild(e);
			});
		});
	};
	const mv = {
		root: root,
		messageitem: mi,
		key: keyHandler(shortcuts),
		aborter: { abort: () => { } },
		updateKeywords: async (modseq, keywords) => {
			mi.Message.ModSeq = modseq;
			mi.Message.Keywords = keywords;
			loadMsgheaderView(msgheaderElem, miv.messageitem, settings.showHeaders, refineKeyword, false);
			loadMoreHeaders(await parsedMessagePromise);
		},
	};
	(async () => {
		let pm;
		if (parsedMessageOpt) {
			pm = parsedMessageOpt;
			parsedMessageResolve(pm);
		}
		else {
			const promise = withStatus('Loading message', client.withOptions({ aborter: mv.aborter }).ParsedMessage(m.ID));
			try {
				pm = await promise;
			}
			catch (err) {
				if (err instanceof Error) {
					parsedMessageReject(err);
				}
				else {
					parsedMessageReject(new Error('fetching message failed'));
				}
				throw err;
			}
			parsedMessageResolve(pm);
		}
		loadButtons(pm);
		loadHeaderDetails(pm);
		loadMoreHeaders(pm);
		const htmlNote = 'In the HTML viewer, the following potentially dangerous functionality is disabled: submitting forms, starting a download from a link, navigating away from this page by clicking a link. If a link does not work, try explicitly opening it in a new tab.';
		const haveText = pm.Texts && pm.Texts.length > 0;
		if (!haveText && !pm.HasHTML) {
			dom._kids(msgcontentElem);
			dom._kids(msgmodeElem, dom.div(dom._class('pad'), style({ borderTop: '1px solid #ccc' }), dom.span('No textual content', style({ backgroundColor: '#ffca91', padding: '0 .15em' }))));
		}
		else if (haveText && !pm.HasHTML) {
			loadText(pm);
			dom._kids(msgmodeElem);
		}
		else {
			const text = haveText && !settings.showHTML;
			dom._kids(msgmodeElem, dom.div(dom._class('pad'), style({ borderTop: '1px solid #ccc' }), !haveText ? dom.span('HTML-only message', attr.title(htmlNote), style({ backgroundColor: '#ffca91', padding: '0 .15em', marginRight: '.25em' })) : [], dom.span(dom._class('btngroup'), haveText ? textbtn = dom.clickbutton(text ? dom._class('active') : [], 'Text', clickCmd(cmdShowText, shortcuts)) : [], htmlbtn = dom.clickbutton(text ? [] : dom._class('active'), 'HTML', attr.title(htmlNote), async function click() {
				// Shortcuts has a function that cycles through html and htmlexternal.
				showShortcut('T');
				await cmdShowHTML();
			}), htmlextbtn = dom.clickbutton('HTML with external resources', attr.title(htmlNote), clickCmd(cmdShowHTMLExternal, shortcuts)))));
			if (text) {
				loadText(pm);
			}
			else {
				loadHTML();
			}
		}
		messageLoaded();
		if (!miv.messageitem.Message.Seen) {
			window.setTimeout(async () => {
				if (!miv.messageitem.Message.Seen && miv.messageitem.Message.ID === msglistView.activeMessageID()) {
					await withStatus('Marking current message as read', client.FlagsAdd([miv.messageitem.Message.ID], ['\\seen']));
				}
			}, 500);
		}
		if (!miv.messageitem.Message.Junk && !miv.messageitem.Message.Notjunk) {
			window.setTimeout(async () => {
				const mailboxIsReject = () => !!listMailboxes().find(mb => mb.ID === miv.messageitem.Message.MailboxID && mb.Name === rejectsMailbox);
				if (!miv.messageitem.Message.Junk && !miv.messageitem.Message.Notjunk && miv.messageitem.Message.ID === msglistView.activeMessageID() && !mailboxIsReject()) {
					await withStatus('Marking current message as not junk', client.FlagsAdd([miv.messageitem.Message.ID], ['$notjunk']));
				}
			}, 5 * 1000);
		}
	})();
	return mv;
};
const newMsglistView = (msgElem, listMailboxes, setLocationHash, otherMailbox, possibleLabels, scrollElemHeight, refineKeyword, viewportEnsureMessages) => {
	// msgitemViews holds all visible item views: All thread roots, and kids only if
	// the thread is expanded, in order of descendants. All descendants of a collapsed
	// root are in collapsedMsgitemViews, unsorted. Having msgitemViews as a list is
	// convenient for reasoning about the visible items, and handling changes to the
	// selected messages.
	// When messages for a thread are all non-matching the query, we no longer show it
	// (e.g. when moving a thread to Archive), but we keep the messages around in
	// oldThreadMessageItems, so an update to the thread (e.g. new delivery) can
	// resurrect the messages.
	let msgitemViews = []; // Only visible msgitems, in order on screen.
	let collapsedMsgitemViews = []; // Invisible messages because collapsed, unsorted.
	let oldThreadMessageItems = []; // Messages from threads removed from view.
	// selected holds the messages that are selected, zero or more. If there is a
	// single message, its content is shown. If there are multiple, just the count is
	// shown. These are in order of being added, not in order of how they are shown in
	// the list. This is needed to handle selection changes with the shift key. For
	// collapsed thread roots, only that root will be in this list. The effective
	// selection must always expand descendants, use mlv.selected() to gather all.
	let selected = [];
	// Focus is the message last interacted with, or the first when messages are
	// loaded. Always set when there is a message. Used for shift+click to expand
	// selection.
	let focus = null;
	let msgView = null;
	// Messages for actions like "archive", "trash", "move to...". We skip messages
	// that are (already) in skipMBID. And we skip messages that are in the designated
	// Sent mailbox, unless there is only one selected message or the view is for the
	// Sent mailbox, then it must be intentional.
	const moveActionMsgIDs = (skipMBID) => {
		const sentMailboxID = listMailboxes().find(mb => mb.Sent)?.ID;
		const effselected = mlv.selected();
		return effselected
			.filter(miv => miv.messageitem.Message.MailboxID !== skipMBID)
			.map(miv => miv.messageitem.Message)
			.filter(m => effselected.length === 1 || !sentMailboxID || m.MailboxID !== sentMailboxID || !otherMailbox(sentMailboxID))
			.map(m => m.ID);
	};
	const cmdArchive = async () => {
		const mb = listMailboxes().find(mb => mb.Archive);
		if (mb) {
			await withStatus('Moving to archive mailbox', client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID));
		}
		else {
			window.alert('No mailbox configured for archiving yet.');
		}
	};
	const cmdDelete = async () => {
		if (!window.confirm('Are you sure you want to permanently delete?')) {
			return;
		}
		await withStatus('Permanently deleting messages', client.MessageDelete(mlv.selected().map(miv => miv.messageitem.Message.ID)));
	};
	const cmdTrash = async () => {
		const mb = listMailboxes().find(mb => mb.Trash);
		if (mb) {
			await withStatus('Moving to trash mailbox', client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID));
		}
		else {
			window.alert('No mailbox configured for trash yet.');
		}
	};
	const cmdJunk = async () => {
		const mb = listMailboxes().find(mb => mb.Junk);
		if (mb) {
			await withStatus('Moving to junk mailbox', client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID));
		}
		else {
			window.alert('No mailbox configured for junk yet.');
		}
	};
	const cmdMarkNotJunk = async () => { await withStatus('Marking as not junk', client.FlagsAdd(mlv.selected().map(miv => miv.messageitem.Message.ID), ['$notjunk'])); };
	const cmdMarkRead = async () => { await withStatus('Marking as read', client.FlagsAdd(mlv.selected().map(miv => miv.messageitem.Message.ID), ['\\seen'])); };
	const cmdMarkUnread = async () => { await withStatus('Marking as not read', client.FlagsClear(mlv.selected().map(miv => miv.messageitem.Message.ID), ['\\seen'])); };
	const cmdMute = async () => {
		const l = mlv.selected();
		await withStatus('Muting thread', client.ThreadMute(l.map(miv => miv.messageitem.Message.ID), true));
		const oldstate = state();
		for (const miv of l) {
			if (!miv.parent && miv.kids.length > 0 && !miv.collapsed) {
				threadCollapse(miv, false);
			}
		}
		updateState(oldstate);
		viewportEnsureMessages();
	};
	const cmdUnmute = async () => { await withStatus('Unmuting thread', client.ThreadMute(mlv.selected().map(miv => miv.messageitem.Message.ID), false)); };
	const seletedRoots = () => {
		const mivs = [];
		mlv.selected().forEach(miv => {
			const mivroot = miv.threadRoot();
			if (!mivs.includes(mivroot)) {
				mivs.push(mivroot);
			}
		});
		return mivs;
	};
	const cmdToggleMute = async () => {
		if (settings.threading === api.ThreadMode.ThreadOff) {
			alert('Toggle muting threads is only available when threading is enabled.');
			return;
		}
		const rootmivs = seletedRoots();
		const unmuted = !!rootmivs.find(miv => !miv.messageitem.Message.ThreadMuted);
		await withStatus(unmuted ? 'Muting' : 'Unmuting', client.ThreadMute(rootmivs.map(miv => miv.messageitem.Message.ID), unmuted ? true : false));
		if (unmuted) {
			const oldstate = state();
			rootmivs.forEach(miv => {
				if (!miv.collapsed) {
					threadCollapse(miv, false);
				}
			});
			updateState(oldstate);
			viewportEnsureMessages();
		}
	};
	const cmdToggleCollapse = async () => {
		if (settings.threading === api.ThreadMode.ThreadOff) {
			alert('Toggling thread collapse/expand is only available when threading is enabled.');
			return;
		}
		const rootmivs = seletedRoots();
		const collapse = !!rootmivs.find(miv => !miv.collapsed);
		const oldstate = state();
		if (collapse) {
			rootmivs.forEach(miv => {
				if (!miv.collapsed) {
					threadCollapse(miv, false);
				}
			});
			selected = rootmivs;
			if (focus) {
				focus = focus.threadRoot();
			}
			viewportEnsureMessages();
		}
		else {
			rootmivs.forEach(miv => {
				if (miv.collapsed) {
					threadExpand(miv, false);
				}
			});
		}
		updateState(oldstate);
		if (settings.threading === api.ThreadMode.ThreadOn) {
			const action = collapse ? 'Collapsing' : 'Expanding';
			await withStatus(action, client.ThreadCollapse(rootmivs.map(miv => miv.messageitem.Message.ID), collapse));
		}
	};
	const cmdSelectThread = async () => {
		if (!focus) {
			return;
		}
		const oldstate = state();
		selected = msgitemViews.filter(miv => miv.messageitem.Message.ThreadID === focus.messageitem.Message.ThreadID);
		updateState(oldstate);
	};
	const cmdCollapseExpand = async (collapse) => {
		if (settings.threading === api.ThreadMode.ThreadOff) {
			alert('Toggling thread collapse/expand is only available when threading is enabled.');
			return;
		}
		const oldstate = state();
		const rootmivs = seletedRoots();
		rootmivs.forEach(miv => {
			if (miv.collapsed !== collapse) {
				if (collapse) {
					threadCollapse(miv, false);
				}
				else {
					threadExpand(miv, false);
				}
			}
		});
		if (collapse) {
			selected = rootmivs;
			if (focus) {
				focus = focus.threadRoot();
			}
		}
		viewportEnsureMessages();
		updateState(oldstate);
		if (settings.threading === api.ThreadMode.ThreadOn) {
			const action = collapse ? 'Collapsing' : 'Expanding';
			await withStatus(action, client.ThreadCollapse(rootmivs.map(miv => miv.messageitem.Message.ID), collapse));
		}
	};
	const cmdCollapse = async () => cmdCollapseExpand(true);
	const cmdExpand = async () => cmdCollapseExpand(false);
	const shortcuts = {
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
	};
	// After making changes, this function looks through the data structure for
	// inconsistencies. Useful during development.
	const checkConsistency = (checkSelection) => {
		if (!settings.checkConsistency) {
			return;
		}
		// Check for duplicates in msgitemViews.
		const mivseen = new Set();
		const threadActive = new Set();
		for (const miv of msgitemViews) {
			const id = miv.messageitem.Message.ID;
			if (mivseen.has(id)) {
				log('duplicate Message.ID', { id: id, mivseenSize: mivseen.size });
				throw new ConsistencyError('duplicate Message.ID in msgitemViews');
			}
			mivseen.add(id);
			if (!miv.root.parentNode) {
				throw new ConsistencyError('msgitemView.root not in dom');
			}
			threadActive.add(miv.messageitem.Message.ThreadID);
		}
		// Check for duplicates in collapsedMsgitemViews, and whether also in msgitemViews.
		const colseen = new Set();
		for (const miv of collapsedMsgitemViews) {
			const id = miv.messageitem.Message.ID;
			if (colseen.has(id)) {
				throw new ConsistencyError('duplicate Message.ID in collapsedMsgitemViews');
			}
			colseen.add(id);
			if (mivseen.has(id)) {
				throw new ConsistencyError('Message.ID in both collapsedMsgitemViews and msgitemViews');
			}
			threadActive.add(miv.messageitem.Message.ThreadID);
		}
		if (settings.threading !== api.ThreadMode.ThreadOff) {
			const oldseen = new Set();
			for (const mi of oldThreadMessageItems) {
				const id = mi.Message.ID;
				if (oldseen.has(id)) {
					throw new ConsistencyError('duplicate Message.ID in oldThreadMessageItems');
				}
				oldseen.add(id);
				if (mivseen.has(id)) {
					throw new ConsistencyError('Message.ID in both msgitemViews and oldThreadMessageItems');
				}
				if (colseen.has(id)) {
					throw new ConsistencyError('Message.ID in both collapsedMsgitemViews and oldThreadMessageItems');
				}
				if (threadActive.has(mi.Message.ThreadID)) {
					throw new ConsistencyError('threadid both in active and in old thread list');
				}
			}
		}
		// Walk all (collapsed) msgitemViews, check each and their descendants are in
		// msgitemViews at the correct position, or in collapsedmsgitemViews.
		msgitemViews.forEach((miv, i) => {
			if (miv.collapsed) {
				for (const dmiv of miv.descendants()) {
					if (!colseen.has(dmiv.messageitem.Message.ID)) {
						throw new ConsistencyError('descendant message id missing from collapsedMsgitemViews');
					}
				}
				return;
			}
			for (const dmiv of miv.descendants()) {
				i++;
				if (!mivseen.has(dmiv.messageitem.Message.ID)) {
					throw new ConsistencyError('descendant missing from msgitemViews');
				}
				if (msgitemViews[i] !== dmiv) {
					throw new ConsistencyError('descendant not at expected position in msgitemViews');
				}
			}
		});
		if (!checkSelection) {
			return;
		}
		// Check all selected & focus exists.
		const selseen = new Set();
		for (const miv of selected) {
			const id = miv.messageitem.Message.ID;
			if (selseen.has(id)) {
				throw new ConsistencyError('duplicate miv in selected');
			}
			selseen.add(id);
			if (!mivseen.has(id)) {
				throw new ConsistencyError('selected id not in msgitemViews');
			}
		}
		if (focus) {
			const id = focus.messageitem.Message.ID;
			if (!mivseen.has(id)) {
				throw new ConsistencyError('focus set to unknown miv');
			}
		}
	};
	// Return active & focus state, and update the UI after changing state.
	const state = () => {
		const active = {};
		for (const miv of mlv.selected()) {
			active[miv.messageitem.Message.ID] = miv;
		}
		return { active: active, focus: focus };
	};
	const updateState = async (oldstate, initial, parsedMessageOpt) => {
		// Set new focus & active classes.
		const newstate = state();
		if (oldstate.focus !== newstate.focus) {
			if (oldstate.focus) {
				oldstate.focus.root.classList.toggle('focus', false);
			}
			if (newstate.focus) {
				newstate.focus.root.classList.toggle('focus', true);
				newstate.focus.root.scrollIntoView({ block: initial ? 'center' : 'nearest' });
			}
		}
		let activeChanged = false;
		for (const id in oldstate.active) {
			if (!newstate.active[id]) {
				oldstate.active[id].root.classList.toggle('active', false);
				activeChanged = true;
			}
		}
		for (const id in newstate.active) {
			if (!oldstate.active[id]) {
				newstate.active[id].root.classList.toggle('active', true);
				activeChanged = true;
			}
		}
		const effselected = mlv.selected();
		if (initial && effselected.length === 1) {
			mlv.redraw(effselected[0]);
		}
		checkConsistency(true);
		if (!activeChanged) {
			return;
		}
		if (msgView) {
			msgView.aborter.abort();
		}
		msgView = null;
		if (effselected.length === 0) {
			dom._kids(msgElem);
		}
		else if (effselected.length === 1) {
			msgElem.classList.toggle('loading', true);
			const loaded = () => { msgElem.classList.toggle('loading', false); };
			msgView = newMsgView(effselected[0], mlv, listMailboxes, possibleLabels, loaded, refineKeyword, parsedMessageOpt);
			dom._kids(msgElem, msgView);
		}
		else {
			const trashMailboxID = listMailboxes().find(mb => mb.Trash)?.ID;
			const allTrash = trashMailboxID && !effselected.find(miv => miv.messageitem.Message.MailboxID !== trashMailboxID);
			dom._kids(msgElem, dom.div(attr.role('region'), attr.arialabel('Buttons for multiple messages'), style({ position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }), dom.div(style({ padding: '4ex', backgroundColor: 'white', borderRadius: '.25em', border: '1px solid #ccc' }), dom.div(style({ textAlign: 'center', marginBottom: '4ex' }), '' + effselected.length + ' messages selected'), dom.div(dom.clickbutton('Archive', attr.title('Move to the Archive mailbox. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox.'), clickCmd(cmdArchive, shortcuts)), ' ', allTrash ?
				dom.clickbutton('Delete', attr.title('Permanently delete messages.'), clickCmd(cmdDelete, shortcuts)) :
				dom.clickbutton('Trash', attr.title('Move to the Trash mailbox. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox.'), clickCmd(cmdTrash, shortcuts)), ' ', dom.clickbutton('Junk', attr.title('Move to Junk mailbox, marking as junk and causing this message to be used in spam classification of new incoming messages. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox.'), clickCmd(cmdJunk, shortcuts)), ' ', dom.clickbutton('Move to...', function click(e) {
				const sentMailboxID = listMailboxes().find(mb => mb.Sent)?.ID;
				movePopover(e, listMailboxes(), effselected.map(miv => miv.messageitem.Message).filter(m => effselected.length === 1 || !sentMailboxID || m.MailboxID !== sentMailboxID || !otherMailbox(sentMailboxID)));
			}), ' ', dom.clickbutton('Labels...', attr.title('Add/remove labels ...'), function click(e) {
				labelsPopover(e, effselected.map(miv => miv.messageitem.Message), possibleLabels);
			}), ' ', dom.clickbutton('Mark Not Junk', attr.title('Mark as not junk, causing this message to be used in spam classification of new incoming messages.'), clickCmd(cmdMarkNotJunk, shortcuts)), ' ', dom.clickbutton('Mark Read', clickCmd(cmdMarkRead, shortcuts)), ' ', dom.clickbutton('Mark Unread', clickCmd(cmdMarkUnread, shortcuts)), ' ', dom.clickbutton('Mute thread', clickCmd(cmdMute, shortcuts)), ' ', dom.clickbutton('Unmute thread', clickCmd(cmdUnmute, shortcuts))))));
		}
		setLocationHash();
	};
	// Moves the currently focused msgitemView, without changing selection.
	const moveFocus = (miv) => {
		const oldstate = state();
		focus = miv;
		updateState(oldstate);
	};
	const threadExpand = (miv, changeState) => {
		if (miv.parent) {
			throw new ConsistencyError('cannot expand non-root');
		}
		const oldstate = state();
		miv.collapsed = false;
		const mivl = miv.descendants();
		miv.render();
		mivl.forEach(dmiv => dmiv.render());
		for (const miv of mivl) {
			collapsedMsgitemViews.splice(collapsedMsgitemViews.indexOf(miv), 1);
		}
		const pi = msgitemViews.indexOf(miv);
		msgitemViews.splice(pi + 1, 0, ...mivl);
		const next = miv.root.nextSibling;
		for (const miv of mivl) {
			mlv.root.insertBefore(miv.root, next);
		}
		if (changeState) {
			updateState(oldstate);
		}
	};
	const threadCollapse = (miv, changeState) => {
		if (miv.parent) {
			throw new ConsistencyError('cannot expand non-root');
		}
		const oldstate = state();
		miv.collapsed = true;
		const mivl = miv.descendants();
		collapsedMsgitemViews.push(...mivl);
		// If miv or any child was selected, ensure collapsed thread root is also selected.
		let select = [miv, ...mivl].find(xmiv => selected.indexOf(xmiv) >= 0);
		let seli = selected.length; // Track first index of already selected miv, which is where we insert the thread root if needed, to keep order.
		msgitemViews.splice(msgitemViews.indexOf(miv) + 1, mivl.length);
		for (const dmiv of mivl) {
			dmiv.remove();
			if (focus === dmiv) {
				focus = miv;
			}
			const si = selected.indexOf(dmiv);
			if (si >= 0) {
				if (si < seli) {
					seli = si;
				}
				selected.splice(si, 1);
			}
		}
		if (select) {
			const si = selected.indexOf(miv);
			if (si < 0) {
				selected.splice(seli, 0, miv);
			}
		}
		// Selected messages may have changed.
		if (changeState) {
			updateState(oldstate);
		}
		// Render remaining thread root, with tree size, effective received age/unread state.
		miv.render();
	};
	const threadToggle = () => {
		const oldstate = state();
		const roots = msgitemViews.filter(miv => !miv.parent && miv.kids.length > 0);
		roots.forEach(miv => {
			let wantCollapsed = miv.messageitem.Message.ThreadCollapsed;
			if (settings.threading === api.ThreadMode.ThreadUnread) {
				wantCollapsed = !miv.messageitem.Message.Seen && !miv.findDescendant(miv => !miv.messageitem.Message.Seen);
			}
			if (miv.collapsed === wantCollapsed) {
				return;
			}
			if (wantCollapsed) {
				threadCollapse(miv, false);
			}
			else {
				threadExpand(miv, false);
			}
		});
		updateState(oldstate);
		viewportEnsureMessages();
	};
	const removeSelected = (miv) => {
		const si = selected.indexOf(miv);
		if (si >= 0) {
			selected.splice(si, 1);
		}
		if (focus === miv) {
			const i = msgitemViews.indexOf(miv);
			if (i > 0) {
				focus = msgitemViews[i - 1];
			}
			else if (i + 1 < msgitemViews.length) {
				focus = msgitemViews[i + 1];
			}
			else {
				focus = null;
			}
		}
	};
	// Removes message from either msgitemViews, collapsedMsgitemViews,
	// oldThreadMessageItems, and updates UI.
	// Returns ThreadID of removed message if active (expanded or collapsed), or 0 otherwise.
	const removeUID = (mailboxID, uid) => {
		const match = (miv) => miv.messageitem.Message.MailboxID === mailboxID && miv.messageitem.Message.UID === uid;
		const ci = collapsedMsgitemViews.findIndex(match);
		if (ci >= 0) {
			const miv = collapsedMsgitemViews[ci];
			removeCollapsed(ci);
			return miv.messageitem.Message.ThreadID;
		}
		const i = msgitemViews.findIndex(match);
		if (i >= 0) {
			const miv = msgitemViews[i];
			removeExpanded(i);
			return miv.messageitem.Message.ThreadID;
		}
		const ti = oldThreadMessageItems.findIndex(mi => mi.Message.MailboxID === mailboxID && mi.Message.UID === uid);
		if (ti >= 0) {
			oldThreadMessageItems.splice(ti, 1);
		}
		return 0;
	};
	// Removes message from collapsedMsgitemView and UI at given index, placing
	// messages in oldThreadMessageItems.
	const removeCollapsed = (ci) => {
		// Message is collapsed. That means it isn't visible, and neither are its children,
		// and it has a parent. So we just merge the kids with those of the parent.
		const miv = collapsedMsgitemViews[ci];
		collapsedMsgitemViews.splice(ci, 1);
		removeSelected(miv);
		const trmiv = miv.threadRoot(); // To rerender, below.
		const pmiv = miv.parent;
		if (!pmiv) {
			throw new ConsistencyError('removing collapsed miv, but has no parent');
		}
		miv.parent = null; // Strict cleanup.
		const pki = pmiv.kids.indexOf(miv);
		if (pki < 0) {
			throw new ConsistencyError('miv not in parent.kids');
		}
		pmiv.kids.splice(pki, 1, ...miv.kids); // In parent, replace miv with its kids.
		miv.kids.forEach(kmiv => kmiv.parent = pmiv); // Give kids their new parent.
		miv.kids = []; // Strict cleanup.
		pmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime()); // Sort new list of kids.
		trmiv.render(); // For count, unread state.
		return;
	};
	// Remove message from msgitemViews and UI at the index i.
	const removeExpanded = (i) => {
		log('removeExpanded', { i });
		// Note: If we remove a message we may be left with only messages from another
		// mailbox. We'll leave it, new messages could be delivered for that thread. It
		// would be strange to see the remaining messages of the thread disappear.
		const miv = msgitemViews[i];
		removeSelected(miv);
		const pmiv = miv.parent;
		miv.parent = null;
		if (miv.kids.length === 0) {
			// No kids, easy case, just remove this leaf message.
			miv.remove();
			msgitemViews.splice(i, 1);
			if (pmiv) {
				const pki = pmiv.kids.indexOf(miv);
				if (pki < 0) {
					throw new ConsistencyError('miv not in parent.kids');
				}
				pmiv.kids.splice(pki, 1); // Remove miv from parent's kids.
				miv.parent = null; // Strict cleanup.
				pmiv.render(); // Update counts.
			}
			return;
		}
		if (!pmiv) {
			// If the kids no longer have a parent and become thread roots we leave them in
			// their original location.
			const next = miv.root.nextSibling;
			miv.remove();
			msgitemViews.splice(i, 1);
			if (miv.collapsed) {
				msgitemViews.splice(i, 0, ...miv.kids);
				for (const kmiv of miv.kids) {
					const pki = collapsedMsgitemViews.indexOf(kmiv);
					if (pki < 0) {
						throw new ConsistencyError('cannot find collapsed kid in collapsedMsgitemViews');
					}
					collapsedMsgitemViews.splice(pki, 1);
					kmiv.collapsed = true;
					kmiv.parent = null;
					kmiv.render();
					mlv.root.insertBefore(kmiv.root, next);
				}
			}
			else {
				// Note: if not collapsed, we leave the kids in the original position in msgitemViews.
				miv.kids.forEach(kmiv => {
					kmiv.collapsed = false;
					kmiv.parent = null;
					kmiv.render();
					const lastDesc = kmiv.lastDescendant();
					if (lastDesc) {
						// Update end of thread bar.
						lastDesc.render();
					}
				});
			}
			miv.kids = []; // Strict cleanup.
			return;
		}
		// If the kids will have a parent, we insert them at the expected location in
		// between parent's existing kids. It is easiest just to take out all kids, add the
		// new ones, sort kids, and add back the subtree.
		const odmivs = pmiv.descendants(); // Old direct descendants of parent. This includes miv and kids, and other kids, and miv siblings.
		const pi = msgitemViews.indexOf(pmiv);
		if (pi < 0) {
			throw new ConsistencyError('cannot find parent of removed miv');
		}
		msgitemViews.splice(pi + 1, odmivs.length); // Remove all old descendants, we'll add an updated list later.
		const pki = pmiv.kids.indexOf(miv);
		if (pki < 0) {
			throw new Error('did not find miv in parent.kids');
		}
		pmiv.kids.splice(pki, 1); // Remove miv from parent's kids.
		pmiv.kids.push(...miv.kids); // Add miv.kids to parent's kids.
		miv.kids.forEach(kmiv => { kmiv.parent = pmiv; }); // Set new parent for miv kids.
		miv.kids = []; // Strict cleanup.
		pmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
		const ndmivs = pmiv.descendants(); // Excludes miv, that we are removing.
		if (ndmivs.length !== odmivs.length - 1) {
			throw new ConsistencyError('unexpected new descendants counts during remove');
		}
		msgitemViews.splice(pi + 1, 0, ...ndmivs); // Add all new/current descedants. There is one less than in odmivs.
		odmivs.forEach(ndimv => ndimv.remove());
		const next = pmiv.root.nextSibling;
		for (const ndmiv of ndmivs) {
			mlv.root.insertBefore(ndmiv.root, next);
		}
		pmiv.render();
		ndmivs.forEach(dmiv => dmiv.render());
	};
	// If there are no query-matching messages left for this thread, remove the
	// remaining messages from view and keep them around for future deliveries for the
	// thread.
	const possiblyTakeoutOldThreads = (threadIDs) => {
		const hasMatch = (mivs, threadID) => mivs.find(miv => miv.messageitem.Message.ThreadID === threadID && miv.messageitem.MatchQuery);
		const takeoutOldThread = (mivs, threadID, visible) => {
			let i = 0;
			while (i < mivs.length) {
				const miv = mivs[i];
				const mi = miv.messageitem;
				const m = mi.Message;
				if (threadID !== m.ThreadID) {
					i++;
					continue;
				}
				mivs.splice(i, 1);
				if (visible) {
					miv.remove();
				}
				if (focus === miv) {
					focus = null;
					if (i < mivs.length) {
						focus = mivs[i];
					}
					else if (i > 0) {
						focus = mivs[i - 1];
					}
				}
				const si = selected.indexOf(miv);
				if (si >= 0) {
					selected.splice(si, 1);
				}
				// Strict cleanup.
				miv.parent = null;
				miv.kids = [];
				oldThreadMessageItems.push(mi);
				log('took out old thread message', { mi });
			}
		};
		for (const threadID of threadIDs) {
			if (hasMatch(msgitemViews, threadID) || hasMatch(collapsedMsgitemViews, threadID)) {
				log('still have query-matching message for thread', { threadID });
				continue;
			}
			takeoutOldThread(msgitemViews, threadID, true);
			takeoutOldThread(collapsedMsgitemViews, threadID, false);
		}
	};
	const mlv = {
		root: dom.div(),
		updateFlags: (mailboxID, uid, modseq, mask, flags, keywords) => {
			const updateMessageFlags = (m) => {
				m.ModSeq = modseq;
				const maskobj = mask;
				const flagsobj = flags;
				const mobj = m;
				for (const k in maskobj) {
					if (maskobj[k]) {
						mobj[k] = flagsobj[k];
					}
				}
				m.Keywords = keywords;
			};
			// todo optimize: keep mapping of uid to msgitemView for performance. instead of using Array.find
			let miv = msgitemViews.find(miv => miv.messageitem.Message.MailboxID === mailboxID && miv.messageitem.Message.UID === uid);
			if (!miv) {
				miv = collapsedMsgitemViews.find(miv => miv.messageitem.Message.MailboxID === mailboxID && miv.messageitem.Message.UID === uid);
			}
			if (miv) {
				updateMessageFlags(miv.messageitem.Message);
				miv.render();
				if (miv.parent) {
					const tr = miv.threadRoot();
					if (tr.collapsed) {
						tr.render();
					}
				}
				if (msgView && msgView.messageitem.Message.ID === miv.messageitem.Message.ID) {
					msgView.updateKeywords(modseq, keywords);
				}
				return;
			}
			const mi = oldThreadMessageItems.find(mi => mi.Message.MailboxID === mailboxID && mi.Message.UID === uid);
			if (mi) {
				updateMessageFlags(mi.Message);
			}
			else {
				// Happens for messages outside of view.
				log('could not find msgitemView for uid', uid);
			}
		},
		// Add messages to view, either messages to fill the view with complete threads, or
		// individual messages delivered later.
		addMessageItems: (messageItems, isChange, requestMsgID) => {
			if (messageItems.length === 0) {
				return;
			}
			// Each "mil" is a thread, possibly with multiple thread roots. The thread may
			// already be present.
			messageItems.forEach(mil => {
				if (!mil) {
					return; // For types, should not happen.
				}
				const threadID = mil[0].Message.ThreadID;
				const hasMatch = !!mil.find(mi => mi.MatchQuery);
				if (hasMatch) {
					// This may be a message for a thread that had query-matching matches at some
					// point, but then no longer, causing its messages to have been moved to
					// oldThreadMessageItems. We add back those messages.
					let i = 0;
					while (i < oldThreadMessageItems.length) {
						const omi = oldThreadMessageItems[i];
						if (omi.Message.ThreadID === threadID) {
							oldThreadMessageItems.splice(i, 1);
							if (!mil.find(mi => mi.Message.ID === omi.Message.ID)) {
								mil.push(omi);
								log('resurrected old message');
							}
							else {
								log('dropped old thread message');
							}
						}
						else {
							i++;
						}
					}
				}
				else {
					// New message(s) are not matching query. If there are no "active" messages for
					// this thread, update/add oldThreadMessageItems.
					const match = (miv) => miv.messageitem.Message.ThreadID === threadID;
					if (!msgitemViews.find(match) && !collapsedMsgitemViews.find(match)) {
						log('adding new message(s) to oldTheadMessageItems');
						for (const mi of mil) {
							const ti = oldThreadMessageItems.findIndex(tmi => tmi.Message.ID === mi.Message.ID);
							if (ti) {
								oldThreadMessageItems[ti] = mi;
							}
							else {
								oldThreadMessageItems.push(mi);
							}
						}
						return;
					}
				}
				if (isChange) {
					// This could be an "add" for a message from another mailbox that we are already
					// displaying because of threads. If so, it may have new properties such as the
					// mailbox, so update it.
					const threadIDs = new Set();
					let i = 0;
					while (i < mil.length) {
						const mi = mil[i];
						let miv = msgitemViews.find(miv => miv.messageitem.Message.ID === mi.Message.ID);
						if (!miv) {
							miv = collapsedMsgitemViews.find(miv => miv.messageitem.Message.ID === mi.Message.ID);
						}
						if (miv) {
							miv.messageitem = mi;
							miv.render();
							mil.splice(i, 1);
							miv.threadRoot().render();
							threadIDs.add(mi.Message.ThreadID);
						}
						else {
							i++;
						}
					}
					log('processed changes for messages with thread', { threadIDs, mil });
					if (mil.length === 0) {
						const oldstate = state();
						possiblyTakeoutOldThreads(threadIDs);
						updateState(oldstate);
						return;
					}
				}
				// Find effective receive time for messages. We'll insert at that point.
				let receivedTime = mil[0].Message.Received.getTime();
				const tmiv = msgitemViews.find(miv => miv.messageitem.Message.ThreadID === mil[0].Message.ThreadID);
				if (tmiv) {
					receivedTime = tmiv.receivedTime;
				}
				else {
					for (const mi of mil) {
						const t = mi.Message.Received.getTime();
						if (settings.orderAsc && t < receivedTime || !settings.orderAsc && t > receivedTime) {
							receivedTime = t;
						}
					}
				}
				// Create new MsgitemViews.
				const m = new Map();
				for (const mi of mil) {
					m.set(mi.Message.ID, newMsgitemView(mi, mlv, otherMailbox, listMailboxes, receivedTime, false));
				}
				// Assign miv's to parents or add them to the potential roots.
				let roots = [];
				if (settings.threading === api.ThreadMode.ThreadOff) {
					roots = [...m.values()];
				}
				else {
					nextmiv: for (const [_, miv] of m) {
						for (const pid of (miv.messageitem.Message.ThreadParentIDs || [])) {
							const pmiv = m.get(pid);
							if (pmiv) {
								pmiv.kids.push(miv);
								miv.parent = pmiv;
								continue nextmiv;
							}
						}
						roots.push(miv);
					}
				}
				// Ensure all kids are properly sorted, always ascending by time received.
				for (const [_, miv] of m) {
					miv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
				}
				// Add the potential roots as kids to existing parents, if they exist. Only with threading enabled.
				if (settings.threading !== api.ThreadMode.ThreadOff) {
					nextroot: for (let i = 0; i < roots.length;) {
						const miv = roots[i];
						for (const pid of (miv.messageitem.Message.ThreadParentIDs || [])) {
							const pi = msgitemViews.findIndex(xmiv => xmiv.messageitem.Message.ID === pid);
							let parentmiv;
							let collapsed;
							if (pi >= 0) {
								parentmiv = msgitemViews[pi];
								collapsed = parentmiv.collapsed;
								log('found parent', { pi });
							}
							else {
								parentmiv = collapsedMsgitemViews.find(xmiv => xmiv.messageitem.Message.ID === pid);
								collapsed = true;
							}
							if (!parentmiv) {
								log('no parentmiv', pid);
								continue;
							}
							const trmiv = parentmiv.threadRoot();
							if (collapsed !== trmiv.collapsed) {
								log('collapsed mismatch', { collapsed: collapsed, 'trmiv.collapsed': trmiv.collapsed, trmiv: trmiv });
								throw new ConsistencyError('mismatch between msgitemViews/collapsedMsgitemViews and threadroot collapsed');
							}
							let prevLastDesc = null;
							if (!trmiv.collapsed) {
								// Remove current parent, we'll insert again after linking parent/kids.
								const ndesc = parentmiv.descendants().length;
								log('removing descendants temporarily', { ndesc });
								prevLastDesc = parentmiv.lastDescendant();
								msgitemViews.splice(pi + 1, ndesc);
							}
							// Link parent & kid, sort kids.
							miv.parent = parentmiv;
							parentmiv.kids.push(miv);
							parentmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
							if (trmiv.collapsed) {
								// Thread root is collapsed.
								collapsedMsgitemViews.push(miv, ...miv.descendants());
								// Ensure mivs have a root.
								miv.render();
								miv.descendants().forEach(miv => miv.render());
								// Update count/unread status.
								trmiv.render();
							}
							else {
								const desc = parentmiv.descendants();
								log('inserting parent descendants again', { pi, desc });
								msgitemViews.splice(pi + 1, 0, ...desc); // We had removed the old tree, now adding the updated tree.
								// Insert at correct position in dom.
								const i = msgitemViews.indexOf(miv);
								if (i < 0) {
									throw new ConsistencyError('cannot find miv just inserted');
								}
								const l = [miv, ...miv.descendants()];
								// Ensure mivs have valid root.
								l.forEach(miv => miv.render());
								const next = i + 1 < msgitemViews.length ? msgitemViews[i + 1].root : null;
								log('inserting l before next, or appending', { next, l });
								if (next) {
									for (const miv of l) {
										log('inserting miv', { root: miv.root, before: next });
										mlv.root.insertBefore(miv.root, next);
									}
								}
								else {
									mlv.root.append(...l.map(e => e.root));
								}
								// For beginning/end of thread bar.
								msgitemViews[i - 1].render();
								if (prevLastDesc) {
									prevLastDesc.render();
								}
							}
							roots.splice(i, 1);
							continue nextroot;
						}
						i++;
					}
				}
				// Sort the remaining new roots by their receive times.
				const sign = settings.threading === api.ThreadMode.ThreadOff && settings.orderAsc ? -1 : 1;
				roots.sort((miva, mivb) => sign * (mivb.messageitem.Message.Received.getTime() - miva.messageitem.Message.Received.getTime()));
				// Find place to insert, based on thread receive time.
				let nextmivindex;
				if (tmiv) {
					nextmivindex = msgitemViews.indexOf(tmiv.threadRoot());
				}
				else {
					nextmivindex = msgitemViews.findIndex(miv => !settings.orderAsc && miv.receivedTime <= receivedTime || settings.orderAsc && receivedTime <= miv.receivedTime);
				}
				for (const miv of roots) {
					miv.collapsed = settings.threading === api.ThreadMode.ThreadOn && miv.messageitem.Message.ThreadCollapsed;
					if (settings.threading === api.ThreadMode.ThreadUnread) {
						miv.collapsed = miv.messageitem.Message.Seen && !miv.findDescendant(dmiv => !dmiv.messageitem.Message.Seen);
					}
					if (requestMsgID > 0 && miv.collapsed) {
						miv.collapsed = !miv.findDescendant(dmiv => dmiv.messageitem.Message.ID === requestMsgID);
					}
					const takeThreadRoot = (xmiv) => {
						log('taking threadRoot', { id: xmiv.messageitem.Message.ID });
						// Remove subtree from dom.
						const xdmiv = xmiv.descendants();
						xdmiv.forEach(xdmiv => xdmiv.remove());
						xmiv.remove();
						// Link to new parent.
						miv.kids.push(xmiv);
						xmiv.parent = miv;
						miv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
						return 1 + xdmiv.length;
					};
					if (settings.threading !== api.ThreadMode.ThreadOff) {
						// We may have to take out existing threadroots and place them under this new root.
						// Because when we move a threadroot, we first remove it, then add it again.
						for (let i = 0; i < msgitemViews.length;) {
							const xmiv = msgitemViews[i];
							if (!xmiv.parent && xmiv.messageitem.Message.ThreadID === miv.messageitem.Message.ThreadID && (xmiv.messageitem.Message.ThreadParentIDs || []).includes(miv.messageitem.Message.ID)) {
								msgitemViews.splice(i, takeThreadRoot(xmiv));
								nextmivindex = i;
							}
							else {
								i++;
							}
						}
						for (let i = 0; i < collapsedMsgitemViews.length;) {
							const xmiv = collapsedMsgitemViews[i];
							if (!xmiv.parent && xmiv.messageitem.Message.ThreadID === miv.messageitem.Message.ThreadID && (xmiv.messageitem.Message.ThreadParentIDs || []).includes(miv.messageitem.Message.ID)) {
								takeThreadRoot(xmiv);
								collapsedMsgitemViews.splice(i, 1);
							}
							else {
								i++;
							}
						}
					}
					let l = miv.descendants();
					miv.render();
					l.forEach(kmiv => kmiv.render());
					if (miv.collapsed) {
						collapsedMsgitemViews.push(...l);
						l = [miv];
					}
					else {
						l = [miv, ...l];
					}
					if (nextmivindex < 0) {
						mlv.root.append(...l.map(miv => miv.root));
						msgitemViews.push(...l);
					}
					else {
						const next = msgitemViews[nextmivindex].root;
						for (const miv of l) {
							mlv.root.insertBefore(miv.root, next);
						}
						msgitemViews.splice(nextmivindex, 0, ...l);
					}
				}
			});
			if (!isChange) {
				return;
			}
			const oldstate = state();
			if (!focus) {
				focus = msgitemViews[0];
			}
			if (selected.length === 0) {
				if (focus) {
					selected = [focus];
				}
				else if (msgitemViews.length > 0) {
					selected = [msgitemViews[0]];
				}
			}
			updateState(oldstate);
		},
		// Remove messages, they can be in different threads.
		removeUIDs: (mailboxID, uids) => {
			const oldstate = state();
			const hadSelected = selected.length > 0;
			const threadIDs = new Set();
			uids.forEach(uid => {
				const threadID = removeUID(mailboxID, uid);
				log('removed message with thread', { threadID });
				if (threadID) {
					threadIDs.add(threadID);
				}
			});
			possiblyTakeoutOldThreads(threadIDs);
			if (hadSelected && focus && selected.length === 0) {
				selected = [focus];
			}
			updateState(oldstate);
		},
		// Set new muted/collapsed flags for messages in thread.
		updateMessageThreadFields: (messageIDs, muted, collapsed) => {
			for (const id of messageIDs) {
				let miv = msgitemViews.find(miv => miv.messageitem.Message.ID === id);
				if (!miv) {
					miv = collapsedMsgitemViews.find(miv => miv.messageitem.Message.ID === id);
				}
				if (miv) {
					miv.messageitem.Message.ThreadMuted = muted;
					miv.messageitem.Message.ThreadCollapsed = collapsed;
					const mivthr = miv.threadRoot();
					if (mivthr.collapsed) {
						mivthr.render();
					}
					else {
						miv.render();
					}
				}
				else {
					const mi = oldThreadMessageItems.find(mi => mi.Message.ID === id);
					if (mi) {
						mi.Message.ThreadMuted = muted;
						mi.Message.ThreadCollapsed = collapsed;
					}
				}
			}
		},
		// For location hash.
		activeMessageID: () => selected.length === 1 ? selected[0].messageitem.Message.ID : 0,
		redraw: (miv) => {
			miv.root.classList.toggle('focus', miv === focus);
			miv.root.classList.toggle('active', selected.indexOf(miv) >= 0);
		},
		clear: () => {
			dom._kids(mlv.root);
			msgitemViews.forEach(miv => miv.remove());
			msgitemViews = [];
			collapsedMsgitemViews = [];
			oldThreadMessageItems = [];
			focus = null;
			selected = [];
			dom._kids(msgElem);
			setLocationHash();
		},
		unselect: () => {
			const oldstate = state();
			selected = [];
			updateState(oldstate);
		},
		select: (miv) => {
			const oldstate = state();
			focus = miv;
			selected = [miv];
			updateState(oldstate);
		},
		selected: () => {
			const l = [];
			for (const miv of selected) {
				l.push(miv);
				if (miv.collapsed) {
					l.push(...miv.descendants());
				}
			}
			return l;
		},
		openMessage: (parsedMessage) => {
			let miv = msgitemViews.find(miv => miv.messageitem.Message.ID === parsedMessage.ID);
			if (!miv) {
				// todo: could move focus to the nearest expanded message in this thread, if any?
				return false;
			}
			const oldstate = state();
			focus = miv;
			selected = [miv];
			updateState(oldstate, true, parsedMessage);
			return true;
		},
		click: (miv, ctrl, shift) => {
			if (msgitemViews.length === 0) {
				return;
			}
			const oldstate = state();
			if (shift) {
				const mivindex = msgitemViews.indexOf(miv);
				// Set selection from start of most recent range.
				let recentindex;
				if (selected.length > 0) {
					let o = selected.length - 1;
					recentindex = msgitemViews.indexOf(selected[o]);
					while (o > 0) {
						if (selected[o - 1] === msgitemViews[recentindex - 1]) {
							recentindex--;
						}
						else if (selected[o - 1] === msgitemViews[recentindex + 1]) {
							recentindex++;
						}
						else {
							break;
						}
						o--;
					}
				}
				else {
					recentindex = mivindex;
				}
				const oselected = selected;
				if (mivindex < recentindex) {
					selected = msgitemViews.slice(mivindex, recentindex + 1);
					selected.reverse();
				}
				else {
					selected = msgitemViews.slice(recentindex, mivindex + 1);
				}
				if (ctrl) {
					selected = oselected.filter(e => !selected.includes(e)).concat(selected);
				}
			}
			else if (ctrl) {
				const index = selected.indexOf(miv);
				if (index < 0) {
					selected.push(miv);
				}
				else {
					selected.splice(index, 1);
				}
			}
			else {
				selected = [miv];
			}
			focus = miv;
			updateState(oldstate);
		},
		key: async (k, e) => {
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
			];
			if (!e.altKey && moveKeys.includes(e.key)) {
				const moveclick = (index, clip) => {
					if (clip && index < 0) {
						index = 0;
					}
					else if (clip && index >= msgitemViews.length) {
						index = msgitemViews.length - 1;
					}
					if (index < 0 || index >= msgitemViews.length) {
						return;
					}
					if (e.ctrlKey) {
						moveFocus(msgitemViews[index]);
					}
					else {
						mlv.click(msgitemViews[index], false, e.shiftKey);
					}
				};
				let i = msgitemViews.findIndex(miv => miv === focus);
				if (e.key === ' ') {
					if (i >= 0) {
						mlv.click(msgitemViews[i], e.ctrlKey, e.shiftKey);
					}
				}
				else if (e.key === 'ArrowUp' || e.key === 'k' || e.key === 'K') {
					moveclick(i - 1, e.key === 'K');
				}
				else if (e.key === 'ArrowDown' || e.key === 'j' || e.key === 'J') {
					moveclick(i + 1, e.key === 'J');
				}
				else if (e.key === 'PageUp' || e.key === 'h' || e.key === 'H' || e.key === 'PageDown' || e.key === 'l' || e.key === 'L') {
					if (msgitemViews.length > 0) {
						let n = Math.max(1, Math.floor(scrollElemHeight() / mlv.itemHeight()) - 1);
						if (e.key === 'PageUp' || e.key === 'h' || e.key === 'H') {
							n = -n;
						}
						moveclick(i + n, true);
					}
				}
				else if (e.key === 'Home' || e.key === ',' || e.key === '<') {
					moveclick(0, true);
				}
				else if (e.key === 'End' || e.key === '.' || e.key === '>') {
					moveclick(msgitemViews.length - 1, true);
				}
				else if (e.key === 'n' || e.key === 'N') {
					if (i < 0) {
						moveclick(0, true);
					}
					else {
						const tid = msgitemViews[i].messageitem.Message.ThreadID;
						for (; i < msgitemViews.length; i++) {
							if (msgitemViews[i].messageitem.Message.ThreadID !== tid) {
								moveclick(i, true);
								break;
							}
						}
					}
				}
				else if (e.key === 'p' || e.key === 'P') {
					if (i < 0) {
						moveclick(0, true);
					}
					else {
						let thrmiv = msgitemViews[i].threadRoot();
						if (thrmiv === msgitemViews[i]) {
							if (i - 1 >= 0) {
								thrmiv = msgitemViews[i - 1].threadRoot();
							}
						}
						moveclick(msgitemViews.indexOf(thrmiv), true);
					}
				}
				else if (e.key === 'u' || e.key === 'U') {
					for (i = i < 0 ? 0 : i + 1; i < msgitemViews.length; i += 1) {
						if (!msgitemViews[i].messageitem.Message.Seen || msgitemViews[i].collapsed && msgitemViews[i].findDescendant(miv => !miv.messageitem.Message.Seen)) {
							moveclick(i, true);
							break;
						}
					}
				}
				e.preventDefault();
				e.stopPropagation();
				return;
			}
			const fn = shortcuts[k];
			if (fn) {
				e.preventDefault();
				e.stopPropagation();
				fn();
			}
			else if (msgView) {
				msgView.key(k, e);
			}
			else {
				log('key not handled', k);
			}
		},
		mailboxes: () => listMailboxes(),
		itemHeight: () => msgitemViews.length > 0 ? msgitemViews[0].root.getBoundingClientRect().height : 25,
		threadExpand: (miv) => threadExpand(miv, true),
		threadCollapse: (miv) => threadCollapse(miv, true),
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
	};
	return mlv;
};
const newMailboxView = (xmb, mailboxlistView, otherMailbox) => {
	const plusbox = '⊞';
	const minusbox = '⊟';
	const cmdCollapse = async () => {
		settings.mailboxCollapsed[mbv.mailbox.ID] = true;
		settingsPut(settings);
		mailboxlistView.updateHidden();
		mbv.root.focus();
	};
	const cmdExpand = async () => {
		delete (settings.mailboxCollapsed[mbv.mailbox.ID]);
		settingsPut(settings);
		mailboxlistView.updateHidden();
		mbv.root.focus();
	};
	const collapseElem = dom.span(dom._class('mailboxcollapse'), minusbox, function click(e) {
		e.stopPropagation();
		cmdCollapse();
	});
	const expandElem = dom.span(plusbox, function click(e) {
		e.stopPropagation();
		cmdExpand();
	});
	let name, unread;
	let actionBtn;
	const cmdOpenActions = async () => {
		const trashmb = mailboxlistView.mailboxes().find(mb => mb.Trash);
		const remove = popover(actionBtn, { transparent: true }, dom.div(style({ display: 'flex', flexDirection: 'column', gap: '.5ex' }), dom.div(dom.clickbutton('Move to trash', attr.title('Move mailbox, its messages and its mailboxes to the trash.'), async function click() {
			if (!trashmb) {
				window.alert('No mailbox configured for trash yet.');
				return;
			}
			if (!window.confirm('Are you sure you want to move this mailbox, its messages and its mailboxes to the trash?')) {
				return;
			}
			remove();
			await withStatus('Moving mailbox to trash', client.MailboxRename(mbv.mailbox.ID, trashmb.Name + '/' + mbv.mailbox.Name));
		})), dom.div(dom.clickbutton('Delete mailbox', attr.title('Permanently delete this mailbox and all its messages.'), async function click() {
			if (!window.confirm('Are you sure you want to permanently delete this mailbox and all its messages?')) {
				return;
			}
			remove();
			await withStatus('Deleting mailbox', client.MailboxDelete(mbv.mailbox.ID));
		})), dom.div(dom.clickbutton('Empty mailbox', async function click() {
			if (!window.confirm('Are you sure you want to empty this mailbox, permanently removing its messages? Mailboxes inside this mailbox are not affected.')) {
				return;
			}
			remove();
			await withStatus('Emptying mailbox', client.MailboxEmpty(mbv.mailbox.ID));
		})), dom.div(dom.clickbutton('Rename mailbox', function click() {
			remove();
			let fieldset, name;
			const remove2 = popover(actionBtn, {}, dom.form(async function submit(e) {
				e.preventDefault();
				await withStatus('Renaming mailbox', client.MailboxRename(mbv.mailbox.ID, name.value), fieldset);
				remove2();
			}, fieldset = dom.fieldset(dom.label('Name ', name = dom.input(attr.required(''), attr.value(mbv.mailbox.Name), prop({ selectionStart: 0, selectionEnd: mbv.mailbox.Name.length }))), ' ', dom.submitbutton('Rename'))));
		})), dom.div(dom.clickbutton('Set role for mailbox...', attr.title('Set a special-use role on the mailbox, making it the designated mailbox for either Archived, Sent, Draft, Trashed or Junk messages.'), async function click() {
			remove();
			const setUse = async (set) => {
				const mb = { ...mbv.mailbox };
				mb.Archive = mb.Draft = mb.Junk = mb.Sent = mb.Trash = false;
				set(mb);
				await withStatus('Marking mailbox as special use', client.MailboxSetSpecialUse(mb));
			};
			popover(actionBtn, { transparent: true }, dom.div(style({ display: 'flex', flexDirection: 'column', gap: '.5ex' }), dom.div(dom.clickbutton('Archive', async function click() { await setUse((mb) => { mb.Archive = true; }); })), dom.div(dom.clickbutton('Draft', async function click() { await setUse((mb) => { mb.Draft = true; }); })), dom.div(dom.clickbutton('Junk', async function click() { await setUse((mb) => { mb.Junk = true; }); })), dom.div(dom.clickbutton('Sent', async function click() { await setUse((mb) => { mb.Sent = true; }); })), dom.div(dom.clickbutton('Trash', async function click() { await setUse((mb) => { mb.Trash = true; }); }))));
		}))));
	};
	// Keep track of dragenter/dragleave ourselves, we don't get a neat 1 enter and 1
	// leave event from browsers, we get events for multiple of this elements children.
	let drags = 0;
	const root = dom.div(dom._class('mailboxitem'), attr.tabindex('0'), async function keydown(e) {
		if (e.key === 'Enter') {
			e.stopPropagation();
			await withStatus('Opening mailbox', mbv.open(true));
		}
		else if (e.key === 'ArrowLeft') {
			e.stopPropagation();
			if (!mailboxlistView.mailboxLeaf(mbv)) {
				cmdCollapse();
			}
		}
		else if (e.key === 'ArrowRight') {
			e.stopPropagation();
			if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
				cmdExpand();
			}
		}
		else if (e.key === 'b') {
			cmdOpenActions();
		}
	}, async function dblclick() {
		if (mailboxlistView.mailboxLeaf(mbv)) {
			return;
		}
		if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
			cmdExpand();
		}
		else {
			cmdCollapse();
		}
	}, async function click() {
		mbv.root.focus();
		await withStatus('Opening mailbox', mbv.open(true));
	}, function dragover(e) {
		e.preventDefault();
		e.dataTransfer.dropEffect = 'move';
	}, function dragenter(e) {
		e.stopPropagation();
		drags++;
		mbv.root.classList.toggle('dropping', true);
	}, function dragleave(e) {
		e.stopPropagation();
		drags--;
		if (drags <= 0) {
			mbv.root.classList.toggle('dropping', false);
		}
	}, async function drop(e) {
		e.preventDefault();
		mbv.root.classList.toggle('dropping', false);
		const sentMailboxID = mailboxlistView.mailboxes().find(mb => mb.Sent)?.ID;
		const mailboxMsgIDs = JSON.parse(e.dataTransfer.getData('application/vnd.mox.messages'));
		const msgIDs = mailboxMsgIDs
			.filter(mbMsgID => mbMsgID[0] !== xmb.ID)
			.filter(mbMsgID => mailboxMsgIDs.length === 1 || !sentMailboxID || mbMsgID[0] !== sentMailboxID || !otherMailbox(sentMailboxID))
			.map(mbMsgID => mbMsgID[1]);
		await withStatus('Moving to ' + xmb.Name, client.MessageMove(msgIDs, xmb.ID));
	}, dom.div(dom._class('mailbox'), style({ display: 'flex', justifyContent: 'space-between' }), name = dom.div(style({ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' })), dom.div(style({ whiteSpace: 'nowrap' }), actionBtn = dom.clickbutton(dom._class('mailboxhoveronly'), '...', attr.tabindex('-1'), // Without, tab breaks because this disappears when mailbox loses focus.
	attr.arialabel('Mailbox actions'), attr.title('Actions on mailbox, like deleting, emptying, renaming.'), function click(e) {
		e.stopPropagation();
		cmdOpenActions();
	}), ' ', unread = dom.b(dom._class('silenttitle')))));
	const update = () => {
		let moreElems = [];
		if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
			moreElems = [' ', expandElem];
		}
		else if (!mailboxlistView.mailboxLeaf(mbv)) {
			moreElems = [' ', collapseElem];
		}
		let ntotal = mbv.mailbox.Total;
		let nunread = mbv.mailbox.Unread;
		if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
			const prefix = mbv.mailbox.Name + '/';
			for (const mb of mailboxlistView.mailboxes()) {
				if (mb.Name.startsWith(prefix)) {
					ntotal += mb.Total;
					nunread += mb.Unread;
				}
			}
		}
		dom._kids(name, dom.span(mbv.parents > 0 ? style({ paddingLeft: '' + (mbv.parents * 2 / 3) + 'em' }) : [], mbv.shortname, attr.title('Total messages: ' + ntotal), moreElems));
		dom._kids(unread, nunread === 0 ? ['', attr.title('')] : ['' + nunread, attr.title('' + nunread + ' unread')]);
	};
	const mbv = {
		root: root,
		// Set by update(), typically through MailboxlistView updateMailboxNames after inserting.
		shortname: '',
		parents: 0,
		hidden: false,
		update: update,
		mailbox: xmb,
		open: async (load) => {
			await mailboxlistView.openMailboxView(mbv, load, false);
		},
		setCounts: (total, unread) => {
			mbv.mailbox.Total = total;
			mbv.mailbox.Unread = unread;
			// If mailbox is collapsed, parent needs updating.
			// todo optimize: only update parents, not all.
			mailboxlistView.updateCounts();
		},
		setSpecialUse: (specialUse) => {
			mbv.mailbox.Archive = specialUse.Archive;
			mbv.mailbox.Draft = specialUse.Draft;
			mbv.mailbox.Junk = specialUse.Junk;
			mbv.mailbox.Sent = specialUse.Sent;
			mbv.mailbox.Trash = specialUse.Trash;
		},
		setKeywords: (keywords) => {
			mbv.mailbox.Keywords = keywords;
		},
	};
	return mbv;
};
const newMailboxlistView = (msglistView, requestNewView, updatePageTitle, setLocationHash, unloadSearch, otherMailbox) => {
	let mailboxViews = [];
	let mailboxViewActive;
	// Reorder mailboxes and assign new short names and indenting. Called after changing the list.
	const updateMailboxNames = () => {
		const draftmb = mailboxViews.find(mbv => mbv.mailbox.Draft)?.mailbox;
		const sentmb = mailboxViews.find(mbv => mbv.mailbox.Sent)?.mailbox;
		const archivemb = mailboxViews.find(mbv => mbv.mailbox.Archive)?.mailbox;
		const trashmb = mailboxViews.find(mbv => mbv.mailbox.Trash)?.mailbox;
		const junkmb = mailboxViews.find(mbv => mbv.mailbox.Junk)?.mailbox;
		const stem = (s) => s.split('/')[0];
		const specialUse = [
			(mb) => stem(mb.Name) === 'Inbox',
			(mb) => draftmb && stem(mb.Name) === stem(draftmb.Name),
			(mb) => sentmb && stem(mb.Name) === stem(sentmb.Name),
			(mb) => archivemb && stem(mb.Name) === stem(archivemb.Name),
			(mb) => trashmb && stem(mb.Name) === stem(trashmb.Name),
			(mb) => junkmb && stem(mb.Name) === stem(junkmb.Name),
		];
		mailboxViews.sort((mbva, mbvb) => {
			const ai = specialUse.findIndex(fn => fn(mbva.mailbox));
			const bi = specialUse.findIndex(fn => fn(mbvb.mailbox));
			if (ai < 0 && bi >= 0) {
				return 1;
			}
			else if (ai >= 0 && bi < 0) {
				return -1;
			}
			else if (ai >= 0 && bi >= 0 && ai !== bi) {
				return ai < bi ? -1 : 1;
			}
			const la = mbva.mailbox.Name.split('/');
			const lb = mbvb.mailbox.Name.split('/');
			let n = Math.min(la.length, lb.length);
			for (let i = 0; i < n; i++) {
				if (la[i] === lb[i]) {
					continue;
				}
				return la[i] < lb[i] ? -1 : 1;
			}
			return mbva.mailbox.Name < mbvb.mailbox.Name ? -1 : 1;
		});
		let prevmailboxname = '';
		mailboxViews.forEach(mbv => {
			const mb = mbv.mailbox;
			let shortname = mb.Name;
			let parents = 0;
			if (prevmailboxname) {
				let prefix = '';
				for (const s of prevmailboxname.split('/')) {
					const nprefix = prefix + s + '/';
					if (mb.Name.startsWith(nprefix)) {
						prefix = nprefix;
						parents++;
					}
					else {
						break;
					}
				}
				shortname = mb.Name.substring(prefix.length);
			}
			mbv.shortname = shortname;
			mbv.parents = parents;
			mbv.update(); // Render name.
			prevmailboxname = mb.Name;
		});
		updateHidden();
	};
	const mailboxHidden = (mb, mailboxesMap) => {
		let s = '';
		for (const e of mb.Name.split('/')) {
			if (s) {
				s += '/';
			}
			s += e;
			const pmb = mailboxesMap[s];
			if (pmb && settings.mailboxCollapsed[pmb.ID] && s !== mb.Name) {
				return true;
			}
		}
		return false;
	};
	const mailboxLeaf = (mbv) => {
		const index = mailboxViews.findIndex(v => v === mbv);
		const prefix = mbv.mailbox.Name + '/';
		const r = index < 0 || index + 1 >= mailboxViews.length || !mailboxViews[index + 1].mailbox.Name.startsWith(prefix);
		return r;
	};
	const updateHidden = () => {
		const mailboxNameMap = {};
		mailboxViews.forEach((mbv) => mailboxNameMap[mbv.mailbox.Name] = mbv.mailbox);
		for (const mbv of mailboxViews) {
			mbv.hidden = mailboxHidden(mbv.mailbox, mailboxNameMap);
		}
		mailboxViews.forEach(mbv => mbv.update());
		dom._kids(mailboxesElem, mailboxViews.filter(mbv => !mbv.hidden));
	};
	const root = dom.div();
	const mailboxesElem = dom.div();
	dom._kids(root, dom.div(attr.role('region'), attr.arialabel('Mailboxes'), dom.div(dom.h1('Mailboxes', style({ display: 'inline', fontSize: 'inherit' })), ' ', dom.clickbutton('+', attr.arialabel('Create new mailbox.'), attr.title('Create new mailbox.'), style({ padding: '0 .25em' }), function click(e) {
		let fieldset, name;
		const remove = popover(e.target, {}, dom.form(async function submit(e) {
			e.preventDefault();
			await withStatus('Creating mailbox', client.MailboxCreate(name.value), fieldset);
			remove();
		}, fieldset = dom.fieldset(dom.label('Name ', name = dom.input(attr.required('yes'), focusPlaceholder('Lists/Go/Nuts'))), ' ', dom.submitbutton('Create'))));
	})), mailboxesElem));
	const loadMailboxes = (mailboxes, mbnameOpt) => {
		mailboxViews = mailboxes.map(mb => newMailboxView(mb, mblv, otherMailbox));
		updateMailboxNames();
		if (mbnameOpt) {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.Name === mbnameOpt);
			if (mbv) {
				openMailboxView(mbv, false, false);
			}
		}
	};
	const closeMailbox = () => {
		if (!mailboxViewActive) {
			return;
		}
		mailboxViewActive.root.classList.toggle('active', false);
		mailboxViewActive = null;
		updatePageTitle();
	};
	const openMailboxView = async (mbv, load, focus) => {
		// Ensure searchbarElem is in inactive state.
		unloadSearch();
		if (mailboxViewActive) {
			mailboxViewActive.root.classList.toggle('active', false);
		}
		mailboxViewActive = mbv;
		mbv.root.classList.toggle('active', true);
		updatePageTitle();
		if (load) {
			setLocationHash();
			const f = newFilter();
			f.MailboxID = mbv.mailbox.ID;
			await withStatus('Requesting messages', requestNewView(true, f, newNotFilter()));
		}
		else {
			msglistView.clear();
			setLocationHash();
		}
		if (focus) {
			mbv.root.focus();
		}
	};
	const mblv = {
		root: root,
		loadMailboxes: loadMailboxes,
		closeMailbox: closeMailbox,
		openMailboxView: openMailboxView,
		mailboxLeaf: mailboxLeaf,
		updateHidden: updateHidden,
		updateCounts: () => mailboxViews.forEach(mbv => mbv.update()),
		activeMailbox: () => mailboxViewActive ? mailboxViewActive.mailbox : null,
		mailboxes: () => mailboxViews.map(mbv => mbv.mailbox),
		findMailboxByID: (id) => mailboxViews.find(mbv => mbv.mailbox.ID === id)?.mailbox || null,
		findMailboxByName: (name) => mailboxViews.find(mbv => mbv.mailbox.Name === name)?.mailbox || null,
		openMailboxID: async (id, focus) => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === id);
			if (mbv) {
				await openMailboxView(mbv, false, focus);
			}
			else {
				throw new Error('unknown mailbox');
			}
		},
		addMailbox: (mb) => {
			const mbv = newMailboxView(mb, mblv, otherMailbox);
			mailboxViews.push(mbv);
			updateMailboxNames();
		},
		renameMailbox: (mailboxID, newName) => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID);
			if (!mbv) {
				throw new Error('rename event: unknown mailbox');
			}
			mbv.mailbox.Name = newName;
			updateMailboxNames();
		},
		removeMailbox: (mailboxID) => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID);
			if (!mbv) {
				throw new Error('remove event: unknown mailbox');
			}
			if (mbv === mailboxViewActive) {
				const inboxv = mailboxViews.find(mbv => mbv.mailbox.Name === 'Inbox');
				if (inboxv) {
					openMailboxView(inboxv, true, false); // note: async function
				}
			}
			const index = mailboxViews.findIndex(mbv => mbv.mailbox.ID === mailboxID);
			mailboxViews.splice(index, 1);
			updateMailboxNames();
		},
		setMailboxCounts: (mailboxID, total, unread) => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID);
			if (!mbv) {
				throw new Error('mailbox message/unread count changed: unknown mailbox');
			}
			mbv.setCounts(total, unread);
			if (mbv === mailboxViewActive) {
				updatePageTitle();
			}
		},
		setMailboxSpecialUse: (mailboxID, specialUse) => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID);
			if (!mbv) {
				throw new Error('special-use flags changed: unknown mailbox');
			}
			mbv.setSpecialUse(specialUse);
			updateMailboxNames();
		},
		setMailboxKeywords: (mailboxID, keywords) => {
			const mbv = mailboxViews.find(mbv => mbv.mailbox.ID === mailboxID);
			if (!mbv) {
				throw new Error('keywords changed: unknown mailbox');
			}
			mbv.setKeywords(keywords);
		},
	};
	return mblv;
};
const newSearchView = (searchbarElem, mailboxlistView, startSearch, searchViewClose) => {
	let form;
	let words, mailbox, mailboxkids, from, to, oldestDate, oldestTime, newestDate, newestTime, subject, flagViews, labels, minsize, maxsize;
	let attachmentNone, attachmentAny, attachmentImage, attachmentPDF, attachmentArchive, attachmentSpreadsheet, attachmentDocument, attachmentPresentation;
	const makeDateTime = (dt, tm) => {
		if (!dt && !tm) {
			return '';
		}
		if (!dt) {
			const now = new Date();
			const pad0 = (v) => v <= 9 ? '0' + v : '' + v;
			dt = [now.getFullYear(), pad0(now.getMonth() + 1), pad0(now.getDate())].join('-');
		}
		if (dt && tm) {
			return dt + 'T' + tm;
		}
		return dt;
	};
	const packString = (s) => needsDquote(s) ? dquote(s) : s;
	const packNotString = (s) => '-' + (needsDquote(s) || s.startsWith('-') ? dquote(s) : s);
	// Sync the form fields back into the searchbarElem. We process in order of the form,
	// so we may rearrange terms. We also canonicalize quoting and space and remove
	// empty strings.
	const updateSearchbar = () => {
		let tokens = [];
		if (mailbox.value && mailbox.value !== '-1') {
			const v = mailbox.value === '0' ? '' : mailbox.selectedOptions[0].text; // '0' is "All mailboxes", represented as "mb:".
			tokens.push([false, 'mb', false, v]);
		}
		if (mailboxkids.checked) {
			tokens.push([false, 'submb', false, '']);
		}
		tokens.push(...parseSearchTokens(words.value));
		tokens.push(...parseSearchTokens(from.value).map(t => [t[0], 'f', false, t[3]]));
		tokens.push(...parseSearchTokens(to.value).map(t => [t[0], 't', false, t[3]]));
		const start = makeDateTime(oldestDate.value, oldestTime.value);
		if (start) {
			tokens.push([false, 'start', false, start]);
		}
		const end = makeDateTime(newestDate.value, newestTime.value);
		if (end) {
			tokens.push([false, 'end', false, end]);
		}
		tokens.push(...parseSearchTokens(subject.value).map(t => [t[0], 's', false, t[3]]));
		const check = (elem, tag, value) => {
			if (elem.checked) {
				tokens.push([false, tag, false, value]);
			}
		};
		check(attachmentNone, 'a', 'none');
		check(attachmentAny, 'a', 'any');
		check(attachmentImage, 'a', 'image');
		check(attachmentPDF, 'a', 'pdf');
		check(attachmentArchive, 'a', 'archive');
		check(attachmentSpreadsheet, 'a', 'spreadsheet');
		check(attachmentDocument, 'a', 'document');
		check(attachmentPresentation, 'a', 'presentation');
		tokens.push(...flagViews.filter(fv => fv.active !== null).map(fv => {
			return [!fv.active, 'l', false, fv.flag];
		}));
		tokens.push(...parseSearchTokens(labels.value).map(t => [t[0], 'l', t[2], t[3]]));
		tokens.push(...headerViews.filter(hv => hv.key.value).map(hv => [false, 'h', false, hv.key.value + ':' + hv.value.value]));
		const minstr = parseSearchSize(minsize.value)[0];
		if (minstr) {
			tokens.push([false, 'minsize', false, minstr]);
		}
		const maxstr = parseSearchSize(maxsize.value)[0];
		if (maxstr) {
			tokens.push([false, 'maxsize', false, maxstr]);
		}
		searchbarElem.value = tokens.map(packToken).join(' ');
	};
	const setDateTime = (s, dateElem, timeElem) => {
		if (!s) {
			return;
		}
		const t = s.split('T', 2);
		const dt = t.length === 2 || t[0].includes('-') ? t[0] : '';
		const tm = t.length === 2 ? t[1] : (t[0].includes(':') ? t[0] : '');
		if (dt) {
			dateElem.value = dt;
		}
		if (tm) {
			timeElem.value = tm;
		}
	};
	// Update form based on searchbarElem. We parse the searchbarElem into a filter. Then reset
	// and populate the form.
	const updateForm = () => {
		const [f, notf, strs] = parseSearch(searchbarElem.value, mailboxlistView);
		form.reset();
		const packTwo = (l, lnot) => (l || []).map(packString).concat((lnot || []).map(packNotString)).join(' ');
		if (f.MailboxName) {
			const o = [...mailbox.options].find(o => o.text === f.MailboxName) || mailbox.options[0];
			if (o) {
				o.selected = true;
			}
		}
		else if (f.MailboxID === -1) {
			// "All mailboxes except ...".
			mailbox.options[0].selected = true;
		}
		else {
			const id = '' + f.MailboxID;
			const o = [...mailbox.options].find(o => o.value === id) || mailbox.options[0];
			o.selected = true;
		}
		mailboxkids.checked = f.MailboxChildrenIncluded;
		words.value = packTwo(f.Words, notf.Words);
		from.value = packTwo(f.From, notf.From);
		to.value = packTwo(f.To, notf.To);
		setDateTime(strs.Oldest, oldestDate, oldestTime);
		setDateTime(strs.Newest, newestDate, newestTime);
		subject.value = packTwo(f.Subject, notf.Subject);
		const elem = {
			none: attachmentNone,
			any: attachmentAny,
			image: attachmentImage,
			pdf: attachmentPDF,
			archive: attachmentArchive,
			spreadsheet: attachmentSpreadsheet,
			document: attachmentDocument,
			presentation: attachmentPresentation,
		}[f.Attachments];
		if (elem) {
			attachmentChecks(elem, true);
		}
		const otherlabels = [];
		const othernotlabels = [];
		flagViews.forEach(fv => fv.active = null);
		const setLabels = (flabels, other, not) => {
			(flabels || []).forEach(l => {
				l = l.toLowerCase();
				// Find if this is a well-known flag.
				const fv = flagViews.find(fv => fv.flag.toLowerCase() === l);
				if (fv) {
					fv.active = !not;
					fv.update();
				}
				else {
					other.push(l);
				}
			});
		};
		setLabels(f.Labels, otherlabels, false);
		setLabels(notf.Labels, othernotlabels, true);
		labels.value = packTwo(otherlabels, othernotlabels);
		headerViews.slice(1).forEach(hv => hv.root.remove());
		headerViews = [headerViews[0]];
		if (f.Headers && f.Headers.length > 0) {
			(f.Headers || []).forEach((kv, index) => {
				const [k, v] = kv || ['', ''];
				if (index > 0) {
					addHeaderView();
				}
				headerViews[index].key.value = k;
				headerViews[index].value.value = v;
			});
		}
		if (strs.SizeMin) {
			minsize.value = strs.SizeMin;
		}
		if (strs.SizeMax) {
			maxsize.value = strs.SizeMax;
		}
	};
	const attachmentChecks = (elem, set) => {
		if (elem.checked || set) {
			for (const e of [attachmentNone, attachmentAny, attachmentImage, attachmentPDF, attachmentArchive, attachmentSpreadsheet, attachmentDocument, attachmentPresentation]) {
				if (e !== elem) {
					e.checked = false;
				}
				else if (set) {
					e.checked = true;
				}
			}
		}
	};
	const changeHandlers = [
		function change() {
			updateSearchbar();
		},
		function keyup() {
			updateSearchbar();
		},
	];
	const attachmentHandlers = [
		function change(e) {
			attachmentChecks(e.target);
		},
		function mousedown(e) {
			// Radiobuttons cannot be deselected normally. With this handler a user can push
			// down on the button, then move pointer out of button and release the button to
			// clear the radiobutton.
			const target = e.target;
			if (e.buttons === 1 && target.checked) {
				target.checked = false;
				e.preventDefault();
			}
		},
		...changeHandlers,
	];
	let headersCell; // Where we add headerViews.
	let headerViews;
	const newHeaderView = (first) => {
		let key, value;
		const root = dom.div(style({ display: 'flex' }), key = dom.input(focusPlaceholder('Header name'), style({ width: '40%' }), changeHandlers), dom.div(style({ width: '.5em' })), value = dom.input(focusPlaceholder('Header value'), style({ flexGrow: 1 }), changeHandlers), dom.div(style({ width: '2.5em', paddingLeft: '.25em' }), dom.clickbutton('+', style({ padding: '0 .25em' }), attr.arialabel('Add row for another header filter.'), attr.title('Add row for another header filter.'), function click() {
			addHeaderView();
		}), ' ', first ? [] : dom.clickbutton('-', style({ padding: '0 .25em' }), attr.arialabel('Remove row.'), attr.title('Remove row.'), function click() {
			root.remove();
			const index = headerViews.findIndex(v => v === hv);
			headerViews.splice(index, 1);
			updateSearchbar();
		})));
		const hv = { root: root, key: key, value: value };
		return hv;
	};
	const addHeaderView = () => {
		const hv = newHeaderView(false);
		headersCell.appendChild(hv.root);
		headerViews.push(hv);
	};
	const setPeriod = (d) => {
		newestDate.value = '';
		newestTime.value = '';
		const pad0 = (v) => v <= 9 ? '0' + v : '' + v;
		const dt = [d.getFullYear(), pad0(d.getMonth() + 1), pad0(d.getDate())].join('-');
		const tm = '' + pad0(d.getHours()) + ':' + pad0(d.getMinutes());
		oldestDate.value = dt;
		oldestTime.value = tm;
		updateSearchbar();
	};
	const root = dom.div(style({ position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.2)', zIndex: zindexes.compose }), function click(e) {
		e.stopPropagation();
		searchViewClose();
	}, function keyup(e) {
		if (e.key === 'Escape') {
			e.stopPropagation();
			searchViewClose();
		}
	}, dom.search(style({ position: 'absolute', width: '50em', padding: '.5ex', backgroundColor: 'white', boxShadow: '0px 0px 20px rgba(0, 0, 0, 0.1)', borderRadius: '.15em' }), function click(e) {
		e.stopPropagation();
	}, 
	// This is a separate form, inside the form with the overall search field because
	// when updating the form based on the parsed searchbar, we first need to reset it.
	form = dom.form(dom.table(dom._class('search'), style({ width: '100%' }), dom.tr(dom.td(dom.label('Mailbox', attr.for('searchMailbox')), attr.title('Filter by mailbox, including children of the mailbox.')), dom.td(mailbox = dom.select(attr.id('searchMailbox'), style({ width: '100%' }), dom.option('All mailboxes except Trash/Junk/Rejects', attr.value('-1')), dom.option('All mailboxes', attr.value('0')), changeHandlers), dom.div(style({ paddingTop: '.5ex' }), dom.label(mailboxkids = dom.input(attr.type('checkbox'), changeHandlers), ' Also search in mailboxes below the selected mailbox.')))), dom.tr(dom.td(dom.label('Text', attr.for('searchWords'))), dom.td(words = dom.input(attr.id('searchWords'), attr.title('Filter by text, case-insensitive, substring match, not necessarily whole words.'), focusPlaceholder('word "exact match" -notword'), style({ width: '100%' }), changeHandlers))), dom.tr(dom.td(dom.label('From', attr.for('searchFrom'))), dom.td(from = dom.input(attr.id('searchFrom'), style({ width: '100%' }), focusPlaceholder('Address or name'), newAddressComplete(), changeHandlers))), dom.tr(dom.td(dom.label('To', attr.for('searchTo')), attr.title('Search on addressee, including Cc and Bcc headers.')), dom.td(to = dom.input(attr.id('searchTo'), focusPlaceholder('Address or name, also matches Cc and Bcc addresses'), style({ width: '100%' }), newAddressComplete(), changeHandlers))), dom.tr(dom.td(dom.label('Subject', attr.for('searchSubject'))), dom.td(subject = dom.input(attr.id('searchSubject'), style({ width: '100%' }), focusPlaceholder('"exact match"'), changeHandlers))), dom.tr(dom.td('Received between', style({ whiteSpace: 'nowrap' })), dom.td(style({ lineHeight: 2 }), dom.div(oldestDate = dom.input(attr.type('date'), focusPlaceholder('2023-07-20'), changeHandlers), oldestTime = dom.input(attr.type('time'), focusPlaceholder('23:10'), changeHandlers), ' ', dom.clickbutton('x', style({ padding: '0 .3em' }), attr.arialabel('Clear start date.'), attr.title('Clear start date.'), function click() {
		oldestDate.value = '';
		oldestTime.value = '';
		updateSearchbar();
	}), ' and ', newestDate = dom.input(attr.type('date'), focusPlaceholder('2023-07-20'), changeHandlers), newestTime = dom.input(attr.type('time'), focusPlaceholder('23:10'), changeHandlers), ' ', dom.clickbutton('x', style({ padding: '0 .3em' }), attr.arialabel('Clear end date.'), attr.title('Clear end date.'), function click() {
		newestDate.value = '';
		newestTime.value = '';
		updateSearchbar();
	})), dom.div(dom.clickbutton('1 day', function click() {
		setPeriod(new Date(new Date().getTime() - 24 * 3600 * 1000));
	}), ' ', dom.clickbutton('1 week', function click() {
		setPeriod(new Date(new Date().getTime() - 7 * 24 * 3600 * 1000));
	}), ' ', dom.clickbutton('1 month', function click() {
		setPeriod(new Date(new Date().getTime() - 31 * 24 * 3600 * 1000));
	}), ' ', dom.clickbutton('1 year', function click() {
		setPeriod(new Date(new Date().getTime() - 365 * 24 * 3600 * 1000));
	})))), dom.tr(dom.td('Attachments'), dom.td(dom.label(style({ whiteSpace: 'nowrap' }), attachmentNone = dom.input(attr.type('radio'), attr.name('attachments'), attr.value('none'), attachmentHandlers), ' None'), ' ', dom.label(style({ whiteSpace: 'nowrap' }), attachmentAny = dom.input(attr.type('radio'), attr.name('attachments'), attr.value('any'), attachmentHandlers), ' Any'), ' ', dom.label(style({ whiteSpace: 'nowrap' }), attachmentImage = dom.input(attr.type('radio'), attr.name('attachments'), attr.value('image'), attachmentHandlers), ' Images'), ' ', dom.label(style({ whiteSpace: 'nowrap' }), attachmentPDF = dom.input(attr.type('radio'), attr.name('attachments'), attr.value('pdf'), attachmentHandlers), ' PDFs'), ' ', dom.label(style({ whiteSpace: 'nowrap' }), attachmentArchive = dom.input(attr.type('radio'), attr.name('attachments'), attr.value('archive'), attachmentHandlers), ' Archives'), ' ', dom.label(style({ whiteSpace: 'nowrap' }), attachmentSpreadsheet = dom.input(attr.type('radio'), attr.name('attachments'), attr.value('spreadsheet'), attachmentHandlers), ' Spreadsheets'), ' ', dom.label(style({ whiteSpace: 'nowrap' }), attachmentDocument = dom.input(attr.type('radio'), attr.name('attachments'), attr.value('document'), attachmentHandlers), ' Documents'), ' ', dom.label(style({ whiteSpace: 'nowrap' }), attachmentPresentation = dom.input(attr.type('radio'), attr.name('attachments'), attr.value('presentation'), attachmentHandlers), ' Presentations'), ' ')), dom.tr(dom.td('Labels'), dom.td(style({ lineHeight: 2 }), join(flagViews = Object.entries({ Read: '\\Seen', Replied: '\\Answered', Flagged: '\\Flagged', Deleted: '\\Deleted', Draft: '\\Draft', Forwarded: '$Forwarded', Junk: '$Junk', NotJunk: '$NotJunk', Phishing: '$Phishing', MDNSent: '$MDNSent' }).map(t => {
		const [name, flag] = t;
		const v = {
			active: null,
			flag: flag,
			root: dom.clickbutton(name, function click() {
				if (v.active === null) {
					v.active = true;
				}
				else if (v.active === true) {
					v.active = false;
				}
				else {
					v.active = null;
				}
				v.update();
				updateSearchbar();
			}),
			update: () => {
				v.root.style.backgroundColor = v.active === true ? '#c4ffa9' : (v.active === false ? '#ffb192' : '');
			},
		};
		return v;
	}), () => ' '), ' ', labels = dom.input(focusPlaceholder('todo -done "-dashingname"'), attr.title('User-defined labels.'), changeHandlers))), dom.tr(dom.td('Headers'), headersCell = dom.td(headerViews = [newHeaderView(true)])), dom.tr(dom.td('Size between'), dom.td(minsize = dom.input(style({ width: '6em' }), focusPlaceholder('10kb'), changeHandlers), ' and ', maxsize = dom.input(style({ width: '6em' }), focusPlaceholder('1mb'), changeHandlers)))), dom.div(style({ padding: '1ex', textAlign: 'right' }), dom.submitbutton('Search')), async function submit(e) {
		e.preventDefault();
		await searchView.submit();
	})));
	const submit = async () => {
		const [f, notf, _] = parseSearch(searchbarElem.value, mailboxlistView);
		await startSearch(f, notf);
	};
	let loaded = false;
	const searchView = {
		root: root,
		submit: submit,
		ensureLoaded: () => {
			if (loaded || mailboxlistView.mailboxes().length === 0) {
				return;
			}
			loaded = true;
			dom._kids(mailbox, dom.option('All mailboxes except Trash/Junk/Rejects', attr.value('-1')), dom.option('All mailboxes', attr.value('0')), mailboxlistView.mailboxes().map(mb => dom.option(mb.Name, attr.value('' + mb.ID))));
			searchView.updateForm();
		},
		updateForm: updateForm,
	};
	return searchView;
};
// parse the "mailto:..." part (already decoded) of a "#compose mailto:..." url hash.
const parseComposeMailto = (mailto) => {
	const u = new URL(mailto);
	const addresses = (s) => s.split(',').filter(s => !!s);
	const opts = {};
	opts.to = addresses(u.pathname).map(s => decodeURIComponent(s));
	for (const [xk, v] of new URLSearchParams(u.search)) {
		const k = xk.toLowerCase();
		if (k === 'to') {
			opts.to = [...opts.to, ...addresses(v)];
		}
		else if (k === 'cc') {
			opts.cc = [...(opts.cc || []), ...addresses(v)];
		}
		else if (k === 'bcc') {
			opts.bcc = [...(opts.bcc || []), ...addresses(v)];
		}
		else if (k === 'subject') {
			// q/b-word encoding is allowed, we let the server decode when we start composoing,
			// only if needed. ../rfc/6068:267
			opts.subject = v;
		}
		else if (k === 'body') {
			opts.body = v;
		}
		// todo: we ignore other headers for now. we should handle in-reply-to and references at some point. but we don't allow any custom headers at the time of writing.
	}
	return opts;
};
const init = async () => {
	let connectionElem; // SSE connection status/error. Empty when connected.
	let layoutElem; // Select dropdown for layout.
	let loginAddressElem;
	let msglistscrollElem;
	let queryactivityElem; // We show ... when a query is active and data is forthcoming.
	// Shown at the bottom of msglistscrollElem, immediately below the msglistView, when appropriate.
	const listendElem = dom.div(style({ borderTop: '1px solid #ccc', color: '#666', margin: '1ex' }));
	const listloadingElem = dom.div(style({ textAlign: 'center', padding: '.15em 0', color: '#333', border: '1px solid #ccc', margin: '1ex', backgroundColor: '#f8f8f8' }), 'loading...');
	const listerrElem = dom.div(style({ textAlign: 'center', padding: '.15em 0', color: '#333', border: '1px solid #ccc', margin: '1ex', backgroundColor: '#f8f8f8' }));
	let sseID = 0; // Sent by server in initial SSE response. We use it in API calls to make the SSE endpoint return new data we need.
	let viewSequence = 0; // Counter for assigning viewID.
	let viewID = 0; // Updated when a new view is started, e.g. when opening another mailbox or starting a search.
	let search = {
		active: false,
		query: '', // The query, as shown in the searchbar. Used in location hash.
	};
	let requestSequence = 0; // Counter for assigning requestID.
	let requestID = 0; // Current request, server will mirror it in SSE data. If we get data for a different id, we ignore it.
	let requestAnchorMessageID = 0; // For pagination.
	let requestViewEnd = false; // If true, there is no more data to fetch, no more page needed for this view.
	let requestFilter = newFilter();
	let requestNotFilter = newNotFilter();
	let requestMsgID = 0; // If > 0, we are still expecting a parsed message for the view, coming from the query. Either we get it and set msgitemViewActive and clear this, or we get to the end of the data and clear it.
	const updatePageTitle = () => {
		const mb = mailboxlistView && mailboxlistView.activeMailbox();
		const addr = loginAddress ? loginAddress.User + '@' + formatDomain(loginAddress.Domain) : '';
		if (!mb) {
			document.title = [addr, 'Mox Webmail'].join(' - ');
		}
		else {
			document.title = ['(' + mb.Unread + ') ' + mb.Name, addr, 'Mox Webmail'].join(' - ');
		}
	};
	const setLocationHash = () => {
		const msgid = requestMsgID || msglistView.activeMessageID();
		const msgidstr = msgid ? ',' + msgid : '';
		let hash;
		const mb = mailboxlistView && mailboxlistView.activeMailbox();
		if (mb) {
			hash = '#' + mb.Name + msgidstr;
		}
		else if (search.active) {
			hash = '#search ' + search.query + msgidstr;
		}
		else {
			hash = '#';
		}
		// We need to set the full URL or we would get errors about insecure operations for
		// plain http with firefox.
		const l = window.location;
		const url = l.protocol + '//' + l.host + l.pathname + l.search + hash;
		window.history.replaceState(undefined, '', url);
	};
	const loadSearch = (q) => {
		search = { active: true, query: q };
		searchbarElem.value = q;
		searchbarElem.style.background = 'linear-gradient(135deg, #ffc7ab 0%, #ffdeab 100%)'; // Cleared when another view is loaded.
		searchbarElemBox.style.flexGrow = '4';
	};
	const unloadSearch = () => {
		searchbarElem.value = '';
		searchbarElem.style.background = '';
		searchbarElem.style.zIndex = '';
		searchbarElemBox.style.flexGrow = ''; // Make search bar smaller again.
		search = { active: false, query: '' };
		searchView.root.remove();
	};
	const clearList = () => {
		msglistView.clear();
		listendElem.remove();
		listloadingElem.remove();
		listerrElem.remove();
	};
	const requestNewView = async (clearMsgID, filterOpt, notFilterOpt) => {
		if (!sseID) {
			throw new Error('not connected');
		}
		if (clearMsgID) {
			requestMsgID = 0;
		}
		msglistView.root.classList.toggle('loading', true);
		clearList();
		viewSequence++;
		viewID = viewSequence;
		if (filterOpt) {
			requestFilter = filterOpt;
			requestNotFilter = notFilterOpt || newNotFilter();
		}
		requestAnchorMessageID = 0;
		requestViewEnd = false;
		const bounds = msglistscrollElem.getBoundingClientRect();
		await requestMessages(bounds, requestMsgID);
	};
	const requestMessages = async (scrollBounds, destMessageID) => {
		const fetchCount = Math.max(50, 3 * Math.ceil(scrollBounds.height / msglistView.itemHeight()));
		const page = {
			AnchorMessageID: requestAnchorMessageID,
			Count: fetchCount,
			DestMessageID: destMessageID,
		};
		requestSequence++;
		requestID = requestSequence;
		const [f, notf] = refineFilters(requestFilter, requestNotFilter);
		const query = {
			OrderAsc: settings.orderAsc,
			Threading: settings.threading,
			Filter: f,
			NotFilter: notf,
		};
		const request = {
			ID: requestID,
			SSEID: sseID,
			ViewID: viewID,
			Cancel: false,
			Query: query,
			Page: page,
		};
		dom._kids(queryactivityElem, 'loading...');
		msglistscrollElem.appendChild(listloadingElem);
		await client.Request(request);
	};
	// msgElem can show a message, show actions on multiple messages, or be empty.
	let msgElem = dom.div(style({ position: 'absolute', right: 0, left: 0, top: 0, bottom: 0 }), style({ backgroundColor: '#f8f8f8' }));
	// Returns possible labels based, either from active mailbox (possibly from search), or all mailboxes.
	const possibleLabels = () => {
		if (requestFilter.MailboxID > 0) {
			const mb = mailboxlistView.findMailboxByID(requestFilter.MailboxID);
			if (mb) {
				return mb.Keywords || [];
			}
		}
		const all = {};
		mailboxlistView.mailboxes().forEach(mb => {
			for (const k of (mb.Keywords || [])) {
				all[k] = undefined;
			}
		});
		const l = Object.keys(all);
		l.sort();
		return l;
	};
	const refineKeyword = async (kw) => {
		settingsPut({ ...settings, refine: 'label:' + kw });
		refineToggleActive(refineLabelBtn);
		dom._kids(refineLabelBtn, 'Label: ' + kw);
		await withStatus('Requesting messages', requestNewView(false));
	};
	const viewportEnsureMessages = async () => {
		// We know how many entries we have, and how many screenfulls. So we know when we
		// only have 2 screen fulls left. That's when we request the next data.
		const bounds = msglistscrollElem.getBoundingClientRect();
		if (msglistscrollElem.scrollTop < msglistscrollElem.scrollHeight - 3 * bounds.height) {
			return;
		}
		// log('new request for scroll')
		await withStatus('Requesting more messages', requestMessages(bounds, 0));
	};
	const otherMailbox = (mailboxID) => requestFilter.MailboxID !== mailboxID ? (mailboxlistView.findMailboxByID(mailboxID) || null) : null;
	const listMailboxes = () => mailboxlistView.mailboxes();
	const msglistView = newMsglistView(msgElem, listMailboxes, setLocationHash, otherMailbox, possibleLabels, () => msglistscrollElem ? msglistscrollElem.getBoundingClientRect().height : 0, refineKeyword, viewportEnsureMessages);
	const mailboxlistView = newMailboxlistView(msglistView, requestNewView, updatePageTitle, setLocationHash, unloadSearch, otherMailbox);
	let refineUnreadBtn, refineReadBtn, refineAttachmentsBtn, refineLabelBtn;
	const refineToggleActive = (btn) => {
		for (const e of [refineUnreadBtn, refineReadBtn, refineAttachmentsBtn, refineLabelBtn]) {
			e.classList.toggle('active', e === btn);
		}
		if (btn !== null && btn !== refineLabelBtn) {
			dom._kids(refineLabelBtn, 'Label');
		}
	};
	let threadMode;
	let msglistElem = dom.div(dom._class('msglist'), style({ position: 'absolute', left: '0', right: 0, top: 0, bottom: 0, display: 'flex', flexDirection: 'column' }), dom.div(attr.role('region'), attr.arialabel('Filter and sorting buttons for message list'), style({ display: 'flex', justifyContent: 'space-between', backgroundColor: '#f8f8f8', borderBottom: '1px solid #ccc', padding: '.25em .5em' }), dom.div(dom.h1('Refine:', style({ fontWeight: 'normal', fontSize: 'inherit', display: 'inline', margin: 0 }), attr.title('Refine message listing with quick filters. These refinement filters are in addition to any search criteria, but the refine attachment filter overrides a search attachment criteria.')), ' ', dom.span(dom._class('btngroup'), refineUnreadBtn = dom.clickbutton(settings.refine === 'unread' ? dom._class('active') : [], 'Unread', attr.title('Only show messages marked as unread.'), async function click(e) {
		settingsPut({ ...settings, refine: 'unread' });
		refineToggleActive(e.target);
		await withStatus('Requesting messages', requestNewView(false));
	}), refineReadBtn = dom.clickbutton(settings.refine === 'read' ? dom._class('active') : [], 'Read', attr.title('Only show messages marked as read.'), async function click(e) {
		settingsPut({ ...settings, refine: 'read' });
		refineToggleActive(e.target);
		await withStatus('Requesting messages', requestNewView(false));
	}), refineAttachmentsBtn = dom.clickbutton(settings.refine === 'attachments' ? dom._class('active') : [], 'Attachments', attr.title('Only show messages with attachments.'), async function click(e) {
		settingsPut({ ...settings, refine: 'attachments' });
		refineToggleActive(e.target);
		await withStatus('Requesting messages', requestNewView(false));
	}), refineLabelBtn = dom.clickbutton(settings.refine.startsWith('label:') ? [dom._class('active'), 'Label: ' + settings.refine.substring('label:'.length)] : 'Label', attr.title('Only show messages with the selected label.'), async function click(e) {
		const labels = possibleLabels();
		const remove = popover(e.target, {}, dom.div(style({ display: 'flex', flexDirection: 'column', gap: '1ex' }), labels.map(l => {
			const selectLabel = async () => {
				settingsPut({ ...settings, refine: 'label:' + l });
				refineToggleActive(e.target);
				dom._kids(refineLabelBtn, 'Label: ' + l);
				await withStatus('Requesting messages', requestNewView(false));
				remove();
			};
			return dom.div(dom.clickbutton(dom._class('keyword'), l, async function click() {
				await selectLabel();
			}));
		}), labels.length === 0 ? dom.div('No labels yet, set one on a message first.') : []));
	})), ' ', dom.clickbutton('x', style({ padding: '0 .25em' }), attr.arialabel('Clear refinement filters.'), attr.title('Clear refinement filters.'), async function click(e) {
		settingsPut({ ...settings, refine: '' });
		refineToggleActive(e.target);
		await withStatus('Requesting messages', requestNewView(false));
	})), dom.div(queryactivityElem = dom.span(), ' ', threadMode = dom.select(attr.arialabel('Thread modes.'), attr.title('Off: Threading disabled, messages are shown individually.\nOn: Group messages in threads, expanded by default except when (previously) manually collapsed.\nUnread: Only expand thread with unread messages, ignoring and not saving whether they were manually collapsed.'), dom.option('Threads: Off', attr.value(api.ThreadMode.ThreadOff), settings.threading === api.ThreadMode.ThreadOff ? attr.selected('') : []), dom.option('Threads: On', attr.value(api.ThreadMode.ThreadOn), settings.threading === api.ThreadMode.ThreadOn ? attr.selected('') : []), dom.option('Threads: Unread', attr.value(api.ThreadMode.ThreadUnread), settings.threading === api.ThreadMode.ThreadUnread ? attr.selected('') : []), async function change() {
		let reset = settings.threading === api.ThreadMode.ThreadOff;
		settingsPut({ ...settings, threading: threadMode.value });
		reset = reset || settings.threading === api.ThreadMode.ThreadOff;
		if (reset) {
			await withStatus('Requesting messages', requestNewView(false));
		}
		else {
			msglistView.threadToggle();
		}
	}), ' ', dom.clickbutton('↑↓', attr.title('Toggle sorting by date received.'), settings.orderAsc ? dom._class('invert') : [], async function click(e) {
		settingsPut({ ...settings, orderAsc: !settings.orderAsc });
		e.target.classList.toggle('invert', settings.orderAsc);
		// We don't want to include the currently selected message because it could cause a
		// huge amount of messages to be fetched. e.g. when first message in large mailbox
		// was selected, it would now be the last message.
		await withStatus('Requesting messages', requestNewView(true));
	}))), dom.div(style({ height: '1ex', position: 'relative' }), dom.div(dom._class('msgitemflags')), dom.div(dom._class('msgitemflagsoffset'), style({ position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize' }), dom.div(style({ position: 'absolute', top: 0, bottom: 0, width: '1px', backgroundColor: '#aaa', left: '2.5px' })), function mousedown(e) {
		startDrag(e, (e) => {
			const bounds = msglistscrollElem.getBoundingClientRect();
			const width = Math.round(e.clientX - bounds.x);
			settingsPut({ ...settings, msglistflagsWidth: width });
			updateMsglistWidths();
		});
	}), dom.div(dom._class('msgitemfrom')), dom.div(dom._class('msgitemfromoffset'), style({ position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize' }), dom.div(style({ position: 'absolute', top: 0, bottom: 0, width: '1px', backgroundColor: '#aaa', left: '2.5px' })), function mousedown(e) {
		startDrag(e, (e) => {
			const bounds = msglistscrollElem.getBoundingClientRect();
			const x = Math.round(e.clientX - bounds.x - lastflagswidth);
			const width = bounds.width - lastflagswidth - lastagewidth;
			const pct = 100 * x / width;
			settingsPut({ ...settings, msglistfromPct: pct });
			updateMsglistWidths();
		});
	}), dom.div(dom._class('msgitemsubject')), dom.div(dom._class('msgitemsubjectoffset'), style({ position: 'absolute', width: '6px', top: 0, bottom: 0, marginLeft: '-3px', cursor: 'ew-resize' }), dom.div(style({ position: 'absolute', top: 0, bottom: 0, width: '1px', backgroundColor: '#aaa', left: '2.5px' })), function mousedown(e) {
		startDrag(e, (e) => {
			const bounds = msglistscrollElem.getBoundingClientRect();
			const width = Math.round(bounds.x + bounds.width - e.clientX);
			settingsPut({ ...settings, msglistageWidth: width });
			updateMsglistWidths();
		});
	}), dom.div(dom._class('msgitemage'))), dom.div(style({ flexGrow: '1', position: 'relative' }), msglistscrollElem = dom.div(dom._class('yscroll'), attr.role('region'), attr.arialabel('Message list'), async function scroll() {
		if (!sseID || requestViewEnd || requestID) {
			return;
		}
		await viewportEnsureMessages();
	}, dom.div(style({ width: '100%', borderSpacing: '0' }), msglistView))));
	let searchbarElem; // Input field for search
	// Called by searchView when user executes the search.
	const startSearch = async (f, notf) => {
		if (!sseID) {
			window.alert('Error: not connect');
			return;
		}
		// If search has an attachment filter, clear it from the quick filter or we will
		// confuse the user with no matches. The refinement would override the selection.
		if (f.Attachments !== '' && settings.refine === 'attachments') {
			settingsPut({ ...settings, refine: '' });
			refineToggleActive(null);
		}
		search = { active: true, query: searchbarElem.value };
		mailboxlistView.closeMailbox();
		setLocationHash();
		searchbarElem.style.background = 'linear-gradient(135deg, #ffc7ab 0%, #ffdeab 100%)'; // Cleared when another view is loaded.
		searchView.root.remove();
		searchbarElem.blur();
		document.body.focus();
		await withStatus('Requesting messages', requestNewView(true, f, notf));
	};
	// Called by searchView when it is closed, due to escape key or click on background.
	const searchViewClose = () => {
		if (!search.active) {
			unloadSearch();
		}
		else {
			searchbarElem.value = search.query;
			searchView.root.remove();
		}
	};
	// For dragging.
	let mailboxesElem, topcomposeboxElem, mailboxessplitElem;
	let splitElem;
	let searchbarElemBox; // Detailed search form, opened when searchbarElem gets focused.
	const searchbarInitial = () => {
		const mailboxActive = mailboxlistView.activeMailbox();
		if (mailboxActive && mailboxActive.Name !== 'Inbox') {
			return packToken([false, 'mb', false, mailboxActive.Name]) + ' ';
		}
		return '';
	};
	const ensureSearchView = () => {
		if (searchView.root.parentElement) {
			// Already open.
			return;
		}
		searchView.ensureLoaded();
		const pos = searchbarElem.getBoundingClientRect();
		const child = searchView.root.firstChild;
		child.style.left = '' + pos.x + 'px';
		child.style.top = '' + (pos.y + pos.height + 2) + 'px';
		// Append to just after search input so next tabindex is at form.
		searchbarElem.parentElement.appendChild(searchView.root);
		// Make search bar as wide as possible. Made smaller when searchView is hidden again.
		searchbarElemBox.style.flexGrow = '4';
		searchbarElem.style.zIndex = zindexes.searchbar;
	};
	const cmdSearch = async () => {
		searchbarElem.focus();
		if (!searchbarElem.value) {
			searchbarElem.value = searchbarInitial();
		}
		ensureSearchView();
		searchView.updateForm();
	};
	const cmdCompose = async () => { compose({}); };
	const cmdOpenInbox = async () => {
		const mb = mailboxlistView.findMailboxByName('Inbox');
		if (mb) {
			await mailboxlistView.openMailboxID(mb.ID, true);
			const f = newFilter();
			f.MailboxID = mb.ID;
			await withStatus('Requesting messages', requestNewView(true, f, newNotFilter()));
		}
	};
	const cmdFocusMsg = async () => {
		const btn = msgElem.querySelector('button');
		if (btn && btn instanceof HTMLElement) {
			btn.focus();
		}
	};
	const shortcuts = {
		i: cmdOpenInbox,
		'/': cmdSearch,
		'?': cmdHelp,
		'ctrl ?': cmdTooltip,
		c: cmdCompose,
		'ctrl m': cmdFocusMsg,
	};
	const webmailroot = dom.div(style({ display: 'flex', flexDirection: 'column', alignContent: 'stretch', height: '100dvh' }), dom.div(dom._class('topbar'), style({ display: 'flex' }), attr.role('region'), attr.arialabel('Top bar'), topcomposeboxElem = dom.div(dom._class('pad'), style({ width: settings.mailboxesWidth + 'px', textAlign: 'center' }), dom.clickbutton('Compose', attr.title('Compose new email message.'), function click() {
		shortcutCmd(cmdCompose, shortcuts);
	})), dom.div(dom._class('pad'), style({ paddingLeft: 0, display: 'flex', flexGrow: 1 }), searchbarElemBox = dom.search(style({ display: 'flex', marginRight: '.5em' }), dom.form(style({ display: 'flex', flexGrow: 1 }), searchbarElem = dom.input(attr.placeholder('Search...'), style({ position: 'relative', width: '100%' }), attr.title('Search messages based on criteria like matching free-form text, in a mailbox, labels, addressees.'), focusPlaceholder('word "with space" -notword mb:Inbox f:from@x.example t:rcpt@x.example start:2023-7-1 end:2023-7-8 s:"subject" a:images l:$Forwarded h:Reply-To:other@x.example minsize:500kb'), function click() {
		cmdSearch();
		showShortcut('/');
	}, function focus() {
		// Make search bar as wide as possible. Made smaller when searchView is hidden again.
		searchbarElemBox.style.flexGrow = '4';
		if (!searchbarElem.value) {
			searchbarElem.value = searchbarInitial();
		}
	}, function blur() {
		if (searchbarElem.value === searchbarInitial()) {
			searchbarElem.value = '';
		}
		if (!search.active) {
			searchbarElemBox.style.flexGrow = '';
		}
	}, function change() {
		searchView.updateForm();
	}, function keyup(e) {
		if (e.key === 'Escape') {
			e.stopPropagation();
			searchViewClose();
			return;
		}
		if (searchbarElem.value && searchbarElem.value !== searchbarInitial()) {
			ensureSearchView();
		}
		searchView.updateForm();
	}), dom.clickbutton('x', attr.arialabel('Cancel and clear search and open Inbox.'), attr.title('Cancel and clear search and open Inbox.'), style({ marginLeft: '.25em', padding: '0 .3em' }), async function click() {
		searchbarElem.value = '';
		if (!search.active) {
			return;
		}
		const mb = mailboxlistView.findMailboxByName('Inbox');
		if (!mb) {
			window.alert('Cannot find inbox.');
			return;
		}
		await mailboxlistView.openMailboxID(mb.ID, true);
		const f = newFilter();
		f.MailboxID = mb.ID;
		await withStatus('Requesting messages', requestNewView(true, f, newNotFilter()));
	}), async function submit(e) {
		e.preventDefault();
		await searchView.submit();
	})), connectionElem = dom.div(), statusElem = dom.div(style({ marginLeft: '.5em', flexGrow: '1' }), attr.role('status')), dom.div(style({ paddingLeft: '1em' }), layoutElem = dom.select(attr.title('Layout of message list and message panes. Top/bottom has message list above message view. Left/Right has message list left, message view right. Auto selects based on window width and automatically switches on resize. Wide screens get left/right, smaller screens get top/bottom.'), dom.option('Auto layout', attr.value('auto'), settings.layout === 'auto' ? attr.selected('') : []), dom.option('Top/bottom', attr.value('topbottom'), settings.layout === 'topbottom' ? attr.selected('') : []), dom.option('Left/right', attr.value('leftright'), settings.layout === 'leftright' ? attr.selected('') : []), function change() {
		settingsPut({ ...settings, layout: layoutElem.value });
		if (layoutElem.value === 'auto') {
			autoselectLayout();
		}
		else {
			selectLayout(layoutElem.value);
		}
	}), ' ', dom.clickbutton('Tooltip', attr.title('Show tooltips, based on the title attributes (underdotted text) for the focused element and all user interface elements below it. Use the keyboard shortcut "ctrl ?" instead of clicking on the tooltip button, which changes focus to the tooltip button.'), clickCmd(cmdTooltip, shortcuts)), ' ', dom.clickbutton('Help', attr.title('Show popup with basic usage information and a keyboard shortcuts.'), clickCmd(cmdHelp, shortcuts)), ' ', loginAddressElem = dom.span(), ' ', dom.clickbutton('Logout', attr.title('Logout, invalidating this session.'), async function click(e) {
		await withStatus('Logging out', client.Logout(), e.target);
		localStorageRemove('webmailcsrftoken');
		if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
		// Reload so all state is cleared from memory.
		window.location.reload();
	})))), dom.div(style({ flexGrow: '1' }), style({ position: 'relative' }), mailboxesElem = dom.div(dom._class('mailboxesbar'), style({ position: 'absolute', left: 0, width: settings.mailboxesWidth + 'px', top: 0, bottom: 0 }), style({ display: 'flex', flexDirection: 'column', alignContent: 'stretch' }), dom.div(dom._class('pad', 'yscrollauto'), style({ flexGrow: '1' }), style({ position: 'relative' }), mailboxlistView.root)), mailboxessplitElem = dom.div(style({ position: 'absolute', left: 'calc(' + settings.mailboxesWidth + 'px - 2px)', width: '5px', top: 0, bottom: 0, cursor: 'ew-resize', zIndex: zindexes.splitter }), dom.div(style({ position: 'absolute', width: '1px', top: 0, bottom: 0, left: '2px', right: '2px', backgroundColor: '#aaa' })), function mousedown(e) {
		startDrag(e, (e) => {
			mailboxesElem.style.width = Math.round(e.clientX) + 'px';
			topcomposeboxElem.style.width = Math.round(e.clientX) + 'px';
			mailboxessplitElem.style.left = 'calc(' + e.clientX + 'px - 2px)';
			splitElem.style.left = 'calc(' + e.clientX + 'px + 1px)';
			settingsPut({ ...settings, mailboxesWidth: Math.round(e.clientX) });
		});
	}), splitElem = dom.div(style({ position: 'absolute', left: 'calc(' + settings.mailboxesWidth + 'px + 1px)', right: 0, top: 0, bottom: 0, borderTop: '1px solid #bbb' }))));
	// searchView is shown when search gets focus.
	const searchView = newSearchView(searchbarElem, mailboxlistView, startSearch, searchViewClose);
	document.body.addEventListener('keydown', async (e) => {
		// Don't do anything for just the press of the modifiers.
		switch (e.key) {
			case 'OS':
			case 'Control':
			case 'Shift':
			case 'Alt':
				return;
		}
		// Popup have their own handlers, e.g. for scrolling.
		if (popupOpen) {
			return;
		}
		// Prevent many regular key presses from being processed, some possibly unintended.
		if ((e.target instanceof window.HTMLInputElement || e.target instanceof window.HTMLTextAreaElement || e.target instanceof window.HTMLSelectElement) && !e.ctrlKey && !e.altKey && !e.metaKey) {
			// log('skipping key without modifiers on input/textarea')
			return;
		}
		let l = [];
		if (e.ctrlKey) {
			l.push('ctrl');
		}
		if (e.altKey) {
			l.push('alt');
		}
		if (e.metaKey) {
			l.push('meta');
		}
		l.push(e.key);
		const k = l.join(' ');
		if (attachmentView) {
			attachmentView.key(k, e);
			return;
		}
		if (composeView) {
			await composeView.key(k, e);
			return;
		}
		const cmdfn = shortcuts[k];
		if (cmdfn) {
			e.preventDefault();
			e.stopPropagation();
			await cmdfn();
			return;
		}
		msglistView.key(k, e);
	});
	let currentLayout = '';
	const selectLayout = (want) => {
		if (want === currentLayout) {
			return;
		}
		if (want === 'leftright') {
			let left, split, right;
			dom._kids(splitElem, left = dom.div(style({ position: 'absolute', left: 0, width: 'calc(' + settings.leftWidthPct + '% - 1px)', top: 0, bottom: 0 }), msglistElem), split = dom.div(style({ position: 'absolute', left: 'calc(' + settings.leftWidthPct + '% - 2px)', width: '5px', top: 0, bottom: 0, cursor: 'ew-resize', zIndex: zindexes.splitter }), dom.div(style({ position: 'absolute', backgroundColor: '#aaa', top: 0, bottom: 0, width: '1px', left: '2px', right: '2px' })), function mousedown(e) {
				startDrag(e, (e) => {
					const bounds = left.getBoundingClientRect();
					const x = Math.round(e.clientX - bounds.x);
					left.style.width = 'calc(' + x + 'px - 1px)';
					split.style.left = 'calc(' + x + 'px - 2px)';
					right.style.left = 'calc(' + x + 'px + 1px)';
					settingsPut({ ...settings, leftWidthPct: Math.round(100 * bounds.width / splitElem.getBoundingClientRect().width) });
					updateMsglistWidths();
				});
			}), right = dom.div(style({ position: 'absolute', right: 0, left: 'calc(' + settings.leftWidthPct + '% + 1px)', top: 0, bottom: 0 }), msgElem));
		}
		else {
			let top, split, bottom;
			dom._kids(splitElem, top = dom.div(style({ position: 'absolute', top: 0, height: 'calc(' + settings.topHeightPct + '% - 1px)', left: 0, right: 0 }), msglistElem), split = dom.div(style({ position: 'absolute', top: 'calc(' + settings.topHeightPct + '% - 2px)', height: '5px', left: '0', right: '0', cursor: 'ns-resize', zIndex: zindexes.splitter }), dom.div(style({ position: 'absolute', backgroundColor: '#aaa', left: 0, right: 0, height: '1px', top: '2px', bottom: '2px' })), function mousedown(e) {
				startDrag(e, (e) => {
					const bounds = top.getBoundingClientRect();
					const y = Math.round(e.clientY - bounds.y);
					top.style.height = 'calc(' + y + 'px - 1px)';
					split.style.top = 'calc(' + y + 'px - 2px)';
					bottom.style.top = 'calc(' + y + 'px + 1px)';
					settingsPut({ ...settings, topHeightPct: Math.round(100 * bounds.height / splitElem.getBoundingClientRect().height) });
				});
			}), bottom = dom.div(style({ position: 'absolute', bottom: 0, top: 'calc(' + settings.topHeightPct + '% + 1px)', left: 0, right: 0 }), msgElem));
		}
		currentLayout = want;
		checkMsglistWidth();
	};
	const autoselectLayout = () => {
		const want = window.innerWidth <= 2 * 2560 / 3 ? 'topbottom' : 'leftright';
		selectLayout(want);
	};
	// When the window size or layout changes, we recalculate the desired widths for
	// the msglist "table". It is a list of divs, each with flex layout with 4 elements
	// of fixed size.
	// Cannot use the CSSStyleSheet constructor with its replaceSync method because
	// safari only started implementing it in 2023q1. So we do it the old-fashioned
	// way, inserting a style element and updating its style.
	const styleElem = dom.style(attr.type('text/css'));
	document.head.appendChild(styleElem);
	const stylesheet = styleElem.sheet;
	let lastmsglistwidth = -1;
	const checkMsglistWidth = () => {
		const width = msglistscrollElem.getBoundingClientRect().width;
		if (lastmsglistwidth === width || width <= 0) {
			return;
		}
		updateMsglistWidths();
	};
	let lastflagswidth, lastagewidth;
	let rulesInserted = false;
	const updateMsglistWidths = () => {
		const width = msglistscrollElem.clientWidth - 2; // Borders.
		lastmsglistwidth = width;
		let flagswidth = settings.msglistflagsWidth;
		let agewidth = settings.msglistageWidth;
		let frompct = settings.msglistfromPct; // Of remaining space.
		if (flagswidth + agewidth > width) {
			flagswidth = Math.floor(width / 2);
			agewidth = width - flagswidth;
		}
		const remain = width - (flagswidth + agewidth);
		const fromwidth = Math.floor(frompct * remain / 100);
		const subjectwidth = Math.floor(remain - fromwidth);
		const cssRules = [
			['.msgitemflags', { width: flagswidth }],
			['.msgitemfrom', { width: fromwidth }],
			['.msgitemsubject', { width: subjectwidth }],
			['.msgitemage', { width: agewidth }],
			['.msgitemflagsoffset', { left: flagswidth }],
			['.msgitemfromoffset', { left: flagswidth + fromwidth }],
			['.msgitemsubjectoffset', { left: flagswidth + fromwidth + subjectwidth }],
		];
		if (!rulesInserted) {
			cssRules.forEach((rule, i) => { stylesheet.insertRule(rule[0] + '{}', i); });
			rulesInserted = true;
		}
		cssRules.forEach((rule, i) => {
			const r = stylesheet.cssRules[i];
			for (const k in rule[1]) {
				r.style.setProperty(k, '' + rule[1][k] + 'px');
			}
		});
		lastflagswidth = flagswidth;
		lastagewidth = agewidth;
	};
	// Select initial layout.
	if (layoutElem.value === 'auto') {
		autoselectLayout();
	}
	else {
		selectLayout(layoutElem.value);
	}
	dom._kids(page, webmailroot);
	checkMsglistWidth();
	window.addEventListener('resize', function () {
		if (layoutElem.value === 'auto') {
			autoselectLayout();
		}
		checkMsglistWidth();
	});
	window.addEventListener('hashchange', async (e) => {
		const hash = decodeURIComponent(window.location.hash);
		if (hash.startsWith('#compose ')) {
			try {
				const opts = parseComposeMailto(hash.substring('#compose '.length));
				// Restore previous hash.
				if (e.oldURL) {
					const ou = new URL(e.oldURL);
					window.location.hash = ou.hash;
				}
				else {
					window.location.hash = '';
				}
				(async () => {
					// Resolve Q/B-word mime encoding for subject. ../rfc/6068:267 ../rfc/2047:180
					if (opts.subject && opts.subject.includes('=?')) {
						opts.subject = await withStatus('Decoding MIME words for subject', client.DecodeMIMEWords(opts.subject));
					}
					compose(opts);
				})();
			}
			catch (err) {
				window.alert('Error parsing compose mailto URL: ' + errmsg(err));
				window.location.hash = '';
			}
			return;
		}
		const [search, msgid, f, notf] = parseLocationHash(mailboxlistView);
		requestMsgID = msgid;
		if (search) {
			mailboxlistView.closeMailbox();
			loadSearch(search);
		}
		else {
			unloadSearch();
			await mailboxlistView.openMailboxID(f.MailboxID, false);
		}
		await withStatus('Requesting messages', requestNewView(false, f, notf));
	});
	let eventSource = null; // If set, we have a connection.
	let connecting = false; // Check before reconnecting.
	let noreconnect = false; // Set after one reconnect attempt fails.
	let noreconnectTimer = 0; // Timer ID for resetting noreconnect.
	// Don't show disconnection just before user navigates away.
	let leaving = false;
	window.addEventListener('beforeunload', () => {
		leaving = true;
		if (eventSource) {
			eventSource.close();
			eventSource = null;
			sseID = 0;
		}
	});
	// On chromium, we may get restored when user hits the back button ("bfcache"). We
	// have left, closed the connection, so we should restore it.
	window.addEventListener('pageshow', async (e) => {
		if (e.persisted && !eventSource && !connecting) {
			noreconnect = false;
			connect(false);
		}
	});
	// If user comes back to tab/window, and we are disconnected, try another reconnect.
	window.addEventListener('focus', () => {
		if (!eventSource && !connecting) {
			noreconnect = false;
			connect(true);
		}
	});
	const showNotConnected = () => {
		dom._kids(connectionElem, attr.role('status'), dom.span(style({ backgroundColor: '#ffa9a9', padding: '0 .15em', borderRadius: '.15em' }), 'Not connected', attr.title('Not receiving real-time updates, including of new deliveries.')), ' ', dom.clickbutton('Reconnect', function click() {
			if (!eventSource && !connecting) {
				noreconnect = false;
				connect(true);
			}
		}));
	};
	const capitalizeFirst = (s) => s.charAt(0).toUpperCase() + s.slice(1);
	// Set to compose options when we were opened with a mailto URL. We open the
	// compose window after we received the "start" message with our addresses.
	let openComposeOptions;
	const connect = async (isreconnect) => {
		connectionElem.classList.toggle('loading', true);
		dom._kids(connectionElem);
		connectionElem.classList.toggle('loading', false);
		// We'll clear noreconnect when we've held a connection for 10 mins.
		noreconnect = isreconnect;
		connecting = true;
		let token;
		try {
			token = await withStatus('Fetching token for connection with real-time updates', client.Token(), undefined, true);
		}
		catch (err) {
			connecting = false;
			noreconnect = true;
			dom._kids(statusElem, (capitalizeFirst(err.message || 'Error fetching connection token')) + ', not automatically retrying. ');
			showNotConnected();
			return;
		}
		const h = decodeURIComponent(window.location.hash);
		if (h.startsWith('#compose ')) {
			try {
				// The compose window is opened when we get the "start" event, which gives us our
				// configuration.
				openComposeOptions = parseComposeMailto(h.substring('#compose '.length));
			}
			catch (err) {
				window.alert('Error parsing mailto URL: ' + errmsg(err));
			}
			window.location.hash = '';
		}
		let [searchQuery, msgid, f, notf] = parseLocationHash(mailboxlistView);
		requestMsgID = msgid;
		requestFilter = f;
		requestNotFilter = notf;
		if (searchQuery) {
			loadSearch(searchQuery);
		}
		[f, notf] = refineFilters(requestFilter, requestNotFilter);
		const fetchCount = Math.max(50, 3 * Math.ceil(msglistscrollElem.getBoundingClientRect().height / msglistView.itemHeight()));
		const query = {
			OrderAsc: settings.orderAsc,
			Threading: settings.threading,
			Filter: f,
			NotFilter: notf,
		};
		const page = {
			AnchorMessageID: 0,
			Count: fetchCount,
			DestMessageID: msgid,
		};
		viewSequence++;
		viewID = viewSequence;
		// We get an implicit query for the automatically selected mailbox or query.
		requestSequence++;
		requestID = requestSequence;
		requestAnchorMessageID = 0;
		requestViewEnd = false;
		clearList();
		const request = {
			ID: requestID,
			// A new SSEID is created by the server, sent in the initial response message.
			ViewID: viewID,
			Query: query,
			Page: page,
		};
		let slow = '';
		try {
			const debug = JSON.parse(localStorage.getItem('sherpats-debug') || 'null');
			if (debug && debug.waitMinMsec && debug.waitMaxMsec) {
				slow = '&waitMinMsec=' + debug.waitMinMsec + '&waitMaxMsec=' + debug.waitMaxMsec;
			}
		}
		catch (err) { }
		eventSource = new window.EventSource('events?token=' + encodeURIComponent(token) + '&request=' + encodeURIComponent(JSON.stringify(request)) + slow);
		let eventID = window.setTimeout(() => dom._kids(statusElem, 'Connecting... '), 1000);
		eventSource.addEventListener('open', (e) => {
			log('eventsource open', { e });
			if (eventID) {
				window.clearTimeout(eventID);
				eventID = 0;
			}
			dom._kids(statusElem);
			dom._kids(connectionElem);
		});
		const sseError = (errmsg) => {
			sseID = 0;
			eventSource.close();
			eventSource = null;
			connecting = false;
			if (noreconnectTimer) {
				clearTimeout(noreconnectTimer);
				noreconnectTimer = 0;
			}
			if (leaving) {
				return;
			}
			if (eventID) {
				window.clearTimeout(eventID);
				eventID = 0;
			}
			document.title = ['(not connected)', loginAddress ? (loginAddress.User + '@' + formatDomain(loginAddress.Domain)) : '', 'Mox Webmail'].filter(s => s).join(' - ');
			dom._kids(connectionElem);
			if (noreconnect) {
				dom._kids(statusElem, capitalizeFirst(errmsg) + ', not automatically retrying. ');
				showNotConnected();
				listloadingElem.remove();
				listendElem.remove();
			}
			else {
				connect(true);
			}
		};
		// EventSource-connection error. No details.
		eventSource.addEventListener('error', (e) => {
			log('eventsource error', { e }, JSON.stringify(e));
			sseError('Connection failed');
		});
		// Fatal error on the server side, error message propagated, but connection needs to be closed.
		eventSource.addEventListener('fatalErr', (e) => {
			const errmsg = JSON.parse(e.data) || '(no error message)';
			sseError('Server error: "' + errmsg + '"');
		});
		const checkParse = (fn) => {
			try {
				return fn();
			}
			catch (err) {
				window.alert('invalid event from server: ' + (err.message || '(no message)'));
				throw err;
			}
		};
		eventSource.addEventListener('start', (e) => {
			const data = JSON.parse(e.data);
			if (lastServerVersion && data.Version !== lastServerVersion) {
				if (window.confirm('Server has been updated to a new version. Reload?')) {
					window.location.reload();
					return;
				}
			}
			lastServerVersion = data.Version;
			const start = checkParse(() => api.parser.EventStart(data));
			log('event start', start);
			connecting = false;
			sseID = start.SSEID;
			loginAddress = start.LoginAddress;
			dom._kids(loginAddressElem, formatEmail(loginAddress));
			const loginAddr = formatEmail(loginAddress);
			accountAddresses = start.Addresses || [];
			accountAddresses.sort((a, b) => {
				if (formatEmail(a) === loginAddr) {
					return -1;
				}
				if (formatEmail(b) === loginAddr) {
					return 1;
				}
				if (a.Domain.ASCII !== b.Domain.ASCII) {
					return a.Domain.ASCII < b.Domain.ASCII ? -1 : 1;
				}
				return a.User < b.User ? -1 : 1;
			});
			domainAddressConfigs = start.DomainAddressConfigs || {};
			rejectsMailbox = start.RejectsMailbox;
			clearList();
			// If we were opened through a mailto: link, it's time to open the compose window.
			if (openComposeOptions) {
				(async () => {
					// Resolve Q/B-word mime encoding for subject. ../rfc/6068:267 ../rfc/2047:180
					if (openComposeOptions.subject && openComposeOptions.subject.includes('=?')) {
						openComposeOptions.subject = await withStatus('Decoding MIME words for subject', client.DecodeMIMEWords(openComposeOptions.subject));
					}
					compose(openComposeOptions);
					openComposeOptions = undefined;
				})();
			}
			let mailboxName = start.MailboxName;
			let mb = (start.Mailboxes || []).find(mb => mb.Name === start.MailboxName);
			if (mb) {
				requestFilter.MailboxID = mb.ID; // For check to display mailboxname in msgitemView.
			}
			if (mailboxName === '') {
				mailboxName = (start.Mailboxes || []).find(mb => mb.ID === requestFilter.MailboxID)?.Name || '';
			}
			mailboxlistView.loadMailboxes(start.Mailboxes || [], search.active ? undefined : mailboxName);
			if (searchView.root.parentElement) {
				searchView.ensureLoaded();
			}
			if (!mb) {
				updatePageTitle();
			}
			dom._kids(queryactivityElem, 'loading...');
			msglistscrollElem.appendChild(listloadingElem);
			noreconnectTimer = setTimeout(() => {
				noreconnect = false;
				noreconnectTimer = 0;
			}, 10 * 60 * 1000);
		});
		eventSource.addEventListener('viewErr', async (e) => {
			const viewErr = checkParse(() => api.parser.EventViewErr(JSON.parse(e.data)));
			log('event viewErr', viewErr);
			if (viewErr.ViewID !== viewID || viewErr.RequestID !== requestID) {
				log('received viewErr for other viewID or requestID', { expected: { viewID, requestID }, got: { viewID: viewErr.ViewID, requestID: viewErr.RequestID } });
				return;
			}
			viewID = 0;
			requestID = 0;
			dom._kids(queryactivityElem);
			listloadingElem.remove();
			listerrElem.remove();
			dom._kids(listerrElem, 'Error from server during request for messages: ' + viewErr.Err);
			msglistscrollElem.appendChild(listerrElem);
			window.alert('Error from server during request for messages: ' + viewErr.Err);
		});
		eventSource.addEventListener('viewReset', async (e) => {
			const viewReset = checkParse(() => api.parser.EventViewReset(JSON.parse(e.data)));
			log('event viewReset', viewReset);
			if (viewReset.ViewID !== viewID || viewReset.RequestID !== requestID) {
				log('received viewReset for other viewID or requestID', { expected: { viewID, requestID }, got: { viewID: viewReset.ViewID, requestID: viewReset.RequestID } });
				return;
			}
			clearList();
			dom._kids(queryactivityElem, 'loading...');
			msglistscrollElem.appendChild(listloadingElem);
			window.alert('Could not find message to continue scrolling, resetting the view.');
		});
		eventSource.addEventListener('viewMsgs', async (e) => {
			const viewMsgs = checkParse(() => api.parser.EventViewMsgs(JSON.parse(e.data)));
			log('event viewMsgs', viewMsgs);
			if (viewMsgs.ViewID !== viewID || viewMsgs.RequestID !== requestID) {
				log('received viewMsgs for other viewID or requestID', { expected: { viewID, requestID }, got: { viewID: viewMsgs.ViewID, requestID: viewMsgs.RequestID } });
				return;
			}
			msglistView.root.classList.toggle('loading', false);
			if (viewMsgs.MessageItems) {
				msglistView.addMessageItems(viewMsgs.MessageItems || [], false, requestMsgID);
			}
			if (viewMsgs.ParsedMessage) {
				const ok = msglistView.openMessage(viewMsgs.ParsedMessage);
				if (!ok) {
					// Should not happen, server would be sending a parsedmessage while not including the message itself.
					requestMsgID = 0;
					setLocationHash();
				}
			}
			if (viewMsgs.MessageItems && viewMsgs.MessageItems.length > 0) {
				requestAnchorMessageID = viewMsgs.MessageItems[viewMsgs.MessageItems.length - 1][0].Message.ID;
			}
			requestViewEnd = viewMsgs.ViewEnd;
			if (requestViewEnd) {
				msglistscrollElem.appendChild(listendElem);
			}
			if ((viewMsgs.MessageItems || []).length === 0 || requestViewEnd) {
				dom._kids(queryactivityElem);
				listloadingElem.remove();
				requestID = 0;
				if (requestMsgID) {
					requestMsgID = 0;
					setLocationHash();
				}
			}
		});
		eventSource.addEventListener('viewChanges', async (e) => {
			const viewChanges = checkParse(() => api.parser.EventViewChanges(JSON.parse(e.data)));
			log('event viewChanges', viewChanges);
			if (viewChanges.ViewID !== viewID) {
				log('received viewChanges for other viewID', { expected: viewID, got: viewChanges.ViewID });
				return;
			}
			try {
				(viewChanges.Changes || []).forEach(tc => {
					if (!tc) {
						return;
					}
					const [tag, x] = tc;
					if (tag === 'ChangeMailboxCounts') {
						const c = api.parser.ChangeMailboxCounts(x);
						mailboxlistView.setMailboxCounts(c.MailboxID, c.Total, c.Unread);
					}
					else if (tag === 'ChangeMailboxSpecialUse') {
						const c = api.parser.ChangeMailboxSpecialUse(x);
						mailboxlistView.setMailboxSpecialUse(c.MailboxID, c.SpecialUse);
					}
					else if (tag === 'ChangeMailboxKeywords') {
						const c = api.parser.ChangeMailboxKeywords(x);
						mailboxlistView.setMailboxKeywords(c.MailboxID, c.Keywords || []);
					}
					else if (tag === 'ChangeMsgAdd') {
						const c = api.parser.ChangeMsgAdd(x);
						msglistView.addMessageItems([c.MessageItems || []], true, 0);
					}
					else if (tag === 'ChangeMsgRemove') {
						const c = api.parser.ChangeMsgRemove(x);
						msglistView.removeUIDs(c.MailboxID, c.UIDs || []);
					}
					else if (tag === 'ChangeMsgFlags') {
						const c = api.parser.ChangeMsgFlags(x);
						msglistView.updateFlags(c.MailboxID, c.UID, c.ModSeq, c.Mask, c.Flags, c.Keywords || []);
					}
					else if (tag === 'ChangeMsgThread') {
						const c = api.parser.ChangeMsgThread(x);
						if (c.MessageIDs) {
							msglistView.updateMessageThreadFields(c.MessageIDs, c.Muted, c.Collapsed);
						}
					}
					else if (tag === 'ChangeMailboxRemove') {
						const c = api.parser.ChangeMailboxRemove(x);
						mailboxlistView.removeMailbox(c.MailboxID);
					}
					else if (tag === 'ChangeMailboxAdd') {
						const c = api.parser.ChangeMailboxAdd(x);
						mailboxlistView.addMailbox(c.Mailbox);
					}
					else if (tag === 'ChangeMailboxRename') {
						const c = api.parser.ChangeMailboxRename(x);
						mailboxlistView.renameMailbox(c.MailboxID, c.NewName);
					}
					else {
						throw new Error('unknown change tag ' + tag);
					}
				});
			}
			catch (err) {
				window.alert('Error processing changes (reloading advised): ' + errmsg(err));
			}
		});
	};
	connect(false);
};
window.addEventListener('load', async () => {
	try {
		await init();
	}
	catch (err) {
		window.alert('Error: ' + errmsg(err));
	}
});
// Keep original URL of page load, so we can remove it from stack trace if we need to.
const origLocation = {
	href: window.location.href,
	protocol: window.location.protocol,
	host: window.location.host,
	pathname: window.location.pathname,
	search: window.location.search,
};
// If a JS error happens, show a box in the lower left corner, with a button to
// show details, in a popup. The popup shows the error message and a link to github
// to create an issue. We want to lower the barrier to give feedback.
const showUnhandledError = (err, lineno, colno) => {
	console.log('unhandled error', err);
	if (settings.ignoreErrorsUntil > new Date().getTime() / 1000) {
		return;
	}
	let stack = err.stack || '';
	if (stack) {
		log({ stack });
		// At the time of writing, Firefox has stacks with full location.href of original
		// page load including hash. Chromium has location.href without hash.
		const loc = origLocation;
		stack = '\n' + stack.replaceAll(loc.href, 'webmail.html').replaceAll(loc.protocol + '//' + loc.host + loc.pathname + loc.search, 'webmail.html');
	}
	else {
		stack = ' (not available)';
	}
	const xerrmsg = err.toString();
	const box = dom.div(style({ position: 'absolute', bottom: '1ex', left: '1ex', backgroundColor: 'rgba(249, 191, 191, .9)', maxWidth: '14em', padding: '.25em .5em', borderRadius: '.25em', fontSize: '.8em', wordBreak: 'break-all', zIndex: zindexes.shortcut }), dom.div(style({ marginBottom: '.5ex' }), '' + xerrmsg), dom.clickbutton('Details', function click() {
		box.remove();
		let msg = `Mox version: ${moxversion}
Browser: ${window.navigator.userAgent}
File: webmail.html
Lineno: ${lineno || '-'}
Colno: ${colno || '-'}
Message: ${xerrmsg}

Stack trace: ${stack}
`;
		const body = `[Hi! Please replace this text with an explanation of what you did to trigger this errors. It will help us reproduce the problem. The more details, the more likely it is we can find and fix the problem. If you don't know how or why it happened, that's ok, it is still useful to report the problem. If no stack trace was found and included below, and you are a developer, you can probably find more details about the error in the browser developer console. Thanks!]

Details of the error and browser:

` + '```\n' + msg + '```\n';
		const remove = popup(style({ maxWidth: '60em' }), dom.h1('A JavaScript error occurred'), dom.pre(dom._class('mono'), style({ backgroundColor: '#f8f8f8', padding: '1ex', borderRadius: '.15em', border: '1px solid #ccc', whiteSpace: 'pre-wrap' }), msg), dom.br(), dom.div('There is a good chance this is a bug in Mox Webmail.'), dom.div('Consider filing a bug report ("issue") at ', link('https://github.com/mjl-/mox/issues/new?title=' + encodeURIComponent('mox webmail js error: "' + xerrmsg + '"') + '&body=' + encodeURIComponent(body), 'https://github.com/mjl-/mox/issues/new'), '. The link includes the error details.'), dom.div('Before reporting you could check previous ', link('https://github.com/mjl-/mox/issues?q=is%3Aissue+"mox+webmail+js+error%3A"', 'webmail bug reports'), '.'), dom.br(), dom.div('Your feedback will help improve mox, thanks!'), dom.br(), dom.div(style({ textAlign: 'right' }), dom.clickbutton('Close and silence errors for 1 week', function click() {
			remove();
			settingsPut({ ...settings, ignoreErrorsUntil: Math.round(new Date().getTime() / 1000 + 7 * 24 * 3600) });
		}), ' ', dom.clickbutton('Close', function click() {
			remove();
		})));
	}), ' ', dom.clickbutton('Ignore', function click() {
		box.remove();
	}));
	document.body.appendChild(box);
};
// We don't catch all errors, we use throws to not continue executing javascript.
// But for JavaScript-level errors, we want to show a warning to helpfully get the
// user to submit a bug report.
window.addEventListener('unhandledrejection', (e) => {
	if (!e.reason) {
		return;
	}
	const err = e.reason;
	if (err instanceof EvalError || err instanceof RangeError || err instanceof ReferenceError || err instanceof SyntaxError || err instanceof TypeError || err instanceof URIError || err instanceof ConsistencyError) {
		showUnhandledError(err, 0, 0);
	}
	else {
		console.log('unhandled promiserejection', err, e.promise);
	}
});
// Window-level errors aren't that likely, since all code is in the init promise,
// but doesn't hurt to register an handler.
window.addEventListener('error', e => {
	showUnhandledError(e.error, e.lineno, e.colno);
});
