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
	// OutgoingEvent is an activity for an outgoing delivery. Either generated by the
	// queue, or through an incoming DSN (delivery status notification) message.
	let OutgoingEvent;
	(function (OutgoingEvent) {
		// Message was accepted by a next-hop server. This does not necessarily mean the
		// message has been delivered in the mailbox of the user.
		OutgoingEvent["EventDelivered"] = "delivered";
		// Outbound delivery was suppressed because the recipient address is on the
		// suppression list of the account, or a simplified/base variant of the address is.
		OutgoingEvent["EventSuppressed"] = "suppressed";
		OutgoingEvent["EventDelayed"] = "delayed";
		// Delivery of the message failed and will not be tried again. Also see the
		// "Suppressing" field of [Outgoing].
		OutgoingEvent["EventFailed"] = "failed";
		// Message was relayed into a system that does not generate DSNs. Should only
		// happen when explicitly requested.
		OutgoingEvent["EventRelayed"] = "relayed";
		// Message was accepted and is being delivered to multiple recipients (e.g. the
		// address was an alias/list), which may generate more DSNs.
		OutgoingEvent["EventExpanded"] = "expanded";
		OutgoingEvent["EventCanceled"] = "canceled";
		// An incoming message was received that was either a DSN with an unknown event
		// type ("action"), or an incoming non-DSN-message was received for the unique
		// per-outgoing-message address used for sending.
		OutgoingEvent["EventUnrecognized"] = "unrecognized";
	})(OutgoingEvent = api.OutgoingEvent || (api.OutgoingEvent = {}));
	api.structTypes = { "Account": true, "Address": true, "AddressAlias": true, "Alias": true, "AliasAddress": true, "AutomaticJunkFlags": true, "Destination": true, "Domain": true, "ImportProgress": true, "Incoming": true, "IncomingMeta": true, "IncomingWebhook": true, "JunkFilter": true, "NameAddress": true, "Outgoing": true, "OutgoingWebhook": true, "Route": true, "Ruleset": true, "Structure": true, "SubjectPass": true, "Suppression": true };
	api.stringsTypes = { "CSRFToken": true, "Localpart": true, "OutgoingEvent": true };
	api.intsTypes = {};
	api.types = {
		"Account": { "Name": "Account", "Docs": "", "Fields": [{ "Name": "OutgoingWebhook", "Docs": "", "Typewords": ["nullable", "OutgoingWebhook"] }, { "Name": "IncomingWebhook", "Docs": "", "Typewords": ["nullable", "IncomingWebhook"] }, { "Name": "FromIDLoginAddresses", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "KeepRetiredMessagePeriod", "Docs": "", "Typewords": ["int64"] }, { "Name": "KeepRetiredWebhookPeriod", "Docs": "", "Typewords": ["int64"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Description", "Docs": "", "Typewords": ["string"] }, { "Name": "FullName", "Docs": "", "Typewords": ["string"] }, { "Name": "Destinations", "Docs": "", "Typewords": ["{}", "Destination"] }, { "Name": "SubjectPass", "Docs": "", "Typewords": ["SubjectPass"] }, { "Name": "QuotaMessageSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "RejectsMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "KeepRejects", "Docs": "", "Typewords": ["bool"] }, { "Name": "AutomaticJunkFlags", "Docs": "", "Typewords": ["AutomaticJunkFlags"] }, { "Name": "JunkFilter", "Docs": "", "Typewords": ["nullable", "JunkFilter"] }, { "Name": "MaxOutgoingMessagesPerDay", "Docs": "", "Typewords": ["int32"] }, { "Name": "MaxFirstTimeRecipientsPerDay", "Docs": "", "Typewords": ["int32"] }, { "Name": "NoFirstTimeSenderDelay", "Docs": "", "Typewords": ["bool"] }, { "Name": "Routes", "Docs": "", "Typewords": ["[]", "Route"] }, { "Name": "DNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "Aliases", "Docs": "", "Typewords": ["[]", "AddressAlias"] }] },
		"OutgoingWebhook": { "Name": "OutgoingWebhook", "Docs": "", "Fields": [{ "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Authorization", "Docs": "", "Typewords": ["string"] }, { "Name": "Events", "Docs": "", "Typewords": ["[]", "string"] }] },
		"IncomingWebhook": { "Name": "IncomingWebhook", "Docs": "", "Fields": [{ "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Authorization", "Docs": "", "Typewords": ["string"] }] },
		"Destination": { "Name": "Destination", "Docs": "", "Fields": [{ "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Rulesets", "Docs": "", "Typewords": ["[]", "Ruleset"] }, { "Name": "FullName", "Docs": "", "Typewords": ["string"] }] },
		"Ruleset": { "Name": "Ruleset", "Docs": "", "Fields": [{ "Name": "SMTPMailFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "HeadersRegexp", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListAllowDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "AcceptRejectsToMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Comment", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "ListAllowDNSDomain", "Docs": "", "Typewords": ["Domain"] }] },
		"Domain": { "Name": "Domain", "Docs": "", "Fields": [{ "Name": "ASCII", "Docs": "", "Typewords": ["string"] }, { "Name": "Unicode", "Docs": "", "Typewords": ["string"] }] },
		"SubjectPass": { "Name": "SubjectPass", "Docs": "", "Fields": [{ "Name": "Period", "Docs": "", "Typewords": ["int64"] }] },
		"AutomaticJunkFlags": { "Name": "AutomaticJunkFlags", "Docs": "", "Fields": [{ "Name": "Enabled", "Docs": "", "Typewords": ["bool"] }, { "Name": "JunkMailboxRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "NeutralMailboxRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "NotJunkMailboxRegexp", "Docs": "", "Typewords": ["string"] }] },
		"JunkFilter": { "Name": "JunkFilter", "Docs": "", "Fields": [{ "Name": "Threshold", "Docs": "", "Typewords": ["float64"] }, { "Name": "Onegrams", "Docs": "", "Typewords": ["bool"] }, { "Name": "Twograms", "Docs": "", "Typewords": ["bool"] }, { "Name": "Threegrams", "Docs": "", "Typewords": ["bool"] }, { "Name": "MaxPower", "Docs": "", "Typewords": ["float64"] }, { "Name": "TopWords", "Docs": "", "Typewords": ["int32"] }, { "Name": "IgnoreWords", "Docs": "", "Typewords": ["float64"] }, { "Name": "RareWords", "Docs": "", "Typewords": ["int32"] }] },
		"Route": { "Name": "Route", "Docs": "", "Fields": [{ "Name": "FromDomain", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ToDomain", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "MinimumAttempts", "Docs": "", "Typewords": ["int32"] }, { "Name": "Transport", "Docs": "", "Typewords": ["string"] }, { "Name": "FromDomainASCII", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ToDomainASCII", "Docs": "", "Typewords": ["[]", "string"] }] },
		"AddressAlias": { "Name": "AddressAlias", "Docs": "", "Fields": [{ "Name": "SubscriptionAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "Alias", "Docs": "", "Typewords": ["Alias"] }, { "Name": "MemberAddresses", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Alias": { "Name": "Alias", "Docs": "", "Fields": [{ "Name": "Addresses", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "PostPublic", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListMembers", "Docs": "", "Typewords": ["bool"] }, { "Name": "AllowMsgFrom", "Docs": "", "Typewords": ["bool"] }, { "Name": "LocalpartStr", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "ParsedAddresses", "Docs": "", "Typewords": ["[]", "AliasAddress"] }] },
		"AliasAddress": { "Name": "AliasAddress", "Docs": "", "Fields": [{ "Name": "Address", "Docs": "", "Typewords": ["Address"] }, { "Name": "AccountName", "Docs": "", "Typewords": ["string"] }, { "Name": "Destination", "Docs": "", "Typewords": ["Destination"] }] },
		"Address": { "Name": "Address", "Docs": "", "Fields": [{ "Name": "Localpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }] },
		"Suppression": { "Name": "Suppression", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Created", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "BaseAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "OriginalAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "Manual", "Docs": "", "Typewords": ["bool"] }, { "Name": "Reason", "Docs": "", "Typewords": ["string"] }] },
		"ImportProgress": { "Name": "ImportProgress", "Docs": "", "Fields": [{ "Name": "Token", "Docs": "", "Typewords": ["string"] }] },
		"Outgoing": { "Name": "Outgoing", "Docs": "", "Fields": [{ "Name": "Version", "Docs": "", "Typewords": ["int32"] }, { "Name": "Event", "Docs": "", "Typewords": ["OutgoingEvent"] }, { "Name": "DSN", "Docs": "", "Typewords": ["bool"] }, { "Name": "Suppressing", "Docs": "", "Typewords": ["bool"] }, { "Name": "QueueMsgID", "Docs": "", "Typewords": ["int64"] }, { "Name": "FromID", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "WebhookQueued", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "SMTPCode", "Docs": "", "Typewords": ["int32"] }, { "Name": "SMTPEnhancedCode", "Docs": "", "Typewords": ["string"] }, { "Name": "Error", "Docs": "", "Typewords": ["string"] }, { "Name": "Extra", "Docs": "", "Typewords": ["{}", "string"] }] },
		"Incoming": { "Name": "Incoming", "Docs": "", "Fields": [{ "Name": "Version", "Docs": "", "Typewords": ["int32"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "NameAddress"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "NameAddress"] }, { "Name": "CC", "Docs": "", "Typewords": ["[]", "NameAddress"] }, { "Name": "BCC", "Docs": "", "Typewords": ["[]", "NameAddress"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["[]", "NameAddress"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "InReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "References", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Date", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Text", "Docs": "", "Typewords": ["string"] }, { "Name": "HTML", "Docs": "", "Typewords": ["string"] }, { "Name": "Structure", "Docs": "", "Typewords": ["Structure"] }, { "Name": "Meta", "Docs": "", "Typewords": ["IncomingMeta"] }] },
		"NameAddress": { "Name": "NameAddress", "Docs": "", "Fields": [{ "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "Address", "Docs": "", "Typewords": ["string"] }] },
		"Structure": { "Name": "Structure", "Docs": "", "Fields": [{ "Name": "ContentType", "Docs": "", "Typewords": ["string"] }, { "Name": "ContentTypeParams", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "ContentID", "Docs": "", "Typewords": ["string"] }, { "Name": "DecodedSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "Parts", "Docs": "", "Typewords": ["[]", "Structure"] }] },
		"IncomingMeta": { "Name": "IncomingMeta", "Docs": "", "Fields": [{ "Name": "MsgID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "MsgFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "RcptTo", "Docs": "", "Typewords": ["string"] }, { "Name": "DKIMVerifiedDomains", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "RemoteIP", "Docs": "", "Typewords": ["string"] }, { "Name": "Received", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Automated", "Docs": "", "Typewords": ["bool"] }] },
		"CSRFToken": { "Name": "CSRFToken", "Docs": "", "Values": null },
		"Localpart": { "Name": "Localpart", "Docs": "", "Values": null },
		"OutgoingEvent": { "Name": "OutgoingEvent", "Docs": "", "Values": [{ "Name": "EventDelivered", "Value": "delivered", "Docs": "" }, { "Name": "EventSuppressed", "Value": "suppressed", "Docs": "" }, { "Name": "EventDelayed", "Value": "delayed", "Docs": "" }, { "Name": "EventFailed", "Value": "failed", "Docs": "" }, { "Name": "EventRelayed", "Value": "relayed", "Docs": "" }, { "Name": "EventExpanded", "Value": "expanded", "Docs": "" }, { "Name": "EventCanceled", "Value": "canceled", "Docs": "" }, { "Name": "EventUnrecognized", "Value": "unrecognized", "Docs": "" }] },
	};
	api.parser = {
		Account: (v) => api.parse("Account", v),
		OutgoingWebhook: (v) => api.parse("OutgoingWebhook", v),
		IncomingWebhook: (v) => api.parse("IncomingWebhook", v),
		Destination: (v) => api.parse("Destination", v),
		Ruleset: (v) => api.parse("Ruleset", v),
		Domain: (v) => api.parse("Domain", v),
		SubjectPass: (v) => api.parse("SubjectPass", v),
		AutomaticJunkFlags: (v) => api.parse("AutomaticJunkFlags", v),
		JunkFilter: (v) => api.parse("JunkFilter", v),
		Route: (v) => api.parse("Route", v),
		AddressAlias: (v) => api.parse("AddressAlias", v),
		Alias: (v) => api.parse("Alias", v),
		AliasAddress: (v) => api.parse("AliasAddress", v),
		Address: (v) => api.parse("Address", v),
		Suppression: (v) => api.parse("Suppression", v),
		ImportProgress: (v) => api.parse("ImportProgress", v),
		Outgoing: (v) => api.parse("Outgoing", v),
		Incoming: (v) => api.parse("Incoming", v),
		NameAddress: (v) => api.parse("NameAddress", v),
		Structure: (v) => api.parse("Structure", v),
		IncomingMeta: (v) => api.parse("IncomingMeta", v),
		CSRFToken: (v) => api.parse("CSRFToken", v),
		Localpart: (v) => api.parse("Localpart", v),
		OutgoingEvent: (v) => api.parse("OutgoingEvent", v),
	};
	// Account exports web API functions for the account web interface. All its
	// methods are exported under api/. Function calls require valid HTTP
	// Authentication credentials of a user.
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
		// SetPassword saves a new password for the account, invalidating the previous password.
		// Sessions are not interrupted, and will keep working. New login attempts must use the new password.
		// Password must be at least 8 characters.
		async SetPassword(password) {
			const fn = "SetPassword";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [password];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Account returns information about the account.
		// StorageUsed is the sum of the sizes of all messages, in bytes.
		// StorageLimit is the maximum storage that can be used, or 0 if there is no limit.
		async Account() {
			const fn = "Account";
			const paramTypes = [];
			const returnTypes = [["Account"], ["int64"], ["int64"], ["[]", "Suppression"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AccountSaveFullName saves the full name (used as display name in email messages)
		// for the account.
		async AccountSaveFullName(fullName) {
			const fn = "AccountSaveFullName";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [fullName];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DestinationSave updates a destination.
		// OldDest is compared against the current destination. If it does not match, an
		// error is returned. Otherwise newDest is saved and the configuration reloaded.
		async DestinationSave(destName, oldDest, newDest) {
			const fn = "DestinationSave";
			const paramTypes = [["string"], ["Destination"], ["Destination"]];
			const returnTypes = [];
			const params = [destName, oldDest, newDest];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// ImportAbort aborts an import that is in progress. If the import exists and isn't
		// finished, no changes will have been made by the import.
		async ImportAbort(importToken) {
			const fn = "ImportAbort";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [importToken];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Types exposes types not used in API method signatures, such as the import form upload.
		async Types() {
			const fn = "Types";
			const paramTypes = [];
			const returnTypes = [["ImportProgress"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// SuppressionList lists the addresses on the suppression list of this account.
		async SuppressionList() {
			const fn = "SuppressionList";
			const paramTypes = [];
			const returnTypes = [["[]", "Suppression"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// SuppressionAdd adds an email address to the suppression list.
		async SuppressionAdd(address, manual, reason) {
			const fn = "SuppressionAdd";
			const paramTypes = [["string"], ["bool"], ["string"]];
			const returnTypes = [["Suppression"]];
			const params = [address, manual, reason];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// SuppressionRemove removes the email address from the suppression list.
		async SuppressionRemove(address) {
			const fn = "SuppressionRemove";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [address];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// OutgoingWebhookSave saves a new webhook url for outgoing deliveries. If url
		// is empty, the webhook is disabled. If authorization is non-empty it is used for
		// the Authorization header in HTTP requests. Events specifies the outgoing events
		// to be delivered, or all if empty/nil.
		async OutgoingWebhookSave(url, authorization, events) {
			const fn = "OutgoingWebhookSave";
			const paramTypes = [["string"], ["string"], ["[]", "string"]];
			const returnTypes = [];
			const params = [url, authorization, events];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// OutgoingWebhookTest makes a test webhook call to urlStr, with optional
		// authorization. If the HTTP request is made this call will succeed also for
		// non-2xx HTTP status codes.
		async OutgoingWebhookTest(urlStr, authorization, data) {
			const fn = "OutgoingWebhookTest";
			const paramTypes = [["string"], ["string"], ["Outgoing"]];
			const returnTypes = [["int32"], ["string"], ["string"]];
			const params = [urlStr, authorization, data];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// IncomingWebhookSave saves a new webhook url for incoming deliveries. If url is
		// empty, the webhook is disabled. If authorization is not empty, it is used in
		// the Authorization header in requests.
		async IncomingWebhookSave(url, authorization) {
			const fn = "IncomingWebhookSave";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [url, authorization];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// IncomingWebhookTest makes a test webhook HTTP delivery request to urlStr,
		// with optional authorization header. If the HTTP call is made, this function
		// returns non-error regardless of HTTP status code.
		async IncomingWebhookTest(urlStr, authorization, data) {
			const fn = "IncomingWebhookTest";
			const paramTypes = [["string"], ["string"], ["Incoming"]];
			const returnTypes = [["int32"], ["string"], ["string"]];
			const params = [urlStr, authorization, data];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// FromIDLoginAddressesSave saves new login addresses to enable unique SMTP
		// MAIL FROM addresses ("fromid") for deliveries from the queue.
		async FromIDLoginAddressesSave(loginAddresses) {
			const fn = "FromIDLoginAddressesSave";
			const paramTypes = [["[]", "string"]];
			const returnTypes = [];
			const params = [loginAddresses];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// KeepRetiredPeriodsSave saves periods to save retired messages and webhooks.
		async KeepRetiredPeriodsSave(keepRetiredMessagePeriod, keepRetiredWebhookPeriod) {
			const fn = "KeepRetiredPeriodsSave";
			const paramTypes = [["int64"], ["int64"]];
			const returnTypes = [];
			const params = [keepRetiredMessagePeriod, keepRetiredWebhookPeriod];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AutomaticJunkFlagsSave saves settings for automatically marking messages as
		// junk/nonjunk when moved to mailboxes matching certain regular expressions.
		async AutomaticJunkFlagsSave(enabled, junkRegexp, neutralRegexp, notJunkRegexp) {
			const fn = "AutomaticJunkFlagsSave";
			const paramTypes = [["bool"], ["string"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [enabled, junkRegexp, neutralRegexp, notJunkRegexp];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// JunkFilterSave saves junk filter settings. If junkFilter is nil, the junk filter
		// is disabled. Otherwise all fields except Threegrams are stored.
		async JunkFilterSave(junkFilter) {
			const fn = "JunkFilterSave";
			const paramTypes = [["nullable", "JunkFilter"]];
			const returnTypes = [];
			const params = [junkFilter];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// RejectsSave saves the RejectsMailbox and KeepRejects settings.
		async RejectsSave(mailbox, keep) {
			const fn = "RejectsSave";
			const paramTypes = [["string"], ["bool"]];
			const returnTypes = [];
			const params = [mailbox, keep];
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
const login = async (reason) => {
	return new Promise((resolve, _) => {
		const origFocus = document.activeElement;
		let reasonElem;
		let fieldset;
		let autosize;
		let username;
		let password;
		const root = dom.div(style({ position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: '#eee', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: '1', animation: 'fadein .15s ease-in' }), dom.div(style({ display: 'flex', flexDirection: 'column', alignItems: 'center' }), reasonElem = reason ? dom.div(style({ marginBottom: '2ex', textAlign: 'center' }), reason) : dom.div(), dom.div(style({ backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto', marginBottom: '20vh' }), dom.form(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			reasonElem.remove();
			try {
				fieldset.disabled = true;
				const loginToken = await client.LoginPrep();
				const token = await client.Login(loginToken, username.value, password.value);
				try {
					window.localStorage.setItem('webaccountaddress', username.value);
					window.localStorage.setItem('webaccountcsrftoken', token);
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
		}, fieldset = dom.fieldset(dom.h1('Account'), dom.label(style({ display: 'block', marginBottom: '2ex' }), dom.div('Email address', style({ marginBottom: '.5ex' })), autosize = dom.span(dom._class('autosize'), username = dom.input(attr.required(''), attr.placeholder('jane@example.org'), function change() { autosize.dataset.value = username.value; }, function input() { autosize.dataset.value = username.value; }))), dom.label(style({ display: 'block', marginBottom: '2ex' }), dom.div('Password', style({ marginBottom: '.5ex' })), password = dom.input(attr.type('password'), attr.required(''))), dom.div(style({ textAlign: 'center' }), dom.submitbutton('Login')))))));
		document.body.appendChild(root);
		username.focus();
	});
};
// Popup shows kids in a centered div with white background on top of a
// transparent overlay on top of the window. Clicking the overlay or hitting
// Escape closes the popup. Scrollbars are automatically added to the div with
// kids. Returns a function that removes the popup.
const popup = (...kids) => {
	const origFocus = document.activeElement;
	const close = () => {
		if (!root.parentNode) {
			return;
		}
		root.remove();
		if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
			origFocus.focus();
		}
	};
	let content;
	const root = dom.div(style({ position: 'fixed', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: 'rgba(0, 0, 0, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: '1' }), function keydown(e) {
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
	document.body.appendChild(root);
	content.focus();
	return close;
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
const check = async (elem, p) => {
	try {
		elem.disabled = true;
		return await p;
	}
	catch (err) {
		console.log({ err });
		window.alert('Error: ' + errmsg(err));
		throw err;
	}
	finally {
		elem.disabled = false;
	}
};
// When white-space is relevant, e.g. for email addresses (e.g. "  "@example.org).
const prewrap = (...l) => dom.span(style({ whiteSpace: 'pre-wrap' }), l);
const client = new api.Client().withOptions({ csrfHeader: 'x-mox-csrf', login: login }).withAuthToken(localStorageGet('webaccountcsrftoken') || '');
const link = (href, anchorOpt) => dom.a(attr.href(href), attr.rel('noopener noreferrer'), anchorOpt || href);
const crumblink = (text, path) => {
	return {
		text: text,
		path: path
	};
};
const crumbs = (...l) => {
	const crumbtext = (e) => typeof e === 'string' ? e : e.text;
	document.title = l.map(e => crumbtext(e)).join(' - ');
	const crumblink = (e) => typeof e === 'string' ? prewrap(e) : dom.a(e.text, attr.href(e.path));
	return [
		dom.div(style({ float: 'right' }), localStorageGet('webaccountaddress') || '(unknown)', ' ', dom.clickbutton('Logout', attr.title('Logout, invalidating this session.'), async function click(e) {
			const b = e.target;
			try {
				b.disabled = true;
				await client.Logout();
			}
			catch (err) {
				console.log('logout', err);
				window.alert('Error: ' + errmsg(err));
			}
			finally {
				b.disabled = false;
			}
			localStorageRemove('webaccountaddress');
			localStorageRemove('webaccountcsrftoken');
			// Reload so all state is cleared from memory.
			window.location.reload();
		})),
		dom.h1(l.map((e, index) => index === 0 ? crumblink(e) : [' / ', crumblink(e)])),
		dom.br()
	];
};
const errmsg = (err) => '' + (err.message || '(no error message)');
const footer = dom.div(style({ marginTop: '6ex', opacity: 0.75 }), link('https://www.xmox.nl', 'mox'), ' ', moxversion);
const domainName = (d) => {
	return d.Unicode || d.ASCII;
};
const domainString = (d) => {
	if (d.Unicode) {
		return d.Unicode + " (" + d.ASCII + ")";
	}
	return d.ASCII;
};
const box = (color, ...l) => [
	dom.div(style({
		display: 'inline-block',
		padding: '.25em .5em',
		backgroundColor: color,
		borderRadius: '3px',
		margin: '.5ex 0',
	}), l),
	dom.br(),
];
const green = '#1dea20';
const yellow = '#ffe400';
const red = '#ff7443';
const blue = '#8bc8ff';
const age = (date) => {
	const r = dom.span(dom._class('notooltip'), attr.title(date.toString()));
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
	for (let i = 0; i < periods.length; i++) {
		const p = periods[i];
		if (t >= 2 * p || i === periods.length - 1) {
			const n = Math.round(t / p);
			s = '' + n + suffix[i];
			break;
		}
	}
	if (t < 60) {
		s = '<1min';
		// Prevent showing '-<1min' when browser and server have relatively small time drift of max 1 minute.
		negative = '';
	}
	dom._kids(r, negative + s);
	return r;
};
const formatQuotaSize = (v) => {
	if (v === 0) {
		return '0';
	}
	const m = 1024 * 1024;
	const g = m * 1024;
	const t = g * 1024;
	if (Math.floor(v / t) * t === v) {
		return '' + (v / t) + 't';
	}
	else if (Math.floor(v / g) * g === v) {
		return '' + (v / g) + 'g';
	}
	else if (Math.floor(v / m) * m === v) {
		return '' + (v / m) + 'm';
	}
	return '' + v;
};
const index = async () => {
	const [acc, storageUsed, storageLimit, suppressions] = await client.Account();
	let fullNameForm;
	let fullNameFieldset;
	let fullName;
	let passwordForm;
	let passwordFieldset;
	let password1;
	let password2;
	let passwordHint;
	let autoJunkFlagsFieldset;
	let autoJunkFlagsEnabled;
	let junkMailboxRegexp;
	let neutralMailboxRegexp;
	let notJunkMailboxRegexp;
	let junkFilterFields;
	let junkFilterEnabled;
	let junkThreshold;
	let junkOnegrams;
	let junkTwograms;
	let junkMaxPower;
	let junkTopWords;
	let junkIgnoreWords;
	let junkRareWords;
	let rejectsFieldset;
	let rejectsMailbox;
	let keepRejects;
	let outgoingWebhookFieldset;
	let outgoingWebhookURL;
	let outgoingWebhookAuthorization;
	let outgoingWebhookEvents;
	let incomingWebhookFieldset;
	let incomingWebhookURL;
	let incomingWebhookAuthorization;
	let keepRetiredPeriodsFieldset;
	let keepRetiredMessagePeriod;
	let keepRetiredWebhookPeriod;
	let fromIDLoginAddressesFieldset;
	const second = 1000 * 1000 * 1000;
	const minute = 60 * second;
	const hour = 60 * minute;
	const day = 24 * hour;
	const week = 7 * day;
	const parseDuration = (s) => {
		if (!s) {
			return 0;
		}
		const xparseint = () => {
			const v = parseInt(s.substring(0, s.length - 1));
			if (isNaN(v) || Math.round(v) !== v) {
				throw new Error('bad number in duration');
			}
			return v;
		};
		if (s.endsWith('w')) {
			return xparseint() * week;
		}
		if (s.endsWith('d')) {
			return xparseint() * day;
		}
		if (s.endsWith('h')) {
			return xparseint() * hour;
		}
		if (s.endsWith('m')) {
			return xparseint() * minute;
		}
		if (s.endsWith('s')) {
			return xparseint() * second;
		}
		throw new Error('bad duration ' + s);
	};
	const formatDuration = (v) => {
		if (v === 0) {
			return '';
		}
		const is = (period) => v > 0 && Math.round(v / period) === v / period;
		const format = (period, s) => '' + (v / period) + s;
		if (is(week)) {
			return format(week, 'w');
		}
		if (is(day)) {
			return format(day, 'd');
		}
		if (is(hour)) {
			return format(hour, 'h');
		}
		if (is(minute)) {
			return format(minute, 'm');
		}
		return format(second, 's');
	};
	let importForm;
	let importFieldset;
	let mailboxFileHint;
	let mailboxPrefixHint;
	let importProgress;
	let importAbortBox;
	let suppressionAddress;
	let suppressionReason;
	const importTrack = async (token) => {
		const importConnection = dom.div('Waiting for updates...');
		importProgress.appendChild(importConnection);
		let countsTbody;
		let counts = new Map(); // mailbox -> elem
		let problems; // element
		await new Promise((resolve, reject) => {
			const eventSource = new window.EventSource('importprogress?token=' + encodeURIComponent(token));
			eventSource.addEventListener('open', function (e) {
				console.log('eventsource open', { e });
				dom._kids(importConnection, dom.div('Waiting for updates, connected...'));
				dom._kids(importAbortBox, dom.clickbutton('Abort import', attr.title('If the import is not yet finished, it can be aborted and no messages will have been imported.'), async function click() {
					try {
						await client.ImportAbort(token);
					}
					catch (err) {
						console.log({ err });
						window.alert('Error: ' + errmsg(err));
					}
					// On success, the event source will get an aborted notification and shutdown the connection.
				}));
			});
			eventSource.addEventListener('error', function (e) {
				console.log('eventsource error', { e });
				dom._kids(importConnection, box(red, 'Connection error'));
				reject({ message: 'Connection error' });
			});
			eventSource.addEventListener('count', (e) => {
				const data = JSON.parse(e.data); // {Mailbox: ..., Count: ...}
				console.log('import count event', { e, data });
				if (!countsTbody) {
					importProgress.appendChild(dom.div(dom.br(), dom.h3('Importing mailboxes and messages...'), dom.table(dom.thead(dom.tr(dom.th('Mailbox'), dom.th('Messages'))), countsTbody = dom.tbody())));
				}
				let elem = counts.get(data.Mailbox);
				if (!elem) {
					countsTbody.appendChild(dom.tr(dom.td(data.Mailbox), elem = dom.td(style({ textAlign: 'right' }), '' + data.Count)));
					counts.set(data.Mailbox, elem);
				}
				dom._kids(elem, '' + data.Count);
			});
			eventSource.addEventListener('problem', (e) => {
				const data = JSON.parse(e.data); // {Message: ...}
				console.log('import problem event', { e, data });
				if (!problems) {
					importProgress.appendChild(dom.div(dom.br(), dom.h3('Problems during import'), problems = dom.div()));
				}
				problems.appendChild(dom.div(box(yellow, data.Message)));
			});
			eventSource.addEventListener('step', (e) => {
				const data = JSON.parse(e.data); // {Title: ...}
				console.log('import step event', { e, data });
				importProgress.appendChild(dom.div(dom.br(), box(blue, 'Step: ' + data.Title)));
			});
			eventSource.addEventListener('done', (e) => {
				console.log('import done event', { e });
				importProgress.appendChild(dom.div(dom.br(), box(blue, 'Import finished')));
				eventSource.close();
				dom._kids(importConnection);
				dom._kids(importAbortBox);
				window.sessionStorage.removeItem('ImportToken');
				resolve(null);
			});
			eventSource.addEventListener('aborted', function (e) {
				console.log('import aborted event', { e });
				importProgress.appendChild(dom.div(dom.br(), box(red, 'Import aborted, no message imported')));
				eventSource.close();
				dom._kids(importConnection);
				dom._kids(importAbortBox);
				window.sessionStorage.removeItem('ImportToken');
				reject({ message: 'Import aborted' });
			});
		});
	};
	const authorizationPopup = (dest) => {
		let username;
		let password;
		const close = popup(dom.form(function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			dest.value = 'Basic ' + window.btoa(username.value + ':' + password.value);
			close();
		}, dom.p('Compose HTTP Basic authentication header'), dom.div(style({ marginBottom: '1ex' }), dom.div(dom.label('Username')), username = dom.input(attr.required(''))), dom.div(style({ marginBottom: '1ex' }), dom.div(dom.label('Password (shown in clear)')), password = dom.input(attr.required(''))), dom.div(style({ marginBottom: '1ex' }), dom.submitbutton('Set')), dom.div('A HTTP Basic authorization header contains the password in plain text, as base64.')));
		username.focus();
	};
	const popupTestOutgoing = () => {
		let fieldset;
		let event;
		let dsn;
		let suppressing;
		let queueMsgID;
		let fromID;
		let messageID;
		let error;
		let extra;
		let body;
		let curl;
		let result;
		let data = {
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
		};
		const onchange = function change() {
			data = {
				Version: 0,
				Event: event.value,
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
			};
			const curlStr = "curl " + (outgoingWebhookAuthorization.value ? "-H 'Authorization: " + outgoingWebhookAuthorization.value + "' " : "") + "-H 'X-Mox-Webhook-ID: 1' -H 'X-Mox-Webhook-Attempt: 1' --json '" + JSON.stringify(data) + "' '" + outgoingWebhookURL.value + "'";
			dom._kids(curl, style({ maxWidth: '45em', wordBreak: 'break-all' }), curlStr);
			body.value = JSON.stringify(data, undefined, "\t");
		};
		popup(dom.h1('Test webhook for outgoing delivery'), dom.form(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			result.classList.add('loadstart');
			const [code, response, errmsg] = await check(fieldset, client.OutgoingWebhookTest(outgoingWebhookURL.value, outgoingWebhookAuthorization.value, data));
			const nresult = dom.div(dom._class('loadend'), dom.table(dom.tr(dom.td('HTTP status code'), dom.td('' + code)), dom.tr(dom.td('Error message'), dom.td(errmsg)), dom.tr(dom.td('Response'), dom.td(response))));
			result.replaceWith(nresult);
			result = nresult;
		}, fieldset = dom.fieldset(dom.p('Make a test call to ', dom.b(outgoingWebhookURL.value), '.'), dom.div(style({ display: 'flex', gap: '1em' }), dom.div(dom.h2('Parameters'), dom.div(style({ marginBottom: '.5ex' }), dom.label('Event', dom.div(event = dom.select(onchange, ["delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"].map(s => dom.option(s.substring(0, 1).toUpperCase() + s.substring(1), attr.value(s))))))), dom.div(style({ marginBottom: '.5ex' }), dom.label(dsn = dom.input(attr.type('checkbox')), ' DSN', onchange)), dom.div(style({ marginBottom: '.5ex' }), dom.label(suppressing = dom.input(attr.type('checkbox')), ' Suppressing', onchange)), dom.div(style({ marginBottom: '.5ex' }), dom.label('Queue message ID ', dom.div(queueMsgID = dom.input(attr.required(''), attr.type('number'), attr.value('123'), onchange)))), dom.div(style({ marginBottom: '.5ex' }), dom.label('From ID ', dom.div(fromID = dom.input(attr.required(''), attr.value(data.FromID), onchange)))), dom.div(style({ marginBottom: '.5ex' }), dom.label('MessageID', dom.div(messageID = dom.input(attr.required(''), attr.value(data.MessageID), onchange)))), dom.div(style({ marginBottom: '.5ex' }), dom.label('Error', dom.div(error = dom.input(onchange)))), dom.div(style({ marginBottom: '.5ex' }), dom.label('Extra', dom.div(extra = dom.input(attr.required(''), attr.value('{}'), onchange))))), dom.div(dom.h2('Headers'), dom.pre('X-Mox-Webhook-ID: 1\nX-Mox-Webhook-Attempt: 1'), dom.br(), dom.h2('JSON'), body = dom.textarea(attr.disabled(''), attr.rows('15'), style({ width: '30em' })), dom.br(), dom.h2('curl'), curl = dom.div(dom._class('literal')))), dom.br(), dom.div(style({ textAlign: 'right' }), dom.submitbutton('Post')), dom.br(), result = dom.div())));
		onchange();
	};
	const popupTestIncoming = () => {
		let fieldset;
		let body;
		let curl;
		let result;
		let data = {
			Version: 0,
			From: [{ Name: 'remote', Address: 'remote@remote.example' }],
			To: [{ Name: 'mox', Address: 'mox@mox.example' }],
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
				ContentTypeParams: { charset: 'utf-8' },
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
		};
		const onchange = function change() {
			try {
				api.parser.Incoming(JSON.parse(body.value));
			}
			catch (err) {
				console.log({ err });
				window.alert('Error parsing data: ' + errmsg(err));
			}
			const curlStr = "curl " + (incomingWebhookAuthorization.value ? "-H 'Authorization: " + incomingWebhookAuthorization.value + "' " : "") + "-H 'X-Mox-Webhook-ID: 1' -H 'X-Mox-Webhook-Attempt: 1' --json '" + JSON.stringify(data) + "' '" + incomingWebhookURL.value + "'";
			dom._kids(curl, style({ maxWidth: '45em', wordBreak: 'break-all' }), curlStr);
		};
		popup(dom.h1('Test webhook for incoming delivery'), dom.form(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			result.classList.add('loadstart');
			const [code, response, errmsg] = await check(fieldset, (async () => await client.IncomingWebhookTest(incomingWebhookURL.value, incomingWebhookAuthorization.value, api.parser.Incoming(JSON.parse(body.value))))());
			const nresult = dom.div(dom._class('loadend'), dom.table(dom.tr(dom.td('HTTP status code'), dom.td('' + code)), dom.tr(dom.td('Error message'), dom.td(errmsg)), dom.tr(dom.td('Response'), dom.td(response))));
			result.replaceWith(nresult);
			result = nresult;
		}, fieldset = dom.fieldset(dom.p('Make a test call to ', dom.b(incomingWebhookURL.value), '.'), dom.div(style({ display: 'flex', gap: '1em' }), dom.div(dom.h2('JSON'), body = dom.textarea(style({ maxHeight: '90vh' }), style({ width: '30em' }), onchange)), dom.div(dom.h2('Headers'), dom.pre('X-Mox-Webhook-ID: 1\nX-Mox-Webhook-Attempt: 1'), dom.br(), dom.h2('curl'), curl = dom.div(dom._class('literal')))), dom.br(), dom.div(style({ textAlign: 'right' }), dom.submitbutton('Post')), dom.br(), result = dom.div())));
		body.value = JSON.stringify(data, undefined, '\t');
		body.setAttribute('rows', '' + Math.min(40, (body.value.split('\n').length + 1)));
		onchange();
	};
	dom._kids(page, crumbs('Mox Account'), dom.div('Default domain: ', acc.DNSDomain.ASCII ? domainString(acc.DNSDomain) : '(none)'), dom.br(), fullNameForm = dom.form(fullNameFieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), 'Full name', dom.br(), fullName = dom.input(attr.value(acc.FullName), attr.title('Name to use in From header when composing messages. Can be overridden per configured address.'))), ' ', dom.submitbutton('Save')), async function submit(e) {
		e.preventDefault();
		await check(fullNameFieldset, client.AccountSaveFullName(fullName.value));
		fullName.setAttribute('value', fullName.value);
		fullNameForm.reset();
	}), dom.br(), dom.h2('Addresses'), dom.ul(Object.entries(acc.Destinations || {}).length === 0 ? dom.li('(None, login disabled)') : [], Object.entries(acc.Destinations || {}).sort().map(t => dom.li(dom.a(prewrap(t[0]), attr.href('#destinations/' + encodeURIComponent(t[0]))), t[0].startsWith('@') ? ' (catchall)' : []))), dom.br(), dom.h2('Aliases/lists'), dom.table(dom.thead(dom.tr(dom.th('Alias address', attr.title('Messages sent to this address will be delivered to all members of the alias/list.')), dom.th('Subscription address', attr.title('Address subscribed to the alias/list.')), dom.th('Allowed senders', attr.title('Whether only members can send through the alias/list, or anyone.')), dom.th('Send as alias address', attr.title('If enabled, messages can be sent with the alias address in the message "From" header.')), dom.th())), (acc.Aliases || []).length === 0 ? dom.tr(dom.td(attr.colspan('5'), 'None')) : [], (acc.Aliases || []).sort((a, b) => a.Alias.LocalpartStr < b.Alias.LocalpartStr ? -1 : (domainName(a.Alias.Domain) < domainName(b.Alias.Domain) ? -1 : 1)).map(a => dom.tr(dom.td(prewrap(a.Alias.LocalpartStr, '@', domainName(a.Alias.Domain))), dom.td(prewrap(a.SubscriptionAddress)), dom.td(a.Alias.PostPublic ? 'Anyone' : 'Members only'), dom.td(a.Alias.AllowMsgFrom ? 'Yes' : 'No'), dom.td((a.MemberAddresses || []).length === 0 ? [] :
		dom.clickbutton('Show members', function click() {
			popup(dom.h1('Members of alias ', prewrap(a.Alias.LocalpartStr, '@', domainName(a.Alias.Domain))), dom.ul((a.MemberAddresses || []).map(addr => dom.li(prewrap(addr)))));
		}))))), dom.br(), dom.h2('Change password'), passwordForm = dom.form(passwordFieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), 'New password', dom.br(), password1 = dom.input(attr.type('password'), attr.autocomplete('new-password'), attr.required(''), function focus() {
		passwordHint.style.display = '';
	})), ' ', dom.label(style({ display: 'inline-block' }), 'New password repeat', dom.br(), password2 = dom.input(attr.type('password'), attr.autocomplete('new-password'), attr.required(''))), ' ', dom.submitbutton('Change password')), passwordHint = dom.div(style({ display: 'none', marginTop: '.5ex' }), dom.clickbutton('Generate random password', function click(e) {
		e.preventDefault();
		let b = new Uint8Array(1);
		let s = '';
		const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_;:,<.>/';
		while (s.length < 12) {
			self.crypto.getRandomValues(b);
			if (Math.ceil(b[0] / chars.length) * chars.length > 255) {
				continue; // Prevent bias.
			}
			s += chars[b[0] % chars.length];
		}
		password1.type = 'text';
		password2.type = 'text';
		password1.value = s;
		password2.value = s;
	}), dom.div(dom._class('text'), box(yellow, 'Important: Bots will try to bruteforce your password. Connections with failed authentication attempts will be rate limited but attackers WILL find weak passwords. If your account is compromised, spammers are likely to abuse your system, spamming your address and the wider internet in your name. So please pick a random, unguessable password, preferrably at least 12 characters.'))), async function submit(e) {
		e.stopPropagation();
		e.preventDefault();
		if (!password1.value || password1.value !== password2.value) {
			window.alert('Passwords do not match.');
			return;
		}
		await check(passwordFieldset, client.SetPassword(password1.value));
		passwordForm.reset();
	}), dom.br(), dom.h2('Disk usage'), dom.p('Storage used is ', dom.b(formatQuotaSize(Math.floor(storageUsed / (1024 * 1024)) * 1024 * 1024)), storageLimit > 0 ? [
		dom.b('/', formatQuotaSize(storageLimit)),
		' (',
		'' + Math.floor(100 * storageUsed / storageLimit),
		'%).',
	] : [', no explicit limit is configured.']), dom.h2('Automatic junk flags', attr.title('For the junk filter to work properly, it needs to be trained: Messages need to be marked as junk or nonjunk. Not all email clients help you set those flags. Automatic junk flags set the junk or nonjunk flags when messages are moved/copied to mailboxes matching configured regular expressions.')), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(autoJunkFlagsFieldset, client.AutomaticJunkFlagsSave(autoJunkFlagsEnabled.checked, junkMailboxRegexp.value, neutralMailboxRegexp.value, notJunkMailboxRegexp.value));
	}, autoJunkFlagsFieldset = dom.fieldset(dom.div(style({ display: 'flex', gap: '1em' }), dom.label('Enabled', attr.title("If enabled, junk/nonjunk flags will be set automatically if they match a regular expression below. When two of the three mailbox regular expressions are set, the remaining one will match all unmatched messages. Messages are matched in order 'junk', 'neutral', 'not junk', and the search stops on the first match. Mailboxes are lowercased before matching."), dom.div(autoJunkFlagsEnabled = dom.input(attr.type('checkbox'), acc.AutomaticJunkFlags.Enabled ? attr.checked('') : []))), dom.label('Junk mailbox regexp', dom.div(junkMailboxRegexp = dom.input(attr.value(acc.AutomaticJunkFlags.JunkMailboxRegexp)))), dom.label('Neutral mailbox regexp', dom.div(neutralMailboxRegexp = dom.input(attr.value(acc.AutomaticJunkFlags.NeutralMailboxRegexp)))), dom.label('Not Junk mailbox regexp', dom.div(notJunkMailboxRegexp = dom.input(attr.value(acc.AutomaticJunkFlags.NotJunkMailboxRegexp)))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save')))))), dom.br(), dom.h2('Junk filter', attr.title('Content-based filtering, using the junk-status of individual messages to rank words in such messages as spam or ham. It is recommended you always set the applicable (non)-junk status on messages, and that you do not empty your Trash because those messages contain valuable ham/spam training information.')), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		const xjunkFilter = () => {
			if (!junkFilterEnabled.checked) {
				return null;
			}
			const r = {
				Threshold: parseFloat(junkThreshold.value),
				Onegrams: junkOnegrams.checked,
				Twograms: junkTwograms.checked,
				Threegrams: acc.JunkFilter?.Threegrams || false,
				MaxPower: parseFloat(junkMaxPower.value),
				TopWords: parseInt(junkTopWords.value),
				IgnoreWords: parseFloat(junkIgnoreWords.value),
				RareWords: parseInt(junkRareWords.value),
			};
			return r;
		};
		await check(junkFilterFields, (async () => await client.JunkFilterSave(xjunkFilter()))());
	}, junkFilterFields = dom.fieldset(dom.div(style({ display: 'flex', gap: '1em' }), dom.label('Enabled', attr.title("If enabled, the junk filter is used to classify incoming email from first-time senders. The result, along with other checks, determines if the message will be accepted or rejected"), dom.div(junkFilterEnabled = dom.input(attr.type('checkbox'), acc.JunkFilter ? attr.checked('') : []))), dom.label('Threshold', attr.title('Approximate spaminess score between 0 and 1 above which emails are rejected as spam. Each delivery attempt adds a little noise to make it slightly harder for spammers to identify words that strongly indicate non-spaminess and use it to bypass the filter. E.g. 0.95.'), dom.div(junkThreshold = dom.input(attr.value('' + (acc.JunkFilter?.Threshold || '0.95'))))), dom.label('Onegrams', attr.title('Track ham/spam ranking for single words.'), dom.div(junkOnegrams = dom.input(attr.type('checkbox'), acc.JunkFilter?.Onegrams ? attr.checked('') : []))), dom.label('Twograms', attr.title('Track ham/spam ranking for each two consecutive words.'), dom.div(junkTwograms = dom.input(attr.type('checkbox'), acc.JunkFilter?.Twograms ? attr.checked('') : []))), dom.label('Threegrams', attr.title('Track ham/spam ranking for each three consecutive words. Can only be changed by admin.'), dom.div(dom.input(attr.type('checkbox'), attr.disabled(''), acc.JunkFilter?.Threegrams ? attr.checked('') : []))), dom.label('Max power', attr.title('Maximum power a word (combination) can have. If spaminess is 0.99, and max power is 0.1, spaminess of the word will be set to 0.9. Similar for ham words.'), dom.div(junkMaxPower = dom.input(attr.value('' + (acc.JunkFilter?.MaxPower || 0.01))))), dom.label('Top words', attr.title('Number of most spammy/hammy words to use for calculating probability. E.g. 10.'), dom.div(junkTopWords = dom.input(attr.value('' + (acc.JunkFilter?.TopWords || 10))))), dom.label('Ignore words', attr.title('Ignore words that are this much away from 0.5 haminess/spaminess. E.g. 0.1, causing word (combinations) of 0.4 to 0.6 to be ignored.'), dom.div(junkIgnoreWords = dom.input(attr.value('' + (acc.JunkFilter?.IgnoreWords || 0.1))))), dom.label('Rare words', attr.title('Occurrences in word database until a word is considered rare and its influence in calculating probability reduced. E.g. 1 or 2.'), dom.div(junkRareWords = dom.input(attr.value('' + (acc.JunkFilter?.RareWords || 2))))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save')))))), dom.br(), dom.h2('Rejects'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(rejectsFieldset, client.RejectsSave(rejectsMailbox.value, keepRejects.checked));
	}, rejectsFieldset = dom.fieldset(dom.div(style({ display: 'flex', gap: '1em' }), dom.label('Mailbox', attr.title("Mail that looks like spam will be rejected, but a copy can be stored temporarily in a mailbox, e.g. Rejects. If mail isn't coming in when you expect, you can look there. The mail still isn't accepted, so the remote mail server may retry (hopefully, if legitimate), or give up (hopefully, if indeed a spammer). Messages are automatically removed from this mailbox, so do not set it to a mailbox that has messages you want to keep."), dom.div(rejectsMailbox = dom.input(attr.value(acc.RejectsMailbox)))), dom.label("No cleanup", attr.title("Don't automatically delete mail in the RejectsMailbox listed above. This can be useful, e.g. for future spam training. It can also cause storage to fill up."), dom.div(keepRejects = dom.input(attr.type('checkbox'), acc.KeepRejects ? attr.checked('') : []))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save')))))), dom.br(), dom.h2('Webhooks'), dom.h3('Outgoing', attr.title('Webhooks for outgoing messages are called for each attempt to deliver a message in the outgoing queue, e.g. when the queue has delivered a message to the next hop, when a single attempt failed with a temporary error, when delivery permanently failed, or when DSN (delivery status notification) messages were received about a previously sent message.')), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(outgoingWebhookFieldset, client.OutgoingWebhookSave(outgoingWebhookURL.value, outgoingWebhookAuthorization.value, [...outgoingWebhookEvents.selectedOptions].map(o => o.value)));
	}, outgoingWebhookFieldset = dom.fieldset(dom.div(style({ display: 'flex', gap: '1em' }), dom.div(dom.label(dom.div('URL', attr.title('URL to do an HTTP POST to for each event. Webhooks are disabled if empty.')), outgoingWebhookURL = dom.input(attr.value(acc.OutgoingWebhook?.URL || ''), style({ width: '30em' })))), dom.div(dom.label(dom.div('Authorization header ', dom.a('Basic', attr.href(''), function click(e) {
		e.preventDefault();
		authorizationPopup(outgoingWebhookAuthorization);
	}), attr.title('If non-empty, HTTP requests have this value as Authorization header, e.g. Basic <base64-encoded-username-password>.')), outgoingWebhookAuthorization = dom.input(attr.value(acc.OutgoingWebhook?.Authorization || '')))), dom.div(dom.label(style({ verticalAlign: 'top' }), dom.div('Events', attr.title('Either limit to specific events, or receive all events (default).')), outgoingWebhookEvents = dom.select(style({ verticalAlign: 'bottom' }), attr.multiple(''), attr.size('8'), // Number of options.
	["delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"].map(s => dom.option(s.substring(0, 1).toUpperCase() + s.substring(1), attr.value(s), acc.OutgoingWebhook?.Events?.includes(s) ? attr.selected('') : []))))), dom.div(dom.div(dom.label('\u00a0')), dom.submitbutton('Save'), ' ', dom.clickbutton('Test', function click() {
		popupTestOutgoing();
	}))))), dom.br(), dom.h3('Incoming', attr.title('Webhooks for incoming messages are called for each message received over SMTP, excluding DSN messages about previous deliveries.')), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(incomingWebhookFieldset, client.IncomingWebhookSave(incomingWebhookURL.value, incomingWebhookAuthorization.value));
	}, incomingWebhookFieldset = dom.fieldset(dom.div(style({ display: 'flex', gap: '1em' }), dom.div(dom.label(dom.div('URL'), incomingWebhookURL = dom.input(attr.value(acc.IncomingWebhook?.URL || ''), style({ width: '30em' })))), dom.div(dom.label(dom.div('Authorization header ', dom.a('Basic', attr.href(''), function click(e) {
		e.preventDefault();
		authorizationPopup(incomingWebhookAuthorization);
	}), attr.title('If non-empty, HTTP requests have this value as Authorization header, e.g. Basic <base64-encoded-username-password>.')), incomingWebhookAuthorization = dom.input(attr.value(acc.IncomingWebhook?.Authorization || '')))), dom.div(dom.div(dom.label('\u00a0')), dom.submitbutton('Save'), ' ', dom.clickbutton('Test', function click() {
		popupTestIncoming();
	}))))), dom.br(), dom.h2('Keep messages/webhooks retired from queue', attr.title('After delivering a message or webhook from the queue it is removed by default. But you can also keep these "retired" messages/webhooks around for a while. With unique SMTP MAIL FROM addresses configured below, this allows relating incoming delivery status notification messages (DSNs) to previously sent messages and their original recipients, which is needed for automatic management of recipient suppression lists, which is important for managing the reputation of your mail server. For both messages and webhooks, this can be useful for debugging. Use values like "3d" for 3 days, or units "s" for second, "m" for minute, "h" for hour, "w" for week.')), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(keepRetiredPeriodsFieldset, (async () => await client.KeepRetiredPeriodsSave(parseDuration(keepRetiredMessagePeriod.value), parseDuration(keepRetiredWebhookPeriod.value)))());
	}, keepRetiredPeriodsFieldset = dom.fieldset(dom.div(style({ display: 'flex', gap: '1em', alignItems: 'flex-end' }), dom.div(dom.label('Messages deliveries', dom.br(), keepRetiredMessagePeriod = dom.input(attr.value(formatDuration(acc.KeepRetiredMessagePeriod))))), dom.div(dom.label('Webhook deliveries', dom.br(), keepRetiredWebhookPeriod = dom.input(attr.value(formatDuration(acc.KeepRetiredWebhookPeriod))))), dom.div(dom.submitbutton('Save'))))), dom.br(), dom.h2('Unique SMTP MAIL FROM login addresses ("FromID")', attr.title('Login addresses that cause outgoing email to be sent with SMTP MAIL FROM addresses with a unique id after the localpart catchall separator (which must be enabled when addresses are specified here). Any delivery status notifications (DSN, e.g. for bounces), can be related to the original message and recipient with unique id\'s. You can login to an account with any valid email address, including variants with the localpart catchall separator. You can use this mechanism to both send outgoing messages with and without unique fromid for a given email address. With the webapi and webmail, a unique id will be generated. For submission, the id from the SMTP MAIL FROM command is used if present, and a unique id is generated otherwise. Corresponds to field FromIDLoginAddresses in the Account configuration in domains.conf.')), (() => {
		let inputs = [];
		let elem;
		const render = () => {
			inputs = [];
			const e = dom.form(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(fromIDLoginAddressesFieldset, client.FromIDLoginAddressesSave(inputs.map(e => e.value)));
			}, fromIDLoginAddressesFieldset = dom.fieldset(dom.table(dom.tbody((acc.FromIDLoginAddresses || []).length === 0 ? dom.tr(dom.td('(None)'), dom.td()) : [], (acc.FromIDLoginAddresses || []).map((s, index) => {
				const input = dom.input(attr.required(''), attr.value(s));
				inputs.push(input);
				const x = dom.tr(dom.td(input), dom.td(dom.clickbutton('Remove', function click() {
					acc.FromIDLoginAddresses.splice(index, 1);
					render();
				})));
				return x;
			})), dom.tfoot(dom.tr(dom.td(), dom.td(dom.clickbutton('Add', function click() {
				acc.FromIDLoginAddresses = (acc.FromIDLoginAddresses || []).concat(['']);
				render();
			}))), dom.tr(dom.td(attr.colspan('2'), dom.submitbutton('Save')))))));
			if (elem) {
				elem.replaceWith(e);
				elem = e;
			}
			return e;
		};
		elem = render();
		return elem;
	})(), dom.br(), dom.h2('Suppression list'), dom.p('Messages queued for delivery to recipients on the suppression list will immediately fail. If delivery to a recipient fails repeatedly, it can be added to the suppression list automatically. Repeated rejected delivery attempts can have a negative influence of mail server reputation. Applications sending email can implement their own handling of delivery failure notifications, but not all do.'), dom.form(attr.id('suppressionAdd'), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(e.target, client.SuppressionAdd(suppressionAddress.value, true, suppressionReason.value));
		window.location.reload(); // todo: reload less
	}), dom.table(dom.thead(dom.tr(dom.th('Address', attr.title('Address that caused this entry to be added to the list. The title (shown on hover) displays an address with a fictional simplified localpart, with lower-cased, dots removed, only first part before "+" or "-" (typicaly catchall separators). When checking if an address is on the suppression list, it is checked against this address.')), dom.th('Manual', attr.title('Whether suppression was added manually, instead of automatically based on bounces.')), dom.th('Reason'), dom.th('Since'), dom.th('Action'))), dom.tbody((suppressions || []).length === 0 ? dom.tr(dom.td(attr.colspan('5'), '(None)')) : [], (suppressions || []).map(s => dom.tr(dom.td(prewrap(s.OriginalAddress), attr.title(s.BaseAddress)), dom.td(s.Manual ? '✓' : ''), dom.td(s.Reason), dom.td(age(s.Created)), dom.td(dom.clickbutton('Remove', async function click(e) {
		await check(e.target, client.SuppressionRemove(s.OriginalAddress));
		window.location.reload(); // todo: reload less
	}))))), dom.tfoot(dom.tr(dom.td(suppressionAddress = dom.input(attr.type('required'), attr.form('suppressionAdd'))), dom.td(), dom.td(suppressionReason = dom.input(style({ width: '100%' }), attr.form('suppressionAdd'))), dom.td(), dom.td(dom.submitbutton('Add suppression', attr.form('suppressionAdd')))))), dom.br(), dom.h2('Export'), dom.p('Export all messages in all mailboxes.'), dom.form(attr.target('_blank'), attr.method('POST'), attr.action('export'), dom.input(attr.type('hidden'), attr.name('csrf'), attr.value(localStorageGet('webaccountcsrftoken') || '')), dom.input(attr.type('hidden'), attr.name('mailbox'), attr.value('')), dom.input(attr.type('hidden'), attr.name('recursive'), attr.value('on')), dom.div(style({ display: 'flex', flexDirection: 'column', gap: '.5ex' }), dom.div(dom.label(dom.input(attr.type('radio'), attr.name('format'), attr.value('maildir'), attr.checked('')), ' Maildir'), ' ', dom.label(dom.input(attr.type('radio'), attr.name('format'), attr.value('mbox')), ' Mbox')), dom.div(dom.label(dom.input(attr.type('radio'), attr.name('archive'), attr.value('tar')), ' Tar'), ' ', dom.label(dom.input(attr.type('radio'), attr.name('archive'), attr.value('tgz'), attr.checked('')), ' Tgz'), ' ', dom.label(dom.input(attr.type('radio'), attr.name('archive'), attr.value('zip')), ' Zip'), ' '), dom.div(style({ marginTop: '1ex' }), dom.submitbutton('Export')))), dom.br(), dom.h2('Import'), dom.p('Import messages from a .zip or .tgz file with maildirs and/or mbox files.'), importForm = dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		const request = async () => {
			return new Promise((resolve, reject) => {
				// Browsers can do everything. Except show a progress bar while uploading...
				let progressPercentage;
				dom._kids(importProgress, dom.div(dom.div('Uploading... ', progressPercentage = dom.span())));
				importProgress.style.display = '';
				const xhr = new window.XMLHttpRequest();
				xhr.open('POST', 'import', true);
				xhr.setRequestHeader('x-mox-csrf', localStorageGet('webaccountcsrftoken') || '');
				xhr.upload.addEventListener('progress', (e) => {
					if (!e.lengthComputable) {
						return;
					}
					const pct = Math.floor(100 * e.loaded / e.total);
					dom._kids(progressPercentage, pct + '%');
				});
				xhr.addEventListener('load', () => {
					console.log('upload done', { xhr: xhr, status: xhr.status });
					if (xhr.status !== 200) {
						reject({ message: xhr.status === 400 || xhr.status === 500 ? xhr.responseText : 'status ' + xhr.status });
						return;
					}
					let resp;
					try {
						resp = api.parser.ImportProgress(JSON.parse(xhr.responseText));
					}
					catch (err) {
						reject({ message: 'parsing response json: ' + errmsg(err) });
						return;
					}
					resolve(resp);
				});
				xhr.addEventListener('error', (e) => reject({ message: 'upload error', event: e }));
				xhr.addEventListener('abort', (e) => reject({ message: 'upload aborted', event: e }));
				xhr.send(new window.FormData(importForm));
			});
		};
		try {
			const p = request();
			importFieldset.disabled = true;
			const result = await p;
			try {
				window.sessionStorage.setItem('ImportToken', result.Token);
			}
			catch (err) {
				console.log('storing import token in session storage', { err });
				// Ignore error, could be some browser security thing like private browsing.
			}
			await importTrack(result.Token);
		}
		catch (err) {
			console.log({ err });
			window.alert('Error: ' + errmsg(err));
		}
		finally {
			importFieldset.disabled = false;
		}
	}, importFieldset = dom.fieldset(dom.div(style({ marginBottom: '1ex' }), dom.label(dom.div(style({ marginBottom: '.5ex' }), 'File'), dom.input(attr.type('file'), attr.required(''), attr.name('file'), function focus() {
		mailboxFileHint.style.display = '';
	})), mailboxFileHint = dom.p(style({ display: 'none', fontStyle: 'italic', marginTop: '.5ex' }), 'This file must either be a zip file or a gzipped tar file with mbox and/or maildir mailboxes. For maildirs, an optional file "dovecot-keywords" is read additional keywords, like Forwarded/Junk/NotJunk. If an imported mailbox already exists by name, messages are added to the existing mailbox. If a mailbox does not yet exist it will be created. Messages are not deduplicated, importing them twice will result in duplicates.')), dom.div(style({ marginBottom: '1ex' }), dom.label(dom.div(style({ marginBottom: '.5ex' }), 'Skip mailbox prefix (optional)'), dom.input(attr.name('skipMailboxPrefix'), function focus() {
		mailboxPrefixHint.style.display = '';
	})), mailboxPrefixHint = dom.p(style({ display: 'none', fontStyle: 'italic', marginTop: '.5ex' }), 'If set, any mbox/maildir path with this prefix will have it stripped before importing. For example, if all mailboxes are in a directory "Takeout", specify that path in the field above so mailboxes like "Takeout/Inbox.mbox" are imported into a mailbox called "Inbox" instead of "Takeout/Inbox".')), dom.div(dom.submitbutton('Upload and import'), dom.p(style({ fontStyle: 'italic', marginTop: '.5ex' }), 'The file is uploaded first, then its messages are imported, finally messages are matched for threading. Importing is done in a transaction, you can abort the entire import before it is finished.')))), importAbortBox = dom.div(), // Outside fieldset because it gets disabled, above progress because may be scrolling it down quickly with problems.
	importProgress = dom.div(style({ display: 'none' })), dom.br(), footer);
	// Try to show the progress of an earlier import session. The user may have just
	// refreshed the browser.
	let importToken;
	try {
		importToken = window.sessionStorage.getItem('ImportToken') || '';
	}
	catch (err) {
		console.log('looking up ImportToken in session storage', { err });
		return;
	}
	if (!importToken) {
		return;
	}
	importFieldset.disabled = true;
	dom._kids(importProgress, dom.div(dom.div('Reconnecting to import...')));
	importProgress.style.display = '';
	importTrack(importToken)
		.catch(() => {
		if (window.confirm('Error reconnecting to import. Remove this import session?')) {
			window.sessionStorage.removeItem('ImportToken');
			dom._kids(importProgress);
			importProgress.style.display = 'none';
		}
	})
		.finally(() => {
		importFieldset.disabled = false;
	});
};
const destination = async (name) => {
	const [acc] = await client.Account();
	let dest = (acc.Destinations || {})[name];
	if (!dest) {
		throw new Error('destination not found');
	}
	let rulesetsTbody = dom.tbody();
	let rulesetsRows = [];
	const addRulesetsRow = (rs) => {
		let row;
		let headersCell = dom.td();
		const addHeader = (k, v) => {
			let h;
			let key;
			let value;
			const root = dom.div(key = dom.input(attr.value(k)), ' ', value = dom.input(attr.value(v)), ' ', dom.clickbutton('-', style({ width: '1.5em' }), function click() {
				h.root.remove();
				row.headers = row.headers.filter(x => x !== h);
				if (row.headers.length === 0) {
					const b = dom.clickbutton('+', style({ width: '1.5em' }), function click() {
						b.remove();
						addHeader('', '');
					});
					headersCell.appendChild(dom.div(style({ textAlign: 'right' }), b));
				}
			}), ' ', dom.clickbutton('+', style({ width: '1.5em' }), function click() {
				addHeader('', '');
			}));
			h = { root: root, key: key, value: value };
			row.headers.push(h);
			headersCell.appendChild(root);
		};
		let smtpMailFromRegexp;
		let msgFromRegexp;
		let verifiedDomain;
		let isForward; // Checkbox
		let listAllowDomain;
		let acceptRejectsToMailbox;
		let mailbox;
		let comment;
		const root = dom.tr(dom.td(smtpMailFromRegexp = dom.input(attr.value(rs.SMTPMailFromRegexp || ''))), dom.td(msgFromRegexp = dom.input(attr.value(rs.MsgFromRegexp || ''))), dom.td(verifiedDomain = dom.input(attr.value(rs.VerifiedDomain || ''))), headersCell, dom.td(dom.label(isForward = dom.input(attr.type('checkbox'), rs.IsForward ? attr.checked('') : []))), dom.td(listAllowDomain = dom.input(attr.value(rs.ListAllowDomain || ''))), dom.td(acceptRejectsToMailbox = dom.input(attr.value(rs.AcceptRejectsToMailbox || ''))), dom.td(mailbox = dom.input(attr.value(rs.Mailbox || ''))), dom.td(comment = dom.input(attr.value(rs.Comment || ''))), dom.td(dom.clickbutton('Remove ruleset', function click() {
			row.root.remove();
			rulesetsRows = rulesetsRows.filter(e => e !== row);
		})));
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
		};
		rulesetsRows.push(row);
		Object.entries(rs.HeadersRegexp || {}).sort().forEach(t => addHeader(t[0], t[1]));
		if (Object.entries(rs.HeadersRegexp || {}).length === 0) {
			const b = dom.clickbutton('+', style({ width: '1.5em' }), function click() {
				b.remove();
				addHeader('', '');
			});
			headersCell.appendChild(dom.div(style({ textAlign: 'right' }), b));
		}
		rulesetsTbody.appendChild(row.root);
	};
	(dest.Rulesets || []).forEach(rs => {
		addRulesetsRow(rs);
	});
	let defaultMailbox;
	let fullName;
	let saveButton;
	const addresses = [name, ...Object.keys(acc.Destinations || {}).filter(a => !a.startsWith('@') && a !== name)];
	dom._kids(page, crumbs(crumblink('Mox Account', '#'), 'Destination ' + name), dom.div(dom.span('Default mailbox', attr.title('Default mailbox where email for this recipient is delivered to if it does not match any ruleset. Default is Inbox.')), dom.br(), defaultMailbox = dom.input(attr.value(dest.Mailbox), attr.placeholder('Inbox'))), dom.br(), dom.div(dom.span('Full name', attr.title('Name to use in From header when composing messages. If not set, the account default full name is used.')), dom.br(), fullName = dom.input(attr.value(dest.FullName))), dom.br(), dom.h2('Rulesets'), dom.p('Incoming messages are checked against the rulesets. If a ruleset matches, the message is delivered to the mailbox configured for the ruleset instead of to the default mailbox.'), dom.p('"Is Forward" does not affect matching, but changes prevents the sending mail server from being included in future junk classifications by clearing fields related to the forwarding email server (IP address, EHLO domain, MAIL FROM domain and a matching DKIM domain), and prevents DMARC rejects for forwarded messages.'), dom.p('"List allow domain" does not affect matching, but skips the regular spam checks if one of the verified domains is a (sub)domain of the domain mentioned here.'), dom.p('"Accept rejects to mailbox" does not affect matching, but causes messages classified as junk to be accepted and delivered to this mailbox, instead of being rejected during the SMTP transaction. Useful for incoming forwarded messages where rejecting incoming messages may cause the forwarding server to stop forwarding.'), dom.table(dom.thead(dom.tr(dom.th('SMTP "MAIL FROM" regexp', attr.title('Matches if this regular expression matches (a substring of) the SMTP MAIL FROM address (not the message From-header). E.g. user@example.org.')), dom.th('Message "From" address regexp', attr.title('Matches if this regular expression matches (a substring of) the single address in the message From header.')), dom.th('Verified domain', attr.title('Matches if this domain matches an SPF- and/or DKIM-verified (sub)domain.')), dom.th('Headers regexp', attr.title('Matches if these header field/value regular expressions all match (substrings of) the message headers. Header fields and valuees are converted to lower case before matching. Whitespace is trimmed from the value before matching. A header field can occur multiple times in a message, only one instance has to match. For mailing lists, you could match on ^list-id$ with the value typically the mailing list address in angled brackets with @ replaced with a dot, e.g. <name\\.lists\\.example\\.org>.')), dom.th('Is Forward', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. Can only be used together with SMTPMailFromRegexp and VerifiedDomain. SMTPMailFromRegexp must be set to the address used to deliver the forwarded message, e.g. '^user(|\\+.*)@forward\\.example$'. Changes to junk analysis: 1. Messages are not rejected for failing a DMARC policy, because a legitimate forwarded message without valid/intact/aligned DKIM signature would be rejected because any verified SPF domain will be 'unaligned', of the forwarding mail server. 2. The sending mail server IP address, and sending EHLO and MAIL FROM domains and matching DKIM domain aren't used in future reputation-based spam classifications (but other verified DKIM domains are) because the forwarding server is not a useful spam signal for future messages.")), dom.th('List allow domain', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If this domain matches an SPF- and/or DKIM-verified (sub)domain, the message is accepted without further spam checks, such as a junk filter or DMARC reject evaluation. DMARC rejects should not apply for mailing lists that are not configured to rewrite the From-header of messages that don't have a passing DKIM signature of the From-domain. Otherwise, by rejecting messages, you may be automatically unsubscribed from the mailing list. The assumption is that mailing lists do their own spam filtering/moderation.")), dom.th('Allow rejects to mailbox', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If a message is classified as spam, it isn't rejected during the SMTP transaction (the normal behaviour), but accepted during the SMTP transaction and delivered to the specified mailbox. The specified mailbox is not automatically cleaned up like the account global Rejects mailbox, unless set to that Rejects mailbox.")), dom.th('Mailbox', attr.title('Mailbox to deliver to if this ruleset matches.')), dom.th('Comment', attr.title('Free-form comments.')), dom.th('Action'))), rulesetsTbody, dom.tfoot(dom.tr(dom.td(attr.colspan('9')), dom.td(dom.clickbutton('Add ruleset', function click() {
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
			VerifiedDNSDomain: { ASCII: '', Unicode: '' },
			ListAllowDNSDomain: { ASCII: '', Unicode: '' },
		});
	}))))), dom.br(), saveButton = dom.clickbutton('Save', async function click() {
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
					VerifiedDNSDomain: { ASCII: '', Unicode: '' },
					ListAllowDNSDomain: { ASCII: '', Unicode: '' },
				};
			}),
		};
		await check(saveButton, client.DestinationSave(name, dest, newDest));
		window.location.reload(); // todo: only refresh part of ui
	}), dom.br(), dom.br(), dom.br(), dom.p("Apple's mail applications don't do account autoconfiguration, and when adding an account it can choose defaults that don't work with modern email servers. Adding an account through a \"mobileconfig\" profile file can be more convenient: It contains the IMAP/SMTP settings such as host name, port, TLS, authentication mechanism and user name. This profile does not contain a login password. Opening the profile adds it under Profiles in System Preferences (macOS) or Settings (iOS), where you can install it. These profiles are not signed, so users will have to ignore the warnings about them being unsigned. ", dom.br(), dom.a(attr.href('https://autoconfig.' + domainName(acc.DNSDomain) + '/profile.mobileconfig?addresses=' + encodeURIComponent(addresses.join(',')) + '&name=' + encodeURIComponent(dest.FullName)), attr.download(''), 'Download .mobileconfig email account profile'), dom.br(), dom.a(attr.href('https://autoconfig.' + domainName(acc.DNSDomain) + '/profile.mobileconfig.qrcode.png?addresses=' + encodeURIComponent(addresses.join(',')) + '&name=' + encodeURIComponent(dest.FullName)), attr.download(''), 'Open QR-code with link to .mobileconfig profile')));
};
const init = async () => {
	let curhash;
	const hashChange = async () => {
		if (curhash === window.location.hash) {
			return;
		}
		let h = decodeURIComponent(window.location.hash);
		if (h !== '' && h.substring(0, 1) == '#') {
			h = h.substring(1);
		}
		const t = h.split('/');
		page.classList.add('loading');
		try {
			if (h === '') {
				await index();
			}
			else if (t[0] === 'destinations' && t.length === 2) {
				await destination(t[1]);
			}
			else {
				dom._kids(page, 'page not found');
			}
		}
		catch (err) {
			console.log({ err });
			window.alert('Error: ' + errmsg(err));
			window.location.hash = curhash || '';
			curhash = window.location.hash;
			return;
		}
		curhash = window.location.hash;
		page.classList.remove('loading');
	};
	window.addEventListener('hashchange', hashChange);
	hashChange();
};
window.addEventListener('load', async () => {
	try {
		await init();
	}
	catch (err) {
		window.alert('Error: ' + errmsg(err));
	}
});
