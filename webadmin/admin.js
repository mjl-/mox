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
	// Policy as used in DMARC DNS record for "p=" or "sp=".
	let DMARCPolicy;
	(function (DMARCPolicy) {
		DMARCPolicy["PolicyEmpty"] = "";
		DMARCPolicy["PolicyNone"] = "none";
		DMARCPolicy["PolicyQuarantine"] = "quarantine";
		DMARCPolicy["PolicyReject"] = "reject";
	})(DMARCPolicy = api.DMARCPolicy || (api.DMARCPolicy = {}));
	// Align specifies the required alignment of a domain name.
	let Align;
	(function (Align) {
		Align["AlignStrict"] = "s";
		Align["AlignRelaxed"] = "r";
	})(Align = api.Align || (api.Align = {}));
	// Mode indicates how the policy should be interpreted.
	let Mode;
	(function (Mode) {
		Mode["ModeEnforce"] = "enforce";
		Mode["ModeTesting"] = "testing";
		Mode["ModeNone"] = "none";
	})(Mode = api.Mode || (api.Mode = {}));
	// AuthResult is the result of a login attempt.
	let AuthResult;
	(function (AuthResult) {
		AuthResult["AuthSuccess"] = "ok";
		AuthResult["AuthBadUser"] = "baduser";
		AuthResult["AuthBadPassword"] = "badpassword";
		AuthResult["AuthBadCredentials"] = "badcreds";
		AuthResult["AuthBadChannelBinding"] = "badchanbind";
		AuthResult["AuthBadProtocol"] = "badprotocol";
		AuthResult["AuthLoginDisabled"] = "logindisabled";
		AuthResult["AuthError"] = "error";
		AuthResult["AuthAborted"] = "aborted";
	})(AuthResult = api.AuthResult || (api.AuthResult = {}));
	api.structTypes = { "Account": true, "Address": true, "AddressAlias": true, "Alias": true, "AliasAddress": true, "AuthResults": true, "AutoconfCheckResult": true, "AutodiscoverCheckResult": true, "AutodiscoverSRV": true, "AutomaticJunkFlags": true, "Canonicalization": true, "CheckResult": true, "ClientConfigs": true, "ClientConfigsEntry": true, "ConfigDomain": true, "DANECheckResult": true, "DKIM": true, "DKIMAuthResult": true, "DKIMCheckResult": true, "DKIMRecord": true, "DMARC": true, "DMARCCheckResult": true, "DMARCRecord": true, "DMARCSummary": true, "DNSSECResult": true, "DateRange": true, "Destination": true, "Directive": true, "Domain": true, "DomainFeedback": true, "Dynamic": true, "Evaluation": true, "EvaluationStat": true, "Extension": true, "FailureDetails": true, "Filter": true, "HoldRule": true, "Hook": true, "HookFilter": true, "HookResult": true, "HookRetired": true, "HookRetiredFilter": true, "HookRetiredSort": true, "HookSort": true, "IPDomain": true, "IPRevCheckResult": true, "Identifiers": true, "IncomingWebhook": true, "JunkFilter": true, "LoginAttempt": true, "MTASTS": true, "MTASTSCheckResult": true, "MTASTSRecord": true, "MX": true, "MXCheckResult": true, "Modifier": true, "Msg": true, "MsgResult": true, "MsgRetired": true, "OutgoingWebhook": true, "Pair": true, "Policy": true, "PolicyEvaluated": true, "PolicyOverrideReason": true, "PolicyPublished": true, "PolicyRecord": true, "Record": true, "Report": true, "ReportMetadata": true, "ReportRecord": true, "Result": true, "ResultPolicy": true, "RetiredFilter": true, "RetiredSort": true, "Reverse": true, "Route": true, "Row": true, "Ruleset": true, "SMTPAuth": true, "SPFAuthResult": true, "SPFCheckResult": true, "SPFRecord": true, "SRV": true, "SRVConfCheckResult": true, "STSMX": true, "Selector": true, "Sort": true, "SubjectPass": true, "Summary": true, "SuppressAddress": true, "TLSCheckResult": true, "TLSPublicKey": true, "TLSRPT": true, "TLSRPTCheckResult": true, "TLSRPTDateRange": true, "TLSRPTRecord": true, "TLSRPTSummary": true, "TLSRPTSuppressAddress": true, "TLSReportRecord": true, "TLSResult": true, "Transport": true, "TransportDirect": true, "TransportSMTP": true, "TransportSocks": true, "URI": true, "WebForward": true, "WebHandler": true, "WebInternal": true, "WebRedirect": true, "WebStatic": true, "WebserverConfig": true };
	api.stringsTypes = { "Align": true, "AuthResult": true, "CSRFToken": true, "DMARCPolicy": true, "IP": true, "Localpart": true, "Mode": true, "RUA": true };
	api.intsTypes = {};
	api.types = {
		"CheckResult": { "Name": "CheckResult", "Docs": "", "Fields": [{ "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "DNSSEC", "Docs": "", "Typewords": ["DNSSECResult"] }, { "Name": "IPRev", "Docs": "", "Typewords": ["IPRevCheckResult"] }, { "Name": "MX", "Docs": "", "Typewords": ["MXCheckResult"] }, { "Name": "TLS", "Docs": "", "Typewords": ["TLSCheckResult"] }, { "Name": "DANE", "Docs": "", "Typewords": ["DANECheckResult"] }, { "Name": "SPF", "Docs": "", "Typewords": ["SPFCheckResult"] }, { "Name": "DKIM", "Docs": "", "Typewords": ["DKIMCheckResult"] }, { "Name": "DMARC", "Docs": "", "Typewords": ["DMARCCheckResult"] }, { "Name": "HostTLSRPT", "Docs": "", "Typewords": ["TLSRPTCheckResult"] }, { "Name": "DomainTLSRPT", "Docs": "", "Typewords": ["TLSRPTCheckResult"] }, { "Name": "MTASTS", "Docs": "", "Typewords": ["MTASTSCheckResult"] }, { "Name": "SRVConf", "Docs": "", "Typewords": ["SRVConfCheckResult"] }, { "Name": "Autoconf", "Docs": "", "Typewords": ["AutoconfCheckResult"] }, { "Name": "Autodiscover", "Docs": "", "Typewords": ["AutodiscoverCheckResult"] }] },
		"DNSSECResult": { "Name": "DNSSECResult", "Docs": "", "Fields": [{ "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"IPRevCheckResult": { "Name": "IPRevCheckResult", "Docs": "", "Fields": [{ "Name": "Hostname", "Docs": "", "Typewords": ["Domain"] }, { "Name": "IPNames", "Docs": "", "Typewords": ["{}", "[]", "string"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Domain": { "Name": "Domain", "Docs": "", "Fields": [{ "Name": "ASCII", "Docs": "", "Typewords": ["string"] }, { "Name": "Unicode", "Docs": "", "Typewords": ["string"] }] },
		"MXCheckResult": { "Name": "MXCheckResult", "Docs": "", "Fields": [{ "Name": "Records", "Docs": "", "Typewords": ["[]", "MX"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"MX": { "Name": "MX", "Docs": "", "Fields": [{ "Name": "Host", "Docs": "", "Typewords": ["string"] }, { "Name": "Pref", "Docs": "", "Typewords": ["int32"] }, { "Name": "IPs", "Docs": "", "Typewords": ["[]", "string"] }] },
		"TLSCheckResult": { "Name": "TLSCheckResult", "Docs": "", "Fields": [{ "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"DANECheckResult": { "Name": "DANECheckResult", "Docs": "", "Fields": [{ "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"SPFCheckResult": { "Name": "SPFCheckResult", "Docs": "", "Fields": [{ "Name": "DomainTXT", "Docs": "", "Typewords": ["string"] }, { "Name": "DomainRecord", "Docs": "", "Typewords": ["nullable", "SPFRecord"] }, { "Name": "HostTXT", "Docs": "", "Typewords": ["string"] }, { "Name": "HostRecord", "Docs": "", "Typewords": ["nullable", "SPFRecord"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"SPFRecord": { "Name": "SPFRecord", "Docs": "", "Fields": [{ "Name": "Version", "Docs": "", "Typewords": ["string"] }, { "Name": "Directives", "Docs": "", "Typewords": ["[]", "Directive"] }, { "Name": "Redirect", "Docs": "", "Typewords": ["string"] }, { "Name": "Explanation", "Docs": "", "Typewords": ["string"] }, { "Name": "Other", "Docs": "", "Typewords": ["[]", "Modifier"] }] },
		"Directive": { "Name": "Directive", "Docs": "", "Fields": [{ "Name": "Qualifier", "Docs": "", "Typewords": ["string"] }, { "Name": "Mechanism", "Docs": "", "Typewords": ["string"] }, { "Name": "DomainSpec", "Docs": "", "Typewords": ["string"] }, { "Name": "IPstr", "Docs": "", "Typewords": ["string"] }, { "Name": "IP4CIDRLen", "Docs": "", "Typewords": ["nullable", "int32"] }, { "Name": "IP6CIDRLen", "Docs": "", "Typewords": ["nullable", "int32"] }] },
		"Modifier": { "Name": "Modifier", "Docs": "", "Fields": [{ "Name": "Key", "Docs": "", "Typewords": ["string"] }, { "Name": "Value", "Docs": "", "Typewords": ["string"] }] },
		"DKIMCheckResult": { "Name": "DKIMCheckResult", "Docs": "", "Fields": [{ "Name": "Records", "Docs": "", "Typewords": ["[]", "DKIMRecord"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"DKIMRecord": { "Name": "DKIMRecord", "Docs": "", "Fields": [{ "Name": "Selector", "Docs": "", "Typewords": ["string"] }, { "Name": "TXT", "Docs": "", "Typewords": ["string"] }, { "Name": "Record", "Docs": "", "Typewords": ["nullable", "Record"] }] },
		"Record": { "Name": "Record", "Docs": "", "Fields": [{ "Name": "Version", "Docs": "", "Typewords": ["string"] }, { "Name": "Hashes", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Key", "Docs": "", "Typewords": ["string"] }, { "Name": "Notes", "Docs": "", "Typewords": ["string"] }, { "Name": "Pubkey", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Services", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Flags", "Docs": "", "Typewords": ["[]", "string"] }] },
		"DMARCCheckResult": { "Name": "DMARCCheckResult", "Docs": "", "Fields": [{ "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "TXT", "Docs": "", "Typewords": ["string"] }, { "Name": "Record", "Docs": "", "Typewords": ["nullable", "DMARCRecord"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"DMARCRecord": { "Name": "DMARCRecord", "Docs": "", "Fields": [{ "Name": "Version", "Docs": "", "Typewords": ["string"] }, { "Name": "Policy", "Docs": "", "Typewords": ["DMARCPolicy"] }, { "Name": "SubdomainPolicy", "Docs": "", "Typewords": ["DMARCPolicy"] }, { "Name": "AggregateReportAddresses", "Docs": "", "Typewords": ["[]", "URI"] }, { "Name": "FailureReportAddresses", "Docs": "", "Typewords": ["[]", "URI"] }, { "Name": "ADKIM", "Docs": "", "Typewords": ["Align"] }, { "Name": "ASPF", "Docs": "", "Typewords": ["Align"] }, { "Name": "AggregateReportingInterval", "Docs": "", "Typewords": ["int32"] }, { "Name": "FailureReportingOptions", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ReportingFormat", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Percentage", "Docs": "", "Typewords": ["int32"] }] },
		"URI": { "Name": "URI", "Docs": "", "Fields": [{ "Name": "Address", "Docs": "", "Typewords": ["string"] }, { "Name": "MaxSize", "Docs": "", "Typewords": ["uint64"] }, { "Name": "Unit", "Docs": "", "Typewords": ["string"] }] },
		"TLSRPTCheckResult": { "Name": "TLSRPTCheckResult", "Docs": "", "Fields": [{ "Name": "TXT", "Docs": "", "Typewords": ["string"] }, { "Name": "Record", "Docs": "", "Typewords": ["nullable", "TLSRPTRecord"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"TLSRPTRecord": { "Name": "TLSRPTRecord", "Docs": "", "Fields": [{ "Name": "Version", "Docs": "", "Typewords": ["string"] }, { "Name": "RUAs", "Docs": "", "Typewords": ["[]", "[]", "RUA"] }, { "Name": "Extensions", "Docs": "", "Typewords": ["[]", "Extension"] }] },
		"Extension": { "Name": "Extension", "Docs": "", "Fields": [{ "Name": "Key", "Docs": "", "Typewords": ["string"] }, { "Name": "Value", "Docs": "", "Typewords": ["string"] }] },
		"MTASTSCheckResult": { "Name": "MTASTSCheckResult", "Docs": "", "Fields": [{ "Name": "TXT", "Docs": "", "Typewords": ["string"] }, { "Name": "Record", "Docs": "", "Typewords": ["nullable", "MTASTSRecord"] }, { "Name": "PolicyText", "Docs": "", "Typewords": ["string"] }, { "Name": "Policy", "Docs": "", "Typewords": ["nullable", "Policy"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"MTASTSRecord": { "Name": "MTASTSRecord", "Docs": "", "Fields": [{ "Name": "Version", "Docs": "", "Typewords": ["string"] }, { "Name": "ID", "Docs": "", "Typewords": ["string"] }, { "Name": "Extensions", "Docs": "", "Typewords": ["[]", "Pair"] }] },
		"Pair": { "Name": "Pair", "Docs": "", "Fields": [{ "Name": "Key", "Docs": "", "Typewords": ["string"] }, { "Name": "Value", "Docs": "", "Typewords": ["string"] }] },
		"Policy": { "Name": "Policy", "Docs": "", "Fields": [{ "Name": "Version", "Docs": "", "Typewords": ["string"] }, { "Name": "Mode", "Docs": "", "Typewords": ["Mode"] }, { "Name": "MX", "Docs": "", "Typewords": ["[]", "STSMX"] }, { "Name": "MaxAgeSeconds", "Docs": "", "Typewords": ["int32"] }, { "Name": "Extensions", "Docs": "", "Typewords": ["[]", "Pair"] }] },
		"STSMX": { "Name": "STSMX", "Docs": "", "Fields": [{ "Name": "Wildcard", "Docs": "", "Typewords": ["bool"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }] },
		"SRVConfCheckResult": { "Name": "SRVConfCheckResult", "Docs": "", "Fields": [{ "Name": "SRVs", "Docs": "", "Typewords": ["{}", "[]", "SRV"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"SRV": { "Name": "SRV", "Docs": "", "Fields": [{ "Name": "Target", "Docs": "", "Typewords": ["string"] }, { "Name": "Port", "Docs": "", "Typewords": ["uint16"] }, { "Name": "Priority", "Docs": "", "Typewords": ["uint16"] }, { "Name": "Weight", "Docs": "", "Typewords": ["uint16"] }] },
		"AutoconfCheckResult": { "Name": "AutoconfCheckResult", "Docs": "", "Fields": [{ "Name": "ClientSettingsDomainIPs", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "IPs", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"AutodiscoverCheckResult": { "Name": "AutodiscoverCheckResult", "Docs": "", "Fields": [{ "Name": "Records", "Docs": "", "Typewords": ["[]", "AutodiscoverSRV"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Warnings", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Instructions", "Docs": "", "Typewords": ["[]", "string"] }] },
		"AutodiscoverSRV": { "Name": "AutodiscoverSRV", "Docs": "", "Fields": [{ "Name": "Target", "Docs": "", "Typewords": ["string"] }, { "Name": "Port", "Docs": "", "Typewords": ["uint16"] }, { "Name": "Priority", "Docs": "", "Typewords": ["uint16"] }, { "Name": "Weight", "Docs": "", "Typewords": ["uint16"] }, { "Name": "IPs", "Docs": "", "Typewords": ["[]", "string"] }] },
		"ConfigDomain": { "Name": "ConfigDomain", "Docs": "", "Fields": [{ "Name": "Disabled", "Docs": "", "Typewords": ["bool"] }, { "Name": "Description", "Docs": "", "Typewords": ["string"] }, { "Name": "ClientSettingsDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "LocalpartCatchallSeparator", "Docs": "", "Typewords": ["string"] }, { "Name": "LocalpartCatchallSeparators", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "LocalpartCaseSensitive", "Docs": "", "Typewords": ["bool"] }, { "Name": "DKIM", "Docs": "", "Typewords": ["DKIM"] }, { "Name": "DMARC", "Docs": "", "Typewords": ["nullable", "DMARC"] }, { "Name": "MTASTS", "Docs": "", "Typewords": ["nullable", "MTASTS"] }, { "Name": "TLSRPT", "Docs": "", "Typewords": ["nullable", "TLSRPT"] }, { "Name": "Routes", "Docs": "", "Typewords": ["[]", "Route"] }, { "Name": "Aliases", "Docs": "", "Typewords": ["{}", "Alias"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "LocalpartCatchallSeparatorsEffective", "Docs": "", "Typewords": ["[]", "string"] }] },
		"DKIM": { "Name": "DKIM", "Docs": "", "Fields": [{ "Name": "Selectors", "Docs": "", "Typewords": ["{}", "Selector"] }, { "Name": "Sign", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Selector": { "Name": "Selector", "Docs": "", "Fields": [{ "Name": "Hash", "Docs": "", "Typewords": ["string"] }, { "Name": "HashEffective", "Docs": "", "Typewords": ["string"] }, { "Name": "Canonicalization", "Docs": "", "Typewords": ["Canonicalization"] }, { "Name": "Headers", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "HeadersEffective", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "DontSealHeaders", "Docs": "", "Typewords": ["bool"] }, { "Name": "Expiration", "Docs": "", "Typewords": ["string"] }, { "Name": "PrivateKeyFile", "Docs": "", "Typewords": ["string"] }, { "Name": "Algorithm", "Docs": "", "Typewords": ["string"] }] },
		"Canonicalization": { "Name": "Canonicalization", "Docs": "", "Fields": [{ "Name": "HeaderRelaxed", "Docs": "", "Typewords": ["bool"] }, { "Name": "BodyRelaxed", "Docs": "", "Typewords": ["bool"] }] },
		"DMARC": { "Name": "DMARC", "Docs": "", "Fields": [{ "Name": "Localpart", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "ParsedLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "DNSDomain", "Docs": "", "Typewords": ["Domain"] }] },
		"MTASTS": { "Name": "MTASTS", "Docs": "", "Fields": [{ "Name": "PolicyID", "Docs": "", "Typewords": ["string"] }, { "Name": "Mode", "Docs": "", "Typewords": ["Mode"] }, { "Name": "MaxAge", "Docs": "", "Typewords": ["int64"] }, { "Name": "MX", "Docs": "", "Typewords": ["[]", "string"] }] },
		"TLSRPT": { "Name": "TLSRPT", "Docs": "", "Fields": [{ "Name": "Localpart", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "ParsedLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "DNSDomain", "Docs": "", "Typewords": ["Domain"] }] },
		"Route": { "Name": "Route", "Docs": "", "Fields": [{ "Name": "FromDomain", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ToDomain", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "MinimumAttempts", "Docs": "", "Typewords": ["int32"] }, { "Name": "Transport", "Docs": "", "Typewords": ["string"] }, { "Name": "FromDomainASCII", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ToDomainASCII", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Alias": { "Name": "Alias", "Docs": "", "Fields": [{ "Name": "Addresses", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "PostPublic", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListMembers", "Docs": "", "Typewords": ["bool"] }, { "Name": "AllowMsgFrom", "Docs": "", "Typewords": ["bool"] }, { "Name": "LocalpartStr", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "ParsedAddresses", "Docs": "", "Typewords": ["[]", "AliasAddress"] }] },
		"AliasAddress": { "Name": "AliasAddress", "Docs": "", "Fields": [{ "Name": "Address", "Docs": "", "Typewords": ["Address"] }, { "Name": "AccountName", "Docs": "", "Typewords": ["string"] }, { "Name": "Destination", "Docs": "", "Typewords": ["Destination"] }] },
		"Address": { "Name": "Address", "Docs": "", "Fields": [{ "Name": "Localpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }] },
		"Destination": { "Name": "Destination", "Docs": "", "Fields": [{ "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Rulesets", "Docs": "", "Typewords": ["[]", "Ruleset"] }, { "Name": "SMTPError", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageAuthRequiredSMTPError", "Docs": "", "Typewords": ["string"] }, { "Name": "FullName", "Docs": "", "Typewords": ["string"] }] },
		"Ruleset": { "Name": "Ruleset", "Docs": "", "Fields": [{ "Name": "SMTPMailFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "HeadersRegexp", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListAllowDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "AcceptRejectsToMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Comment", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "ListAllowDNSDomain", "Docs": "", "Typewords": ["Domain"] }] },
		"Account": { "Name": "Account", "Docs": "", "Fields": [{ "Name": "OutgoingWebhook", "Docs": "", "Typewords": ["nullable", "OutgoingWebhook"] }, { "Name": "IncomingWebhook", "Docs": "", "Typewords": ["nullable", "IncomingWebhook"] }, { "Name": "FromIDLoginAddresses", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "KeepRetiredMessagePeriod", "Docs": "", "Typewords": ["int64"] }, { "Name": "KeepRetiredWebhookPeriod", "Docs": "", "Typewords": ["int64"] }, { "Name": "LoginDisabled", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Description", "Docs": "", "Typewords": ["string"] }, { "Name": "FullName", "Docs": "", "Typewords": ["string"] }, { "Name": "Destinations", "Docs": "", "Typewords": ["{}", "Destination"] }, { "Name": "SubjectPass", "Docs": "", "Typewords": ["SubjectPass"] }, { "Name": "QuotaMessageSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "RejectsMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "KeepRejects", "Docs": "", "Typewords": ["bool"] }, { "Name": "AutomaticJunkFlags", "Docs": "", "Typewords": ["AutomaticJunkFlags"] }, { "Name": "JunkFilter", "Docs": "", "Typewords": ["nullable", "JunkFilter"] }, { "Name": "MaxOutgoingMessagesPerDay", "Docs": "", "Typewords": ["int32"] }, { "Name": "MaxFirstTimeRecipientsPerDay", "Docs": "", "Typewords": ["int32"] }, { "Name": "NoFirstTimeSenderDelay", "Docs": "", "Typewords": ["bool"] }, { "Name": "NoCustomPassword", "Docs": "", "Typewords": ["bool"] }, { "Name": "Routes", "Docs": "", "Typewords": ["[]", "Route"] }, { "Name": "DNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "Aliases", "Docs": "", "Typewords": ["[]", "AddressAlias"] }] },
		"OutgoingWebhook": { "Name": "OutgoingWebhook", "Docs": "", "Fields": [{ "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Authorization", "Docs": "", "Typewords": ["string"] }, { "Name": "Events", "Docs": "", "Typewords": ["[]", "string"] }] },
		"IncomingWebhook": { "Name": "IncomingWebhook", "Docs": "", "Fields": [{ "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Authorization", "Docs": "", "Typewords": ["string"] }] },
		"SubjectPass": { "Name": "SubjectPass", "Docs": "", "Fields": [{ "Name": "Period", "Docs": "", "Typewords": ["int64"] }] },
		"AutomaticJunkFlags": { "Name": "AutomaticJunkFlags", "Docs": "", "Fields": [{ "Name": "Enabled", "Docs": "", "Typewords": ["bool"] }, { "Name": "JunkMailboxRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "NeutralMailboxRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "NotJunkMailboxRegexp", "Docs": "", "Typewords": ["string"] }] },
		"JunkFilter": { "Name": "JunkFilter", "Docs": "", "Fields": [{ "Name": "Threshold", "Docs": "", "Typewords": ["float64"] }, { "Name": "Onegrams", "Docs": "", "Typewords": ["bool"] }, { "Name": "Twograms", "Docs": "", "Typewords": ["bool"] }, { "Name": "Threegrams", "Docs": "", "Typewords": ["bool"] }, { "Name": "MaxPower", "Docs": "", "Typewords": ["float64"] }, { "Name": "TopWords", "Docs": "", "Typewords": ["int32"] }, { "Name": "IgnoreWords", "Docs": "", "Typewords": ["float64"] }, { "Name": "RareWords", "Docs": "", "Typewords": ["int32"] }] },
		"AddressAlias": { "Name": "AddressAlias", "Docs": "", "Fields": [{ "Name": "SubscriptionAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "Alias", "Docs": "", "Typewords": ["Alias"] }, { "Name": "MemberAddresses", "Docs": "", "Typewords": ["[]", "string"] }] },
		"PolicyRecord": { "Name": "PolicyRecord", "Docs": "", "Fields": [{ "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Inserted", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "ValidEnd", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "LastUpdate", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "LastUse", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Backoff", "Docs": "", "Typewords": ["bool"] }, { "Name": "RecordID", "Docs": "", "Typewords": ["string"] }, { "Name": "Version", "Docs": "", "Typewords": ["string"] }, { "Name": "Mode", "Docs": "", "Typewords": ["Mode"] }, { "Name": "MX", "Docs": "", "Typewords": ["[]", "STSMX"] }, { "Name": "MaxAgeSeconds", "Docs": "", "Typewords": ["int32"] }, { "Name": "Extensions", "Docs": "", "Typewords": ["[]", "Pair"] }, { "Name": "PolicyText", "Docs": "", "Typewords": ["string"] }] },
		"TLSReportRecord": { "Name": "TLSReportRecord", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "FromDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "HostReport", "Docs": "", "Typewords": ["bool"] }, { "Name": "Report", "Docs": "", "Typewords": ["Report"] }] },
		"Report": { "Name": "Report", "Docs": "", "Fields": [{ "Name": "OrganizationName", "Docs": "", "Typewords": ["string"] }, { "Name": "DateRange", "Docs": "", "Typewords": ["TLSRPTDateRange"] }, { "Name": "ContactInfo", "Docs": "", "Typewords": ["string"] }, { "Name": "ReportID", "Docs": "", "Typewords": ["string"] }, { "Name": "Policies", "Docs": "", "Typewords": ["[]", "Result"] }] },
		"TLSRPTDateRange": { "Name": "TLSRPTDateRange", "Docs": "", "Fields": [{ "Name": "Start", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "End", "Docs": "", "Typewords": ["timestamp"] }] },
		"Result": { "Name": "Result", "Docs": "", "Fields": [{ "Name": "Policy", "Docs": "", "Typewords": ["ResultPolicy"] }, { "Name": "Summary", "Docs": "", "Typewords": ["Summary"] }, { "Name": "FailureDetails", "Docs": "", "Typewords": ["[]", "FailureDetails"] }] },
		"ResultPolicy": { "Name": "ResultPolicy", "Docs": "", "Fields": [{ "Name": "Type", "Docs": "", "Typewords": ["string"] }, { "Name": "String", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "MXHost", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Summary": { "Name": "Summary", "Docs": "", "Fields": [{ "Name": "TotalSuccessfulSessionCount", "Docs": "", "Typewords": ["int64"] }, { "Name": "TotalFailureSessionCount", "Docs": "", "Typewords": ["int64"] }] },
		"FailureDetails": { "Name": "FailureDetails", "Docs": "", "Fields": [{ "Name": "ResultType", "Docs": "", "Typewords": ["string"] }, { "Name": "SendingMTAIP", "Docs": "", "Typewords": ["string"] }, { "Name": "ReceivingMXHostname", "Docs": "", "Typewords": ["string"] }, { "Name": "ReceivingMXHelo", "Docs": "", "Typewords": ["string"] }, { "Name": "ReceivingIP", "Docs": "", "Typewords": ["string"] }, { "Name": "FailedSessionCount", "Docs": "", "Typewords": ["int64"] }, { "Name": "AdditionalInformation", "Docs": "", "Typewords": ["string"] }, { "Name": "FailureReasonCode", "Docs": "", "Typewords": ["string"] }] },
		"TLSRPTSummary": { "Name": "TLSRPTSummary", "Docs": "", "Fields": [{ "Name": "PolicyDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "Success", "Docs": "", "Typewords": ["int64"] }, { "Name": "Failure", "Docs": "", "Typewords": ["int64"] }, { "Name": "ResultTypeCounts", "Docs": "", "Typewords": ["{}", "int64"] }] },
		"DomainFeedback": { "Name": "DomainFeedback", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "FromDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "Version", "Docs": "", "Typewords": ["string"] }, { "Name": "ReportMetadata", "Docs": "", "Typewords": ["ReportMetadata"] }, { "Name": "PolicyPublished", "Docs": "", "Typewords": ["PolicyPublished"] }, { "Name": "Records", "Docs": "", "Typewords": ["[]", "ReportRecord"] }] },
		"ReportMetadata": { "Name": "ReportMetadata", "Docs": "", "Fields": [{ "Name": "OrgName", "Docs": "", "Typewords": ["string"] }, { "Name": "Email", "Docs": "", "Typewords": ["string"] }, { "Name": "ExtraContactInfo", "Docs": "", "Typewords": ["string"] }, { "Name": "ReportID", "Docs": "", "Typewords": ["string"] }, { "Name": "DateRange", "Docs": "", "Typewords": ["DateRange"] }, { "Name": "Errors", "Docs": "", "Typewords": ["[]", "string"] }] },
		"DateRange": { "Name": "DateRange", "Docs": "", "Fields": [{ "Name": "Begin", "Docs": "", "Typewords": ["int64"] }, { "Name": "End", "Docs": "", "Typewords": ["int64"] }] },
		"PolicyPublished": { "Name": "PolicyPublished", "Docs": "", "Fields": [{ "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "ADKIM", "Docs": "", "Typewords": ["string"] }, { "Name": "ASPF", "Docs": "", "Typewords": ["string"] }, { "Name": "Policy", "Docs": "", "Typewords": ["string"] }, { "Name": "SubdomainPolicy", "Docs": "", "Typewords": ["string"] }, { "Name": "Percentage", "Docs": "", "Typewords": ["int32"] }, { "Name": "ReportingOptions", "Docs": "", "Typewords": ["string"] }] },
		"ReportRecord": { "Name": "ReportRecord", "Docs": "", "Fields": [{ "Name": "Row", "Docs": "", "Typewords": ["Row"] }, { "Name": "Identifiers", "Docs": "", "Typewords": ["Identifiers"] }, { "Name": "AuthResults", "Docs": "", "Typewords": ["AuthResults"] }] },
		"Row": { "Name": "Row", "Docs": "", "Fields": [{ "Name": "SourceIP", "Docs": "", "Typewords": ["string"] }, { "Name": "Count", "Docs": "", "Typewords": ["int32"] }, { "Name": "PolicyEvaluated", "Docs": "", "Typewords": ["PolicyEvaluated"] }] },
		"PolicyEvaluated": { "Name": "PolicyEvaluated", "Docs": "", "Fields": [{ "Name": "Disposition", "Docs": "", "Typewords": ["string"] }, { "Name": "DKIM", "Docs": "", "Typewords": ["string"] }, { "Name": "SPF", "Docs": "", "Typewords": ["string"] }, { "Name": "Reasons", "Docs": "", "Typewords": ["[]", "PolicyOverrideReason"] }] },
		"PolicyOverrideReason": { "Name": "PolicyOverrideReason", "Docs": "", "Fields": [{ "Name": "Type", "Docs": "", "Typewords": ["string"] }, { "Name": "Comment", "Docs": "", "Typewords": ["string"] }] },
		"Identifiers": { "Name": "Identifiers", "Docs": "", "Fields": [{ "Name": "EnvelopeTo", "Docs": "", "Typewords": ["string"] }, { "Name": "EnvelopeFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "HeaderFrom", "Docs": "", "Typewords": ["string"] }] },
		"AuthResults": { "Name": "AuthResults", "Docs": "", "Fields": [{ "Name": "DKIM", "Docs": "", "Typewords": ["[]", "DKIMAuthResult"] }, { "Name": "SPF", "Docs": "", "Typewords": ["[]", "SPFAuthResult"] }] },
		"DKIMAuthResult": { "Name": "DKIMAuthResult", "Docs": "", "Fields": [{ "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Selector", "Docs": "", "Typewords": ["string"] }, { "Name": "Result", "Docs": "", "Typewords": ["string"] }, { "Name": "HumanResult", "Docs": "", "Typewords": ["string"] }] },
		"SPFAuthResult": { "Name": "SPFAuthResult", "Docs": "", "Fields": [{ "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Scope", "Docs": "", "Typewords": ["string"] }, { "Name": "Result", "Docs": "", "Typewords": ["string"] }] },
		"DMARCSummary": { "Name": "DMARCSummary", "Docs": "", "Fields": [{ "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Total", "Docs": "", "Typewords": ["int32"] }, { "Name": "DispositionNone", "Docs": "", "Typewords": ["int32"] }, { "Name": "DispositionQuarantine", "Docs": "", "Typewords": ["int32"] }, { "Name": "DispositionReject", "Docs": "", "Typewords": ["int32"] }, { "Name": "DKIMFail", "Docs": "", "Typewords": ["int32"] }, { "Name": "SPFFail", "Docs": "", "Typewords": ["int32"] }, { "Name": "PolicyOverrides", "Docs": "", "Typewords": ["{}", "int32"] }] },
		"Reverse": { "Name": "Reverse", "Docs": "", "Fields": [{ "Name": "Hostnames", "Docs": "", "Typewords": ["[]", "string"] }] },
		"ClientConfigs": { "Name": "ClientConfigs", "Docs": "", "Fields": [{ "Name": "Entries", "Docs": "", "Typewords": ["[]", "ClientConfigsEntry"] }] },
		"ClientConfigsEntry": { "Name": "ClientConfigsEntry", "Docs": "", "Fields": [{ "Name": "Protocol", "Docs": "", "Typewords": ["string"] }, { "Name": "Host", "Docs": "", "Typewords": ["Domain"] }, { "Name": "Port", "Docs": "", "Typewords": ["int32"] }, { "Name": "Listener", "Docs": "", "Typewords": ["string"] }, { "Name": "Note", "Docs": "", "Typewords": ["string"] }] },
		"HoldRule": { "Name": "HoldRule", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "SenderDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "RecipientDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "SenderDomainStr", "Docs": "", "Typewords": ["string"] }, { "Name": "RecipientDomainStr", "Docs": "", "Typewords": ["string"] }] },
		"Filter": { "Name": "Filter", "Docs": "", "Fields": [{ "Name": "Max", "Docs": "", "Typewords": ["int32"] }, { "Name": "IDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "From", "Docs": "", "Typewords": ["string"] }, { "Name": "To", "Docs": "", "Typewords": ["string"] }, { "Name": "Hold", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "Submitted", "Docs": "", "Typewords": ["string"] }, { "Name": "NextAttempt", "Docs": "", "Typewords": ["string"] }, { "Name": "Transport", "Docs": "", "Typewords": ["nullable", "string"] }] },
		"Sort": { "Name": "Sort", "Docs": "", "Fields": [{ "Name": "Field", "Docs": "", "Typewords": ["string"] }, { "Name": "LastID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Last", "Docs": "", "Typewords": ["any"] }, { "Name": "Asc", "Docs": "", "Typewords": ["bool"] }] },
		"Msg": { "Name": "Msg", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "BaseID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Queued", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Hold", "Docs": "", "Typewords": ["bool"] }, { "Name": "SenderAccount", "Docs": "", "Typewords": ["string"] }, { "Name": "SenderLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "SenderDomain", "Docs": "", "Typewords": ["IPDomain"] }, { "Name": "SenderDomainStr", "Docs": "", "Typewords": ["string"] }, { "Name": "FromID", "Docs": "", "Typewords": ["string"] }, { "Name": "RecipientLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "RecipientDomain", "Docs": "", "Typewords": ["IPDomain"] }, { "Name": "RecipientDomainStr", "Docs": "", "Typewords": ["string"] }, { "Name": "Attempts", "Docs": "", "Typewords": ["int32"] }, { "Name": "MaxAttempts", "Docs": "", "Typewords": ["int32"] }, { "Name": "DialedIPs", "Docs": "", "Typewords": ["{}", "[]", "IP"] }, { "Name": "NextAttempt", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "LastAttempt", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Results", "Docs": "", "Typewords": ["[]", "MsgResult"] }, { "Name": "Has8bit", "Docs": "", "Typewords": ["bool"] }, { "Name": "SMTPUTF8", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsDMARCReport", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsTLSReport", "Docs": "", "Typewords": ["bool"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgPrefix", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "DSNUTF8", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Transport", "Docs": "", "Typewords": ["string"] }, { "Name": "RequireTLS", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "FutureReleaseRequest", "Docs": "", "Typewords": ["string"] }, { "Name": "Extra", "Docs": "", "Typewords": ["{}", "string"] }] },
		"IPDomain": { "Name": "IPDomain", "Docs": "", "Fields": [{ "Name": "IP", "Docs": "", "Typewords": ["IP"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }] },
		"MsgResult": { "Name": "MsgResult", "Docs": "", "Fields": [{ "Name": "Start", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Duration", "Docs": "", "Typewords": ["int64"] }, { "Name": "Success", "Docs": "", "Typewords": ["bool"] }, { "Name": "Code", "Docs": "", "Typewords": ["int32"] }, { "Name": "Secode", "Docs": "", "Typewords": ["string"] }, { "Name": "Error", "Docs": "", "Typewords": ["string"] }] },
		"RetiredFilter": { "Name": "RetiredFilter", "Docs": "", "Fields": [{ "Name": "Max", "Docs": "", "Typewords": ["int32"] }, { "Name": "IDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "From", "Docs": "", "Typewords": ["string"] }, { "Name": "To", "Docs": "", "Typewords": ["string"] }, { "Name": "Submitted", "Docs": "", "Typewords": ["string"] }, { "Name": "LastActivity", "Docs": "", "Typewords": ["string"] }, { "Name": "Transport", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Success", "Docs": "", "Typewords": ["nullable", "bool"] }] },
		"RetiredSort": { "Name": "RetiredSort", "Docs": "", "Fields": [{ "Name": "Field", "Docs": "", "Typewords": ["string"] }, { "Name": "LastID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Last", "Docs": "", "Typewords": ["any"] }, { "Name": "Asc", "Docs": "", "Typewords": ["bool"] }] },
		"MsgRetired": { "Name": "MsgRetired", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "BaseID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Queued", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "SenderAccount", "Docs": "", "Typewords": ["string"] }, { "Name": "SenderLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "SenderDomainStr", "Docs": "", "Typewords": ["string"] }, { "Name": "FromID", "Docs": "", "Typewords": ["string"] }, { "Name": "RecipientLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "RecipientDomain", "Docs": "", "Typewords": ["IPDomain"] }, { "Name": "RecipientDomainStr", "Docs": "", "Typewords": ["string"] }, { "Name": "Attempts", "Docs": "", "Typewords": ["int32"] }, { "Name": "MaxAttempts", "Docs": "", "Typewords": ["int32"] }, { "Name": "DialedIPs", "Docs": "", "Typewords": ["{}", "[]", "IP"] }, { "Name": "LastAttempt", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Results", "Docs": "", "Typewords": ["[]", "MsgResult"] }, { "Name": "Has8bit", "Docs": "", "Typewords": ["bool"] }, { "Name": "SMTPUTF8", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsDMARCReport", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsTLSReport", "Docs": "", "Typewords": ["bool"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "Transport", "Docs": "", "Typewords": ["string"] }, { "Name": "RequireTLS", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "FutureReleaseRequest", "Docs": "", "Typewords": ["string"] }, { "Name": "Extra", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "LastActivity", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "RecipientAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "Success", "Docs": "", "Typewords": ["bool"] }, { "Name": "KeepUntil", "Docs": "", "Typewords": ["timestamp"] }] },
		"HookFilter": { "Name": "HookFilter", "Docs": "", "Fields": [{ "Name": "Max", "Docs": "", "Typewords": ["int32"] }, { "Name": "IDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "Submitted", "Docs": "", "Typewords": ["string"] }, { "Name": "NextAttempt", "Docs": "", "Typewords": ["string"] }, { "Name": "Event", "Docs": "", "Typewords": ["string"] }] },
		"HookSort": { "Name": "HookSort", "Docs": "", "Fields": [{ "Name": "Field", "Docs": "", "Typewords": ["string"] }, { "Name": "LastID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Last", "Docs": "", "Typewords": ["any"] }, { "Name": "Asc", "Docs": "", "Typewords": ["bool"] }] },
		"Hook": { "Name": "Hook", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "QueueMsgID", "Docs": "", "Typewords": ["int64"] }, { "Name": "FromID", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "Extra", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Authorization", "Docs": "", "Typewords": ["string"] }, { "Name": "IsIncoming", "Docs": "", "Typewords": ["bool"] }, { "Name": "OutgoingEvent", "Docs": "", "Typewords": ["string"] }, { "Name": "Payload", "Docs": "", "Typewords": ["string"] }, { "Name": "Submitted", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Attempts", "Docs": "", "Typewords": ["int32"] }, { "Name": "NextAttempt", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Results", "Docs": "", "Typewords": ["[]", "HookResult"] }] },
		"HookResult": { "Name": "HookResult", "Docs": "", "Fields": [{ "Name": "Start", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Duration", "Docs": "", "Typewords": ["int64"] }, { "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Success", "Docs": "", "Typewords": ["bool"] }, { "Name": "Code", "Docs": "", "Typewords": ["int32"] }, { "Name": "Error", "Docs": "", "Typewords": ["string"] }, { "Name": "Response", "Docs": "", "Typewords": ["string"] }] },
		"HookRetiredFilter": { "Name": "HookRetiredFilter", "Docs": "", "Fields": [{ "Name": "Max", "Docs": "", "Typewords": ["int32"] }, { "Name": "IDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "Submitted", "Docs": "", "Typewords": ["string"] }, { "Name": "LastActivity", "Docs": "", "Typewords": ["string"] }, { "Name": "Event", "Docs": "", "Typewords": ["string"] }] },
		"HookRetiredSort": { "Name": "HookRetiredSort", "Docs": "", "Fields": [{ "Name": "Field", "Docs": "", "Typewords": ["string"] }, { "Name": "LastID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Last", "Docs": "", "Typewords": ["any"] }, { "Name": "Asc", "Docs": "", "Typewords": ["bool"] }] },
		"HookRetired": { "Name": "HookRetired", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "QueueMsgID", "Docs": "", "Typewords": ["int64"] }, { "Name": "FromID", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "Extra", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Authorization", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsIncoming", "Docs": "", "Typewords": ["bool"] }, { "Name": "OutgoingEvent", "Docs": "", "Typewords": ["string"] }, { "Name": "Payload", "Docs": "", "Typewords": ["string"] }, { "Name": "Submitted", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "SupersededByID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Attempts", "Docs": "", "Typewords": ["int32"] }, { "Name": "Results", "Docs": "", "Typewords": ["[]", "HookResult"] }, { "Name": "Success", "Docs": "", "Typewords": ["bool"] }, { "Name": "LastActivity", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "KeepUntil", "Docs": "", "Typewords": ["timestamp"] }] },
		"WebserverConfig": { "Name": "WebserverConfig", "Docs": "", "Fields": [{ "Name": "WebDNSDomainRedirects", "Docs": "", "Typewords": ["[]", "[]", "Domain"] }, { "Name": "WebDomainRedirects", "Docs": "", "Typewords": ["[]", "[]", "string"] }, { "Name": "WebHandlers", "Docs": "", "Typewords": ["[]", "WebHandler"] }] },
		"WebHandler": { "Name": "WebHandler", "Docs": "", "Fields": [{ "Name": "LogName", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "PathRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "DontRedirectPlainHTTP", "Docs": "", "Typewords": ["bool"] }, { "Name": "Compress", "Docs": "", "Typewords": ["bool"] }, { "Name": "WebStatic", "Docs": "", "Typewords": ["nullable", "WebStatic"] }, { "Name": "WebRedirect", "Docs": "", "Typewords": ["nullable", "WebRedirect"] }, { "Name": "WebForward", "Docs": "", "Typewords": ["nullable", "WebForward"] }, { "Name": "WebInternal", "Docs": "", "Typewords": ["nullable", "WebInternal"] }, { "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "DNSDomain", "Docs": "", "Typewords": ["Domain"] }] },
		"WebStatic": { "Name": "WebStatic", "Docs": "", "Fields": [{ "Name": "StripPrefix", "Docs": "", "Typewords": ["string"] }, { "Name": "Root", "Docs": "", "Typewords": ["string"] }, { "Name": "ListFiles", "Docs": "", "Typewords": ["bool"] }, { "Name": "ContinueNotFound", "Docs": "", "Typewords": ["bool"] }, { "Name": "ResponseHeaders", "Docs": "", "Typewords": ["{}", "string"] }] },
		"WebRedirect": { "Name": "WebRedirect", "Docs": "", "Fields": [{ "Name": "BaseURL", "Docs": "", "Typewords": ["string"] }, { "Name": "OrigPathRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "ReplacePath", "Docs": "", "Typewords": ["string"] }, { "Name": "StatusCode", "Docs": "", "Typewords": ["int32"] }] },
		"WebForward": { "Name": "WebForward", "Docs": "", "Fields": [{ "Name": "StripPath", "Docs": "", "Typewords": ["bool"] }, { "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "ResponseHeaders", "Docs": "", "Typewords": ["{}", "string"] }] },
		"WebInternal": { "Name": "WebInternal", "Docs": "", "Fields": [{ "Name": "BasePath", "Docs": "", "Typewords": ["string"] }, { "Name": "Service", "Docs": "", "Typewords": ["string"] }] },
		"Transport": { "Name": "Transport", "Docs": "", "Fields": [{ "Name": "Submissions", "Docs": "", "Typewords": ["nullable", "TransportSMTP"] }, { "Name": "Submission", "Docs": "", "Typewords": ["nullable", "TransportSMTP"] }, { "Name": "SMTP", "Docs": "", "Typewords": ["nullable", "TransportSMTP"] }, { "Name": "Socks", "Docs": "", "Typewords": ["nullable", "TransportSocks"] }, { "Name": "Direct", "Docs": "", "Typewords": ["nullable", "TransportDirect"] }] },
		"TransportSMTP": { "Name": "TransportSMTP", "Docs": "", "Fields": [{ "Name": "Host", "Docs": "", "Typewords": ["string"] }, { "Name": "Port", "Docs": "", "Typewords": ["int32"] }, { "Name": "STARTTLSInsecureSkipVerify", "Docs": "", "Typewords": ["bool"] }, { "Name": "NoSTARTTLS", "Docs": "", "Typewords": ["bool"] }, { "Name": "Auth", "Docs": "", "Typewords": ["nullable", "SMTPAuth"] }] },
		"SMTPAuth": { "Name": "SMTPAuth", "Docs": "", "Fields": [{ "Name": "Username", "Docs": "", "Typewords": ["string"] }, { "Name": "Password", "Docs": "", "Typewords": ["string"] }, { "Name": "Mechanisms", "Docs": "", "Typewords": ["[]", "string"] }] },
		"TransportSocks": { "Name": "TransportSocks", "Docs": "", "Fields": [{ "Name": "Address", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPs", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "RemoteHostname", "Docs": "", "Typewords": ["string"] }] },
		"TransportDirect": { "Name": "TransportDirect", "Docs": "", "Fields": [{ "Name": "DisableIPv4", "Docs": "", "Typewords": ["bool"] }, { "Name": "DisableIPv6", "Docs": "", "Typewords": ["bool"] }] },
		"EvaluationStat": { "Name": "EvaluationStat", "Docs": "", "Fields": [{ "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "Dispositions", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Count", "Docs": "", "Typewords": ["int32"] }, { "Name": "SendReport", "Docs": "", "Typewords": ["bool"] }] },
		"Evaluation": { "Name": "Evaluation", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "PolicyDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "Evaluated", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Optional", "Docs": "", "Typewords": ["bool"] }, { "Name": "IntervalHours", "Docs": "", "Typewords": ["int32"] }, { "Name": "Addresses", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "PolicyPublished", "Docs": "", "Typewords": ["PolicyPublished"] }, { "Name": "SourceIP", "Docs": "", "Typewords": ["string"] }, { "Name": "Disposition", "Docs": "", "Typewords": ["string"] }, { "Name": "AlignedDKIMPass", "Docs": "", "Typewords": ["bool"] }, { "Name": "AlignedSPFPass", "Docs": "", "Typewords": ["bool"] }, { "Name": "OverrideReasons", "Docs": "", "Typewords": ["[]", "PolicyOverrideReason"] }, { "Name": "EnvelopeTo", "Docs": "", "Typewords": ["string"] }, { "Name": "EnvelopeFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "HeaderFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "DKIMResults", "Docs": "", "Typewords": ["[]", "DKIMAuthResult"] }, { "Name": "SPFResults", "Docs": "", "Typewords": ["[]", "SPFAuthResult"] }] },
		"SuppressAddress": { "Name": "SuppressAddress", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Inserted", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "ReportingAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "Until", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Comment", "Docs": "", "Typewords": ["string"] }] },
		"TLSResult": { "Name": "TLSResult", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "PolicyDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "DayUTC", "Docs": "", "Typewords": ["string"] }, { "Name": "RecipientDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "Created", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Updated", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "IsHost", "Docs": "", "Typewords": ["bool"] }, { "Name": "SendReport", "Docs": "", "Typewords": ["bool"] }, { "Name": "SentToRecipientDomain", "Docs": "", "Typewords": ["bool"] }, { "Name": "RecipientDomainReportingAddresses", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "SentToPolicyDomain", "Docs": "", "Typewords": ["bool"] }, { "Name": "Results", "Docs": "", "Typewords": ["[]", "Result"] }] },
		"TLSRPTSuppressAddress": { "Name": "TLSRPTSuppressAddress", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Inserted", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "ReportingAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "Until", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Comment", "Docs": "", "Typewords": ["string"] }] },
		"Dynamic": { "Name": "Dynamic", "Docs": "", "Fields": [{ "Name": "Domains", "Docs": "", "Typewords": ["{}", "ConfigDomain"] }, { "Name": "Accounts", "Docs": "", "Typewords": ["{}", "Account"] }, { "Name": "WebDomainRedirects", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "WebHandlers", "Docs": "", "Typewords": ["[]", "WebHandler"] }, { "Name": "Routes", "Docs": "", "Typewords": ["[]", "Route"] }, { "Name": "MonitorDNSBLs", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "MonitorDNSBLZones", "Docs": "", "Typewords": ["[]", "Domain"] }] },
		"TLSPublicKey": { "Name": "TLSPublicKey", "Docs": "", "Fields": [{ "Name": "Fingerprint", "Docs": "", "Typewords": ["string"] }, { "Name": "Created", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Type", "Docs": "", "Typewords": ["string"] }, { "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "NoIMAPPreauth", "Docs": "", "Typewords": ["bool"] }, { "Name": "CertDER", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "LoginAddress", "Docs": "", "Typewords": ["string"] }] },
		"LoginAttempt": { "Name": "LoginAttempt", "Docs": "", "Fields": [{ "Name": "Key", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Last", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "First", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Count", "Docs": "", "Typewords": ["int64"] }, { "Name": "AccountName", "Docs": "", "Typewords": ["string"] }, { "Name": "LoginAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIP", "Docs": "", "Typewords": ["string"] }, { "Name": "LocalIP", "Docs": "", "Typewords": ["string"] }, { "Name": "TLS", "Docs": "", "Typewords": ["string"] }, { "Name": "TLSPubKeyFingerprint", "Docs": "", "Typewords": ["string"] }, { "Name": "Protocol", "Docs": "", "Typewords": ["string"] }, { "Name": "UserAgent", "Docs": "", "Typewords": ["string"] }, { "Name": "AuthMech", "Docs": "", "Typewords": ["string"] }, { "Name": "Result", "Docs": "", "Typewords": ["AuthResult"] }] },
		"CSRFToken": { "Name": "CSRFToken", "Docs": "", "Values": null },
		"DMARCPolicy": { "Name": "DMARCPolicy", "Docs": "", "Values": [{ "Name": "PolicyEmpty", "Value": "", "Docs": "" }, { "Name": "PolicyNone", "Value": "none", "Docs": "" }, { "Name": "PolicyQuarantine", "Value": "quarantine", "Docs": "" }, { "Name": "PolicyReject", "Value": "reject", "Docs": "" }] },
		"Align": { "Name": "Align", "Docs": "", "Values": [{ "Name": "AlignStrict", "Value": "s", "Docs": "" }, { "Name": "AlignRelaxed", "Value": "r", "Docs": "" }] },
		"RUA": { "Name": "RUA", "Docs": "", "Values": null },
		"Mode": { "Name": "Mode", "Docs": "", "Values": [{ "Name": "ModeEnforce", "Value": "enforce", "Docs": "" }, { "Name": "ModeTesting", "Value": "testing", "Docs": "" }, { "Name": "ModeNone", "Value": "none", "Docs": "" }] },
		"Localpart": { "Name": "Localpart", "Docs": "", "Values": null },
		"IP": { "Name": "IP", "Docs": "", "Values": [] },
		"AuthResult": { "Name": "AuthResult", "Docs": "", "Values": [{ "Name": "AuthSuccess", "Value": "ok", "Docs": "" }, { "Name": "AuthBadUser", "Value": "baduser", "Docs": "" }, { "Name": "AuthBadPassword", "Value": "badpassword", "Docs": "" }, { "Name": "AuthBadCredentials", "Value": "badcreds", "Docs": "" }, { "Name": "AuthBadChannelBinding", "Value": "badchanbind", "Docs": "" }, { "Name": "AuthBadProtocol", "Value": "badprotocol", "Docs": "" }, { "Name": "AuthLoginDisabled", "Value": "logindisabled", "Docs": "" }, { "Name": "AuthError", "Value": "error", "Docs": "" }, { "Name": "AuthAborted", "Value": "aborted", "Docs": "" }] },
	};
	api.parser = {
		CheckResult: (v) => api.parse("CheckResult", v),
		DNSSECResult: (v) => api.parse("DNSSECResult", v),
		IPRevCheckResult: (v) => api.parse("IPRevCheckResult", v),
		Domain: (v) => api.parse("Domain", v),
		MXCheckResult: (v) => api.parse("MXCheckResult", v),
		MX: (v) => api.parse("MX", v),
		TLSCheckResult: (v) => api.parse("TLSCheckResult", v),
		DANECheckResult: (v) => api.parse("DANECheckResult", v),
		SPFCheckResult: (v) => api.parse("SPFCheckResult", v),
		SPFRecord: (v) => api.parse("SPFRecord", v),
		Directive: (v) => api.parse("Directive", v),
		Modifier: (v) => api.parse("Modifier", v),
		DKIMCheckResult: (v) => api.parse("DKIMCheckResult", v),
		DKIMRecord: (v) => api.parse("DKIMRecord", v),
		Record: (v) => api.parse("Record", v),
		DMARCCheckResult: (v) => api.parse("DMARCCheckResult", v),
		DMARCRecord: (v) => api.parse("DMARCRecord", v),
		URI: (v) => api.parse("URI", v),
		TLSRPTCheckResult: (v) => api.parse("TLSRPTCheckResult", v),
		TLSRPTRecord: (v) => api.parse("TLSRPTRecord", v),
		Extension: (v) => api.parse("Extension", v),
		MTASTSCheckResult: (v) => api.parse("MTASTSCheckResult", v),
		MTASTSRecord: (v) => api.parse("MTASTSRecord", v),
		Pair: (v) => api.parse("Pair", v),
		Policy: (v) => api.parse("Policy", v),
		STSMX: (v) => api.parse("STSMX", v),
		SRVConfCheckResult: (v) => api.parse("SRVConfCheckResult", v),
		SRV: (v) => api.parse("SRV", v),
		AutoconfCheckResult: (v) => api.parse("AutoconfCheckResult", v),
		AutodiscoverCheckResult: (v) => api.parse("AutodiscoverCheckResult", v),
		AutodiscoverSRV: (v) => api.parse("AutodiscoverSRV", v),
		ConfigDomain: (v) => api.parse("ConfigDomain", v),
		DKIM: (v) => api.parse("DKIM", v),
		Selector: (v) => api.parse("Selector", v),
		Canonicalization: (v) => api.parse("Canonicalization", v),
		DMARC: (v) => api.parse("DMARC", v),
		MTASTS: (v) => api.parse("MTASTS", v),
		TLSRPT: (v) => api.parse("TLSRPT", v),
		Route: (v) => api.parse("Route", v),
		Alias: (v) => api.parse("Alias", v),
		AliasAddress: (v) => api.parse("AliasAddress", v),
		Address: (v) => api.parse("Address", v),
		Destination: (v) => api.parse("Destination", v),
		Ruleset: (v) => api.parse("Ruleset", v),
		Account: (v) => api.parse("Account", v),
		OutgoingWebhook: (v) => api.parse("OutgoingWebhook", v),
		IncomingWebhook: (v) => api.parse("IncomingWebhook", v),
		SubjectPass: (v) => api.parse("SubjectPass", v),
		AutomaticJunkFlags: (v) => api.parse("AutomaticJunkFlags", v),
		JunkFilter: (v) => api.parse("JunkFilter", v),
		AddressAlias: (v) => api.parse("AddressAlias", v),
		PolicyRecord: (v) => api.parse("PolicyRecord", v),
		TLSReportRecord: (v) => api.parse("TLSReportRecord", v),
		Report: (v) => api.parse("Report", v),
		TLSRPTDateRange: (v) => api.parse("TLSRPTDateRange", v),
		Result: (v) => api.parse("Result", v),
		ResultPolicy: (v) => api.parse("ResultPolicy", v),
		Summary: (v) => api.parse("Summary", v),
		FailureDetails: (v) => api.parse("FailureDetails", v),
		TLSRPTSummary: (v) => api.parse("TLSRPTSummary", v),
		DomainFeedback: (v) => api.parse("DomainFeedback", v),
		ReportMetadata: (v) => api.parse("ReportMetadata", v),
		DateRange: (v) => api.parse("DateRange", v),
		PolicyPublished: (v) => api.parse("PolicyPublished", v),
		ReportRecord: (v) => api.parse("ReportRecord", v),
		Row: (v) => api.parse("Row", v),
		PolicyEvaluated: (v) => api.parse("PolicyEvaluated", v),
		PolicyOverrideReason: (v) => api.parse("PolicyOverrideReason", v),
		Identifiers: (v) => api.parse("Identifiers", v),
		AuthResults: (v) => api.parse("AuthResults", v),
		DKIMAuthResult: (v) => api.parse("DKIMAuthResult", v),
		SPFAuthResult: (v) => api.parse("SPFAuthResult", v),
		DMARCSummary: (v) => api.parse("DMARCSummary", v),
		Reverse: (v) => api.parse("Reverse", v),
		ClientConfigs: (v) => api.parse("ClientConfigs", v),
		ClientConfigsEntry: (v) => api.parse("ClientConfigsEntry", v),
		HoldRule: (v) => api.parse("HoldRule", v),
		Filter: (v) => api.parse("Filter", v),
		Sort: (v) => api.parse("Sort", v),
		Msg: (v) => api.parse("Msg", v),
		IPDomain: (v) => api.parse("IPDomain", v),
		MsgResult: (v) => api.parse("MsgResult", v),
		RetiredFilter: (v) => api.parse("RetiredFilter", v),
		RetiredSort: (v) => api.parse("RetiredSort", v),
		MsgRetired: (v) => api.parse("MsgRetired", v),
		HookFilter: (v) => api.parse("HookFilter", v),
		HookSort: (v) => api.parse("HookSort", v),
		Hook: (v) => api.parse("Hook", v),
		HookResult: (v) => api.parse("HookResult", v),
		HookRetiredFilter: (v) => api.parse("HookRetiredFilter", v),
		HookRetiredSort: (v) => api.parse("HookRetiredSort", v),
		HookRetired: (v) => api.parse("HookRetired", v),
		WebserverConfig: (v) => api.parse("WebserverConfig", v),
		WebHandler: (v) => api.parse("WebHandler", v),
		WebStatic: (v) => api.parse("WebStatic", v),
		WebRedirect: (v) => api.parse("WebRedirect", v),
		WebForward: (v) => api.parse("WebForward", v),
		WebInternal: (v) => api.parse("WebInternal", v),
		Transport: (v) => api.parse("Transport", v),
		TransportSMTP: (v) => api.parse("TransportSMTP", v),
		SMTPAuth: (v) => api.parse("SMTPAuth", v),
		TransportSocks: (v) => api.parse("TransportSocks", v),
		TransportDirect: (v) => api.parse("TransportDirect", v),
		EvaluationStat: (v) => api.parse("EvaluationStat", v),
		Evaluation: (v) => api.parse("Evaluation", v),
		SuppressAddress: (v) => api.parse("SuppressAddress", v),
		TLSResult: (v) => api.parse("TLSResult", v),
		TLSRPTSuppressAddress: (v) => api.parse("TLSRPTSuppressAddress", v),
		Dynamic: (v) => api.parse("Dynamic", v),
		TLSPublicKey: (v) => api.parse("TLSPublicKey", v),
		LoginAttempt: (v) => api.parse("LoginAttempt", v),
		CSRFToken: (v) => api.parse("CSRFToken", v),
		DMARCPolicy: (v) => api.parse("DMARCPolicy", v),
		Align: (v) => api.parse("Align", v),
		RUA: (v) => api.parse("RUA", v),
		Mode: (v) => api.parse("Mode", v),
		Localpart: (v) => api.parse("Localpart", v),
		IP: (v) => api.parse("IP", v),
		AuthResult: (v) => api.parse("AuthResult", v),
	};
	// Admin exports web API functions for the admin web interface. All its methods are
	// exported under api/. Function calls require valid HTTP Authentication
	// credentials of a user.
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
		async Login(loginToken, password) {
			const fn = "Login";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [["CSRFToken"]];
			const params = [loginToken, password];
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
		// CheckDomain checks the configuration for the domain, such as MX, SMTP STARTTLS,
		// SPF, DKIM, DMARC, TLSRPT, MTASTS, autoconfig, autodiscover.
		async CheckDomain(domainName) {
			const fn = "CheckDomain";
			const paramTypes = [["string"]];
			const returnTypes = [["CheckResult"]];
			const params = [domainName];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Domains returns all configured domain names.
		async Domains() {
			const fn = "Domains";
			const paramTypes = [];
			const returnTypes = [["[]", "ConfigDomain"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Domain returns the dns domain for a (potentially unicode as IDNA) domain name.
		async Domain(domain) {
			const fn = "Domain";
			const paramTypes = [["string"]];
			const returnTypes = [["Domain"]];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// ParseDomain parses a domain, possibly an IDNA domain.
		async ParseDomain(domain) {
			const fn = "ParseDomain";
			const paramTypes = [["string"]];
			const returnTypes = [["Domain"]];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainConfig returns the configuration for a domain.
		async DomainConfig(domain) {
			const fn = "DomainConfig";
			const paramTypes = [["string"]];
			const returnTypes = [["ConfigDomain"]];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainLocalparts returns the encoded localparts and accounts configured in domain.
		async DomainLocalparts(domain) {
			const fn = "DomainLocalparts";
			const paramTypes = [["string"]];
			const returnTypes = [["{}", "string"], ["{}", "Alias"]];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Accounts returns the names of all configured and all disabled accounts.
		async Accounts() {
			const fn = "Accounts";
			const paramTypes = [];
			const returnTypes = [["[]", "string"], ["[]", "string"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Account returns the parsed configuration of an account.
		async Account(account) {
			const fn = "Account";
			const paramTypes = [["string"]];
			const returnTypes = [["Account"], ["int64"]];
			const params = [account];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// ConfigFiles returns the paths and contents of the static and dynamic configuration files.
		async ConfigFiles() {
			const fn = "ConfigFiles";
			const paramTypes = [];
			const returnTypes = [["string"], ["string"], ["string"], ["string"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// MTASTSPolicies returns all mtasts policies from the cache.
		async MTASTSPolicies() {
			const fn = "MTASTSPolicies";
			const paramTypes = [];
			const returnTypes = [["[]", "PolicyRecord"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSReports returns TLS reports overlapping with period start/end, for the given
		// policy domain (or all domains if empty). The reports are sorted first by period
		// end (most recent first), then by policy domain.
		async TLSReports(start, end, policyDomain) {
			const fn = "TLSReports";
			const paramTypes = [["timestamp"], ["timestamp"], ["string"]];
			const returnTypes = [["[]", "TLSReportRecord"]];
			const params = [start, end, policyDomain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSReportID returns a single TLS report.
		async TLSReportID(domain, reportID) {
			const fn = "TLSReportID";
			const paramTypes = [["string"], ["int64"]];
			const returnTypes = [["TLSReportRecord"]];
			const params = [domain, reportID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTSummaries returns a summary of received TLS reports overlapping with
		// period start/end for one or all domains (when domain is empty).
		// The returned summaries are ordered by domain name.
		async TLSRPTSummaries(start, end, policyDomain) {
			const fn = "TLSRPTSummaries";
			const paramTypes = [["timestamp"], ["timestamp"], ["string"]];
			const returnTypes = [["[]", "TLSRPTSummary"]];
			const params = [start, end, policyDomain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCReports returns DMARC reports overlapping with period start/end, for the
		// given domain (or all domains if empty). The reports are sorted first by period
		// end (most recent first), then by domain.
		async DMARCReports(start, end, domain) {
			const fn = "DMARCReports";
			const paramTypes = [["timestamp"], ["timestamp"], ["string"]];
			const returnTypes = [["[]", "DomainFeedback"]];
			const params = [start, end, domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCReportID returns a single DMARC report.
		async DMARCReportID(domain, reportID) {
			const fn = "DMARCReportID";
			const paramTypes = [["string"], ["int64"]];
			const returnTypes = [["DomainFeedback"]];
			const params = [domain, reportID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCSummaries returns a summary of received DMARC reports overlapping with
		// period start/end for one or all domains (when domain is empty).
		// The returned summaries are ordered by domain name.
		async DMARCSummaries(start, end, domain) {
			const fn = "DMARCSummaries";
			const paramTypes = [["timestamp"], ["timestamp"], ["string"]];
			const returnTypes = [["[]", "DMARCSummary"]];
			const params = [start, end, domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// LookupIP does a reverse lookup of ip.
		async LookupIP(ip) {
			const fn = "LookupIP";
			const paramTypes = [["string"]];
			const returnTypes = [["Reverse"]];
			const params = [ip];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DNSBLStatus returns the IPs from which outgoing connections may be made and
		// their current status in DNSBLs that are configured. The IPs are typically the
		// configured listen IPs, or otherwise IPs on the machines network interfaces, with
		// internal/private IPs removed.
		// 
		// The returned value maps IPs to per DNSBL statuses, where "pass" means not listed and
		// anything else is an error string, e.g. "fail: ..." or "temperror: ...".
		async DNSBLStatus() {
			const fn = "DNSBLStatus";
			const paramTypes = [];
			const returnTypes = [["{}", "{}", "string"], ["[]", "Domain"], ["[]", "Domain"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async MonitorDNSBLsSave(text) {
			const fn = "MonitorDNSBLsSave";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [text];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainRecords returns lines describing DNS records that should exist for the
		// configured domain.
		async DomainRecords(domain) {
			const fn = "DomainRecords";
			const paramTypes = [["string"]];
			const returnTypes = [["[]", "string"]];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainAdd adds a new domain and reloads the configuration.
		async DomainAdd(disabled, domain, accountName, localpart) {
			const fn = "DomainAdd";
			const paramTypes = [["bool"], ["string"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [disabled, domain, accountName, localpart];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainRemove removes an existing domain and reloads the configuration.
		async DomainRemove(domain) {
			const fn = "DomainRemove";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AccountAdd adds existing a new account, with an initial email address, and
		// reloads the configuration.
		async AccountAdd(accountName, address) {
			const fn = "AccountAdd";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [accountName, address];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AccountRemove removes an existing account and reloads the configuration.
		async AccountRemove(accountName) {
			const fn = "AccountRemove";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [accountName];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AddressAdd adds a new address to the account, which must already exist.
		async AddressAdd(address, accountName) {
			const fn = "AddressAdd";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [address, accountName];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AddressRemove removes an existing address.
		async AddressRemove(address) {
			const fn = "AddressRemove";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [address];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// SetPassword saves a new password for an account, invalidating the previous password.
		// Sessions are not interrupted, and will keep working. New login attempts must use the new password.
		// Password must be at least 8 characters.
		async SetPassword(accountName, password) {
			const fn = "SetPassword";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [accountName, password];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AccountSettingsSave set new settings for an account that only an admin can set.
		async AccountSettingsSave(accountName, maxOutgoingMessagesPerDay, maxFirstTimeRecipientsPerDay, maxMsgSize, firstTimeSenderDelay, noCustomPassword) {
			const fn = "AccountSettingsSave";
			const paramTypes = [["string"], ["int32"], ["int32"], ["int64"], ["bool"], ["bool"]];
			const returnTypes = [];
			const params = [accountName, maxOutgoingMessagesPerDay, maxFirstTimeRecipientsPerDay, maxMsgSize, firstTimeSenderDelay, noCustomPassword];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AccountLoginDisabledSave saves the LoginDisabled field of an account.
		async AccountLoginDisabledSave(accountName, loginDisabled) {
			const fn = "AccountLoginDisabledSave";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [accountName, loginDisabled];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// ClientConfigsDomain returns configurations for email clients, IMAP and
		// Submission (SMTP) for the domain.
		async ClientConfigsDomain(domain) {
			const fn = "ClientConfigsDomain";
			const paramTypes = [["string"]];
			const returnTypes = [["ClientConfigs"]];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueSize returns the number of messages currently in the outgoing queue.
		async QueueSize() {
			const fn = "QueueSize";
			const paramTypes = [];
			const returnTypes = [["int32"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueHoldRuleList lists the hold rules.
		async QueueHoldRuleList() {
			const fn = "QueueHoldRuleList";
			const paramTypes = [];
			const returnTypes = [["[]", "HoldRule"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueHoldRuleAdd adds a hold rule. Newly submitted and existing messages
		// matching the hold rule will be marked "on hold".
		async QueueHoldRuleAdd(hr) {
			const fn = "QueueHoldRuleAdd";
			const paramTypes = [["HoldRule"]];
			const returnTypes = [["HoldRule"]];
			const params = [hr];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueHoldRuleRemove removes a hold rule. The Hold field of messages in
		// the queue are not changed.
		async QueueHoldRuleRemove(holdRuleID) {
			const fn = "QueueHoldRuleRemove";
			const paramTypes = [["int64"]];
			const returnTypes = [];
			const params = [holdRuleID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueList returns the messages currently in the outgoing queue.
		async QueueList(filter, sort) {
			const fn = "QueueList";
			const paramTypes = [["Filter"], ["Sort"]];
			const returnTypes = [["[]", "Msg"]];
			const params = [filter, sort];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueNextAttemptSet sets a new time for next delivery attempt of matching
		// messages from the queue.
		async QueueNextAttemptSet(filter, minutes) {
			const fn = "QueueNextAttemptSet";
			const paramTypes = [["Filter"], ["int32"]];
			const returnTypes = [["int32"]];
			const params = [filter, minutes];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueNextAttemptAdd adds a duration to the time of next delivery attempt of
		// matching messages from the queue.
		async QueueNextAttemptAdd(filter, minutes) {
			const fn = "QueueNextAttemptAdd";
			const paramTypes = [["Filter"], ["int32"]];
			const returnTypes = [["int32"]];
			const params = [filter, minutes];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueHoldSet sets the Hold field of matching messages in the queue.
		async QueueHoldSet(filter, onHold) {
			const fn = "QueueHoldSet";
			const paramTypes = [["Filter"], ["bool"]];
			const returnTypes = [["int32"]];
			const params = [filter, onHold];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueFail fails delivery for matching messages, causing DSNs to be sent.
		async QueueFail(filter) {
			const fn = "QueueFail";
			const paramTypes = [["Filter"]];
			const returnTypes = [["int32"]];
			const params = [filter];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueDrop removes matching messages from the queue.
		async QueueDrop(filter) {
			const fn = "QueueDrop";
			const paramTypes = [["Filter"]];
			const returnTypes = [["int32"]];
			const params = [filter];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueRequireTLSSet updates the requiretls field for matching messages in the
		// queue, to be used for the next delivery.
		async QueueRequireTLSSet(filter, requireTLS) {
			const fn = "QueueRequireTLSSet";
			const paramTypes = [["Filter"], ["nullable", "bool"]];
			const returnTypes = [["int32"]];
			const params = [filter, requireTLS];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// QueueTransportSet initiates delivery of a message from the queue and sets the transport
		// to use for delivery.
		async QueueTransportSet(filter, transport) {
			const fn = "QueueTransportSet";
			const paramTypes = [["Filter"], ["string"]];
			const returnTypes = [["int32"]];
			const params = [filter, transport];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// RetiredList returns messages retired from the queue (delivery could
		// have succeeded or failed).
		async RetiredList(filter, sort) {
			const fn = "RetiredList";
			const paramTypes = [["RetiredFilter"], ["RetiredSort"]];
			const returnTypes = [["[]", "MsgRetired"]];
			const params = [filter, sort];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// HookQueueSize returns the number of webhooks still to be delivered.
		async HookQueueSize() {
			const fn = "HookQueueSize";
			const paramTypes = [];
			const returnTypes = [["int32"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// HookList lists webhooks still to be delivered.
		async HookList(filter, sort) {
			const fn = "HookList";
			const paramTypes = [["HookFilter"], ["HookSort"]];
			const returnTypes = [["[]", "Hook"]];
			const params = [filter, sort];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// HookNextAttemptSet sets a new time for next delivery attempt of matching
		// hooks from the queue.
		async HookNextAttemptSet(filter, minutes) {
			const fn = "HookNextAttemptSet";
			const paramTypes = [["HookFilter"], ["int32"]];
			const returnTypes = [["int32"]];
			const params = [filter, minutes];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// HookNextAttemptAdd adds a duration to the time of next delivery attempt of
		// matching hooks from the queue.
		async HookNextAttemptAdd(filter, minutes) {
			const fn = "HookNextAttemptAdd";
			const paramTypes = [["HookFilter"], ["int32"]];
			const returnTypes = [["int32"]];
			const params = [filter, minutes];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// HookRetiredList lists retired webhooks.
		async HookRetiredList(filter, sort) {
			const fn = "HookRetiredList";
			const paramTypes = [["HookRetiredFilter"], ["HookRetiredSort"]];
			const returnTypes = [["[]", "HookRetired"]];
			const params = [filter, sort];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// HookCancel prevents further delivery attempts of matching webhooks.
		async HookCancel(filter) {
			const fn = "HookCancel";
			const paramTypes = [["HookFilter"]];
			const returnTypes = [["int32"]];
			const params = [filter];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// LogLevels returns the current log levels.
		async LogLevels() {
			const fn = "LogLevels";
			const paramTypes = [];
			const returnTypes = [["{}", "string"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// LogLevelSet sets a log level for a package.
		async LogLevelSet(pkg, levelStr) {
			const fn = "LogLevelSet";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [pkg, levelStr];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// LogLevelRemove removes a log level for a package, which cannot be the empty string.
		async LogLevelRemove(pkg) {
			const fn = "LogLevelRemove";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [pkg];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// CheckUpdatesEnabled returns whether checking for updates is enabled.
		async CheckUpdatesEnabled() {
			const fn = "CheckUpdatesEnabled";
			const paramTypes = [];
			const returnTypes = [["bool"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// WebserverConfig returns the current webserver config
		async WebserverConfig() {
			const fn = "WebserverConfig";
			const paramTypes = [];
			const returnTypes = [["WebserverConfig"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// WebserverConfigSave saves a new webserver config. If oldConf is not equal to
		// the current config, an error is returned.
		async WebserverConfigSave(oldConf, newConf) {
			const fn = "WebserverConfigSave";
			const paramTypes = [["WebserverConfig"], ["WebserverConfig"]];
			const returnTypes = [["WebserverConfig"]];
			const params = [oldConf, newConf];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Transports returns the configured transports, for sending email.
		async Transports() {
			const fn = "Transports";
			const paramTypes = [];
			const returnTypes = [["{}", "Transport"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCEvaluationStats returns a map of all domains with evaluations to a count of
		// the evaluations and whether those evaluations will cause a report to be sent.
		async DMARCEvaluationStats() {
			const fn = "DMARCEvaluationStats";
			const paramTypes = [];
			const returnTypes = [["{}", "EvaluationStat"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCEvaluationsDomain returns all evaluations for aggregate reports for the
		// domain, sorted from oldest to most recent.
		async DMARCEvaluationsDomain(domain) {
			const fn = "DMARCEvaluationsDomain";
			const paramTypes = [["string"]];
			const returnTypes = [["Domain"], ["[]", "Evaluation"]];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCRemoveEvaluations removes evaluations for a domain.
		async DMARCRemoveEvaluations(domain) {
			const fn = "DMARCRemoveEvaluations";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCSuppressAdd adds a reporting address to the suppress list. Outgoing
		// reports will be suppressed for a period.
		async DMARCSuppressAdd(reportingAddress, until, comment) {
			const fn = "DMARCSuppressAdd";
			const paramTypes = [["string"], ["timestamp"], ["string"]];
			const returnTypes = [];
			const params = [reportingAddress, until, comment];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCSuppressList returns all reporting addresses on the suppress list.
		async DMARCSuppressList() {
			const fn = "DMARCSuppressList";
			const paramTypes = [];
			const returnTypes = [["[]", "SuppressAddress"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCSuppressRemove removes a reporting address record from the suppress list.
		async DMARCSuppressRemove(id) {
			const fn = "DMARCSuppressRemove";
			const paramTypes = [["int64"]];
			const returnTypes = [];
			const params = [id];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCSuppressExtend updates the until field of a suppressed reporting address record.
		async DMARCSuppressExtend(id, until) {
			const fn = "DMARCSuppressExtend";
			const paramTypes = [["int64"], ["timestamp"]];
			const returnTypes = [];
			const params = [id, until];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTResults returns all TLSRPT results in the database.
		async TLSRPTResults() {
			const fn = "TLSRPTResults";
			const paramTypes = [];
			const returnTypes = [["[]", "TLSResult"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTResultsPolicyDomain returns the TLS results for a domain.
		async TLSRPTResultsDomain(isRcptDom, policyDomain) {
			const fn = "TLSRPTResultsDomain";
			const paramTypes = [["bool"], ["string"]];
			const returnTypes = [["Domain"], ["[]", "TLSResult"]];
			const params = [isRcptDom, policyDomain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// LookupTLSRPTRecord looks up a TLSRPT record and returns the parsed form, original txt
		// form from DNS, and error with the TLSRPT record as a string.
		async LookupTLSRPTRecord(domain) {
			const fn = "LookupTLSRPTRecord";
			const paramTypes = [["string"]];
			const returnTypes = [["nullable", "TLSRPTRecord"], ["string"], ["string"]];
			const params = [domain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTRemoveResults removes the TLS results for a domain for the given day. If
		// day is empty, all results are removed.
		async TLSRPTRemoveResults(isRcptDom, domain, day) {
			const fn = "TLSRPTRemoveResults";
			const paramTypes = [["bool"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [isRcptDom, domain, day];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTSuppressAdd adds a reporting address to the suppress list. Outgoing
		// reports will be suppressed for a period.
		async TLSRPTSuppressAdd(reportingAddress, until, comment) {
			const fn = "TLSRPTSuppressAdd";
			const paramTypes = [["string"], ["timestamp"], ["string"]];
			const returnTypes = [];
			const params = [reportingAddress, until, comment];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTSuppressList returns all reporting addresses on the suppress list.
		async TLSRPTSuppressList() {
			const fn = "TLSRPTSuppressList";
			const paramTypes = [];
			const returnTypes = [["[]", "TLSRPTSuppressAddress"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTSuppressRemove removes a reporting address record from the suppress list.
		async TLSRPTSuppressRemove(id) {
			const fn = "TLSRPTSuppressRemove";
			const paramTypes = [["int64"]];
			const returnTypes = [];
			const params = [id];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTSuppressExtend updates the until field of a suppressed reporting address record.
		async TLSRPTSuppressExtend(id, until) {
			const fn = "TLSRPTSuppressExtend";
			const paramTypes = [["int64"], ["timestamp"]];
			const returnTypes = [];
			const params = [id, until];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// LookupCid turns an ID from a Received header into a cid as used in logging.
		async LookupCid(recvID) {
			const fn = "LookupCid";
			const paramTypes = [["string"]];
			const returnTypes = [["string"]];
			const params = [recvID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// Config returns the dynamic config.
		async Config() {
			const fn = "Config";
			const paramTypes = [];
			const returnTypes = [["Dynamic"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// AccountRoutesSave saves routes for an account.
		async AccountRoutesSave(accountName, routes) {
			const fn = "AccountRoutesSave";
			const paramTypes = [["string"], ["[]", "Route"]];
			const returnTypes = [];
			const params = [accountName, routes];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainRoutesSave saves routes for a domain.
		async DomainRoutesSave(domainName, routes) {
			const fn = "DomainRoutesSave";
			const paramTypes = [["string"], ["[]", "Route"]];
			const returnTypes = [];
			const params = [domainName, routes];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// RoutesSave saves global routes.
		async RoutesSave(routes) {
			const fn = "RoutesSave";
			const paramTypes = [["[]", "Route"]];
			const returnTypes = [];
			const params = [routes];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDescriptionSave saves the description for a domain.
		async DomainDescriptionSave(domainName, descr) {
			const fn = "DomainDescriptionSave";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName, descr];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainClientSettingsDomainSave saves the client settings domain for a domain.
		async DomainClientSettingsDomainSave(domainName, clientSettingsDomain) {
			const fn = "DomainClientSettingsDomainSave";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName, clientSettingsDomain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainLocalpartConfigSave saves the localpart catchall and case-sensitive
		// settings for a domain.
		async DomainLocalpartConfigSave(domainName, localpartCatchallSeparators, localpartCaseSensitive) {
			const fn = "DomainLocalpartConfigSave";
			const paramTypes = [["string"], ["[]", "string"], ["bool"]];
			const returnTypes = [];
			const params = [domainName, localpartCatchallSeparators, localpartCaseSensitive];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDMARCAddressSave saves the DMARC reporting address/processing
		// configuration for a domain. If localpart is empty, processing reports is
		// disabled.
		async DomainDMARCAddressSave(domainName, localpart, domain, account, mailbox) {
			const fn = "DomainDMARCAddressSave";
			const paramTypes = [["string"], ["string"], ["string"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName, localpart, domain, account, mailbox];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainTLSRPTAddressSave saves the TLS reporting address/processing
		// configuration for a domain. If localpart is empty, processing reports is
		// disabled.
		async DomainTLSRPTAddressSave(domainName, localpart, domain, account, mailbox) {
			const fn = "DomainTLSRPTAddressSave";
			const paramTypes = [["string"], ["string"], ["string"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName, localpart, domain, account, mailbox];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainMTASTSSave saves the MTASTS policy for a domain. If policyID is empty,
		// no MTASTS policy is served.
		async DomainMTASTSSave(domainName, policyID, mode, maxAge, mx) {
			const fn = "DomainMTASTSSave";
			const paramTypes = [["string"], ["string"], ["Mode"], ["int64"], ["[]", "string"]];
			const returnTypes = [];
			const params = [domainName, policyID, mode, maxAge, mx];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDKIMAdd adds a DKIM selector for a domain, generating a new private
		// key. The selector is not enabled for signing.
		async DomainDKIMAdd(domainName, selector, algorithm, hash, headerRelaxed, bodyRelaxed, seal, headers, lifetime) {
			const fn = "DomainDKIMAdd";
			const paramTypes = [["string"], ["string"], ["string"], ["string"], ["bool"], ["bool"], ["bool"], ["[]", "string"], ["int64"]];
			const returnTypes = [];
			const params = [domainName, selector, algorithm, hash, headerRelaxed, bodyRelaxed, seal, headers, lifetime];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDKIMRemove removes a DKIM selector for a domain.
		async DomainDKIMRemove(domainName, selector) {
			const fn = "DomainDKIMRemove";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName, selector];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDKIMSave saves the settings of selectors, and which to enable for
		// signing, for a domain. All currently configured selectors must be present,
		// selectors cannot be added/removed with this function.
		async DomainDKIMSave(domainName, selectors, sign) {
			const fn = "DomainDKIMSave";
			const paramTypes = [["string"], ["{}", "Selector"], ["[]", "string"]];
			const returnTypes = [];
			const params = [domainName, selectors, sign];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDisabledSave saves the Disabled field of a domain. A disabled domain
		// rejects incoming/outgoing messages involving the domain and does not request new
		// TLS certificats with ACME.
		async DomainDisabledSave(domainName, disabled) {
			const fn = "DomainDisabledSave";
			const paramTypes = [["string"], ["bool"]];
			const returnTypes = [];
			const params = [domainName, disabled];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasAdd(aliaslp, domainName, alias) {
			const fn = "AliasAdd";
			const paramTypes = [["string"], ["string"], ["Alias"]];
			const returnTypes = [];
			const params = [aliaslp, domainName, alias];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasUpdate(aliaslp, domainName, postPublic, listMembers, allowMsgFrom) {
			const fn = "AliasUpdate";
			const paramTypes = [["string"], ["string"], ["bool"], ["bool"], ["bool"]];
			const returnTypes = [];
			const params = [aliaslp, domainName, postPublic, listMembers, allowMsgFrom];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasRemove(aliaslp, domainName) {
			const fn = "AliasRemove";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [aliaslp, domainName];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasAddressesAdd(aliaslp, domainName, addresses) {
			const fn = "AliasAddressesAdd";
			const paramTypes = [["string"], ["string"], ["[]", "string"]];
			const returnTypes = [];
			const params = [aliaslp, domainName, addresses];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasAddressesRemove(aliaslp, domainName, addresses) {
			const fn = "AliasAddressesRemove";
			const paramTypes = [["string"], ["string"], ["[]", "string"]];
			const returnTypes = [];
			const params = [aliaslp, domainName, addresses];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async TLSPublicKeys(accountOpt) {
			const fn = "TLSPublicKeys";
			const paramTypes = [["string"]];
			const returnTypes = [["[]", "TLSPublicKey"]];
			const params = [accountOpt];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async LoginAttempts(accountName, limit) {
			const fn = "LoginAttempts";
			const paramTypes = [["string"], ["int32"]];
			const returnTypes = [["[]", "LoginAttempt"]];
			const params = [accountName, limit];
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
let moxversion;
let moxgoos;
let moxgoarch;
const login = async (reason) => {
	return new Promise((resolve, _) => {
		const origFocus = document.activeElement;
		let reasonElem;
		let fieldset;
		let password;
		const root = dom.div(style({ position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: '#eee', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: '1', animation: 'fadein .15s ease-in' }), dom.div(style({ display: 'flex', flexDirection: 'column', alignItems: 'center' }), reasonElem = reason ? dom.div(style({ marginBottom: '2ex', textAlign: 'center' }), reason) : dom.div(), dom.div(style({ backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto', marginBottom: '20vh' }), dom.form(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			reasonElem.remove();
			try {
				fieldset.disabled = true;
				const loginToken = await client.LoginPrep();
				const token = await client.Login(loginToken, password.value);
				try {
					window.localStorage.setItem('webadmincsrftoken', token);
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
		}, fieldset = dom.fieldset(dom.h1('Admin'), dom.label(style({ display: 'block', marginBottom: '2ex' }), dom.div('Password', style({ marginBottom: '.5ex' })), password = dom.input(attr.type('password'), attr.autocomplete('current-password'), attr.required(''))), dom.div(style({ textAlign: 'center' }), dom.submitbutton('Login')))))));
		document.body.appendChild(root);
		password.focus();
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
const client = new api.Client().withOptions({ csrfHeader: 'x-mox-csrf', login: login }).withAuthToken(localStorageGet('webadmincsrftoken') || '');
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
const green = '#1dea20';
const yellow = '#ffe400';
const red = '#ff7443';
const blue = '#8bc8ff';
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
		dom.div(style({ float: 'right' }), dom.clickbutton('Logout', attr.title('Logout, invalidating this session.'), async function click(e) {
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
			localStorageRemove('webadmincsrftoken');
			// Reload so all state is cleared from memory.
			window.location.reload();
		})),
		dom.h1(l.map((e, index) => index === 0 ? crumblink(e) : [' / ', crumblink(e)])),
		dom.br()
	];
};
const errmsg = (err) => '' + (err.message || '(no error message)');
const footer = () => dom.div(style({ marginTop: '6ex', opacity: 0.75 }), link('https://www.xmox.nl', 'mox'), ' ', moxversion, ' ', moxgoos, '/', moxgoarch, ', ', dom.a(attr.href('licenses.txt'), 'licenses'));
const age = (date, future, nowSecs) => {
	if (!nowSecs) {
		nowSecs = new Date().getTime() / 1000;
	}
	let t = nowSecs - date.getTime() / 1000;
	let negative = false;
	if (t < 0) {
		negative = true;
		t = -t;
	}
	const minute = 60;
	const hour = 60 * minute;
	const day = 24 * hour;
	const month = 30 * day;
	const year = 365 * day;
	const periods = [year, month, day, hour, minute, 1];
	const suffix = ['y', 'm', 'd', 'h', 'mins', 's'];
	let l = [];
	for (let i = 0; i < periods.length; i++) {
		const p = periods[i];
		if (t >= 2 * p || i == periods.length - 1) {
			const n = Math.floor(t / p);
			l.push('' + n + suffix[i]);
			t -= n * p;
			if (l.length >= 2) {
				break;
			}
		}
	}
	let s = l.join(' ');
	if (!future || !negative) {
		s += ' ago';
	}
	return dom.span(attr.title(date.toString()), s);
};
const domainName = (d) => {
	return d.Unicode || d.ASCII;
};
const domainString = (d) => {
	if (d.Unicode) {
		return d.Unicode + " (" + d.ASCII + ")";
	}
	return d.ASCII;
};
// IP is encoded as base64 bytes, either 4 or 16.
// It's a bit silly to encode this in JS, but it's convenient to simply pass on the
// net.IP bytes from the backend.
const formatIP = (s) => {
	const buf = window.atob(s);
	const bytes = Uint8Array.from(buf, (m) => m.codePointAt(0) || 0);
	if (bytes.length === 4 || isIPv4MappedIPv6(bytes)) {
		// Format last 4 bytes as IPv4 address.
		return [bytes.at(-4), bytes.at(-3), bytes.at(-2), bytes.at(-1)].join('.');
	}
	return formatIPv6(bytes);
};
// See if b is of the form ::ffff:x.x.x.x
const v4v6Prefix = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
const isIPv4MappedIPv6 = (b) => {
	if (b.length !== 16) {
		return false;
	}
	for (let i = 0; i < v4v6Prefix.length; i++) {
		if (b[i] !== v4v6Prefix[i]) {
			return false;
		}
	}
	return true;
};
const formatIPv6 = (b) => {
	const hexchars = "0123456789abcdef";
	const hex = (v, skipzero) => (skipzero && ((v >> 4) & 0xf) === 0 ? '' : hexchars[(v >> 4) & 0xf]) + hexchars[v & 0xf];
	let zeroStart = 0, zeroEnd = 0;
	// Find largest run of zeroes.
	let i = 0;
	while (i < 16) {
		let j = i;
		while (j < 16 && b[j] === 0) {
			j++;
		}
		if (j - i > 2 && j - i > zeroEnd - zeroStart) {
			zeroStart = i;
			zeroEnd = j;
			i = j;
		}
		else if (j > i) {
			i = j;
		}
		else {
			i++;
		}
	}
	let s = '';
	for (let i = 0; i < 16; i++) {
		if (i === zeroStart) {
			s += '::';
		}
		else if (i < zeroStart || i >= zeroEnd) {
			if (i > 0 && i % 2 === 0 && !s.endsWith(':')) {
				s += ':';
			}
			if (i % 2 === 1 || b[i] !== 0) {
				s += hex(b[i], s === '' || s.endsWith(':'));
			}
		}
	}
	return s;
};
const ipdomainString = (ipd) => {
	if (ipd.IP !== '') {
		return formatIP(ipd.IP);
	}
	return domainString(ipd.Domain);
};
const formatSize = (n) => {
	if (n > 10 * 1024 * 1024) {
		return Math.round(n / (1024 * 1024)) + ' mb';
	}
	else if (n > 500) {
		return Math.round(n / 1024) + ' kb';
	}
	return n + ' bytes';
};
const index = async () => {
	const [domains, queueSize, hooksQueueSize, checkUpdatesEnabled, [accounts, accountsDisabled]] = await Promise.all([
		client.Domains(),
		client.QueueSize(),
		client.HookQueueSize(),
		client.CheckUpdatesEnabled(),
		client.Accounts(),
	]);
	let fieldset;
	let disabled;
	let domain;
	let account;
	let localpart;
	let recvIDFieldset;
	let recvID;
	let cidElem;
	return dom.div(crumbs('Mox Admin'), checkUpdatesEnabled ? [] : dom.p(box(yellow, 'Warning: Checking for updates has not been enabled in mox.conf (CheckUpdates: true).', dom.br(), 'Make sure you stay up to date through another mechanism!', dom.br(), 'You have a responsibility to keep the internet-connected software you run up to date and secure!', dom.br(), 'See ', link('https://updates.xmox.nl/changelog'))), dom.p(dom.a('Accounts', attr.href('#accounts')), dom.br(), dom.a('Queue', attr.href('#queue')), ' (' + queueSize + ')', dom.br(), dom.a('Webhook queue', attr.href('#webhookqueue')), ' (' + hooksQueueSize + ')', dom.br()), dom.h2('Domains'), (domains || []).length === 0 ? box(red, 'No domains') :
		dom.ul((domains || []).map(d => dom.li(dom.a(attr.href('#domains/' + domainName(d.Domain)), domainString(d.Domain)), d.Disabled ? ' (disabled)' : []))), dom.br(), dom.h2('Add domain'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(fieldset, client.DomainAdd(disabled.checked, domain.value, account.value, localpart.value));
		window.location.hash = '#domains/' + domain.value;
	}, fieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), dom.span('Domain', attr.title('Domain for incoming/outgoing email to add to mox. Can also be a subdomain of a domain already configured.')), dom.br(), domain = dom.input(attr.required(''))), ' ', dom.label(style({ display: 'inline-block' }), dom.span('Postmaster/reporting account', attr.title('Account that is considered the owner of this domain. If the account does not yet exist, it will be created and a a localpart is required for the initial email address.')), dom.br(), account = dom.input(attr.required(''), attr.list('accountList')), dom.datalist(attr.id('accountList'), (accounts || []).map(a => dom.option(attr.value(a), a + (accountsDisabled?.includes(a) ? ' (disabled)' : ''))))), ' ', dom.label(style({ display: 'inline-block' }), dom.span('Localpart (if new account)', attr.title('Must be set if and only if account does not yet exist. A localpart is the part before the "@"-sign of an email address. An account requires an email address, so creating a new account for a domain requires a localpart to form an initial email address.')), dom.br(), localpart = dom.input()), ' ', dom.label(disabled = dom.input(attr.type('checkbox')), ' Disabled', attr.title('Disabled domains do fetch new certificates with ACME and do not accept incoming or outgoing messages involving the domain. Accounts and addresses referencing a disabled domain can be created. USeful during/before migrations.')), ' ', dom.submitbutton('Add domain', attr.title('Domain will be added and the config reloaded. Add the required DNS records after adding the domain.')))), dom.br(), dom.h2('Reports'), dom.div(dom.a('DMARC', attr.href('#dmarc/reports'))), dom.div(dom.a('TLS', attr.href('#tlsrpt/reports'))), dom.br(), dom.h2('Operations'), dom.div(dom.a('MTA-STS policies', attr.href('#mtasts'))), dom.div(dom.a('DMARC evaluations', attr.href('#dmarc/evaluations'))), dom.div(dom.a('TLS connection results', attr.href('#tlsrpt/results'))), dom.div(dom.a('DNSBL', attr.href('#dnsbl'))), dom.div(style({ marginTop: '.5ex' }), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		dom._kids(cidElem);
		const cid = await check(recvIDFieldset, client.LookupCid(recvID.value));
		dom._kids(cidElem, cid);
	}, recvIDFieldset = dom.fieldset(dom.label('Received ID', attr.title('The ID in the Received header that was added during incoming delivery.')), ' ', recvID = dom.input(attr.required('')), ' ', dom.submitbutton('Lookup cid', attr.title('Logging about an incoming message includes an attribute "cid", a counter identifying the transaction related to delivery of the message. The ID in the received header is an encrypted cid, which this form decrypts, after which you can look it up in the logging.')), ' ', cidElem = dom.span()))), 
	// todo: routing, globally, per domain and per account
	dom.br(), dom.h2('Configuration'), dom.div(dom.a('Routes', attr.href('#routes'))), dom.div(dom.a('Webserver', attr.href('#webserver'))), dom.div(dom.a('Files', attr.href('#config'))), dom.div(dom.a('Log levels', attr.href('#loglevels'))), footer());
};
const globalRoutes = async () => {
	const [transports, config] = await Promise.all([
		client.Transports(),
		client.Config(),
	]);
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'Routes'), RoutesEditor('global', transports, config.Routes || [], async (routes) => await client.RoutesSave(routes)));
};
const config = async () => {
	const [staticPath, dynamicPath, staticText, dynamicText] = await client.ConfigFiles();
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'Config'), dom.h2(staticPath), dom.pre(dom._class('literal'), staticText), dom.h2(dynamicPath), dom.pre(dom._class('literal'), dynamicText));
};
const loglevels = async () => {
	const loglevels = await client.LogLevels();
	const levels = ['error', 'info', 'warn', 'debug', 'trace', 'traceauth', 'tracedata'];
	let form;
	let fieldset;
	let pkg;
	let level;
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'Log levels'), dom.p('Note: changing a log level here only changes it for the current process. When mox restarts, it sets the log levels from the configuration file. Change mox.conf to keep the changes.'), dom.table(dom.thead(dom.tr(dom.th('Package', attr.title('Log levels can be configured per package. E.g. smtpserver, imapserver, dkim, dmarc, tlsrpt, etc.')), dom.th('Level', attr.title('If you set the log level to "trace", imap and smtp protocol transcripts will be logged. Sensitive authentication is replaced with "***" unless the level is >= "traceauth". Data is masked with "..." unless the level is "tracedata".')), dom.th('Action'))), dom.tbody(Object.entries(loglevels).map(t => {
		let lvl;
		return dom.tr(dom.td(t[0] || '(default)'), dom.td(lvl = dom.select(levels.map(l => dom.option(l, t[1] === l ? attr.selected('') : [])))), dom.td(dom.clickbutton('Save', attr.title('Set new log level for package.'), async function click(e) {
			e.preventDefault();
			await check(e.target, client.LogLevelSet(t[0], lvl.value));
			window.location.reload(); // todo: reload just the current loglevels
		}), ' ', dom.clickbutton('Remove', attr.title('Remove this log level, the default log level will apply.'), t[0] === '' ? attr.disabled('') : [], async function click(e) {
			e.preventDefault();
			await check(e.target, client.LogLevelRemove(t[0]));
			window.location.reload(); // todo: reload just the current loglevels
		})));
	}))), dom.br(), dom.h2('Add log level setting'), form = dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(fieldset, client.LogLevelSet(pkg.value, level.value));
		form.reset();
		window.location.reload(); // todo: reload just the current loglevels
	}, fieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), 'Package', dom.br(), pkg = dom.input(attr.required(''))), ' ', dom.label(style({ display: 'inline-block' }), 'Level', dom.br(), level = dom.select(attr.required(''), levels.map(l => dom.option(l, l === 'debug' ? attr.selected('') : [])))), ' ', dom.submitbutton('Add')), dom.br(), dom.p('Suggestions for packages: autotls dkim dmarc dmarcdb dns dnsbl dsn http imapserver iprev junk message metrics mox moxio mtasts mtastsdb publicsuffix queue sendmail serve smtpserver spf store subjectpass tlsrpt tlsrptdb updates')));
};
const box = (color, ...l) => [
	dom.div(style({
		display: 'inline-block',
		padding: '.125em .25em',
		backgroundColor: color,
		borderRadius: '3px',
		margin: '.5ex 0',
	}), l),
	dom.br(),
];
const inlineBox = (color, ...l) => dom.span(style({
	display: 'inline-block',
	padding: color ? '0.05em 0.2em' : '',
	backgroundColor: color,
	borderRadius: '3px',
}), l);
const accounts = async () => {
	const [[accounts, accountsDisabled], domains, loginAttempts] = await Promise.all([
		client.Accounts(),
		client.Domains(),
		client.LoginAttempts("", 10),
	]);
	let fieldset;
	let localpart;
	let domain;
	let account;
	let accountModified = false;
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'Accounts'), dom.h2('Accounts'), (accounts || []).length === 0 ? dom.p('No accounts') :
		dom.ul((accounts || []).map(s => dom.li(dom.a(attr.href('#accounts/l/' + s), s), accountsDisabled?.includes(s) ? ' (disabled)' : ''))), dom.br(), dom.h2('Add account'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(fieldset, client.AccountAdd(account.value, localpart.value + '@' + domain.value));
		window.location.hash = '#accounts/l/' + account.value;
	}, fieldset = dom.fieldset(dom.p('Start with the initial email address for the account. The localpart is the account name too by default, but the account name can be changed.'), dom.label(style({ display: 'inline-block' }), dom.span('Localpart', attr.title('The part before the "@" of an email address. More addresses, also at different domains, can be added after the account has been created.')), dom.br(), localpart = dom.input(attr.required(''), function keyup() {
		if (!accountModified) {
			account.value = localpart.value;
		}
	})), '@', dom.label(style({ display: 'inline-block' }), dom.span('Domain', attr.title('The domain of the email address, after the "@".')), dom.br(), domain = dom.select(attr.required(''), (domains || []).map(d => dom.option(domainName(d.Domain))))), ' ', dom.label(style({ display: 'inline-block' }), dom.span('Account name', attr.title('An account has a password, and email address(es) (possibly at different domains). Its messages and the message index database are are stored in the file system in a directory with the name of the account. An account name is not an email address. Use a name like a unix user name, or the localpart (the part before the "@") of the initial address.')), dom.br(), account = dom.input(attr.required(''), function change() {
		accountModified = true;
	})), ' ', dom.submitbutton('Add account', attr.title('The account will be added and the config reloaded.')))), dom.br(), dom.h2('Recent login attempts', attr.title('Login attempts are stored for 30 days. At most 10000 failed login attempts are stored per account to prevent unlimited growth of the database.')), renderLoginAttempts(true, loginAttempts || []), dom.br(), loginAttempts && loginAttempts.length >= 10 ? dom.p('See ', dom.a(attr.href('#accounts/loginattempts'), 'all login attempts'), '.') : []);
};
const loginattempts = async () => {
	const loginAttempts = await client.LoginAttempts("", 0);
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Accounts', '#accounts'), 'Login attempts'), dom.h2('Login attempts'), dom.p('Login attempts are stored for 30 days. At most 10000 failed login attempts are stored per account to prevent unlimited growth of the database.'), renderLoginAttempts(true, loginAttempts || []));
};
const accountloginattempts = async (accountName) => {
	const loginAttempts = await client.LoginAttempts(accountName, 0);
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Accounts', '#accounts'), ['(admin)', '-'].includes(accountName) ? accountName : crumblink(accountName, '#accounts/l/' + accountName), 'Login attempts'), dom.h2('Login attempts'), dom.p('Login attempts are stored for 30 days. At most 10000 failed login attempts are stored per account to prevent unlimited growth of the database.'), renderLoginAttempts(false, loginAttempts || []));
};
const renderLoginAttempts = (accountLinks, loginAttempts) => {
	// todo: pagination and search
	const nowSecs = new Date().getTime() / 1000;
	return dom.table(dom.thead(dom.tr(dom.th('Time'), dom.th('Result'), dom.th('Count'), dom.th('Account'), dom.th('Address'), dom.th('Protocol'), dom.th('Mechanism'), dom.th('User Agent'), dom.th('Remote IP'), dom.th('Local IP'), dom.th('TLS'), dom.th('TLS pubkey fingerprint'), dom.th('First seen'))), dom.tbody(loginAttempts.length ? [] : dom.tr(dom.td(attr.colspan('13'), 'No login attempts in past 30 days.')), loginAttempts.map(la => dom.tr(dom.td(age(la.Last, false, nowSecs)), dom.td(la.Result === 'ok' ? la.Result : box(red, la.Result)), dom.td('' + la.Count), dom.td(accountLinks ? dom.a(attr.href('#accounts/l/' + la.AccountName + '/loginattempts'), la.AccountName) : la.AccountName), dom.td(la.LoginAddress), dom.td(la.Protocol), dom.td(la.AuthMech), dom.td(la.UserAgent), dom.td(la.RemoteIP), dom.td(la.LocalIP), dom.td(la.TLS), dom.td(la.TLSPubKeyFingerprint), dom.td(age(la.First, false, nowSecs))))));
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
const RoutesEditor = (kind, transports, routes, save) => {
	const transportNames = Object.keys(transports || {});
	transportNames.sort();
	const hdr = dom.h2('Routes', attr.title('Messages submitted to the queue for outgoing delivery are delivered directly to the MX records of the recipient domain by default. However, other "transports" can be configured, such as SMTP submission/relay or connecting through a SOCKS proxy. Routes with matching rules and a transport can be configured for accounts, domains and globally. Routes are evaluated in that order, the first match is applied.'));
	let routesElem;
	const render = () => {
		if (transportNames.length === 0) {
			return [hdr, dom.p('No transports configured.', attr.title('To configure routes, first configure transports via the mox.conf config file.'))];
		}
		let routesFieldset;
		let routeRows = [];
		let elem = dom.form(async function submit(e) {
			e.stopPropagation();
			e.preventDefault();
			await check(routesFieldset, save(routeRows.map(rr => rr.gather())));
		}, routesFieldset = dom.fieldset(dom.table(dom.thead(dom.tr(dom.th('From domain'), dom.th('To domain'), dom.th('Minimum attempts'), dom.th('Transport'), dom.th(dom.clickbutton('Add', function click() {
			routes = routeRows.map(rr => rr.gather());
			routes.push({ FromDomain: [], ToDomain: [], MinimumAttempts: 0, Transport: transportNames[0] });
			render();
		})))), dom.tbody((routes || []).length === 0 ? dom.tr(dom.td(attr.colspan('5'), 'No routes.')) : [], routeRows = (routes || []).map((r, index) => {
			let fromDomain = dom.input(attr.value((r.FromDomain || []).join(',')));
			let toDomain = dom.input(attr.value((r.ToDomain || []).join(',')));
			let minimumAttempts = dom.input(attr.value('' + r.MinimumAttempts));
			let transport = dom.select(attr.required(''), transportNames.map(s => dom.option(s, s === r.Transport ? attr.selected('') : [])));
			const tr = dom.tr(dom.td(fromDomain), dom.td(toDomain), dom.td(minimumAttempts), dom.td(transport), dom.td(dom.clickbutton('Remove', function click() {
				routeRows.splice(index, 1);
				routes = routeRows.map(rr => rr.gather());
				render();
			})));
			return {
				root: tr,
				gather: () => {
					return {
						FromDomain: fromDomain.value ? fromDomain.value.split(',') : [],
						ToDomain: toDomain.value ? toDomain.value.split(',') : [],
						MinimumAttempts: parseInt(minimumAttempts.value) || 0,
						Transport: transport.value,
					};
				},
			};
		}))), dom.div(dom.submitbutton('Save'))));
		if (!routesElem && (routes || []).length === 0) {
			// Keep it short.
			elem = dom.div('No ' + kind + ' routes configured. ', dom.clickbutton('Add', function click() {
				routes = routeRows.map(rr => rr.gather());
				routes.push({ FromDomain: [], ToDomain: [], MinimumAttempts: 0, Transport: transportNames[0] });
				render();
			}));
		}
		elem = dom.div(hdr, elem);
		if (routesElem) {
			routesElem.replaceWith(elem);
		}
		routesElem = elem;
		return elem;
	};
	return render();
};
const account = async (name) => {
	const [[config, diskUsage], domains, transports, tlspubkeys, loginAttempts] = await Promise.all([
		client.Account(name),
		client.Domains(),
		client.Transports(),
		client.TLSPublicKeys(name),
		client.LoginAttempts(name, 10),
	]);
	// todo: show suppression list, and buttons to add/remove entries.
	let form;
	let fieldset;
	let localpart;
	let domain;
	let fieldsetSettings;
	let maxOutgoingMessagesPerDay;
	let maxFirstTimeRecipientsPerDay;
	let quotaMessageSize;
	let firstTimeSenderDelay;
	let noCustomPassword;
	let formPassword;
	let fieldsetPassword;
	let password;
	let passwordHint;
	const xparseSize = (s) => {
		s = s.toLowerCase();
		let mult = 1;
		if (s.endsWith('k')) {
			mult = 1024;
		}
		else if (s.endsWith('m')) {
			mult = 1024 * 1024;
		}
		else if (s.endsWith('g')) {
			mult = 1024 * 1024 * 1024;
		}
		else if (s.endsWith('t')) {
			mult = 1024 * 1024 * 1024 * 1024;
		}
		if (mult !== 1) {
			s = s.substring(0, s.length - 1);
		}
		let v = parseInt(s);
		if (isNaN(v) || s !== '' + v) {
			throw new Error('invalid number; use units like "k", "m", "g", for example "2g". specify 0 to use the global default quota, or -1 for unlimited storage overriding the global quota');
		}
		return v * mult;
	};
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Accounts', '#accounts'), name), config.LoginDisabled ? dom.p(box(yellow, 'Warning: Login for this account is disabled with message: ' + config.LoginDisabled)) : [], dom.h2('Addresses'), dom.table(dom.thead(dom.tr(dom.th('Address'), dom.th('Action'))), dom.tbody(Object.keys(config.Destinations || {}).length === 0 ? dom.tr(dom.td(attr.colspan('2'), '(None, login disabled)')) : [], Object.keys(config.Destinations || {}).map(k => {
		let v = k;
		const t = k.split('@');
		if (t.length > 1) {
			const d = t[t.length - 1];
			const lp = t.slice(0, t.length - 1).join('@');
			v = [
				prewrap(lp), '@',
				dom.a(d, attr.href('#domains/' + d)),
			];
			if (lp === '') {
				v.unshift('(catchall) ');
			}
		}
		return dom.tr(dom.td(v), dom.td(dom.clickbutton('Remove', async function click(e) {
			e.preventDefault();
			const aliases = (config.Aliases || []).filter(aa => aa.SubscriptionAddress === k).map(aa => aa.Alias.LocalpartStr + "@" + domainName(aa.Alias.Domain));
			const aliasmsg = aliases.length > 0 ? ' Address will be removed from alias(es): ' + aliases.join(', ') : '';
			if (!window.confirm('Are you sure you want to remove this address?' + aliasmsg)) {
				return;
			}
			await check(e.target, client.AddressRemove(k));
			window.location.reload(); // todo: reload just the list
		})));
	}))), dom.br(), dom.h2('Add address'), form = dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		const address = localpart.value + '@' + domain.value;
		await check(fieldset, client.AddressAdd(address, name));
		form.reset();
		window.location.reload(); // todo: only reload the destinations
	}, fieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), dom.span('Localpart', attr.title('The localpart is the part before the "@"-sign of an email address. If empty, a catchall address is configured for the domain.')), dom.br(), localpart = dom.input()), '@', dom.label(style({ display: 'inline-block' }), dom.span('Domain'), dom.br(), domain = dom.select((domains || []).map(d => dom.option(domainName(d.Domain), domainName(d.Domain) === config.Domain ? attr.selected('') : [])))), ' ', dom.submitbutton('Add address'))), dom.br(), dom.h2('Alias (list) membership'), dom.table(dom.thead(dom.tr(dom.th('Alias address', attr.title('Messages sent to this address will be delivered to all members of the alias/list. A member does not receive a message if their address is in the message From header.')), dom.th('Subscription address'), dom.th('Allowed senders', attr.title('Whether only members can send through the alias/list, or anyone.')), dom.th('Send as alias address', attr.title('If enabled, messages can be sent with the alias address in the message "From" header.')), dom.th('Members visible', attr.title('If enabled, members can see the addresses of other members.')))), (config.Aliases || []).length === 0 ? dom.tr(dom.td(attr.colspan('6'), 'None')) : [], (config.Aliases || []).sort((a, b) => a.Alias.LocalpartStr < b.Alias.LocalpartStr ? -1 : (domainName(a.Alias.Domain) < domainName(b.Alias.Domain) ? -1 : 1)).map(a => dom.tr(dom.td(dom.a(prewrap(a.Alias.LocalpartStr, '@', domainName(a.Alias.Domain)), attr.href('#domains/' + domainName(a.Alias.Domain) + '/alias/' + encodeURIComponent(a.Alias.LocalpartStr)))), dom.td(prewrap(a.SubscriptionAddress)), dom.td(a.Alias.PostPublic ? 'Anyone' : 'Members only'), dom.td(a.Alias.AllowMsgFrom ? 'Yes' : 'No'), dom.td(a.Alias.ListMembers ? 'Yes' : 'No'), dom.td(dom.clickbutton('Remove', async function click(e) {
		await check(e.target, client.AliasAddressesRemove(a.Alias.LocalpartStr, domainName(a.Alias.Domain), [a.SubscriptionAddress]));
		window.location.reload(); // todo: reload less
	}))))), dom.br(), dom.h2('Settings'), dom.form(fieldsetSettings = dom.fieldset(dom.label(style({ display: 'block', marginBottom: '.5ex' }), dom.span('Maximum outgoing messages per day', attr.title('Maximum number of outgoing messages for this account in a 24 hour window. This limits the damage to recipients and the reputation of this mail server in case of account compromise. Default 1000. MaxOutgoingMessagesPerDay in configuration file.')), dom.br(), maxOutgoingMessagesPerDay = dom.input(attr.type('number'), attr.required(''), attr.value('' + (config.MaxOutgoingMessagesPerDay || 1000)))), dom.label(style({ display: 'block', marginBottom: '.5ex' }), dom.span('Maximum first-time recipients per day', attr.title('Maximum number of first-time recipients in outgoing messages for this account in a 24 hour window. This limits the damage to recipients and the reputation of this mail server in case of account compromise. Default 200. MaxFirstTimeRecipientsPerDay in configuration file.')), dom.br(), maxFirstTimeRecipientsPerDay = dom.input(attr.type('number'), attr.required(''), attr.value('' + (config.MaxFirstTimeRecipientsPerDay || 200)))), dom.label(style({ display: 'block', marginBottom: '.5ex' }), dom.span('Disk usage quota: Maximum total message size ', attr.title('Default maximum total message size in bytes for the account, overriding any globally configured default maximum size if non-zero. A negative value can be used to have no limit in case there is a limit by default. Attempting to add new messages to an account beyond its maximum total size will result in an error. Useful to prevent a single account from filling storage. Use units "k" for kilobytes, or "m", "g", "t".')), dom.br(), quotaMessageSize = dom.input(attr.value(formatQuotaSize(config.QuotaMessageSize))), ' Current usage is ', formatQuotaSize(Math.floor(diskUsage / (1024 * 1024)) * 1024 * 1024), '.'), dom.div(style({ display: 'block', marginBottom: '.5ex' }), dom.label(firstTimeSenderDelay = dom.input(attr.type('checkbox'), config.NoFirstTimeSenderDelay ? [] : attr.checked('')), ' ', dom.span('Delay deliveries from first-time senders', attr.title('To slow down potential spammers, when the message is misclassified as non-junk. Turning off the delay can be useful when the account processes messages automatically and needs fast responses.')))), dom.div(style({ display: 'block', marginBottom: '.5ex' }), dom.label(noCustomPassword = dom.input(attr.type('checkbox'), config.NoCustomPassword ? attr.checked('') : []), ' ', dom.span("Don't allow account to set a password of their choice", attr.title('If set, this account cannot set a password of their own choice, but can only set a new randomly generated password, preventing password reuse across services and use of weak passwords.')))), dom.submitbutton('Save')), async function submit(e) {
		e.stopPropagation();
		e.preventDefault();
		await check(fieldsetSettings, (async () => await client.AccountSettingsSave(name, parseInt(maxOutgoingMessagesPerDay.value) || 0, parseInt(maxFirstTimeRecipientsPerDay.value) || 0, xparseSize(quotaMessageSize.value), firstTimeSenderDelay.checked, noCustomPassword.checked))());
	}), dom.br(), dom.h2('Set new password'), formPassword = dom.form(fieldsetPassword = dom.fieldset(dom.label(style({ display: 'inline-block' }), 'New password', dom.br(), password = dom.input(attr.type('password'), attr.autocomplete('new-password'), attr.required(''), function focus() {
		passwordHint.style.display = '';
	})), ' ', dom.submitbutton('Change password')), passwordHint = dom.div(style({ display: 'none', marginTop: '.5ex' }), dom.clickbutton('Generate random password', function click(e) {
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
		password.type = 'text';
		password.value = s;
	}), dom.div(dom._class('text'), box(yellow, 'Important: Bots will try to bruteforce your password. Connections with failed authentication attempts will be rate limited but attackers WILL find passwords reused at other services and weak passwords. If your account is compromised, spammers are likely to abuse your system, spamming your address and the wider internet in your name. So please pick a random, unguessable password, preferrably at least 12 characters.'))), async function submit(e) {
		e.stopPropagation();
		e.preventDefault();
		await check(fieldsetPassword, client.SetPassword(name, password.value));
		window.alert('Password has been changed.');
		formPassword.reset();
	}), dom.br(), dom.h2('TLS public keys', attr.title('For TLS client authentication with certificates, for IMAP and/or submission (SMTP). Only the public key of the certificate is used during TLS authentication, to identify this account. Names, expiration or constraints are not verified.')), dom.table(dom.thead(dom.tr(dom.th('Login address'), dom.th('Name'), dom.th('Type'), dom.th('No IMAP "preauth"', attr.title('New IMAP immediate TLS connections authenticated with a client certificate are automatically switched to "authenticated" state with an untagged IMAP "preauth" message by default. IMAP connections have a state machine specifying when commands are allowed. Authenticating is not allowed while in the "authenticated" state. Enable this option to work around clients that would try to authenticated anyway.')), dom.th('Fingerprint'))), dom.tbody(tlspubkeys?.length ? [] : dom.tr(dom.td(attr.colspan('5'), 'None')), (tlspubkeys || []).map(tpk => {
		const row = dom.tr(dom.td(tpk.LoginAddress), dom.td(tpk.Name), dom.td(tpk.Type), dom.td(tpk.NoIMAPPreauth ? 'Enabled' : ''), dom.td(tpk.Fingerprint));
		return row;
	}))), dom.br(), RoutesEditor('account-specific', transports, config.Routes || [], async (routes) => await client.AccountRoutesSave(name, routes)), dom.br(), dom.h2('Danger'), dom.div(config.LoginDisabled ? [
		box(yellow, 'Account login is currently disabled.'),
		dom.clickbutton('Enable account login', async function click(e) {
			if (window.confirm('Are you sure you want to enable login to this account?')) {
				await check(e.target, client.AccountLoginDisabledSave(name, ''));
				window.location.reload(); // todo: update account and rerender.
			}
		})
	] : dom.clickbutton('Disable account login', function click() {
		let fieldset;
		let loginDisabled;
		const close = popup(dom.h1('Disable account login'), dom.form(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(fieldset, client.AccountLoginDisabledSave(name, loginDisabled.value));
			close();
			window.location.reload(); // todo: update account and rerender.
		}, fieldset = dom.fieldset(dom.label(dom.div('Message to user'), loginDisabled = dom.input(attr.required(''), style({ width: '100%' })), dom.p(style({ fontStyle: 'italic' }), 'Will be shown to user on login attempts. Single line, no special and maximum 256 characters since message is used in IMAP/SMTP.')), dom.div(dom.submitbutton('Disable login')))));
	})), dom.br(), dom.h2('Recent login attempts', attr.title('Login attempts are stored for 30 days. At most 10000 failed login attempts are stored per account to prevent unlimited growth of the database.')), renderLoginAttempts(false, loginAttempts || []), dom.br(), loginAttempts && loginAttempts.length >= 10 ? dom.p('See ', dom.a(attr.href('#accounts/l/' + name + '/loginattempts'), 'all login attempts'), ' for this account.') : [], dom.br(), dom.clickbutton('Remove account', async function click(e) {
		e.preventDefault();
		if (!window.confirm('Are you sure you want to remove this account? All account data, including messages will be removed.')) {
			return;
		}
		await check(e.target, client.AccountRemove(name));
		window.location.hash = '#accounts';
	}));
};
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
const formatDuration = (v, goDuration) => {
	if (v === 0) {
		return '';
	}
	const is = (period) => v > 0 && Math.round(v / period) === v / period;
	const format = (period, s) => '' + (v / period) + s;
	if (!goDuration && is(week)) {
		return format(week, 'w');
	}
	if (!goDuration && is(day)) {
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
const domain = async (d) => {
	const end = new Date();
	const start = new Date(new Date().getTime() - 30 * 24 * 3600 * 1000);
	const [dmarcSummaries, tlsrptSummaries, [localpartAccounts, localpartAliases], clientConfigs, [accounts, accountsDisabled], domainConfig, transports] = await Promise.all([
		client.DMARCSummaries(start, end, d),
		client.TLSRPTSummaries(start, end, d),
		client.DomainLocalparts(d),
		client.ClientConfigsDomain(d),
		client.Accounts(),
		client.DomainConfig(d),
		client.Transports(),
	]);
	const dnsdomain = domainConfig.Domain;
	let addrForm;
	let addrFieldset;
	let addrLocalpart;
	let addrAccount;
	let aliasFieldset;
	let aliasLocalpart;
	let aliasAddresses;
	let aliasAddText;
	let descrFieldset;
	let descrText;
	let clientSettingsDomainFieldset;
	let clientSettingsDomain;
	let localpartFieldset;
	let localpartCaseSensitive;
	let dmarcFieldset;
	let dmarcLocalpart;
	let dmarcDomain;
	let dmarcAccount;
	let dmarcMailbox;
	let tlsrptFieldset;
	let tlsrptLocalpart;
	let tlsrptDomain;
	let tlsrptAccount;
	let tlsrptMailbox;
	let mtastsFieldset;
	let mtastsPolicyID;
	let mtastsMode;
	let mtastsMaxAge;
	let mtastsMX;
	const popupDKIMHeaders = (sel, span) => {
		const l = sel.HeadersEffective || [];
		let headers;
		const close = popup(dom.h1('Headers to sign with DKIM'), dom.p('Headers signed with DKIM cannot be modified in transit, or the signature would fail to verify. Headers that could influence how messages are interpreted are best DKIM-signed.'), dom.form(function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			sel.HeadersEffective = headers.value.split('\n').map(s => s.trim()).filter(s => s);
			dom._kids(span, (sel.HeadersEffective || []).join('; '));
			close();
		}, dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Headers', dom.div(headers = dom.textarea(new String(l.join('\n')), attr.rows('' + Math.max(2, 1 + l.length))))), dom.div(dom.submitbutton('OK')), dom.br(), dom.p("Changes are not yet saved after closing the popup. Don't forget to save.")));
	};
	const popupDKIMAdd = () => {
		let fieldset;
		let selector;
		let algorithm;
		let hash;
		let canonHeader;
		let canonBody;
		let seal;
		let headers;
		let lifetime;
		const defaultSelector = () => {
			const d = new Date();
			let s = '' + d.getFullYear();
			let mon = '' + (1 + d.getMonth());
			s += mon.length === 1 ? '0' + mon : mon;
			s += 'a';
			return s;
		};
		popup(style({ minWidth: '30em' }), dom.h1('Add DKIM key/selector'), dom.form(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			if (!window.confirm('Are you sure? A key will be generated by the server, the selector configured but disabled. The page will reload, so unsaved changes to other DKIM selectors will be lost. After adding the key, first add the selector to DNS, then enable it for signing outgoing messages.')) {
				return;
			}
			await check(fieldset, (async () => await client.DomainDKIMAdd(d, selector.value, algorithm.value, hash.value, canonHeader.value === 'relaxed', canonBody.value === 'relaxed', seal.checked, headers.value.split('\n').map(s => s.trim()).filter(s => s), parseDuration(lifetime.value)))());
			window.alert("Selector added. Page will be reloaded. Don't forget to add the selector to DNS, see suggested DNS records, and don't forget to enable the selector afterwards.");
			window.location.reload(); // todo: reload only dkim section
		}, fieldset = dom.fieldset(dom.div(style({ display: 'flex', gap: '1em' }), dom.div(dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Selector', attr.title('Used in the DKIM-Signature header, and used to form a DNS record under ._domainkey.<domain>.'), dom.div(selector = dom.input(attr.required(''), attr.value(defaultSelector())))), dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Algorithm', attr.title('For signing messages. RSA is common at the time of writing, not all mail servers recognize ed25519 signature.'), dom.div(algorithm = dom.select(dom.option('rsa'), dom.option('ed25519')))), dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Hash', attr.title("Used in signing messages. Don't use sha1 unless you understand the consequences."), dom.div(hash = dom.select(dom.option('sha256')))), dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Canonicalization - header', attr.title('Canonicalization processes the message headers before signing. Relaxed allows more whitespace changes, making it more likely for DKIM signatures to validate after transit through servers that make whitespace modifications. Simple is more strict.'), dom.div(canonHeader = dom.select(dom.option('relaxed'), dom.option('simple')))), dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Canonicalization - body', attr.title('Like canonicalization for headers, but for the bodies.'), dom.div(canonBody = dom.select(dom.option('relaxed'), dom.option('simple')))), dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Signature lifetime', attr.title('How long a signature remains valid. Should be as long as a message may take to be delivered. The signature must be valid at the time a message is being delivered to the final destination.'), dom.div(lifetime = dom.input(attr.value('3d'), attr.required('')))), dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Seal headers', attr.title("DKIM-signatures cover headers. If headers are not sealed, additional message headers can be added with the same key without invalidating the signature. This may confuse software about which headers are trustworthy. Sealing is the safer option."), dom.div(seal = dom.input(attr.type('checkbox'), attr.checked(''))))), dom.div(dom.label(style({ display: 'block', marginBottom: '1ex' }), 'Headers (optional)', attr.title('Headers to sign. If left empty, a set of standard headers are signed. The (standard set of) headers are most easily edited after creating the selector/key.'), dom.div(headers = dom.textarea(attr.rows('15')))))), dom.div(dom.submitbutton('Add')))));
	};
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'Domain ' + domainString(dnsdomain)), domainConfig.Disabled ? dom.p(box(yellow, 'Warning: Domain is disabled. Incoming/outgoing messages involving this domain are rejected and ACME for new TLS certificates is disabled.')) : [], dom.ul(dom.li(dom.a('Required DNS records', attr.href('#domains/' + d + '/dnsrecords'))), dom.li(dom.a('Check current actual DNS records and domain configuration', attr.href('#domains/' + d + '/dnscheck')))), dom.br(), dom.h2('Client configuration'), dom.p('If autoconfig/autodiscover does not work with an email client, use the settings below for this domain. Authenticate with email address and password. ', dom.span('Explicitly configure', attr.title('To prevent authentication mechanism downgrade attempts that may result in clients sending plain text passwords to a MitM.')), ' the first supported authentication mechanism: SCRAM-SHA-256-PLUS, SCRAM-SHA-1-PLUS, SCRAM-SHA-256, SCRAM-SHA-1, CRAM-MD5.'), dom.table(dom.thead(dom.tr(dom.th('Protocol'), dom.th('Host'), dom.th('Port'), dom.th('Listener'), dom.th('Note'))), dom.tbody((clientConfigs.Entries || []).map(e => dom.tr(dom.td(e.Protocol), dom.td(domainString(e.Host)), dom.td('' + e.Port), dom.td('' + e.Listener), dom.td('' + e.Note))))), dom.br(), dom.h2('DMARC aggregate reports summary'), renderDMARCSummaries(dmarcSummaries || []), dom.br(), dom.h2('TLS reports summary'), renderTLSRPTSummaries(tlsrptSummaries || []), dom.br(), dom.h2('Addresses'), dom.table(dom.thead(dom.tr(dom.th('Address'), dom.th('Account'), dom.th('Action'))), dom.tbody(Object.entries(localpartAccounts).map(t => dom.tr(dom.td(prewrap(t[0]) || '(catchall)'), dom.td(dom.a(t[1], attr.href('#accounts/l/' + t[1]))), dom.td(dom.clickbutton('Remove', async function click(e) {
		e.preventDefault();
		if (!window.confirm('Are you sure you want to remove this address? If it is a member of an alias, it will be removed from the alias.')) {
			return;
		}
		await check(e.target, client.AddressRemove(t[0] + '@' + d));
		window.location.reload(); // todo: only reload the localparts
	})))))), dom.br(), dom.h2('Add address'), addrForm = dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(addrFieldset, client.AddressAdd(addrLocalpart.value + '@' + d, addrAccount.value));
		addrForm.reset();
		window.location.reload(); // todo: only reload the addresses
	}, addrFieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), dom.span('Localpart', attr.title('The localpart is the part before the "@"-sign of an address. An empty localpart is the catchall destination/address for the domain.')), dom.br(), addrLocalpart = dom.input()), '@', domainName(dnsdomain), ' ', dom.label(style({ display: 'inline-block' }), dom.span('Account', attr.title('Account to assign the address to.')), dom.br(), addrAccount = dom.select(attr.required(''), (accounts || []).map(a => dom.option(attr.value(a), a + (accountsDisabled?.includes(a) ? ' (disabled)' : ''))))), ' ', dom.submitbutton('Add address', attr.title('Address will be added and the config reloaded.')))), dom.br(), dom.h2('Aliases (lists)'), dom.table(dom.thead(dom.tr(dom.th('Address'), dom.th('Allowed senders', attr.title('Whether only members can send through the alias/list, or anyone.')), dom.th('Send as alias address', attr.title('If enabled, messages can be sent with the alias address in the message "From" header.')), dom.th('Members visible', attr.title('If enabled, members can see the addresses of other members.')))), Object.values(localpartAliases).length === 0 ? dom.tr(dom.td(attr.colspan('4'), 'None')) : [], Object.values(localpartAliases).sort((a, b) => a.LocalpartStr < b.LocalpartStr ? -1 : 1).map(a => {
		return dom.tr(dom.td(dom.a(prewrap(a.LocalpartStr), attr.href('#domains/' + d + '/alias/' + encodeURIComponent(a.LocalpartStr)))), dom.td(a.PostPublic ? 'Anyone' : 'Members only'), dom.td(a.AllowMsgFrom ? 'Yes' : 'No'), dom.td(a.ListMembers ? 'Yes' : 'No'));
	})), dom.br(), dom.h2('Add alias (list)'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		const alias = {
			Addresses: aliasAddresses.value.split('\n').map(s => s.trim()).filter(s => !!s),
			PostPublic: true,
			ListMembers: false,
			AllowMsgFrom: false,
			// Ignored:
			LocalpartStr: '',
			Domain: dnsdomain,
		};
		await check(aliasFieldset, client.AliasAdd(aliasLocalpart.value, d, alias));
		window.location.hash = '#domains/' + d + '/alias/' + encodeURIComponent(aliasLocalpart.value);
	}, aliasFieldset = dom.fieldset(style({ display: 'flex', alignItems: 'flex-start', gap: '1em' }), dom.label(dom.div('Localpart', attr.title('The localpart is the part before the "@"-sign of an address.')), aliasLocalpart = dom.input(attr.required('')), '@', domainName(dnsdomain), ' '), dom.label(dom.div('Addresses', attr.title('One members address per line, full address of form localpart@domain. At least one address required.')), aliasAddresses = dom.textarea(attr.required(''), attr.rows('1'), function focus() {
		aliasAddresses.setAttribute('rows', '5');
		aliasAddText.style.visibility = 'visible';
	})), dom.div(dom.div('\u00a0'), dom.submitbutton('Add alias', attr.title('Alias will be added and the config reloaded.')), aliasAddText = dom.p(style({ visibility: 'hidden', fontStyle: 'italic' }), 'Messages sent to aliases are delivered to each member address of the alias, like a mailing list. For an additional address for an account, add it as regular address (see above).')))), dom.br(), RoutesEditor('domain-specific', transports, domainConfig.Routes || [], async (routes) => await client.DomainRoutesSave(d, routes)), dom.br(), dom.h2('Settings'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(descrFieldset, client.DomainDescriptionSave(d, descrText.value));
	}, descrFieldset = dom.fieldset(style({ display: 'flex', gap: '1em' }), dom.label(attr.title('Free-form description of domain.'), dom.div('Description'), descrText = dom.input(attr.value(domainConfig.Description), style({ width: '30em' }))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save'))))), dom.form(style({ marginTop: '1ex' }), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(clientSettingsDomainFieldset, client.DomainClientSettingsDomainSave(d, clientSettingsDomain.value));
	}, clientSettingsDomainFieldset = dom.fieldset(style({ display: 'flex', gap: '1em' }), dom.label(attr.title('Hostname for client settings instead of the mail server hostname. E.g. mail.<domain>. For future migration to another mail operator without requiring all clients to update their settings, it is convenient to have client settings that reference a subdomain of the hosted domain instead of the hostname of the server where the mail is currently hosted. If empty, the hostname of the mail server is used for client configurations. Unicode name.'), dom.div('Client settings domain'), clientSettingsDomain = dom.input(attr.value(domainConfig.ClientSettingsDomain), style({ width: '30em' }))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save'))))), (() => {
		let separatorViews = [];
		let separatorsBox;
		const addSeparatorView = (s) => {
			const separator = dom.input(attr.required(''), attr.value(s), style({ width: '2em' }));
			const v = {
				separator: separator,
				root: dom.div(separator, ' ', dom.clickbutton('Remove', function click() {
					separatorViews.splice(separatorViews.indexOf(v), 1);
					v.root.remove();
					if (separatorViews.length === 0) {
						separatorsBox.append(dom.div('(None)'));
					}
				})),
			};
			if (separatorViews.length === 0) {
				dom._kids(separatorsBox);
			}
			separatorViews.push(v);
			separatorsBox.appendChild(v.root);
		};
		const elem = dom.form(style({ marginTop: '1ex' }), async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(localpartFieldset, client.DomainLocalpartConfigSave(d, separatorViews.map(v => v.separator.value), localpartCaseSensitive.checked));
		}, localpartFieldset = dom.fieldset(style({ display: 'flex', gap: '1em' }), dom.label(attr.title('If set, upper/lower case is relevant for email delivery.'), dom.div('Localpart case sensitive'), localpartCaseSensitive = dom.input(attr.type('checkbox'), domainConfig.LocalpartCaseSensitive ? attr.checked('') : [])), dom.div(dom.label(attr.title('If not empty, only the string before the separator is used for email delivery decisions. For example, if set to \"+\", you+anything@example.com will be delivered to you@example.com.'), 'Localpart catchall separators'), ' ', dom.clickbutton('Add', function click() {
			addSeparatorView('');
		}), separatorsBox = dom.div(style({ display: 'flex', flexDirection: 'column', gap: '.25em' }), dom.div('(None)'))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save')))));
		for (const sep of (domainConfig.LocalpartCatchallSeparatorsEffective || [])) {
			addSeparatorView(sep);
		}
		return elem;
	})(), dom.br(), dom.h2('DMARC reporting address'), dom.form(style({ marginTop: '1ex' }), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		if (!dmarcLocalpart.value) {
			dmarcDomain.value = '';
			dmarcAccount.value = '';
			dmarcMailbox.value = '';
		}
		const needChange = (dmarcLocalpart.value === '') !== (domainConfig.DMARC === null) || domainConfig.DMARC && (domainConfig.DMARC.Localpart !== dmarcLocalpart.value || domainConfig.DMARC?.Domain !== dmarcDomain.value);
		await check(dmarcFieldset, client.DomainDMARCAddressSave(d, dmarcLocalpart.value, dmarcDomain.value, dmarcAccount.value, dmarcMailbox.value));
		if (needChange) {
			window.alert('Do not forget to update the DNS records with the updated reporting address (rua).');
			if (dmarcLocalpart.value) {
				domainConfig.DMARC = { Localpart: dmarcLocalpart.value, Domain: dmarcDomain.value, Account: dmarcAccount.value, Mailbox: dmarcMailbox.value, ParsedLocalpart: '', DNSDomain: { ASCII: '', Unicode: '' } };
			}
			else {
				domainConfig.DMARC = null;
			}
		}
	}, dmarcFieldset = dom.fieldset(style({ display: 'flex', gap: '1em' }), dom.label(attr.title('Address-part before the @ that accepts DMARC reports. Must be non-internationalized. Recommended value: dmarcreports.'), dom.div('Localpart'), dmarcLocalpart = dom.input(attr.value(domainConfig.DMARC?.Localpart || ''))), dom.label(attr.title("Alternative domain for reporting address, for incoming reports. Typically empty, causing this domain to be used. Can be used to receive reports for domains that aren't fully hosted on this server. Configure such a domain as a hosted domain without making all the DNS changes, and configure this field with a domain that is fully hosted on this server, so the localpart and the domain of this field form a reporting address. Then only update the DMARC DNS record for the hosted domain, ensuring the reporting address is specified in its \"rua\" field as shown in the DNS settings for this domain. Unicode name."), dom.div('Alternative domain (optional)'), dmarcDomain = dom.input(attr.value(domainConfig.DMARC?.Domain || ''))), dom.label(attr.title('Account to deliver to.'), dom.div('Account'), dmarcAccount = dom.select(dom.option(''), (accounts || []).map(s => dom.option(attr.value(s), s + (accountsDisabled?.includes(s) ? ' (disabled)' : ''), s === domainConfig.DMARC?.Account ? attr.selected('') : [])))), dom.label(attr.title('Mailbox to deliver to, e.g. DMARC.'), dom.div('Mailbox'), dmarcMailbox = dom.input(attr.value(domainConfig.DMARC?.Mailbox || ''))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save'))))), dom.br(), dom.h2('TLS reporting address'), dom.form(style({ marginTop: '1ex' }), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		if (!tlsrptLocalpart.value) {
			tlsrptDomain.value = '';
			tlsrptAccount.value = '';
			tlsrptMailbox.value = '';
		}
		const needChange = (tlsrptLocalpart.value === '') !== (domainConfig.TLSRPT === null) || domainConfig.TLSRPT && (domainConfig.TLSRPT.Localpart !== tlsrptLocalpart.value || domainConfig.TLSRPT?.Domain !== tlsrptDomain.value);
		await check(tlsrptFieldset, client.DomainTLSRPTAddressSave(d, tlsrptLocalpart.value, tlsrptDomain.value, tlsrptAccount.value, tlsrptMailbox.value));
		if (needChange) {
			window.alert('Do not forget to update the DNS records with the updated reporting address (rua).');
			if (tlsrptLocalpart.value) {
				domainConfig.TLSRPT = { Localpart: tlsrptLocalpart.value, Domain: tlsrptDomain.value, Account: tlsrptAccount.value, Mailbox: tlsrptMailbox.value, ParsedLocalpart: '', DNSDomain: { ASCII: '', Unicode: '' } };
			}
			else {
				domainConfig.TLSRPT = null;
			}
		}
	}, tlsrptFieldset = dom.fieldset(style({ display: 'flex', gap: '1em' }), dom.label(attr.title('Address-part before the @ that accepts TLSRPT reports. Must be non-internationalized. Recommended value: tlsrpt-reports.'), dom.div('Localpart'), tlsrptLocalpart = dom.input(attr.value(domainConfig.TLSRPT?.Localpart || ''))), dom.label(attr.title("Alternative domain for reporting address, for incoming reports. Typically empty, causing the domain wherein this config exists to be used. Can be used to receive reports for domains that aren't fully hosted on this server. Configure such a domain as a hosted domain without making all the DNS changes, and configure this field with a domain that is fully hosted on this server, so the localpart and the domain of this field form a reporting address. Then only update the TLSRPT DNS record for the not fully hosted domain, ensuring the reporting address is specified in its \"rua\" field as shown in the suggested DNS settings. Unicode name."), dom.div('Alternative domain (optional)'), tlsrptDomain = dom.input(attr.value(domainConfig.TLSRPT?.Domain || ''))), dom.label(attr.title('Account to deliver to.'), dom.div('Account'), tlsrptAccount = dom.select(dom.option(''), (accounts || []).map(s => dom.option(attr.value(s), s + (accountsDisabled?.includes(s) ? ' (disabled)' : ''), s === domainConfig.TLSRPT?.Account ? attr.selected('') : [])))), dom.label(attr.title('Mailbox to deliver to, e.g. TLSRPT.'), dom.div('Mailbox'), tlsrptMailbox = dom.input(attr.value(domainConfig.TLSRPT?.Mailbox || ''))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save'))))), dom.br(), dom.h2('MTA-STS policy', attr.title("MTA-STS is a mechanism that allows publishing a policy with requirements for WebPKI-verified SMTP STARTTLS connections for email delivered to a domain. Existence of a policy is announced in a DNS TXT record (often unprotected/unverified, MTA-STS's weak spot). If a policy exists, it is fetched with a WebPKI-verified HTTPS request. The policy can indicate that WebPKI-verified SMTP STARTTLS is required, and which MX hosts (optionally with a wildcard pattern) are allowd. MX hosts to deliver to are still taken from DNS (again, not necessarily protected/verified), but messages will only be delivered to domains matching the MX hosts from the published policy. Mail servers look up the MTA-STS policy when first delivering to a domain, then keep a cached copy, periodically checking the DNS record if a new policy is available, and fetching and caching it if so. To update a policy, first serve a new policy with an updated policy ID, then update the DNS record (not the other way around). To remove an enforced policy, publish an updated policy with mode \"none\" for a long enough period so all cached policies have been refreshed (taking DNS TTL and policy max age into account), then remove the policy from DNS, wait for TTL to expire, and stop serving the policy.")), dom.form(style({ marginTop: '1ex' }), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		let mx = [];
		let mode = api.Mode.ModeNone;
		let maxAge = 0;
		if (!mtastsPolicyID.value) {
			mtastsMode.value = '';
			mtastsMaxAge.value = '';
			mtastsMX.value = '';
			if (domainConfig.MTASTS?.PolicyID && !window.confirm('Are you sure you want to remove the MTA-STS policy? Only remove policies after having served a policy with mode "none" for a long enough period, so all previously served and remotely cached policies have expired past the then-configured DNS TTL plus policy max-age period, and seen the policy with mode "none".')) {
				return;
			}
		}
		else {
			if (!mtastsMode.value) {
				throw new Error('mode is required for an active policy');
			}
			mode = mtastsMode.value;
			maxAge = parseDuration(mtastsMaxAge.value);
			mx = mtastsMX.value ? mtastsMX.value.split('\n') : [];
			if (domainConfig.MTASTS?.PolicyID === mtastsPolicyID.value && !window.confirm('Are you sure you want to save the policy without updating the policy ID? Remote servers may hold on to the old cached policies. Policy IDs should be changed when the policy is changed. Remember to first update the policy here, then publish the new policy ID in DNS.')) {
				return;
			}
		}
		await check(mtastsFieldset, client.DomainMTASTSSave(d, mtastsPolicyID.value, mode, maxAge, mx));
		if (domainConfig.MTASTS?.PolicyID === mtastsPolicyID.value) {
			return;
		}
		if (domainConfig.MTASTS?.PolicyID && !mtastsPolicyID.value) {
			window.alert("Don't forget to remove the MTA-STS DNS record.");
			domainConfig.MTASTS = null;
		}
		else if (mtastsPolicyID.value) {
			if (mtastsPolicyID.value !== domainConfig.MTASTS?.PolicyID) {
				window.alert("Don't forget to update the MTA-STS DNS record with the new policy ID, see suggested DNS records.");
			}
			domainConfig.MTASTS = {
				PolicyID: mtastsPolicyID.value,
				Mode: mode,
				MaxAge: maxAge,
				MX: mx,
			};
		}
	}, mtastsFieldset = dom.fieldset(style({ display: 'flex', gap: '1em' }), dom.label(attr.title('Policies are versioned. The version must be specified in the DNS record. If you change a policy, first change it here to update the served policy, then update the DNS record with the updated policy ID.'), dom.div('Policy ID ', dom.a('generate', attr.href(''), attr.title('Generate new policy ID based on current time.'), function click(e) {
		e.preventDefault();
		// 20060102T150405
		mtastsPolicyID.value = new Date().toISOString().replace(/-/g, '').replace(/:/g, '').split('.')[0];
	})), mtastsPolicyID = dom.input(attr.value(domainConfig.MTASTS?.PolicyID || ''))), dom.label(attr.title("If set to \"enforce\", a remote SMTP server will not deliver email to us if it cannot make a WebPKI-verified SMTP STARTTLS connection. In mode \"testing\", deliveries can be done without verified TLS, but errors will be reported through TLS reporting. In mode \"none\", verified TLS is not required, used for phasing out an MTA-STS policy."), dom.div('Mode'), mtastsMode = dom.select(dom.option(''), Object.values(api.Mode).map(s => dom.option(s, domainConfig.MTASTS?.Mode === s ? attr.selected('') : [])))), dom.label(attr.title('How long a remote mail server is allowed to cache a policy. Typically 1 or several weeks. Units: s for seconds, m for minutes, h for hours, d for day, w for weeks.'), dom.div('Max age'), mtastsMaxAge = dom.input(attr.value(domainConfig.MTASTS?.MaxAge ? formatDuration(domainConfig.MTASTS?.MaxAge || 0) : ''))), dom.label(attr.title('List of server names allowed for SMTP. If empty, the configured hostname is set. Host names can contain a wildcard (*) as a leading label (matching a single label, e.g. *.example matches host.example, not sub.host.example).'), dom.div('MX hosts/patterns (optional)'), mtastsMX = dom.textarea(new String((domainConfig.MTASTS?.MX || []).join('\n')), attr.rows('' + Math.max(2, 1 + (domainConfig.MTASTS?.MX || []).length)))), dom.div(dom.span('\u00a0'), dom.div(dom.submitbutton('Save'))))), dom.br(), dom.h2('DKIM', attr.title('With DKIM signing, a domain is taking responsibility for (content of) emails it sends, letting receiving mail servers build up a (hopefully positive) reputation of the domain, which can help with mail delivery.')), (() => {
		let fieldset;
		let rows = [];
		return dom.form(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			if (!window.confirm("Are you sure you want to save changes to DKIM selectors?")) {
				return;
			}
			const selectors = {};
			const sign = [];
			for (const row of rows) {
				const [selName, enabled, sel] = row.gather();
				sel.Expiration = formatDuration(parseDuration(sel.Expiration), true);
				selectors[selName] = sel;
				if (enabled) {
					sign.push(selName);
				}
			}
			await check(fieldset, client.DomainDKIMSave(d, selectors, sign));
			window.alert("Don't forget to update DNS records if needed. See suggested DNS records.");
		}, fieldset = dom.fieldset(dom.table(dom.thead(dom.tr(dom.th('Selector', attr.title('Used in the DKIM-Signature header, and used to form a DNS record under ._domainkey.<domain>.')), dom.th('Enabled', attr.title('Whether a DKIM-Signature is added to messages for this message. Multiple selectors can be enabled. Having backup keys published in DNS can be useful for quickly rotating a key.')), dom.th('Algorithm', attr.title('For signing messages. RSA is common at the time of writing, not all mail servers recognize ed25519 signature.')), dom.th('Hash', attr.title("Used in signing messages. Don't use sha1 unless you understand the consequences.")), dom.th('Canonicalization header/body', attr.colspan('2'), attr.title('Canonicalization processes the message headers and bodies before signing. Relaxed allows more whitespace changes, making it more likely for DKIM signatures to validate after transit through servers that make whitespace modifications. Simple is more strict.')), dom.th('Seal headers', attr.title("DKIM-signatures cover headers. If headers are not sealed, additional message headers can be added with the same key without invalidating the signature. This may confuse software about which headers are trustworthy. Sealing is the safer option.")), dom.th('Headers', attr.title('Headers to sign.')), dom.th('Signature lifetime', attr.title('How long a signature remains valid. Should be as long as a message may take to be delivered. The signature must be valid at the time a message is being delivered to the final destination.')), dom.th('Action'))), dom.tbody(Object.keys(domainConfig.DKIM.Selectors || []).length === 0 ? dom.tr(dom.td(attr.colspan('9'), 'No DKIM keys/selectors.')) : [], rows = Object.entries(domainConfig.DKIM.Selectors || []).sort().map(([selName, sel]) => {
			let enabled;
			let hash;
			let canonHeader;
			let canonBody;
			let seal;
			let headersElem;
			let lifetime;
			const tr = dom.tr(dom.td(selName), dom.td(enabled = dom.input(attr.type('checkbox'), (domainConfig.DKIM.Sign || []).includes(selName) ? attr.checked('') : [])), dom.td(sel.Algorithm), dom.td(hash = dom.select(dom.option('sha256', sel.HashEffective === 'sha256' ? attr.selected('') : []), dom.option('sha1', sel.HashEffective === 'sha1' ? attr.selected('') : []))), dom.td(canonHeader = dom.select(dom.option('relaxed'), dom.option('simple', sel.Canonicalization.HeaderRelaxed ? [] : attr.selected('')))), dom.td(canonBody = dom.select(dom.option('relaxed'), dom.option('simple', sel.Canonicalization.BodyRelaxed ? [] : attr.selected('')))), dom.td(seal = dom.input(attr.type('checkbox'), sel.DontSealHeaders ? [] : attr.checked(''))), dom.td(headersElem = dom.span((sel.HeadersEffective || []).join('; ')), ' ', dom.a(attr.href(''), 'Edit', function click(e) {
				e.preventDefault();
				popupDKIMHeaders(sel, headersElem);
			})), dom.td(lifetime = dom.input(attr.value(sel.Expiration))), dom.td(dom.clickbutton('Remove', async function click(e) {
				if (!window.confirm('Are you sure you want to remove this selector? It is removed immediately, after which the page is reloaded, losing unsaved changes.')) {
					return;
				}
				await check(e.target, client.DomainDKIMRemove(d, selName));
				window.alert("Don't forget to remove the corresponding DNS records (if it exists). If the DKIM key was active, it is best to wait for all messages in transit have been delivered (which can take days if messages are held up in remote queues), or those messages will not pass DKIM validiation.");
				window.location.reload(); // todo: reload less
			})));
			return {
				root: tr,
				gather: () => {
					const nsel = {
						Hash: hash.value,
						HashEffective: hash.value,
						Canonicalization: {
							HeaderRelaxed: canonHeader.value === 'relaxed',
							BodyRelaxed: canonBody.value === 'relaxed',
						},
						Headers: sel.HeadersEffective,
						HeadersEffective: sel.HeadersEffective,
						DontSealHeaders: !seal.checked,
						Expiration: lifetime.value,
						PrivateKeyFile: '',
						Algorithm: '',
					};
					return [selName, enabled.checked, nsel];
				},
			};
		})), dom.tfoot(dom.tr(dom.td(attr.colspan('9'), dom.submitbutton('Save'), ' ', dom.clickbutton('Add key/selector', function click() {
			popupDKIMAdd();
		})))))));
	})(), dom.br(), dom.h2('External checks'), dom.ul(dom.li(link('https://internet.nl/mail/' + dnsdomain.ASCII + '/', 'Check configuration at internet.nl'))), dom.br(), dom.h2('Danger'), dom.div(domainConfig.Disabled ? [
		box(yellow, 'Domain is currently disabled.'),
		dom.clickbutton('Enable domain', async function click(e) {
			if (window.confirm('Are you sure you want to enable this domain? Incoming/outgoing messages involving this domain will be accepted, and ACME for new TLS certificates will be enabled.')) {
				check(e.target, client.DomainDisabledSave(d, false));
			}
		})
	] : dom.clickbutton('Disable domain', async function click(e) {
		if (window.confirm('Are you sure you want to disable this domain? Incoming/outgoing messages involving this domain will be rejected with a temporary error code, and ACME for new TLS certificates will be disabled.')) {
			check(e.target, client.DomainDisabledSave(d, true));
		}
	})), dom.br(), dom.clickbutton('Remove domain', async function click(e) {
		e.preventDefault();
		if (!window.confirm('Are you sure you want to remove this domain?')) {
			return;
		}
		await check(e.target, client.DomainRemove(d));
		window.location.hash = '#';
	}));
};
const domainAlias = async (d, aliasLocalpart) => {
	const domain = await client.DomainConfig(d);
	const alias = (domain.Aliases || {})[aliasLocalpart];
	if (!alias) {
		throw new Error('alias not found');
	}
	let aliasFieldset;
	let postPublic;
	let listMembers;
	let allowMsgFrom;
	let addFieldset;
	let addAddress;
	let delFieldset;
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Domain ' + domainString(domain.Domain), '#domains/' + d), 'Alias ' + aliasLocalpart + '@' + domainName(domain.Domain)), dom.h2('Alias'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		check(aliasFieldset, client.AliasUpdate(aliasLocalpart, d, postPublic.checked, listMembers.checked, allowMsgFrom.checked));
	}, aliasFieldset = dom.fieldset(style({ display: 'flex', flexDirection: 'column', gap: '.5ex' }), dom.label(postPublic = dom.input(attr.type('checkbox'), alias.PostPublic ? attr.checked('') : []), ' Public, anyone is allowed to send to the alias, instead of only members of the alias', attr.title('Based on address in message From header, which is assumed to be DMARC-like verified. If this setting is disabled and a non-member sends a message to the alias, the message is rejected.')), dom.label(listMembers = dom.input(attr.type('checkbox'), alias.ListMembers ? attr.checked('') : []), ' Members can list other members'), dom.label(allowMsgFrom = dom.input(attr.type('checkbox'), alias.AllowMsgFrom ? attr.checked('') : []), ' Allow messages to use the alias address in the message From header'), dom.div(style({ marginTop: '1ex' }), dom.submitbutton('Save')))), dom.br(), dom.h2('Members'), dom.p('Members receive messages sent to the alias. If a member address is in the message From header, the member will not receive the message.'), dom.table(dom.thead(dom.tr(dom.th('Address'), dom.th('Account'), dom.th())), dom.tbody((alias.Addresses || []).map((address, index) => {
		const pa = (alias.ParsedAddresses || [])[index];
		return dom.tr(dom.td(prewrap(address)), dom.td(dom.a(pa.AccountName, attr.href('#accounts/l/' + pa.AccountName))), dom.td(dom.clickbutton('Remove', async function click(e) {
			await check(e.target, client.AliasAddressesRemove(aliasLocalpart, d, [address]));
			window.location.reload(); // todo: reload less
		})));
	})), dom.tfoot(dom.tr(dom.td(attr.colspan('3'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(addFieldset, client.AliasAddressesAdd(aliasLocalpart, d, addAddress.value.split('\n').map(s => s.trim()).filter(s => s)));
		window.location.reload(); // todo: reload less
	}, addFieldset = dom.fieldset(addAddress = dom.textarea(attr.required(''), attr.rows('1'), attr.placeholder('localpart@domain'), function focus() { addAddress.setAttribute('rows', '5'); }), ' ', dom.submitbutton('Add', style({ verticalAlign: 'top' })))))))), dom.br(), dom.h2('Danger'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		if (!confirm('Are you sure you want to remove this alias?')) {
			return;
		}
		await check(delFieldset, client.AliasRemove(aliasLocalpart, d));
		window.location.hash = '#domains/' + d;
	}, delFieldset = dom.fieldset(dom.div(dom.submitbutton('Remove alias')))));
};
const domainDNSRecords = async (d) => {
	const [records, dnsdomain] = await Promise.all([
		client.DomainRecords(d),
		client.ParseDomain(d),
	]);
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Domain ' + domainString(dnsdomain), '#domains/' + d), 'DNS Records'), dom.h1('Required DNS records'), dom.pre(dom._class('literal'), (records || []).join('\n')), dom.br());
};
const domainDNSCheck = async (d) => {
	const [checks, dnsdomain] = await Promise.all([
		client.CheckDomain(d),
		client.ParseDomain(d),
	]);
	const resultSection = (title, r, details) => {
		let success = [];
		if ((r.Errors || []).length === 0 && (r.Warnings || []).length === 0) {
			success = box(green, 'OK');
		}
		const errors = (r.Errors || []).length === 0 ? [] : box(red, dom.ul((r.Errors || []).map(s => dom.li(s))));
		const warnings = (r.Warnings || []).length === 0 ? [] : box(yellow, dom.ul((r.Warnings || []).map(s => dom.li(s))));
		let instructions = null;
		if (r.Instructions && r.Instructions.length > 0) {
			instructions = dom.div(style({ margin: '.5ex 0' }));
			const instrs = [
				(r.Instructions || []).map(s => [
					dom.pre(dom._class('literal'), style({ display: 'inline-block', maxWidth: '60em' }), s),
					dom.br(),
				]),
			];
			if ((r.Errors || []).length === 0) {
				dom._kids(instructions, dom.div(dom.a('Show instructions', attr.href('#'), function click(e) {
					e.preventDefault();
					dom._kids(instructions, instrs);
				}), dom.br()));
			}
			else {
				dom._kids(instructions, instrs);
			}
		}
		return [
			dom.h2(title),
			success,
			errors,
			warnings,
			details,
			dom.br(),
			instructions ? instructions : [],
			dom.br(),
		];
	};
	const detailsDNSSEC = [];
	const detailsIPRev = !checks.IPRev.IPNames || !Object.entries(checks.IPRev.IPNames).length ? [] : [
		dom.div('Hostname: ' + domainString(checks.IPRev.Hostname)),
		dom.table(dom.thead(dom.tr(dom.th('IP'), dom.th('Addresses'))), dom.tbody(Object.entries(checks.IPRev.IPNames).sort().map(t => dom.tr(dom.td(t[0]), dom.td((t[1] || []).join(', ')))))),
	];
	const detailsMX = (checks.MX.Records || []).length === 0 ? [] : [
		dom.table(dom.thead(dom.tr(dom.th('Preference'), dom.th('Host'), dom.th('IPs'))), dom.tbody((checks.MX.Records || []).map(mx => dom.tr(dom.td('' + mx.Pref), dom.td(mx.Host), dom.td((mx.IPs || []).join(', ')))))),
	];
	const detailsTLS = [];
	const detailsDANE = [];
	const detailsSPF = [
		checks.SPF.DomainTXT ? [dom.div('Domain TXT record: ' + checks.SPF.DomainTXT)] : [],
		checks.SPF.HostTXT ? [dom.div('Host TXT record: ' + checks.SPF.HostTXT)] : [],
	];
	const detailsDKIM = (checks.DKIM.Records || []).length === 0 ? [] : [
		dom.table(dom.thead(dom.tr(dom.th('Selector'), dom.th('TXT record'))), dom.tbody((checks.DKIM.Records || []).map(rec => dom.tr(dom.td(rec.Selector), dom.td(rec.TXT)))))
	];
	const detailsDMARC = !checks.DMARC.Domain ? [] : [
		dom.div('Domain: ' + checks.DMARC.Domain),
		!checks.DMARC.TXT ? [] : dom.div('TXT record: ' + checks.DMARC.TXT),
	];
	const detailsTLSRPT = (checksTLSRPT) => !checksTLSRPT.TXT ? [] : [
		dom.div('TXT record: ' + checksTLSRPT.TXT),
	];
	const detailsMTASTS = !checks.MTASTS.TXT && !checks.MTASTS.PolicyText ? [] : [
		!checks.MTASTS.TXT ? [] : dom.div('MTA-STS record: ' + checks.MTASTS.TXT),
		!checks.MTASTS.PolicyText ? [] : dom.div('MTA-STS policy: ', dom.pre(dom._class('literal'), style({ maxWidth: '60em' }), checks.MTASTS.PolicyText)),
	];
	const detailsSRVConf = !checks.SRVConf.SRVs || Object.keys(checks.SRVConf.SRVs).length === 0 ? [] : [
		dom.table(dom.thead(dom.tr(dom.th('Service'), dom.th('Priority'), dom.th('Weight'), dom.th('Port'), dom.th('Host'))), dom.tbody(Object.entries(checks.SRVConf.SRVs || []).map(t => {
			const l = t[1];
			if (!l || !l.length) {
				return dom.tr(dom.td(t[0]), dom.td(attr.colspan('4'), '(none)'));
			}
			return l.map(r => dom.tr([t[0], r.Priority, r.Weight, r.Port, r.Target].map(s => dom.td('' + s))));
		}))),
	];
	const detailsAutoconf = [
		...(!checks.Autoconf.ClientSettingsDomainIPs ? [] : [dom.div('Client settings domain IPs: ' + checks.Autoconf.ClientSettingsDomainIPs.join(', '))]),
		...(!checks.Autoconf.IPs ? [] : [dom.div('IPs: ' + checks.Autoconf.IPs.join(', '))]),
	];
	const detailsAutodiscover = !checks.Autodiscover.Records ? [] : [
		dom.table(dom.thead(dom.tr(dom.th('Host'), dom.th('Port'), dom.th('Priority'), dom.th('Weight'), dom.th('IPs'))), dom.tbody((checks.Autodiscover.Records || []).map(r => dom.tr([r.Target, r.Port, r.Priority, r.Weight, (r.IPs || []).join(', ')].map(s => dom.td('' + s)))))),
	];
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Domain ' + domainString(dnsdomain), '#domains/' + d), 'Check DNS'), dom.h1('DNS records and domain configuration check'), resultSection('DNSSEC', checks.DNSSEC, detailsDNSSEC), resultSection('IPRev', checks.IPRev, detailsIPRev), resultSection('MX', checks.MX, detailsMX), resultSection('TLS', checks.TLS, detailsTLS), resultSection('DANE', checks.DANE, detailsDANE), resultSection('SPF', checks.SPF, detailsSPF), resultSection('DKIM', checks.DKIM, detailsDKIM), resultSection('DMARC', checks.DMARC, detailsDMARC), resultSection('Host TLSRPT', checks.HostTLSRPT, detailsTLSRPT(checks.HostTLSRPT)), resultSection('Domain TLSRPT', checks.DomainTLSRPT, detailsTLSRPT(checks.DomainTLSRPT)), resultSection('MTA-STS', checks.MTASTS, detailsMTASTS), resultSection('SRV conf', checks.SRVConf, detailsSRVConf), resultSection('Autoconf', checks.Autoconf, detailsAutoconf), resultSection('Autodiscover', checks.Autodiscover, detailsAutodiscover), dom.br());
};
const dmarcIndex = async () => {
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'DMARC'), dom.ul(dom.li(dom.a(attr.href('#dmarc/reports'), 'Reports'), ', incoming DMARC aggregate reports.'), dom.li(dom.a(attr.href('#dmarc/evaluations'), 'Evaluations'), ', for outgoing DMARC aggregate reports.')));
};
const dmarcReports = async () => {
	const end = new Date();
	const start = new Date(new Date().getTime() - 30 * 24 * 3600 * 1000);
	const summaries = await client.DMARCSummaries(start, end, "");
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('DMARC', '#dmarc'), 'Aggregate reporting summary'), dom.p('DMARC reports are periodically sent by other mail servers that received an email message with a "From" header with our domain. Domains can have a DMARC DNS record that asks other mail servers to send these aggregate reports for analysis.'), renderDMARCSummaries(summaries || []));
};
const renderDMARCSummaries = (summaries) => {
	return [
		dom.p('Below a summary of DMARC aggregate reporting results for the past 30 days.'),
		summaries.length === 0 ? dom.div(box(yellow, 'No domains with reports.')) :
			dom.table(dom.thead(dom.tr(dom.th('Domain', attr.title('Domain to which the DMARC policy applied. If example.com has a DMARC policy, and email is sent with a From-header with subdomain.example.com, and there is no DMARC record for that subdomain, but there is one for example.com, then the DMARC policy of example.com applies and reports are sent for that that domain.')), dom.th('Messages', attr.title('Total number of messages that had the DMARC policy applied and reported. Actual messages sent is likely higher because not all email servers send DMARC aggregate reports, or perform DMARC checks at all.')), dom.th('DMARC "quarantine"/"reject"', attr.title('Messages for which policy was to mark them as spam (quarantine) or reject them during SMTP delivery.')), dom.th('DKIM "fail"', attr.title('Messages with a failing DKIM check. This can happen when sending through a mailing list where that list keeps your address in the message From-header but also strips DKIM-Signature headers in the message. DMARC evaluation passes if either DKIM passes or SPF passes.')), dom.th('SPF "fail"', attr.title('Message with a failing SPF check. This can happen with email forwarding and with mailing list. Other mail servers have sent email with this domain in the message From-header. DMARC evaluation passes if at least SPF or DKIM passes.')), dom.th('Policy overrides', attr.title('Mail servers can override the DMARC policy. E.g. a mail server may be able to detect emails coming from mailing lists that do not pass DMARC and would have to be rejected, but for which an override has been configured.')))), dom.tbody(summaries.map(r => dom.tr(dom.td(dom.a(attr.href('#domains/' + r.Domain + '/dmarc'), attr.title('See report details.'), r.Domain)), dom.td(style({ textAlign: 'right' }), '' + r.Total), dom.td(style({ textAlign: 'right' }), r.DispositionQuarantine === 0 && r.DispositionReject === 0 ? '0/0' : box(red, '' + r.DispositionQuarantine + '/' + r.DispositionReject)), dom.td(style({ textAlign: 'right' }), box(r.DKIMFail === 0 ? green : red, '' + r.DKIMFail)), dom.td(style({ textAlign: 'right' }), box(r.SPFFail === 0 ? green : red, '' + r.SPFFail)), dom.td(!r.PolicyOverrides ? [] : Object.entries(r.PolicyOverrides).map(kv => (kv[0] || '(no reason)') + ': ' + kv[1]).join('; '))))))
	];
};
const dmarcEvaluations = async () => {
	const [evalStats, suppressAddresses] = await Promise.all([
		client.DMARCEvaluationStats(),
		client.DMARCSuppressList(),
	]);
	const isEmpty = (o) => {
		for (const _ in o) {
			return false;
		}
		return true;
	};
	let fieldset;
	let reportingAddress;
	let until;
	let comment;
	const nextmonth = new Date(new Date().getTime() + 31 * 24 * 3600 * 1000);
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('DMARC', '#dmarc'), 'Evaluations'), dom.p('Incoming messages are checked against the DMARC policy of the domain in the message From header. If the policy requests reporting on the resulting evaluations, they are stored in the database. Each interval of 1 to 24 hours, the evaluations may be sent to a reporting address specified in the domain\'s DMARC policy. Not all evaluations are a reason to send a report, but if a report is sent all evaluations are included.'), dom.table(dom._class('hover'), dom.thead(dom.tr(dom.th('Domain', attr.title('Domain in the message From header. Keep in mind these can be forged, so this does not necessarily mean someone from this domain authentically tried delivering email.')), dom.th('Dispositions', attr.title('Unique dispositions occurring in report.')), dom.th('Evaluations', attr.title('Total number of message delivery attempts, including retries.')), dom.th('Send report', attr.title('Whether the current evaluations will cause a report to be sent.')))), dom.tbody(Object.entries(evalStats).sort((a, b) => a[0] < b[0] ? -1 : 1).map(t => dom.tr(dom.td(dom.a(attr.href('#dmarc/evaluations/' + domainName(t[1].Domain)), domainString(t[1].Domain))), dom.td((t[1].Dispositions || []).join(' ')), dom.td(style({ textAlign: 'right' }), '' + t[1].Count), dom.td(style({ textAlign: 'right' }), t[1].SendReport ? '✓' : ''))), isEmpty(evalStats) ? dom.tr(dom.td(attr.colspan('3'), 'No evaluations.')) : [])), dom.br(), dom.br(), dom.h2('Suppressed reporting addresses'), dom.p('In practice, sending a DMARC report to a reporting address can cause DSN to be sent back. Such addresses can be added to a suppression list for a period, to reduce noise in the postmaster mailbox.'), dom.form(async function submit(e) {
		e.stopPropagation();
		e.preventDefault();
		await check(fieldset, client.DMARCSuppressAdd(reportingAddress.value, new Date(until.value), comment.value));
		window.location.reload(); // todo: add the address to the list, or only reload the list
	}, fieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), 'Reporting address', dom.br(), reportingAddress = dom.input(attr.required(''))), ' ', dom.label(style({ display: 'inline-block' }), 'Until', dom.br(), until = dom.input(attr.type('date'), attr.required(''), attr.value(nextmonth.getFullYear() + '-' + (1 + nextmonth.getMonth()) + '-' + nextmonth.getDate()))), ' ', dom.label(style({ display: 'inline-block' }), dom.span('Comment (optional)'), dom.br(), comment = dom.input()), ' ', dom.submitbutton('Add', attr.title('Outgoing reports to this reporting address will be suppressed until the end time.')))), dom.br(), dom.table(dom._class('hover'), dom.thead(dom.tr(dom.th('Reporting address'), dom.th('Until'), dom.th('Comment'), dom.th('Action'))), dom.tbody((suppressAddresses || []).length === 0 ? dom.tr(dom.td(attr.colspan('4'), 'No suppressed reporting addresses.')) : [], (suppressAddresses || []).map(ba => dom.tr(dom.td(prewrap(ba.ReportingAddress)), dom.td(ba.Until.toISOString()), dom.td(ba.Comment), dom.td(dom.clickbutton('Remove', async function click(e) {
		await check(e.target, client.DMARCSuppressRemove(ba.ID));
		window.location.reload(); // todo: only reload the list
	}), ' ', dom.clickbutton('Extend for 1 month', async function click(e) {
		await check(e.target, client.DMARCSuppressExtend(ba.ID, new Date(new Date().getTime() + 31 * 24 * 3600 * 1000)));
		window.location.reload(); // todo: only reload the list
	})))))));
};
const dmarcEvaluationsDomain = async (domain) => {
	const [d, evaluations] = await client.DMARCEvaluationsDomain(domain);
	let lastInterval = '';
	let lastAddresses = '';
	const formatPolicy = (e) => {
		const p = e.PolicyPublished;
		let s = '';
		const add = (k, v) => {
			if (v) {
				s += k + '=' + v + '; ';
			}
		};
		add('p', p.Policy);
		add('sp', p.SubdomainPolicy);
		add('adkim', p.ADKIM);
		add('aspf', p.ASPF);
		add('pct', '' + p.Percentage);
		add('fo', '' + p.ReportingOptions);
		return s;
	};
	let lastPolicy = '';
	const authStatus = (v) => inlineBox(v ? '' : yellow, v ? 'pass' : 'fail');
	const formatDKIMResults = (results) => results.map(r => dom.div('selector ' + r.Selector + (r.Domain !== domain ? ', domain ' + r.Domain : '') + ': ', inlineBox(r.Result === "pass" ? '' : yellow, r.Result)));
	const formatSPFResults = (alignedpass, results) => results.map(r => dom.div('' + r.Scope + (r.Domain !== domain ? ', domain ' + r.Domain : '') + ': ', inlineBox(r.Result === "pass" && alignedpass ? '' : yellow, r.Result)));
	const sourceIP = (ip) => {
		const r = dom.span(ip, attr.title('Click to do a reverse lookup of the IP.'), style({ cursor: 'pointer' }), async function click(e) {
			e.preventDefault();
			try {
				const rev = await client.LookupIP(ip);
				r.innerText = ip + '\n' + (rev.Hostnames || []).join('\n');
			}
			catch (err) {
				r.innerText = ip + '\nerror: ' + errmsg(err);
			}
		});
		return r;
	};
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('DMARC', '#dmarc'), crumblink('Evaluations', '#dmarc/evaluations'), 'Domain ' + domainString(d)), dom.div(dom.clickbutton('Remove evaluations', async function click(e) {
		await check(e.target, client.DMARCRemoveEvaluations(domain));
		window.location.reload(); // todo: only clear the table?
	})), dom.br(), dom.p('The evaluations below will be sent in a DMARC aggregate report to the addresses found in the published DMARC DNS record, which is fetched again before sending the report. The fields Interval hours, Addresses and Policy are only filled for the first row and whenever a new value in the published DMARC record is encountered.'), dom.table(dom._class('hover'), dom.thead(dom.tr(dom.th('ID'), dom.th('Evaluated'), dom.th('Optional', attr.title('Some evaluations will not cause a DMARC aggregate report to be sent. But if a report is sent, optional records are included.')), dom.th('Interval hours', attr.title('DMARC policies published by a domain can specify how often they would like to receive reports. The default is 24 hours, but can be as often as each hour. To keep reports comparable between different mail servers that send reports, reports are sent at rounded up intervals of whole hours that can divide a 24 hour day, and are aligned with the start of a day at UTC.')), dom.th('Addresses', attr.title('Addresses that will receive the report. An address can have a maximum report size configured. If there is no address, no report will be sent.')), dom.th('Policy', attr.title('Summary of the policy as encountered in the DMARC DNS record of the domain, and used for evaluation.')), dom.th('IP', attr.title('IP address of delivery attempt that was evaluated, relevant for SPF.')), dom.th('Disposition', attr.title('Our decision to accept/reject this message. It may be different than requested by the published policy. For example, when overriding due to delivery from a mailing list or forwarded address.')), dom.th('Aligned DKIM/SPF', attr.title('Whether DKIM and SPF had an aligned pass, where strict/relaxed alignment means whether the domain of an SPF pass and DKIM pass matches the exact domain (strict) or optionally a subdomain (relaxed). A DMARC pass requires at least one pass.')), dom.th('Envelope to', attr.title('Domain used in SMTP RCPT TO during delivery.')), dom.th('Envelope from', attr.title('Domain used in SMTP MAIL FROM during delivery.')), dom.th('Message from', attr.title('Domain in "From" message header.')), dom.th('DKIM details', attr.title('Results of verifying DKIM-Signature headers in message. Only signatures with matching organizational domain are included, regardless of strict/relaxed DKIM alignment in DMARC policy.')), dom.th('SPF details', attr.title('Results of SPF check used in DMARC evaluation. "mfrom" indicates the "SMTP MAIL FROM" domain was used, "helo" indicates the SMTP EHLO domain was used.')))), dom.tbody((evaluations || []).map(e => {
		const ival = e.IntervalHours + 'h';
		const interval = ival === lastInterval ? '' : ival;
		lastInterval = ival;
		const a = (e.Addresses || []).join('\n');
		const addresses = a === lastAddresses ? '' : a;
		lastAddresses = a;
		const p = formatPolicy(e);
		const policy = p === lastPolicy ? '' : p;
		lastPolicy = p;
		return dom.tr(dom.td('' + e.ID), dom.td(new Date(e.Evaluated).toUTCString()), dom.td(e.Optional ? 'Yes' : ''), dom.td(interval), dom.td(addresses), dom.td(policy), dom.td(sourceIP(e.SourceIP)), dom.td(inlineBox(e.Disposition === 'none' ? '' : red, e.Disposition), (e.OverrideReasons || []).length > 0 ? ' (' + (e.OverrideReasons || []).map(r => r.Type).join(', ') + ')' : ''), dom.td(authStatus(e.AlignedDKIMPass), '/', authStatus(e.AlignedSPFPass)), dom.td(e.EnvelopeTo), dom.td(e.EnvelopeFrom), dom.td(e.HeaderFrom), dom.td(formatDKIMResults(e.DKIMResults || [])), dom.td(formatSPFResults(e.AlignedSPFPass, e.SPFResults || [])));
	}), (evaluations || []).length === 0 ? dom.tr(dom.td(attr.colspan('14'), 'No evaluations.')) : [])));
};
const utcDate = (dt) => new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth(), dt.getUTCDate(), dt.getUTCHours(), dt.getUTCMinutes(), dt.getUTCSeconds()));
const utcDateStr = (dt) => [dt.getUTCFullYear(), 1 + dt.getUTCMonth(), dt.getUTCDate()].join('-');
const isDayChange = (dt) => utcDateStr(new Date(dt.getTime() - 2 * 60 * 1000)) !== utcDateStr(new Date(dt.getTime() + 2 * 60 * 1000));
const period = (start, end) => {
	const beginUTC = utcDate(start);
	const endUTC = utcDate(end);
	const beginDayChange = isDayChange(beginUTC);
	const endDayChange = isDayChange(endUTC);
	let beginstr = utcDateStr(beginUTC);
	let endstr = utcDateStr(endUTC);
	const title = attr.title('' + beginUTC.toISOString() + ' - ' + endUTC.toISOString());
	if (beginDayChange && endDayChange && Math.abs(beginUTC.getTime() - endUTC.getTime()) < 24 * (2 * 60 + 3600) * 1000) {
		return dom.span(beginstr, title);
	}
	const pad = (v) => v < 10 ? '0' + v : '' + v;
	if (!beginDayChange) {
		beginstr += ' ' + pad(beginUTC.getUTCHours()) + ':' + pad(beginUTC.getUTCMinutes());
	}
	if (!endDayChange) {
		endstr += ' ' + pad(endUTC.getUTCHours()) + ':' + pad(endUTC.getUTCMinutes());
	}
	return dom.span(beginstr + ' - ' + endstr, title);
};
const domainDMARC = async (d) => {
	const end = new Date();
	const start = new Date(new Date().getTime() - 30 * 24 * 3600 * 1000);
	const [reports, dnsdomain] = await Promise.all([
		client.DMARCReports(start, end, d),
		client.Domain(d),
	]);
	// todo future: table sorting? period selection (last day, 7 days, 1 month, 1 year, custom period)? collapse rows for a report? show totals per report? a simple bar graph to visualize messages and dmarc/dkim/spf fails? similar for TLSRPT.
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Domain ' + domainString(dnsdomain), '#domains/' + d), 'DMARC aggregate reports'), dom.p('DMARC reports are periodically sent by other mail servers that received an email message with a "From" header with our domain. Domains can have a DMARC DNS record that asks other mail servers to send these aggregate reports for analysis.'), dom.p('Below the DMARC aggregate reports for the past 30 days.'), (reports || []).length === 0 ? dom.div('No DMARC reports for domain.') :
		dom.table(dom._class('hover'), dom.thead(dom.tr(dom.th('ID'), dom.th('Organisation', attr.title('Organization that sent the DMARC report.')), dom.th('Period (UTC)', attr.title('Period this reporting period is about. Mail servers are recommended to stick to whole UTC days.')), dom.th('Policy', attr.title('The DMARC policy that the remote mail server had fetched and applied to the message. A policy that changed during the reporting period may result in unexpected policy evaluations.')), dom.th('Source IP', attr.title('Remote IP address of session at remote mail server.')), dom.th('Messages', attr.title('Total messages that the results apply to.')), dom.th('Result', attr.title('DMARC evaluation result.')), dom.th('ADKIM', attr.title('DKIM alignment. For a pass, one of the DKIM signatures that pass must be strict/relaxed-aligned with the domain, as specified by the policy.')), dom.th('ASPF', attr.title('SPF alignment. For a pass, the SPF policy must pass and be strict/relaxed-aligned with the domain, as specified by the policy.')), dom.th('SMTP to', attr.title('Domain of destination address, as specified during the SMTP session.')), dom.th('SMTP from', attr.title('Domain of originating address, as specified during the SMTP session.')), dom.th('Header from', attr.title('Domain of address in From-header of message.')), dom.th('Auth Results', attr.title('Details of DKIM and/or SPF authentication results. DMARC requires at least one aligned DKIM or SPF pass.')))), dom.tbody((reports || []).map(r => {
			const m = r.ReportMetadata;
			let policy = [];
			if (r.PolicyPublished.Domain !== d) {
				policy.push(r.PolicyPublished.Domain);
			}
			const alignments = { '': '', 'r': 'relaxed', 's': 'strict' };
			if (r.PolicyPublished.ADKIM !== '') {
				policy.push('dkim ' + (alignments[r.PolicyPublished.ADKIM] || ('invalid dkim alignment: ' + (r.PolicyPublished.ADKIM || '(missing)'))));
			}
			if (r.PolicyPublished.ASPF !== '') {
				policy.push('spf ' + (alignments[r.PolicyPublished.ASPF] || ('invalid spf alignment: ' + (r.PolicyPublished.ASPF || '(missing)'))));
			}
			if (r.PolicyPublished.Policy !== '') {
				policy.push('policy ' + r.PolicyPublished.Policy);
			}
			if (r.PolicyPublished.SubdomainPolicy !== '' && r.PolicyPublished.SubdomainPolicy !== r.PolicyPublished.Policy) {
				policy.push('subdomain ' + r.PolicyPublished.SubdomainPolicy);
			}
			if (r.PolicyPublished.Percentage !== 100) {
				policy.push('' + r.PolicyPublished.Percentage + '%');
			}
			const sourceIP = (ip) => {
				const r = dom.span(ip, attr.title('Click to do a reverse lookup of the IP.'), style({ cursor: 'pointer' }), async function click(e) {
					e.preventDefault();
					try {
						const rev = await client.LookupIP(ip);
						r.innerText = ip + '\n' + (rev.Hostnames || []).join('\n');
					}
					catch (err) {
						r.innerText = ip + '\nerror: ' + errmsg(err);
					}
				});
				return r;
			};
			let authResults = 0;
			for (const record of (r.Records || [])) {
				authResults += (record.AuthResults.DKIM || []).length;
				authResults += (record.AuthResults.SPF || []).length;
			}
			const reportRowspan = attr.rowspan('' + authResults);
			return (r.Records || []).map((record, recordIndex) => {
				const row = record.Row;
				const pol = row.PolicyEvaluated;
				const ids = record.Identifiers;
				const dkims = record.AuthResults.DKIM || [];
				const spfs = record.AuthResults.SPF || [];
				const recordRowspan = attr.rowspan('' + (dkims.length + spfs.length));
				const valignTop = style({ verticalAlign: 'top' });
				const dmarcStatuses = {
					'': '(missing)',
					none: 'DMARC checks or were not applied. This does not mean these messages are definitely not spam though, and they may have been rejected based on other checks, such as reputation or content-based filters.',
					quarantine: 'DMARC policy is to mark message as spam.',
					reject: 'DMARC policy is to reject the message during SMTP delivery.',
				};
				const rows = [];
				const addRow = (...last) => {
					const tr = dom.tr(recordIndex > 0 || rows.length > 0 ? [] : [
						dom.td(reportRowspan, valignTop, dom.a('' + r.ID, attr.href('#domains/' + d + '/dmarc/' + r.ID), attr.title('View raw report.'))),
						dom.td(reportRowspan, valignTop, m.OrgName, attr.title('Email: ' + m.Email + ', ReportID: ' + m.ReportID)),
						dom.td(reportRowspan, valignTop, period(new Date(m.DateRange.Begin * 1000), new Date(m.DateRange.End * 1000)), m.Errors && m.Errors.length ? dom.span('errors', attr.title(m.Errors.join('; '))) : []),
						dom.td(reportRowspan, valignTop, policy.join(', ')),
					], rows.length > 0 ? [] : [
						dom.td(recordRowspan, valignTop, sourceIP(row.SourceIP)),
						dom.td(recordRowspan, valignTop, '' + row.Count),
						dom.td(recordRowspan, valignTop, dom.span(pol.Disposition === 'none' ? 'none' : box(red, pol.Disposition), attr.title(pol.Disposition + ': ' + (dmarcStatuses[pol.Disposition] || '(invalid disposition)'))), (pol.Reasons || []).map(reason => [dom.br(), dom.span(reason.Type + (reason.Comment ? ' (' + reason.Comment + ')' : ''), attr.title('Policy was overridden by remote mail server for this reasons.'))])),
						dom.td(recordRowspan, valignTop, pol.DKIM === 'pass' ? 'pass' : box(yellow, dom.span(pol.DKIM, attr.title('No or no valid DKIM-signature is present that is "aligned" with the domain name.')))),
						dom.td(recordRowspan, valignTop, pol.SPF === 'pass' ? 'pass' : box(yellow, dom.span(pol.SPF, attr.title('No SPF policy was found, or IP is not allowed by policy, or domain name is not "aligned" with the domain name.')))),
						dom.td(recordRowspan, valignTop, ids.EnvelopeTo),
						dom.td(recordRowspan, valignTop, ids.EnvelopeFrom),
						dom.td(recordRowspan, valignTop, ids.HeaderFrom),
					], dom.td(last));
					rows.push(tr);
				};
				for (const dkim of dkims) {
					const statuses = {
						'': '(missing)',
						none: 'Message was not signed',
						pass: 'Message was signed and signature was verified.',
						fail: 'Message was signed, but signature was invalid.',
						policy: 'Message was signed, but signature is not accepted by policy.',
						neutral: 'Message was signed, but the signature contains an error or could not be processed. This status is also used for errors not covered by other statuses.',
						temperror: 'Message could not be verified. E.g. because of DNS resolve error. A later attempt may succeed. A missing DNS record is treated as temporary error, a new key may not have propagated through DNS shortly after it was taken into use.',
						permerror: 'Message cannot be verified. E.g. when a required header field is absent or for invalid (combination of) parameters. We typically set this if a DNS record does not allow the signature, e.g. due to algorithm mismatch or expiry.',
					};
					addRow('dkim: ', dom.span((dkim.Result === 'none' || dkim.Result === 'pass') ? dkim.Result : box(yellow, dkim.Result), attr.title((dkim.HumanResult ? 'additional information: ' + dkim.HumanResult + ';\n' : '') + dkim.Result + ': ' + (statuses[dkim.Result] || 'invalid status'))), !dkim.Selector ? [] : [
						', ',
						dom.span(dkim.Selector, attr.title('Selector, the DKIM record is at "<selector>._domainkey.<domain>".' + (dkim.Domain === d ? '' : ';\ndomain: ' + dkim.Domain))),
					]);
				}
				for (const spf of spfs) {
					const statuses = {
						'': '(missing)',
						none: 'No SPF policy found.',
						neutral: 'Policy states nothing about IP, typically due to "?" qualifier in SPF record.',
						pass: 'IP is authorized.',
						fail: 'IP is explicitly not authorized, due to "-" qualifier in SPF record.',
						softfail: 'Weak statement that IP is probably not authorized, "~" qualifier in SPF record.',
						temperror: 'Trying again later may succeed, e.g. for temporary DNS lookup error.',
						permerror: 'Error requiring some intervention to correct. E.g. invalid DNS record.',
					};
					addRow('spf: ', dom.span((spf.Result === 'none' || spf.Result === 'neutral' || spf.Result === 'pass') ? spf.Result : box(yellow, spf.Result), attr.title(spf.Result + ': ' + (statuses[spf.Result] || 'invalid status'))), ', ', dom.span(spf.Scope, attr.title('scopes:\nhelo: "SMTP HELO"\nmfrom: SMTP "MAIL FROM"')), ' ', dom.span(spf.Domain));
				}
				return rows;
			});
		}))));
};
const domainDMARCReport = async (d, reportID) => {
	const [report, dnsdomain] = await Promise.all([
		client.DMARCReportID(d, reportID),
		client.Domain(d),
	]);
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Domain ' + domainString(dnsdomain), '#domains/' + d), crumblink('DMARC aggregate reports', '#domains/' + d + '/dmarc'), 'Report ' + reportID), dom.p('Below is the raw report as received from the remote mail server.'), dom.div(dom._class('literal'), JSON.stringify(report, null, '\t')));
};
const tlsrptIndex = async () => {
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'TLSRPT'), dom.ul(dom.li(dom.a(attr.href('#tlsrpt/reports'), 'Reports'), ', incoming TLS reports.'), dom.li(dom.a(attr.href('#tlsrpt/results'), 'Results'), ', for outgoing TLS reports.')));
};
const tlsrptResults = async () => {
	const [results, suppressAddresses] = await Promise.all([
		client.TLSRPTResults(),
		client.TLSRPTSuppressList(),
	]);
	// todo: add a view where results are grouped by policy domain+dayutc. now each recipient domain gets a row.
	let fieldset;
	let reportingAddress;
	let until;
	let comment;
	const nextmonth = new Date(new Date().getTime() + 31 * 24 * 3600 * 1000);
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('TLSRPT', '#tlsrpt'), 'Results'), dom.p('Messages are delivered with SMTP with TLS using STARTTLS if supported and/or required by the recipient domain\'s mail server. TLS connections may fail for various reasons, such as mismatching certificate host name, expired certificates or TLS protocol version/cipher suite incompatibilities. Statistics about successful connections and failed connections are tracked. Results can be tracked for recipient domains (for MTA-STS policies), and per MX host (for DANE). A domain/host can publish a TLSRPT DNS record with addresses that should receive TLS reports. Reports are sent every 24 hours. Not all results are enough reason to send a report, but if a report is sent all results are included. By default, reports are only sent if a report contains a connection failure. Sending reports about all-successful connections can be configured. Reports sent to recipient domains include the results for its MX hosts, and reports for an MX host reference the recipient domains.'), dom.table(dom._class('hover'), dom.thead(dom.tr(dom.th('Day (UTC)', attr.title('Day covering these results, a whole day from 00:00 UTC to 24:00 UTC.')), dom.th('Recipient domain', attr.title('Domain of addressee. For delivery to a recipient, the recipient and policy domains will match for reporting on MTA-STS policies, but can also result in reports for hosts from the MX record of the recipient to report on DANE policies.')), dom.th('Policy domain', attr.title('Domain for TLSRPT policy, specifying URIs to which reports should be sent.')), dom.th('Host', attr.title('Whether policy domain is an (MX) host (for DANE), or a recipient domain (for MTA-STS).')), dom.th('Policies', attr.title('Policies found.')), dom.th('Success', attr.title('Total number of successful connections.')), dom.th('Failure', attr.title('Total number of failed connection attempts.')), dom.th('Failure details', attr.title('Total number of details about failures.')), dom.th('Send report', attr.title('Whether the current results may cause a report to be sent. To prevent report loops, reports are not sent for TLS connections used to deliver TLS or DMARC reports. Whether a report is eventually sent depends on more factors, such as whether the policy domain has a TLSRPT policy with reporting addresses, and whether TLS connection failures were registered (depending on configuration).')))), dom.tbody((results || []).sort((a, b) => {
		if (a.DayUTC !== b.DayUTC) {
			return a.DayUTC < b.DayUTC ? -1 : 1;
		}
		if (a.RecipientDomain !== b.RecipientDomain) {
			return a.RecipientDomain < b.RecipientDomain ? -1 : 1;
		}
		return a.PolicyDomain < b.PolicyDomain ? -1 : 1;
	}).map(r => {
		let success = 0;
		let failed = 0;
		let failureDetails = 0;
		(r.Results || []).forEach(result => {
			success += result.Summary.TotalSuccessfulSessionCount;
			failed += result.Summary.TotalFailureSessionCount;
			failureDetails += (result.FailureDetails || []).length;
		});
		const policyTypes = [];
		for (const result of (r.Results || [])) {
			const pt = result.Policy.Type;
			if (!policyTypes.includes(pt)) {
				policyTypes.push(pt);
			}
		}
		return dom.tr(dom.td(r.DayUTC), dom.td(r.RecipientDomain), dom.td(dom.a(attr.href('#tlsrpt/results/' + (r.RecipientDomain === r.PolicyDomain ? 'rcptdom/' : 'host/') + r.PolicyDomain), r.PolicyDomain)), dom.td(r.IsHost ? '✓' : ''), dom.td(policyTypes.join(', ')), dom.td(style({ textAlign: 'right' }), '' + success), dom.td(style({ textAlign: 'right' }), '' + failed), dom.td(style({ textAlign: 'right' }), '' + failureDetails), dom.td(style({ textAlign: 'right' }), r.SendReport ? '✓' : ''));
	}), (results || []).length === 0 ? dom.tr(dom.td(attr.colspan('9'), 'No results.')) : [])), dom.br(), dom.br(), dom.h2('Suppressed reporting addresses'), dom.p('In practice, sending a TLS report to a reporting address can cause DSN to be sent back. Such addresses can be added to a suppress list for a period, to reduce noise in the postmaster mailbox.'), dom.form(async function submit(e) {
		e.stopPropagation();
		e.preventDefault();
		await check(fieldset, client.TLSRPTSuppressAdd(reportingAddress.value, new Date(until.value), comment.value));
		window.location.reload(); // todo: add the address to the list, or only reload the list
	}, fieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), 'Reporting address', dom.br(), reportingAddress = dom.input(attr.required(''))), ' ', dom.label(style({ display: 'inline-block' }), 'Until', dom.br(), until = dom.input(attr.type('date'), attr.required(''), attr.value(nextmonth.getFullYear() + '-' + (1 + nextmonth.getMonth()) + '-' + nextmonth.getDate()))), ' ', dom.label(style({ display: 'inline-block' }), dom.span('Comment (optional)'), dom.br(), comment = dom.input()), ' ', dom.submitbutton('Add', attr.title('Outgoing reports to this reporting address will be suppressed until the end time.')))), dom.br(), dom.table(dom._class('hover'), dom.thead(dom.tr(dom.th('Reporting address'), dom.th('Until'), dom.th('Comment'), dom.th('Action'))), dom.tbody((suppressAddresses || []).length === 0 ? dom.tr(dom.td(attr.colspan('4'), 'No suppressed reporting addresses.')) : [], (suppressAddresses || []).map(ba => dom.tr(dom.td(prewrap(ba.ReportingAddress)), dom.td(ba.Until.toISOString()), dom.td(ba.Comment), dom.td(dom.clickbutton('Remove', async function click(e) {
		await check(e.target, client.TLSRPTSuppressRemove(ba.ID));
		window.location.reload(); // todo: only reload the list
	}), ' ', dom.clickbutton('Extend for 1 month', async function click(e) {
		await check(e.target, client.TLSRPTSuppressExtend(ba.ID, new Date(new Date().getTime() + 31 * 24 * 3600 * 1000)));
		window.location.reload(); // todo: only reload the list
	})))))));
};
const tlsrptResultsPolicyDomain = async (isrcptdom, domain) => {
	const [d, tlsresults] = await client.TLSRPTResultsDomain(isrcptdom, domain);
	const recordPromise = client.LookupTLSRPTRecord(domain);
	let recordBox;
	const root = dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('TLSRPT', '#tlsrpt'), crumblink('Results', '#tlsrpt/results'), (isrcptdom ? 'Recipient domain ' : 'Host ') + domainString(d)), dom.div(dom.clickbutton('Remove results', async function click(e) {
		e.preventDefault();
		await check(e.target, client.TLSRPTRemoveResults(isrcptdom, domain, ''));
		window.location.reload(); // todo: only clear the table?
	})), dom.br(), dom.div('Fetching TLSRPT DNS record...'), recordBox = dom.div(), dom.br(), dom.p('Below are the results per day and ' + (isrcptdom ? 'policy' : 'recipient') + ' domain that may be sent in a report.'), (tlsresults || []).map(tlsresult => [
		dom.h2(tlsresult.DayUTC, ' - ', dom.span(attr.title('Recipient domain, as used in SMTP MAIL TO, usually based on message To/Cc/Bcc.'), isrcptdom ? tlsresult.PolicyDomain : tlsresult.RecipientDomain)),
		dom.p('Send report (if TLSRPT policy exists and has address): ' + (tlsresult.SendReport ? 'Yes' : 'No'), dom.br(), 'Report about (MX) host (instead of recipient domain): ' + (tlsresult.IsHost ? 'Yes' : 'No')),
		dom.div(dom._class('literal'), JSON.stringify(tlsresult.Results, null, '\t')),
	]));
	(async () => {
		let txt = '';
		let error;
		try {
			let [_, xtxt, xerror] = await recordPromise;
			txt = xtxt;
			error = xerror;
		}
		catch (err) {
			error = 'error: ' + errmsg(err);
		}
		const l = [];
		if (txt) {
			l.push(dom.div(dom._class('literal'), txt));
		}
		if (error) {
			l.push(box(red, error));
		}
		dom._kids(recordBox, l);
	})();
	return root;
};
const tlsrptReports = async () => {
	const end = new Date();
	const start = new Date(new Date().getTime() - 30 * 24 * 3600 * 1000);
	const summaries = await client.TLSRPTSummaries(start, end, '');
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('TLSRPT', '#tlsrpt'), 'Reports'), dom.p('TLSRPT (TLS reporting) is a mechanism to request feedback from other mail servers about TLS connections to your mail server. If is typically used along with MTA-STS and/or DANE to enforce that SMTP connections are protected with TLS. Mail servers implementing TLSRPT will typically send a daily report with both successful and failed connection counts, including details about failures.'), renderTLSRPTSummaries(summaries || []));
};
const renderTLSRPTSummaries = (summaries) => {
	return [
		dom.p('Below a summary of TLS reports for the past 30 days.'),
		summaries.length === 0 ? dom.div(box(yellow, 'No domains with TLS reports.')) :
			dom.table(dom._class('hover'), dom.thead(dom.tr(dom.th('Policy domain', attr.title('Policy domain the report is about. The recipient domain for MTA-STS, the TLSA base domain for DANE.')), dom.th('Successes', attr.title('Number of successful SMTP STARTTLS sessions.')), dom.th('Failures', attr.title('Number of failed SMTP STARTTLS sessions.')), dom.th('Failure details', attr.title('Details about connection failures.')))), dom.tbody(summaries.map(r => dom.tr(dom.td(dom.a(attr.href('#tlsrpt/reports/' + domainName(r.PolicyDomain)), attr.title('See report details.'), domainName(r.PolicyDomain))), dom.td(style({ textAlign: 'right' }), '' + r.Success), dom.td(style({ textAlign: 'right' }), '' + r.Failure), dom.td(!r.ResultTypeCounts ? [] : Object.entries(r.ResultTypeCounts).map(kv => kv[0] + ': ' + kv[1]).join('; '))))))
	];
};
const domainTLSRPT = async (d) => {
	const end = new Date();
	const start = new Date(new Date().getTime() - 30 * 24 * 3600 * 1000);
	const [records, dnsdomain] = await Promise.all([
		client.TLSReports(start, end, d),
		client.ParseDomain(d),
	]);
	const policyType = (policy) => {
		let s = policy.Type;
		if (s === 'sts') {
			const mode = (policy.String || []).find(s => s.startsWith('mode:'));
			if (mode) {
				s += ': ' + mode.replace('mode:', '').trim();
			}
		}
		return s;
	};
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('TLSRPT', '#tlsrpt'), crumblink('Reports', '#tlsrpt/reports'), 'Domain ' + domainString(dnsdomain)), dom.p('TLSRPT (TLS reporting) is a mechanism to request feedback from other mail servers about TLS connections to your mail server. If is typically used along with MTA-STS and/or DANE to enforce that SMTP connections are protected with TLS. Mail servers implementing TLSRPT will typically send a daily report with both successful and failed connection counts, including details about failures.'), dom.p('Below the TLS reports for the past 30 days.'), (records || []).length === 0 ? dom.div('No TLS reports for domain.') :
		dom.table(dom._class('hover'), dom.thead(dom.tr(dom.th('Report', attr.colspan('3')), dom.th('Policy', attr.colspan('3')), dom.th('Failure Details', attr.colspan('8'))), dom.tr(dom.th('ID'), dom.th('From', attr.title('SMTP mail from from which we received the report.')), dom.th('Period (UTC)', attr.title('Period this reporting period is about. Mail servers are recommended to stick to whole UTC days.')), dom.th('Policy', attr.title('The policy applied, typically STSv1.')), dom.th('Successes', attr.title('Total number of successful TLS connections for policy.')), dom.th('Failures', attr.title('Total number of failed TLS connections for policy.')), dom.th('Result Type', attr.title('Type of failure.')), dom.th('Sending MTA', attr.title('IP of sending MTA.')), dom.th('Receiving MX Host'), dom.th('Receiving MX HELO'), dom.th('Receiving IP'), dom.th('Count', attr.title('Number of TLS connections that failed with these details.')), dom.th('More', attr.title('Optional additional information about the failure.')), dom.th('Code', attr.title('Optional API error code relating to the failure.')))), dom.tbody((records || []).map(record => {
			const r = record.Report;
			let nrows = 0;
			(r.Policies || []).forEach(pr => nrows += (pr.FailureDetails || []).length || 1);
			const reportRowSpan = attr.rowspan('' + nrows);
			const valignTop = style({ verticalAlign: 'top' });
			const alignRight = style({ textAlign: 'right' });
			return (r.Policies || []).map((result, index) => {
				const rows = [];
				const details = result.FailureDetails || [];
				const resultRowSpan = attr.rowspan('' + (details.length || 1));
				const addRow = (d, di) => {
					const row = dom.tr(index > 0 || rows.length > 0 ? [] : [
						dom.td(reportRowSpan, valignTop, dom.a('' + record.ID, attr.href('#tlsrpt/reports/' + record.Domain + '/' + record.ID))),
						dom.td(reportRowSpan, valignTop, r.OrganizationName || r.ContactInfo || record.MailFrom || '', attr.title('Organization: ' + r.OrganizationName + '; \nContact info: ' + r.ContactInfo + '; \nReport ID: ' + r.ReportID + '; \nMail from: ' + record.MailFrom)),
						dom.td(reportRowSpan, valignTop, period(r.DateRange.Start, r.DateRange.End)),
					], di > 0 ? [] : [
						dom.td(resultRowSpan, valignTop, policyType(result.Policy), attr.title((result.Policy.String || []).join('\n'))),
						dom.td(resultRowSpan, valignTop, alignRight, '' + result.Summary.TotalSuccessfulSessionCount),
						dom.td(resultRowSpan, valignTop, alignRight, '' + result.Summary.TotalFailureSessionCount),
					], !d ? dom.td(attr.colspan('8')) : [
						dom.td(d.ResultType),
						dom.td(d.SendingMTAIP),
						dom.td(d.ReceivingMXHostname),
						dom.td(d.ReceivingMXHelo),
						dom.td(d.ReceivingIP),
						dom.td(alignRight, '' + d.FailedSessionCount),
						dom.td(d.AdditionalInformation),
						dom.td(d.FailureReasonCode),
					]);
					rows.push(row);
				};
				let di = 0;
				for (const d of details) {
					addRow(d, di);
					di++;
				}
				if (details.length === 0) {
					addRow(undefined, 0);
				}
				return rows;
			});
		}))));
};
const domainTLSRPTID = async (d, reportID) => {
	const [report, dnsdomain] = await Promise.all([
		client.TLSReportID(d, reportID),
		client.ParseDomain(d),
	]);
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('TLSRPT', '#tlsrpt'), crumblink('Reports', '#tlsrpt/reports'), crumblink('Domain ' + domainString(dnsdomain), '#tlsrpt/reports/' + d + ''), 'Report ' + reportID), dom.p('Below is the raw report as received from the remote mail server.'), dom.div(dom._class('literal'), JSON.stringify(report, null, '\t')));
};
const mtasts = async () => {
	const policies = await client.MTASTSPolicies();
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'MTA-STS policies'), dom.p("MTA-STS is a mechanism allowing email domains to publish a policy for using SMTP STARTTLS and TLS verification. See ", link('https://www.rfc-editor.org/rfc/rfc8461.html', 'RFC 8461'), '.'), dom.p("The SMTP protocol is unencrypted by default, though the SMTP STARTTLS command is typically used to enable TLS on a connection. However, MTA's using STARTTLS typically do not validate the TLS certificate. An MTA-STS policy can specify that validation of host name, non-expiration and webpki trust is required."), makeMTASTSTable(policies || []));
};
const formatMTASTSMX = (mx) => {
	return mx.map(e => {
		return (e.Wildcard ? '*.' : '') + e.Domain.ASCII;
	}).join(', ');
};
const makeMTASTSTable = (items) => {
	if (items.length === 0) {
		return dom.div('No data');
	}
	// Elements: Field name in JSON, column name override, title for column name.
	const keys = [
		["LastUse", "", "Last time this policy was used."],
		["Domain", "Domain", "Domain this policy was retrieved from and this policy applies to."],
		["Backoff", "", "If true, a DNS record for MTA-STS exists, but a policy could not be fetched. This indicates a failure with MTA-STS."],
		["RecordID", "", "Unique ID for this policy. Each time a domain changes its policy, it must also change the record ID that is published in DNS to propagate the change."],
		["Version", "", "For valid MTA-STS policies, this must be 'STSv1'."],
		["Mode", "", "'enforce': TLS must be used and certificates must be validated; 'none': TLS and certificate validation is not required, typically only useful for removing once-used MTA-STS; 'testing': TLS should be used and certificated should be validated, but fallback to unverified TLS or plain text is allowed, but such cases must be reported"],
		["MX", "", "The MX hosts that are configured to do TLS. If TLS and validation is required, but an MX host is not on this list, delivery will not be attempted to that host."],
		["MaxAgeSeconds", "", "How long a policy can be cached and reused after it was fetched. Typically in the order of weeks."],
		["Extensions", "", "Free-form extensions in the MTA-STS policy."],
		["ValidEnd", "", "Until when this cached policy is valid, based on time the policy was fetched and the policy max age. Non-failure policies are automatically refreshed before they become invalid."],
		["LastUpdate", "", "Last time this policy was updated."],
		["Inserted", "", "Time when the policy was first inserted."],
	];
	const nowSecs = new Date().getTime() / 1000;
	return dom.table(dom._class('hover'), dom.thead(dom.tr(keys.map(kt => dom.th(dom.span(attr.title(kt[2]), kt[1] || kt[0]))))), dom.tbody(items.map(e => dom.tr([
		age(e.LastUse, false, nowSecs),
		e.Domain,
		e.Backoff,
		e.RecordID,
		e.Version,
		e.Mode,
		formatMTASTSMX(e.MX || []),
		e.MaxAgeSeconds,
		e.Extensions,
		age(e.ValidEnd, true, nowSecs),
		age(e.LastUpdate, false, nowSecs),
		age(e.Inserted, false, nowSecs),
	].map(v => dom.td(v === null ? [] : (v instanceof HTMLElement ? v : '' + v)))))));
};
const dnsbl = async () => {
	const [ipZoneResults, usingZones, monitorZones] = await client.DNSBLStatus();
	const url = (ip) => 'https://multirbl.valli.org/lookup/' + encodeURIComponent(ip) + '.html';
	let fieldset;
	let monitorTextarea;
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'DNS blocklist status for IPs'), dom.p('Follow the external links to a third party DNSBL checker to see if the IP is on one of the many blocklist.'), dom.ul(Object.entries(ipZoneResults).sort().map(ipZones => {
		const [ip, zoneResults] = ipZones;
		return dom.li(link(url(ip), ip), !ipZones.length ? [] : dom.ul(Object.entries(zoneResults).sort().map(zoneResult => dom.li(zoneResult[0] + ': ', zoneResult[1] === 'pass' ? 'pass' : box(red, zoneResult[1])))));
	})), !Object.entries(ipZoneResults).length ? box(red, 'No IPs found.') : [], dom.br(), dom.h2('DNSBL zones checked due to being used for incoming deliveries'), (usingZones || []).length === 0 ?
		dom.div('None') :
		dom.ul((usingZones || []).map(zone => dom.li(domainString(zone)))), dom.br(), dom.h2('DNSBL zones to monitor only'), dom.form(async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		await check(fieldset, client.MonitorDNSBLsSave(monitorTextarea.value));
		dnsbl(); // Render page again.
	}, fieldset = dom.fieldset(dom.div('One per line'), dom.div(style({ marginBottom: '.5ex' }), monitorTextarea = dom.textarea(style({ width: '20rem' }), attr.rows('' + Math.max(5, 1 + (monitorZones || []).length)), new String((monitorZones || []).map(zone => domainName(zone)).join('\n'))), dom.div('Examples: sbl.spamhaus.org or bl.spamcop.net')), dom.div(dom.submitbutton('Save')))));
};
const queueList = async () => {
	let filter = { Max: parseInt(localStorageGet('adminpaginationsize') || '') || 100, IDs: [], Account: '', From: '', To: '', Hold: null, Submitted: '', NextAttempt: '', Transport: null };
	let sort = { Field: "NextAttempt", LastID: 0, Last: null, Asc: true };
	let [holdRules, msgs0, transports] = await Promise.all([
		client.QueueHoldRuleList(),
		client.QueueList(filter, sort),
		client.Transports(),
	]);
	let msgs = msgs0 || [];
	// todo: more sorting
	// todo: after making changes, don't reload entire page. probably best to fetch messages by id and rerender. also report on which messages weren't affected (e.g. no longer in queue).
	// todo: display which transport will be used for a message according to routing rules (in case none is explicitly configured).
	// todo: live updates with SSE connections
	// todo: keep updating times/age.
	// todo: reuse this code in webaccount to show users their own message queue, and give (more limited) options to fail/reschedule deliveries.
	const nowSecs = new Date().getTime() / 1000;
	let holdRuleAccount;
	let holdRuleSenderDomain;
	let holdRuleRecipientDomain;
	let holdRuleSubmit;
	let sortElem;
	let filterForm;
	let filterAccount;
	let filterFrom;
	let filterTo;
	let filterSubmitted;
	let filterHold;
	let filterNextAttempt;
	let filterTransport;
	let requiretlsFieldset;
	let requiretls;
	let transport;
	// Message ID to checkbox.
	let toggles = new Map();
	// We operate on what the user has selected, not what the filters would currently
	// evaluate to. This function can throw an error, which is why we have awkward
	// syntax when calling this as parameter in api client calls below.
	const gatherIDs = () => {
		const f = {
			Max: 0,
			IDs: Array.from(toggles.entries()).filter(t => t[1].checked).map(t => t[0]),
			Account: '',
			From: '',
			To: '',
			Hold: null,
			Submitted: '',
			NextAttempt: '',
			Transport: null,
		};
		// Don't want to accidentally operate on all messages.
		if ((f.IDs || []).length === 0) {
			throw new Error('No messages selected.');
		}
		return f;
	};
	const popupDetails = (m) => {
		const nowSecs = new Date().getTime() / 1000;
		popup(dom.h1('Details'), dom.table(dom.tr(dom.td('Message subject'), dom.td(m.Subject))), dom.br(), dom.h2('Results'), dom.table(dom.thead(dom.tr(dom.th('Start'), dom.th('Duration'), dom.th('Success'), dom.th('Code'), dom.th('Secode'), dom.th('Error'))), dom.tbody((m.Results || []).length === 0 ? dom.tr(dom.td(attr.colspan('6'), 'No results.')) : [], (m.Results || []).map(r => dom.tr(dom.td(age(r.Start, false, nowSecs)), dom.td(Math.round(r.Duration / 1000000) + 'ms'), dom.td(r.Success ? '✓' : ''), dom.td('' + (r.Code || '')), dom.td(r.Secode), dom.td(r.Error))))));
	};
	let tbody = dom.tbody();
	const render = () => {
		toggles = new Map();
		for (const m of msgs) {
			toggles.set(m.ID, dom.input(attr.type('checkbox'), msgs.length === 1 ? attr.checked('') : []));
		}
		const ntbody = dom.tbody(dom._class('loadend'), msgs.length === 0 ? dom.tr(dom.td(attr.colspan('15'), 'No messages.')) : [], msgs.map(m => {
			return dom.tr(dom.td(toggles.get(m.ID)), dom.td('' + m.ID + (m.BaseID > 0 ? '/' + m.BaseID : '')), dom.td(age(new Date(m.Queued), false, nowSecs)), dom.td(m.SenderAccount || '-'), dom.td(prewrap(m.SenderLocalpart, "@", ipdomainString(m.SenderDomain))), // todo: escaping of localpart
			dom.td(prewrap(m.RecipientLocalpart, "@", ipdomainString(m.RecipientDomain))), // todo: escaping of localpart
			dom.td(formatSize(m.Size)), dom.td('' + m.Attempts), dom.td(m.Hold ? 'Hold' : ''), dom.td(age(new Date(m.NextAttempt), true, nowSecs)), dom.td(m.LastAttempt ? age(new Date(m.LastAttempt), false, nowSecs) : '-'), dom.td(m.Results && m.Results.length > 0 ? m.Results[m.Results.length - 1].Error : []), dom.td(m.Transport || '(default)'), dom.td(m.RequireTLS === true ? 'Yes' : (m.RequireTLS === false ? 'No' : '')), dom.td(dom.clickbutton('Details', function click() {
				popupDetails(m);
			})));
		}));
		tbody.replaceWith(ntbody);
		tbody = ntbody;
	};
	render();
	const buttonNextAttemptSet = (text, minutes) => dom.clickbutton(text, async function click(e) {
		// note: awkward client call because gatherIDs() can throw an exception.
		const n = await check(e.target, (async () => await client.QueueNextAttemptSet(gatherIDs(), minutes))());
		window.alert('' + n + ' message(s) updated');
		window.location.reload(); // todo: reload less
	});
	const buttonNextAttemptAdd = (text, minutes) => dom.clickbutton(text, async function click(e) {
		const n = await check(e.target, (async () => await client.QueueNextAttemptAdd(gatherIDs(), minutes))());
		window.alert('' + n + ' message(s) updated');
		window.location.reload(); // todo: reload less
	});
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'Queue'), dom.p(dom.a(attr.href('#queue/retired'), 'Retired messages')), dom.h2('Hold rules', attr.title('Messages submitted to the queue that match a hold rule are automatically marked as "on hold", preventing delivery until explicitly taken off hold again.')), dom.form(attr.id('holdRuleForm'), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		const pr = {
			ID: 0,
			Account: holdRuleAccount.value,
			SenderDomainStr: holdRuleSenderDomain.value,
			RecipientDomainStr: holdRuleRecipientDomain.value,
			// Filled in by backend, we provide dummy values.
			SenderDomain: { ASCII: '', Unicode: '' },
			RecipientDomain: { ASCII: '', Unicode: '' },
		};
		await check(holdRuleSubmit, client.QueueHoldRuleAdd(pr));
		window.location.reload(); // todo: reload less
	}), (function () {
		// We don't show the full form until asked. Too much visual clutter.
		let show = (holdRules || []).length > 0;
		const box = dom.div();
		const renderHoldRules = () => {
			dom._kids(box, !show ?
				dom.div('No hold rules. ', dom.clickbutton('Add', function click() {
					show = true;
					renderHoldRules();
				})) : [
				dom.p('Newly submitted messages matching a hold rule will be marked as "on hold" and not be delivered until further action by the admin. To create a rule matching all messages, leave all fields empty.'),
				dom.table(dom.thead(dom.tr(dom.th('Account'), dom.th('Sender domain'), dom.th('Recipient domain'), dom.th('Action'))), dom.tbody((holdRules || []).length === 0 ? dom.tr(dom.td(attr.colspan('4'), 'No hold rules.')) : [], (holdRules || []).map(pr => dom.tr(!pr.Account && !pr.SenderDomainStr && !pr.RecipientDomainStr ?
					dom.td(attr.colspan('3'), '(Match all messages)') : [
					dom.td(pr.Account),
					dom.td(domainString(pr.SenderDomain)),
					dom.td(domainString(pr.RecipientDomain)),
				], dom.td(dom.clickbutton('Remove', attr.title('Removing a hold rule does not modify the "on hold" status of messages in the queue.'), async function click(e) {
					await check(e.target, client.QueueHoldRuleRemove(pr.ID));
					window.location.reload(); // todo: reload less
				})))), dom.tr(dom.td(holdRuleAccount = dom.input(attr.form('holdRuleForm'))), dom.td(holdRuleSenderDomain = dom.input(attr.form('holdRuleForm'))), dom.td(holdRuleRecipientDomain = dom.input(attr.form('holdRuleForm'))), dom.td(holdRuleSubmit = dom.submitbutton('Add hold rule', attr.form('holdRuleForm'), attr.title('When adding a new hold rule, existing messages in queue matching the new rule will be marked as on hold.'))))))
			]);
		};
		renderHoldRules();
		return box;
	})(), dom.br(), 
	// Filtering.
	filterForm = dom.form(attr.id('queuefilter'), // Referenced by input elements in table row.
	async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		filter = {
			Max: filter.Max,
			IDs: [],
			Account: filterAccount.value,
			From: filterFrom.value,
			To: filterTo.value,
			Hold: filterHold.value === 'Yes' ? true : (filterHold.value === 'No' ? false : null),
			Submitted: filterSubmitted.value,
			NextAttempt: filterNextAttempt.value,
			Transport: !filterTransport.value ? null : (filterTransport.value === '(default)' ? '' : filterTransport.value),
		};
		sort = {
			Field: sortElem.value.startsWith('nextattempt') ? 'NextAttempt' : 'Queued',
			LastID: 0,
			Last: null,
			Asc: sortElem.value.endsWith('asc'),
		};
		tbody.classList.add('loadstart');
		msgs = await check({ disabled: false }, client.QueueList(filter, sort)) || [];
		render();
	}), dom.h2('Messages'), dom.table(dom._class('hover'), style({ width: '100%' }), dom.thead(dom.tr(dom.td(attr.colspan('2'), 'Filter'), dom.td(filterSubmitted = dom.input(attr.form('queuefilter'), style({ width: '7em' }), attr.title('Example: "<-1h" for filtering messages submitted more than 1 hour ago.'))), dom.td(filterAccount = dom.input(attr.form('queuefilter'))), dom.td(filterFrom = dom.input(attr.form('queuefilter')), attr.title('Example: "@sender.example" to filter by domain of sender.')), dom.td(filterTo = dom.input(attr.form('queuefilter')), attr.title('Example: "@recipient.example" to filter by domain of recipient.')), dom.td(), // todo: add filter by size?
	dom.td(), // todo: add filter by attempts?
	dom.td(filterHold = dom.select(attr.form('queuefilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option('', attr.value('')), dom.option('Yes'), dom.option('No'))), dom.td(filterNextAttempt = dom.input(attr.form('queuefilter'), style({ width: '7em' }), attr.title('Example: ">1h" for filtering messages to be delivered in more than 1 hour, or "<now" for messages to be delivered as soon as possible.'))), dom.td(), dom.td(), dom.td(filterTransport = dom.select(Object.keys(transports || {}).length === 0 ? style({ display: 'none' }) : [], attr.form('queuefilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option(''), dom.option('(default)'), Object.keys(transports || {}).sort().map(t => dom.option(t)))), dom.td(attr.colspan('2'), style({ textAlign: 'right' }), // Less content shifting while rendering.
	'Sort ', sortElem = dom.select(attr.form('queuefilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option('Next attempt ↑', attr.value('nextattempt-asc')), dom.option('Next attempt ↓', attr.value('nextattempt-desc')), dom.option('Submitted ↑', attr.value('submitted-asc')), dom.option('Submitted ↓', attr.value('submitted-desc'))), ' ', dom.submitbutton('Apply', attr.form('queuefilter')), ' ', dom.clickbutton('Reset', attr.form('queuefilter'), function click() {
		filterForm.reset();
		filterForm.requestSubmit();
	}))), dom.tr(dom.td(dom.input(attr.type('checkbox'), msgs.length === 1 ? attr.checked('') : [], attr.form('queuefilter'), function change(e) {
		const elem = e.target;
		for (const [_, toggle] of toggles) {
			toggle.checked = elem.checked;
		}
	})), dom.th('ID'), dom.th('Submitted'), dom.th('Account'), dom.th('From'), dom.th('To'), dom.th('Size'), dom.th('Attempts'), dom.th('Hold'), dom.th('Next attempt'), dom.th('Last attempt'), dom.th('Last error'), dom.th('Transport'), dom.th('Require TLS'), dom.th('Actions'))), tbody, dom.tfoot(dom.tr(dom.td(attr.colspan('15'), 
	// todo: consider implementing infinite scroll, autoloading more pages. means the operations on selected messages should be moved from below to above the table. and probably only show them when at least one message is selected to prevent clutter.
	dom.clickbutton('Load more', attr.title('Try to load more entries. You can still try to load more entries when at the end of the list, new entries may have been appended since the previous call.'), async function click(e) {
		if (msgs.length === 0) {
			sort.LastID = 0;
			sort.Last = null;
		}
		else {
			const lm = msgs[msgs.length - 1];
			sort.LastID = lm.ID;
			if (sort.Field === "Queued") {
				sort.Last = lm.Queued;
			}
			else {
				sort.Last = lm.NextAttempt;
			}
		}
		tbody.classList.add('loadstart');
		const l = await check(e.target, client.QueueList(filter, sort)) || [];
		msgs.push(...l);
		render();
	}))))), dom.br(), dom.br(), dom.div(dom._class('unclutter'), dom.h2('Change selected messages'), dom.div(style({ display: 'flex', gap: '2em' }), dom.div(dom.div('Hold'), dom.div(dom.clickbutton('On', async function click(e) {
		const n = await check(e.target, (async () => await client.QueueHoldSet(gatherIDs(), true))());
		window.alert('' + n + ' message(s) updated');
		window.location.reload(); // todo: reload less
	}), ' ', dom.clickbutton('Off', async function click(e) {
		const n = await check(e.target, (async () => await client.QueueHoldSet(gatherIDs(), false))());
		window.alert('' + n + ' message(s) updated');
		window.location.reload(); // todo: reload less
	}))), dom.div(dom.div('Schedule next delivery attempt'), buttonNextAttemptSet('Now', 0), ' ', dom.clickbutton('More...', function click(e) {
		e.target.replaceWith(dom.div(dom.br(), dom.div('Scheduled time plus'), dom.div(buttonNextAttemptAdd('1m', 1), ' ', buttonNextAttemptAdd('5m', 5), ' ', buttonNextAttemptAdd('30m', 30), ' ', buttonNextAttemptAdd('1h', 60), ' ', buttonNextAttemptAdd('2h', 2 * 60), ' ', buttonNextAttemptAdd('4h', 4 * 60), ' ', buttonNextAttemptAdd('8h', 8 * 60), ' ', buttonNextAttemptAdd('16h', 16 * 60), ' '), dom.br(), dom.div('Now plus'), dom.div(buttonNextAttemptSet('1m', 1), ' ', buttonNextAttemptSet('5m', 5), ' ', buttonNextAttemptSet('30m', 30), ' ', buttonNextAttemptSet('1h', 60), ' ', buttonNextAttemptSet('2h', 2 * 60), ' ', buttonNextAttemptSet('4h', 4 * 60), ' ', buttonNextAttemptSet('8h', 8 * 60), ' ', buttonNextAttemptSet('16h', 16 * 60), ' ')));
	})), dom.div(dom.form(dom.label('Require TLS'), requiretlsFieldset = dom.fieldset(requiretls = dom.select(attr.title('How to use TLS for message delivery over SMTP:\n\nDefault: Delivery attempts follow the policies published by the recipient domain: Verification with MTA-STS and/or DANE, or optional opportunistic unverified STARTTLS if the domain does not specify a policy.\n\nWith RequireTLS: For sensitive messages, you may want to require verified TLS. The recipient destination domain SMTP server must support the REQUIRETLS SMTP extension for delivery to succeed. It is automatically chosen when the destination domain mail servers of all recipients are known to support it.\n\nFallback to insecure: If delivery fails due to MTA-STS and/or DANE policies specified by the recipient domain, and the content is not sensitive, you may choose to ignore the recipient domain TLS policies so delivery can succeed.'), dom.option('Default', attr.value('')), dom.option('With RequireTLS', attr.value('yes')), dom.option('Fallback to insecure', attr.value('no'))), ' ', dom.submitbutton('Change')), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		const n = await check(requiretlsFieldset, (async () => await client.QueueRequireTLSSet(gatherIDs(), requiretls.value === '' ? null : requiretls.value === 'yes'))());
		window.alert('' + n + ' message(s) updated');
		window.location.reload(); // todo: only refresh the list
	})), dom.div(dom.form(dom.label('Transport'), dom.fieldset(transport = dom.select(attr.title('Transport to use for delivery attempts. The default is direct delivery, connecting to the MX hosts of the domain.'), dom.option('(default)', attr.value('')), Object.keys(transports || []).sort().map(t => dom.option(t))), ' ', dom.submitbutton('Change')), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		const n = await check(e.target, (async () => await client.QueueTransportSet(gatherIDs(), transport.value))());
		window.alert('' + n + ' message(s) updated');
		window.location.reload(); // todo: only refresh the list
	})), dom.div(dom.div('Delivery'), dom.clickbutton('Fail delivery', attr.title('Cause delivery to fail, sending a DSN to the sender.'), async function click(e) {
		e.preventDefault();
		if (!window.confirm('Are you sure you want to fail delivery for the selected message(s)? Notifications of delivery failure will be sent (DSNs).')) {
			return;
		}
		const n = await check(e.target, (async () => await client.QueueFail(gatherIDs()))());
		window.alert('' + n + ' message(s) updated');
		window.location.reload(); // todo: only refresh the list
	})), dom.div(dom.div('Messages'), dom.clickbutton('Remove', attr.title('Completely remove messages from queue, not sending a DSN.'), async function click(e) {
		e.preventDefault();
		if (!window.confirm('Are you sure you want to fail delivery for the selected message(s)? It will be removed completely, no DSN about failure to deliver will be sent.')) {
			return;
		}
		const n = await check(e.target, (async () => await client.QueueDrop(gatherIDs()))());
		window.alert('' + n + ' message(s) updated');
		window.location.reload(); // todo: only refresh the list
	})))));
};
const retiredList = async () => {
	let filter = { Max: parseInt(localStorageGet('adminpaginationsize') || '') || 100, IDs: [], Account: '', From: '', To: '', Submitted: '', LastActivity: '', Transport: null };
	let sort = { Field: "LastActivity", LastID: 0, Last: null, Asc: false };
	const [retired0, transports0] = await Promise.all([
		client.RetiredList(filter, sort),
		client.Transports(),
	]);
	let retired = retired0 || [];
	let transports = transports0 || {};
	const nowSecs = new Date().getTime() / 1000;
	let sortElem;
	let filterForm;
	let filterAccount;
	let filterFrom;
	let filterTo;
	let filterSubmitted;
	let filterLastActivity;
	let filterTransport;
	let filterSuccess;
	const popupDetails = (m) => {
		const nowSecs = new Date().getTime() / 1000;
		popup(dom.h1('Details'), dom.table(dom.tr(dom.td('Message subject'), dom.td(m.Subject))), dom.br(), dom.h2('Results'), dom.table(dom.thead(dom.tr(dom.th('Start'), dom.th('Duration'), dom.th('Success'), dom.th('Code'), dom.th('Secode'), dom.th('Error'))), dom.tbody((m.Results || []).length === 0 ? dom.tr(dom.td(attr.colspan('6'), 'No results.')) : [], (m.Results || []).map(r => dom.tr(dom.td(age(r.Start, false, nowSecs)), dom.td(Math.round(r.Duration / 1000000) + 'ms'), dom.td(r.Success ? '✓' : ''), dom.td('' + (r.Code || '')), dom.td(r.Secode), dom.td(r.Error))))));
	};
	let tbody = dom.tbody();
	const render = () => {
		const ntbody = dom.tbody(dom._class('loadend'), retired.length === 0 ? dom.tr(dom.td(attr.colspan('14'), 'No retired messages.')) : [], retired.map(m => dom.tr(dom.td('' + m.ID + (m.BaseID > 0 ? '/' + m.BaseID : '')), dom.td(m.Success ? '✓' : ''), dom.td(age(new Date(m.LastActivity), false, nowSecs)), dom.td(age(new Date(m.Queued), false, nowSecs)), dom.td(m.SenderAccount || '-'), dom.td(prewrap(m.SenderLocalpart, "@", m.SenderDomainStr)), // todo: escaping of localpart
		dom.td(prewrap(m.RecipientLocalpart, "@", m.RecipientDomainStr)), // todo: escaping of localpart
		dom.td(formatSize(m.Size)), dom.td('' + m.Attempts), dom.td(m.LastAttempt ? age(new Date(m.LastAttempt), false, nowSecs) : '-'), dom.td(m.Results && m.Results.length > 0 ? m.Results[m.Results.length - 1].Error : []), dom.td(m.Transport || ''), dom.td(m.RequireTLS === true ? 'Yes' : (m.RequireTLS === false ? 'No' : '')), dom.td(dom.clickbutton('Details', function click() {
			popupDetails(m);
		})))));
		tbody.replaceWith(ntbody);
		tbody = ntbody;
	};
	render();
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Queue', '#queue'), 'Retired messages'), 
	// Filtering.
	filterForm = dom.form(attr.id('queuefilter'), // Referenced by input elements in table row.
	async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		filter = {
			Max: filter.Max,
			IDs: [],
			Account: filterAccount.value,
			From: filterFrom.value,
			To: filterTo.value,
			Submitted: filterSubmitted.value,
			LastActivity: filterLastActivity.value,
			Transport: !filterTransport.value ? null : (filterTransport.value === '(default)' ? '' : filterTransport.value),
			Success: filterSuccess.value === '' ? null : (filterSuccess.value === 'Yes' ? true : false),
		};
		sort = {
			Field: sortElem.value.startsWith('lastactivity') ? 'LastActivity' : 'Queued',
			LastID: 0,
			Last: null,
			Asc: sortElem.value.endsWith('asc'),
		};
		tbody.classList.add('loadstart');
		retired = await check({ disabled: false }, client.RetiredList(filter, sort)) || [];
		render();
	}), dom.h2('Retired messages'), dom.p('Meta information about queued messages may be kept after successful and/or failed delivery, configurable per account.'), dom.table(dom._class('hover'), style({ width: '100%' }), dom.thead(dom.tr(dom.td('Filter'), dom.td(filterSuccess = dom.select(attr.form('queuefilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option(''), dom.option('Yes'), dom.option('No'))), dom.td(filterLastActivity = dom.input(attr.form('queuefilter'), style({ width: '7em' }), attr.title('Example: ">-1h" for filtering messages with last activity less than 1 hour ago.'))), dom.td(filterSubmitted = dom.input(attr.form('queuefilter'), style({ width: '7em' }), attr.title('Example: "<-1h" for filtering messages submitted more than 1 hour ago.'))), dom.td(filterAccount = dom.input(attr.form('queuefilter'))), dom.td(filterFrom = dom.input(attr.form('queuefilter')), attr.title('Example: "@sender.example" to filter by domain of sender.')), dom.td(filterTo = dom.input(attr.form('queuefilter')), attr.title('Example: "@recipient.example" to filter by domain of recipient.')), dom.td(), // todo: add filter by size?
	dom.td(), // todo: add filter by attempts?
	dom.td(), dom.td(), dom.td(filterTransport = dom.select(Object.keys(transports).length === 0 ? style({ display: 'none' }) : [], attr.form('queuefilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option(''), dom.option('(default)'), Object.keys(transports).sort().map(t => dom.option(t)))), dom.td(attr.colspan('2'), style({ textAlign: 'right' }), // Less content shifting while rendering.
	'Sort ', sortElem = dom.select(attr.form('queuefilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option('Last activity ↓', attr.value('lastactivity-desc')), dom.option('Last activity ↑', attr.value('lastactivity-asc')), dom.option('Submitted ↓', attr.value('submitted-desc')), dom.option('Submitted ↑', attr.value('submitted-asc'))), ' ', dom.submitbutton('Apply', attr.form('queuefilter')), ' ', dom.clickbutton('Reset', attr.form('queuefilter'), function click() {
		filterForm.reset();
		filterForm.requestSubmit();
	}))), dom.tr(dom.th('ID'), dom.th('Success'), dom.th('Last activity'), dom.th('Submitted'), dom.th('Account'), dom.th('From'), dom.th('To'), dom.th('Size'), dom.th('Attempts'), dom.th('Last attempt'), dom.th('Last error'), dom.th('Require TLS'), dom.th('Transport'), dom.th('Actions'))), tbody, dom.tfoot(dom.tr(dom.td(attr.colspan('14'), dom.clickbutton('Load more', attr.title('Try to load more entries. You can still try to load more entries when at the end of the list, new entries may have been appended since the previous call.'), async function click(e) {
		if (retired.length === 0) {
			sort.LastID = 0;
			sort.Last = null;
		}
		else {
			const lm = retired[retired.length - 1];
			sort.LastID = lm.ID;
			if (sort.Field === "Queued") {
				sort.Last = lm.Queued;
			}
			else {
				sort.Last = lm.LastActivity;
			}
		}
		tbody.classList.add('loadstart');
		const l = await check(e.target, client.RetiredList(filter, sort)) || [];
		retired.push(...l);
		render();
	}))))));
};
const formatExtra = (extra) => {
	if (!extra) {
		return '';
	}
	return Object.entries(extra).sort((a, b) => a[0] < b[0] ? -1 : 1).map(t => t[0] + ': ' + t[1]).join('; ');
};
const hooksList = async () => {
	let filter = { Max: parseInt(localStorageGet('adminpaginationsize') || '') || 100, IDs: [], Account: '', Submitted: '', NextAttempt: '', Event: '' };
	let sort = { Field: "NextAttempt", LastID: 0, Last: null, Asc: true };
	let hooks = await client.HookList(filter, sort) || [];
	const nowSecs = new Date().getTime() / 1000;
	let sortElem;
	let filterForm;
	let filterSubmitted;
	let filterAccount;
	let filterEvent;
	let filterNextAttempt;
	// Hook ID to checkbox.
	let toggles = new Map();
	// We operate on what the user has selected, not what the filters would currently
	// evaluate to. This function can throw an error, which is why we have awkward
	// syntax when calling this as parameter in api client calls below.
	const gatherIDs = () => {
		const f = {
			Max: 0,
			IDs: Array.from(toggles.entries()).filter(t => t[1].checked).map(t => t[0]),
			Account: '',
			Event: '',
			Submitted: '',
			NextAttempt: '',
		};
		// Don't want to accidentally operate on all messages.
		if ((f.IDs || []).length === 0) {
			throw new Error('No hooks selected.');
		}
		return f;
	};
	const popupDetails = (h) => {
		const nowSecs = new Date().getTime() / 1000;
		popup(dom.h1('Details'), dom.div(dom._class('twocols'), dom.div(dom.table(dom.tr(dom.td('Message subject'), dom.td(h.Subject))), dom.br(), dom.h2('Results'), dom.table(dom.thead(dom.tr(dom.th('Start'), dom.th('Duration'), dom.th('Success'), dom.th('Code'), dom.th('Error'), dom.th('URL'), dom.th('Response'))), dom.tbody((h.Results || []).length === 0 ? dom.tr(dom.td(attr.colspan('7'), 'No results.')) : [], (h.Results || []).map(r => dom.tr(dom.td(age(r.Start, false, nowSecs)), dom.td(Math.round(r.Duration / 1000000) + 'ms'), dom.td(r.Success ? '✓' : ''), dom.td('' + (r.Code || '')), dom.td(r.Error), dom.td(r.URL), dom.td(r.Response))))), dom.br()), dom.div(dom.h2('Webhook JSON body'), dom.pre(dom._class('literal'), JSON.stringify(JSON.parse(h.Payload), undefined, '\t')))));
	};
	let tbody = dom.tbody();
	const render = () => {
		toggles = new Map();
		for (const h of (hooks || [])) {
			toggles.set(h.ID, dom.input(attr.type('checkbox'), (hooks || []).length === 1 ? attr.checked('') : []));
		}
		const ntbody = dom.tbody(dom._class('loadend'), hooks.length === 0 ? dom.tr(dom.td(attr.colspan('15'), 'No webhooks.')) : [], hooks.map(h => dom.tr(dom.td(toggles.get(h.ID)), dom.td('' + h.ID), dom.td(age(new Date(h.Submitted), false, nowSecs)), dom.td('' + (h.QueueMsgID || '')), // todo future: make it easy to open the corresponding (retired) message from queue (if still around).
		dom.td('' + h.FromID), dom.td('' + h.MessageID), dom.td(h.Account || '-'), dom.td(h.IsIncoming ? "incoming" : h.OutgoingEvent), dom.td(formatExtra(h.Extra)), dom.td('' + h.Attempts), dom.td(age(h.NextAttempt, true, nowSecs)), dom.td(h.Results && h.Results.length > 0 ? age(h.Results[h.Results.length - 1].Start, false, nowSecs) : []), dom.td(h.Results && h.Results.length > 0 ? h.Results[h.Results.length - 1].Error : []), dom.td(h.URL), dom.td(dom.clickbutton('Details', function click() {
			popupDetails(h);
		})))));
		tbody.replaceWith(ntbody);
		tbody = ntbody;
	};
	render();
	const buttonNextAttemptSet = (text, minutes) => dom.clickbutton(text, async function click(e) {
		// note: awkward client call because gatherIDs() can throw an exception.
		const n = await check(e.target, (async () => await client.HookNextAttemptSet(gatherIDs(), minutes))());
		window.alert('' + n + ' hook(s) updated');
		window.location.reload(); // todo: reload less
	});
	const buttonNextAttemptAdd = (text, minutes) => dom.clickbutton(text, async function click(e) {
		const n = await check(e.target, (async () => await client.HookNextAttemptAdd(gatherIDs(), minutes))());
		window.alert('' + n + ' hook(s) updated');
		window.location.reload(); // todo: reload less
	});
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'Webhook queue'), dom.p(dom.a(attr.href('#webhookqueue/retired'), 'Retired webhooks')), dom.h2('Webhooks'), dom.table(dom._class('hover'), style({ width: '100%' }), dom.thead(dom.tr(dom.td(attr.colspan('2'), 'Filter'), dom.td(filterSubmitted = dom.input(attr.form('hooksfilter'), style({ width: '7em' }), attr.title('Example: "<-1h" for filtering webhooks submitted more than 1 hour ago.'))), dom.td(), dom.td(), dom.td(), dom.td(filterAccount = dom.input(attr.form('hooksfilter'), style({ width: '8em' }))), dom.td(filterEvent = dom.select(attr.form('hooksfilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option(''), 
	// note: outgoing hook events are in ../webhook/webhook.go, ../mox-/config.go ../webadmin/admin.ts and ../webapi/gendoc.sh. keep in sync.
	['incoming', 'delivered', 'suppressed', 'delayed', 'failed', 'relayed', 'expanded', 'canceled', 'unrecognized'].map(s => dom.option(s)))), dom.td(), dom.td(), dom.td(filterNextAttempt = dom.input(attr.form('hooksfilter'), style({ width: '7em' }), attr.title('Example: ">1h" for filtering webhooks to be delivered in more than 1 hour, or "<now" for webhooks to be delivered as soon as possible.'))), dom.td(), dom.td(), dom.td(attr.colspan('2'), style({ textAlign: 'right' }), // Less content shifting while rendering.
	'Sort ', sortElem = dom.select(attr.form('hooksfilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option('Next attempt ↑', attr.value('nextattempt-asc')), dom.option('Next attempt ↓', attr.value('nextattempt-desc')), dom.option('Submitted ↑', attr.value('submitted-asc')), dom.option('Submitted ↓', attr.value('submitted-desc'))), ' ', dom.submitbutton('Apply', attr.form('hooksfilter')), ' ', dom.clickbutton('Reset', attr.form('hooksfilter'), function click() {
		filterForm.reset();
		filterForm.requestSubmit();
	}))), dom.tr(dom.td(dom.input(attr.type('checkbox'), (hooks || []).length === 1 ? attr.checked('') : [], attr.form('hooksfilter'), function change(e) {
		const elem = e.target;
		for (const [_, toggle] of toggles) {
			toggle.checked = elem.checked;
		}
	})), dom.th('ID'), dom.th('Submitted'), dom.th('Queue Msg ID', attr.title('ID of queued message this event is about.')), dom.th('FromID'), dom.th('MessageID'), dom.th('Account'), dom.th('Event'), dom.th('Extra'), dom.th('Attempts'), dom.th('Next'), dom.th('Last'), dom.th('Error'), dom.th('URL'), dom.th('Actions'))), tbody, dom.tfoot(dom.tr(dom.td(attr.colspan('15'), dom.clickbutton('Load more', attr.title('Try to load more entries. You can still try to load more entries when at the end of the list, new entries may have been appended since the previous call.'), async function click(e) {
		if (hooks.length === 0) {
			sort.LastID = 0;
			sort.Last = null;
		}
		else {
			const last = hooks[hooks.length - 1];
			sort.LastID = last.ID;
			if (sort.Field === "Submitted") {
				sort.Last = last.Submitted;
			}
			else {
				sort.Last = last.NextAttempt;
			}
		}
		tbody.classList.add('loadstart');
		const l = await check(e.target, client.HookList(filter, sort)) || [];
		hooks.push(...l);
		render();
	}))))), 
	// Filtering.
	filterForm = dom.form(attr.id('hooksfilter'), // Referenced by input elements in table row.
	async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		filter = {
			Max: filter.Max,
			IDs: [],
			Account: filterAccount.value,
			Event: filterEvent.value,
			Submitted: filterSubmitted.value,
			NextAttempt: filterNextAttempt.value,
		};
		sort = {
			Field: sortElem.value.startsWith('nextattempt') ? 'NextAttempt' : 'Submitted',
			LastID: 0,
			Last: null,
			Asc: sortElem.value.endsWith('asc'),
		};
		tbody.classList.add('loadstart');
		hooks = await check({ disabled: false }, client.HookList(filter, sort)) || [];
		render();
	}), dom.br(), dom.br(), dom.div(dom._class('unclutter'), dom.h2('Change selected webhooks'), dom.div(style({ display: 'flex', gap: '2em' }), dom.div(dom.div('Schedule next delivery attempt'), buttonNextAttemptSet('Now', 0), ' ', dom.clickbutton('More...', function click(e) {
		e.target.replaceWith(dom.div(dom.br(), dom.div('Scheduled time plus'), dom.div(buttonNextAttemptAdd('1m', 1), ' ', buttonNextAttemptAdd('5m', 5), ' ', buttonNextAttemptAdd('30m', 30), ' ', buttonNextAttemptAdd('1h', 60), ' ', buttonNextAttemptAdd('2h', 2 * 60), ' ', buttonNextAttemptAdd('4h', 4 * 60), ' ', buttonNextAttemptAdd('8h', 8 * 60), ' ', buttonNextAttemptAdd('16h', 16 * 60), ' '), dom.br(), dom.div('Now plus'), dom.div(buttonNextAttemptSet('1m', 1), ' ', buttonNextAttemptSet('5m', 5), ' ', buttonNextAttemptSet('30m', 30), ' ', buttonNextAttemptSet('1h', 60), ' ', buttonNextAttemptSet('2h', 2 * 60), ' ', buttonNextAttemptSet('4h', 4 * 60), ' ', buttonNextAttemptSet('8h', 8 * 60), ' ', buttonNextAttemptSet('16h', 16 * 60), ' ')));
	})), dom.div(dom.div('Delivery'), dom.clickbutton('Cancel', attr.title('Retires webhooks, preventing further delivery attempts.'), async function click(e) {
		e.preventDefault();
		if (!window.confirm('Are you sure you want to cancel these webhooks?')) {
			return;
		}
		const n = await check(e.target, (async () => await client.HookCancel(gatherIDs()))());
		window.alert('' + n + ' webhook(s) updated');
		window.location.reload(); // todo: only refresh the list
	})))));
};
const hooksRetiredList = async () => {
	let filter = { Max: parseInt(localStorageGet('adminpaginationsize') || '') || 100, IDs: [], Account: '', Submitted: '', LastActivity: '', Event: '' };
	let sort = { Field: "LastActivity", LastID: 0, Last: null, Asc: false };
	let hooks = await client.HookRetiredList(filter, sort) || [];
	const nowSecs = new Date().getTime() / 1000;
	let sortElem;
	let filterForm;
	let filterSubmitted;
	let filterAccount;
	let filterEvent;
	let filterLastActivity;
	const popupDetails = (h) => {
		const nowSecs = new Date().getTime() / 1000;
		popup(dom.h1('Details'), dom.div(dom._class('twocols'), dom.div(dom.table(dom.tr(dom.td('Message subject'), dom.td(h.Subject)), h.SupersededByID != 0 ? dom.tr(dom.td('Superseded by webhook ID'), dom.td('' + h.SupersededByID)) : []), dom.br(), dom.h2('Results'), dom.table(dom.thead(dom.tr(dom.th('Start'), dom.th('Duration'), dom.th('Success'), dom.th('Code'), dom.th('Error'), dom.th('URL'), dom.th('Response'))), dom.tbody((h.Results || []).length === 0 ? dom.tr(dom.td(attr.colspan('7'), 'No results.')) : [], (h.Results || []).map(r => dom.tr(dom.td(age(r.Start, false, nowSecs)), dom.td(Math.round(r.Duration / 1000000) + 'ms'), dom.td(r.Success ? '✓' : ''), dom.td('' + (r.Code || '')), dom.td(r.Error), dom.td(r.URL), dom.td(r.Response))))), dom.br()), dom.div(dom.h2('Webhook JSON body'), dom.pre(dom._class('literal'), JSON.stringify(JSON.parse(h.Payload), undefined, '\t')))));
	};
	let tbody = dom.tbody();
	// todo future: add selection + button to reschedule old retired webhooks.
	const render = () => {
		const ntbody = dom.tbody(dom._class('loadend'), hooks.length === 0 ? dom.tr(dom.td(attr.colspan('14'), 'No retired webhooks.')) : [], hooks.map(h => dom.tr(dom.td('' + h.ID), dom.td(h.Success ? '✓' : ''), dom.td(age(h.LastActivity, false, nowSecs)), dom.td(age(new Date(h.Submitted), false, nowSecs)), dom.td('' + (h.QueueMsgID || '')), dom.td('' + h.FromID), dom.td('' + h.MessageID), dom.td(h.Account || '-'), dom.td(h.IsIncoming ? "incoming" : h.OutgoingEvent), dom.td(formatExtra(h.Extra)), dom.td('' + h.Attempts), dom.td(h.Results && h.Results.length > 0 ? h.Results[h.Results.length - 1].Error : []), dom.td(h.URL), dom.td(dom.clickbutton('Details', function click() {
			popupDetails(h);
		})))));
		tbody.replaceWith(ntbody);
		tbody = ntbody;
	};
	render();
	return dom.div(crumbs(crumblink('Mox Admin', '#'), crumblink('Webhook queue', '#webhookqueue'), 'Retired webhooks'), dom.h2('Retired webhooks'), dom.table(dom._class('hover'), style({ width: '100%' }), dom.thead(dom.tr(dom.td('Filter'), dom.td(), dom.td(filterLastActivity = dom.input(attr.form('hooksfilter'), style({ width: '7em' }), attr.title('Example: ">-1h" for filtering last activity for webhooks more than 1 hour ago.'))), dom.td(filterSubmitted = dom.input(attr.form('hooksfilter'), style({ width: '7em' }), attr.title('Example: "<-1h" for filtering webhooks submitted more than 1 hour ago.'))), dom.td(), dom.td(), dom.td(), dom.td(filterAccount = dom.input(attr.form('hooksfilter'), style({ width: '8em' }))), dom.td(filterEvent = dom.select(attr.form('hooksfilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option(''), 
	// note: outgoing hook events are in ../webhook/webhook.go, ../mox-/config.go ../webadmin/admin.ts and ../webapi/gendoc.sh. keep in sync.
	['incoming', 'delivered', 'suppressed', 'delayed', 'failed', 'relayed', 'expanded', 'canceled', 'unrecognized'].map(s => dom.option(s)))), dom.td(), dom.td(), dom.td(), dom.td(attr.colspan('2'), style({ textAlign: 'right' }), // Less content shifting while rendering.
	'Sort ', sortElem = dom.select(attr.form('hooksfilter'), function change() {
		filterForm.requestSubmit();
	}, dom.option('Last activity ↓', attr.value('nextattempt-desc')), dom.option('Last activity ↑', attr.value('nextattempt-asc')), dom.option('Submitted ↓', attr.value('submitted-desc')), dom.option('Submitted ↑', attr.value('submitted-asc'))), ' ', dom.submitbutton('Apply', attr.form('hooksfilter')), ' ', dom.clickbutton('Reset', attr.form('hooksfilter'), function click() {
		filterForm.reset();
		filterForm.requestSubmit();
	}))), dom.tr(dom.th('ID'), dom.th('Success'), dom.th('Last'), dom.th('Submitted'), dom.th('Queue Msg ID', attr.title('ID of queued message this event is about.')), dom.th('FromID'), dom.th('MessageID'), dom.th('Account'), dom.th('Event'), dom.th('Extra'), dom.th('Attempts'), dom.th('Error'), dom.th('URL'), dom.th('Actions'))), tbody, dom.tfoot(dom.tr(dom.td(attr.colspan('14'), dom.clickbutton('Load more', attr.title('Try to load more entries. You can still try to load more entries when at the end of the list, new entries may have been appended since the previous call.'), async function click(e) {
		if (hooks.length === 0) {
			sort.LastID = 0;
			sort.Last = null;
		}
		else {
			const last = hooks[hooks.length - 1];
			sort.LastID = last.ID;
			if (sort.Field === "Submitted") {
				sort.Last = last.Submitted;
			}
			else {
				sort.Last = last.LastActivity;
			}
		}
		tbody.classList.add('loadstart');
		const l = await check(e.target, client.HookRetiredList(filter, sort)) || [];
		hooks.push(...l);
		render();
	}))))), 
	// Filtering.
	filterForm = dom.form(attr.id('hooksfilter'), // Referenced by input elements in table row.
	async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		filter = {
			Max: filter.Max,
			IDs: [],
			Account: filterAccount.value,
			Event: filterEvent.value,
			Submitted: filterSubmitted.value,
			LastActivity: filterLastActivity.value,
		};
		sort = {
			Field: sortElem.value.startsWith('lastactivity') ? 'LastActivity' : 'Submitted',
			LastID: 0,
			Last: null,
			Asc: sortElem.value.endsWith('asc'),
		};
		tbody.classList.add('loadstart');
		hooks = await check({ disabled: false }, client.HookRetiredList(filter, sort)) || [];
		render();
	}));
};
const webserver = async () => {
	let conf = await client.WebserverConfig();
	// We disable this while saving the form.
	let fieldset;
	// Keep track of redirects. Rows are objects that hold both the DOM and allows
	// retrieving the visible (modified) data to construct a config for saving.
	let redirectRows = [];
	let redirectsTbody;
	let noredirect;
	// Make a new redirect rows, adding it to the list. The caller typically uses this
	// while building the DOM, the element is added because this object has it as
	// "root" field.
	const redirectRow = (t) => {
		let row;
		let from;
		let to;
		const root = dom.tr(dom.td(from = dom.input(attr.required(''), attr.value(domainName(t[0])))), dom.td(to = dom.input(attr.required(''), attr.value(domainName(t[1])))), dom.td(dom.clickbutton('Remove', function click() {
			redirectRows = redirectRows.filter(r => r !== row);
			row.root.remove();
			noredirect.style.display = redirectRows.length ? 'none' : '';
		})));
		// "get" is the common function to retrieve the data from an object with a root field as DOM element.
		const get = () => [from.value, to.value];
		row = { root: root, from: from, to: to, get: get };
		redirectRows.push(row);
		return row;
	};
	// Reusable component for managing headers. Just a table with a header key and
	// value. We can remove existing rows, and add new rows, and edit existing.
	const makeHeaders = (h) => {
		let view;
		let rows = [];
		let tbody;
		let norow;
		const headerRow = (k, v) => {
			let row;
			let key;
			let value;
			const root = dom.tr(dom.td(key = dom.input(attr.required(''), attr.value(k))), dom.td(value = dom.input(attr.required(''), attr.value(v))), dom.td(dom.clickbutton('Remove', function click() {
				rows = rows.filter(x => x !== row);
				row.root.remove();
				norow.style.display = rows.length ? 'none' : '';
			})));
			const get = () => [row.key.value, row.value.value];
			row = { root: root, key: key, value: value, get: get };
			rows.push(row);
			return row;
		};
		const add = dom.clickbutton('Add', function click() {
			const row = headerRow('', '');
			tbody.appendChild(row.root);
			norow.style.display = rows.length ? 'none' : '';
		});
		const root = dom.table(tbody = dom.tbody(Object.entries(h).sort().map(t => headerRow(t[0], t[1])), norow = dom.tr(style({ display: rows.length ? 'none' : '' }), dom.td(attr.colspan('3'), 'None added.'))));
		const get = () => Object.fromEntries(rows.map(row => row.get()));
		view = { root: root, add: add, get: get };
		return view;
	};
	// Similar to redirects, but for web handlers.
	let handlerRows = [];
	let handlersTbody;
	let nohandler;
	// Make a handler row. This is more complicated, since it can be one of the three
	// types (static, redirect, forward), and can change between those types.
	const handlerRow = (wh) => {
		let row; // Shared between the handler types.
		let handlerType;
		let staticView = null;
		let redirectView = null;
		let forwardView = null;
		let internalView = null;
		let moveButtons;
		const makeWebStatic = (ws) => {
			let view;
			let stripPrefix;
			let rootPath;
			let listFiles;
			let continueNotFound;
			let responseHeaders = makeHeaders(ws.ResponseHeaders || {});
			const get = () => {
				return {
					StripPrefix: stripPrefix.value,
					Root: rootPath.value,
					ListFiles: listFiles.checked,
					ContinueNotFound: continueNotFound.checked,
					ResponseHeaders: responseHeaders.get(),
				};
			};
			const root = dom.table(dom.tr(dom.td('Type'), dom.td('StripPrefix', attr.title('Path to strip from the request URL before evaluating to a local path. If the requested URL path does not start with this prefix and ContinueNotFound it is considered non-matching and next WebHandlers are tried. If ContinueNotFound is not set, a file not found (404) is returned in that case.')), dom.td('Root', attr.title('Directory to serve files from for this handler. Keep in mind that relative paths are relative to the working directory of mox.')), dom.td('ListFiles', attr.title('If set, and a directory is requested, and no index.html is present that can be served, a file listing is returned. Results in 403 if ListFiles is not set. If a directory is requested and the URL does not end with a slash, the response is a redirect to the path with trailing slash.')), dom.td('ContinueNotFound', attr.title("If a requested URL does not exist, don't return a file not found (404) response, but consider this handler non-matching and continue attempts to serve with later WebHandlers, which may be a reverse proxy generating dynamic content, possibly even writing a static file for a next request to serve statically. If ContinueNotFound is set, HTTP requests other than GET and HEAD do not match. This mechanism can be used to implement the equivalent of 'try_files' in other webservers.")), dom.td(dom.span('Response headers', attr.title('Headers to add to the response. Useful for cache-control, content-type, etc. By default, Content-Type headers are automatically added for recognized file types, unless added explicitly through this setting. For directory listings, a content-type header is skipped.')), ' ', responseHeaders.add)), dom.tr(dom.td(dom.select(attr.required(''), dom.option('Static', attr.selected('')), dom.option('Redirect'), dom.option('Forward'), dom.option('Internal'), function change(e) {
				makeType(e.target.value);
			})), dom.td(stripPrefix = dom.input(attr.value(ws.StripPrefix || ''))), dom.td(rootPath = dom.input(attr.required(''), attr.placeholder('web/...'), attr.value(ws.Root || ''))), dom.td(listFiles = dom.input(attr.type('checkbox'), ws.ListFiles ? attr.checked('') : [])), dom.td(continueNotFound = dom.input(attr.type('checkbox'), ws.ContinueNotFound ? attr.checked('') : [])), dom.td(responseHeaders)));
			view = { root: root, get: get };
			return view;
		};
		const makeWebRedirect = (wr) => {
			let view;
			let baseURL;
			let origPathRegexp;
			let replacePath;
			let statusCode;
			const get = () => {
				return {
					BaseURL: baseURL.value,
					OrigPathRegexp: origPathRegexp.value,
					ReplacePath: replacePath.value,
					StatusCode: statusCode.value ? parseInt(statusCode.value) : 0,
				};
			};
			const root = dom.table(dom.tr(dom.td('Type'), dom.td('BaseURL', attr.title('Base URL to redirect to. The path must be empty and will be replaced, either by the request URL path, or by OrigPathRegexp/ReplacePath. Scheme, host, port and fragment stay intact, and query strings are combined. If empty, the response redirects to a different path through OrigPathRegexp and ReplacePath, which must then be set. Use a URL without scheme to redirect without changing the protocol, e.g. //newdomain/. If a redirect would send a request to a URL with the same scheme, host and path, the WebRedirect does not match so a next WebHandler can be tried. This can be used to redirect all plain http traffic to https.')), dom.td('OrigPathRegexp', attr.title('Regular expression for matching path. If set and path does not match, a 404 is returned. The HTTP path used for matching always starts with a slash.')), dom.td('ReplacePath', attr.title("Replacement path for destination URL based on OrigPathRegexp. Implemented with Go's Regexp.ReplaceAllString: $1 is replaced with the text of the first submatch, etc. If both OrigPathRegexp and ReplacePath are empty, BaseURL must be set and all paths are redirected unaltered.")), dom.td('StatusCode', attr.title('Status code to use in redirect, e.g. 307. By default, a permanent redirect (308) is returned.'))), dom.tr(dom.td(dom.select(attr.required(''), dom.option('Static'), dom.option('Redirect', attr.selected('')), dom.option('Forward'), dom.option('Internal'), function change(e) {
				makeType(e.target.value);
			})), dom.td(baseURL = dom.input(attr.placeholder('empty or https://target/path?q=1#frag or //target/...'), attr.value(wr.BaseURL || ''))), dom.td(origPathRegexp = dom.input(attr.placeholder('^/old/(.*)'), attr.value(wr.OrigPathRegexp || ''))), dom.td(replacePath = dom.input(attr.placeholder('/new/$1'), attr.value(wr.ReplacePath || ''))), dom.td(statusCode = dom.input(style({ width: '4em' }), attr.type('number'), attr.value(wr.StatusCode ? '' + wr.StatusCode : ''), attr.min('300'), attr.max('399')))));
			view = { root: root, get: get };
			return view;
		};
		const makeWebForward = (wf) => {
			let view;
			let stripPath;
			let url;
			let responseHeaders = makeHeaders(wf.ResponseHeaders || {});
			const get = () => {
				return {
					StripPath: stripPath.checked,
					URL: url.value,
					ResponseHeaders: responseHeaders.get(),
				};
			};
			const root = dom.table(dom.tr(dom.td('Type'), dom.td('StripPath', attr.title('Strip the matching WebHandler path from the WebHandler before forwarding the request.')), dom.td('URL', attr.title("URL to forward HTTP requests to, e.g. http://127.0.0.1:8123/base. If StripPath is false the full request path is added to the URL. Host headers are sent unmodified. New X-Forwarded-{For,Host,Proto} headers are set. Any query string in the URL is ignored. Requests are made using Go's net/http.DefaultTransport that takes environment variables HTTP_PROXY and HTTPS_PROXY into account. Websocket connections are forwarded and data is copied between client and backend without looking at the framing. The websocket 'version' and 'key'/'accept' headers are verified during the handshake, but other websocket headers, including 'origin', 'protocol' and 'extensions' headers, are not inspected and the backend is responsible for verifying/interpreting them.")), dom.td(dom.span('Response headers', attr.title('Headers to add to the response. Useful for adding security- and cache-related headers.')), ' ', responseHeaders.add)), dom.tr(dom.td(dom.select(attr.required(''), dom.option('Static'), dom.option('Redirect'), dom.option('Forward', attr.selected('')), dom.option('Internal'), function change(e) {
				makeType(e.target.value);
			})), dom.td(stripPath = dom.input(attr.type('checkbox'), wf.StripPath || wf.StripPath === undefined ? attr.checked('') : [])), dom.td(url = dom.input(attr.required(''), attr.placeholder('http://127.0.0.1:8888'), attr.value(wf.URL || ''))), dom.td(responseHeaders)));
			view = { root: root, get: get };
			return view;
		};
		const makeWebInternal = (wi) => {
			let view;
			let basePath;
			let service;
			const get = () => {
				return {
					BasePath: basePath.value,
					Service: service.value,
				};
			};
			const root = dom.table(dom.tr(dom.td('Type'), dom.td('Base path', attr.title('Path to use as root of internal service, e.g. /webmail/.')), dom.td('Service')), dom.tr(dom.td(dom.select(attr.required(''), dom.option('Static'), dom.option('Redirect'), dom.option('Forward'), dom.option('Internal', attr.selected('')), function change(e) {
				makeType(e.target.value);
			})), dom.td(basePath = dom.input(attr.value(wi.BasePath), attr.required(''), attr.placeholder('/.../'))), dom.td(service = dom.select(dom.option('Admin', attr.value('admin')), dom.option('Account', attr.value('account')), dom.option('Webmail', attr.value('webmail')), dom.option('Webapi', attr.value('webapi')), prop({ value: wi.Service })))));
			view = { root: root, get: get };
			return view;
		};
		let logName;
		let domain;
		let pathRegexp;
		let toHTTPS;
		let compress;
		let details;
		const detailsRoot = (root) => {
			details.replaceWith(root);
			details = root;
		};
		// Transform the input fields to match the type of WebHandler.
		const makeType = (s) => {
			if (s === 'Static') {
				staticView = makeWebStatic(wh.WebStatic || {
					StripPrefix: '',
					Root: '',
					ListFiles: false,
					ContinueNotFound: false,
					ResponseHeaders: {},
				});
				detailsRoot(staticView.root);
			}
			else if (s === 'Redirect') {
				redirectView = makeWebRedirect(wh.WebRedirect || {
					BaseURL: '',
					OrigPathRegexp: '',
					ReplacePath: '',
					StatusCode: 0,
				});
				detailsRoot(redirectView.root);
			}
			else if (s === 'Forward') {
				forwardView = makeWebForward(wh.WebForward || {
					StripPath: false,
					URL: '',
					ResponseHeaders: {},
				});
				detailsRoot(forwardView.root);
			}
			else if (s === 'Internal') {
				internalView = makeWebInternal(wh.WebInternal || {
					BasePath: '',
					Service: 'admin',
				});
				detailsRoot(internalView.root);
			}
			else {
				throw new Error('unknown handler type');
			}
			handlerType = s;
		};
		// Remove row from oindex, insert it in nindex. Both in handlerRows and in the DOM.
		const moveHandler = (row, oindex, nindex) => {
			row.root.remove();
			handlersTbody.insertBefore(row.root, handlersTbody.children[nindex]);
			handlerRows.splice(oindex, 1);
			handlerRows.splice(nindex, 0, row);
		};
		// Row that starts starts with two tables: one for the fields all WebHandlers have
		// (in common). And one for the details, i.e. WebStatic, WebRedirect, WebForward.
		const root = dom.tr(dom.td(dom.table(dom.tr(dom.td('LogName', attr.title('Name used during logging for requests matching this handler. If empty, the index of the handler in the list is used.')), dom.td('Domain', attr.title('Request must be for this domain to match this handler.')), dom.td('Path Regexp', attr.title('Request must match this path regular expression to match this handler. Must start with with a ^.')), dom.td('To HTTPS', attr.title('Redirect plain HTTP (non-TLS) requests to HTTPS.')), dom.td('Compress', attr.title('Transparently compress responses (currently with gzip) if the client supports it, the status is 200 OK, no Content-Encoding is set on the response yet and the Content-Type of the response hints that the data is compressible (text/..., specific application/... and .../...+json and .../...+xml). For static files only, a cache with compressed files is kept.'))), dom.tr(dom.td(logName = dom.input(attr.value(wh.LogName || ''))), dom.td(domain = dom.input(attr.required(''), attr.placeholder('example.org'), attr.value(domainName(wh.DNSDomain)))), dom.td(pathRegexp = dom.input(attr.required(''), attr.placeholder('^/'), attr.value(wh.PathRegexp || ''))), dom.td(toHTTPS = dom.input(attr.type('checkbox'), attr.title('Redirect plain HTTP (non-TLS) requests to HTTPS'), !wh.DontRedirectPlainHTTP ? attr.checked('') : [])), dom.td(compress = dom.input(attr.type('checkbox'), attr.title('Transparently compress responses.'), wh.Compress ? attr.checked('') : [])))), 
		// Replaced with a call to makeType, below (and later when switching types).
		details = dom.table()), dom.td(dom.td(dom.clickbutton('Remove', function click() {
			handlerRows = handlerRows.filter(r => r !== row);
			row.root.remove();
			nohandler.style.display = handlerRows.length ? 'none' : '';
		}), ' ', 
		// We show/hide the buttons to move when clicking the Move button.
		moveButtons = dom.span(style({ display: 'none' }), dom.clickbutton('↑↑', attr.title('Move to top.'), function click() {
			const index = handlerRows.findIndex(r => r === row);
			if (index > 0) {
				moveHandler(row, index, 0);
			}
		}), ' ', dom.clickbutton('↑', attr.title('Move one up.'), function click() {
			const index = handlerRows.findIndex(r => r === row);
			if (index > 0) {
				moveHandler(row, index, index - 1);
			}
		}), ' ', dom.clickbutton('↓', attr.title('Move one down.'), function click() {
			const index = handlerRows.findIndex(r => r === row);
			if (index + 1 < handlerRows.length) {
				moveHandler(row, index, index + 1);
			}
		}), ' ', dom.clickbutton('↓↓', attr.title('Move to bottom.'), function click() {
			const index = handlerRows.findIndex(r => r === row);
			if (index + 1 < handlerRows.length) {
				moveHandler(row, index, handlerRows.length - 1);
			}
		})))));
		// Final "get" that returns a WebHandler that reflects the UI.
		const get = () => {
			const wh = {
				LogName: logName.value,
				Domain: domain.value,
				PathRegexp: pathRegexp.value,
				DontRedirectPlainHTTP: !toHTTPS.checked,
				Compress: compress.checked,
				Name: '',
				DNSDomain: { ASCII: '', Unicode: '' },
			};
			if (handlerType === 'Static' && staticView != null) {
				wh.WebStatic = staticView.get();
			}
			else if (handlerType === 'Redirect' && redirectView !== null) {
				wh.WebRedirect = redirectView.get();
			}
			else if (handlerType === 'Forward' && forwardView !== null) {
				wh.WebForward = forwardView.get();
			}
			else if (handlerType === 'Internal' && internalView !== null) {
				wh.WebInternal = internalView.get();
			}
			else {
				throw new Error('unknown WebHandler type');
			}
			return wh;
		};
		// Initialize one of the Web* types.
		if (wh.WebStatic) {
			handlerType = 'Static';
		}
		else if (wh.WebRedirect) {
			handlerType = 'Redirect';
		}
		else if (wh.WebForward) {
			handlerType = 'Forward';
		}
		else if (wh.WebInternal) {
			handlerType = 'Internal';
		}
		else {
			throw new Error('unknown WebHandler type');
		}
		makeType(handlerType);
		row = { root: root, moveButtons: moveButtons, get: get };
		handlerRows.push(row);
		return row;
	};
	// Return webserver config to store.
	const gatherConf = () => {
		return {
			WebDomainRedirects: redirectRows.map(row => row.get()),
			WebHandlers: handlerRows.map(row => row.get()),
		};
	};
	// Add and move buttons, both above and below the table for quick access, hence a function.
	const handlerActions = () => {
		return [
			'Action ',
			dom.clickbutton('Add', function click() {
				// New WebHandler added as WebForward. Good chance this is what the user wants. And
				// it has the least fields. (;
				const nwh = {
					LogName: '',
					Domain: '',
					PathRegexp: '^/',
					DontRedirectPlainHTTP: false,
					Compress: false,
					WebForward: {
						StripPath: true,
						URL: '',
					},
					Name: '',
					DNSDomain: { ASCII: '', Unicode: '' },
				};
				const row = handlerRow(nwh);
				handlersTbody.appendChild(row.root);
				nohandler.style.display = handlerRows.length ? 'none' : '';
			}),
			' ',
			dom.clickbutton('Move', function click() {
				for (const row of handlerRows) {
					row.moveButtons.style.display = row.moveButtons.style.display === 'none' ? '' : 'none';
				}
			}),
		];
	};
	return dom.div(crumbs(crumblink('Mox Admin', '#'), 'Webserver config'), dom.form(fieldset = dom.fieldset(dom.h2('Domain redirects', attr.title('Corresponds with WebDomainRedirects in domains.conf')), dom.p('Incoming requests for these domains are redirected to the target domain, with HTTPS.'), dom.table(dom.thead(dom.tr(dom.th('From'), dom.th('To'), dom.th('Action ', dom.clickbutton('Add', function click() {
		const row = redirectRow([{ ASCII: '', Unicode: '' }, { ASCII: '', Unicode: '' }]);
		redirectsTbody.appendChild(row.root);
		noredirect.style.display = redirectRows.length ? 'none' : '';
	})))), redirectsTbody = dom.tbody((conf.WebDNSDomainRedirects || []).sort().map(t => redirectRow([t[0], t[1]])), noredirect = dom.tr(style({ display: redirectRows.length ? 'none' : '' }), dom.td(attr.colspan('3'), 'No redirects.')))), dom.br(), dom.h2('Handlers', attr.title('Corresponds with WebHandlers in domains.conf')), dom.p('Each incoming request is matched against the configured handlers, in order. The first matching handler serves the request. System handlers such as for ACME validation, MTA-STS and autoconfig, come first. Then these webserver handlers. Finally the internal service handlers for admin, account, webmail and webapi configured in mox.conf. Don\'t forget to save after making a change.'), dom.table(dom._class('long'), dom.thead(dom.tr(dom.th(), dom.th(handlerActions()))), handlersTbody = dom.tbody((conf.WebHandlers || []).map(wh => handlerRow(wh)), nohandler = dom.tr(style({ display: handlerRows.length ? 'none' : '' }), dom.td(attr.colspan('2'), 'No handlers.'))), dom.tfoot(dom.tr(dom.th(), dom.th(handlerActions())))), dom.br(), dom.submitbutton('Save', attr.title('Save config. If the configuration has changed since this page was loaded, an error will be returned. After saving, the changes take effect immediately.'))), async function submit(e) {
		e.preventDefault();
		e.stopPropagation();
		conf = await check(fieldset, client.WebserverConfigSave(conf, gatherConf()));
	}));
};
const init = async () => {
	let curhash;
	[moxversion, moxgoos, moxgoarch] = await client.Version();
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
			let root;
			if (h == '') {
				root = await index();
			}
			else if (h === 'config') {
				root = await config();
			}
			else if (h === 'loglevels') {
				root = await loglevels();
			}
			else if (h === 'accounts') {
				root = await accounts();
			}
			else if (h === 'accounts/loginattempts') {
				root = await loginattempts();
			}
			else if (t[0] === 'accounts' && t.length === 3 && t[1] === 'l') {
				root = await account(t[2]);
			}
			else if (t[0] === 'accounts' && t.length === 4 && t[1] === 'l' && t[3] === 'loginattempts') {
				root = await accountloginattempts(t[2]);
			}
			else if (t[0] === 'domains' && t.length === 2) {
				root = await domain(t[1]);
			}
			else if (t[0] === 'domains' && t.length === 4 && t[2] === 'alias') {
				root = await domainAlias(t[1], t[3]);
			}
			else if (t[0] === 'domains' && t.length === 3 && t[2] === 'dmarc') {
				root = await domainDMARC(t[1]);
			}
			else if (t[0] === 'domains' && t.length === 4 && t[2] === 'dmarc' && parseInt(t[3])) {
				root = await domainDMARCReport(t[1], parseInt(t[3]));
			}
			else if (t[0] === 'domains' && t.length === 3 && t[2] === 'dnscheck') {
				root = await domainDNSCheck(t[1]);
			}
			else if (t[0] === 'domains' && t.length === 3 && t[2] === 'dnsrecords') {
				root = await domainDNSRecords(t[1]);
			}
			else if (h === 'queue') {
				root = await queueList();
			}
			else if (h === 'queue/retired') {
				root = await retiredList();
			}
			else if (h === 'webhookqueue') {
				root = await hooksList();
			}
			else if (h === 'webhookqueue/retired') {
				root = await hooksRetiredList();
			}
			else if (h === 'tlsrpt') {
				root = await tlsrptIndex();
			}
			else if (h === 'tlsrpt/reports') {
				root = await tlsrptReports();
			}
			else if (t[0] === 'tlsrpt' && t[1] === 'reports' && t.length === 3) {
				root = await domainTLSRPT(t[2]);
			}
			else if (t[0] === 'tlsrpt' && t[1] === 'reports' && t.length === 4 && parseInt(t[3])) {
				root = await domainTLSRPTID(t[2], parseInt(t[3]));
			}
			else if (h === 'tlsrpt/results') {
				root = await tlsrptResults();
			}
			else if (t[0] == 'tlsrpt' && t[1] == 'results' && (t[2] === 'rcptdom' || t[2] == 'host') && t.length === 4) {
				root = await tlsrptResultsPolicyDomain(t[2] === 'rcptdom', t[3]);
			}
			else if (h === 'dmarc') {
				root = await dmarcIndex();
			}
			else if (h === 'dmarc/reports') {
				root = await dmarcReports();
			}
			else if (h === 'dmarc/evaluations') {
				root = await dmarcEvaluations();
			}
			else if (t[0] == 'dmarc' && t[1] == 'evaluations' && t.length === 3) {
				root = await dmarcEvaluationsDomain(t[2]);
			}
			else if (h === 'mtasts') {
				root = await mtasts();
			}
			else if (h === 'dnsbl') {
				root = await dnsbl();
			}
			else if (h === 'routes') {
				root = await globalRoutes();
			}
			else if (h === 'webserver') {
				root = await webserver();
			}
			else {
				root = dom.div('page not found');
			}
			if (window.moxBeforeDisplay) {
				moxBeforeDisplay(root);
			}
			dom._kids(page, root);
		}
		catch (err) {
			console.log('error', err);
			window.alert('Error: ' + errmsg(err));
			curhash = window.location.hash;
			return;
		}
		curhash = window.location.hash;
		page.classList.remove('loading');
	};
	window.addEventListener('hashchange', hashChange);
	hashChange();
};
window.addEventListener('load', init);
