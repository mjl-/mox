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
	api.structTypes = { "Destination": true, "Domain": true, "ImportProgress": true, "Ruleset": true };
	api.stringsTypes = { "CSRFToken": true };
	api.intsTypes = {};
	api.types = {
		"Domain": { "Name": "Domain", "Docs": "", "Fields": [{ "Name": "ASCII", "Docs": "", "Typewords": ["string"] }, { "Name": "Unicode", "Docs": "", "Typewords": ["string"] }] },
		"Destination": { "Name": "Destination", "Docs": "", "Fields": [{ "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Rulesets", "Docs": "", "Typewords": ["[]", "Ruleset"] }, { "Name": "FullName", "Docs": "", "Typewords": ["string"] }] },
		"Ruleset": { "Name": "Ruleset", "Docs": "", "Fields": [{ "Name": "SMTPMailFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "HeadersRegexp", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListAllowDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "AcceptRejectsToMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "ListAllowDNSDomain", "Docs": "", "Typewords": ["Domain"] }] },
		"ImportProgress": { "Name": "ImportProgress", "Docs": "", "Fields": [{ "Name": "Token", "Docs": "", "Typewords": ["string"] }] },
		"CSRFToken": { "Name": "CSRFToken", "Docs": "", "Values": null },
	};
	api.parser = {
		Domain: (v) => api.parse("Domain", v),
		Destination: (v) => api.parse("Destination", v),
		Ruleset: (v) => api.parse("Ruleset", v),
		ImportProgress: (v) => api.parse("ImportProgress", v),
		CSRFToken: (v) => api.parse("CSRFToken", v),
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
		// Account returns information about the account: full name, the default domain,
		// and the destinations (keys are email addresses, or localparts to the default
		// domain). todo: replace with a function that returns the whole account, when
		// sherpadoc understands unnamed struct fields.
		async Account() {
			const fn = "Account";
			const paramTypes = [];
			const returnTypes = [["string"], ["Domain"], ["{}", "Destination"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
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
const login = async (reason) => {
	return new Promise((resolve, _) => {
		const origFocus = document.activeElement;
		let reasonElem;
		let fieldset;
		let autosize;
		let username;
		let password;
		const root = dom.div(style({ position: 'absolute', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: '#eee', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: '1', animation: 'fadein .15s ease-in' }), dom.div(reasonElem = reason ? dom.div(style({ marginBottom: '2ex', textAlign: 'center' }), reason) : dom.div(), dom.div(style({ backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto', marginBottom: '20vh' }), dom.form(async function submit(e) {
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
const client = new api.Client().withOptions({ csrfHeader: 'x-mox-csrf', login: login }).withAuthToken(localStorageGet('webaccountcsrftoken') || '');
const link = (href, anchorOpt) => dom.a(attr.href(href), attr.rel('noopener noreferrer'), anchorOpt || href);
const crumblink = (text, link) => dom.a(text, attr.href(link));
const crumbs = (...l) => [
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
	dom.h1(l.map((e, index) => index === 0 ? e : [' / ', e])),
	dom.br()
];
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
const index = async () => {
	const [accountFullName, domain, destinations] = await client.Account();
	let fullNameForm;
	let fullNameFieldset;
	let fullName;
	let passwordForm;
	let passwordFieldset;
	let password1;
	let password2;
	let passwordHint;
	let importForm;
	let importFieldset;
	let mailboxFileHint;
	let mailboxPrefixHint;
	let importProgress;
	let importAbortBox;
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
	const exportForm = (filename) => {
		return dom.form(attr.target('_blank'), attr.method('POST'), attr.action('export/' + filename), dom.input(attr.type('hidden'), attr.name('csrf'), attr.value(localStorageGet('webaccountcsrftoken') || '')), dom.submitbutton('Export'));
	};
	dom._kids(page, crumbs('Mox Account'), dom.p('NOTE: Not all account settings can be configured through these pages yet. See the configuration file for more options.'), dom.div('Default domain: ', domain.ASCII ? domainString(domain) : '(none)'), dom.br(), fullNameForm = dom.form(fullNameFieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), 'Full name', dom.br(), fullName = dom.input(attr.value(accountFullName), attr.title('Name to use in From header when composing messages. Can be overridden per configured address.'))), ' ', dom.submitbutton('Save')), async function submit(e) {
		e.preventDefault();
		fullNameFieldset.disabled = true;
		try {
			await client.AccountSaveFullName(fullName.value);
			fullName.setAttribute('value', fullName.value);
			fullNameForm.reset();
			window.alert('Full name has been changed.');
		}
		catch (err) {
			console.log({ err });
			window.alert('Error: ' + errmsg(err));
		}
		finally {
			fullNameFieldset.disabled = false;
		}
	}), dom.br(), dom.h2('Addresses'), dom.ul(Object.entries(destinations).sort().map(t => dom.li(dom.a(t[0], attr.href('#destinations/' + t[0])), t[0].startsWith('@') ? ' (catchall)' : []))), dom.br(), dom.h2('Change password'), passwordForm = dom.form(passwordFieldset = dom.fieldset(dom.label(style({ display: 'inline-block' }), 'New password', dom.br(), password1 = dom.input(attr.type('password'), attr.autocomplete('new-password'), attr.required(''), function focus() {
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
		passwordFieldset.disabled = true;
		try {
			await client.SetPassword(password1.value);
			window.alert('Password has been changed.');
			passwordForm.reset();
		}
		catch (err) {
			console.log({ err });
			window.alert('Error: ' + errmsg(err));
		}
		finally {
			passwordFieldset.disabled = false;
		}
	}), dom.br(), dom.h2('Export'), dom.p('Export all messages in all mailboxes. In maildir or mbox format, as .zip or .tgz file.'), dom.table(dom._class('slim'), dom.tr(dom.td('Maildirs in .tgz'), dom.td(exportForm('mail-export-maildir.tgz'))), dom.tr(dom.td('Maildirs in .zip'), dom.td(exportForm('mail-export-maildir.zip'))), dom.tr(dom.td('Mbox files in .tgz'), dom.td(exportForm('mail-export-mbox.tgz'))), dom.tr(dom.td('Mbox files in .zip'), dom.td(exportForm('mail-export-mbox.zip')))), dom.br(), dom.h2('Import'), dom.p('Import messages from a .zip or .tgz file with maildirs and/or mbox files.'), importForm = dom.form(async function submit(e) {
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
	})), mailboxFileHint = dom.p(style({ display: 'none', fontStyle: 'italic', marginTop: '.5ex' }), 'This file must either be a zip file or a gzipped tar file with mbox and/or maildir mailboxes. For maildirs, an optional file "dovecot-keywords" is read additional keywords, like Forwarded/Junk/NotJunk. If an imported mailbox already exists by name, messages are added to the existing mailbox. If a mailbox does not yet exist it will be created.')), dom.div(style({ marginBottom: '1ex' }), dom.label(dom.div(style({ marginBottom: '.5ex' }), 'Skip mailbox prefix (optional)'), dom.input(attr.name('skipMailboxPrefix'), function focus() {
		mailboxPrefixHint.style.display = '';
	})), mailboxPrefixHint = dom.p(style({ display: 'none', fontStyle: 'italic', marginTop: '.5ex' }), 'If set, any mbox/maildir path with this prefix will have it stripped before importing. For example, if all mailboxes are in a directory "Takeout", specify that path in the field above so mailboxes like "Takeout/Inbox.mbox" are imported into a mailbox called "Inbox" instead of "Takeout/Inbox".')), dom.div(dom.submitbutton('Upload and import'), dom.p(style({ fontStyle: 'italic', marginTop: '.5ex' }), 'The file is uploaded first, then its messages are imported, finally messages are matched for threading. Importing is done in a transaction, you can abort the entire import before it is finished.')))), importAbortBox = dom.div(), // Outside fieldset because it gets disabled, above progress because may be scrolling it down quickly with problems.
	importProgress = dom.div(style({ display: 'none' })), footer);
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
	const [_, domain, destinations] = await client.Account();
	let dest = destinations[name];
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
		let verifiedDomain;
		let isForward; // Checkbox
		let listAllowDomain;
		let acceptRejectsToMailbox;
		let mailbox;
		const root = dom.tr(dom.td(smtpMailFromRegexp = dom.input(attr.value(rs.SMTPMailFromRegexp || ''))), dom.td(verifiedDomain = dom.input(attr.value(rs.VerifiedDomain || ''))), headersCell, dom.td(dom.label(isForward = dom.input(attr.type('checkbox'), rs.IsForward ? attr.checked('') : []))), dom.td(listAllowDomain = dom.input(attr.value(rs.ListAllowDomain || ''))), dom.td(acceptRejectsToMailbox = dom.input(attr.value(rs.AcceptRejectsToMailbox || ''))), dom.td(mailbox = dom.input(attr.value(rs.Mailbox || ''))), dom.td(dom.clickbutton('Remove ruleset', function click() {
			row.root.remove();
			rulesetsRows = rulesetsRows.filter(e => e !== row);
		})));
		row = {
			root: root,
			smtpMailFromRegexp: smtpMailFromRegexp,
			verifiedDomain: verifiedDomain,
			headers: [],
			isForward: isForward,
			listAllowDomain: listAllowDomain,
			acceptRejectsToMailbox: acceptRejectsToMailbox,
			mailbox: mailbox,
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
	const addresses = [name, ...Object.keys(destinations).filter(a => !a.startsWith('@') && a !== name)];
	dom._kids(page, crumbs(crumblink('Mox Account', '#'), 'Destination ' + name), dom.div(dom.span('Default mailbox', attr.title('Default mailbox where email for this recipient is delivered to if it does not match any ruleset. Default is Inbox.')), dom.br(), defaultMailbox = dom.input(attr.value(dest.Mailbox), attr.placeholder('Inbox'))), dom.br(), dom.div(dom.span('Full name', attr.title('Name to use in From header when composing messages. If not set, the account default full name is used.')), dom.br(), fullName = dom.input(attr.value(dest.FullName))), dom.br(), dom.h2('Rulesets'), dom.p('Incoming messages are checked against the rulesets. If a ruleset matches, the message is delivered to the mailbox configured for the ruleset instead of to the default mailbox.'), dom.p('"Is Forward" does not affect matching, but changes prevents the sending mail server from being included in future junk classifications by clearing fields related to the forwarding email server (IP address, EHLO domain, MAIL FROM domain and a matching DKIM domain), and prevents DMARC rejects for forwarded messages.'), dom.p('"List allow domain" does not affect matching, but skips the regular spam checks if one of the verified domains is a (sub)domain of the domain mentioned here.'), dom.p('"Accept rejects to mailbox" does not affect matching, but causes messages classified as junk to be accepted and delivered to this mailbox, instead of being rejected during the SMTP transaction. Useful for incoming forwarded messages where rejecting incoming messages may cause the forwarding server to stop forwarding.'), dom.table(dom.thead(dom.tr(dom.th('SMTP "MAIL FROM" regexp', attr.title('Matches if this regular expression matches (a substring of) the SMTP MAIL FROM address (not the message From-header). E.g. user@example.org.')), dom.th('Verified domain', attr.title('Matches if this domain matches an SPF- and/or DKIM-verified (sub)domain.')), dom.th('Headers regexp', attr.title('Matches if these header field/value regular expressions all match (substrings of) the message headers. Header fields and valuees are converted to lower case before matching. Whitespace is trimmed from the value before matching. A header field can occur multiple times in a message, only one instance has to match. For mailing lists, you could match on ^list-id$ with the value typically the mailing list address in angled brackets with @ replaced with a dot, e.g. <name\\.lists\\.example\\.org>.')), dom.th('Is Forward', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. Can only be used together with SMTPMailFromRegexp and VerifiedDomain. SMTPMailFromRegexp must be set to the address used to deliver the forwarded message, e.g. '^user(|\\+.*)@forward\\.example$'. Changes to junk analysis: 1. Messages are not rejected for failing a DMARC policy, because a legitimate forwarded message without valid/intact/aligned DKIM signature would be rejected because any verified SPF domain will be 'unaligned', of the forwarding mail server. 2. The sending mail server IP address, and sending EHLO and MAIL FROM domains and matching DKIM domain aren't used in future reputation-based spam classifications (but other verified DKIM domains are) because the forwarding server is not a useful spam signal for future messages.")), dom.th('List allow domain', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If this domain matches an SPF- and/or DKIM-verified (sub)domain, the message is accepted without further spam checks, such as a junk filter or DMARC reject evaluation. DMARC rejects should not apply for mailing lists that are not configured to rewrite the From-header of messages that don't have a passing DKIM signature of the From-domain. Otherwise, by rejecting messages, you may be automatically unsubscribed from the mailing list. The assumption is that mailing lists do their own spam filtering/moderation.")), dom.th('Allow rejects to mailbox', attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If a message is classified as spam, it isn't rejected during the SMTP transaction (the normal behaviour), but accepted during the SMTP transaction and delivered to the specified mailbox. The specified mailbox is not automatically cleaned up like the account global Rejects mailbox, unless set to that Rejects mailbox.")), dom.th('Mailbox', attr.title('Mailbox to deliver to if this ruleset matches.')), dom.th('Action'))), rulesetsTbody, dom.tfoot(dom.tr(dom.td(attr.colspan('7')), dom.td(dom.clickbutton('Add ruleset', function click() {
		addRulesetsRow({
			SMTPMailFromRegexp: '',
			VerifiedDomain: '',
			HeadersRegexp: {},
			IsForward: false,
			ListAllowDomain: '',
			AcceptRejectsToMailbox: '',
			Mailbox: '',
			VerifiedDNSDomain: { ASCII: '', Unicode: '' },
			ListAllowDNSDomain: { ASCII: '', Unicode: '' },
		});
	}))))), dom.br(), saveButton = dom.clickbutton('Save', async function click() {
		saveButton.disabled = true;
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
						VerifiedDNSDomain: { ASCII: '', Unicode: '' },
						ListAllowDNSDomain: { ASCII: '', Unicode: '' },
					};
				}),
			};
			page.classList.add('loading');
			await client.DestinationSave(name, dest, newDest);
			window.location.reload(); // todo: only refresh part of ui
		}
		catch (err) {
			console.log({ err });
			window.alert('Error: ' + errmsg(err));
			page.classList.remove('loading');
			return;
		}
		finally {
			saveButton.disabled = false;
		}
	}), dom.br(), dom.br(), dom.br(), dom.p("Apple's mail applications don't do account autoconfiguration, and when adding an account it can choose defaults that don't work with modern email servers. Adding an account through a \"mobileconfig\" profile file can be more convenient: It contains the IMAP/SMTP settings such as host name, port, TLS, authentication mechanism and user name. This profile does not contain a login password. Opening the profile adds it under Profiles in System Preferences (macOS) or Settings (iOS), where you can install it. These profiles are not signed, so users will have to ignore the warnings about them being unsigned. ", dom.br(), dom.a(attr.href('https://autoconfig.' + domainName(domain) + '/profile.mobileconfig?addresses=' + encodeURIComponent(addresses.join(',')) + '&name=' + encodeURIComponent(dest.FullName)), attr.download(''), 'Download .mobileconfig email account profile'), dom.br(), dom.a(attr.href('https://autoconfig.' + domainName(domain) + '/profile.mobileconfig.qrcode.png?addresses=' + encodeURIComponent(addresses.join(',')) + '&name=' + encodeURIComponent(dest.FullName)), attr.download(''), 'Open QR-code with link to .mobileconfig profile')));
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
