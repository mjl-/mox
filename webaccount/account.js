(() => {
	var __defProp = Object.defineProperty;
	var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

	// .js/lib.js
	var scriptblocks = [0, 128, 256, 384, 592, 688, 768, 880, 1024, 1280, 1328, 1424, 1536, 1792, 1872, 1920, 1984, 2048, 2112, 2144, 2160, 2208, 2304, 2432, 2560, 2688, 2816, 2944, 3072, 3200, 3328, 3456, 3584, 3712, 3840, 4096, 4256, 4352, 4608, 4992, 5024, 5120, 5760, 5792, 5888, 5920, 5952, 5984, 6016, 6144, 6320, 6400, 6480, 6528, 6624, 6656, 6688, 6832, 6912, 7040, 7104, 7168, 7248, 7296, 7312, 7360, 7376, 7424, 7552, 7616, 7680, 7936, 8192, 8304, 8352, 8400, 8448, 8528, 8592, 8704, 8960, 9216, 9280, 9312, 9472, 9600, 9632, 9728, 9984, 10176, 10224, 10240, 10496, 10624, 10752, 11008, 11264, 11360, 11392, 11520, 11568, 11648, 11744, 11776, 11904, 12032, 12272, 12288, 12352, 12448, 12544, 12592, 12688, 12704, 12736, 12784, 12800, 13056, 13312, 19904, 19968, 40960, 42128, 42192, 42240, 42560, 42656, 42752, 42784, 43008, 43056, 43072, 43136, 43232, 43264, 43312, 43360, 43392, 43488, 43520, 43616, 43648, 43744, 43776, 43824, 43888, 43968, 44032, 55216, 55296, 56192, 56320, 57344, 63744, 64256, 64336, 65024, 65040, 65056, 65072, 65104, 65136, 65280, 65520, 65536, 65664, 65792, 65856, 65936, 66e3, 66176, 66208, 66272, 66304, 66352, 66384, 66432, 66464, 66560, 66640, 66688, 66736, 66816, 66864, 66928, 67072, 67456, 67584, 67648, 67680, 67712, 67808, 67840, 67872, 67968, 68e3, 68096, 68192, 68224, 68288, 68352, 68416, 68448, 68480, 68608, 68736, 68864, 69216, 69248, 69312, 69376, 69424, 69488, 69552, 69600, 69632, 69760, 69840, 69888, 69968, 70016, 70112, 70144, 70272, 70320, 70400, 70656, 70784, 71040, 71168, 71264, 71296, 71424, 71680, 71840, 71936, 72096, 72192, 72272, 72368, 72384, 72448, 72704, 72816, 72960, 73056, 73440, 73472, 73648, 73664, 73728, 74752, 74880, 77712, 77824, 78896, 82944, 92160, 92736, 92784, 92880, 92928, 93760, 93952, 94176, 94208, 100352, 101120, 101632, 110576, 110592, 110848, 110896, 110960, 113664, 113824, 118528, 118784, 119040, 119296, 119488, 119520, 119552, 119648, 119808, 120832, 122624, 122880, 122928, 123136, 123536, 123584, 124112, 124896, 124928, 125184, 126064, 126208, 126464, 126976, 127024, 127136, 127232, 127488, 127744, 128512, 128592, 128640, 128768, 128896, 129024, 129280, 129536, 129648, 129792, 131072, 173824, 177984, 178208, 183984, 194560, 196608, 201552, 917504, 917760, 983040, 1048576];
	var findBlock = /* @__PURE__ */ __name((code) => {
		let s = 0;
		let e = scriptblocks.length;
		while (s < e - 1) {
			let i = Math.floor((s + e) / 2);
			if (code < scriptblocks[i]) {
				e = i;
			} else {
				s = i;
			}
		}
		return s;
	}, "findBlock");
	var formatText = /* @__PURE__ */ __name((e, s) => {
		if (!s) {
			return;
		}
		let ascii = true;
		for (const c of s) {
			const cp = c.codePointAt(0);
			if (cp !== void 0 && cp >= 128) {
				ascii = false;
				break;
			}
		}
		if (ascii) {
			e.appendChild(document.createTextNode(s));
			return;
		}
		let n = 0;
		let str = "";
		let block = -1;
		let mod = 1;
		const put = /* @__PURE__ */ __name((nextblock) => {
			if (n === 0 && nextblock === 0) {
				mod = 0;
			}
			if (n % 2 === mod) {
				const x = document.createElement("span");
				x.classList.add("scriptswitch");
				x.appendChild(document.createTextNode(str));
				e.appendChild(x);
			} else {
				e.appendChild(document.createTextNode(str));
			}
			n++;
			str = "";
		}, "put");
		for (const c of s) {
			if (c === " " || c === "	" || c === "\r" || c === "\n") {
				str += c;
				continue;
			}
			const code = c.codePointAt(0);
			if (block < 0 || !(code >= scriptblocks[block] && (code < scriptblocks[block + 1] || block === scriptblocks.length - 1))) {
				const nextblock = code < 128 ? 0 : findBlock(code);
				if (block >= 0) {
					put(nextblock);
				}
				block = nextblock;
			}
			str += c;
		}
		put(-1);
	}, "formatText");
	var _domKids = /* @__PURE__ */ __name((e, l) => {
		l.forEach((c) => {
			const xc = c;
			if (typeof c === "string") {
				formatText(e, c);
			} else if (c instanceof String) {
				e.appendChild(document.createTextNode("" + c));
			} else if (c instanceof Element) {
				e.appendChild(c);
			} else if (c instanceof Function) {
				if (!c.name) {
					throw new Error("function without name");
				}
				e.addEventListener(c.name, c);
			} else if (Array.isArray(xc)) {
				_domKids(e, c);
			} else if (xc._class) {
				for (const s of xc._class) {
					e.classList.toggle(s, true);
				}
			} else if (xc._attrs) {
				for (const k in xc._attrs) {
					e.setAttribute(k, xc._attrs[k]);
				}
			} else if (xc._styles) {
				for (const k in xc._styles) {
					const estyle = e.style;
					estyle[k] = xc._styles[k];
				}
			} else if (xc._props) {
				for (const k in xc._props) {
					const eprops = e;
					eprops[k] = xc._props[k];
				}
			} else if (xc.root) {
				e.appendChild(xc.root);
			} else {
				console.log("bad kid", c);
				throw new Error("bad kid");
			}
		});
		return e;
	}, "_domKids");
	var dom = {
		_kids: /* @__PURE__ */ __name(function(e, ...kl) {
			while (e.firstChild) {
				e.removeChild(e.firstChild);
			}
			_domKids(e, kl);
		}, "_kids"),
		_attrs: /* @__PURE__ */ __name((x) => {
			return { _attrs: x };
		}, "_attrs"),
		_class: /* @__PURE__ */ __name((...x) => {
			return { _class: x };
		}, "_class"),
		// The createElement calls are spelled out so typescript can derive function
		// signatures with a specific HTML*Element return type.
		div: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("div"), l), "div"),
		span: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("span"), l), "span"),
		a: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("a"), l), "a"),
		input: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("input"), l), "input"),
		textarea: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("textarea"), l), "textarea"),
		select: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("select"), l), "select"),
		option: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("option"), l), "option"),
		clickbutton: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("button"), [attr.type("button"), ...l]), "clickbutton"),
		submitbutton: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("button"), [attr.type("submit"), ...l]), "submitbutton"),
		form: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("form"), l), "form"),
		fieldset: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("fieldset"), l), "fieldset"),
		table: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("table"), l), "table"),
		thead: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("thead"), l), "thead"),
		tbody: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("tbody"), l), "tbody"),
		tfoot: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("tfoot"), l), "tfoot"),
		tr: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("tr"), l), "tr"),
		td: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("td"), l), "td"),
		th: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("th"), l), "th"),
		datalist: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("datalist"), l), "datalist"),
		h1: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("h1"), l), "h1"),
		h2: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("h2"), l), "h2"),
		h3: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("h3"), l), "h3"),
		br: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("br"), l), "br"),
		hr: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("hr"), l), "hr"),
		pre: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("pre"), l), "pre"),
		label: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("label"), l), "label"),
		ul: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("ul"), l), "ul"),
		li: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("li"), l), "li"),
		iframe: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("iframe"), l), "iframe"),
		b: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("b"), l), "b"),
		img: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("img"), l), "img"),
		style: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("style"), l), "style"),
		search: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("search"), l), "search"),
		p: /* @__PURE__ */ __name((...l) => _domKids(document.createElement("p"), l), "p")
	};
	var _attr = /* @__PURE__ */ __name((k, v) => {
		const o = {};
		o[k] = v;
		return { _attrs: o };
	}, "_attr");
	var attr = {
		title: /* @__PURE__ */ __name((s) => _attr("title", s), "title"),
		value: /* @__PURE__ */ __name((s) => _attr("value", s), "value"),
		type: /* @__PURE__ */ __name((s) => _attr("type", s), "type"),
		tabindex: /* @__PURE__ */ __name((s) => _attr("tabindex", s), "tabindex"),
		src: /* @__PURE__ */ __name((s) => _attr("src", s), "src"),
		placeholder: /* @__PURE__ */ __name((s) => _attr("placeholder", s), "placeholder"),
		href: /* @__PURE__ */ __name((s) => _attr("href", s), "href"),
		checked: /* @__PURE__ */ __name((s) => _attr("checked", s), "checked"),
		selected: /* @__PURE__ */ __name((s) => _attr("selected", s), "selected"),
		id: /* @__PURE__ */ __name((s) => _attr("id", s), "id"),
		datalist: /* @__PURE__ */ __name((s) => _attr("datalist", s), "datalist"),
		rows: /* @__PURE__ */ __name((s) => _attr("rows", s), "rows"),
		target: /* @__PURE__ */ __name((s) => _attr("target", s), "target"),
		rel: /* @__PURE__ */ __name((s) => _attr("rel", s), "rel"),
		required: /* @__PURE__ */ __name((s) => _attr("required", s), "required"),
		multiple: /* @__PURE__ */ __name((s) => _attr("multiple", s), "multiple"),
		download: /* @__PURE__ */ __name((s) => _attr("download", s), "download"),
		disabled: /* @__PURE__ */ __name((s) => _attr("disabled", s), "disabled"),
		draggable: /* @__PURE__ */ __name((s) => _attr("draggable", s), "draggable"),
		rowspan: /* @__PURE__ */ __name((s) => _attr("rowspan", s), "rowspan"),
		colspan: /* @__PURE__ */ __name((s) => _attr("colspan", s), "colspan"),
		for: /* @__PURE__ */ __name((s) => _attr("for", s), "for"),
		role: /* @__PURE__ */ __name((s) => _attr("role", s), "role"),
		arialabel: /* @__PURE__ */ __name((s) => _attr("aria-label", s), "arialabel"),
		arialive: /* @__PURE__ */ __name((s) => _attr("aria-live", s), "arialive"),
		name: /* @__PURE__ */ __name((s) => _attr("name", s), "name"),
		min: /* @__PURE__ */ __name((s) => _attr("min", s), "min"),
		max: /* @__PURE__ */ __name((s) => _attr("max", s), "max"),
		action: /* @__PURE__ */ __name((s) => _attr("action", s), "action"),
		method: /* @__PURE__ */ __name((s) => _attr("method", s), "method"),
		autocomplete: /* @__PURE__ */ __name((s) => _attr("autocomplete", s), "autocomplete"),
		list: /* @__PURE__ */ __name((s) => _attr("list", s), "list"),
		form: /* @__PURE__ */ __name((s) => _attr("form", s), "form"),
		size: /* @__PURE__ */ __name((s) => _attr("size", s), "size")
	};
	var style = /* @__PURE__ */ __name((x) => {
		return { _styles: x };
	}, "style");

	// .js/webaccount/api.js
	var OutgoingEvent;
	(function(OutgoingEvent2) {
		OutgoingEvent2["EventDelivered"] = "delivered";
		OutgoingEvent2["EventSuppressed"] = "suppressed";
		OutgoingEvent2["EventDelayed"] = "delayed";
		OutgoingEvent2["EventFailed"] = "failed";
		OutgoingEvent2["EventRelayed"] = "relayed";
		OutgoingEvent2["EventExpanded"] = "expanded";
		OutgoingEvent2["EventCanceled"] = "canceled";
		OutgoingEvent2["EventUnrecognized"] = "unrecognized";
	})(OutgoingEvent || (OutgoingEvent = {}));
	var AuthResult;
	(function(AuthResult2) {
		AuthResult2["AuthSuccess"] = "ok";
		AuthResult2["AuthBadUser"] = "baduser";
		AuthResult2["AuthBadPassword"] = "badpassword";
		AuthResult2["AuthBadCredentials"] = "badcreds";
		AuthResult2["AuthBadChannelBinding"] = "badchanbind";
		AuthResult2["AuthBadProtocol"] = "badprotocol";
		AuthResult2["AuthLoginDisabled"] = "logindisabled";
		AuthResult2["AuthError"] = "error";
		AuthResult2["AuthAborted"] = "aborted";
	})(AuthResult || (AuthResult = {}));
	var structTypes = { "Account": true, "Address": true, "AddressAlias": true, "Alias": true, "AliasAddress": true, "AutomaticJunkFlags": true, "Destination": true, "Domain": true, "ImportProgress": true, "Incoming": true, "IncomingMeta": true, "IncomingWebhook": true, "JunkFilter": true, "LoginAttempt": true, "NameAddress": true, "Outgoing": true, "OutgoingWebhook": true, "Route": true, "Ruleset": true, "Structure": true, "SubjectPass": true, "Suppression": true, "TLSPublicKey": true };
	var stringsTypes = { "AuthResult": true, "CSRFToken": true, "Localpart": true, "OutgoingEvent": true };
	var intsTypes = {};
	var types = {
		"Account": { "Name": "Account", "Docs": "", "Fields": [{ "Name": "OutgoingWebhook", "Docs": "", "Typewords": ["nullable", "OutgoingWebhook"] }, { "Name": "IncomingWebhook", "Docs": "", "Typewords": ["nullable", "IncomingWebhook"] }, { "Name": "FromIDLoginAddresses", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "KeepRetiredMessagePeriod", "Docs": "", "Typewords": ["int64"] }, { "Name": "KeepRetiredWebhookPeriod", "Docs": "", "Typewords": ["int64"] }, { "Name": "LoginDisabled", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Description", "Docs": "", "Typewords": ["string"] }, { "Name": "FullName", "Docs": "", "Typewords": ["string"] }, { "Name": "Destinations", "Docs": "", "Typewords": ["{}", "Destination"] }, { "Name": "SubjectPass", "Docs": "", "Typewords": ["SubjectPass"] }, { "Name": "QuotaMessageSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "RejectsMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "KeepRejects", "Docs": "", "Typewords": ["bool"] }, { "Name": "Introbox", "Docs": "", "Typewords": ["string"] }, { "Name": "AutomaticJunkFlags", "Docs": "", "Typewords": ["AutomaticJunkFlags"] }, { "Name": "JunkFilter", "Docs": "", "Typewords": ["nullable", "JunkFilter"] }, { "Name": "MaxOutgoingMessagesPerDay", "Docs": "", "Typewords": ["int32"] }, { "Name": "MaxFirstTimeRecipientsPerDay", "Docs": "", "Typewords": ["int32"] }, { "Name": "NoFirstTimeSenderDelay", "Docs": "", "Typewords": ["bool"] }, { "Name": "NoCustomPassword", "Docs": "", "Typewords": ["bool"] }, { "Name": "IMAPCapabilitiesDisabled", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Routes", "Docs": "", "Typewords": ["[]", "Route"] }, { "Name": "DNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "Aliases", "Docs": "", "Typewords": ["[]", "AddressAlias"] }] },
		"OutgoingWebhook": { "Name": "OutgoingWebhook", "Docs": "", "Fields": [{ "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Authorization", "Docs": "", "Typewords": ["string"] }, { "Name": "Events", "Docs": "", "Typewords": ["[]", "string"] }] },
		"IncomingWebhook": { "Name": "IncomingWebhook", "Docs": "", "Fields": [{ "Name": "URL", "Docs": "", "Typewords": ["string"] }, { "Name": "Authorization", "Docs": "", "Typewords": ["string"] }] },
		"Destination": { "Name": "Destination", "Docs": "", "Fields": [{ "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Rulesets", "Docs": "", "Typewords": ["[]", "Ruleset"] }, { "Name": "SMTPError", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageAuthRequiredSMTPError", "Docs": "", "Typewords": ["string"] }, { "Name": "FullName", "Docs": "", "Typewords": ["string"] }] },
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
		"Structure": { "Name": "Structure", "Docs": "", "Fields": [{ "Name": "ContentType", "Docs": "", "Typewords": ["string"] }, { "Name": "ContentTypeParams", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "ContentID", "Docs": "", "Typewords": ["string"] }, { "Name": "ContentDisposition", "Docs": "", "Typewords": ["string"] }, { "Name": "Filename", "Docs": "", "Typewords": ["string"] }, { "Name": "DecodedSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "Parts", "Docs": "", "Typewords": ["[]", "Structure"] }] },
		"IncomingMeta": { "Name": "IncomingMeta", "Docs": "", "Fields": [{ "Name": "MsgID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "MsgFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "RcptTo", "Docs": "", "Typewords": ["string"] }, { "Name": "DKIMVerifiedDomains", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "RemoteIP", "Docs": "", "Typewords": ["string"] }, { "Name": "Received", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Automated", "Docs": "", "Typewords": ["bool"] }] },
		"TLSPublicKey": { "Name": "TLSPublicKey", "Docs": "", "Fields": [{ "Name": "Fingerprint", "Docs": "", "Typewords": ["string"] }, { "Name": "Created", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Type", "Docs": "", "Typewords": ["string"] }, { "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "NoIMAPPreauth", "Docs": "", "Typewords": ["bool"] }, { "Name": "CertDER", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Account", "Docs": "", "Typewords": ["string"] }, { "Name": "LoginAddress", "Docs": "", "Typewords": ["string"] }] },
		"LoginAttempt": { "Name": "LoginAttempt", "Docs": "", "Fields": [{ "Name": "Key", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Last", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "First", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Count", "Docs": "", "Typewords": ["int64"] }, { "Name": "AccountName", "Docs": "", "Typewords": ["string"] }, { "Name": "LoginAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIP", "Docs": "", "Typewords": ["string"] }, { "Name": "LocalIP", "Docs": "", "Typewords": ["string"] }, { "Name": "TLS", "Docs": "", "Typewords": ["string"] }, { "Name": "TLSPubKeyFingerprint", "Docs": "", "Typewords": ["string"] }, { "Name": "Protocol", "Docs": "", "Typewords": ["string"] }, { "Name": "UserAgent", "Docs": "", "Typewords": ["string"] }, { "Name": "AuthMech", "Docs": "", "Typewords": ["string"] }, { "Name": "Result", "Docs": "", "Typewords": ["AuthResult"] }] },
		"CSRFToken": { "Name": "CSRFToken", "Docs": "", "Values": null },
		"Localpart": { "Name": "Localpart", "Docs": "", "Values": null },
		"OutgoingEvent": { "Name": "OutgoingEvent", "Docs": "", "Values": [{ "Name": "EventDelivered", "Value": "delivered", "Docs": "" }, { "Name": "EventSuppressed", "Value": "suppressed", "Docs": "" }, { "Name": "EventDelayed", "Value": "delayed", "Docs": "" }, { "Name": "EventFailed", "Value": "failed", "Docs": "" }, { "Name": "EventRelayed", "Value": "relayed", "Docs": "" }, { "Name": "EventExpanded", "Value": "expanded", "Docs": "" }, { "Name": "EventCanceled", "Value": "canceled", "Docs": "" }, { "Name": "EventUnrecognized", "Value": "unrecognized", "Docs": "" }] },
		"AuthResult": { "Name": "AuthResult", "Docs": "", "Values": [{ "Name": "AuthSuccess", "Value": "ok", "Docs": "" }, { "Name": "AuthBadUser", "Value": "baduser", "Docs": "" }, { "Name": "AuthBadPassword", "Value": "badpassword", "Docs": "" }, { "Name": "AuthBadCredentials", "Value": "badcreds", "Docs": "" }, { "Name": "AuthBadChannelBinding", "Value": "badchanbind", "Docs": "" }, { "Name": "AuthBadProtocol", "Value": "badprotocol", "Docs": "" }, { "Name": "AuthLoginDisabled", "Value": "logindisabled", "Docs": "" }, { "Name": "AuthError", "Value": "error", "Docs": "" }, { "Name": "AuthAborted", "Value": "aborted", "Docs": "" }] }
	};
	var parser = {
		Account: /* @__PURE__ */ __name((v) => parse("Account", v), "Account"),
		OutgoingWebhook: /* @__PURE__ */ __name((v) => parse("OutgoingWebhook", v), "OutgoingWebhook"),
		IncomingWebhook: /* @__PURE__ */ __name((v) => parse("IncomingWebhook", v), "IncomingWebhook"),
		Destination: /* @__PURE__ */ __name((v) => parse("Destination", v), "Destination"),
		Ruleset: /* @__PURE__ */ __name((v) => parse("Ruleset", v), "Ruleset"),
		Domain: /* @__PURE__ */ __name((v) => parse("Domain", v), "Domain"),
		SubjectPass: /* @__PURE__ */ __name((v) => parse("SubjectPass", v), "SubjectPass"),
		AutomaticJunkFlags: /* @__PURE__ */ __name((v) => parse("AutomaticJunkFlags", v), "AutomaticJunkFlags"),
		JunkFilter: /* @__PURE__ */ __name((v) => parse("JunkFilter", v), "JunkFilter"),
		Route: /* @__PURE__ */ __name((v) => parse("Route", v), "Route"),
		AddressAlias: /* @__PURE__ */ __name((v) => parse("AddressAlias", v), "AddressAlias"),
		Alias: /* @__PURE__ */ __name((v) => parse("Alias", v), "Alias"),
		AliasAddress: /* @__PURE__ */ __name((v) => parse("AliasAddress", v), "AliasAddress"),
		Address: /* @__PURE__ */ __name((v) => parse("Address", v), "Address"),
		Suppression: /* @__PURE__ */ __name((v) => parse("Suppression", v), "Suppression"),
		ImportProgress: /* @__PURE__ */ __name((v) => parse("ImportProgress", v), "ImportProgress"),
		Outgoing: /* @__PURE__ */ __name((v) => parse("Outgoing", v), "Outgoing"),
		Incoming: /* @__PURE__ */ __name((v) => parse("Incoming", v), "Incoming"),
		NameAddress: /* @__PURE__ */ __name((v) => parse("NameAddress", v), "NameAddress"),
		Structure: /* @__PURE__ */ __name((v) => parse("Structure", v), "Structure"),
		IncomingMeta: /* @__PURE__ */ __name((v) => parse("IncomingMeta", v), "IncomingMeta"),
		TLSPublicKey: /* @__PURE__ */ __name((v) => parse("TLSPublicKey", v), "TLSPublicKey"),
		LoginAttempt: /* @__PURE__ */ __name((v) => parse("LoginAttempt", v), "LoginAttempt"),
		CSRFToken: /* @__PURE__ */ __name((v) => parse("CSRFToken", v), "CSRFToken"),
		Localpart: /* @__PURE__ */ __name((v) => parse("Localpart", v), "Localpart"),
		OutgoingEvent: /* @__PURE__ */ __name((v) => parse("OutgoingEvent", v), "OutgoingEvent"),
		AuthResult: /* @__PURE__ */ __name((v) => parse("AuthResult", v), "AuthResult")
	};
	var defaultOptions = { slicesNullable: true, mapsNullable: true, nullableOptional: true };
	var Client = class _Client {
		static {
			__name(this, "Client");
		}
		baseURL;
		authState;
		options;
		constructor() {
			this.authState = {};
			this.options = { ...defaultOptions };
			this.baseURL = this.options.baseURL || defaultBaseURL;
		}
		withAuthToken(token) {
			const c = new _Client();
			c.authState.token = token;
			c.options = this.options;
			return c;
		}
		withOptions(options) {
			const c = new _Client();
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
		// SetPassword saves a new password for the account, invalidating the previous
		// password.
		// 
		// Sessions are not interrupted, and will keep working. New login attempts must use
		// the new password.
		// 
		// Password must be at least 8 characters.
		// 
		// Setting a user-supplied password is not allowed if NoCustomPassword is set
		// for the account.
		async SetPassword(password) {
			const fn = "SetPassword";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [password];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// GeneratePassword sets a new randomly generated password for the current account.
		// Sessions are not interrupted, and will keep working.
		async GeneratePassword() {
			const fn = "GeneratePassword";
			const paramTypes = [];
			const returnTypes = [["string"]];
			const params = [];
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
		// IntroboxSave saves the mailbox for messages from senders with no established
		// reputation, creating it if it does not exist. The mailbox cannot be Inbox and
		// must be different from RejectsMailbox. If empty, the introbox is disabled.
		async IntroboxSave(mailbox) {
			const fn = "IntroboxSave";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [mailbox];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async TLSPublicKeys() {
			const fn = "TLSPublicKeys";
			const paramTypes = [];
			const returnTypes = [["[]", "TLSPublicKey"]];
			const params = [];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async TLSPublicKeyAdd(loginAddress, name, noIMAPPreauth, certPEM) {
			const fn = "TLSPublicKeyAdd";
			const paramTypes = [["string"], ["string"], ["bool"], ["string"]];
			const returnTypes = [["TLSPublicKey"]];
			const params = [loginAddress, name, noIMAPPreauth, certPEM];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async TLSPublicKeyRemove(fingerprint) {
			const fn = "TLSPublicKeyRemove";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [fingerprint];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async TLSPublicKeyUpdate(pubKey) {
			const fn = "TLSPublicKeyUpdate";
			const paramTypes = [["TLSPublicKey"]];
			const returnTypes = [];
			const params = [pubKey];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async LoginAttempts(limit) {
			const fn = "LoginAttempts";
			const paramTypes = [["int32"]];
			const returnTypes = [["[]", "LoginAttempt"]];
			const params = [limit];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async IMAPSave(capabilitiesDisabled) {
			const fn = "IMAPSave";
			const paramTypes = [["[]", "string"]];
			const returnTypes = [];
			const params = [capabilitiesDisabled];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
	};
	var defaultBaseURL = (function() {
		let p = location.pathname;
		if (p && p[p.length - 1] !== "/") {
			let l = location.pathname.split("/");
			l = l.slice(0, l.length - 1);
			p = "/" + l.join("/") + "/";
		}
		return location.protocol + "//" + location.host + p + "api/";
	})();
	var verifyArg = /* @__PURE__ */ __name((path, v, typewords, toJS, allowUnknownKeys, types2, opts) => {
		return new verifier(types2, toJS, allowUnknownKeys, opts).verify(path, v, typewords);
	}, "verifyArg");
	var parse = /* @__PURE__ */ __name((name, v) => verifyArg(name, v, [name], true, false, types, defaultOptions), "parse");
	var verifier = class {
		static {
			__name(this, "verifier");
		}
		types;
		toJS;
		allowUnknownKeys;
		opts;
		constructor(types2, toJS, allowUnknownKeys, opts) {
			this.types = types2;
			this.toJS = toJS;
			this.allowUnknownKeys = allowUnknownKeys;
			this.opts = opts;
		}
		verify(path, v, typewords) {
			typewords = typewords.slice(0);
			const ww = typewords.shift();
			const error = /* @__PURE__ */ __name((msg) => {
				if (path != "") {
					msg = path + ": " + msg;
				}
				throw new Error(msg);
			}, "error");
			if (typeof ww !== "string") {
				error("bad typewords");
				return;
			}
			const w = ww;
			const ensure = /* @__PURE__ */ __name((ok, expect) => {
				if (!ok) {
					error("got " + JSON.stringify(v) + ", expected " + expect);
				}
				return v;
			}, "ensure");
			switch (w) {
				case "nullable":
					if (v === null || v === void 0 && this.opts.nullableOptional) {
						return v;
					}
					return this.verify(path, v, typewords);
				case "[]":
					if (v === null && this.opts.slicesNullable || v === void 0 && this.opts.slicesNullable && this.opts.nullableOptional) {
						return v;
					}
					ensure(Array.isArray(v), "array");
					return v.map((e, i) => this.verify(path + "[" + i + "]", e, typewords));
				case "{}":
					if (v === null && this.opts.mapsNullable || v === void 0 && this.opts.mapsNullable && this.opts.nullableOptional) {
						return v;
					}
					ensure(v !== null || typeof v === "object", "object");
					const r = {};
					for (const k in v) {
						r[k] = this.verify(path + "." + k, v[k], typewords);
					}
					return r;
			}
			ensure(typewords.length == 0, "empty typewords");
			const t = typeof v;
			switch (w) {
				case "any":
					return v;
				case "bool":
					ensure(t === "boolean", "bool");
					return v;
				case "int8":
				case "uint8":
				case "int16":
				case "uint16":
				case "int32":
				case "uint32":
				case "int64":
				case "uint64":
					ensure(t === "number" && Number.isInteger(v), "integer");
					return v;
				case "float32":
				case "float64":
					ensure(t === "number", "float");
					return v;
				case "int64s":
				case "uint64s":
					ensure(t === "number" && Number.isInteger(v) || t === "string", "integer fitting in float without precision loss, or string");
					return "" + v;
				case "string":
					ensure(t === "string", "string");
					return v;
				case "timestamp":
					if (this.toJS) {
						ensure(t === "string", "string, with timestamp");
						const d = new Date(v);
						if (d instanceof Date && !isNaN(d.getTime())) {
							return d;
						}
						error("invalid date " + v);
					} else {
						ensure(t === "object" && v !== null, "non-null object");
						ensure(v.__proto__ === Date.prototype, "Date");
						return v.toISOString();
					}
			}
			const nt = this.types[w];
			if (!nt) {
				error("unknown type " + w);
			}
			if (v === null) {
				error("bad value " + v + " for named type " + w);
			}
			if (structTypes[nt.Name]) {
				const t2 = nt;
				if (typeof v !== "object") {
					error("bad value " + v + " for struct " + w);
				}
				const r = {};
				for (const f of t2.Fields) {
					r[f.Name] = this.verify(path + "." + f.Name, v[f.Name], f.Typewords);
				}
				if (!this.allowUnknownKeys) {
					const known = {};
					for (const f of t2.Fields) {
						known[f.Name] = true;
					}
					Object.keys(v).forEach((k) => {
						if (!known[k]) {
							error("unknown key " + k + " for struct " + w);
						}
					});
				}
				return r;
			} else if (stringsTypes[nt.Name]) {
				const t2 = nt;
				if (typeof v !== "string") {
					error("mistyped value " + v + " for named strings " + t2.Name);
				}
				if (!t2.Values || t2.Values.length === 0) {
					return v;
				}
				for (const sv of t2.Values) {
					if (sv.Value === v) {
						return v;
					}
				}
				error("unknown value " + v + " for named strings " + t2.Name);
			} else if (intsTypes[nt.Name]) {
				const t2 = nt;
				if (typeof v !== "number" || !Number.isInteger(v)) {
					error("mistyped value " + v + " for named ints " + t2.Name);
				}
				if (!t2.Values || t2.Values.length === 0) {
					return v;
				}
				for (const sv of t2.Values) {
					if (sv.Value === v) {
						return v;
					}
				}
				error("unknown value " + v + " for named ints " + t2.Name);
			} else {
				throw new Error("unexpected named type " + nt);
			}
		}
	};
	var _sherpaCall = /* @__PURE__ */ __name(async (baseURL, authState, options, paramTypes, returnTypes, name, params) => {
		if (!options.skipParamCheck) {
			if (params.length !== paramTypes.length) {
				return Promise.reject({ message: "wrong number of parameters in sherpa call, saw " + params.length + " != expected " + paramTypes.length });
			}
			params = params.map((v, index2) => verifyArg("params[" + index2 + "]", v, paramTypes[index2], false, false, types, options));
		}
		const simulate = /* @__PURE__ */ __name(async (json2) => {
			const config = JSON.parse(json2 || "null") || {};
			const waitMinMsec = config.waitMinMsec || 0;
			const waitMaxMsec = config.waitMaxMsec || 0;
			const wait = Math.random() * (waitMaxMsec - waitMinMsec);
			const failRate = config.failRate || 0;
			return new Promise((resolve, reject) => {
				if (options.aborter) {
					options.aborter.abort = () => {
						reject({ message: "call to " + name + " aborted by user", code: "sherpa:aborted" });
						reject = resolve = /* @__PURE__ */ __name(() => {
						}, "resolve");
					};
				}
				setTimeout(() => {
					const r = Math.random();
					if (r < failRate) {
						reject({ message: "injected failure on " + name, code: "server:injected" });
					} else {
						resolve();
					}
					reject = resolve = /* @__PURE__ */ __name(() => {
					}, "resolve");
				}, waitMinMsec + wait);
			});
		}, "simulate");
		let json = "";
		try {
			json = window.localStorage.getItem("sherpats-debug") || "";
		} catch (err) {
		}
		if (json) {
			await simulate(json);
		}
		const fn = /* @__PURE__ */ __name((resolve, reject) => {
			let resolve1 = /* @__PURE__ */ __name((v) => {
				resolve(v);
				resolve1 = /* @__PURE__ */ __name(() => {
				}, "resolve1");
				reject1 = /* @__PURE__ */ __name(() => {
				}, "reject1");
			}, "resolve1");
			let reject1 = /* @__PURE__ */ __name((v) => {
				if ((v.code === "user:noAuth" || v.code === "user:badAuth") && options.login) {
					const login2 = options.login;
					if (!authState.loginPromise) {
						authState.loginPromise = new Promise((aresolve, areject) => {
							login2(v.code === "user:badAuth" ? v.message || "" : "").then((token) => {
								authState.token = token;
								authState.loginPromise = void 0;
								aresolve();
							}, (err) => {
								authState.loginPromise = void 0;
								areject(err);
							});
						});
					}
					authState.loginPromise.then(() => {
						fn(resolve, reject);
					}, (err) => {
						reject(err);
					});
					return;
				}
				reject(v);
				resolve1 = /* @__PURE__ */ __name(() => {
				}, "resolve1");
				reject1 = /* @__PURE__ */ __name(() => {
				}, "reject1");
			}, "reject1");
			const url = baseURL + name;
			const req = new window.XMLHttpRequest();
			if (options.aborter) {
				options.aborter.abort = () => {
					req.abort();
					reject1({ code: "sherpa:aborted", message: "request aborted" });
				};
			}
			req.open("POST", url, true);
			if (options.csrfHeader && authState.token) {
				req.setRequestHeader(options.csrfHeader, authState.token);
			}
			if (options.timeoutMsec) {
				req.timeout = options.timeoutMsec;
			}
			req.onload = () => {
				if (req.status !== 200) {
					if (req.status === 404) {
						reject1({ code: "sherpa:badFunction", message: "function does not exist" });
					} else {
						reject1({ code: "sherpa:http", message: "error calling function, HTTP status: " + req.status });
					}
					return;
				}
				let resp;
				try {
					resp = JSON.parse(req.responseText);
				} catch (err) {
					reject1({ code: "sherpa:badResponse", message: "bad JSON from server" });
					return;
				}
				if (resp && resp.error) {
					const err = resp.error;
					reject1({ code: err.code, message: err.message });
					return;
				} else if (!resp || !resp.hasOwnProperty("result")) {
					reject1({ code: "sherpa:badResponse", message: "invalid sherpa response object, missing 'result'" });
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
							throw new Error("function " + name + ' returned a value while prototype says it returns "void"');
						}
					} else if (returnTypes.length === 1) {
						result = verifyArg("result", result, returnTypes[0], true, true, types, options);
					} else {
						if (result.length != returnTypes.length) {
							throw new Error("wrong number of values returned by " + name + ", saw " + result.length + " != expected " + returnTypes.length);
						}
						result = result.map((v, index2) => verifyArg("result[" + index2 + "]", v, returnTypes[index2], true, true, types, options));
					}
				} catch (err) {
					let errmsg2 = "bad types";
					if (err instanceof Error) {
						errmsg2 = err.message;
					}
					reject1({ code: "sherpa:badTypes", message: errmsg2 });
				}
				resolve1(result);
			};
			req.onerror = () => {
				reject1({ code: "sherpa:connection", message: "connection failed" });
			};
			req.ontimeout = () => {
				reject1({ code: "sherpa:timeout", message: "request timeout" });
			};
			req.setRequestHeader("Content-Type", "application/json");
			try {
				req.send(JSON.stringify({ params }));
			} catch (err) {
				reject1({ code: "sherpa:badData", message: "cannot marshal to JSON" });
			}
		}, "fn");
		return await new Promise(fn);
	}, "_sherpaCall");

	// .js/webaccount/account.js
	var moxversion;
	var moxgoos;
	var moxgoarch;
	var login = /* @__PURE__ */ __name(async (reason) => {
		return new Promise((resolve, _) => {
			const origFocus = document.activeElement;
			let reasonElem;
			let fieldset;
			let autosize;
			let username;
			let password;
			const root = dom.div(style({ position: "absolute", top: 0, right: 0, bottom: 0, left: 0, backgroundColor: "#eee", display: "flex", alignItems: "center", justifyContent: "center", zIndex: "1", animation: "fadein .15s ease-in" }), dom.div(style({ display: "flex", flexDirection: "column", alignItems: "center" }), reasonElem = reason ? dom.div(style({ marginBottom: "2ex", textAlign: "center" }), reason) : dom.div(), dom.div(style({ backgroundColor: "white", borderRadius: ".25em", padding: "1em", boxShadow: "0 0 20px rgba(0, 0, 0, 0.1)", border: "1px solid #ddd", maxWidth: "95vw", overflowX: "auto", maxHeight: "95vh", overflowY: "auto", marginBottom: "20vh" }), dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				reasonElem.remove();
				try {
					fieldset.disabled = true;
					const loginToken = await client.LoginPrep();
					const token = await client.Login(loginToken, username.value, password.value);
					try {
						window.localStorage.setItem("webaccountaddress", username.value);
						window.localStorage.setItem("webaccountcsrftoken", token);
					} catch (err) {
						console.log("saving csrf token in localStorage", err);
					}
					root.remove();
					if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
						origFocus.focus();
					}
					resolve(token);
				} catch (err) {
					console.log("login error", err);
					window.alert("Error: " + errmsg(err));
				} finally {
					fieldset.disabled = false;
				}
			}, "submit"), fieldset = dom.fieldset(dom.h1("Account"), dom.label(style({ display: "block", marginBottom: "2ex" }), dom.div("Email address", style({ marginBottom: ".5ex" })), autosize = dom.span(dom._class("autosize"), username = dom.input(attr.required(""), attr.autocomplete("email"), attr.placeholder("jane@example.org"), /* @__PURE__ */ __name(function change() {
				autosize.dataset.value = username.value;
			}, "change"), /* @__PURE__ */ __name(function input() {
				autosize.dataset.value = username.value;
			}, "input")))), dom.label(style({ display: "block", marginBottom: "2ex" }), dom.div("Password", style({ marginBottom: ".5ex" })), password = dom.input(attr.type("password"), attr.autocomplete("current-password"), attr.required(""))), dom.div(style({ textAlign: "center" }), dom.submitbutton("Login")))))));
			document.body.appendChild(root);
			username.focus();
		});
	}, "login");
	var popup = /* @__PURE__ */ __name((...kids) => {
		const origFocus = document.activeElement;
		const close = /* @__PURE__ */ __name(() => {
			if (!root.parentNode) {
				return;
			}
			root.remove();
			if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
				origFocus.focus();
			}
		}, "close");
		let content;
		const root = dom.div(style({ position: "fixed", top: 0, right: 0, bottom: 0, left: 0, backgroundColor: "rgba(0, 0, 0, 0.1)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: "1" }), /* @__PURE__ */ __name(function keydown(e) {
			if (e.key === "Escape") {
				e.stopPropagation();
				close();
			}
		}, "keydown"), /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
			close();
		}, "click"), content = dom.div(attr.tabindex("0"), style({ backgroundColor: "white", borderRadius: ".25em", padding: "1em", boxShadow: "0 0 20px rgba(0, 0, 0, 0.1)", border: "1px solid #ddd", maxWidth: "95vw", overflowX: "auto", maxHeight: "95vh", overflowY: "auto" }), /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
		}, "click"), kids));
		document.body.appendChild(root);
		content.focus();
		return close;
	}, "popup");
	var localStorageGet = /* @__PURE__ */ __name((k) => {
		try {
			return window.localStorage.getItem(k);
		} catch (err) {
			return null;
		}
	}, "localStorageGet");
	var localStorageRemove = /* @__PURE__ */ __name((k) => {
		try {
			return window.localStorage.removeItem(k);
		} catch (err) {
		}
	}, "localStorageRemove");
	var check = /* @__PURE__ */ __name(async (elem, p) => {
		try {
			elem.disabled = true;
			return await p;
		} catch (err) {
			console.log({ err });
			window.alert("Error: " + errmsg(err));
			throw err;
		} finally {
			elem.disabled = false;
		}
	}, "check");
	var prewrap = /* @__PURE__ */ __name((...l) => dom.span(style({ whiteSpace: "pre-wrap" }), l), "prewrap");
	var client = new Client().withOptions({ csrfHeader: "x-mox-csrf", login }).withAuthToken(localStorageGet("webaccountcsrftoken") || "");
	var link = /* @__PURE__ */ __name((href, anchorOpt) => dom.a(attr.href(href), attr.rel("noopener noreferrer"), anchorOpt || href), "link");
	var crumblink = /* @__PURE__ */ __name((text, path) => {
		return {
			text,
			path
		};
	}, "crumblink");
	var crumbs = /* @__PURE__ */ __name((...l) => {
		const crumbtext = /* @__PURE__ */ __name((e) => typeof e === "string" ? e : e.text, "crumbtext");
		document.title = l.map((e) => crumbtext(e)).join(" - ");
		const crumblink2 = /* @__PURE__ */ __name((e) => typeof e === "string" ? prewrap(e) : dom.a(e.text, attr.href(e.path)), "crumblink");
		return [
			dom.div(style({ float: "right" }), localStorageGet("webaccountaddress") || "(unknown)", " ", dom.clickbutton("Logout", attr.title("Logout, invalidating this session."), /* @__PURE__ */ __name(async function click(e) {
				const b = e.target;
				try {
					b.disabled = true;
					await client.Logout();
				} catch (err) {
					console.log("logout", err);
					window.alert("Error: " + errmsg(err));
				} finally {
					b.disabled = false;
				}
				localStorageRemove("webaccountaddress");
				localStorageRemove("webaccountcsrftoken");
				window.location.reload();
			}, "click"))),
			dom.h1(l.map((e, index2) => index2 === 0 ? crumblink2(e) : [" / ", crumblink2(e)])),
			dom.br()
		];
	}, "crumbs");
	var errmsg = /* @__PURE__ */ __name((err) => "" + (err.message || "(no error message)"), "errmsg");
	var footer = /* @__PURE__ */ __name(() => dom.div(style({ marginTop: "6ex", opacity: 0.75 }), link("https://www.xmox.nl", "mox"), " ", moxversion, moxgoos, "/", moxgoarch, ", ", dom.a(attr.href("licenses.txt"), "licenses")), "footer");
	var domainName = /* @__PURE__ */ __name((d) => {
		return d.Unicode || d.ASCII;
	}, "domainName");
	var domainString = /* @__PURE__ */ __name((d) => {
		if (d.Unicode) {
			return d.Unicode + " (" + d.ASCII + ")";
		}
		return d.ASCII;
	}, "domainString");
	var box = /* @__PURE__ */ __name((color, ...l) => [
		dom.div(style({
			display: "inline-block",
			padding: ".125em .25em",
			backgroundColor: color,
			borderRadius: "3px",
			margin: ".5ex 0"
		}), l),
		dom.br()
	], "box");
	var yellow = "#ffe400";
	var red = "#ff7443";
	var blue = "#8bc8ff";
	var age = /* @__PURE__ */ __name((date) => {
		const r = dom.span(dom._class("notooltip"), attr.title(date.toString()));
		const nowSecs = (/* @__PURE__ */ new Date()).getTime() / 1e3;
		let t = nowSecs - date.getTime() / 1e3;
		let negative = "";
		if (t < 0) {
			negative = "-";
			t = -t;
		}
		const minute = 60;
		const hour = 60 * minute;
		const day = 24 * hour;
		const month = 30 * day;
		const year = 365 * day;
		const periods = [year, month, day, hour, minute];
		const suffix = ["y", "mo", "d", "h", "min"];
		let s;
		for (let i = 0; i < periods.length; i++) {
			const p = periods[i];
			if (t >= 2 * p || i === periods.length - 1) {
				const n = Math.round(t / p);
				s = "" + n + suffix[i];
				break;
			}
		}
		if (t < 60) {
			s = "<1min";
			negative = "";
		}
		dom._kids(r, negative + s);
		return r;
	}, "age");
	var formatQuotaSize = /* @__PURE__ */ __name((v) => {
		if (v === 0) {
			return "0";
		}
		const m = 1024 * 1024;
		const g = m * 1024;
		const t = g * 1024;
		if (Math.floor(v / t) * t === v) {
			return "" + v / t + "t";
		} else if (Math.floor(v / g) * g === v) {
			return "" + v / g + "g";
		} else if (Math.floor(v / m) * m === v) {
			return "" + v / m + "m";
		}
		return "" + v;
	}, "formatQuotaSize");
	var index = /* @__PURE__ */ __name(async () => {
		const [[acc, storageUsed, storageLimit, suppressions], tlspubkeys0, recentLoginAttempts] = await Promise.all([
			client.Account(),
			client.TLSPublicKeys(),
			client.LoginAttempts(10)
		]);
		const tlspubkeys = tlspubkeys0 || [];
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
		let introboxFieldset;
		let introboxMailbox;
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
		const second = 1e3 * 1e3 * 1e3;
		const minute = 60 * second;
		const hour = 60 * minute;
		const day = 24 * hour;
		const week = 7 * day;
		const parseDuration = /* @__PURE__ */ __name((s) => {
			if (!s) {
				return 0;
			}
			const xparseint = /* @__PURE__ */ __name(() => {
				const v = parseInt(s.substring(0, s.length - 1));
				if (isNaN(v) || Math.round(v) !== v) {
					throw new Error("bad number in duration");
				}
				return v;
			}, "xparseint");
			if (s.endsWith("w")) {
				return xparseint() * week;
			}
			if (s.endsWith("d")) {
				return xparseint() * day;
			}
			if (s.endsWith("h")) {
				return xparseint() * hour;
			}
			if (s.endsWith("m")) {
				return xparseint() * minute;
			}
			if (s.endsWith("s")) {
				return xparseint() * second;
			}
			throw new Error("bad duration " + s);
		}, "parseDuration");
		const formatDuration = /* @__PURE__ */ __name((v) => {
			if (v === 0) {
				return "";
			}
			const is = /* @__PURE__ */ __name((period) => v > 0 && Math.round(v / period) === v / period, "is");
			const format = /* @__PURE__ */ __name((period, s) => "" + v / period + s, "format");
			if (is(week)) {
				return format(week, "w");
			}
			if (is(day)) {
				return format(day, "d");
			}
			if (is(hour)) {
				return format(hour, "h");
			}
			if (is(minute)) {
				return format(minute, "m");
			}
			return format(second, "s");
		}, "formatDuration");
		let importForm;
		let importFieldset;
		let mailboxFileHint;
		let mailboxPrefixHint;
		let importProgress;
		let importAbortBox;
		let suppressionAddress;
		let suppressionReason;
		let imapFieldset;
		let imapCapabilitiesDisabled;
		const importTrack = /* @__PURE__ */ __name(async (token) => {
			const importConnection = dom.div("Waiting for updates...");
			importProgress.appendChild(importConnection);
			let countsTbody;
			let counts = /* @__PURE__ */ new Map();
			let problems;
			await new Promise((resolve, reject) => {
				const eventSource = new window.EventSource("importprogress?token=" + encodeURIComponent(token));
				eventSource.addEventListener("open", function(e) {
					console.log("eventsource open", { e });
					dom._kids(importConnection, dom.div("Waiting for updates, connected..."));
					dom._kids(importAbortBox, dom.clickbutton("Abort import", attr.title("If the import is not yet finished, it can be aborted and no messages will have been imported."), /* @__PURE__ */ __name(async function click() {
						try {
							await client.ImportAbort(token);
						} catch (err) {
							console.log({ err });
							window.alert("Error: " + errmsg(err));
						}
					}, "click")));
				});
				eventSource.addEventListener("error", function(e) {
					console.log("eventsource error", { e });
					dom._kids(importConnection, box(red, "Connection error"));
					reject({ message: "Connection error" });
				});
				eventSource.addEventListener("count", (e) => {
					const data = JSON.parse(e.data);
					console.log("import count event", { e, data });
					if (!countsTbody) {
						importProgress.appendChild(dom.div(dom.br(), dom.h3("Importing mailboxes and messages..."), dom.table(dom.thead(dom.tr(dom.th("Mailbox"), dom.th("Messages"))), countsTbody = dom.tbody())));
					}
					let elem = counts.get(data.Mailbox);
					if (!elem) {
						countsTbody.appendChild(dom.tr(dom.td(data.Mailbox), elem = dom.td(style({ textAlign: "right" }), "" + data.Count)));
						counts.set(data.Mailbox, elem);
					}
					dom._kids(elem, "" + data.Count);
				});
				eventSource.addEventListener("problem", (e) => {
					const data = JSON.parse(e.data);
					console.log("import problem event", { e, data });
					if (!problems) {
						importProgress.appendChild(dom.div(dom.br(), dom.h3("Problems during import"), problems = dom.div()));
					}
					problems.appendChild(dom.div(box(yellow, data.Message)));
				});
				eventSource.addEventListener("step", (e) => {
					const data = JSON.parse(e.data);
					console.log("import step event", { e, data });
					importProgress.appendChild(dom.div(dom.br(), box(blue, "Step: " + data.Title)));
				});
				eventSource.addEventListener("done", (e) => {
					console.log("import done event", { e });
					importProgress.appendChild(dom.div(dom.br(), box(blue, "Import finished")));
					eventSource.close();
					dom._kids(importConnection);
					dom._kids(importAbortBox);
					window.sessionStorage.removeItem("ImportToken");
					resolve(null);
				});
				eventSource.addEventListener("aborted", function(e) {
					console.log("import aborted event", { e });
					importProgress.appendChild(dom.div(dom.br(), box(red, "Import aborted, no message imported")));
					eventSource.close();
					dom._kids(importConnection);
					dom._kids(importAbortBox);
					window.sessionStorage.removeItem("ImportToken");
					reject({ message: "Import aborted" });
				});
			});
		}, "importTrack");
		const authorizationPopup = /* @__PURE__ */ __name((dest) => {
			let username;
			let password;
			const close = popup(dom.form(/* @__PURE__ */ __name(function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				dest.value = "Basic " + window.btoa(username.value + ":" + password.value);
				close();
			}, "submit"), dom.p("Compose HTTP Basic authentication header"), dom.div(style({ marginBottom: "1ex" }), dom.div(dom.label("Username")), username = dom.input(attr.required(""))), dom.div(style({ marginBottom: "1ex" }), dom.div(dom.label("Password (shown in clear)")), password = dom.input(attr.required(""))), dom.div(style({ marginBottom: "1ex" }), dom.submitbutton("Set")), dom.div("A HTTP Basic authorization header contains the password in plain text, as base64.")));
			username.focus();
		}, "authorizationPopup");
		const popupTestOutgoing = /* @__PURE__ */ __name(() => {
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
				Event: OutgoingEvent.EventDelivered,
				DSN: false,
				Suppressing: false,
				QueueMsgID: 123,
				FromID: "MDEyMzQ1Njc4OWFiY2RlZg",
				MessageID: "<QnxzgulZK51utga6agH_rg@mox.example>",
				Subject: "test from mox web pages",
				WebhookQueued: /* @__PURE__ */ new Date(),
				SMTPCode: 0,
				SMTPEnhancedCode: "",
				Error: "",
				Extra: {}
			};
			const onchange = /* @__PURE__ */ __name(function change() {
				data = {
					Version: 0,
					Event: event.value,
					DSN: dsn.checked,
					Suppressing: suppressing.checked,
					QueueMsgID: parseInt(queueMsgID.value),
					FromID: fromID.value,
					MessageID: messageID.value,
					Subject: "test from mox web pages",
					WebhookQueued: /* @__PURE__ */ new Date(),
					SMTPCode: 0,
					SMTPEnhancedCode: "",
					Error: error.value,
					Extra: JSON.parse(extra.value)
				};
				const curlStr = "curl " + (outgoingWebhookAuthorization.value ? "-H 'Authorization: " + outgoingWebhookAuthorization.value + "' " : "") + "-H 'X-Mox-Webhook-ID: 1' -H 'X-Mox-Webhook-Attempt: 1' --json '" + JSON.stringify(data) + "' '" + outgoingWebhookURL.value + "'";
				dom._kids(curl, style({ maxWidth: "45em", wordBreak: "break-all" }), curlStr);
				body.value = JSON.stringify(data, void 0, "	");
			}, "change");
			popup(dom.h1("Test webhook for outgoing delivery"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				result.classList.add("loadstart");
				const [code, response, errmsg2] = await check(fieldset, client.OutgoingWebhookTest(outgoingWebhookURL.value, outgoingWebhookAuthorization.value, data));
				const nresult = dom.div(dom._class("loadend"), dom.table(dom.tr(dom.td("HTTP status code"), dom.td("" + code)), dom.tr(dom.td("Error message"), dom.td(errmsg2)), dom.tr(dom.td("Response"), dom.td(response))));
				result.replaceWith(nresult);
				result = nresult;
			}, "submit"), fieldset = dom.fieldset(dom.p("Make a test call to ", dom.b(outgoingWebhookURL.value), "."), dom.div(style({ display: "flex", gap: "1em" }), dom.div(dom.h2("Parameters"), dom.div(style({ marginBottom: ".5ex" }), dom.label("Event", dom.div(event = dom.select(onchange, ["delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"].map((s) => dom.option(s.substring(0, 1).toUpperCase() + s.substring(1), attr.value(s))))))), dom.div(style({ marginBottom: ".5ex" }), dom.label(dsn = dom.input(attr.type("checkbox")), " DSN", onchange)), dom.div(style({ marginBottom: ".5ex" }), dom.label(suppressing = dom.input(attr.type("checkbox")), " Suppressing", onchange)), dom.div(style({ marginBottom: ".5ex" }), dom.label("Queue message ID ", dom.div(queueMsgID = dom.input(attr.required(""), attr.type("number"), attr.value("123"), onchange)))), dom.div(style({ marginBottom: ".5ex" }), dom.label("From ID ", dom.div(fromID = dom.input(attr.required(""), attr.value(data.FromID), onchange)))), dom.div(style({ marginBottom: ".5ex" }), dom.label("MessageID", dom.div(messageID = dom.input(attr.required(""), attr.value(data.MessageID), onchange)))), dom.div(style({ marginBottom: ".5ex" }), dom.label("Error", dom.div(error = dom.input(onchange)))), dom.div(style({ marginBottom: ".5ex" }), dom.label("Extra", dom.div(extra = dom.input(attr.required(""), attr.value("{}"), onchange))))), dom.div(dom.h2("Headers"), dom.pre("X-Mox-Webhook-ID: 1\nX-Mox-Webhook-Attempt: 1"), dom.br(), dom.h2("JSON"), body = dom.textarea(attr.disabled(""), attr.rows("15"), style({ width: "30em" })), dom.br(), dom.h2("curl"), curl = dom.div(dom._class("literal")))), dom.br(), dom.div(style({ textAlign: "right" }), dom.submitbutton("Post")), dom.br(), result = dom.div())));
			onchange();
		}, "popupTestOutgoing");
		const popupTestIncoming = /* @__PURE__ */ __name(() => {
			let fieldset;
			let body;
			let curl;
			let result;
			let data = {
				Version: 0,
				From: [{ Name: "remote", Address: "remote@remote.example" }],
				To: [{ Name: "mox", Address: "mox@mox.example" }],
				CC: [],
				BCC: [],
				ReplyTo: [],
				Subject: "test webhook for incoming message",
				MessageID: "<QnxzgulZK51utga6agH_rg@mox.example>",
				InReplyTo: "",
				References: [],
				Date: /* @__PURE__ */ new Date(),
				Text: "hi \u263A\n",
				HTML: "",
				Structure: {
					ContentType: "text/plain",
					ContentTypeParams: { charset: "utf-8" },
					ContentID: "",
					ContentDisposition: "",
					Filename: "",
					DecodedSize: 8,
					Parts: []
				},
				Meta: {
					MsgID: 1,
					MailFrom: "remote@remote.example",
					MailFromValidated: true,
					MsgFromValidated: true,
					RcptTo: "mox@localhost",
					DKIMVerifiedDomains: ["remote.example"],
					RemoteIP: "127.0.0.1",
					Received: /* @__PURE__ */ new Date(),
					MailboxName: "Inbox",
					Automated: false
				}
			};
			const onchange = /* @__PURE__ */ __name(function change() {
				try {
					parser.Incoming(JSON.parse(body.value));
				} catch (err) {
					console.log({ err });
					window.alert("Error parsing data: " + errmsg(err));
				}
				const curlStr = "curl " + (incomingWebhookAuthorization.value ? "-H 'Authorization: " + incomingWebhookAuthorization.value + "' " : "") + "-H 'X-Mox-Webhook-ID: 1' -H 'X-Mox-Webhook-Attempt: 1' --json '" + JSON.stringify(data) + "' '" + incomingWebhookURL.value + "'";
				dom._kids(curl, style({ maxWidth: "45em", wordBreak: "break-all" }), curlStr);
			}, "change");
			popup(dom.h1("Test webhook for incoming delivery"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				result.classList.add("loadstart");
				const [code, response, errmsg2] = await check(fieldset, (async () => await client.IncomingWebhookTest(incomingWebhookURL.value, incomingWebhookAuthorization.value, parser.Incoming(JSON.parse(body.value))))());
				const nresult = dom.div(dom._class("loadend"), dom.table(dom.tr(dom.td("HTTP status code"), dom.td("" + code)), dom.tr(dom.td("Error message"), dom.td(errmsg2)), dom.tr(dom.td("Response"), dom.td(response))));
				result.replaceWith(nresult);
				result = nresult;
			}, "submit"), fieldset = dom.fieldset(dom.p("Make a test call to ", dom.b(incomingWebhookURL.value), "."), dom.div(style({ display: "flex", gap: "1em" }), dom.div(dom.h2("JSON"), body = dom.textarea(style({ maxHeight: "90vh" }), style({ width: "30em" }), onchange)), dom.div(dom.h2("Headers"), dom.pre("X-Mox-Webhook-ID: 1\nX-Mox-Webhook-Attempt: 1"), dom.br(), dom.h2("curl"), curl = dom.div(dom._class("literal")))), dom.br(), dom.div(style({ textAlign: "right" }), dom.submitbutton("Post")), dom.br(), result = dom.div())));
			body.value = JSON.stringify(data, void 0, "	");
			body.setAttribute("rows", "" + Math.min(40, body.value.split("\n").length + 1));
			onchange();
		}, "popupTestIncoming");
		const root = dom.div(
			crumbs("Mox Account"),
			dom.div("Default domain: ", acc.DNSDomain.ASCII ? domainString(acc.DNSDomain) : "(none)"),
			dom.br(),
			fullNameForm = dom.form(fullNameFieldset = dom.fieldset(dom.label(style({ display: "inline-block" }), "Full name", dom.br(), fullName = dom.input(attr.value(acc.FullName), attr.title("Name to use in From header when composing messages. Can be overridden per configured address."))), " ", dom.submitbutton("Save")), /* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				await check(fullNameFieldset, client.AccountSaveFullName(fullName.value));
				fullName.setAttribute("value", fullName.value);
				fullNameForm.reset();
			}, "submit")),
			dom.br(),
			dom.h2("Addresses"),
			dom.ul(Object.entries(acc.Destinations || {}).length === 0 ? dom.li("(None, login disabled)") : [], Object.entries(acc.Destinations || {}).sort().map((t) => dom.li(dom.a(prewrap(t[0]), attr.href("#destinations/" + encodeURIComponent(t[0]))), t[0].startsWith("@") ? " (catchall)" : []))),
			dom.br(),
			dom.h2("Aliases/lists"),
			dom.table(dom.thead(dom.tr(dom.th("Alias address", attr.title("Messages sent to this address will be delivered to all members of the alias/list. A member does not receive a message if their address is in the message From header.")), dom.th("Subscription address", attr.title("Address subscribed to the alias/list.")), dom.th("Allowed senders", attr.title("Whether only members can send through the alias/list, or anyone.")), dom.th("Send as alias address", attr.title('If enabled, messages can be sent with the alias address in the message "From" header.')), dom.th())), (acc.Aliases || []).length === 0 ? dom.tr(dom.td(attr.colspan("5"), "None")) : [], (acc.Aliases || []).sort((a, b) => a.Alias.LocalpartStr < b.Alias.LocalpartStr ? -1 : domainName(a.Alias.Domain) < domainName(b.Alias.Domain) ? -1 : 1).map((a) => dom.tr(dom.td(prewrap(a.Alias.LocalpartStr, "@", domainName(a.Alias.Domain))), dom.td(prewrap(a.SubscriptionAddress)), dom.td(a.Alias.PostPublic ? "Anyone" : "Members only"), dom.td(a.Alias.AllowMsgFrom ? "Yes" : "No"), dom.td((a.MemberAddresses || []).length === 0 ? [] : dom.clickbutton("Show members", /* @__PURE__ */ __name(function click() {
				popup(dom.h1("Members of alias ", prewrap(a.Alias.LocalpartStr, "@", domainName(a.Alias.Domain))), dom.ul((a.MemberAddresses || []).map((addr) => dom.li(prewrap(addr)))));
			}, "click")))))),
			dom.br(),
			dom.h2("Recent login attempts", attr.title("Login attempts are stored for 30 days. At most 10000 failed login attempts are stored to prevent unlimited growth of the database.")),
			renderLoginAttempts(recentLoginAttempts || []),
			dom.br(),
			recentLoginAttempts && recentLoginAttempts.length >= 10 ? dom.p("See ", dom.a(attr.href("#loginattempts"), "all login attempts"), ".") : dom.br(),
			dom.h2("Change password"),
			acc.NoCustomPassword ? dom.div(dom.clickbutton("Generate and set new password", attr.title("Automatically generate a new password and set it for this account. Custom passwords risk reuse across services and are currently disabled for this account."), /* @__PURE__ */ __name(async function click(e) {
				const password = await check(e.target, client.GeneratePassword());
				window.alert("New password: " + password + "\n\nStore it securely, for example in a password manager.");
			}, "click"))) : passwordForm = dom.form(passwordFieldset = dom.fieldset(dom.label(style({ display: "inline-block" }), "New password", dom.br(), password1 = dom.input(attr.type("password"), attr.autocomplete("new-password"), attr.required(""), /* @__PURE__ */ __name(function focus() {
				passwordHint.style.display = "";
			}, "focus"))), " ", dom.label(style({ display: "inline-block" }), "New password repeat", dom.br(), password2 = dom.input(attr.type("password"), attr.autocomplete("new-password"), attr.required(""))), " ", dom.submitbutton("Change password")), passwordHint = dom.div(style({ display: "none", marginTop: ".5ex" }), dom.clickbutton("Generate random password", /* @__PURE__ */ __name(function click(e) {
				e.preventDefault();
				let b = new Uint8Array(1);
				let s = "";
				const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_;:,<.>/";
				while (s.length < 12) {
					self.crypto.getRandomValues(b);
					if (Math.ceil(b[0] / chars.length) * chars.length > 255) {
						continue;
					}
					s += chars[b[0] % chars.length];
				}
				password1.type = "text";
				password2.type = "text";
				password1.value = s;
				password2.value = s;
			}, "click")), dom.div(dom._class("text"), box(yellow, "Important: Bots will try to bruteforce your password. Connections with failed authentication attempts will be rate limited but attackers WILL find passwords reused at other services and weak passwords. If your account is compromised, spammers are likely to abuse your system, spamming your address and the wider internet in your name. So please pick a random, unguessable password, preferrably at least 12 characters."))), /* @__PURE__ */ __name(async function submit(e) {
				e.stopPropagation();
				e.preventDefault();
				if (!password1.value || password1.value !== password2.value) {
					window.alert("Passwords do not match.");
					return;
				}
				await check(passwordFieldset, client.SetPassword(password1.value));
				passwordForm.reset();
			}, "submit")),
			dom.br(),
			dom.h2("TLS public keys"),
			dom.p("For TLS client authentication with certificates, for IMAP and/or submission (SMTP). Only the public key of the certificate is used during TLS authentication, to identify this account. Names, expiration or constraints are not verified."),
			(() => {
				let elem = dom.div();
				const preauthHelp = 'New IMAP immediate TLS connections authenticated with a client certificate are automatically switched to "authenticated" state with an untagged IMAP "preauth" message by default. IMAP connections have a state machine specifying when commands are allowed. Authenticating is not allowed while in the "authenticated" state. Enable this option to work around clients that would try to authenticated anyway.';
				const render = /* @__PURE__ */ __name(() => {
					const e = dom.div(dom.table(dom.thead(dom.tr(dom.th("Login address"), dom.th("Name"), dom.th("Type"), dom.th('No IMAP "preauth"', attr.title(preauthHelp)), dom.th("Fingerprint"), dom.th("Update"), dom.th("Remove"))), dom.tbody(tlspubkeys.length === 0 ? dom.tr(dom.td(attr.colspan("7"), "None")) : [], tlspubkeys.map((tpk, index2) => {
						let loginAddress;
						let name;
						let noIMAPPreauth;
						let update;
						const formID = "tlk-" + index2;
						const row = dom.tr(dom.td(dom.form(attr.id(formID), /* @__PURE__ */ __name(async function submit(e2) {
							e2.stopPropagation();
							e2.preventDefault();
							const ntpk = { ...tpk };
							ntpk.LoginAddress = loginAddress.value;
							ntpk.Name = name.value;
							ntpk.NoIMAPPreauth = noIMAPPreauth.checked;
							await check(update, client.TLSPublicKeyUpdate(ntpk));
							tpk.LoginAddress = ntpk.LoginAddress;
							tpk.Name = ntpk.Name;
							tpk.NoIMAPPreauth = ntpk.NoIMAPPreauth;
						}, "submit"), loginAddress = dom.input(attr.autocomplete("email"), attr.value(tpk.LoginAddress), attr.required("")))), dom.td(name = dom.input(attr.form(formID), attr.value(tpk.Name), attr.required(""))), dom.td(tpk.Type), dom.td(dom.label(noIMAPPreauth = dom.input(attr.form(formID), attr.type("checkbox"), tpk.NoIMAPPreauth ? attr.checked("") : []), ' No IMAP "preauth"', attr.title(preauthHelp))), dom.td(tpk.Fingerprint), dom.td(update = dom.submitbutton(attr.form(formID), "Update")), dom.td(dom.form(/* @__PURE__ */ __name(async function submit(e2) {
							e2.stopPropagation();
							e2.preventDefault();
							await check(e2.target, client.TLSPublicKeyRemove(tpk.Fingerprint));
							tlspubkeys.splice(tlspubkeys.indexOf(tpk), 1);
							render();
						}, "submit"), dom.submitbutton("Remove"))));
						return row;
					}))), dom.clickbutton("Add", style({ marginTop: "1ex" }), /* @__PURE__ */ __name(function click() {
						let address;
						let name;
						let noIMAPPreauth;
						let file;
						const close = popup(dom.div(style({ maxWidth: "45em" }), dom.h1("Add TLS public key"), dom.form(/* @__PURE__ */ __name(async function submit(e2) {
							e2.preventDefault();
							e2.stopPropagation();
							if (file.files?.length !== 1) {
								throw new Error("exactly 1 certificate required");
							}
							const certPEM = await new Promise((resolve, reject) => {
								const fr = new window.FileReader();
								fr.addEventListener("load", () => {
									resolve(fr.result);
								});
								fr.addEventListener("error", () => {
									reject(fr.error);
								});
								fr.readAsText(file.files[0]);
							});
							const ntpk = await check(e2.target, client.TLSPublicKeyAdd(address.value, name.value, noIMAPPreauth.checked, certPEM));
							tlspubkeys.push(ntpk);
							render();
							close();
						}, "submit"), dom.label(style({ display: "block", marginBottom: "1ex" }), dom.div(dom.b("Login address")), address = dom.input(attr.autocomplete("email"), attr.value(localStorageGet("webaccountaddress") || ""), attr.required("")), dom.div(style({ fontStyle: "italic", marginTop: ".5ex" }), "Login address used for sessions using this key.")), dom.label(style({ display: "block", marginBottom: "1ex" }), noIMAPPreauth = dom.input(attr.type("checkbox")), ' No IMAP "preauth"', attr.title(preauthHelp)), dom.div(style({ display: "block", marginBottom: "1ex" }), dom.label(dom.div(dom.b("Certificate")), file = dom.input(attr.type("file"), attr.required(""))), dom.p(style({ fontStyle: "italic", margin: "1ex 0" }), "Upload a PEM file containing a certificate, not a private key. Only the public key of the certificate is used during TLS authentication, to identify this account. Names, expiration, and constraints are not verified. ", dom.a("Show suggested commands", attr.href(""), /* @__PURE__ */ __name(function click2(e2) {
							e2.preventDefault();
							popup(dom.h1("Generate a private key and certificate"), dom.pre(dom._class("literal"), `export keyname=...    # Used for file names, certificate "common name" and as name of tls public key.
											# Suggestion: Use an application name and/or email address.
export passphrase=... # Protects the private key in the PEM and p12 files.

# Generate an ECDSA P-256 private key and a long-lived, unsigned, basic certificate
# for the corresponding public key.
openssl req \\
	-config /dev/null \\
	-x509 \\
	-newkey ec \\
	-pkeyopt ec_paramgen_curve:P-256 \\
	-passout env:passphrase \\
	-keyout "$keyname.ecdsa-p256.privatekey.pkcs8.pem" \\
	-out "$keyname.ecdsa-p256.certificate.pem" \\
	-days 36500 \\
	-subj "/CN=$keyname"

# Generate a p12 file containing both certificate and private key, for
# applications/operating systems that cannot read PEM files with
# certificates/private keys.
openssl pkcs12 \\
	-export \\
	-in "$keyname.ecdsa-p256.certificate.pem" \\
	-inkey "$keyname.ecdsa-p256.privatekey.pkcs8.pem" \\
	-name "$keyname" \\
	-passin env:passphrase \\
	-passout env:passphrase \\
	-out "$keyname.ecdsa-p256-privatekey-certificate.p12"

# If the p12 file cannot be imported in the destination OS or email application,
# try adding -legacy to the "openssl pkcs12" command.
`));
						}, "click")), " for generating a private key and certificate.")), dom.label(style({ display: "block", marginBottom: "1ex" }), dom.div(dom.b("Name")), name = dom.input(), dom.div(style({ fontStyle: "italic", marginTop: ".5ex" }), 'Optional. If empty, the "subject common name" from the certificate is used.')), dom.br(), dom.submitbutton("Add"))));
					}, "click")));
					if (elem) {
						elem.replaceWith(e);
					}
					elem = e;
				}, "render");
				render();
				return elem;
			})(),
			dom.br(),
			dom.h2("Disk usage"),
			dom.p("Storage used is ", dom.b(formatQuotaSize(Math.floor(storageUsed / (1024 * 1024)) * 1024 * 1024)), storageLimit > 0 ? [
				dom.b("/", formatQuotaSize(storageLimit)),
				" (",
				"" + Math.floor(100 * storageUsed / storageLimit),
				"%)."
			] : [", no explicit limit is configured."]),
			dom.h2("Automatic junk flags", attr.title("For the junk filter to work properly, it needs to be trained: Messages need to be marked as junk or nonjunk. Not all email clients help you set those flags. Automatic junk flags set the junk or nonjunk flags when messages are moved/copied to mailboxes matching configured regular expressions.")),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(autoJunkFlagsFieldset, client.AutomaticJunkFlagsSave(autoJunkFlagsEnabled.checked, junkMailboxRegexp.value, neutralMailboxRegexp.value, notJunkMailboxRegexp.value));
			}, "submit"), autoJunkFlagsFieldset = dom.fieldset(dom.div(style({ display: "flex", gap: "1em" }), dom.label("Enabled", attr.title("If enabled, junk/nonjunk flags will be set automatically if they match a regular expression below. When two of the three mailbox regular expressions are set, the remaining one will match all unmatched messages. Messages are matched in order 'junk', 'neutral', 'not junk', and the search stops on the first match. Mailboxes are lowercased before matching."), dom.div(autoJunkFlagsEnabled = dom.input(attr.type("checkbox"), acc.AutomaticJunkFlags.Enabled ? attr.checked("") : []))), dom.label("Junk mailbox regexp", dom.div(junkMailboxRegexp = dom.input(attr.value(acc.AutomaticJunkFlags.JunkMailboxRegexp)))), dom.label("Neutral mailbox regexp", dom.div(neutralMailboxRegexp = dom.input(attr.value(acc.AutomaticJunkFlags.NeutralMailboxRegexp)))), dom.label("Not Junk mailbox regexp", dom.div(notJunkMailboxRegexp = dom.input(attr.value(acc.AutomaticJunkFlags.NotJunkMailboxRegexp)))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save")))))),
			dom.br(),
			dom.h2("Junk filter", attr.title("Content-based filtering, using the junk-status of individual messages to rank words in such messages as spam or ham. It is recommended you always set the applicable (non)-junk status on messages, and that you do not empty your Trash because those messages contain valuable ham/spam training information.")),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				const xjunkFilter = /* @__PURE__ */ __name(() => {
					if (!junkFilterEnabled.checked) {
						return null;
					}
					const r = {
						Threshold: parseFloat(junkThreshold.value),
						Onegrams: junkOnegrams.checked,
						Twograms: junkTwograms.checked,
						Threegrams: acc.JunkFilter?.Threegrams || false,
						// Ignored on server.
						MaxPower: parseFloat(junkMaxPower.value),
						TopWords: parseInt(junkTopWords.value),
						IgnoreWords: parseFloat(junkIgnoreWords.value),
						RareWords: parseInt(junkRareWords.value)
					};
					return r;
				}, "xjunkFilter");
				await check(junkFilterFields, (async () => await client.JunkFilterSave(xjunkFilter()))());
			}, "submit"), junkFilterFields = dom.fieldset(dom.div(style({ display: "flex", gap: "1em" }), dom.label("Enabled", attr.title("If enabled, the junk filter is used to classify incoming email from first-time senders. The result, along with other checks, determines if the message will be accepted or rejected"), dom.div(junkFilterEnabled = dom.input(attr.type("checkbox"), acc.JunkFilter ? attr.checked("") : []))), dom.label("Threshold", attr.title("Approximate spaminess score between 0 and 1 above which emails are rejected as spam. Each delivery attempt adds a little noise to make it slightly harder for spammers to identify words that strongly indicate non-spaminess and use it to bypass the filter. E.g. 0.95."), dom.div(junkThreshold = dom.input(attr.value("" + (acc.JunkFilter?.Threshold || "0.95"))))), dom.label("Onegrams", attr.title("Track ham/spam ranking for single words."), dom.div(junkOnegrams = dom.input(attr.type("checkbox"), acc.JunkFilter?.Onegrams ? attr.checked("") : []))), dom.label("Twograms", attr.title("Track ham/spam ranking for each two consecutive words."), dom.div(junkTwograms = dom.input(attr.type("checkbox"), acc.JunkFilter?.Twograms ? attr.checked("") : []))), dom.label("Threegrams", attr.title("Track ham/spam ranking for each three consecutive words. Can only be changed by admin."), dom.div(dom.input(attr.type("checkbox"), attr.disabled(""), acc.JunkFilter?.Threegrams ? attr.checked("") : []))), dom.label("Max power", attr.title("Maximum power a word (combination) can have. If spaminess is 0.99, and max power is 0.1, spaminess of the word will be set to 0.9. Similar for ham words."), dom.div(junkMaxPower = dom.input(attr.value("" + (acc.JunkFilter?.MaxPower || 0.01))))), dom.label("Top words", attr.title("Number of most spammy/hammy words to use for calculating probability. E.g. 10."), dom.div(junkTopWords = dom.input(attr.value("" + (acc.JunkFilter?.TopWords || 10))))), dom.label("Ignore words", attr.title("Ignore words that are this much away from 0.5 haminess/spaminess. E.g. 0.1, causing word (combinations) of 0.4 to 0.6 to be ignored."), dom.div(junkIgnoreWords = dom.input(attr.value("" + (acc.JunkFilter?.IgnoreWords || 0.1))))), dom.label("Rare words", attr.title("Occurrences in word database until a word is considered rare and its influence in calculating probability reduced. E.g. 1 or 2."), dom.div(junkRareWords = dom.input(attr.value("" + (acc.JunkFilter?.RareWords || 2))))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save")))))),
			dom.br(),
			dom.h2("Introbox"),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(introboxFieldset, client.IntroboxSave(introboxMailbox.value));
			}, "submit"), introboxFieldset = dom.fieldset(dom.div(style({ display: "flex", gap: "1em" }), dom.label("Mailbox", attr.title("Mailbox for delivering messages to Inbox from new first-time message-from addresses (without established reputation). Useful for deprioritizing mail from unknown correspondents while keeping mail from known correspondents in Inbox. Must be different from Inbox and the RejectsMailbox. Moving a message from Introbox to its originally intended mailbox marks it as nonjunk, so future messages from the sender are delivered to their regular destination. Ensure this mailbox is matched by NeutralMailboxRegexp for proper automatic junk flags handling."), dom.div(introboxMailbox = dom.input(attr.value(acc.Introbox)))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save")))))),
			dom.br(),
			dom.h2("Rejects"),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(rejectsFieldset, client.RejectsSave(rejectsMailbox.value, keepRejects.checked));
			}, "submit"), rejectsFieldset = dom.fieldset(dom.div(style({ display: "flex", gap: "1em" }), dom.label("Mailbox", attr.title("Mail that looks like spam will be rejected, but a copy can be stored temporarily in a mailbox, e.g. Rejects. If mail isn't coming in when you expect, you can look there. The mail still isn't accepted, so the remote mail server may retry (hopefully, if legitimate), or give up (hopefully, if indeed a spammer). Messages are automatically removed from this mailbox, so do not set it to a mailbox that has messages you want to keep."), dom.div(rejectsMailbox = dom.input(attr.value(acc.RejectsMailbox)))), dom.label("No cleanup", attr.title("Don't automatically delete mail in the RejectsMailbox listed above. This can be useful, e.g. for future spam training. It can also cause storage to fill up."), dom.div(keepRejects = dom.input(attr.type("checkbox"), acc.KeepRejects ? attr.checked("") : []))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save")))))),
			dom.br(),
			dom.h2("Webhooks"),
			dom.h3("Outgoing", attr.title("Webhooks for outgoing messages are called for each attempt to deliver a message in the outgoing queue, e.g. when the queue has delivered a message to the next hop, when a single attempt failed with a temporary error, when delivery permanently failed, or when DSN (delivery status notification) messages were received about a previously sent message.")),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(outgoingWebhookFieldset, client.OutgoingWebhookSave(outgoingWebhookURL.value, outgoingWebhookAuthorization.value, [...outgoingWebhookEvents.selectedOptions].map((o) => o.value)));
			}, "submit"), outgoingWebhookFieldset = dom.fieldset(dom.div(style({ display: "flex", gap: "1em" }), dom.div(dom.label(dom.div("URL", attr.title("URL to do an HTTP POST to for each event. Webhooks are disabled if empty.")), outgoingWebhookURL = dom.input(attr.value(acc.OutgoingWebhook?.URL || ""), style({ width: "30em" })))), dom.div(dom.label(dom.div("Authorization header ", dom.a("Basic", attr.href(""), /* @__PURE__ */ __name(function click(e) {
				e.preventDefault();
				authorizationPopup(outgoingWebhookAuthorization);
			}, "click")), attr.title("If non-empty, HTTP requests have this value as Authorization header, e.g. Basic <base64-encoded-username-password>.")), outgoingWebhookAuthorization = dom.input(attr.value(acc.OutgoingWebhook?.Authorization || "")))), dom.div(dom.label(style({ verticalAlign: "top" }), dom.div("Events", attr.title("Either limit to specific events, or receive all events (default).")), outgoingWebhookEvents = dom.select(
				style({ verticalAlign: "bottom" }),
				attr.multiple(""),
				attr.size("8"),
				// Number of options.
				["delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"].map((s) => dom.option(s.substring(0, 1).toUpperCase() + s.substring(1), attr.value(s), acc.OutgoingWebhook?.Events?.includes(s) ? attr.selected("") : []))
			))), dom.div(dom.div(dom.label("\xA0")), dom.submitbutton("Save"), " ", dom.clickbutton("Test", /* @__PURE__ */ __name(function click() {
				popupTestOutgoing();
			}, "click")))))),
			dom.br(),
			dom.h3("Incoming", attr.title("Webhooks for incoming messages are called for each message received over SMTP, excluding DSN messages about previous deliveries.")),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(incomingWebhookFieldset, client.IncomingWebhookSave(incomingWebhookURL.value, incomingWebhookAuthorization.value));
			}, "submit"), incomingWebhookFieldset = dom.fieldset(dom.div(style({ display: "flex", gap: "1em" }), dom.div(dom.label(dom.div("URL"), incomingWebhookURL = dom.input(attr.value(acc.IncomingWebhook?.URL || ""), style({ width: "30em" })))), dom.div(dom.label(dom.div("Authorization header ", dom.a("Basic", attr.href(""), /* @__PURE__ */ __name(function click(e) {
				e.preventDefault();
				authorizationPopup(incomingWebhookAuthorization);
			}, "click")), attr.title("If non-empty, HTTP requests have this value as Authorization header, e.g. Basic <base64-encoded-username-password>.")), incomingWebhookAuthorization = dom.input(attr.value(acc.IncomingWebhook?.Authorization || "")))), dom.div(dom.div(dom.label("\xA0")), dom.submitbutton("Save"), " ", dom.clickbutton("Test", /* @__PURE__ */ __name(function click() {
				popupTestIncoming();
			}, "click")))))),
			dom.br(),
			dom.h2("Keep messages/webhooks retired from queue", attr.title('After delivering a message or webhook from the queue it is removed by default. But you can also keep these "retired" messages/webhooks around for a while. With unique SMTP MAIL FROM addresses configured below, this allows relating incoming delivery status notification messages (DSNs) to previously sent messages and their original recipients, which is needed for automatic management of recipient suppression lists, which is important for managing the reputation of your mail server. For both messages and webhooks, this can be useful for debugging. Use values like "3d" for 3 days, or units "s" for second, "m" for minute, "h" for hour, "w" for week.')),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(keepRetiredPeriodsFieldset, (async () => await client.KeepRetiredPeriodsSave(parseDuration(keepRetiredMessagePeriod.value), parseDuration(keepRetiredWebhookPeriod.value)))());
			}, "submit"), keepRetiredPeriodsFieldset = dom.fieldset(dom.div(style({ display: "flex", gap: "1em", alignItems: "flex-end" }), dom.div(dom.label("Messages deliveries", dom.br(), keepRetiredMessagePeriod = dom.input(attr.value(formatDuration(acc.KeepRetiredMessagePeriod))))), dom.div(dom.label("Webhook deliveries", dom.br(), keepRetiredWebhookPeriod = dom.input(attr.value(formatDuration(acc.KeepRetiredWebhookPeriod))))), dom.div(dom.submitbutton("Save"))))),
			dom.br(),
			dom.h2('Unique SMTP MAIL FROM login addresses ("FromID")', attr.title("Login addresses that cause outgoing email to be sent with SMTP MAIL FROM addresses with a unique id after the localpart catchall separator (which must be enabled when addresses are specified here). Any delivery status notifications (DSN, e.g. for bounces), can be related to the original message and recipient with unique id's. You can login to an account with any valid email address, including variants with the localpart catchall separator. You can use this mechanism to both send outgoing messages with and without unique fromid for a given email address. With the webapi and webmail, a unique id will be generated. For submission, the id from the SMTP MAIL FROM command is used if present, and a unique id is generated otherwise. Corresponds to field FromIDLoginAddresses in the Account configuration in domains.conf.")),
			(() => {
				let inputs = [];
				let elem;
				const render = /* @__PURE__ */ __name(() => {
					inputs = [];
					const e = dom.form(/* @__PURE__ */ __name(async function submit(e2) {
						e2.preventDefault();
						e2.stopPropagation();
						await check(fromIDLoginAddressesFieldset, client.FromIDLoginAddressesSave(inputs.map((e3) => e3.value)));
					}, "submit"), fromIDLoginAddressesFieldset = dom.fieldset(dom.table(dom.tbody((acc.FromIDLoginAddresses || []).length === 0 ? dom.tr(dom.td("(None)"), dom.td()) : [], (acc.FromIDLoginAddresses || []).map((s, index2) => {
						const input = dom.input(attr.required(""), attr.value(s));
						inputs.push(input);
						const x = dom.tr(dom.td(input), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(function click() {
							acc.FromIDLoginAddresses.splice(index2, 1);
							render();
						}, "click"))));
						return x;
					})), dom.tfoot(dom.tr(dom.td(), dom.td(dom.clickbutton("Add", /* @__PURE__ */ __name(function click() {
						acc.FromIDLoginAddresses = (acc.FromIDLoginAddresses || []).concat([""]);
						render();
					}, "click")))), dom.tr(dom.td(attr.colspan("2"), dom.submitbutton("Save")))))));
					if (elem) {
						elem.replaceWith(e);
						elem = e;
					}
					return e;
				}, "render");
				elem = render();
				return elem;
			})(),
			dom.br(),
			dom.h2("Suppression list"),
			dom.p("Messages queued for delivery to recipients on the suppression list will immediately fail. If delivery to a recipient fails repeatedly, it can be added to the suppression list automatically. Repeated rejected delivery attempts can have a negative influence of mail server reputation. Applications sending email can implement their own handling of delivery failure notifications, but not all do."),
			dom.form(attr.id("suppressionAdd"), /* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(e.target, client.SuppressionAdd(suppressionAddress.value, true, suppressionReason.value));
				window.location.reload();
			}, "submit")),
			dom.table(dom.thead(dom.tr(dom.th("Address", attr.title('Address that caused this entry to be added to the list. The title (shown on hover) displays an address with a fictional simplified localpart, with lower-cased, dots removed, only first part before "+" or "-" (typicaly catchall separators). When checking if an address is on the suppression list, it is checked against this address.')), dom.th("Manual", attr.title("Whether suppression was added manually, instead of automatically based on bounces.")), dom.th("Reason"), dom.th("Since"), dom.th("Action"))), dom.tbody((suppressions || []).length === 0 ? dom.tr(dom.td(attr.colspan("5"), "(None)")) : [], (suppressions || []).map((s) => dom.tr(dom.td(prewrap(s.OriginalAddress), attr.title(s.BaseAddress)), dom.td(s.Manual ? "\u2713" : ""), dom.td(s.Reason), dom.td(age(s.Created)), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(async function click(e) {
				await check(e.target, client.SuppressionRemove(s.OriginalAddress));
				window.location.reload();
			}, "click")))))), dom.tfoot(dom.tr(dom.td(suppressionAddress = dom.input(attr.type("required"), attr.form("suppressionAdd"))), dom.td(), dom.td(suppressionReason = dom.input(style({ width: "100%" }), attr.form("suppressionAdd"))), dom.td(), dom.td(dom.submitbutton("Add suppression", attr.form("suppressionAdd")))))),
			dom.br(),
			dom.h2("IMAP"),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(imapFieldset, (async () => await client.IMAPSave(imapCapabilitiesDisabled.value.split(" ").filter((s) => s)))());
			}, "submit"), imapFieldset = dom.fieldset(dom.div(style({ display: "flex", gap: "1em", alignItems: "flex-end" }), dom.div(dom.label("Disabled IMAP capabilities (space-separated)", attr.title("IMAP capabilities (upper-case) to disable on the connection after authentication. Useful if the account uses an email client with an incompatible implementation for a capability/extension."), dom.br(), imapCapabilitiesDisabled = dom.input(attr.value((acc.IMAPCapabilitiesDisabled || []).join(" "))))), dom.div(dom.submitbutton("Save"))))),
			dom.br(),
			dom.h2("Export"),
			dom.p("Export all messages in all mailboxes."),
			dom.form(attr.target("_blank"), attr.method("POST"), attr.action("export"), dom.input(attr.type("hidden"), attr.name("csrf"), attr.value(localStorageGet("webaccountcsrftoken") || "")), dom.input(attr.type("hidden"), attr.name("mailbox"), attr.value("")), dom.input(attr.type("hidden"), attr.name("recursive"), attr.value("on")), dom.div(style({ display: "flex", flexDirection: "column", gap: ".5ex" }), dom.div(dom.label(dom.input(attr.type("radio"), attr.name("format"), attr.value("maildir"), attr.checked("")), " Maildir"), " ", dom.label(dom.input(attr.type("radio"), attr.name("format"), attr.value("mbox")), " Mbox")), dom.div(dom.label(dom.input(attr.type("radio"), attr.name("archive"), attr.value("tar")), " Tar"), " ", dom.label(dom.input(attr.type("radio"), attr.name("archive"), attr.value("tgz"), attr.checked("")), " Tgz"), " ", dom.label(dom.input(attr.type("radio"), attr.name("archive"), attr.value("zip")), " Zip"), " "), dom.div(style({ marginTop: "1ex" }), dom.submitbutton("Export")))),
			dom.br(),
			dom.h2("Import"),
			dom.p("Import messages from a .zip or .tgz file with maildirs and/or mbox files."),
			importForm = dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				const request = /* @__PURE__ */ __name(async () => {
					return new Promise((resolve, reject) => {
						let progressPercentage;
						dom._kids(importProgress, dom.div(dom.div("Uploading... ", progressPercentage = dom.span())));
						importProgress.style.display = "";
						const xhr = new window.XMLHttpRequest();
						xhr.open("POST", "import", true);
						xhr.setRequestHeader("x-mox-csrf", localStorageGet("webaccountcsrftoken") || "");
						xhr.upload.addEventListener("progress", (e2) => {
							if (!e2.lengthComputable) {
								return;
							}
							const pct = Math.floor(100 * e2.loaded / e2.total);
							dom._kids(progressPercentage, pct + "%");
						});
						xhr.addEventListener("load", () => {
							console.log("upload done", { xhr, status: xhr.status });
							if (xhr.status !== 200) {
								reject({ message: xhr.status === 400 || xhr.status === 500 ? xhr.responseText : "status " + xhr.status });
								return;
							}
							let resp;
							try {
								resp = parser.ImportProgress(JSON.parse(xhr.responseText));
							} catch (err) {
								reject({ message: "parsing response json: " + errmsg(err) });
								return;
							}
							resolve(resp);
						});
						xhr.addEventListener("error", (e2) => reject({ message: "upload error", event: e2 }));
						xhr.addEventListener("abort", (e2) => reject({ message: "upload aborted", event: e2 }));
						xhr.send(new window.FormData(importForm));
					});
				}, "request");
				try {
					const p = request();
					importFieldset.disabled = true;
					const result = await p;
					try {
						window.sessionStorage.setItem("ImportToken", result.Token);
					} catch (err) {
						console.log("storing import token in session storage", { err });
					}
					await importTrack(result.Token);
				} catch (err) {
					console.log({ err });
					window.alert("Error: " + errmsg(err));
				} finally {
					importFieldset.disabled = false;
				}
			}, "submit"), importFieldset = dom.fieldset(dom.div(style({ marginBottom: "1ex" }), dom.label(dom.div(style({ marginBottom: ".5ex" }), "File"), dom.input(attr.type("file"), attr.required(""), attr.name("file"), /* @__PURE__ */ __name(function focus() {
				mailboxFileHint.style.display = "";
			}, "focus"))), mailboxFileHint = dom.p(style({ display: "none", fontStyle: "italic", marginTop: ".5ex" }), 'This file must either be a zip file or a gzipped tar file with mbox and/or maildir mailboxes. For maildirs, an optional file "dovecot-keywords" is read additional keywords, like Forwarded/Junk/NotJunk. If an imported mailbox already exists by name, messages are added to the existing mailbox. If a mailbox does not yet exist it will be created. Messages are not deduplicated, importing them twice will result in duplicates.')), dom.div(style({ marginBottom: "1ex" }), dom.label(dom.div(style({ marginBottom: ".5ex" }), "Skip mailbox prefix (optional)"), dom.input(attr.name("skipMailboxPrefix"), /* @__PURE__ */ __name(function focus() {
				mailboxPrefixHint.style.display = "";
			}, "focus"))), mailboxPrefixHint = dom.p(style({ display: "none", fontStyle: "italic", marginTop: ".5ex" }), 'If set, any mbox/maildir path with this prefix will have it stripped before importing. For example, if all mailboxes are in a directory "Takeout", specify that path in the field above so mailboxes like "Takeout/Inbox.mbox" are imported into a mailbox called "Inbox" instead of "Takeout/Inbox".')), dom.div(dom.submitbutton("Upload and import"), dom.p(style({ fontStyle: "italic", marginTop: ".5ex" }), "The file is uploaded first, then its messages are imported, finally messages are matched for threading. Importing is done in a transaction, you can abort the entire import before it is finished.")))),
			importAbortBox = dom.div(),
			// Outside fieldset because it gets disabled, above progress because may be scrolling it down quickly with problems.
			importProgress = dom.div(style({ display: "none" })),
			dom.br(),
			footer()
		);
		(async () => {
			let importToken;
			try {
				importToken = window.sessionStorage.getItem("ImportToken") || "";
			} catch (err) {
				console.log("looking up ImportToken in session storage", { err });
				return;
			}
			if (!importToken) {
				return;
			}
			importFieldset.disabled = true;
			dom._kids(importProgress, dom.div(dom.div("Reconnecting to import...")));
			importProgress.style.display = "";
			importTrack(importToken).catch(() => {
				if (window.confirm("Error reconnecting to import. Remove this import session?")) {
					window.sessionStorage.removeItem("ImportToken");
					dom._kids(importProgress);
					importProgress.style.display = "none";
				}
			}).finally(() => {
				importFieldset.disabled = false;
			});
		})();
		return root;
	}, "index");
	var renderLoginAttempts = /* @__PURE__ */ __name((loginAttempts) => {
		return dom.table(dom.thead(dom.tr(dom.th("Time"), dom.th("Result"), dom.th("Count"), dom.th("LoginAddress"), dom.th("Protocol"), dom.th("Mechanism"), dom.th("User Agent"), dom.th("Remote IP"), dom.th("Local IP"), dom.th("TLS"), dom.th("TLS pubkey fingerprint"), dom.th("First seen"))), dom.tbody(loginAttempts.length ? [] : dom.tr(dom.td(attr.colspan("11"), "No login attempts in past 30 days.")), loginAttempts.map((la) => dom.tr(dom.td(age(la.Last)), dom.td(la.Result === "ok" ? la.Result : box(red, la.Result)), dom.td("" + la.Count), dom.td(la.LoginAddress), dom.td(la.Protocol), dom.td(la.AuthMech), dom.td(la.UserAgent), dom.td(la.RemoteIP), dom.td(la.LocalIP), dom.td(la.TLS), dom.td(la.TLSPubKeyFingerprint), dom.td(age(la.First))))));
	}, "renderLoginAttempts");
	var loginattempts = /* @__PURE__ */ __name(async () => {
		const loginAttempts = await client.LoginAttempts(0);
		return dom.div(crumbs(crumblink("Mox Account", "#"), "Login attempts"), dom.h2("Login attempts"), dom.p("Login attempts are stored for 30 days. At most 10000 failed login attempts are stored to prevent unlimited growth of the database."), renderLoginAttempts(loginAttempts || []));
	}, "loginattempts");
	var destination = /* @__PURE__ */ __name(async (name) => {
		const [acc] = await client.Account();
		let dest = (acc.Destinations || {})[name];
		if (!dest) {
			throw new Error("destination not found");
		}
		let rulesetsTbody = dom.tbody();
		let rulesetsRows = [];
		const addRulesetsRow = /* @__PURE__ */ __name((rs) => {
			let row;
			let headersCell = dom.td();
			const addHeader = /* @__PURE__ */ __name((k, v) => {
				let h;
				let key;
				let value;
				const root2 = dom.div(key = dom.input(attr.value(k)), " ", value = dom.input(attr.value(v)), " ", dom.clickbutton("-", style({ width: "1.5em" }), /* @__PURE__ */ __name(function click() {
					h.root.remove();
					row.headers = row.headers.filter((x) => x !== h);
					if (row.headers.length === 0) {
						const b = dom.clickbutton("+", style({ width: "1.5em" }), /* @__PURE__ */ __name(function click2() {
							b.remove();
							addHeader("", "");
						}, "click"));
						headersCell.appendChild(dom.div(style({ textAlign: "right" }), b));
					}
				}, "click")), " ", dom.clickbutton("+", style({ width: "1.5em" }), /* @__PURE__ */ __name(function click() {
					addHeader("", "");
				}, "click")));
				h = { root: root2, key, value };
				row.headers.push(h);
				headersCell.appendChild(root2);
			}, "addHeader");
			let smtpMailFromRegexp;
			let msgFromRegexp;
			let verifiedDomain;
			let isForward;
			let listAllowDomain;
			let acceptRejectsToMailbox;
			let mailbox;
			let comment;
			const root = dom.tr(dom.td(smtpMailFromRegexp = dom.input(attr.value(rs.SMTPMailFromRegexp || ""))), dom.td(msgFromRegexp = dom.input(attr.value(rs.MsgFromRegexp || ""))), dom.td(verifiedDomain = dom.input(attr.value(rs.VerifiedDomain || ""))), headersCell, dom.td(dom.label(isForward = dom.input(attr.type("checkbox"), rs.IsForward ? attr.checked("") : []))), dom.td(listAllowDomain = dom.input(attr.value(rs.ListAllowDomain || ""))), dom.td(acceptRejectsToMailbox = dom.input(attr.value(rs.AcceptRejectsToMailbox || ""))), dom.td(mailbox = dom.input(attr.value(rs.Mailbox || ""))), dom.td(comment = dom.input(attr.value(rs.Comment || ""))), dom.td(dom.clickbutton("Remove ruleset", /* @__PURE__ */ __name(function click() {
				row.root.remove();
				rulesetsRows = rulesetsRows.filter((e) => e !== row);
			}, "click"))));
			row = {
				root,
				smtpMailFromRegexp,
				msgFromRegexp,
				verifiedDomain,
				headers: [],
				isForward,
				listAllowDomain,
				acceptRejectsToMailbox,
				mailbox,
				comment
			};
			rulesetsRows.push(row);
			Object.entries(rs.HeadersRegexp || {}).sort().forEach((t) => addHeader(t[0], t[1]));
			if (Object.entries(rs.HeadersRegexp || {}).length === 0) {
				const b = dom.clickbutton("+", style({ width: "1.5em" }), /* @__PURE__ */ __name(function click() {
					b.remove();
					addHeader("", "");
				}, "click"));
				headersCell.appendChild(dom.div(style({ textAlign: "right" }), b));
			}
			rulesetsTbody.appendChild(row.root);
		}, "addRulesetsRow");
		(dest.Rulesets || []).forEach((rs) => {
			addRulesetsRow(rs);
		});
		let defaultMailbox;
		let fullName;
		let smtpError;
		let msgAuthRequiredSMTPError;
		let saveButton;
		const addresses = [name, ...Object.keys(acc.Destinations || {}).filter((a) => !a.startsWith("@") && a !== name)];
		return dom.div(crumbs(crumblink("Mox Account", "#"), "Destination " + name), dom.div(dom.span("Default mailbox", attr.title("Default mailbox where email for this recipient is delivered to if it does not match any ruleset. Default is Inbox.")), dom.br(), defaultMailbox = dom.input(attr.value(dest.Mailbox), attr.placeholder("Inbox"))), dom.br(), dom.div(dom.span("Full name", attr.title("Name to use in From header when composing messages. If not set, the account default full name is used.")), dom.br(), fullName = dom.input(attr.value(dest.FullName))), dom.br(), dom.div(dom.span("Reject deliveries with SMTP Error", attr.title("If non-empty, incoming delivery attempts to this destination will be rejected during SMTP RCPT TO with this error response line. The response line must start with an error code. Currently the following error resonse codes are allowed: 421 (temporary local error), 550 (mailbox not found). If the line consists of only an error code, an appropriate error message is added. Rejecting messages with a 4xx code invites later retries by the remote, while 5xx codes should prevent further delivery attempts.")), dom.br(), smtpError = dom.input(attr.value(dest.SMTPError), attr.placeholder("421 or 550..."))), dom.br(), dom.div(dom.span("Reject messages without authenticated domain (aligned SPF/DKIM)", attr.title("If non-empty, an additional DMARC-like message authentication check is done for incoming messages, validating the domain in the From-header of the message. Messages without either an aligned SPF or aligned DKIM pass are rejected during the SMTP DATA command with a permanent error code followed by the message in this field. The domain in the message 'From' header is matched in relaxed or strict mode according to the domain's DMARC policy if present, or relaxed mode (organizational instead of exact domain match) otherwise. Useful for autoresponders that don't want to accept messages they don't want to send an automated reply to.")), dom.br(), msgAuthRequiredSMTPError = dom.input(attr.value(dest.MessageAuthRequiredSMTPError), attr.placeholder("messages must have aligned spf/dkim for domain authentication..."))), dom.br(), dom.h2("Rulesets"), dom.p("Incoming messages are checked against the rulesets. If a ruleset matches, the message is delivered to the mailbox configured for the ruleset instead of to the default mailbox."), dom.p('"Is Forward" does not affect matching, but changes prevents the sending mail server from being included in future junk classifications by clearing fields related to the forwarding email server (IP address, EHLO domain, MAIL FROM domain and a matching DKIM domain), and prevents DMARC rejects for forwarded messages.'), dom.p('"List allow domain" does not affect matching, but skips the regular spam checks if one of the verified domains is a (sub)domain of the domain mentioned here.'), dom.p('"Accept rejects to mailbox" does not affect matching, but causes messages classified as junk to be accepted and delivered to this mailbox, instead of being rejected during the SMTP transaction. Useful for incoming forwarded messages where rejecting incoming messages may cause the forwarding server to stop forwarding.'), dom.table(dom.thead(dom.tr(dom.th('SMTP "MAIL FROM" regexp', attr.title("Matches if this regular expression matches (a substring of) the SMTP MAIL FROM address (not the message From-header). E.g. user@example.org.")), dom.th('Message "From" address regexp', attr.title("Matches if this regular expression matches (a substring of) the single address in the message From header.")), dom.th("Verified domain", attr.title("Matches if this domain matches an SPF- and/or DKIM-verified (sub)domain.")), dom.th("Headers regexp", attr.title("Matches if these header field/value regular expressions all match (substrings of) the message headers. Header fields and valuees are converted to lower case before matching. Whitespace is trimmed from the value before matching. A header field can occur multiple times in a message, only one instance has to match. For mailing lists, you could match on ^list-id$ with the value typically the mailing list address in angled brackets with @ replaced with a dot, e.g. <name\\.lists\\.example\\.org>.")), dom.th("Is Forward", attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. Can only be used together with SMTPMailFromRegexp and VerifiedDomain. SMTPMailFromRegexp must be set to the address used to deliver the forwarded message, e.g. '^user(|\\+.*)@forward\\.example$'. Changes to junk analysis: 1. Messages are not rejected for failing a DMARC policy, because a legitimate forwarded message without valid/intact/aligned DKIM signature would be rejected because any verified SPF domain will be 'unaligned', of the forwarding mail server. 2. The sending mail server IP address, and sending EHLO and MAIL FROM domains and matching DKIM domain aren't used in future reputation-based spam classifications (but other verified DKIM domains are) because the forwarding server is not a useful spam signal for future messages.")), dom.th("List allow domain", attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If this domain matches an SPF- and/or DKIM-verified (sub)domain, the message is accepted without further spam checks, such as a junk filter or DMARC reject evaluation. DMARC rejects should not apply for mailing lists that are not configured to rewrite the From-header of messages that don't have a passing DKIM signature of the From-domain. Otherwise, by rejecting messages, you may be automatically unsubscribed from the mailing list. The assumption is that mailing lists do their own spam filtering/moderation.")), dom.th("Allow rejects to mailbox", attr.title("Influences spam filtering only, this option does not change whether a message matches this ruleset. If a message is classified as spam, it isn't rejected during the SMTP transaction (the normal behaviour), but accepted during the SMTP transaction and delivered to the specified mailbox. The specified mailbox is not automatically cleaned up like the account global Rejects mailbox, unless set to that Rejects mailbox.")), dom.th("Mailbox", attr.title("Mailbox to deliver to if this ruleset matches.")), dom.th("Comment", attr.title("Free-form comments.")), dom.th("Action"))), rulesetsTbody, dom.tfoot(dom.tr(dom.td(attr.colspan("9")), dom.td(dom.clickbutton("Add ruleset", /* @__PURE__ */ __name(function click() {
			addRulesetsRow({
				SMTPMailFromRegexp: "",
				MsgFromRegexp: "",
				VerifiedDomain: "",
				HeadersRegexp: {},
				IsForward: false,
				ListAllowDomain: "",
				AcceptRejectsToMailbox: "",
				Mailbox: "",
				Comment: "",
				VerifiedDNSDomain: { ASCII: "", Unicode: "" },
				ListAllowDNSDomain: { ASCII: "", Unicode: "" }
			});
		}, "click")))))), dom.br(), saveButton = dom.clickbutton("Save", /* @__PURE__ */ __name(async function click() {
			const newDest = {
				Mailbox: defaultMailbox.value,
				FullName: fullName.value,
				Rulesets: rulesetsRows.map((row) => {
					return {
						SMTPMailFromRegexp: row.smtpMailFromRegexp.value,
						MsgFromRegexp: row.msgFromRegexp.value,
						VerifiedDomain: row.verifiedDomain.value,
						HeadersRegexp: Object.fromEntries(row.headers.map((h) => [h.key.value, h.value.value])),
						IsForward: row.isForward.checked,
						ListAllowDomain: row.listAllowDomain.value,
						AcceptRejectsToMailbox: row.acceptRejectsToMailbox.value,
						Mailbox: row.mailbox.value,
						Comment: row.comment.value,
						VerifiedDNSDomain: { ASCII: "", Unicode: "" },
						ListAllowDNSDomain: { ASCII: "", Unicode: "" }
					};
				}),
				SMTPError: smtpError.value,
				MessageAuthRequiredSMTPError: msgAuthRequiredSMTPError.value
			};
			await check(saveButton, client.DestinationSave(name, dest, newDest));
			window.location.reload();
		}, "click")), dom.br(), dom.br(), dom.br(), dom.p(`Apple's mail applications don't do account autoconfiguration, and when adding an account it can choose defaults that don't work with modern email servers. Adding an account through a "mobileconfig" profile file can be more convenient: It contains the IMAP/SMTP settings such as host name, port, TLS, authentication mechanism and user name. This profile does not contain a login password. Opening the profile in Safari adds it to the Files app on iOS. Opening the profile in the Files app then adds it under Profiles in System Preferences (macOS) or Settings (iOS), where you can install it. These profiles are not signed, so users will have to ignore the warnings about them being unsigned. `, dom.br(), dom.a(attr.href("https://autoconfig." + domainName(acc.DNSDomain) + "/profile.mobileconfig?addresses=" + encodeURIComponent(addresses.join(",")) + "&name=" + encodeURIComponent(dest.FullName)), attr.download(""), "Download .mobileconfig email account profile"), dom.br(), dom.a(attr.href("https://autoconfig." + domainName(acc.DNSDomain) + "/profile.mobileconfig.qrcode.png?addresses=" + encodeURIComponent(addresses.join(",")) + "&name=" + encodeURIComponent(dest.FullName)), attr.download(""), "Open QR-code with link to .mobileconfig profile")));
	}, "destination");
	var init = /* @__PURE__ */ __name(async () => {
		let curhash;
		[moxversion, moxgoos, moxgoarch] = await client.Version();
		const hashChange = /* @__PURE__ */ __name(async () => {
			if (curhash === window.location.hash) {
				return;
			}
			let h = decodeURIComponent(window.location.hash);
			if (h !== "" && h.substring(0, 1) == "#") {
				h = h.substring(1);
			}
			const t = h.split("/");
			page.classList.add("loading");
			try {
				let root;
				if (h === "") {
					root = await index();
				} else if (t[0] === "loginattempts" && t.length === 1) {
					root = await loginattempts();
				} else if (t[0] === "destinations" && t.length === 2) {
					root = await destination(t[1]);
				} else {
					root = dom.div("page not found");
				}
				if (window.moxBeforeDisplay) {
					moxBeforeDisplay(root);
				}
				dom._kids(page, root);
			} catch (err) {
				console.log({ err });
				window.alert("Error: " + errmsg(err));
				window.location.hash = curhash || "";
				curhash = window.location.hash;
				return;
			}
			curhash = window.location.hash;
			page.classList.remove("loading");
		}, "hashChange");
		window.addEventListener("hashchange", hashChange);
		hashChange();
	}, "init");
	window.addEventListener("load", async () => {
		try {
			await init();
		} catch (err) {
			window.alert("Error: " + errmsg(err));
		}
	});
})();
