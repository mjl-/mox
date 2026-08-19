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
	var prop = /* @__PURE__ */ __name((x) => {
		return { _props: x };
	}, "prop");

	// .js/webadmin/api.js
	var DMARCPolicy;
	(function(DMARCPolicy2) {
		DMARCPolicy2["PolicyEmpty"] = "";
		DMARCPolicy2["PolicyNone"] = "none";
		DMARCPolicy2["PolicyQuarantine"] = "quarantine";
		DMARCPolicy2["PolicyReject"] = "reject";
	})(DMARCPolicy || (DMARCPolicy = {}));
	var Align;
	(function(Align2) {
		Align2["AlignStrict"] = "s";
		Align2["AlignRelaxed"] = "r";
	})(Align || (Align = {}));
	var Mode;
	(function(Mode2) {
		Mode2["ModeEnforce"] = "enforce";
		Mode2["ModeTesting"] = "testing";
		Mode2["ModeNone"] = "none";
	})(Mode || (Mode = {}));
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
	var structTypes = { "Account": true, "Address": true, "AddressAlias": true, "Alias": true, "AliasAddress": true, "AuthResults": true, "AutoconfCheckResult": true, "AutodiscoverCheckResult": true, "AutodiscoverSRV": true, "AutomaticJunkFlags": true, "Canonicalization": true, "CheckResult": true, "ClientConfigs": true, "ClientConfigsEntry": true, "ConfigDomain": true, "DANECheckResult": true, "DKIM": true, "DKIMAuthResult": true, "DKIMCheckResult": true, "DKIMRecord": true, "DMARC": true, "DMARCCheckResult": true, "DMARCRecord": true, "DMARCSummary": true, "DNSSECResult": true, "DateRange": true, "Destination": true, "Directive": true, "Domain": true, "DomainFeedback": true, "Dynamic": true, "Evaluation": true, "EvaluationStat": true, "Extension": true, "FailureDetails": true, "Filter": true, "HoldRule": true, "Hook": true, "HookFilter": true, "HookResult": true, "HookRetired": true, "HookRetiredFilter": true, "HookRetiredSort": true, "HookSort": true, "IPDomain": true, "IPRevCheckResult": true, "Identifiers": true, "IncomingWebhook": true, "JunkFilter": true, "LoginAttempt": true, "MTASTS": true, "MTASTSCheckResult": true, "MTASTSRecord": true, "MX": true, "MXCheckResult": true, "Modifier": true, "Msg": true, "MsgResult": true, "MsgRetired": true, "OutgoingWebhook": true, "Pair": true, "Policy": true, "PolicyEvaluated": true, "PolicyOverrideReason": true, "PolicyPublished": true, "PolicyRecord": true, "Record": true, "Report": true, "ReportMetadata": true, "ReportRecord": true, "Result": true, "ResultPolicy": true, "RetiredFilter": true, "RetiredSort": true, "Reverse": true, "Route": true, "Row": true, "Ruleset": true, "SMTPAuth": true, "SPFAuthResult": true, "SPFCheckResult": true, "SPFRecord": true, "SRV": true, "SRVConfCheckResult": true, "STSMX": true, "Selector": true, "Sort": true, "SubjectPass": true, "Summary": true, "SuppressAddress": true, "TLSCheckResult": true, "TLSPublicKey": true, "TLSRPT": true, "TLSRPTCheckResult": true, "TLSRPTDateRange": true, "TLSRPTRecord": true, "TLSRPTSummary": true, "TLSRPTSuppressAddress": true, "TLSReportRecord": true, "TLSResult": true, "Transport": true, "TransportDirect": true, "TransportFail": true, "TransportSMTP": true, "TransportSocks": true, "URI": true, "WebForward": true, "WebHandler": true, "WebInternal": true, "WebRedirect": true, "WebStatic": true, "WebserverConfig": true };
	var stringsTypes = { "Align": true, "AuthResult": true, "CSRFToken": true, "DMARCPolicy": true, "IP": true, "Localpart": true, "Mode": true, "RUA": true };
	var intsTypes = {};
	var types = {
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
		"Account": { "Name": "Account", "Docs": "", "Fields": [{ "Name": "OutgoingWebhook", "Docs": "", "Typewords": ["nullable", "OutgoingWebhook"] }, { "Name": "IncomingWebhook", "Docs": "", "Typewords": ["nullable", "IncomingWebhook"] }, { "Name": "FromIDLoginAddresses", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "KeepRetiredMessagePeriod", "Docs": "", "Typewords": ["int64"] }, { "Name": "KeepRetiredWebhookPeriod", "Docs": "", "Typewords": ["int64"] }, { "Name": "LoginDisabled", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["string"] }, { "Name": "Description", "Docs": "", "Typewords": ["string"] }, { "Name": "FullName", "Docs": "", "Typewords": ["string"] }, { "Name": "Destinations", "Docs": "", "Typewords": ["{}", "Destination"] }, { "Name": "SubjectPass", "Docs": "", "Typewords": ["SubjectPass"] }, { "Name": "QuotaMessageSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "RejectsMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "KeepRejects", "Docs": "", "Typewords": ["bool"] }, { "Name": "Introbox", "Docs": "", "Typewords": ["string"] }, { "Name": "AutomaticJunkFlags", "Docs": "", "Typewords": ["AutomaticJunkFlags"] }, { "Name": "JunkFilter", "Docs": "", "Typewords": ["nullable", "JunkFilter"] }, { "Name": "MaxOutgoingMessagesPerDay", "Docs": "", "Typewords": ["int32"] }, { "Name": "MaxFirstTimeRecipientsPerDay", "Docs": "", "Typewords": ["int32"] }, { "Name": "NoFirstTimeSenderDelay", "Docs": "", "Typewords": ["bool"] }, { "Name": "NoCustomPassword", "Docs": "", "Typewords": ["bool"] }, { "Name": "IMAPCapabilitiesDisabled", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Routes", "Docs": "", "Typewords": ["[]", "Route"] }, { "Name": "DNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "Aliases", "Docs": "", "Typewords": ["[]", "AddressAlias"] }] },
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
		"Transport": { "Name": "Transport", "Docs": "", "Fields": [{ "Name": "Submissions", "Docs": "", "Typewords": ["nullable", "TransportSMTP"] }, { "Name": "Submission", "Docs": "", "Typewords": ["nullable", "TransportSMTP"] }, { "Name": "SMTP", "Docs": "", "Typewords": ["nullable", "TransportSMTP"] }, { "Name": "Socks", "Docs": "", "Typewords": ["nullable", "TransportSocks"] }, { "Name": "Direct", "Docs": "", "Typewords": ["nullable", "TransportDirect"] }, { "Name": "Fail", "Docs": "", "Typewords": ["nullable", "TransportFail"] }] },
		"TransportSMTP": { "Name": "TransportSMTP", "Docs": "", "Fields": [{ "Name": "Host", "Docs": "", "Typewords": ["string"] }, { "Name": "Port", "Docs": "", "Typewords": ["int32"] }, { "Name": "STARTTLSInsecureSkipVerify", "Docs": "", "Typewords": ["bool"] }, { "Name": "NoSTARTTLS", "Docs": "", "Typewords": ["bool"] }, { "Name": "Auth", "Docs": "", "Typewords": ["nullable", "SMTPAuth"] }] },
		"SMTPAuth": { "Name": "SMTPAuth", "Docs": "", "Fields": [{ "Name": "Username", "Docs": "", "Typewords": ["string"] }, { "Name": "Password", "Docs": "", "Typewords": ["string"] }, { "Name": "Mechanisms", "Docs": "", "Typewords": ["[]", "string"] }] },
		"TransportSocks": { "Name": "TransportSocks", "Docs": "", "Fields": [{ "Name": "Address", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPs", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "RemoteHostname", "Docs": "", "Typewords": ["string"] }] },
		"TransportDirect": { "Name": "TransportDirect", "Docs": "", "Fields": [{ "Name": "DisableIPv4", "Docs": "", "Typewords": ["bool"] }, { "Name": "DisableIPv6", "Docs": "", "Typewords": ["bool"] }] },
		"TransportFail": { "Name": "TransportFail", "Docs": "", "Fields": [{ "Name": "SMTPCode", "Docs": "", "Typewords": ["int32"] }, { "Name": "SMTPMessage", "Docs": "", "Typewords": ["string"] }, { "Name": "Code", "Docs": "", "Typewords": ["int32"] }, { "Name": "Message", "Docs": "", "Typewords": ["string"] }] },
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
		"AuthResult": { "Name": "AuthResult", "Docs": "", "Values": [{ "Name": "AuthSuccess", "Value": "ok", "Docs": "" }, { "Name": "AuthBadUser", "Value": "baduser", "Docs": "" }, { "Name": "AuthBadPassword", "Value": "badpassword", "Docs": "" }, { "Name": "AuthBadCredentials", "Value": "badcreds", "Docs": "" }, { "Name": "AuthBadChannelBinding", "Value": "badchanbind", "Docs": "" }, { "Name": "AuthBadProtocol", "Value": "badprotocol", "Docs": "" }, { "Name": "AuthLoginDisabled", "Value": "logindisabled", "Docs": "" }, { "Name": "AuthError", "Value": "error", "Docs": "" }, { "Name": "AuthAborted", "Value": "aborted", "Docs": "" }] }
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
		async CheckDomain(domainName2) {
			const fn = "CheckDomain";
			const paramTypes = [["string"]];
			const returnTypes = [["CheckResult"]];
			const params = [domainName2];
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
		async Domain(domain2) {
			const fn = "Domain";
			const paramTypes = [["string"]];
			const returnTypes = [["Domain"]];
			const params = [domain2];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// ParseDomain parses a domain, possibly an IDNA domain.
		async ParseDomain(domain2) {
			const fn = "ParseDomain";
			const paramTypes = [["string"]];
			const returnTypes = [["Domain"]];
			const params = [domain2];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainConfig returns the configuration for a domain.
		async DomainConfig(domain2) {
			const fn = "DomainConfig";
			const paramTypes = [["string"]];
			const returnTypes = [["ConfigDomain"]];
			const params = [domain2];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainLocalparts returns the encoded localparts and accounts configured in domain.
		async DomainLocalparts(domain2) {
			const fn = "DomainLocalparts";
			const paramTypes = [["string"]];
			const returnTypes = [["{}", "string"], ["{}", "Alias"]];
			const params = [domain2];
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
		async Account(account2) {
			const fn = "Account";
			const paramTypes = [["string"]];
			const returnTypes = [["Account"], ["int64"]];
			const params = [account2];
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
		async TLSReportID(domain2, reportID) {
			const fn = "TLSReportID";
			const paramTypes = [["string"], ["int64"]];
			const returnTypes = [["TLSReportRecord"]];
			const params = [domain2, reportID];
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
		async DMARCReports(start, end, domain2) {
			const fn = "DMARCReports";
			const paramTypes = [["timestamp"], ["timestamp"], ["string"]];
			const returnTypes = [["[]", "DomainFeedback"]];
			const params = [start, end, domain2];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCReportID returns a single DMARC report.
		async DMARCReportID(domain2, reportID) {
			const fn = "DMARCReportID";
			const paramTypes = [["string"], ["int64"]];
			const returnTypes = [["DomainFeedback"]];
			const params = [domain2, reportID];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCSummaries returns a summary of received DMARC reports overlapping with
		// period start/end for one or all domains (when domain is empty).
		// The returned summaries are ordered by domain name.
		async DMARCSummaries(start, end, domain2) {
			const fn = "DMARCSummaries";
			const paramTypes = [["timestamp"], ["timestamp"], ["string"]];
			const returnTypes = [["[]", "DMARCSummary"]];
			const params = [start, end, domain2];
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
		async DomainRecords(domain2) {
			const fn = "DomainRecords";
			const paramTypes = [["string"]];
			const returnTypes = [["[]", "string"]];
			const params = [domain2];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainAdd adds a new domain and reloads the configuration.
		async DomainAdd(disabled, domain2, accountName, localpart) {
			const fn = "DomainAdd";
			const paramTypes = [["bool"], ["string"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [disabled, domain2, accountName, localpart];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainRemove removes an existing domain and reloads the configuration.
		async DomainRemove(domain2) {
			const fn = "DomainRemove";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [domain2];
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
		async ClientConfigsDomain(domain2) {
			const fn = "ClientConfigsDomain";
			const paramTypes = [["string"]];
			const returnTypes = [["ClientConfigs"]];
			const params = [domain2];
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
		async DMARCEvaluationsDomain(domain2) {
			const fn = "DMARCEvaluationsDomain";
			const paramTypes = [["string"]];
			const returnTypes = [["Domain"], ["[]", "Evaluation"]];
			const params = [domain2];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DMARCRemoveEvaluations removes evaluations for a domain.
		async DMARCRemoveEvaluations(domain2) {
			const fn = "DMARCRemoveEvaluations";
			const paramTypes = [["string"]];
			const returnTypes = [];
			const params = [domain2];
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
		async LookupTLSRPTRecord(domain2) {
			const fn = "LookupTLSRPTRecord";
			const paramTypes = [["string"]];
			const returnTypes = [["nullable", "TLSRPTRecord"], ["string"], ["string"]];
			const params = [domain2];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// TLSRPTRemoveResults removes the TLS results for a domain for the given day. If
		// day is empty, all results are removed.
		async TLSRPTRemoveResults(isRcptDom, domain2, day2) {
			const fn = "TLSRPTRemoveResults";
			const paramTypes = [["bool"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [isRcptDom, domain2, day2];
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
		async DomainRoutesSave(domainName2, routes) {
			const fn = "DomainRoutesSave";
			const paramTypes = [["string"], ["[]", "Route"]];
			const returnTypes = [];
			const params = [domainName2, routes];
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
		async DomainDescriptionSave(domainName2, descr) {
			const fn = "DomainDescriptionSave";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName2, descr];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainClientSettingsDomainSave saves the client settings domain for a domain.
		async DomainClientSettingsDomainSave(domainName2, clientSettingsDomain) {
			const fn = "DomainClientSettingsDomainSave";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName2, clientSettingsDomain];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainLocalpartConfigSave saves the localpart catchall and case-sensitive
		// settings for a domain.
		async DomainLocalpartConfigSave(domainName2, localpartCatchallSeparators, localpartCaseSensitive) {
			const fn = "DomainLocalpartConfigSave";
			const paramTypes = [["string"], ["[]", "string"], ["bool"]];
			const returnTypes = [];
			const params = [domainName2, localpartCatchallSeparators, localpartCaseSensitive];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDMARCAddressSave saves the DMARC reporting address/processing
		// configuration for a domain. If localpart is empty, processing reports is
		// disabled.
		async DomainDMARCAddressSave(domainName2, localpart, domain2, account2, mailbox) {
			const fn = "DomainDMARCAddressSave";
			const paramTypes = [["string"], ["string"], ["string"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName2, localpart, domain2, account2, mailbox];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainTLSRPTAddressSave saves the TLS reporting address/processing
		// configuration for a domain. If localpart is empty, processing reports is
		// disabled.
		async DomainTLSRPTAddressSave(domainName2, localpart, domain2, account2, mailbox) {
			const fn = "DomainTLSRPTAddressSave";
			const paramTypes = [["string"], ["string"], ["string"], ["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName2, localpart, domain2, account2, mailbox];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainMTASTSSave saves the MTASTS policy for a domain. If policyID is empty,
		// no MTASTS policy is served.
		async DomainMTASTSSave(domainName2, policyID, mode, maxAge, mx) {
			const fn = "DomainMTASTSSave";
			const paramTypes = [["string"], ["string"], ["Mode"], ["int64"], ["[]", "string"]];
			const returnTypes = [];
			const params = [domainName2, policyID, mode, maxAge, mx];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDKIMAdd adds a DKIM selector for a domain, generating a new private
		// key. The selector is not enabled for signing.
		async DomainDKIMAdd(domainName2, selector, algorithm, hash, headerRelaxed, bodyRelaxed, seal, headers, lifetime) {
			const fn = "DomainDKIMAdd";
			const paramTypes = [["string"], ["string"], ["string"], ["string"], ["bool"], ["bool"], ["bool"], ["[]", "string"], ["int64"]];
			const returnTypes = [];
			const params = [domainName2, selector, algorithm, hash, headerRelaxed, bodyRelaxed, seal, headers, lifetime];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDKIMRemove removes a DKIM selector for a domain.
		async DomainDKIMRemove(domainName2, selector) {
			const fn = "DomainDKIMRemove";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [domainName2, selector];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDKIMSave saves the settings of selectors, and which to enable for
		// signing, for a domain. All currently configured selectors must be present,
		// selectors cannot be added/removed with this function.
		async DomainDKIMSave(domainName2, selectors, sign) {
			const fn = "DomainDKIMSave";
			const paramTypes = [["string"], ["{}", "Selector"], ["[]", "string"]];
			const returnTypes = [];
			const params = [domainName2, selectors, sign];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		// DomainDisabledSave saves the Disabled field of a domain. A disabled domain
		// rejects incoming/outgoing messages involving the domain and does not request new
		// TLS certificats with ACME.
		async DomainDisabledSave(domainName2, disabled) {
			const fn = "DomainDisabledSave";
			const paramTypes = [["string"], ["bool"]];
			const returnTypes = [];
			const params = [domainName2, disabled];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasAdd(aliaslp, domainName2, alias) {
			const fn = "AliasAdd";
			const paramTypes = [["string"], ["string"], ["Alias"]];
			const returnTypes = [];
			const params = [aliaslp, domainName2, alias];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasUpdate(aliaslp, domainName2, postPublic, listMembers, allowMsgFrom) {
			const fn = "AliasUpdate";
			const paramTypes = [["string"], ["string"], ["bool"], ["bool"], ["bool"]];
			const returnTypes = [];
			const params = [aliaslp, domainName2, postPublic, listMembers, allowMsgFrom];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasRemove(aliaslp, domainName2) {
			const fn = "AliasRemove";
			const paramTypes = [["string"], ["string"]];
			const returnTypes = [];
			const params = [aliaslp, domainName2];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasAddressesAdd(aliaslp, domainName2, addresses) {
			const fn = "AliasAddressesAdd";
			const paramTypes = [["string"], ["string"], ["[]", "string"]];
			const returnTypes = [];
			const params = [aliaslp, domainName2, addresses];
			return await _sherpaCall(this.baseURL, this.authState, { ...this.options }, paramTypes, returnTypes, fn, params);
		}
		async AliasAddressesRemove(aliaslp, domainName2, addresses) {
			const fn = "AliasAddressesRemove";
			const paramTypes = [["string"], ["string"], ["[]", "string"]];
			const returnTypes = [];
			const params = [aliaslp, domainName2, addresses];
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
			const config2 = JSON.parse(json2 || "null") || {};
			const waitMinMsec = config2.waitMinMsec || 0;
			const waitMaxMsec = config2.waitMaxMsec || 0;
			const wait = Math.random() * (waitMaxMsec - waitMinMsec);
			const failRate = config2.failRate || 0;
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

	// .js/webadmin/admin.js
	var moxversion;
	var moxgoos;
	var moxgoarch;
	var login = /* @__PURE__ */ __name(async (reason) => {
		return new Promise((resolve, _) => {
			const origFocus = document.activeElement;
			let reasonElem;
			let fieldset;
			let password;
			const root = dom.div(style({ position: "absolute", top: 0, right: 0, bottom: 0, left: 0, backgroundColor: "#eee", display: "flex", alignItems: "center", justifyContent: "center", zIndex: "1", animation: "fadein .15s ease-in" }), dom.div(style({ display: "flex", flexDirection: "column", alignItems: "center" }), reasonElem = reason ? dom.div(style({ marginBottom: "2ex", textAlign: "center" }), reason) : dom.div(), dom.div(style({ backgroundColor: "white", borderRadius: ".25em", padding: "1em", boxShadow: "0 0 20px rgba(0, 0, 0, 0.1)", border: "1px solid #ddd", maxWidth: "95vw", overflowX: "auto", maxHeight: "95vh", overflowY: "auto", marginBottom: "20vh" }), dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				reasonElem.remove();
				try {
					fieldset.disabled = true;
					const loginToken = await client.LoginPrep();
					const token = await client.Login(loginToken, password.value);
					try {
						window.localStorage.setItem("webadmincsrftoken", token);
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
			}, "submit"), fieldset = dom.fieldset(dom.h1("Admin"), dom.label(style({ display: "block", marginBottom: "2ex" }), dom.div("Password", style({ marginBottom: ".5ex" })), password = dom.input(attr.type("password"), attr.autocomplete("current-password"), attr.required(""))), dom.div(style({ textAlign: "center" }), dom.submitbutton("Login")))))));
			document.body.appendChild(root);
			password.focus();
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
	var client = new Client().withOptions({ csrfHeader: "x-mox-csrf", login }).withAuthToken(localStorageGet("webadmincsrftoken") || "");
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
	var green = "#1dea20";
	var yellow = "#ffe400";
	var red = "#ff7443";
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
			dom.div(style({ float: "right" }), dom.clickbutton("Logout", attr.title("Logout, invalidating this session."), /* @__PURE__ */ __name(async function click(e) {
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
				localStorageRemove("webadmincsrftoken");
				window.location.reload();
			}, "click"))),
			dom.h1(l.map((e, index2) => index2 === 0 ? crumblink2(e) : [" / ", crumblink2(e)])),
			dom.br()
		];
	}, "crumbs");
	var errmsg = /* @__PURE__ */ __name((err) => "" + (err.message || "(no error message)"), "errmsg");
	var footer = /* @__PURE__ */ __name(() => dom.div(style({ marginTop: "6ex", opacity: 0.75 }), link("https://www.xmox.nl", "mox"), " ", moxversion, " ", moxgoos, "/", moxgoarch, ", ", dom.a(attr.href("licenses.txt"), "licenses")), "footer");
	var age = /* @__PURE__ */ __name((date, future, nowSecs) => {
		if (!nowSecs) {
			nowSecs = (/* @__PURE__ */ new Date()).getTime() / 1e3;
		}
		let t = nowSecs - date.getTime() / 1e3;
		let negative = false;
		if (t < 0) {
			negative = true;
			t = -t;
		}
		const minute2 = 60;
		const hour2 = 60 * minute2;
		const day2 = 24 * hour2;
		const month = 30 * day2;
		const year = 365 * day2;
		const periods = [year, month, day2, hour2, minute2, 1];
		const suffix = ["y", "m", "d", "h", "mins", "s"];
		let l = [];
		for (let i = 0; i < periods.length; i++) {
			const p = periods[i];
			if (t >= 2 * p || i == periods.length - 1) {
				const n = Math.floor(t / p);
				l.push("" + n + suffix[i]);
				t -= n * p;
				if (l.length >= 2) {
					break;
				}
			}
		}
		let s = l.join(" ");
		if (!future || !negative) {
			s += " ago";
		}
		return dom.span(attr.title(date.toString()), s);
	}, "age");
	var domainName = /* @__PURE__ */ __name((d) => {
		return d.Unicode || d.ASCII;
	}, "domainName");
	var domainString = /* @__PURE__ */ __name((d) => {
		if (d.Unicode) {
			return d.Unicode + " (" + d.ASCII + ")";
		}
		return d.ASCII;
	}, "domainString");
	var formatIP = /* @__PURE__ */ __name((s) => {
		const buf = window.atob(s);
		const bytes = Uint8Array.from(buf, (m) => m.codePointAt(0) || 0);
		if (bytes.length === 4 || isIPv4MappedIPv6(bytes)) {
			return [bytes.at(-4), bytes.at(-3), bytes.at(-2), bytes.at(-1)].join(".");
		}
		return formatIPv6(bytes);
	}, "formatIP");
	var v4v6Prefix = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255]);
	var isIPv4MappedIPv6 = /* @__PURE__ */ __name((b) => {
		if (b.length !== 16) {
			return false;
		}
		for (let i = 0; i < v4v6Prefix.length; i++) {
			if (b[i] !== v4v6Prefix[i]) {
				return false;
			}
		}
		return true;
	}, "isIPv4MappedIPv6");
	var formatIPv6 = /* @__PURE__ */ __name((b) => {
		const hexchars = "0123456789abcdef";
		const hex = /* @__PURE__ */ __name((v, skipzero) => (skipzero && (v >> 4 & 15) === 0 ? "" : hexchars[v >> 4 & 15]) + hexchars[v & 15], "hex");
		let zeroStart = 0, zeroEnd = 0;
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
			} else if (j > i) {
				i = j;
			} else {
				i++;
			}
		}
		let s = "";
		for (let i2 = 0; i2 < 16; i2++) {
			if (i2 === zeroStart) {
				s += "::";
			} else if (i2 < zeroStart || i2 >= zeroEnd) {
				if (i2 > 0 && i2 % 2 === 0 && !s.endsWith(":")) {
					s += ":";
				}
				if (i2 % 2 === 1 || b[i2] !== 0) {
					s += hex(b[i2], s === "" || s.endsWith(":"));
				}
			}
		}
		return s;
	}, "formatIPv6");
	var ipdomainString = /* @__PURE__ */ __name((ipd) => {
		if (ipd.IP !== "") {
			return formatIP(ipd.IP);
		}
		return domainString(ipd.Domain);
	}, "ipdomainString");
	var formatSize = /* @__PURE__ */ __name((n) => {
		if (n > 10 * 1024 * 1024) {
			return Math.round(n / (1024 * 1024)) + " mb";
		} else if (n > 500) {
			return Math.round(n / 1024) + " kb";
		}
		return n + " bytes";
	}, "formatSize");
	var index = /* @__PURE__ */ __name(async () => {
		const [domains, queueSize, hooksQueueSize, checkUpdatesEnabled, [accounts2, accountsDisabled]] = await Promise.all([
			client.Domains(),
			client.QueueSize(),
			client.HookQueueSize(),
			client.CheckUpdatesEnabled(),
			client.Accounts()
		]);
		let fieldset;
		let disabled;
		let domain2;
		let account2;
		let localpart;
		let recvIDFieldset;
		let recvID;
		let cidElem;
		return dom.div(
			crumbs("Mox Admin"),
			checkUpdatesEnabled ? [] : dom.p(box(yellow, "Warning: Checking for updates has not been enabled in mox.conf (CheckUpdates: true).", dom.br(), "Make sure you stay up to date through another mechanism!", dom.br(), "You have a responsibility to keep the internet-connected software you run up to date and secure!", dom.br(), "See ", link("https://updates.xmox.nl/changelog"))),
			dom.p(dom.a("Accounts", attr.href("#accounts")), dom.br(), dom.a("Queue", attr.href("#queue")), " (" + queueSize + ")", dom.br(), dom.a("Webhook queue", attr.href("#webhookqueue")), " (" + hooksQueueSize + ")", dom.br()),
			dom.h2("Domains"),
			(domains || []).length === 0 ? box(red, "No domains") : dom.ul((domains || []).map((d) => dom.li(dom.a(attr.href("#domains/" + domainName(d.Domain)), domainString(d.Domain)), d.Disabled ? " (disabled)" : []))),
			dom.br(),
			dom.h2("Add domain"),
			dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(fieldset, client.DomainAdd(disabled.checked, domain2.value, account2.value, localpart.value));
				window.location.hash = "#domains/" + domain2.value;
			}, "submit"), fieldset = dom.fieldset(dom.label(style({ display: "inline-block" }), dom.span("Domain", attr.title("Domain for incoming/outgoing email to add to mox. Can also be a subdomain of a domain already configured.")), dom.br(), domain2 = dom.input(attr.required(""))), " ", dom.label(style({ display: "inline-block" }), dom.span("Postmaster/reporting account", attr.title("Account that is considered the owner of this domain. If the account does not yet exist, it will be created and a a localpart is required for the initial email address.")), dom.br(), account2 = dom.input(attr.required(""), attr.list("accountList")), dom.datalist(attr.id("accountList"), (accounts2 || []).map((a) => dom.option(attr.value(a), a + (accountsDisabled?.includes(a) ? " (disabled)" : ""))))), " ", dom.label(style({ display: "inline-block" }), dom.span("Localpart (if new account)", attr.title('Must be set if and only if account does not yet exist. A localpart is the part before the "@"-sign of an email address. An account requires an email address, so creating a new account for a domain requires a localpart to form an initial email address.')), dom.br(), localpart = dom.input()), " ", dom.label(disabled = dom.input(attr.type("checkbox")), " Disabled", attr.title("Disabled domains do fetch new certificates with ACME and do not accept incoming or outgoing messages involving the domain. Accounts and addresses referencing a disabled domain can be created. Useful during/before migrations.")), " ", dom.submitbutton("Add domain", attr.title("Domain will be added and the config reloaded. Add the required DNS records after adding the domain.")))),
			dom.br(),
			dom.h2("Reports"),
			dom.div(dom.a("DMARC", attr.href("#dmarc/reports"))),
			dom.div(dom.a("TLS", attr.href("#tlsrpt/reports"))),
			dom.br(),
			dom.h2("Operations"),
			dom.div(dom.a("MTA-STS policies", attr.href("#mtasts"))),
			dom.div(dom.a("DMARC evaluations", attr.href("#dmarc/evaluations"))),
			dom.div(dom.a("TLS connection results", attr.href("#tlsrpt/results"))),
			dom.div(dom.a("DNSBL", attr.href("#dnsbl"))),
			dom.div(style({ marginTop: ".5ex" }), dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				dom._kids(cidElem);
				const cid = await check(recvIDFieldset, client.LookupCid(recvID.value));
				dom._kids(cidElem, cid);
			}, "submit"), recvIDFieldset = dom.fieldset(dom.label("Received ID", attr.title("The ID in the Received header that was added during incoming delivery.")), " ", recvID = dom.input(attr.required("")), " ", dom.submitbutton("Lookup cid", attr.title('Logging about an incoming message includes an attribute "cid", a counter identifying the transaction related to delivery of the message. The ID in the received header is an encrypted cid, which this form decrypts, after which you can look it up in the logging.')), " ", cidElem = dom.span()))),
			// todo: routing, globally, per domain and per account
			dom.br(),
			dom.h2("Configuration"),
			dom.div(dom.a("Routes", attr.href("#routes"))),
			dom.div(dom.a("Webserver", attr.href("#webserver"))),
			dom.div(dom.a("Files", attr.href("#config"))),
			dom.div(dom.a("Log levels", attr.href("#loglevels"))),
			footer()
		);
	}, "index");
	var globalRoutes = /* @__PURE__ */ __name(async () => {
		const [transports, config2] = await Promise.all([
			client.Transports(),
			client.Config()
		]);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "Routes"), RoutesEditor("global", transports, config2.Routes || [], async (routes) => await client.RoutesSave(routes)));
	}, "globalRoutes");
	var config = /* @__PURE__ */ __name(async () => {
		const [staticPath, dynamicPath, staticText, dynamicText] = await client.ConfigFiles();
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "Config"), dom.h2(staticPath), dom.pre(dom._class("literal"), staticText), dom.h2(dynamicPath), dom.pre(dom._class("literal"), dynamicText));
	}, "config");
	var loglevels = /* @__PURE__ */ __name(async () => {
		const loglevels2 = await client.LogLevels();
		const levels = ["error", "warn", "info", "debug", "trace", "traceauth", "tracedata"];
		let form;
		let fieldset;
		let pkg;
		let level;
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "Log levels"), dom.p("Note: changing a log level here only changes it for the current process. When mox restarts, it sets the log levels from the configuration file. Change mox.conf to keep the changes."), dom.table(dom.thead(dom.tr(dom.th("Package", attr.title("Log levels can be configured per package. E.g. smtpserver, imapserver, dkim, dmarc, tlsrpt, etc.")), dom.th("Level", attr.title('If you set the log level to "trace", imap and smtp protocol transcripts will be logged. Sensitive authentication is replaced with "***" unless the level is >= "traceauth". Data is masked with "..." unless the level is "tracedata".')), dom.th("Action"))), dom.tbody(Object.entries(loglevels2).map((t) => {
			let lvl;
			return dom.tr(dom.td(t[0] || "(default)"), dom.td(lvl = dom.select(levels.map((l) => dom.option(l, t[1] === l ? attr.selected("") : [])))), dom.td(dom.clickbutton("Save", attr.title("Set new log level for package."), /* @__PURE__ */ __name(async function click(e) {
				e.preventDefault();
				await check(e.target, client.LogLevelSet(t[0], lvl.value));
				window.location.reload();
			}, "click")), " ", dom.clickbutton("Remove", attr.title("Remove this log level, the default log level will apply."), t[0] === "" ? attr.disabled("") : [], /* @__PURE__ */ __name(async function click(e) {
				e.preventDefault();
				await check(e.target, client.LogLevelRemove(t[0]));
				window.location.reload();
			}, "click"))));
		}))), dom.br(), dom.h2("Add log level setting"), form = dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(fieldset, client.LogLevelSet(pkg.value, level.value));
			form.reset();
			window.location.reload();
		}, "submit"), fieldset = dom.fieldset(dom.label(style({ display: "inline-block" }), "Package", dom.br(), pkg = dom.input(attr.required(""))), " ", dom.label(style({ display: "inline-block" }), "Level", dom.br(), level = dom.select(attr.required(""), levels.map((l) => dom.option(l, l === "debug" ? attr.selected("") : [])))), " ", dom.submitbutton("Add")), dom.br(), dom.p("Suggestions for packages: autotls dkim dmarc dmarcdb dns dnsbl dsn http imapserver iprev junk message metrics mox moxio mtasts mtastsdb publicsuffix queue sendmail serve smtpserver spf store subjectpass tlsrpt tlsrptdb updates")));
	}, "loglevels");
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
	var inlineBox = /* @__PURE__ */ __name((color, ...l) => dom.span(style({
		display: "inline-block",
		padding: color ? "0.05em 0.2em" : "",
		backgroundColor: color,
		borderRadius: "3px"
	}), l), "inlineBox");
	var accounts = /* @__PURE__ */ __name(async () => {
		const [[accounts2, accountsDisabled], domains, loginAttempts] = await Promise.all([
			client.Accounts(),
			client.Domains(),
			client.LoginAttempts("", 10)
		]);
		let fieldset;
		let localpart;
		let domain2;
		let account2;
		let accountModified = false;
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "Accounts"), dom.h2("Accounts"), (accounts2 || []).length === 0 ? dom.p("No accounts") : dom.ul((accounts2 || []).map((s) => dom.li(dom.a(attr.href("#accounts/l/" + s), s), accountsDisabled?.includes(s) ? " (disabled)" : ""))), dom.br(), dom.h2("Add account"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(fieldset, client.AccountAdd(account2.value, localpart.value + "@" + domain2.value));
			window.location.hash = "#accounts/l/" + account2.value;
		}, "submit"), fieldset = dom.fieldset(dom.p("Start with the initial email address for the account. The localpart is the account name too by default, but the account name can be changed."), dom.label(style({ display: "inline-block" }), dom.span("Localpart", attr.title('The part before the "@" of an email address. More addresses, also at different domains, can be added after the account has been created.')), dom.br(), localpart = dom.input(attr.required(""), /* @__PURE__ */ __name(function keyup() {
			if (!accountModified) {
				account2.value = localpart.value;
			}
		}, "keyup"))), "@", dom.label(style({ display: "inline-block" }), dom.span("Domain", attr.title('The domain of the email address, after the "@".')), dom.br(), domain2 = dom.select(attr.required(""), (domains || []).map((d) => dom.option(domainName(d.Domain))))), " ", dom.label(style({ display: "inline-block" }), dom.span("Account name", attr.title('An account has a password, and email address(es) (possibly at different domains). Its messages and the message index database are are stored in the file system in a directory with the name of the account. An account name is not an email address. Use a name like a unix user name, or the localpart (the part before the "@") of the initial address.')), dom.br(), account2 = dom.input(attr.required(""), /* @__PURE__ */ __name(function change() {
			accountModified = true;
		}, "change"))), " ", dom.submitbutton("Add account", attr.title("The account will be added and the config reloaded.")))), dom.br(), dom.h2("Recent login attempts", attr.title("Login attempts are stored for 30 days. At most 10000 failed login attempts are stored per account to prevent unlimited growth of the database.")), renderLoginAttempts(true, loginAttempts || []), dom.br(), loginAttempts && loginAttempts.length >= 10 ? dom.p("See ", dom.a(attr.href("#accounts/loginattempts"), "all login attempts"), ".") : []);
	}, "accounts");
	var loginattempts = /* @__PURE__ */ __name(async () => {
		const loginAttempts = await client.LoginAttempts("", 0);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("Accounts", "#accounts"), "Login attempts"), dom.h2("Login attempts"), dom.p("Login attempts are stored for 30 days. At most 10000 failed login attempts are stored per account to prevent unlimited growth of the database."), renderLoginAttempts(true, loginAttempts || []));
	}, "loginattempts");
	var accountloginattempts = /* @__PURE__ */ __name(async (accountName) => {
		const loginAttempts = await client.LoginAttempts(accountName, 0);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("Accounts", "#accounts"), ["(admin)", "-"].includes(accountName) ? accountName : crumblink(accountName, "#accounts/l/" + accountName), "Login attempts"), dom.h2("Login attempts"), dom.p("Login attempts are stored for 30 days. At most 10000 failed login attempts are stored per account to prevent unlimited growth of the database."), renderLoginAttempts(false, loginAttempts || []));
	}, "accountloginattempts");
	var renderLoginAttempts = /* @__PURE__ */ __name((accountLinks, loginAttempts) => {
		const nowSecs = (/* @__PURE__ */ new Date()).getTime() / 1e3;
		return dom.table(dom.thead(dom.tr(dom.th("Time"), dom.th("Result"), dom.th("Count"), dom.th("Account"), dom.th("Address"), dom.th("Protocol"), dom.th("Mechanism"), dom.th("User Agent"), dom.th("Remote IP"), dom.th("Local IP"), dom.th("TLS"), dom.th("TLS pubkey fingerprint"), dom.th("First seen"))), dom.tbody(loginAttempts.length ? [] : dom.tr(dom.td(attr.colspan("13"), "No login attempts in past 30 days.")), loginAttempts.map((la) => dom.tr(dom.td(age(la.Last, false, nowSecs)), dom.td(la.Result === "ok" ? la.Result : box(red, la.Result)), dom.td("" + la.Count), dom.td(accountLinks ? dom.a(attr.href("#accounts/l/" + la.AccountName + "/loginattempts"), la.AccountName) : la.AccountName), dom.td(la.LoginAddress), dom.td(la.Protocol), dom.td(la.AuthMech), dom.td(la.UserAgent), dom.td(la.RemoteIP), dom.td(la.LocalIP), dom.td(la.TLS), dom.td(la.TLSPubKeyFingerprint), dom.td(age(la.First, false, nowSecs))))));
	}, "renderLoginAttempts");
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
	var RoutesEditor = /* @__PURE__ */ __name((kind, transports, routes, save) => {
		const transportNames = Object.keys(transports || {});
		transportNames.sort();
		const hdr = dom.h2("Routes", attr.title('Messages submitted to the queue for outgoing delivery are delivered directly to the MX records of the recipient domain by default. However, other "transports" can be configured, such as SMTP submission/relay or connecting through a SOCKS proxy. Routes with matching rules and a transport can be configured for accounts, domains and globally. Routes are evaluated in that order, the first match is applied.'));
		let routesElem;
		const render = /* @__PURE__ */ __name(() => {
			if (transportNames.length === 0) {
				return [hdr, dom.p("No transports configured.", attr.title("To configure routes, first configure transports via the mox.conf config file."))];
			}
			let routesFieldset;
			let routeRows = [];
			let elem = dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.stopPropagation();
				e.preventDefault();
				await check(routesFieldset, save(routeRows.map((rr) => rr.gather())));
			}, "submit"), routesFieldset = dom.fieldset(dom.table(dom.thead(dom.tr(dom.th("From domain"), dom.th("To domain"), dom.th("Minimum attempts"), dom.th("Transport"), dom.th(dom.clickbutton("Add", /* @__PURE__ */ __name(function click() {
				routes = routeRows.map((rr) => rr.gather());
				routes.push({ FromDomain: [], ToDomain: [], MinimumAttempts: 0, Transport: transportNames[0] });
				render();
			}, "click"))))), dom.tbody((routes || []).length === 0 ? dom.tr(dom.td(attr.colspan("5"), "No routes.")) : [], routeRows = (routes || []).map((r, index2) => {
				let fromDomain = dom.input(attr.value((r.FromDomain || []).join(",")));
				let toDomain = dom.input(attr.value((r.ToDomain || []).join(",")));
				let minimumAttempts = dom.input(attr.value("" + r.MinimumAttempts));
				let transport = dom.select(attr.required(""), transportNames.map((s) => dom.option(s, s === r.Transport ? attr.selected("") : [])));
				const tr = dom.tr(dom.td(fromDomain), dom.td(toDomain), dom.td(minimumAttempts), dom.td(transport), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(function click() {
					routeRows.splice(index2, 1);
					routes = routeRows.map((rr) => rr.gather());
					render();
				}, "click"))));
				return {
					root: tr,
					gather: /* @__PURE__ */ __name(() => {
						return {
							FromDomain: fromDomain.value ? fromDomain.value.split(",") : [],
							ToDomain: toDomain.value ? toDomain.value.split(",") : [],
							MinimumAttempts: parseInt(minimumAttempts.value) || 0,
							Transport: transport.value
						};
					}, "gather")
				};
			}))), dom.div(dom.submitbutton("Save"))));
			if (!routesElem && (routes || []).length === 0) {
				elem = dom.div("No " + kind + " routes configured. ", dom.clickbutton("Add", /* @__PURE__ */ __name(function click() {
					routes = routeRows.map((rr) => rr.gather());
					routes.push({ FromDomain: [], ToDomain: [], MinimumAttempts: 0, Transport: transportNames[0] });
					render();
				}, "click")));
			}
			elem = dom.div(hdr, elem);
			if (routesElem) {
				routesElem.replaceWith(elem);
			}
			routesElem = elem;
			return elem;
		}, "render");
		return render();
	}, "RoutesEditor");
	var account = /* @__PURE__ */ __name(async (name) => {
		const [[config2, diskUsage], domains, transports, tlspubkeys, loginAttempts] = await Promise.all([
			client.Account(name),
			client.Domains(),
			client.Transports(),
			client.TLSPublicKeys(name),
			client.LoginAttempts(name, 10)
		]);
		let form;
		let fieldset;
		let localpart;
		let domain2;
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
		const xparseSize = /* @__PURE__ */ __name((s) => {
			s = s.toLowerCase();
			let mult = 1;
			if (s.endsWith("k")) {
				mult = 1024;
			} else if (s.endsWith("m")) {
				mult = 1024 * 1024;
			} else if (s.endsWith("g")) {
				mult = 1024 * 1024 * 1024;
			} else if (s.endsWith("t")) {
				mult = 1024 * 1024 * 1024 * 1024;
			}
			if (mult !== 1) {
				s = s.substring(0, s.length - 1);
			}
			let v = parseInt(s);
			if (isNaN(v) || s !== "" + v) {
				throw new Error('invalid number; use units like "k", "m", "g", for example "2g". specify 0 to use the global default quota, or -1 for unlimited storage overriding the global quota');
			}
			return v * mult;
		}, "xparseSize");
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("Accounts", "#accounts"), name), config2.LoginDisabled ? dom.p(box(yellow, "Warning: Login for this account is disabled with message: " + config2.LoginDisabled)) : [], dom.h2("Addresses"), dom.table(dom.thead(dom.tr(dom.th("Address"), dom.th("Action"))), dom.tbody(Object.keys(config2.Destinations || {}).length === 0 ? dom.tr(dom.td(attr.colspan("2"), "(None, login disabled)")) : [], Object.keys(config2.Destinations || {}).map((k) => {
			let v = k;
			const t = k.split("@");
			if (t.length > 1) {
				const d = t[t.length - 1];
				const lp = t.slice(0, t.length - 1).join("@");
				v = [
					prewrap(lp),
					"@",
					dom.a(d, attr.href("#domains/" + d))
				];
				if (lp === "") {
					v.unshift("(catchall) ");
				}
			}
			return dom.tr(dom.td(v), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(async function click(e) {
				e.preventDefault();
				const aliases = (config2.Aliases || []).filter((aa) => aa.SubscriptionAddress === k).map((aa) => aa.Alias.LocalpartStr + "@" + domainName(aa.Alias.Domain));
				const aliasmsg = aliases.length > 0 ? " Address will be removed from alias(es): " + aliases.join(", ") : "";
				if (!window.confirm("Are you sure you want to remove this address?" + aliasmsg)) {
					return;
				}
				await check(e.target, client.AddressRemove(k));
				window.location.reload();
			}, "click"))));
		}))), dom.br(), dom.h2("Add address"), form = dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			const address = localpart.value + "@" + domain2.value;
			await check(fieldset, client.AddressAdd(address, name));
			form.reset();
			window.location.reload();
		}, "submit"), fieldset = dom.fieldset(dom.label(style({ display: "inline-block" }), dom.span("Localpart", attr.title('The localpart is the part before the "@"-sign of an email address. If empty, a catchall address is configured for the domain.')), dom.br(), localpart = dom.input()), "@", dom.label(style({ display: "inline-block" }), dom.span("Domain"), dom.br(), domain2 = dom.select((domains || []).map((d) => dom.option(domainName(d.Domain), domainName(d.Domain) === config2.Domain ? attr.selected("") : [])))), " ", dom.submitbutton("Add address"))), dom.br(), dom.h2("Alias (list) membership"), dom.table(dom.thead(dom.tr(dom.th("Alias address", attr.title("Messages sent to this address will be delivered to all members of the alias/list. A member does not receive a message if their address is in the message From header.")), dom.th("Subscription address"), dom.th("Allowed senders", attr.title("Whether only members can send through the alias/list, or anyone.")), dom.th("Send as alias address", attr.title('If enabled, messages can be sent with the alias address in the message "From" header.')), dom.th("Members visible", attr.title("If enabled, members can see the addresses of other members.")))), (config2.Aliases || []).length === 0 ? dom.tr(dom.td(attr.colspan("6"), "None")) : [], (config2.Aliases || []).sort((a, b) => a.Alias.LocalpartStr < b.Alias.LocalpartStr ? -1 : domainName(a.Alias.Domain) < domainName(b.Alias.Domain) ? -1 : 1).map((a) => dom.tr(dom.td(dom.a(prewrap(a.Alias.LocalpartStr, "@", domainName(a.Alias.Domain)), attr.href("#domains/" + domainName(a.Alias.Domain) + "/alias/" + encodeURIComponent(a.Alias.LocalpartStr)))), dom.td(prewrap(a.SubscriptionAddress)), dom.td(a.Alias.PostPublic ? "Anyone" : "Members only"), dom.td(a.Alias.AllowMsgFrom ? "Yes" : "No"), dom.td(a.Alias.ListMembers ? "Yes" : "No"), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(async function click(e) {
			await check(e.target, client.AliasAddressesRemove(a.Alias.LocalpartStr, domainName(a.Alias.Domain), [a.SubscriptionAddress]));
			window.location.reload();
		}, "click")))))), dom.br(), dom.h2("Settings"), dom.form(fieldsetSettings = dom.fieldset(dom.label(style({ display: "block", marginBottom: ".5ex" }), dom.span("Maximum outgoing messages per day", attr.title("Maximum number of outgoing messages for this account in a 24 hour window. This limits the damage to recipients and the reputation of this mail server in case of account compromise. Default 1000. MaxOutgoingMessagesPerDay in configuration file.")), dom.br(), maxOutgoingMessagesPerDay = dom.input(attr.type("number"), attr.required(""), attr.value("" + (config2.MaxOutgoingMessagesPerDay || 1e3)))), dom.label(style({ display: "block", marginBottom: ".5ex" }), dom.span("Maximum first-time recipients per day", attr.title("Maximum number of first-time recipients in outgoing messages for this account in a 24 hour window. This limits the damage to recipients and the reputation of this mail server in case of account compromise. Default 200. MaxFirstTimeRecipientsPerDay in configuration file.")), dom.br(), maxFirstTimeRecipientsPerDay = dom.input(attr.type("number"), attr.required(""), attr.value("" + (config2.MaxFirstTimeRecipientsPerDay || 200)))), dom.label(style({ display: "block", marginBottom: ".5ex" }), dom.span("Disk usage quota: Maximum total message size ", attr.title('Default maximum total message size in bytes for the account, overriding any globally configured default maximum size if non-zero. A negative value can be used to have no limit in case there is a limit by default. Attempting to add new messages to an account beyond its maximum total size will result in an error. Useful to prevent a single account from filling storage. Use units "k" for kilobytes, or "m", "g", "t".')), dom.br(), quotaMessageSize = dom.input(attr.value(formatQuotaSize(config2.QuotaMessageSize))), " Current usage is ", formatQuotaSize(Math.floor(diskUsage / (1024 * 1024)) * 1024 * 1024), "."), dom.div(style({ display: "block", marginBottom: ".5ex" }), dom.label(firstTimeSenderDelay = dom.input(attr.type("checkbox"), config2.NoFirstTimeSenderDelay ? [] : attr.checked("")), " ", dom.span("Delay deliveries from first-time senders", attr.title("To slow down potential spammers, when the message is misclassified as non-junk. Turning off the delay can be useful when the account processes messages automatically and needs fast responses.")))), dom.div(style({ display: "block", marginBottom: ".5ex" }), dom.label(noCustomPassword = dom.input(attr.type("checkbox"), config2.NoCustomPassword ? attr.checked("") : []), " ", dom.span("Don't allow account to set a password of their choice", attr.title("If set, this account cannot set a password of their own choice, but can only set a new randomly generated password, preventing password reuse across services and use of weak passwords.")))), dom.submitbutton("Save")), /* @__PURE__ */ __name(async function submit(e) {
			e.stopPropagation();
			e.preventDefault();
			await check(fieldsetSettings, (async () => await client.AccountSettingsSave(name, parseInt(maxOutgoingMessagesPerDay.value) || 0, parseInt(maxFirstTimeRecipientsPerDay.value) || 0, xparseSize(quotaMessageSize.value), firstTimeSenderDelay.checked, noCustomPassword.checked))());
		}, "submit")), dom.br(), dom.h2("Set new password"), formPassword = dom.form(fieldsetPassword = dom.fieldset(dom.label(style({ display: "inline-block" }), "New password", dom.br(), password = dom.input(attr.type("password"), attr.autocomplete("new-password"), attr.required(""), /* @__PURE__ */ __name(function focus() {
			passwordHint.style.display = "";
		}, "focus"))), " ", dom.submitbutton("Change password")), passwordHint = dom.div(style({ display: "none", marginTop: ".5ex" }), dom.clickbutton("Generate random password", /* @__PURE__ */ __name(function click(e) {
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
			password.type = "text";
			password.value = s;
		}, "click")), dom.div(dom._class("text"), box(yellow, "Important: Bots will try to bruteforce your password. Connections with failed authentication attempts will be rate limited but attackers WILL find passwords reused at other services and weak passwords. If your account is compromised, spammers are likely to abuse your system, spamming your address and the wider internet in your name. So please pick a random, unguessable password, preferrably at least 12 characters."))), /* @__PURE__ */ __name(async function submit(e) {
			e.stopPropagation();
			e.preventDefault();
			await check(fieldsetPassword, client.SetPassword(name, password.value));
			window.alert("Password has been changed.");
			formPassword.reset();
		}, "submit")), dom.br(), dom.h2("TLS public keys", attr.title("For TLS client authentication with certificates, for IMAP and/or submission (SMTP). Only the public key of the certificate is used during TLS authentication, to identify this account. Names, expiration or constraints are not verified.")), dom.table(dom.thead(dom.tr(dom.th("Login address"), dom.th("Name"), dom.th("Type"), dom.th('No IMAP "preauth"', attr.title('New IMAP immediate TLS connections authenticated with a client certificate are automatically switched to "authenticated" state with an untagged IMAP "preauth" message by default. IMAP connections have a state machine specifying when commands are allowed. Authenticating is not allowed while in the "authenticated" state. Enable this option to work around clients that would try to authenticated anyway.')), dom.th("Fingerprint"))), dom.tbody(tlspubkeys?.length ? [] : dom.tr(dom.td(attr.colspan("5"), "None")), (tlspubkeys || []).map((tpk) => {
			const row = dom.tr(dom.td(tpk.LoginAddress), dom.td(tpk.Name), dom.td(tpk.Type), dom.td(tpk.NoIMAPPreauth ? "Enabled" : ""), dom.td(tpk.Fingerprint));
			return row;
		}))), dom.br(), RoutesEditor("account-specific", transports, config2.Routes || [], async (routes) => await client.AccountRoutesSave(name, routes)), dom.br(), dom.h2("Danger"), dom.div(config2.LoginDisabled ? [
			box(yellow, "Account login is currently disabled."),
			dom.clickbutton("Enable account login", /* @__PURE__ */ __name(async function click(e) {
				if (window.confirm("Are you sure you want to enable login to this account?")) {
					await check(e.target, client.AccountLoginDisabledSave(name, ""));
					window.location.reload();
				}
			}, "click"))
		] : dom.clickbutton("Disable account login", /* @__PURE__ */ __name(function click() {
			let fieldset2;
			let loginDisabled;
			const close = popup(dom.h1("Disable account login"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(fieldset2, client.AccountLoginDisabledSave(name, loginDisabled.value));
				close();
				window.location.reload();
			}, "submit"), fieldset2 = dom.fieldset(dom.label(dom.div("Message to user"), loginDisabled = dom.input(attr.required(""), style({ width: "100%" })), dom.p(style({ fontStyle: "italic" }), "Will be shown to user on login attempts. Single line, no special and maximum 256 characters since message is used in IMAP/SMTP.")), dom.div(dom.submitbutton("Disable login")))));
		}, "click"))), dom.br(), dom.h2("Recent login attempts", attr.title("Login attempts are stored for 30 days. At most 10000 failed login attempts are stored per account to prevent unlimited growth of the database.")), renderLoginAttempts(false, loginAttempts || []), dom.br(), loginAttempts && loginAttempts.length >= 10 ? dom.p("See ", dom.a(attr.href("#accounts/l/" + name + "/loginattempts"), "all login attempts"), " for this account.") : [], dom.br(), dom.clickbutton("Remove account", /* @__PURE__ */ __name(async function click(e) {
			e.preventDefault();
			if (!window.confirm("Are you sure you want to remove this account? All account data, including messages will be removed.")) {
				return;
			}
			await check(e.target, client.AccountRemove(name));
			window.location.hash = "#accounts";
		}, "click")));
	}, "account");
	var second = 1e3 * 1e3 * 1e3;
	var minute = 60 * second;
	var hour = 60 * minute;
	var day = 24 * hour;
	var week = 7 * day;
	var parseDuration = /* @__PURE__ */ __name((s) => {
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
	var formatDuration = /* @__PURE__ */ __name((v, goDuration) => {
		if (v === 0) {
			return "";
		}
		const is = /* @__PURE__ */ __name((period2) => v > 0 && Math.round(v / period2) === v / period2, "is");
		const format = /* @__PURE__ */ __name((period2, s) => "" + v / period2 + s, "format");
		if (!goDuration && is(week)) {
			return format(week, "w");
		}
		if (!goDuration && is(day)) {
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
	var domain = /* @__PURE__ */ __name(async (d) => {
		const end = /* @__PURE__ */ new Date();
		const start = new Date((/* @__PURE__ */ new Date()).getTime() - 30 * 24 * 3600 * 1e3);
		const [dmarcSummaries, tlsrptSummaries, [localpartAccounts, localpartAliases], clientConfigs, [accounts2, accountsDisabled], domainConfig, transports] = await Promise.all([
			client.DMARCSummaries(start, end, d),
			client.TLSRPTSummaries(start, end, d),
			client.DomainLocalparts(d),
			client.ClientConfigsDomain(d),
			client.Accounts(),
			client.DomainConfig(d),
			client.Transports()
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
		const popupDKIMHeaders = /* @__PURE__ */ __name((sel, span) => {
			const l = sel.HeadersEffective || [];
			let headers;
			const close = popup(dom.h1("Headers to sign with DKIM"), dom.p("Headers signed with DKIM cannot be modified in transit, or the signature would fail to verify. Headers that could influence how messages are interpreted are best DKIM-signed."), dom.form(/* @__PURE__ */ __name(function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				sel.HeadersEffective = headers.value.split("\n").map((s) => s.trim()).filter((s) => s);
				dom._kids(span, (sel.HeadersEffective || []).join("; "));
				close();
			}, "submit"), dom.label(style({ display: "block", marginBottom: "1ex" }), "Headers", dom.div(headers = dom.textarea(new String(l.join("\n")), attr.rows("" + Math.max(2, 1 + l.length))))), dom.div(dom.submitbutton("OK")), dom.br(), dom.p("Changes are not yet saved after closing the popup. Don't forget to save.")));
		}, "popupDKIMHeaders");
		const popupDKIMAdd = /* @__PURE__ */ __name(() => {
			let fieldset;
			let selector;
			let algorithm;
			let hash;
			let canonHeader;
			let canonBody;
			let seal;
			let headers;
			let lifetime;
			const defaultSelector = /* @__PURE__ */ __name(() => {
				const d2 = /* @__PURE__ */ new Date();
				let s = "" + d2.getFullYear();
				let mon = "" + (1 + d2.getMonth());
				s += mon.length === 1 ? "0" + mon : mon;
				s += "a";
				return s;
			}, "defaultSelector");
			popup(style({ minWidth: "30em" }), dom.h1("Add DKIM key/selector"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				if (!window.confirm("Are you sure? A key will be generated by the server, the selector configured but disabled. The page will reload, so unsaved changes to other DKIM selectors will be lost. After adding the key, first add the selector to DNS, then enable it for signing outgoing messages.")) {
					return;
				}
				await check(fieldset, (async () => await client.DomainDKIMAdd(d, selector.value, algorithm.value, hash.value, canonHeader.value === "relaxed", canonBody.value === "relaxed", seal.checked, headers.value.split("\n").map((s) => s.trim()).filter((s) => s), parseDuration(lifetime.value)))());
				window.alert("Selector added. Page will be reloaded. Don't forget to add the selector to DNS, see suggested DNS records, and don't forget to enable the selector afterwards.");
				window.location.reload();
			}, "submit"), fieldset = dom.fieldset(dom.div(style({ display: "flex", gap: "1em" }), dom.div(dom.label(style({ display: "block", marginBottom: "1ex" }), "Selector", attr.title("Used in the DKIM-Signature header, and used to form a DNS record under ._domainkey.<domain>."), dom.div(selector = dom.input(attr.required(""), attr.value(defaultSelector())))), dom.label(style({ display: "block", marginBottom: "1ex" }), "Algorithm", attr.title("For signing messages. RSA is common at the time of writing, not all mail servers recognize ed25519 signature."), dom.div(algorithm = dom.select(dom.option("rsa"), dom.option("ed25519")))), dom.label(style({ display: "block", marginBottom: "1ex" }), "Hash", attr.title("Used in signing messages. Don't use sha1 unless you understand the consequences."), dom.div(hash = dom.select(dom.option("sha256")))), dom.label(style({ display: "block", marginBottom: "1ex" }), "Canonicalization - header", attr.title("Canonicalization processes the message headers before signing. Relaxed allows more whitespace changes, making it more likely for DKIM signatures to validate after transit through servers that make whitespace modifications. Simple is more strict."), dom.div(canonHeader = dom.select(dom.option("relaxed"), dom.option("simple")))), dom.label(style({ display: "block", marginBottom: "1ex" }), "Canonicalization - body", attr.title("Like canonicalization for headers, but for the bodies."), dom.div(canonBody = dom.select(dom.option("relaxed"), dom.option("simple")))), dom.label(style({ display: "block", marginBottom: "1ex" }), "Signature lifetime", attr.title("How long a signature remains valid. Should be as long as a message may take to be delivered. The signature must be valid at the time a message is being delivered to the final destination."), dom.div(lifetime = dom.input(attr.value("3d"), attr.required("")))), dom.label(style({ display: "block", marginBottom: "1ex" }), "Seal headers", attr.title("DKIM-signatures cover headers. If headers are not sealed, additional message headers can be added with the same key without invalidating the signature. This may confuse software about which headers are trustworthy. Sealing is the safer option."), dom.div(seal = dom.input(attr.type("checkbox"), attr.checked(""))))), dom.div(dom.label(style({ display: "block", marginBottom: "1ex" }), "Headers (optional)", attr.title("Headers to sign. If left empty, a set of standard headers are signed. The (standard set of) headers are most easily edited after creating the selector/key."), dom.div(headers = dom.textarea(attr.rows("15")))))), dom.div(dom.submitbutton("Add")))));
		}, "popupDKIMAdd");
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "Domain " + domainString(dnsdomain)), domainConfig.Disabled ? dom.p(box(yellow, "Warning: Domain is disabled. Incoming/outgoing messages involving this domain are rejected and ACME for new TLS certificates is disabled.")) : [], dom.ul(dom.li(dom.a("Required DNS records", attr.href("#domains/" + d + "/dnsrecords"))), dom.li(dom.a("Check current actual DNS records and domain configuration", attr.href("#domains/" + d + "/dnscheck")))), dom.br(), dom.h2("Client configuration"), dom.p("If autoconfig/autodiscover does not work with an email client, use the settings below for this domain. Authenticate with email address and password. ", dom.span("Explicitly configure", attr.title("To prevent authentication mechanism downgrade attempts that may result in clients sending plain text passwords to a MitM.")), " the first supported authentication mechanism: SCRAM-SHA-256-PLUS, SCRAM-SHA-1-PLUS, SCRAM-SHA-256, SCRAM-SHA-1, CRAM-MD5."), dom.table(dom.thead(dom.tr(dom.th("Protocol"), dom.th("Host"), dom.th("Port"), dom.th("Listener"), dom.th("Note"))), dom.tbody((clientConfigs.Entries || []).map((e) => dom.tr(dom.td(e.Protocol), dom.td(domainString(e.Host)), dom.td("" + e.Port), dom.td("" + e.Listener), dom.td("" + e.Note))))), dom.br(), dom.h2("DMARC aggregate reports summary"), renderDMARCSummaries(dmarcSummaries || []), dom.br(), dom.h2("TLS reports summary"), renderTLSRPTSummaries(tlsrptSummaries || []), dom.br(), dom.h2("Addresses"), dom.table(dom.thead(dom.tr(dom.th("Address"), dom.th("Account"), dom.th("Action"))), dom.tbody(Object.entries(localpartAccounts).map((t) => dom.tr(dom.td(prewrap(t[0]) || "(catchall)"), dom.td(dom.a(t[1], attr.href("#accounts/l/" + t[1]))), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(async function click(e) {
			e.preventDefault();
			if (!window.confirm("Are you sure you want to remove this address? If it is a member of an alias, it will be removed from the alias.")) {
				return;
			}
			await check(e.target, client.AddressRemove(t[0] + "@" + d));
			window.location.reload();
		}, "click"))))))), dom.br(), dom.h2("Add address"), addrForm = dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(addrFieldset, client.AddressAdd(addrLocalpart.value + "@" + d, addrAccount.value));
			addrForm.reset();
			window.location.reload();
		}, "submit"), addrFieldset = dom.fieldset(dom.label(style({ display: "inline-block" }), dom.span("Localpart", attr.title('The localpart is the part before the "@"-sign of an address. An empty localpart is the catchall destination/address for the domain.')), dom.br(), addrLocalpart = dom.input()), "@", domainName(dnsdomain), " ", dom.label(style({ display: "inline-block" }), dom.span("Account", attr.title("Account to assign the address to.")), dom.br(), addrAccount = dom.select(attr.required(""), (accounts2 || []).map((a) => dom.option(attr.value(a), a + (accountsDisabled?.includes(a) ? " (disabled)" : ""))))), " ", dom.submitbutton("Add address", attr.title("Address will be added and the config reloaded.")))), dom.br(), dom.h2("Aliases (lists)"), dom.table(dom.thead(dom.tr(dom.th("Address"), dom.th("Allowed senders", attr.title("Whether only members can send through the alias/list, or anyone.")), dom.th("Send as alias address", attr.title('If enabled, messages can be sent with the alias address in the message "From" header.')), dom.th("Members visible", attr.title("If enabled, members can see the addresses of other members.")))), Object.values(localpartAliases).length === 0 ? dom.tr(dom.td(attr.colspan("4"), "None")) : [], Object.values(localpartAliases).sort((a, b) => a.LocalpartStr < b.LocalpartStr ? -1 : 1).map((a) => {
			return dom.tr(dom.td(dom.a(prewrap(a.LocalpartStr), attr.href("#domains/" + d + "/alias/" + encodeURIComponent(a.LocalpartStr)))), dom.td(a.PostPublic ? "Anyone" : "Members only"), dom.td(a.AllowMsgFrom ? "Yes" : "No"), dom.td(a.ListMembers ? "Yes" : "No"));
		})), dom.br(), dom.h2("Add alias (list)"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			const alias = {
				Addresses: aliasAddresses.value.split("\n").map((s) => s.trim()).filter((s) => !!s),
				PostPublic: true,
				ListMembers: false,
				AllowMsgFrom: false,
				// Ignored:
				LocalpartStr: "",
				Domain: dnsdomain
			};
			await check(aliasFieldset, client.AliasAdd(aliasLocalpart.value, d, alias));
			window.location.hash = "#domains/" + d + "/alias/" + encodeURIComponent(aliasLocalpart.value);
		}, "submit"), aliasFieldset = dom.fieldset(style({ display: "flex", alignItems: "flex-start", gap: "1em" }), dom.label(dom.div("Localpart", attr.title('The localpart is the part before the "@"-sign of an address.')), aliasLocalpart = dom.input(attr.required("")), "@", domainName(dnsdomain), " "), dom.label(dom.div("Addresses", attr.title("One members address per line, full address of form localpart@domain. At least one address required.")), aliasAddresses = dom.textarea(attr.required(""), attr.rows("1"), /* @__PURE__ */ __name(function focus() {
			aliasAddresses.setAttribute("rows", "5");
			aliasAddText.style.visibility = "visible";
		}, "focus"))), dom.div(dom.div("\xA0"), dom.submitbutton("Add alias", attr.title("Alias will be added and the config reloaded.")), aliasAddText = dom.p(style({ visibility: "hidden", fontStyle: "italic" }), "Messages sent to aliases are delivered to each member address of the alias, like a mailing list. For an additional address for an account, add it as regular address (see above).")))), dom.br(), RoutesEditor("domain-specific", transports, domainConfig.Routes || [], async (routes) => await client.DomainRoutesSave(d, routes)), dom.br(), dom.h2("Settings"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(descrFieldset, client.DomainDescriptionSave(d, descrText.value));
		}, "submit"), descrFieldset = dom.fieldset(style({ display: "flex", gap: "1em" }), dom.label(attr.title("Free-form description of domain."), dom.div("Description"), descrText = dom.input(attr.value(domainConfig.Description), style({ width: "30em" }))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save"))))), dom.form(style({ marginTop: "1ex" }), /* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(clientSettingsDomainFieldset, client.DomainClientSettingsDomainSave(d, clientSettingsDomain.value));
		}, "submit"), clientSettingsDomainFieldset = dom.fieldset(style({ display: "flex", gap: "1em" }), dom.label(attr.title("Hostname for client settings instead of the mail server hostname. E.g. mail.<domain>. For future migration to another mail operator without requiring all clients to update their settings, it is convenient to have client settings that reference a subdomain of the hosted domain instead of the hostname of the server where the mail is currently hosted. If empty, the hostname of the mail server is used for client configurations. Unicode name."), dom.div("Client settings domain"), clientSettingsDomain = dom.input(attr.value(domainConfig.ClientSettingsDomain), style({ width: "30em" }))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save"))))), (() => {
			let separatorViews = [];
			let separatorsBox;
			const addSeparatorView = /* @__PURE__ */ __name((s) => {
				const separator = dom.input(attr.required(""), attr.value(s), style({ width: "2em" }));
				const v = {
					separator,
					root: dom.div(separator, " ", dom.clickbutton("Remove", /* @__PURE__ */ __name(function click() {
						separatorViews.splice(separatorViews.indexOf(v), 1);
						v.root.remove();
						if (separatorViews.length === 0) {
							separatorsBox.append(dom.div("(None)"));
						}
					}, "click")))
				};
				if (separatorViews.length === 0) {
					dom._kids(separatorsBox);
				}
				separatorViews.push(v);
				separatorsBox.appendChild(v.root);
			}, "addSeparatorView");
			const elem = dom.form(style({ marginTop: "1ex" }), /* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				await check(localpartFieldset, client.DomainLocalpartConfigSave(d, separatorViews.map((v) => v.separator.value), localpartCaseSensitive.checked));
			}, "submit"), localpartFieldset = dom.fieldset(style({ display: "flex", gap: "1em" }), dom.label(attr.title("If set, upper/lower case is relevant for email delivery."), dom.div("Localpart case sensitive"), localpartCaseSensitive = dom.input(attr.type("checkbox"), domainConfig.LocalpartCaseSensitive ? attr.checked("") : [])), dom.div(dom.label(attr.title('If not empty, only the string before the separator is used for email delivery decisions. For example, if set to "+", you+anything@example.com will be delivered to you@example.com.'), "Localpart catchall separators"), " ", dom.clickbutton("Add", /* @__PURE__ */ __name(function click() {
				addSeparatorView("");
			}, "click")), separatorsBox = dom.div(style({ display: "flex", flexDirection: "column", gap: ".25em" }), dom.div("(None)"))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save")))));
			for (const sep of domainConfig.LocalpartCatchallSeparatorsEffective || []) {
				addSeparatorView(sep);
			}
			return elem;
		})(), dom.br(), dom.h2("DMARC reporting address"), dom.form(style({ marginTop: "1ex" }), /* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			if (!dmarcLocalpart.value) {
				dmarcDomain.value = "";
				dmarcAccount.value = "";
				dmarcMailbox.value = "";
			}
			const needChange = dmarcLocalpart.value === "" !== (domainConfig.DMARC === null) || domainConfig.DMARC && (domainConfig.DMARC.Localpart !== dmarcLocalpart.value || domainConfig.DMARC?.Domain !== dmarcDomain.value);
			await check(dmarcFieldset, client.DomainDMARCAddressSave(d, dmarcLocalpart.value, dmarcDomain.value, dmarcAccount.value, dmarcMailbox.value));
			if (needChange) {
				window.alert("Do not forget to update the DNS records with the updated reporting address (rua).");
				if (dmarcLocalpart.value) {
					domainConfig.DMARC = { Localpart: dmarcLocalpart.value, Domain: dmarcDomain.value, Account: dmarcAccount.value, Mailbox: dmarcMailbox.value, ParsedLocalpart: "", DNSDomain: { ASCII: "", Unicode: "" } };
				} else {
					domainConfig.DMARC = null;
				}
			}
		}, "submit"), dmarcFieldset = dom.fieldset(style({ display: "flex", gap: "1em" }), dom.label(attr.title("Address-part before the @ that accepts DMARC reports. Must be non-internationalized. Recommended value: dmarcreports."), dom.div("Localpart"), dmarcLocalpart = dom.input(attr.value(domainConfig.DMARC?.Localpart || ""))), dom.label(attr.title(`Alternative domain for reporting address, for incoming reports. Typically empty, causing this domain to be used. Can be used to receive reports for domains that aren't fully hosted on this server. Configure such a domain as a hosted domain without making all the DNS changes, and configure this field with a domain that is fully hosted on this server, so the localpart and the domain of this field form a reporting address. Then only update the DMARC DNS record for the hosted domain, ensuring the reporting address is specified in its "rua" field as shown in the DNS settings for this domain. Unicode name.`), dom.div("Alternative domain (optional)"), dmarcDomain = dom.input(attr.value(domainConfig.DMARC?.Domain || ""))), dom.label(attr.title("Account to deliver to."), dom.div("Account"), dmarcAccount = dom.select(dom.option(""), (accounts2 || []).map((s) => dom.option(attr.value(s), s + (accountsDisabled?.includes(s) ? " (disabled)" : ""), s === domainConfig.DMARC?.Account ? attr.selected("") : [])))), dom.label(attr.title("Mailbox to deliver to, e.g. DMARC."), dom.div("Mailbox"), dmarcMailbox = dom.input(attr.value(domainConfig.DMARC?.Mailbox || ""))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save"))))), dom.br(), dom.h2("TLS reporting address"), dom.form(style({ marginTop: "1ex" }), /* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			if (!tlsrptLocalpart.value) {
				tlsrptDomain.value = "";
				tlsrptAccount.value = "";
				tlsrptMailbox.value = "";
			}
			const needChange = tlsrptLocalpart.value === "" !== (domainConfig.TLSRPT === null) || domainConfig.TLSRPT && (domainConfig.TLSRPT.Localpart !== tlsrptLocalpart.value || domainConfig.TLSRPT?.Domain !== tlsrptDomain.value);
			await check(tlsrptFieldset, client.DomainTLSRPTAddressSave(d, tlsrptLocalpart.value, tlsrptDomain.value, tlsrptAccount.value, tlsrptMailbox.value));
			if (needChange) {
				window.alert("Do not forget to update the DNS records with the updated reporting address (rua).");
				if (tlsrptLocalpart.value) {
					domainConfig.TLSRPT = { Localpart: tlsrptLocalpart.value, Domain: tlsrptDomain.value, Account: tlsrptAccount.value, Mailbox: tlsrptMailbox.value, ParsedLocalpart: "", DNSDomain: { ASCII: "", Unicode: "" } };
				} else {
					domainConfig.TLSRPT = null;
				}
			}
		}, "submit"), tlsrptFieldset = dom.fieldset(style({ display: "flex", gap: "1em" }), dom.label(attr.title("Address-part before the @ that accepts TLSRPT reports. Must be non-internationalized. Recommended value: tlsrpt-reports."), dom.div("Localpart"), tlsrptLocalpart = dom.input(attr.value(domainConfig.TLSRPT?.Localpart || ""))), dom.label(attr.title(`Alternative domain for reporting address, for incoming reports. Typically empty, causing the domain wherein this config exists to be used. Can be used to receive reports for domains that aren't fully hosted on this server. Configure such a domain as a hosted domain without making all the DNS changes, and configure this field with a domain that is fully hosted on this server, so the localpart and the domain of this field form a reporting address. Then only update the TLSRPT DNS record for the not fully hosted domain, ensuring the reporting address is specified in its "rua" field as shown in the suggested DNS settings. Unicode name.`), dom.div("Alternative domain (optional)"), tlsrptDomain = dom.input(attr.value(domainConfig.TLSRPT?.Domain || ""))), dom.label(attr.title("Account to deliver to."), dom.div("Account"), tlsrptAccount = dom.select(dom.option(""), (accounts2 || []).map((s) => dom.option(attr.value(s), s + (accountsDisabled?.includes(s) ? " (disabled)" : ""), s === domainConfig.TLSRPT?.Account ? attr.selected("") : [])))), dom.label(attr.title("Mailbox to deliver to, e.g. TLSRPT."), dom.div("Mailbox"), tlsrptMailbox = dom.input(attr.value(domainConfig.TLSRPT?.Mailbox || ""))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save"))))), dom.br(), dom.h2("MTA-STS policy", attr.title(`MTA-STS is a mechanism that allows publishing a policy with requirements for WebPKI-verified SMTP STARTTLS connections for email delivered to a domain. Existence of a policy is announced in a DNS TXT record (often unprotected/unverified, MTA-STS's weak spot). If a policy exists, it is fetched with a WebPKI-verified HTTPS request. The policy can indicate that WebPKI-verified SMTP STARTTLS is required, and which MX hosts (optionally with a wildcard pattern) are allowd. MX hosts to deliver to are still taken from DNS (again, not necessarily protected/verified), but messages will only be delivered to domains matching the MX hosts from the published policy. Mail servers look up the MTA-STS policy when first delivering to a domain, then keep a cached copy, periodically checking the DNS record if a new policy is available, and fetching and caching it if so. To update a policy, first serve a new policy with an updated policy ID, then update the DNS record (not the other way around). To remove an enforced policy, publish an updated policy with mode "none" for a long enough period so all cached policies have been refreshed (taking DNS TTL and policy max age into account), then remove the policy from DNS, wait for TTL to expire, and stop serving the policy.`)), dom.form(style({ marginTop: "1ex" }), /* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			let mx = [];
			let mode = Mode.ModeNone;
			let maxAge = 0;
			if (!mtastsPolicyID.value) {
				mtastsMode.value = "";
				mtastsMaxAge.value = "";
				mtastsMX.value = "";
				if (domainConfig.MTASTS?.PolicyID && !window.confirm('Are you sure you want to remove the MTA-STS policy? Only remove policies after having served a policy with mode "none" for a long enough period, so all previously served and remotely cached policies have expired past the then-configured DNS TTL plus policy max-age period, and seen the policy with mode "none".')) {
					return;
				}
			} else {
				if (!mtastsMode.value) {
					throw new Error("mode is required for an active policy");
				}
				mode = mtastsMode.value;
				maxAge = parseDuration(mtastsMaxAge.value);
				mx = mtastsMX.value ? mtastsMX.value.split("\n") : [];
				if (domainConfig.MTASTS?.PolicyID === mtastsPolicyID.value && !window.confirm("Are you sure you want to save the policy without updating the policy ID? Remote servers may hold on to the old cached policies. Policy IDs should be changed when the policy is changed. Remember to first update the policy here, then publish the new policy ID in DNS.")) {
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
			} else if (mtastsPolicyID.value) {
				if (mtastsPolicyID.value !== domainConfig.MTASTS?.PolicyID) {
					window.alert("Don't forget to update the MTA-STS DNS record with the new policy ID, see suggested DNS records.");
				}
				domainConfig.MTASTS = {
					PolicyID: mtastsPolicyID.value,
					Mode: mode,
					MaxAge: maxAge,
					MX: mx
				};
			}
		}, "submit"), mtastsFieldset = dom.fieldset(style({ display: "flex", gap: "1em" }), dom.label(attr.title("Policies are versioned. The version must be specified in the DNS record. If you change a policy, first change it here to update the served policy, then update the DNS record with the updated policy ID."), dom.div("Policy ID ", dom.a("generate", attr.href(""), attr.title("Generate new policy ID based on current time."), /* @__PURE__ */ __name(function click(e) {
			e.preventDefault();
			mtastsPolicyID.value = (/* @__PURE__ */ new Date()).toISOString().replace(/-/g, "").replace(/:/g, "").split(".")[0];
		}, "click"))), mtastsPolicyID = dom.input(attr.value(domainConfig.MTASTS?.PolicyID || ""))), dom.label(attr.title('If set to "enforce", a remote SMTP server will not deliver email to us if it cannot make a WebPKI-verified SMTP STARTTLS connection. In mode "testing", deliveries can be done without verified TLS, but errors will be reported through TLS reporting. In mode "none", verified TLS is not required, used for phasing out an MTA-STS policy.'), dom.div("Mode"), mtastsMode = dom.select(dom.option(""), Object.values(Mode).map((s) => dom.option(s, domainConfig.MTASTS?.Mode === s ? attr.selected("") : [])))), dom.label(attr.title("How long a remote mail server is allowed to cache a policy. Typically 1 or several weeks. Units: s for seconds, m for minutes, h for hours, d for day, w for weeks."), dom.div("Max age"), mtastsMaxAge = dom.input(attr.value(domainConfig.MTASTS?.MaxAge ? formatDuration(domainConfig.MTASTS?.MaxAge || 0) : ""))), dom.label(attr.title("List of server names allowed for SMTP. If empty, the configured hostname is set. Host names can contain a wildcard (*) as a leading label (matching a single label, e.g. *.example matches host.example, not sub.host.example)."), dom.div("MX hosts/patterns (optional)"), mtastsMX = dom.textarea(new String((domainConfig.MTASTS?.MX || []).join("\n")), attr.rows("" + Math.max(2, 1 + (domainConfig.MTASTS?.MX || []).length)))), dom.div(dom.span("\xA0"), dom.div(dom.submitbutton("Save"))))), dom.br(), dom.h2("DKIM", attr.title("With DKIM signing, a domain is taking responsibility for (content of) emails it sends, letting receiving mail servers build up a (hopefully positive) reputation of the domain, which can help with mail delivery.")), (() => {
			let fieldset;
			let rows = [];
			return dom.form(/* @__PURE__ */ __name(async function submit(e) {
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
			}, "submit"), fieldset = dom.fieldset(dom.table(dom.thead(dom.tr(dom.th("Selector", attr.title("Used in the DKIM-Signature header, and used to form a DNS record under ._domainkey.<domain>.")), dom.th("Enabled", attr.title("Whether a DKIM-Signature is added to messages for this message. Multiple selectors can be enabled. Having backup keys published in DNS can be useful for quickly rotating a key.")), dom.th("Algorithm", attr.title("For signing messages. RSA is common at the time of writing, not all mail servers recognize ed25519 signature.")), dom.th("Hash", attr.title("Used in signing messages. Don't use sha1 unless you understand the consequences.")), dom.th("Canonicalization header/body", attr.colspan("2"), attr.title("Canonicalization processes the message headers and bodies before signing. Relaxed allows more whitespace changes, making it more likely for DKIM signatures to validate after transit through servers that make whitespace modifications. Simple is more strict.")), dom.th("Seal headers", attr.title("DKIM-signatures cover headers. If headers are not sealed, additional message headers can be added with the same key without invalidating the signature. This may confuse software about which headers are trustworthy. Sealing is the safer option.")), dom.th("Headers", attr.title("Headers to sign.")), dom.th("Signature lifetime", attr.title("How long a signature remains valid. Should be as long as a message may take to be delivered. The signature must be valid at the time a message is being delivered to the final destination.")), dom.th("Action"))), dom.tbody(Object.keys(domainConfig.DKIM.Selectors || []).length === 0 ? dom.tr(dom.td(attr.colspan("9"), "No DKIM keys/selectors.")) : [], rows = Object.entries(domainConfig.DKIM.Selectors || []).sort().map(([selName, sel]) => {
				let enabled;
				let hash;
				let canonHeader;
				let canonBody;
				let seal;
				let headersElem;
				let lifetime;
				const tr = dom.tr(dom.td(selName), dom.td(enabled = dom.input(attr.type("checkbox"), (domainConfig.DKIM.Sign || []).includes(selName) ? attr.checked("") : [])), dom.td(sel.Algorithm), dom.td(hash = dom.select(dom.option("sha256", sel.HashEffective === "sha256" ? attr.selected("") : []), dom.option("sha1", sel.HashEffective === "sha1" ? attr.selected("") : []))), dom.td(canonHeader = dom.select(dom.option("relaxed"), dom.option("simple", sel.Canonicalization.HeaderRelaxed ? [] : attr.selected("")))), dom.td(canonBody = dom.select(dom.option("relaxed"), dom.option("simple", sel.Canonicalization.BodyRelaxed ? [] : attr.selected("")))), dom.td(seal = dom.input(attr.type("checkbox"), sel.DontSealHeaders ? [] : attr.checked(""))), dom.td(headersElem = dom.span((sel.HeadersEffective || []).join("; ")), " ", dom.a(attr.href(""), "Edit", /* @__PURE__ */ __name(function click(e) {
					e.preventDefault();
					popupDKIMHeaders(sel, headersElem);
				}, "click"))), dom.td(lifetime = dom.input(attr.value(sel.Expiration))), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(async function click(e) {
					if (!window.confirm("Are you sure you want to remove this selector? It is removed immediately, after which the page is reloaded, losing unsaved changes.")) {
						return;
					}
					await check(e.target, client.DomainDKIMRemove(d, selName));
					window.alert("Don't forget to remove the corresponding DNS records (if it exists). If the DKIM key was active, it is best to wait for all messages in transit have been delivered (which can take days if messages are held up in remote queues), or those messages will not pass DKIM validiation.");
					window.location.reload();
				}, "click"))));
				return {
					root: tr,
					gather: /* @__PURE__ */ __name(() => {
						const nsel = {
							Hash: hash.value,
							HashEffective: hash.value,
							Canonicalization: {
								HeaderRelaxed: canonHeader.value === "relaxed",
								BodyRelaxed: canonBody.value === "relaxed"
							},
							Headers: sel.HeadersEffective,
							HeadersEffective: sel.HeadersEffective,
							DontSealHeaders: !seal.checked,
							Expiration: lifetime.value,
							PrivateKeyFile: "",
							Algorithm: ""
						};
						return [selName, enabled.checked, nsel];
					}, "gather")
				};
			})), dom.tfoot(dom.tr(dom.td(attr.colspan("9"), dom.submitbutton("Save"), " ", dom.clickbutton("Add key/selector", /* @__PURE__ */ __name(function click() {
				popupDKIMAdd();
			}, "click"))))))));
		})(), dom.br(), dom.h2("External checks"), dom.ul(dom.li(link("https://internet.nl/mail/" + dnsdomain.ASCII + "/", "Check configuration at internet.nl"))), dom.br(), dom.h2("Danger"), dom.div(domainConfig.Disabled ? [
			box(yellow, "Domain is currently disabled."),
			dom.clickbutton("Enable domain", /* @__PURE__ */ __name(async function click(e) {
				if (window.confirm("Are you sure you want to enable this domain? Incoming/outgoing messages involving this domain will be accepted, and ACME for new TLS certificates will be enabled.")) {
					check(e.target, client.DomainDisabledSave(d, false));
				}
			}, "click"))
		] : dom.clickbutton("Disable domain", /* @__PURE__ */ __name(async function click(e) {
			if (window.confirm("Are you sure you want to disable this domain? Incoming/outgoing messages involving this domain will be rejected with a temporary error code, and ACME for new TLS certificates will be disabled.")) {
				check(e.target, client.DomainDisabledSave(d, true));
			}
		}, "click"))), dom.br(), dom.clickbutton("Remove domain", /* @__PURE__ */ __name(async function click(e) {
			e.preventDefault();
			if (!window.confirm("Are you sure you want to remove this domain?")) {
				return;
			}
			await check(e.target, client.DomainRemove(d));
			window.location.hash = "#";
		}, "click")));
	}, "domain");
	var domainAlias = /* @__PURE__ */ __name(async (d, aliasLocalpart) => {
		const domain2 = await client.DomainConfig(d);
		const alias = (domain2.Aliases || {})[aliasLocalpart];
		if (!alias) {
			throw new Error("alias not found");
		}
		let aliasFieldset;
		let postPublic;
		let listMembers;
		let allowMsgFrom;
		let addFieldset;
		let addAddress;
		let delFieldset;
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("Domain " + domainString(domain2.Domain), "#domains/" + d), "Alias " + aliasLocalpart + "@" + domainName(domain2.Domain)), dom.h2("Alias"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			check(aliasFieldset, client.AliasUpdate(aliasLocalpart, d, postPublic.checked, listMembers.checked, allowMsgFrom.checked));
		}, "submit"), aliasFieldset = dom.fieldset(style({ display: "flex", flexDirection: "column", gap: ".5ex" }), dom.label(postPublic = dom.input(attr.type("checkbox"), alias.PostPublic ? attr.checked("") : []), " Public, anyone is allowed to send to the alias, instead of only members of the alias", attr.title("Based on address in message From header, which is assumed to be DMARC-like verified. If this setting is disabled and a non-member sends a message to the alias, the message is rejected.")), dom.label(listMembers = dom.input(attr.type("checkbox"), alias.ListMembers ? attr.checked("") : []), " Members can list other members"), dom.label(allowMsgFrom = dom.input(attr.type("checkbox"), alias.AllowMsgFrom ? attr.checked("") : []), " Allow messages to use the alias address in the message From header"), dom.div(style({ marginTop: "1ex" }), dom.submitbutton("Save")))), dom.br(), dom.h2("Members"), dom.p("Members receive messages sent to the alias. If a member address is in the message From header, the member will not receive the message."), dom.table(dom.thead(dom.tr(dom.th("Address"), dom.th("Account"), dom.th())), dom.tbody((alias.Addresses || []).map((address, index2) => {
			const pa = (alias.ParsedAddresses || [])[index2];
			return dom.tr(dom.td(prewrap(address)), dom.td(dom.a(pa.AccountName, attr.href("#accounts/l/" + pa.AccountName))), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(async function click(e) {
				await check(e.target, client.AliasAddressesRemove(aliasLocalpart, d, [address]));
				window.location.reload();
			}, "click"))));
		})), dom.tfoot(dom.tr(dom.td(attr.colspan("3"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(addFieldset, client.AliasAddressesAdd(aliasLocalpart, d, addAddress.value.split("\n").map((s) => s.trim()).filter((s) => s)));
			window.location.reload();
		}, "submit"), addFieldset = dom.fieldset(addAddress = dom.textarea(attr.required(""), attr.rows("1"), attr.placeholder("localpart@domain"), /* @__PURE__ */ __name(function focus() {
			addAddress.setAttribute("rows", "5");
		}, "focus")), " ", dom.submitbutton("Add", style({ verticalAlign: "top" })))))))), dom.br(), dom.h2("Danger"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			if (!confirm("Are you sure you want to remove this alias?")) {
				return;
			}
			await check(delFieldset, client.AliasRemove(aliasLocalpart, d));
			window.location.hash = "#domains/" + d;
		}, "submit"), delFieldset = dom.fieldset(dom.div(dom.submitbutton("Remove alias")))));
	}, "domainAlias");
	var domainDNSRecords = /* @__PURE__ */ __name(async (d) => {
		const [records, dnsdomain] = await Promise.all([
			client.DomainRecords(d),
			client.ParseDomain(d)
		]);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("Domain " + domainString(dnsdomain), "#domains/" + d), "DNS Records"), dom.h1("Required DNS records"), dom.pre(dom._class("literal"), (records || []).join("\n")), dom.br());
	}, "domainDNSRecords");
	var domainDNSCheck = /* @__PURE__ */ __name(async (d) => {
		const [checks, dnsdomain] = await Promise.all([
			client.CheckDomain(d),
			client.ParseDomain(d)
		]);
		const resultSection = /* @__PURE__ */ __name((title, r, details) => {
			let success = [];
			if ((r.Errors || []).length === 0 && (r.Warnings || []).length === 0) {
				success = box(green, "OK");
			}
			const errors = (r.Errors || []).length === 0 ? [] : box(red, dom.ul((r.Errors || []).map((s) => dom.li(s))));
			const warnings = (r.Warnings || []).length === 0 ? [] : box(yellow, dom.ul((r.Warnings || []).map((s) => dom.li(s))));
			let instructions = null;
			if (r.Instructions && r.Instructions.length > 0) {
				instructions = dom.div(style({ margin: ".5ex 0" }));
				const instrs = [
					(r.Instructions || []).map((s) => [
						dom.pre(dom._class("literal"), style({ display: "inline-block", maxWidth: "60em" }), s),
						dom.br()
					])
				];
				if ((r.Errors || []).length === 0) {
					dom._kids(instructions, dom.div(dom.a("Show instructions", attr.href("#"), /* @__PURE__ */ __name(function click(e) {
						e.preventDefault();
						dom._kids(instructions, instrs);
					}, "click")), dom.br()));
				} else {
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
				dom.br()
			];
		}, "resultSection");
		const detailsDNSSEC = [];
		const detailsIPRev = !checks.IPRev.IPNames || !Object.entries(checks.IPRev.IPNames).length ? [] : [
			dom.div("Hostname: " + domainString(checks.IPRev.Hostname)),
			dom.table(dom.thead(dom.tr(dom.th("IP"), dom.th("Addresses"))), dom.tbody(Object.entries(checks.IPRev.IPNames).sort().map((t) => dom.tr(dom.td(t[0]), dom.td((t[1] || []).join(", "))))))
		];
		const detailsMX = (checks.MX.Records || []).length === 0 ? [] : [
			dom.table(dom.thead(dom.tr(dom.th("Preference"), dom.th("Host"), dom.th("IPs"))), dom.tbody((checks.MX.Records || []).map((mx) => dom.tr(dom.td("" + mx.Pref), dom.td(mx.Host), dom.td((mx.IPs || []).join(", "))))))
		];
		const detailsTLS = [];
		const detailsDANE = [];
		const detailsSPF = [
			checks.SPF.DomainTXT ? [dom.div("Domain TXT record: " + checks.SPF.DomainTXT)] : [],
			checks.SPF.HostTXT ? [dom.div("Host TXT record: " + checks.SPF.HostTXT)] : []
		];
		const detailsDKIM = (checks.DKIM.Records || []).length === 0 ? [] : [
			dom.table(dom.thead(dom.tr(dom.th("Selector"), dom.th("TXT record"))), dom.tbody((checks.DKIM.Records || []).map((rec) => dom.tr(dom.td(rec.Selector), dom.td(rec.TXT)))))
		];
		const detailsDMARC = !checks.DMARC.Domain ? [] : [
			dom.div("Domain: " + checks.DMARC.Domain),
			!checks.DMARC.TXT ? [] : dom.div("TXT record: " + checks.DMARC.TXT)
		];
		const detailsTLSRPT = /* @__PURE__ */ __name((checksTLSRPT) => !checksTLSRPT.TXT ? [] : [
			dom.div("TXT record: " + checksTLSRPT.TXT)
		], "detailsTLSRPT");
		const detailsMTASTS = !checks.MTASTS.TXT && !checks.MTASTS.PolicyText ? [] : [
			!checks.MTASTS.TXT ? [] : dom.div("MTA-STS record: " + checks.MTASTS.TXT),
			!checks.MTASTS.PolicyText ? [] : dom.div("MTA-STS policy: ", dom.pre(dom._class("literal"), style({ maxWidth: "60em" }), checks.MTASTS.PolicyText))
		];
		const detailsSRVConf = !checks.SRVConf.SRVs || Object.keys(checks.SRVConf.SRVs).length === 0 ? [] : [
			dom.table(dom.thead(dom.tr(dom.th("Service"), dom.th("Priority"), dom.th("Weight"), dom.th("Port"), dom.th("Host"))), dom.tbody(Object.entries(checks.SRVConf.SRVs || []).map((t) => {
				const l = t[1];
				if (!l || !l.length) {
					return dom.tr(dom.td(t[0]), dom.td(attr.colspan("4"), "(none)"));
				}
				return l.map((r) => dom.tr([t[0], r.Priority, r.Weight, r.Port, r.Target].map((s) => dom.td("" + s))));
			})))
		];
		const detailsAutoconf = [
			...!checks.Autoconf.ClientSettingsDomainIPs ? [] : [dom.div("Client settings domain IPs: " + checks.Autoconf.ClientSettingsDomainIPs.join(", "))],
			...!checks.Autoconf.IPs ? [] : [dom.div("IPs: " + checks.Autoconf.IPs.join(", "))]
		];
		const detailsAutodiscover = !checks.Autodiscover.Records ? [] : [
			dom.table(dom.thead(dom.tr(dom.th("Host"), dom.th("Port"), dom.th("Priority"), dom.th("Weight"), dom.th("IPs"))), dom.tbody((checks.Autodiscover.Records || []).map((r) => dom.tr([r.Target, r.Port, r.Priority, r.Weight, (r.IPs || []).join(", ")].map((s) => dom.td("" + s))))))
		];
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("Domain " + domainString(dnsdomain), "#domains/" + d), "Check DNS"), dom.h1("DNS records and domain configuration check"), resultSection("DNSSEC", checks.DNSSEC, detailsDNSSEC), resultSection("IPRev", checks.IPRev, detailsIPRev), resultSection("MX", checks.MX, detailsMX), resultSection("TLS", checks.TLS, detailsTLS), resultSection("DANE", checks.DANE, detailsDANE), resultSection("SPF", checks.SPF, detailsSPF), resultSection("DKIM", checks.DKIM, detailsDKIM), resultSection("DMARC", checks.DMARC, detailsDMARC), resultSection("Host TLSRPT", checks.HostTLSRPT, detailsTLSRPT(checks.HostTLSRPT)), resultSection("Domain TLSRPT", checks.DomainTLSRPT, detailsTLSRPT(checks.DomainTLSRPT)), resultSection("MTA-STS", checks.MTASTS, detailsMTASTS), resultSection("SRV conf", checks.SRVConf, detailsSRVConf), resultSection("Autoconf", checks.Autoconf, detailsAutoconf), resultSection("Autodiscover", checks.Autodiscover, detailsAutodiscover), dom.br());
	}, "domainDNSCheck");
	var dmarcIndex = /* @__PURE__ */ __name(async () => {
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "DMARC"), dom.ul(dom.li(dom.a(attr.href("#dmarc/reports"), "Reports"), ", incoming DMARC aggregate reports."), dom.li(dom.a(attr.href("#dmarc/evaluations"), "Evaluations"), ", for outgoing DMARC aggregate reports.")));
	}, "dmarcIndex");
	var dmarcReports = /* @__PURE__ */ __name(async () => {
		const end = /* @__PURE__ */ new Date();
		const start = new Date((/* @__PURE__ */ new Date()).getTime() - 30 * 24 * 3600 * 1e3);
		const summaries = await client.DMARCSummaries(start, end, "");
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("DMARC", "#dmarc"), "Aggregate reporting summary"), dom.p('DMARC reports are periodically sent by other mail servers that received an email message with a "From" header with our domain. Domains can have a DMARC DNS record that asks other mail servers to send these aggregate reports for analysis.'), renderDMARCSummaries(summaries || []));
	}, "dmarcReports");
	var renderDMARCSummaries = /* @__PURE__ */ __name((summaries) => {
		return [
			dom.p("Below a summary of DMARC aggregate reporting results for the past 30 days."),
			summaries.length === 0 ? dom.div(box(yellow, "No domains with reports.")) : dom.table(dom.thead(dom.tr(dom.th("Domain", attr.title("Domain to which the DMARC policy applied. If example.com has a DMARC policy, and email is sent with a From-header with subdomain.example.com, and there is no DMARC record for that subdomain, but there is one for example.com, then the DMARC policy of example.com applies and reports are sent for that that domain.")), dom.th("Messages", attr.title("Total number of messages that had the DMARC policy applied and reported. Actual messages sent is likely higher because not all email servers send DMARC aggregate reports, or perform DMARC checks at all.")), dom.th('DMARC "quarantine"/"reject"', attr.title("Messages for which policy was to mark them as spam (quarantine) or reject them during SMTP delivery.")), dom.th('DKIM "fail"', attr.title("Messages with a failing DKIM check. This can happen when sending through a mailing list where that list keeps your address in the message From-header but also strips DKIM-Signature headers in the message. DMARC evaluation passes if either DKIM passes or SPF passes.")), dom.th('SPF "fail"', attr.title("Message with a failing SPF check. This can happen with email forwarding and with mailing list. Other mail servers have sent email with this domain in the message From-header. DMARC evaluation passes if at least SPF or DKIM passes.")), dom.th("Policy overrides", attr.title("Mail servers can override the DMARC policy. E.g. a mail server may be able to detect emails coming from mailing lists that do not pass DMARC and would have to be rejected, but for which an override has been configured.")))), dom.tbody(summaries.map((r) => dom.tr(dom.td(dom.a(attr.href("#domains/" + r.Domain + "/dmarc"), attr.title("See report details."), r.Domain)), dom.td(style({ textAlign: "right" }), "" + r.Total), dom.td(style({ textAlign: "right" }), r.DispositionQuarantine === 0 && r.DispositionReject === 0 ? "0/0" : box(red, "" + r.DispositionQuarantine + "/" + r.DispositionReject)), dom.td(style({ textAlign: "right" }), box(r.DKIMFail === 0 ? green : red, "" + r.DKIMFail)), dom.td(style({ textAlign: "right" }), box(r.SPFFail === 0 ? green : red, "" + r.SPFFail)), dom.td(!r.PolicyOverrides ? [] : Object.entries(r.PolicyOverrides).map((kv) => (kv[0] || "(no reason)") + ": " + kv[1]).join("; "))))))
		];
	}, "renderDMARCSummaries");
	var dmarcEvaluations = /* @__PURE__ */ __name(async () => {
		const [evalStats, suppressAddresses] = await Promise.all([
			client.DMARCEvaluationStats(),
			client.DMARCSuppressList()
		]);
		const isEmpty = /* @__PURE__ */ __name((o) => {
			for (const _ in o) {
				return false;
			}
			return true;
		}, "isEmpty");
		let fieldset;
		let reportingAddress;
		let until;
		let comment;
		const nextmonth = new Date((/* @__PURE__ */ new Date()).getTime() + 31 * 24 * 3600 * 1e3);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("DMARC", "#dmarc"), "Evaluations"), dom.p("Incoming messages are checked against the DMARC policy of the domain in the message From header. If the policy requests reporting on the resulting evaluations, they are stored in the database. Each interval of 1 to 24 hours, the evaluations may be sent to a reporting address specified in the domain's DMARC policy. Not all evaluations are a reason to send a report, but if a report is sent all evaluations are included."), dom.table(dom._class("hover"), dom.thead(dom.tr(dom.th("Domain", attr.title("Domain in the message From header. Keep in mind these can be forged, so this does not necessarily mean someone from this domain authentically tried delivering email.")), dom.th("Dispositions", attr.title("Unique dispositions occurring in report.")), dom.th("Evaluations", attr.title("Total number of message delivery attempts, including retries.")), dom.th("Send report", attr.title("Whether the current evaluations will cause a report to be sent.")))), dom.tbody(Object.entries(evalStats).sort((a, b) => a[0] < b[0] ? -1 : 1).map((t) => dom.tr(dom.td(dom.a(attr.href("#dmarc/evaluations/" + domainName(t[1].Domain)), domainString(t[1].Domain))), dom.td((t[1].Dispositions || []).join(" ")), dom.td(style({ textAlign: "right" }), "" + t[1].Count), dom.td(style({ textAlign: "right" }), t[1].SendReport ? "\u2713" : ""))), isEmpty(evalStats) ? dom.tr(dom.td(attr.colspan("3"), "No evaluations.")) : [])), dom.br(), dom.br(), dom.h2("Suppressed reporting addresses"), dom.p("In practice, sending a DMARC report to a reporting address can cause DSN to be sent back. Such addresses can be added to a suppression list for a period, to reduce noise in the postmaster mailbox."), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.stopPropagation();
			e.preventDefault();
			await check(fieldset, client.DMARCSuppressAdd(reportingAddress.value, new Date(until.value), comment.value));
			window.location.reload();
		}, "submit"), fieldset = dom.fieldset(dom.label(style({ display: "inline-block" }), "Reporting address", dom.br(), reportingAddress = dom.input(attr.required(""))), " ", dom.label(style({ display: "inline-block" }), "Until", dom.br(), until = dom.input(attr.type("date"), attr.required(""), attr.value(nextmonth.getFullYear() + "-" + (1 + nextmonth.getMonth()) + "-" + nextmonth.getDate()))), " ", dom.label(style({ display: "inline-block" }), dom.span("Comment (optional)"), dom.br(), comment = dom.input()), " ", dom.submitbutton("Add", attr.title("Outgoing reports to this reporting address will be suppressed until the end time.")))), dom.br(), dom.table(dom._class("hover"), dom.thead(dom.tr(dom.th("Reporting address"), dom.th("Until"), dom.th("Comment"), dom.th("Action"))), dom.tbody((suppressAddresses || []).length === 0 ? dom.tr(dom.td(attr.colspan("4"), "No suppressed reporting addresses.")) : [], (suppressAddresses || []).map((ba) => dom.tr(dom.td(prewrap(ba.ReportingAddress)), dom.td(ba.Until.toISOString()), dom.td(ba.Comment), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(async function click(e) {
			await check(e.target, client.DMARCSuppressRemove(ba.ID));
			window.location.reload();
		}, "click")), " ", dom.clickbutton("Extend for 1 month", /* @__PURE__ */ __name(async function click(e) {
			await check(e.target, client.DMARCSuppressExtend(ba.ID, new Date((/* @__PURE__ */ new Date()).getTime() + 31 * 24 * 3600 * 1e3)));
			window.location.reload();
		}, "click"))))))));
	}, "dmarcEvaluations");
	var dmarcEvaluationsDomain = /* @__PURE__ */ __name(async (domain2) => {
		const [d, evaluations] = await client.DMARCEvaluationsDomain(domain2);
		let lastInterval = "";
		let lastAddresses = "";
		const formatPolicy = /* @__PURE__ */ __name((e) => {
			const p = e.PolicyPublished;
			let s = "";
			const add = /* @__PURE__ */ __name((k, v) => {
				if (v) {
					s += k + "=" + v + "; ";
				}
			}, "add");
			add("p", p.Policy);
			add("sp", p.SubdomainPolicy);
			add("adkim", p.ADKIM);
			add("aspf", p.ASPF);
			add("pct", "" + p.Percentage);
			add("fo", "" + p.ReportingOptions);
			return s;
		}, "formatPolicy");
		let lastPolicy = "";
		const authStatus = /* @__PURE__ */ __name((v) => inlineBox(v ? "" : yellow, v ? "pass" : "fail"), "authStatus");
		const formatDKIMResults = /* @__PURE__ */ __name((results) => results.map((r) => dom.div("selector " + r.Selector + (r.Domain !== domain2 ? ", domain " + r.Domain : "") + ": ", inlineBox(r.Result === "pass" ? "" : yellow, r.Result))), "formatDKIMResults");
		const formatSPFResults = /* @__PURE__ */ __name((alignedpass, results) => results.map((r) => dom.div("" + r.Scope + (r.Domain !== domain2 ? ", domain " + r.Domain : "") + ": ", inlineBox(r.Result === "pass" && alignedpass ? "" : yellow, r.Result))), "formatSPFResults");
		const sourceIP = /* @__PURE__ */ __name((ip) => {
			const r = dom.span(ip, attr.title("Click to do a reverse lookup of the IP."), style({ cursor: "pointer" }), /* @__PURE__ */ __name(async function click(e) {
				e.preventDefault();
				try {
					const rev = await client.LookupIP(ip);
					r.innerText = ip + "\n" + (rev.Hostnames || []).join("\n");
				} catch (err) {
					r.innerText = ip + "\nerror: " + errmsg(err);
				}
			}, "click"));
			return r;
		}, "sourceIP");
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("DMARC", "#dmarc"), crumblink("Evaluations", "#dmarc/evaluations"), "Domain " + domainString(d)), dom.div(dom.clickbutton("Remove evaluations", /* @__PURE__ */ __name(async function click(e) {
			await check(e.target, client.DMARCRemoveEvaluations(domain2));
			window.location.reload();
		}, "click"))), dom.br(), dom.p("The evaluations below will be sent in a DMARC aggregate report to the addresses found in the published DMARC DNS record, which is fetched again before sending the report. The fields Interval hours, Addresses and Policy are only filled for the first row and whenever a new value in the published DMARC record is encountered."), dom.table(dom._class("hover"), dom.thead(dom.tr(dom.th("ID"), dom.th("Evaluated"), dom.th("Optional", attr.title("Some evaluations will not cause a DMARC aggregate report to be sent. But if a report is sent, optional records are included.")), dom.th("Interval hours", attr.title("DMARC policies published by a domain can specify how often they would like to receive reports. The default is 24 hours, but can be as often as each hour. To keep reports comparable between different mail servers that send reports, reports are sent at rounded up intervals of whole hours that can divide a 24 hour day, and are aligned with the start of a day at UTC.")), dom.th("Addresses", attr.title("Addresses that will receive the report. An address can have a maximum report size configured. If there is no address, no report will be sent.")), dom.th("Policy", attr.title("Summary of the policy as encountered in the DMARC DNS record of the domain, and used for evaluation.")), dom.th("IP", attr.title("IP address of delivery attempt that was evaluated, relevant for SPF.")), dom.th("Disposition", attr.title("Our decision to accept/reject this message. It may be different than requested by the published policy. For example, when overriding due to delivery from a mailing list or forwarded address.")), dom.th("Aligned DKIM/SPF", attr.title("Whether DKIM and SPF had an aligned pass, where strict/relaxed alignment means whether the domain of an SPF pass and DKIM pass matches the exact domain (strict) or optionally a subdomain (relaxed). A DMARC pass requires at least one pass.")), dom.th("Envelope to", attr.title("Domain used in SMTP RCPT TO during delivery.")), dom.th("Envelope from", attr.title("Domain used in SMTP MAIL FROM during delivery.")), dom.th("Message from", attr.title('Domain in "From" message header.')), dom.th("DKIM details", attr.title("Results of verifying DKIM-Signature headers in message. Only signatures with matching organizational domain are included, regardless of strict/relaxed DKIM alignment in DMARC policy.")), dom.th("SPF details", attr.title('Results of SPF check used in DMARC evaluation. "mfrom" indicates the "SMTP MAIL FROM" domain was used, "helo" indicates the SMTP EHLO domain was used.')))), dom.tbody((evaluations || []).map((e) => {
			const ival = e.IntervalHours + "h";
			const interval = ival === lastInterval ? "" : ival;
			lastInterval = ival;
			const a = (e.Addresses || []).join("\n");
			const addresses = a === lastAddresses ? "" : a;
			lastAddresses = a;
			const p = formatPolicy(e);
			const policy = p === lastPolicy ? "" : p;
			lastPolicy = p;
			return dom.tr(dom.td("" + e.ID), dom.td(new Date(e.Evaluated).toUTCString()), dom.td(e.Optional ? "Yes" : ""), dom.td(interval), dom.td(addresses), dom.td(policy), dom.td(sourceIP(e.SourceIP)), dom.td(inlineBox(e.Disposition === "none" ? "" : red, e.Disposition), (e.OverrideReasons || []).length > 0 ? " (" + (e.OverrideReasons || []).map((r) => r.Type).join(", ") + ")" : ""), dom.td(authStatus(e.AlignedDKIMPass), "/", authStatus(e.AlignedSPFPass)), dom.td(e.EnvelopeTo), dom.td(e.EnvelopeFrom), dom.td(e.HeaderFrom), dom.td(formatDKIMResults(e.DKIMResults || [])), dom.td(formatSPFResults(e.AlignedSPFPass, e.SPFResults || [])));
		}), (evaluations || []).length === 0 ? dom.tr(dom.td(attr.colspan("14"), "No evaluations.")) : [])));
	}, "dmarcEvaluationsDomain");
	var utcDate = /* @__PURE__ */ __name((dt) => new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth(), dt.getUTCDate(), dt.getUTCHours(), dt.getUTCMinutes(), dt.getUTCSeconds())), "utcDate");
	var utcDateStr = /* @__PURE__ */ __name((dt) => [dt.getUTCFullYear(), 1 + dt.getUTCMonth(), dt.getUTCDate()].join("-"), "utcDateStr");
	var isDayChange = /* @__PURE__ */ __name((dt) => utcDateStr(new Date(dt.getTime() - 2 * 60 * 1e3)) !== utcDateStr(new Date(dt.getTime() + 2 * 60 * 1e3)), "isDayChange");
	var period = /* @__PURE__ */ __name((start, end) => {
		const beginUTC = utcDate(start);
		const endUTC = utcDate(end);
		const beginDayChange = isDayChange(beginUTC);
		const endDayChange = isDayChange(endUTC);
		let beginstr = utcDateStr(beginUTC);
		let endstr = utcDateStr(endUTC);
		const title = attr.title("" + beginUTC.toISOString() + " - " + endUTC.toISOString());
		if (beginDayChange && endDayChange && Math.abs(beginUTC.getTime() - endUTC.getTime()) < 24 * (2 * 60 + 3600) * 1e3) {
			return dom.span(beginstr, title);
		}
		const pad = /* @__PURE__ */ __name((v) => v < 10 ? "0" + v : "" + v, "pad");
		if (!beginDayChange) {
			beginstr += " " + pad(beginUTC.getUTCHours()) + ":" + pad(beginUTC.getUTCMinutes());
		}
		if (!endDayChange) {
			endstr += " " + pad(endUTC.getUTCHours()) + ":" + pad(endUTC.getUTCMinutes());
		}
		return dom.span(beginstr + " - " + endstr, title);
	}, "period");
	var domainDMARC = /* @__PURE__ */ __name(async (d) => {
		const end = /* @__PURE__ */ new Date();
		const start = new Date((/* @__PURE__ */ new Date()).getTime() - 30 * 24 * 3600 * 1e3);
		const [reports, dnsdomain] = await Promise.all([
			client.DMARCReports(start, end, d),
			client.Domain(d)
		]);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("Domain " + domainString(dnsdomain), "#domains/" + d), "DMARC aggregate reports"), dom.p('DMARC reports are periodically sent by other mail servers that received an email message with a "From" header with our domain. Domains can have a DMARC DNS record that asks other mail servers to send these aggregate reports for analysis.'), dom.p("Below the DMARC aggregate reports for the past 30 days."), (reports || []).length === 0 ? dom.div("No DMARC reports for domain.") : dom.table(dom._class("hover"), dom.thead(dom.tr(dom.th("ID"), dom.th("Organisation", attr.title("Organization that sent the DMARC report.")), dom.th("Period (UTC)", attr.title("Period this reporting period is about. Mail servers are recommended to stick to whole UTC days.")), dom.th("Policy", attr.title("The DMARC policy that the remote mail server had fetched and applied to the message. A policy that changed during the reporting period may result in unexpected policy evaluations.")), dom.th("Source IP", attr.title("Remote IP address of session at remote mail server.")), dom.th("Messages", attr.title("Total messages that the results apply to.")), dom.th("Result", attr.title("DMARC evaluation result.")), dom.th("ADKIM", attr.title("DKIM alignment. For a pass, one of the DKIM signatures that pass must be strict/relaxed-aligned with the domain, as specified by the policy.")), dom.th("ASPF", attr.title("SPF alignment. For a pass, the SPF policy must pass and be strict/relaxed-aligned with the domain, as specified by the policy.")), dom.th("SMTP to", attr.title("Domain of destination address, as specified during the SMTP session.")), dom.th("SMTP from", attr.title("Domain of originating address, as specified during the SMTP session.")), dom.th("Header from", attr.title("Domain of address in From-header of message.")), dom.th("Auth Results", attr.title("Details of DKIM and/or SPF authentication results. DMARC requires at least one aligned DKIM or SPF pass.")))), dom.tbody((reports || []).map((r) => {
			const m = r.ReportMetadata;
			let policy = [];
			if (r.PolicyPublished.Domain !== d) {
				policy.push(r.PolicyPublished.Domain);
			}
			const alignments = { "": "", "r": "relaxed", "s": "strict" };
			if (r.PolicyPublished.ADKIM !== "") {
				policy.push("dkim " + (alignments[r.PolicyPublished.ADKIM] || "invalid dkim alignment: " + (r.PolicyPublished.ADKIM || "(missing)")));
			}
			if (r.PolicyPublished.ASPF !== "") {
				policy.push("spf " + (alignments[r.PolicyPublished.ASPF] || "invalid spf alignment: " + (r.PolicyPublished.ASPF || "(missing)")));
			}
			if (r.PolicyPublished.Policy !== "") {
				policy.push("policy " + r.PolicyPublished.Policy);
			}
			if (r.PolicyPublished.SubdomainPolicy !== "" && r.PolicyPublished.SubdomainPolicy !== r.PolicyPublished.Policy) {
				policy.push("subdomain " + r.PolicyPublished.SubdomainPolicy);
			}
			if (r.PolicyPublished.Percentage !== 100) {
				policy.push("" + r.PolicyPublished.Percentage + "%");
			}
			const sourceIP = /* @__PURE__ */ __name((ip) => {
				const r2 = dom.span(ip, attr.title("Click to do a reverse lookup of the IP."), style({ cursor: "pointer" }), /* @__PURE__ */ __name(async function click(e) {
					e.preventDefault();
					try {
						const rev = await client.LookupIP(ip);
						r2.innerText = ip + "\n" + (rev.Hostnames || []).join("\n");
					} catch (err) {
						r2.innerText = ip + "\nerror: " + errmsg(err);
					}
				}, "click"));
				return r2;
			}, "sourceIP");
			let authResults = 0;
			for (const record of r.Records || []) {
				authResults += (record.AuthResults.DKIM || []).length;
				authResults += (record.AuthResults.SPF || []).length;
			}
			const reportRowspan = attr.rowspan("" + authResults);
			return (r.Records || []).map((record, recordIndex) => {
				const row = record.Row;
				const pol = row.PolicyEvaluated;
				const ids = record.Identifiers;
				const dkims = record.AuthResults.DKIM || [];
				const spfs = record.AuthResults.SPF || [];
				const recordRowspan = attr.rowspan("" + (dkims.length + spfs.length));
				const valignTop = style({ verticalAlign: "top" });
				const dmarcStatuses = {
					"": "(missing)",
					none: "DMARC checks or were not applied. This does not mean these messages are definitely not spam though, and they may have been rejected based on other checks, such as reputation or content-based filters.",
					quarantine: "DMARC policy is to mark message as spam.",
					reject: "DMARC policy is to reject the message during SMTP delivery."
				};
				const rows = [];
				const addRow = /* @__PURE__ */ __name((...last) => {
					const tr = dom.tr(recordIndex > 0 || rows.length > 0 ? [] : [
						dom.td(reportRowspan, valignTop, dom.a("" + r.ID, attr.href("#domains/" + d + "/dmarc/" + r.ID), attr.title("View raw report."))),
						dom.td(reportRowspan, valignTop, m.OrgName, attr.title("Email: " + m.Email + ", ReportID: " + m.ReportID)),
						dom.td(reportRowspan, valignTop, period(new Date(m.DateRange.Begin * 1e3), new Date(m.DateRange.End * 1e3)), m.Errors && m.Errors.length ? dom.span("errors", attr.title(m.Errors.join("; "))) : []),
						dom.td(reportRowspan, valignTop, policy.join(", "))
					], rows.length > 0 ? [] : [
						dom.td(recordRowspan, valignTop, sourceIP(row.SourceIP)),
						dom.td(recordRowspan, valignTop, "" + row.Count),
						dom.td(recordRowspan, valignTop, dom.span(pol.Disposition === "none" ? "none" : box(red, pol.Disposition), attr.title(pol.Disposition + ": " + (dmarcStatuses[pol.Disposition] || "(invalid disposition)"))), (pol.Reasons || []).map((reason) => [dom.br(), dom.span(reason.Type + (reason.Comment ? " (" + reason.Comment + ")" : ""), attr.title("Policy was overridden by remote mail server for this reasons."))])),
						dom.td(recordRowspan, valignTop, pol.DKIM === "pass" ? "pass" : box(yellow, dom.span(pol.DKIM, attr.title('No or no valid DKIM-signature is present that is "aligned" with the domain name.')))),
						dom.td(recordRowspan, valignTop, pol.SPF === "pass" ? "pass" : box(yellow, dom.span(pol.SPF, attr.title('No SPF policy was found, or IP is not allowed by policy, or domain name is not "aligned" with the domain name.')))),
						dom.td(recordRowspan, valignTop, ids.EnvelopeTo),
						dom.td(recordRowspan, valignTop, ids.EnvelopeFrom),
						dom.td(recordRowspan, valignTop, ids.HeaderFrom)
					], dom.td(last));
					rows.push(tr);
				}, "addRow");
				for (const dkim of dkims) {
					const statuses = {
						"": "(missing)",
						none: "Message was not signed",
						pass: "Message was signed and signature was verified.",
						fail: "Message was signed, but signature was invalid.",
						policy: "Message was signed, but signature is not accepted by policy.",
						neutral: "Message was signed, but the signature contains an error or could not be processed. This status is also used for errors not covered by other statuses.",
						temperror: "Message could not be verified. E.g. because of DNS resolve error. A later attempt may succeed. A missing DNS record is treated as temporary error, a new key may not have propagated through DNS shortly after it was taken into use.",
						permerror: "Message cannot be verified. E.g. when a required header field is absent or for invalid (combination of) parameters. We typically set this if a DNS record does not allow the signature, e.g. due to algorithm mismatch or expiry."
					};
					addRow("dkim: ", dom.span(dkim.Result === "none" || dkim.Result === "pass" ? dkim.Result : box(yellow, dkim.Result), attr.title((dkim.HumanResult ? "additional information: " + dkim.HumanResult + ";\n" : "") + dkim.Result + ": " + (statuses[dkim.Result] || "invalid status"))), !dkim.Selector ? [] : [
						", ",
						dom.span(dkim.Selector, attr.title('Selector, the DKIM record is at "<selector>._domainkey.<domain>".' + (dkim.Domain === d ? "" : ";\ndomain: " + dkim.Domain)))
					]);
				}
				for (const spf of spfs) {
					const statuses = {
						"": "(missing)",
						none: "No SPF policy found.",
						neutral: 'Policy states nothing about IP, typically due to "?" qualifier in SPF record.',
						pass: "IP is authorized.",
						fail: 'IP is explicitly not authorized, due to "-" qualifier in SPF record.',
						softfail: 'Weak statement that IP is probably not authorized, "~" qualifier in SPF record.',
						temperror: "Trying again later may succeed, e.g. for temporary DNS lookup error.",
						permerror: "Error requiring some intervention to correct. E.g. invalid DNS record."
					};
					addRow("spf: ", dom.span(spf.Result === "none" || spf.Result === "neutral" || spf.Result === "pass" ? spf.Result : box(yellow, spf.Result), attr.title(spf.Result + ": " + (statuses[spf.Result] || "invalid status"))), ", ", dom.span(spf.Scope, attr.title('scopes:\nhelo: "SMTP HELO"\nmfrom: SMTP "MAIL FROM"')), " ", dom.span(spf.Domain));
				}
				return rows;
			});
		}))));
	}, "domainDMARC");
	var domainDMARCReport = /* @__PURE__ */ __name(async (d, reportID) => {
		const [report, dnsdomain] = await Promise.all([
			client.DMARCReportID(d, reportID),
			client.Domain(d)
		]);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("Domain " + domainString(dnsdomain), "#domains/" + d), crumblink("DMARC aggregate reports", "#domains/" + d + "/dmarc"), "Report " + reportID), dom.p("Below is the raw report as received from the remote mail server."), dom.div(dom._class("literal"), JSON.stringify(report, null, "	")));
	}, "domainDMARCReport");
	var tlsrptIndex = /* @__PURE__ */ __name(async () => {
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "TLSRPT"), dom.ul(dom.li(dom.a(attr.href("#tlsrpt/reports"), "Reports"), ", incoming TLS reports."), dom.li(dom.a(attr.href("#tlsrpt/results"), "Results"), ", for outgoing TLS reports.")));
	}, "tlsrptIndex");
	var tlsrptResults = /* @__PURE__ */ __name(async () => {
		const [results, suppressAddresses] = await Promise.all([
			client.TLSRPTResults(),
			client.TLSRPTSuppressList()
		]);
		let fieldset;
		let reportingAddress;
		let until;
		let comment;
		const nextmonth = new Date((/* @__PURE__ */ new Date()).getTime() + 31 * 24 * 3600 * 1e3);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("TLSRPT", "#tlsrpt"), "Results"), dom.p("Messages are delivered with SMTP with TLS using STARTTLS if supported and/or required by the recipient domain's mail server. TLS connections may fail for various reasons, such as mismatching certificate host name, expired certificates or TLS protocol version/cipher suite incompatibilities. Statistics about successful connections and failed connections are tracked. Results can be tracked for recipient domains (for MTA-STS policies), and per MX host (for DANE). A domain/host can publish a TLSRPT DNS record with addresses that should receive TLS reports. Reports are sent every 24 hours. Not all results are enough reason to send a report, but if a report is sent all results are included. By default, reports are only sent if a report contains a connection failure. Sending reports about all-successful connections can be configured. Reports sent to recipient domains include the results for its MX hosts, and reports for an MX host reference the recipient domains."), dom.table(dom._class("hover"), dom.thead(dom.tr(dom.th("Day (UTC)", attr.title("Day covering these results, a whole day from 00:00 UTC to 24:00 UTC.")), dom.th("Recipient domain", attr.title("Domain of addressee. For delivery to a recipient, the recipient and policy domains will match for reporting on MTA-STS policies, but can also result in reports for hosts from the MX record of the recipient to report on DANE policies.")), dom.th("Policy domain", attr.title("Domain for TLSRPT policy, specifying URIs to which reports should be sent.")), dom.th("Host", attr.title("Whether policy domain is an (MX) host (for DANE), or a recipient domain (for MTA-STS).")), dom.th("Policies", attr.title("Policies found.")), dom.th("Success", attr.title("Total number of successful connections.")), dom.th("Failure", attr.title("Total number of failed connection attempts.")), dom.th("Failure details", attr.title("Total number of details about failures.")), dom.th("Send report", attr.title("Whether the current results may cause a report to be sent. To prevent report loops, reports are not sent for TLS connections used to deliver TLS or DMARC reports. Whether a report is eventually sent depends on more factors, such as whether the policy domain has a TLSRPT policy with reporting addresses, and whether TLS connection failures were registered (depending on configuration).")))), dom.tbody((results || []).sort((a, b) => {
			if (a.DayUTC !== b.DayUTC) {
				return a.DayUTC < b.DayUTC ? -1 : 1;
			}
			if (a.RecipientDomain !== b.RecipientDomain) {
				return a.RecipientDomain < b.RecipientDomain ? -1 : 1;
			}
			return a.PolicyDomain < b.PolicyDomain ? -1 : 1;
		}).map((r) => {
			let success = 0;
			let failed = 0;
			let failureDetails = 0;
			(r.Results || []).forEach((result) => {
				success += result.Summary.TotalSuccessfulSessionCount;
				failed += result.Summary.TotalFailureSessionCount;
				failureDetails += (result.FailureDetails || []).length;
			});
			const policyTypes = [];
			for (const result of r.Results || []) {
				const pt = result.Policy.Type;
				if (!policyTypes.includes(pt)) {
					policyTypes.push(pt);
				}
			}
			return dom.tr(dom.td(r.DayUTC), dom.td(r.RecipientDomain), dom.td(dom.a(attr.href("#tlsrpt/results/" + (r.RecipientDomain === r.PolicyDomain ? "rcptdom/" : "host/") + r.PolicyDomain), r.PolicyDomain)), dom.td(r.IsHost ? "\u2713" : ""), dom.td(policyTypes.join(", ")), dom.td(style({ textAlign: "right" }), "" + success), dom.td(style({ textAlign: "right" }), "" + failed), dom.td(style({ textAlign: "right" }), "" + failureDetails), dom.td(style({ textAlign: "right" }), r.SendReport ? "\u2713" : ""));
		}), (results || []).length === 0 ? dom.tr(dom.td(attr.colspan("9"), "No results.")) : [])), dom.br(), dom.br(), dom.h2("Suppressed reporting addresses"), dom.p("In practice, sending a TLS report to a reporting address can cause DSN to be sent back. Such addresses can be added to a suppress list for a period, to reduce noise in the postmaster mailbox."), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.stopPropagation();
			e.preventDefault();
			await check(fieldset, client.TLSRPTSuppressAdd(reportingAddress.value, new Date(until.value), comment.value));
			window.location.reload();
		}, "submit"), fieldset = dom.fieldset(dom.label(style({ display: "inline-block" }), "Reporting address", dom.br(), reportingAddress = dom.input(attr.required(""))), " ", dom.label(style({ display: "inline-block" }), "Until", dom.br(), until = dom.input(attr.type("date"), attr.required(""), attr.value(nextmonth.getFullYear() + "-" + (1 + nextmonth.getMonth()) + "-" + nextmonth.getDate()))), " ", dom.label(style({ display: "inline-block" }), dom.span("Comment (optional)"), dom.br(), comment = dom.input()), " ", dom.submitbutton("Add", attr.title("Outgoing reports to this reporting address will be suppressed until the end time.")))), dom.br(), dom.table(dom._class("hover"), dom.thead(dom.tr(dom.th("Reporting address"), dom.th("Until"), dom.th("Comment"), dom.th("Action"))), dom.tbody((suppressAddresses || []).length === 0 ? dom.tr(dom.td(attr.colspan("4"), "No suppressed reporting addresses.")) : [], (suppressAddresses || []).map((ba) => dom.tr(dom.td(prewrap(ba.ReportingAddress)), dom.td(ba.Until.toISOString()), dom.td(ba.Comment), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(async function click(e) {
			await check(e.target, client.TLSRPTSuppressRemove(ba.ID));
			window.location.reload();
		}, "click")), " ", dom.clickbutton("Extend for 1 month", /* @__PURE__ */ __name(async function click(e) {
			await check(e.target, client.TLSRPTSuppressExtend(ba.ID, new Date((/* @__PURE__ */ new Date()).getTime() + 31 * 24 * 3600 * 1e3)));
			window.location.reload();
		}, "click"))))))));
	}, "tlsrptResults");
	var tlsrptResultsPolicyDomain = /* @__PURE__ */ __name(async (isrcptdom, domain2) => {
		const [d, tlsresults] = await client.TLSRPTResultsDomain(isrcptdom, domain2);
		const recordPromise = client.LookupTLSRPTRecord(domain2);
		let recordBox;
		const root = dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("TLSRPT", "#tlsrpt"), crumblink("Results", "#tlsrpt/results"), (isrcptdom ? "Recipient domain " : "Host ") + domainString(d)), dom.div(dom.clickbutton("Remove results", /* @__PURE__ */ __name(async function click(e) {
			e.preventDefault();
			await check(e.target, client.TLSRPTRemoveResults(isrcptdom, domain2, ""));
			window.location.reload();
		}, "click"))), dom.br(), dom.div("Fetching TLSRPT DNS record..."), recordBox = dom.div(), dom.br(), dom.p("Below are the results per day and " + (isrcptdom ? "policy" : "recipient") + " domain that may be sent in a report."), (tlsresults || []).map((tlsresult) => [
			dom.h2(tlsresult.DayUTC, " - ", dom.span(attr.title("Recipient domain, as used in SMTP MAIL TO, usually based on message To/Cc/Bcc."), isrcptdom ? tlsresult.PolicyDomain : tlsresult.RecipientDomain)),
			dom.p("Send report (if TLSRPT policy exists and has address): " + (tlsresult.SendReport ? "Yes" : "No"), dom.br(), "Report about (MX) host (instead of recipient domain): " + (tlsresult.IsHost ? "Yes" : "No")),
			dom.div(dom._class("literal"), JSON.stringify(tlsresult.Results, null, "	"))
		]));
		(async () => {
			let txt = "";
			let error;
			try {
				let [_, xtxt, xerror] = await recordPromise;
				txt = xtxt;
				error = xerror;
			} catch (err) {
				error = "error: " + errmsg(err);
			}
			const l = [];
			if (txt) {
				l.push(dom.div(dom._class("literal"), txt));
			}
			if (error) {
				l.push(box(red, error));
			}
			dom._kids(recordBox, l);
		})();
		return root;
	}, "tlsrptResultsPolicyDomain");
	var tlsrptReports = /* @__PURE__ */ __name(async () => {
		const end = /* @__PURE__ */ new Date();
		const start = new Date((/* @__PURE__ */ new Date()).getTime() - 30 * 24 * 3600 * 1e3);
		const summaries = await client.TLSRPTSummaries(start, end, "");
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("TLSRPT", "#tlsrpt"), "Reports"), dom.p("TLSRPT (TLS reporting) is a mechanism to request feedback from other mail servers about TLS connections to your mail server. If is typically used along with MTA-STS and/or DANE to enforce that SMTP connections are protected with TLS. Mail servers implementing TLSRPT will typically send a daily report with both successful and failed connection counts, including details about failures."), renderTLSRPTSummaries(summaries || []));
	}, "tlsrptReports");
	var renderTLSRPTSummaries = /* @__PURE__ */ __name((summaries) => {
		return [
			dom.p("Below a summary of TLS reports for the past 30 days."),
			summaries.length === 0 ? dom.div(box(yellow, "No domains with TLS reports.")) : dom.table(dom._class("hover"), dom.thead(dom.tr(dom.th("Policy domain", attr.title("Policy domain the report is about. The recipient domain for MTA-STS, the TLSA base domain for DANE.")), dom.th("Successes", attr.title("Number of successful SMTP STARTTLS sessions.")), dom.th("Failures", attr.title("Number of failed SMTP STARTTLS sessions.")), dom.th("Failure details", attr.title("Details about connection failures.")))), dom.tbody(summaries.map((r) => dom.tr(dom.td(dom.a(attr.href("#tlsrpt/reports/" + domainName(r.PolicyDomain)), attr.title("See report details."), domainName(r.PolicyDomain))), dom.td(style({ textAlign: "right" }), "" + r.Success), dom.td(style({ textAlign: "right" }), "" + r.Failure), dom.td(!r.ResultTypeCounts ? [] : Object.entries(r.ResultTypeCounts).map((kv) => kv[0] + ": " + kv[1]).join("; "))))))
		];
	}, "renderTLSRPTSummaries");
	var domainTLSRPT = /* @__PURE__ */ __name(async (d) => {
		const end = /* @__PURE__ */ new Date();
		const start = new Date((/* @__PURE__ */ new Date()).getTime() - 30 * 24 * 3600 * 1e3);
		const [records, dnsdomain] = await Promise.all([
			client.TLSReports(start, end, d),
			client.ParseDomain(d)
		]);
		const policyType = /* @__PURE__ */ __name((policy) => {
			let s = policy.Type;
			if (s === "sts") {
				const mode = (policy.String || []).find((s2) => s2.startsWith("mode:"));
				if (mode) {
					s += ": " + mode.replace("mode:", "").trim();
				}
			}
			return s;
		}, "policyType");
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("TLSRPT", "#tlsrpt"), crumblink("Reports", "#tlsrpt/reports"), "Domain " + domainString(dnsdomain)), dom.p("TLSRPT (TLS reporting) is a mechanism to request feedback from other mail servers about TLS connections to your mail server. If is typically used along with MTA-STS and/or DANE to enforce that SMTP connections are protected with TLS. Mail servers implementing TLSRPT will typically send a daily report with both successful and failed connection counts, including details about failures."), dom.p("Below the TLS reports for the past 30 days."), (records || []).length === 0 ? dom.div("No TLS reports for domain.") : dom.table(dom._class("hover"), dom.thead(dom.tr(dom.th("Report", attr.colspan("3")), dom.th("Policy", attr.colspan("3")), dom.th("Failure Details", attr.colspan("8"))), dom.tr(dom.th("ID"), dom.th("From", attr.title("SMTP mail from from which we received the report.")), dom.th("Period (UTC)", attr.title("Period this reporting period is about. Mail servers are recommended to stick to whole UTC days.")), dom.th("Policy", attr.title("The policy applied, typically STSv1.")), dom.th("Successes", attr.title("Total number of successful TLS connections for policy.")), dom.th("Failures", attr.title("Total number of failed TLS connections for policy.")), dom.th("Result Type", attr.title("Type of failure.")), dom.th("Sending MTA", attr.title("IP of sending MTA.")), dom.th("Receiving MX Host"), dom.th("Receiving MX HELO"), dom.th("Receiving IP"), dom.th("Count", attr.title("Number of TLS connections that failed with these details.")), dom.th("More", attr.title("Optional additional information about the failure.")), dom.th("Code", attr.title("Optional API error code relating to the failure.")))), dom.tbody((records || []).map((record) => {
			const r = record.Report;
			let nrows = 0;
			(r.Policies || []).forEach((pr) => nrows += (pr.FailureDetails || []).length || 1);
			const reportRowSpan = attr.rowspan("" + nrows);
			const valignTop = style({ verticalAlign: "top" });
			const alignRight = style({ textAlign: "right" });
			return (r.Policies || []).map((result, index2) => {
				const rows = [];
				const details = result.FailureDetails || [];
				const resultRowSpan = attr.rowspan("" + (details.length || 1));
				const addRow = /* @__PURE__ */ __name((d2, di2) => {
					const row = dom.tr(index2 > 0 || rows.length > 0 ? [] : [
						dom.td(reportRowSpan, valignTop, dom.a("" + record.ID, attr.href("#tlsrpt/reports/" + record.Domain + "/" + record.ID))),
						dom.td(reportRowSpan, valignTop, r.OrganizationName || r.ContactInfo || record.MailFrom || "", attr.title("Organization: " + r.OrganizationName + "; \nContact info: " + r.ContactInfo + "; \nReport ID: " + r.ReportID + "; \nMail from: " + record.MailFrom)),
						dom.td(reportRowSpan, valignTop, period(r.DateRange.Start, r.DateRange.End))
					], di2 > 0 ? [] : [
						dom.td(resultRowSpan, valignTop, policyType(result.Policy), attr.title((result.Policy.String || []).join("\n"))),
						dom.td(resultRowSpan, valignTop, alignRight, "" + result.Summary.TotalSuccessfulSessionCount),
						dom.td(resultRowSpan, valignTop, alignRight, "" + result.Summary.TotalFailureSessionCount)
					], !d2 ? dom.td(attr.colspan("8")) : [
						dom.td(d2.ResultType),
						dom.td(d2.SendingMTAIP),
						dom.td(d2.ReceivingMXHostname),
						dom.td(d2.ReceivingMXHelo),
						dom.td(d2.ReceivingIP),
						dom.td(alignRight, "" + d2.FailedSessionCount),
						dom.td(d2.AdditionalInformation),
						dom.td(d2.FailureReasonCode)
					]);
					rows.push(row);
				}, "addRow");
				let di = 0;
				for (const d2 of details) {
					addRow(d2, di);
					di++;
				}
				if (details.length === 0) {
					addRow(void 0, 0);
				}
				return rows;
			});
		}))));
	}, "domainTLSRPT");
	var domainTLSRPTID = /* @__PURE__ */ __name(async (d, reportID) => {
		const [report, dnsdomain] = await Promise.all([
			client.TLSReportID(d, reportID),
			client.ParseDomain(d)
		]);
		return dom.div(crumbs(crumblink("Mox Admin", "#"), crumblink("TLSRPT", "#tlsrpt"), crumblink("Reports", "#tlsrpt/reports"), crumblink("Domain " + domainString(dnsdomain), "#tlsrpt/reports/" + d), "Report " + reportID), dom.p("Below is the raw report as received from the remote mail server."), dom.div(dom._class("literal"), JSON.stringify(report, null, "	")));
	}, "domainTLSRPTID");
	var mtasts = /* @__PURE__ */ __name(async () => {
		const policies = await client.MTASTSPolicies();
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "MTA-STS policies"), dom.p("MTA-STS is a mechanism allowing email domains to publish a policy for using SMTP STARTTLS and TLS verification. See ", link("https://www.rfc-editor.org/rfc/rfc8461.html", "RFC 8461"), "."), dom.p("The SMTP protocol is unencrypted by default, though the SMTP STARTTLS command is typically used to enable TLS on a connection. However, MTA's using STARTTLS typically do not validate the TLS certificate. An MTA-STS policy can specify that validation of host name, non-expiration and webpki trust is required."), makeMTASTSTable(policies || []));
	}, "mtasts");
	var formatMTASTSMX = /* @__PURE__ */ __name((mx) => {
		return mx.map((e) => {
			return (e.Wildcard ? "*." : "") + e.Domain.ASCII;
		}).join(", ");
	}, "formatMTASTSMX");
	var makeMTASTSTable = /* @__PURE__ */ __name((items) => {
		if (items.length === 0) {
			return dom.div("No data");
		}
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
			["Inserted", "", "Time when the policy was first inserted."]
		];
		const nowSecs = (/* @__PURE__ */ new Date()).getTime() / 1e3;
		return dom.table(dom._class("hover"), dom.thead(dom.tr(keys.map((kt) => dom.th(dom.span(attr.title(kt[2]), kt[1] || kt[0]))))), dom.tbody(items.map((e) => dom.tr([
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
			age(e.Inserted, false, nowSecs)
		].map((v) => dom.td(v === null ? [] : v instanceof HTMLElement ? v : "" + v))))));
	}, "makeMTASTSTable");
	var dnsbl = /* @__PURE__ */ __name(async () => {
		const [ipZoneResults, usingZones, monitorZones] = await client.DNSBLStatus();
		const url = /* @__PURE__ */ __name((ip) => "https://multirbl.valli.org/lookup/" + encodeURIComponent(ip) + ".html", "url");
		let fieldset;
		let monitorTextarea;
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "DNS blocklist status for IPs"), dom.p("Follow the external links to a third party DNSBL checker to see if the IP is on one of the many blocklist."), dom.ul(Object.entries(ipZoneResults).sort().map((ipZones) => {
			const [ip, zoneResults] = ipZones;
			return dom.li(link(url(ip), ip), !ipZones.length ? [] : dom.ul(Object.entries(zoneResults).sort().map((zoneResult) => dom.li(zoneResult[0] + ": ", zoneResult[1] === "pass" ? "pass" : box(red, zoneResult[1])))));
		})), !Object.entries(ipZoneResults).length ? box(red, "No IPs found.") : [], dom.br(), dom.h2("DNSBL zones checked due to being used for incoming deliveries"), (usingZones || []).length === 0 ? dom.div("None") : dom.ul((usingZones || []).map((zone) => dom.li(domainString(zone)))), dom.br(), dom.h2("DNSBL zones to monitor only"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			await check(fieldset, client.MonitorDNSBLsSave(monitorTextarea.value));
			dnsbl();
		}, "submit"), fieldset = dom.fieldset(dom.div("One per line"), dom.div(style({ marginBottom: ".5ex" }), monitorTextarea = dom.textarea(style({ width: "20rem" }), attr.rows("" + Math.max(5, 1 + (monitorZones || []).length)), new String((monitorZones || []).map((zone) => domainName(zone)).join("\n"))), dom.div("Examples: sbl.spamhaus.org or bl.spamcop.net")), dom.div(dom.submitbutton("Save")))));
	}, "dnsbl");
	var queueList = /* @__PURE__ */ __name(async () => {
		let filter = { Max: parseInt(localStorageGet("adminpaginationsize") || "") || 100, IDs: [], Account: "", From: "", To: "", Hold: null, Submitted: "", NextAttempt: "", Transport: null };
		let sort = { Field: "NextAttempt", LastID: 0, Last: null, Asc: true };
		let [holdRules, msgs0, transports] = await Promise.all([
			client.QueueHoldRuleList(),
			client.QueueList(filter, sort),
			client.Transports()
		]);
		let msgs = msgs0 || [];
		const nowSecs = (/* @__PURE__ */ new Date()).getTime() / 1e3;
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
		let toggles = /* @__PURE__ */ new Map();
		const gatherIDs = /* @__PURE__ */ __name(() => {
			const f = {
				Max: 0,
				IDs: Array.from(toggles.entries()).filter((t) => t[1].checked).map((t) => t[0]),
				Account: "",
				From: "",
				To: "",
				Hold: null,
				Submitted: "",
				NextAttempt: "",
				Transport: null
			};
			if ((f.IDs || []).length === 0) {
				throw new Error("No messages selected.");
			}
			return f;
		}, "gatherIDs");
		const popupDetails = /* @__PURE__ */ __name((m) => {
			const nowSecs2 = (/* @__PURE__ */ new Date()).getTime() / 1e3;
			popup(dom.h1("Details"), dom.table(dom.tr(dom.td("Message subject"), dom.td(m.Subject))), dom.br(), dom.h2("Results"), dom.table(dom.thead(dom.tr(dom.th("Start"), dom.th("Duration"), dom.th("Success"), dom.th("Code"), dom.th("Secode"), dom.th("Error"))), dom.tbody((m.Results || []).length === 0 ? dom.tr(dom.td(attr.colspan("6"), "No results.")) : [], (m.Results || []).map((r) => dom.tr(dom.td(age(r.Start, false, nowSecs2)), dom.td(Math.round(r.Duration / 1e6) + "ms"), dom.td(r.Success ? "\u2713" : ""), dom.td("" + (r.Code || "")), dom.td(r.Secode), dom.td(r.Error))))));
		}, "popupDetails");
		let tbody = dom.tbody();
		const render = /* @__PURE__ */ __name(() => {
			toggles = /* @__PURE__ */ new Map();
			for (const m of msgs) {
				toggles.set(m.ID, dom.input(attr.type("checkbox"), msgs.length === 1 ? attr.checked("") : []));
			}
			const ntbody = dom.tbody(dom._class("loadend"), msgs.length === 0 ? dom.tr(dom.td(attr.colspan("15"), "No messages.")) : [], msgs.map((m) => {
				return dom.tr(
					dom.td(toggles.get(m.ID)),
					dom.td("" + m.ID + (m.BaseID > 0 ? "/" + m.BaseID : "")),
					dom.td(age(new Date(m.Queued), false, nowSecs)),
					dom.td(m.SenderAccount || "-"),
					dom.td(prewrap(m.SenderLocalpart, "@", ipdomainString(m.SenderDomain))),
					// todo: escaping of localpart
					dom.td(prewrap(m.RecipientLocalpart, "@", ipdomainString(m.RecipientDomain))),
					// todo: escaping of localpart
					dom.td(formatSize(m.Size)),
					dom.td("" + m.Attempts),
					dom.td(m.Hold ? "Hold" : ""),
					dom.td(age(new Date(m.NextAttempt), true, nowSecs)),
					dom.td(m.LastAttempt ? age(new Date(m.LastAttempt), false, nowSecs) : "-"),
					dom.td(m.Results && m.Results.length > 0 ? m.Results[m.Results.length - 1].Error : []),
					dom.td(m.Transport || "(default)"),
					dom.td(m.RequireTLS === true ? "Yes" : m.RequireTLS === false ? "No" : ""),
					dom.td(dom.clickbutton("Details", /* @__PURE__ */ __name(function click() {
						popupDetails(m);
					}, "click")))
				);
			}));
			tbody.replaceWith(ntbody);
			tbody = ntbody;
		}, "render");
		render();
		const buttonNextAttemptSet = /* @__PURE__ */ __name((text, minutes) => dom.clickbutton(text, /* @__PURE__ */ __name(async function click(e) {
			const n = await check(e.target, (async () => await client.QueueNextAttemptSet(gatherIDs(), minutes))());
			window.alert("" + n + " message(s) updated");
			window.location.reload();
		}, "click")), "buttonNextAttemptSet");
		const buttonNextAttemptAdd = /* @__PURE__ */ __name((text, minutes) => dom.clickbutton(text, /* @__PURE__ */ __name(async function click(e) {
			const n = await check(e.target, (async () => await client.QueueNextAttemptAdd(gatherIDs(), minutes))());
			window.alert("" + n + " message(s) updated");
			window.location.reload();
		}, "click")), "buttonNextAttemptAdd");
		return dom.div(
			crumbs(crumblink("Mox Admin", "#"), "Queue"),
			dom.p(dom.a(attr.href("#queue/retired"), "Retired messages")),
			dom.h2("Hold rules", attr.title('Messages submitted to the queue that match a hold rule are automatically marked as "on hold", preventing delivery until explicitly taken off hold again.')),
			dom.form(attr.id("holdRuleForm"), /* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				const pr = {
					ID: 0,
					Account: holdRuleAccount.value,
					SenderDomainStr: holdRuleSenderDomain.value,
					RecipientDomainStr: holdRuleRecipientDomain.value,
					// Filled in by backend, we provide dummy values.
					SenderDomain: { ASCII: "", Unicode: "" },
					RecipientDomain: { ASCII: "", Unicode: "" }
				};
				await check(holdRuleSubmit, client.QueueHoldRuleAdd(pr));
				window.location.reload();
			}, "submit")),
			(function() {
				let show = (holdRules || []).length > 0;
				const box2 = dom.div();
				const renderHoldRules = /* @__PURE__ */ __name(() => {
					dom._kids(box2, !show ? dom.div("No hold rules. ", dom.clickbutton("Add", /* @__PURE__ */ __name(function click() {
						show = true;
						renderHoldRules();
					}, "click"))) : [
						dom.p('Newly submitted messages matching a hold rule will be marked as "on hold" and not be delivered until further action by the admin. To create a rule matching all messages, leave all fields empty.'),
						dom.table(dom.thead(dom.tr(dom.th("Account"), dom.th("Sender domain"), dom.th("Recipient domain"), dom.th("Action"))), dom.tbody((holdRules || []).length === 0 ? dom.tr(dom.td(attr.colspan("4"), "No hold rules.")) : [], (holdRules || []).map((pr) => dom.tr(!pr.Account && !pr.SenderDomainStr && !pr.RecipientDomainStr ? dom.td(attr.colspan("3"), "(Match all messages)") : [
							dom.td(pr.Account),
							dom.td(domainString(pr.SenderDomain)),
							dom.td(domainString(pr.RecipientDomain))
						], dom.td(dom.clickbutton("Remove", attr.title('Removing a hold rule does not modify the "on hold" status of messages in the queue.'), /* @__PURE__ */ __name(async function click(e) {
							await check(e.target, client.QueueHoldRuleRemove(pr.ID));
							window.location.reload();
						}, "click"))))), dom.tr(dom.td(holdRuleAccount = dom.input(attr.form("holdRuleForm"))), dom.td(holdRuleSenderDomain = dom.input(attr.form("holdRuleForm"))), dom.td(holdRuleRecipientDomain = dom.input(attr.form("holdRuleForm"))), dom.td(holdRuleSubmit = dom.submitbutton("Add hold rule", attr.form("holdRuleForm"), attr.title("When adding a new hold rule, existing messages in queue matching the new rule will be marked as on hold."))))))
					]);
				}, "renderHoldRules");
				renderHoldRules();
				return box2;
			})(),
			dom.br(),
			// Filtering.
			filterForm = dom.form(
				attr.id("queuefilter"),
				// Referenced by input elements in table row.
				/* @__PURE__ */ __name(async function submit(e) {
					e.preventDefault();
					e.stopPropagation();
					filter = {
						Max: filter.Max,
						IDs: [],
						Account: filterAccount.value,
						From: filterFrom.value,
						To: filterTo.value,
						Hold: filterHold.value === "Yes" ? true : filterHold.value === "No" ? false : null,
						Submitted: filterSubmitted.value,
						NextAttempt: filterNextAttempt.value,
						Transport: !filterTransport.value ? null : filterTransport.value === "(default)" ? "" : filterTransport.value
					};
					sort = {
						Field: sortElem.value.startsWith("nextattempt") ? "NextAttempt" : "Queued",
						LastID: 0,
						Last: null,
						Asc: sortElem.value.endsWith("asc")
					};
					tbody.classList.add("loadstart");
					msgs = await check({ disabled: false }, client.QueueList(filter, sort)) || [];
					render();
				}, "submit")
			),
			dom.h2("Messages"),
			dom.table(dom._class("hover"), style({ width: "100%" }), dom.thead(dom.tr(
				dom.td(attr.colspan("2"), "Filter"),
				dom.td(filterSubmitted = dom.input(attr.form("queuefilter"), style({ width: "7em" }), attr.title('Example: "<-1h" for filtering messages submitted more than 1 hour ago.'))),
				dom.td(filterAccount = dom.input(attr.form("queuefilter"))),
				dom.td(filterFrom = dom.input(attr.form("queuefilter")), attr.title('Example: "@sender.example" to filter by domain of sender.')),
				dom.td(filterTo = dom.input(attr.form("queuefilter")), attr.title('Example: "@recipient.example" to filter by domain of recipient.')),
				dom.td(),
				// todo: add filter by size?
				dom.td(),
				// todo: add filter by attempts?
				dom.td(filterHold = dom.select(attr.form("queuefilter"), /* @__PURE__ */ __name(function change() {
					filterForm.requestSubmit();
				}, "change"), dom.option("", attr.value("")), dom.option("Yes"), dom.option("No"))),
				dom.td(filterNextAttempt = dom.input(attr.form("queuefilter"), style({ width: "7em" }), attr.title('Example: ">1h" for filtering messages to be delivered in more than 1 hour, or "<now" for messages to be delivered as soon as possible.'))),
				dom.td(),
				dom.td(),
				dom.td(filterTransport = dom.select(Object.keys(transports || {}).length === 0 ? style({ display: "none" }) : [], attr.form("queuefilter"), /* @__PURE__ */ __name(function change() {
					filterForm.requestSubmit();
				}, "change"), dom.option(""), dom.option("(default)"), Object.keys(transports || {}).sort().map((t) => dom.option(t)))),
				dom.td(
					attr.colspan("2"),
					style({ textAlign: "right" }),
					// Less content shifting while rendering.
					"Sort ",
					sortElem = dom.select(attr.form("queuefilter"), /* @__PURE__ */ __name(function change() {
						filterForm.requestSubmit();
					}, "change"), dom.option("Next attempt \u2191", attr.value("nextattempt-asc")), dom.option("Next attempt \u2193", attr.value("nextattempt-desc")), dom.option("Submitted \u2191", attr.value("submitted-asc")), dom.option("Submitted \u2193", attr.value("submitted-desc"))),
					" ",
					dom.submitbutton("Apply", attr.form("queuefilter")),
					" ",
					dom.clickbutton("Reset", attr.form("queuefilter"), /* @__PURE__ */ __name(function click() {
						filterForm.reset();
						filterForm.requestSubmit();
					}, "click"))
				)
			), dom.tr(dom.td(dom.input(attr.type("checkbox"), msgs.length === 1 ? attr.checked("") : [], attr.form("queuefilter"), /* @__PURE__ */ __name(function change(e) {
				const elem = e.target;
				for (const [_, toggle] of toggles) {
					toggle.checked = elem.checked;
				}
			}, "change"))), dom.th("ID"), dom.th("Submitted"), dom.th("Account"), dom.th("From"), dom.th("To"), dom.th("Size"), dom.th("Attempts"), dom.th("Hold"), dom.th("Next attempt"), dom.th("Last attempt"), dom.th("Last error"), dom.th("Transport"), dom.th("Require TLS"), dom.th("Actions"))), tbody, dom.tfoot(dom.tr(dom.td(
				attr.colspan("15"),
				// todo: consider implementing infinite scroll, autoloading more pages. means the operations on selected messages should be moved from below to above the table. and probably only show them when at least one message is selected to prevent clutter.
				dom.clickbutton("Load more", attr.title("Try to load more entries. You can still try to load more entries when at the end of the list, new entries may have been appended since the previous call."), /* @__PURE__ */ __name(async function click(e) {
					if (msgs.length === 0) {
						sort.LastID = 0;
						sort.Last = null;
					} else {
						const lm = msgs[msgs.length - 1];
						sort.LastID = lm.ID;
						if (sort.Field === "Queued") {
							sort.Last = lm.Queued;
						} else {
							sort.Last = lm.NextAttempt;
						}
					}
					tbody.classList.add("loadstart");
					const l = await check(e.target, client.QueueList(filter, sort)) || [];
					msgs.push(...l);
					render();
				}, "click"))
			)))),
			dom.br(),
			dom.br(),
			dom.div(dom._class("unclutter"), dom.h2("Change selected messages"), dom.div(style({ display: "flex", gap: "2em" }), dom.div(dom.div("Hold"), dom.div(dom.clickbutton("On", /* @__PURE__ */ __name(async function click(e) {
				const n = await check(e.target, (async () => await client.QueueHoldSet(gatherIDs(), true))());
				window.alert("" + n + " message(s) updated");
				window.location.reload();
			}, "click")), " ", dom.clickbutton("Off", /* @__PURE__ */ __name(async function click(e) {
				const n = await check(e.target, (async () => await client.QueueHoldSet(gatherIDs(), false))());
				window.alert("" + n + " message(s) updated");
				window.location.reload();
			}, "click")))), dom.div(dom.div("Schedule next delivery attempt"), buttonNextAttemptSet("Now", 0), " ", dom.clickbutton("More...", /* @__PURE__ */ __name(function click(e) {
				e.target.replaceWith(dom.div(dom.br(), dom.div("Scheduled time plus"), dom.div(buttonNextAttemptAdd("1m", 1), " ", buttonNextAttemptAdd("5m", 5), " ", buttonNextAttemptAdd("30m", 30), " ", buttonNextAttemptAdd("1h", 60), " ", buttonNextAttemptAdd("2h", 2 * 60), " ", buttonNextAttemptAdd("4h", 4 * 60), " ", buttonNextAttemptAdd("8h", 8 * 60), " ", buttonNextAttemptAdd("16h", 16 * 60), " "), dom.br(), dom.div("Now plus"), dom.div(buttonNextAttemptSet("1m", 1), " ", buttonNextAttemptSet("5m", 5), " ", buttonNextAttemptSet("30m", 30), " ", buttonNextAttemptSet("1h", 60), " ", buttonNextAttemptSet("2h", 2 * 60), " ", buttonNextAttemptSet("4h", 4 * 60), " ", buttonNextAttemptSet("8h", 8 * 60), " ", buttonNextAttemptSet("16h", 16 * 60), " ")));
			}, "click"))), dom.div(dom.form(dom.label("Require TLS"), requiretlsFieldset = dom.fieldset(requiretls = dom.select(attr.title("How to use TLS for message delivery over SMTP:\n\nDefault: Delivery attempts follow the policies published by the recipient domain: Verification with MTA-STS and/or DANE, or optional opportunistic unverified STARTTLS if the domain does not specify a policy.\n\nWith RequireTLS: For sensitive messages, you may want to require verified TLS. The recipient destination domain SMTP server must support the REQUIRETLS SMTP extension for delivery to succeed. It is automatically chosen when the destination domain mail servers of all recipients are known to support it.\n\nFallback to insecure: If delivery fails due to MTA-STS and/or DANE policies specified by the recipient domain, and the content is not sensitive, you may choose to ignore the recipient domain TLS policies so delivery can succeed."), dom.option("Default", attr.value("")), dom.option("With RequireTLS", attr.value("yes")), dom.option("Fallback to insecure", attr.value("no"))), " ", dom.submitbutton("Change")), /* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				const n = await check(requiretlsFieldset, (async () => await client.QueueRequireTLSSet(gatherIDs(), requiretls.value === "" ? null : requiretls.value === "yes"))());
				window.alert("" + n + " message(s) updated");
				window.location.reload();
			}, "submit"))), dom.div(dom.form(dom.label("Transport"), dom.fieldset(transport = dom.select(attr.title("Transport to use for delivery attempts. The default is direct delivery, connecting to the MX hosts of the domain."), dom.option("(default)", attr.value("")), Object.keys(transports || []).sort().map((t) => dom.option(t))), " ", dom.submitbutton("Change")), /* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				const n = await check(e.target, (async () => await client.QueueTransportSet(gatherIDs(), transport.value))());
				window.alert("" + n + " message(s) updated");
				window.location.reload();
			}, "submit"))), dom.div(dom.div("Delivery"), dom.clickbutton("Fail delivery", attr.title("Cause delivery to fail, sending a DSN to the sender."), /* @__PURE__ */ __name(async function click(e) {
				e.preventDefault();
				if (!window.confirm("Are you sure you want to fail delivery for the selected message(s)? Notifications of delivery failure will be sent (DSNs).")) {
					return;
				}
				const n = await check(e.target, (async () => await client.QueueFail(gatherIDs()))());
				window.alert("" + n + " message(s) updated");
				window.location.reload();
			}, "click"))), dom.div(dom.div("Messages"), dom.clickbutton("Remove", attr.title("Completely remove messages from queue, not sending a DSN."), /* @__PURE__ */ __name(async function click(e) {
				e.preventDefault();
				if (!window.confirm("Are you sure you want to fail delivery for the selected message(s)? It will be removed completely, no DSN about failure to deliver will be sent.")) {
					return;
				}
				const n = await check(e.target, (async () => await client.QueueDrop(gatherIDs()))());
				window.alert("" + n + " message(s) updated");
				window.location.reload();
			}, "click")))))
		);
	}, "queueList");
	var retiredList = /* @__PURE__ */ __name(async () => {
		let filter = { Max: parseInt(localStorageGet("adminpaginationsize") || "") || 100, IDs: [], Account: "", From: "", To: "", Submitted: "", LastActivity: "", Transport: null };
		let sort = { Field: "LastActivity", LastID: 0, Last: null, Asc: false };
		const [retired0, transports0] = await Promise.all([
			client.RetiredList(filter, sort),
			client.Transports()
		]);
		let retired = retired0 || [];
		let transports = transports0 || {};
		const nowSecs = (/* @__PURE__ */ new Date()).getTime() / 1e3;
		let sortElem;
		let filterForm;
		let filterAccount;
		let filterFrom;
		let filterTo;
		let filterSubmitted;
		let filterLastActivity;
		let filterTransport;
		let filterSuccess;
		const popupDetails = /* @__PURE__ */ __name((m) => {
			const nowSecs2 = (/* @__PURE__ */ new Date()).getTime() / 1e3;
			popup(dom.h1("Details"), dom.table(dom.tr(dom.td("Message subject"), dom.td(m.Subject))), dom.br(), dom.h2("Results"), dom.table(dom.thead(dom.tr(dom.th("Start"), dom.th("Duration"), dom.th("Success"), dom.th("Code"), dom.th("Secode"), dom.th("Error"))), dom.tbody((m.Results || []).length === 0 ? dom.tr(dom.td(attr.colspan("6"), "No results.")) : [], (m.Results || []).map((r) => dom.tr(dom.td(age(r.Start, false, nowSecs2)), dom.td(Math.round(r.Duration / 1e6) + "ms"), dom.td(r.Success ? "\u2713" : ""), dom.td("" + (r.Code || "")), dom.td(r.Secode), dom.td(r.Error))))));
		}, "popupDetails");
		let tbody = dom.tbody();
		const render = /* @__PURE__ */ __name(() => {
			const ntbody = dom.tbody(dom._class("loadend"), retired.length === 0 ? dom.tr(dom.td(attr.colspan("14"), "No retired messages.")) : [], retired.map((m) => dom.tr(
				dom.td("" + m.ID + (m.BaseID > 0 ? "/" + m.BaseID : "")),
				dom.td(m.Success ? "\u2713" : ""),
				dom.td(age(new Date(m.LastActivity), false, nowSecs)),
				dom.td(age(new Date(m.Queued), false, nowSecs)),
				dom.td(m.SenderAccount || "-"),
				dom.td(prewrap(m.SenderLocalpart, "@", m.SenderDomainStr)),
				// todo: escaping of localpart
				dom.td(prewrap(m.RecipientLocalpart, "@", m.RecipientDomainStr)),
				// todo: escaping of localpart
				dom.td(formatSize(m.Size)),
				dom.td("" + m.Attempts),
				dom.td(m.LastAttempt ? age(new Date(m.LastAttempt), false, nowSecs) : "-"),
				dom.td(m.Results && m.Results.length > 0 ? m.Results[m.Results.length - 1].Error : []),
				dom.td(m.Transport || ""),
				dom.td(m.RequireTLS === true ? "Yes" : m.RequireTLS === false ? "No" : ""),
				dom.td(dom.clickbutton("Details", /* @__PURE__ */ __name(function click() {
					popupDetails(m);
				}, "click")))
			)));
			tbody.replaceWith(ntbody);
			tbody = ntbody;
		}, "render");
		render();
		return dom.div(
			crumbs(crumblink("Mox Admin", "#"), crumblink("Queue", "#queue"), "Retired messages"),
			// Filtering.
			filterForm = dom.form(
				attr.id("queuefilter"),
				// Referenced by input elements in table row.
				/* @__PURE__ */ __name(async function submit(e) {
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
						Transport: !filterTransport.value ? null : filterTransport.value === "(default)" ? "" : filterTransport.value,
						Success: filterSuccess.value === "" ? null : filterSuccess.value === "Yes" ? true : false
					};
					sort = {
						Field: sortElem.value.startsWith("lastactivity") ? "LastActivity" : "Queued",
						LastID: 0,
						Last: null,
						Asc: sortElem.value.endsWith("asc")
					};
					tbody.classList.add("loadstart");
					retired = await check({ disabled: false }, client.RetiredList(filter, sort)) || [];
					render();
				}, "submit")
			),
			dom.h2("Retired messages"),
			dom.p("Meta information about queued messages may be kept after successful and/or failed delivery, configurable per account."),
			dom.table(dom._class("hover"), style({ width: "100%" }), dom.thead(dom.tr(
				dom.td("Filter"),
				dom.td(filterSuccess = dom.select(attr.form("queuefilter"), /* @__PURE__ */ __name(function change() {
					filterForm.requestSubmit();
				}, "change"), dom.option(""), dom.option("Yes"), dom.option("No"))),
				dom.td(filterLastActivity = dom.input(attr.form("queuefilter"), style({ width: "7em" }), attr.title('Example: ">-1h" for filtering messages with last activity less than 1 hour ago.'))),
				dom.td(filterSubmitted = dom.input(attr.form("queuefilter"), style({ width: "7em" }), attr.title('Example: "<-1h" for filtering messages submitted more than 1 hour ago.'))),
				dom.td(filterAccount = dom.input(attr.form("queuefilter"))),
				dom.td(filterFrom = dom.input(attr.form("queuefilter")), attr.title('Example: "@sender.example" to filter by domain of sender.')),
				dom.td(filterTo = dom.input(attr.form("queuefilter")), attr.title('Example: "@recipient.example" to filter by domain of recipient.')),
				dom.td(),
				// todo: add filter by size?
				dom.td(),
				// todo: add filter by attempts?
				dom.td(),
				dom.td(),
				dom.td(filterTransport = dom.select(Object.keys(transports).length === 0 ? style({ display: "none" }) : [], attr.form("queuefilter"), /* @__PURE__ */ __name(function change() {
					filterForm.requestSubmit();
				}, "change"), dom.option(""), dom.option("(default)"), Object.keys(transports).sort().map((t) => dom.option(t)))),
				dom.td(
					attr.colspan("2"),
					style({ textAlign: "right" }),
					// Less content shifting while rendering.
					"Sort ",
					sortElem = dom.select(attr.form("queuefilter"), /* @__PURE__ */ __name(function change() {
						filterForm.requestSubmit();
					}, "change"), dom.option("Last activity \u2193", attr.value("lastactivity-desc")), dom.option("Last activity \u2191", attr.value("lastactivity-asc")), dom.option("Submitted \u2193", attr.value("submitted-desc")), dom.option("Submitted \u2191", attr.value("submitted-asc"))),
					" ",
					dom.submitbutton("Apply", attr.form("queuefilter")),
					" ",
					dom.clickbutton("Reset", attr.form("queuefilter"), /* @__PURE__ */ __name(function click() {
						filterForm.reset();
						filterForm.requestSubmit();
					}, "click"))
				)
			), dom.tr(dom.th("ID"), dom.th("Success"), dom.th("Last activity"), dom.th("Submitted"), dom.th("Account"), dom.th("From"), dom.th("To"), dom.th("Size"), dom.th("Attempts"), dom.th("Last attempt"), dom.th("Last error"), dom.th("Require TLS"), dom.th("Transport"), dom.th("Actions"))), tbody, dom.tfoot(dom.tr(dom.td(attr.colspan("14"), dom.clickbutton("Load more", attr.title("Try to load more entries. You can still try to load more entries when at the end of the list, new entries may have been appended since the previous call."), /* @__PURE__ */ __name(async function click(e) {
				if (retired.length === 0) {
					sort.LastID = 0;
					sort.Last = null;
				} else {
					const lm = retired[retired.length - 1];
					sort.LastID = lm.ID;
					if (sort.Field === "Queued") {
						sort.Last = lm.Queued;
					} else {
						sort.Last = lm.LastActivity;
					}
				}
				tbody.classList.add("loadstart");
				const l = await check(e.target, client.RetiredList(filter, sort)) || [];
				retired.push(...l);
				render();
			}, "click"))))))
		);
	}, "retiredList");
	var formatExtra = /* @__PURE__ */ __name((extra) => {
		if (!extra) {
			return "";
		}
		return Object.entries(extra).sort((a, b) => a[0] < b[0] ? -1 : 1).map((t) => t[0] + ": " + t[1]).join("; ");
	}, "formatExtra");
	var hooksList = /* @__PURE__ */ __name(async () => {
		let filter = { Max: parseInt(localStorageGet("adminpaginationsize") || "") || 100, IDs: [], Account: "", Submitted: "", NextAttempt: "", Event: "" };
		let sort = { Field: "NextAttempt", LastID: 0, Last: null, Asc: true };
		let hooks = await client.HookList(filter, sort) || [];
		const nowSecs = (/* @__PURE__ */ new Date()).getTime() / 1e3;
		let sortElem;
		let filterForm;
		let filterSubmitted;
		let filterAccount;
		let filterEvent;
		let filterNextAttempt;
		let toggles = /* @__PURE__ */ new Map();
		const gatherIDs = /* @__PURE__ */ __name(() => {
			const f = {
				Max: 0,
				IDs: Array.from(toggles.entries()).filter((t) => t[1].checked).map((t) => t[0]),
				Account: "",
				Event: "",
				Submitted: "",
				NextAttempt: ""
			};
			if ((f.IDs || []).length === 0) {
				throw new Error("No hooks selected.");
			}
			return f;
		}, "gatherIDs");
		const popupDetails = /* @__PURE__ */ __name((h) => {
			const nowSecs2 = (/* @__PURE__ */ new Date()).getTime() / 1e3;
			popup(dom.h1("Details"), dom.div(dom._class("twocols"), dom.div(dom.table(dom.tr(dom.td("Message subject"), dom.td(h.Subject))), dom.br(), dom.h2("Results"), dom.table(dom.thead(dom.tr(dom.th("Start"), dom.th("Duration"), dom.th("Success"), dom.th("Code"), dom.th("Error"), dom.th("URL"), dom.th("Response"))), dom.tbody((h.Results || []).length === 0 ? dom.tr(dom.td(attr.colspan("7"), "No results.")) : [], (h.Results || []).map((r) => dom.tr(dom.td(age(r.Start, false, nowSecs2)), dom.td(Math.round(r.Duration / 1e6) + "ms"), dom.td(r.Success ? "\u2713" : ""), dom.td("" + (r.Code || "")), dom.td(r.Error), dom.td(r.URL), dom.td(r.Response))))), dom.br()), dom.div(dom.h2("Webhook JSON body"), dom.pre(dom._class("literal"), JSON.stringify(JSON.parse(h.Payload), void 0, "	")))));
		}, "popupDetails");
		let tbody = dom.tbody();
		const render = /* @__PURE__ */ __name(() => {
			toggles = /* @__PURE__ */ new Map();
			for (const h of hooks || []) {
				toggles.set(h.ID, dom.input(attr.type("checkbox"), (hooks || []).length === 1 ? attr.checked("") : []));
			}
			const ntbody = dom.tbody(dom._class("loadend"), hooks.length === 0 ? dom.tr(dom.td(attr.colspan("15"), "No webhooks.")) : [], hooks.map((h) => dom.tr(
				dom.td(toggles.get(h.ID)),
				dom.td("" + h.ID),
				dom.td(age(new Date(h.Submitted), false, nowSecs)),
				dom.td("" + (h.QueueMsgID || "")),
				// todo future: make it easy to open the corresponding (retired) message from queue (if still around).
				dom.td("" + h.FromID),
				dom.td("" + h.MessageID),
				dom.td(h.Account || "-"),
				dom.td(h.IsIncoming ? "incoming" : h.OutgoingEvent),
				dom.td(formatExtra(h.Extra)),
				dom.td("" + h.Attempts),
				dom.td(age(h.NextAttempt, true, nowSecs)),
				dom.td(h.Results && h.Results.length > 0 ? age(h.Results[h.Results.length - 1].Start, false, nowSecs) : []),
				dom.td(h.Results && h.Results.length > 0 ? h.Results[h.Results.length - 1].Error : []),
				dom.td(h.URL),
				dom.td(dom.clickbutton("Details", /* @__PURE__ */ __name(function click() {
					popupDetails(h);
				}, "click")))
			)));
			tbody.replaceWith(ntbody);
			tbody = ntbody;
		}, "render");
		render();
		const buttonNextAttemptSet = /* @__PURE__ */ __name((text, minutes) => dom.clickbutton(text, /* @__PURE__ */ __name(async function click(e) {
			const n = await check(e.target, (async () => await client.HookNextAttemptSet(gatherIDs(), minutes))());
			window.alert("" + n + " hook(s) updated");
			window.location.reload();
		}, "click")), "buttonNextAttemptSet");
		const buttonNextAttemptAdd = /* @__PURE__ */ __name((text, minutes) => dom.clickbutton(text, /* @__PURE__ */ __name(async function click(e) {
			const n = await check(e.target, (async () => await client.HookNextAttemptAdd(gatherIDs(), minutes))());
			window.alert("" + n + " hook(s) updated");
			window.location.reload();
		}, "click")), "buttonNextAttemptAdd");
		return dom.div(
			crumbs(crumblink("Mox Admin", "#"), "Webhook queue"),
			dom.p(dom.a(attr.href("#webhookqueue/retired"), "Retired webhooks")),
			dom.h2("Webhooks"),
			dom.table(dom._class("hover"), style({ width: "100%" }), dom.thead(dom.tr(dom.td(attr.colspan("2"), "Filter"), dom.td(filterSubmitted = dom.input(attr.form("hooksfilter"), style({ width: "7em" }), attr.title('Example: "<-1h" for filtering webhooks submitted more than 1 hour ago.'))), dom.td(), dom.td(), dom.td(), dom.td(filterAccount = dom.input(attr.form("hooksfilter"), style({ width: "8em" }))), dom.td(filterEvent = dom.select(
				attr.form("hooksfilter"),
				/* @__PURE__ */ __name(function change() {
					filterForm.requestSubmit();
				}, "change"),
				dom.option(""),
				// note: outgoing hook events are in ../webhook/webhook.go, ../mox-/config.go ../webadmin/admin.ts and ../webapi/gendoc.sh. keep in sync.
				["incoming", "delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"].map((s) => dom.option(s))
			)), dom.td(), dom.td(), dom.td(filterNextAttempt = dom.input(attr.form("hooksfilter"), style({ width: "7em" }), attr.title('Example: ">1h" for filtering webhooks to be delivered in more than 1 hour, or "<now" for webhooks to be delivered as soon as possible.'))), dom.td(), dom.td(), dom.td(
				attr.colspan("2"),
				style({ textAlign: "right" }),
				// Less content shifting while rendering.
				"Sort ",
				sortElem = dom.select(attr.form("hooksfilter"), /* @__PURE__ */ __name(function change() {
					filterForm.requestSubmit();
				}, "change"), dom.option("Next attempt \u2191", attr.value("nextattempt-asc")), dom.option("Next attempt \u2193", attr.value("nextattempt-desc")), dom.option("Submitted \u2191", attr.value("submitted-asc")), dom.option("Submitted \u2193", attr.value("submitted-desc"))),
				" ",
				dom.submitbutton("Apply", attr.form("hooksfilter")),
				" ",
				dom.clickbutton("Reset", attr.form("hooksfilter"), /* @__PURE__ */ __name(function click() {
					filterForm.reset();
					filterForm.requestSubmit();
				}, "click"))
			)), dom.tr(dom.td(dom.input(attr.type("checkbox"), (hooks || []).length === 1 ? attr.checked("") : [], attr.form("hooksfilter"), /* @__PURE__ */ __name(function change(e) {
				const elem = e.target;
				for (const [_, toggle] of toggles) {
					toggle.checked = elem.checked;
				}
			}, "change"))), dom.th("ID"), dom.th("Submitted"), dom.th("Queue Msg ID", attr.title("ID of queued message this event is about.")), dom.th("FromID"), dom.th("MessageID"), dom.th("Account"), dom.th("Event"), dom.th("Extra"), dom.th("Attempts"), dom.th("Next"), dom.th("Last"), dom.th("Error"), dom.th("URL"), dom.th("Actions"))), tbody, dom.tfoot(dom.tr(dom.td(attr.colspan("15"), dom.clickbutton("Load more", attr.title("Try to load more entries. You can still try to load more entries when at the end of the list, new entries may have been appended since the previous call."), /* @__PURE__ */ __name(async function click(e) {
				if (hooks.length === 0) {
					sort.LastID = 0;
					sort.Last = null;
				} else {
					const last = hooks[hooks.length - 1];
					sort.LastID = last.ID;
					if (sort.Field === "Submitted") {
						sort.Last = last.Submitted;
					} else {
						sort.Last = last.NextAttempt;
					}
				}
				tbody.classList.add("loadstart");
				const l = await check(e.target, client.HookList(filter, sort)) || [];
				hooks.push(...l);
				render();
			}, "click")))))),
			// Filtering.
			filterForm = dom.form(
				attr.id("hooksfilter"),
				// Referenced by input elements in table row.
				/* @__PURE__ */ __name(async function submit(e) {
					e.preventDefault();
					e.stopPropagation();
					filter = {
						Max: filter.Max,
						IDs: [],
						Account: filterAccount.value,
						Event: filterEvent.value,
						Submitted: filterSubmitted.value,
						NextAttempt: filterNextAttempt.value
					};
					sort = {
						Field: sortElem.value.startsWith("nextattempt") ? "NextAttempt" : "Submitted",
						LastID: 0,
						Last: null,
						Asc: sortElem.value.endsWith("asc")
					};
					tbody.classList.add("loadstart");
					hooks = await check({ disabled: false }, client.HookList(filter, sort)) || [];
					render();
				}, "submit")
			),
			dom.br(),
			dom.br(),
			dom.div(dom._class("unclutter"), dom.h2("Change selected webhooks"), dom.div(style({ display: "flex", gap: "2em" }), dom.div(dom.div("Schedule next delivery attempt"), buttonNextAttemptSet("Now", 0), " ", dom.clickbutton("More...", /* @__PURE__ */ __name(function click(e) {
				e.target.replaceWith(dom.div(dom.br(), dom.div("Scheduled time plus"), dom.div(buttonNextAttemptAdd("1m", 1), " ", buttonNextAttemptAdd("5m", 5), " ", buttonNextAttemptAdd("30m", 30), " ", buttonNextAttemptAdd("1h", 60), " ", buttonNextAttemptAdd("2h", 2 * 60), " ", buttonNextAttemptAdd("4h", 4 * 60), " ", buttonNextAttemptAdd("8h", 8 * 60), " ", buttonNextAttemptAdd("16h", 16 * 60), " "), dom.br(), dom.div("Now plus"), dom.div(buttonNextAttemptSet("1m", 1), " ", buttonNextAttemptSet("5m", 5), " ", buttonNextAttemptSet("30m", 30), " ", buttonNextAttemptSet("1h", 60), " ", buttonNextAttemptSet("2h", 2 * 60), " ", buttonNextAttemptSet("4h", 4 * 60), " ", buttonNextAttemptSet("8h", 8 * 60), " ", buttonNextAttemptSet("16h", 16 * 60), " ")));
			}, "click"))), dom.div(dom.div("Delivery"), dom.clickbutton("Cancel", attr.title("Retires webhooks, preventing further delivery attempts."), /* @__PURE__ */ __name(async function click(e) {
				e.preventDefault();
				if (!window.confirm("Are you sure you want to cancel these webhooks?")) {
					return;
				}
				const n = await check(e.target, (async () => await client.HookCancel(gatherIDs()))());
				window.alert("" + n + " webhook(s) updated");
				window.location.reload();
			}, "click")))))
		);
	}, "hooksList");
	var hooksRetiredList = /* @__PURE__ */ __name(async () => {
		let filter = { Max: parseInt(localStorageGet("adminpaginationsize") || "") || 100, IDs: [], Account: "", Submitted: "", LastActivity: "", Event: "" };
		let sort = { Field: "LastActivity", LastID: 0, Last: null, Asc: false };
		let hooks = await client.HookRetiredList(filter, sort) || [];
		const nowSecs = (/* @__PURE__ */ new Date()).getTime() / 1e3;
		let sortElem;
		let filterForm;
		let filterSubmitted;
		let filterAccount;
		let filterEvent;
		let filterLastActivity;
		const popupDetails = /* @__PURE__ */ __name((h) => {
			const nowSecs2 = (/* @__PURE__ */ new Date()).getTime() / 1e3;
			popup(dom.h1("Details"), dom.div(dom._class("twocols"), dom.div(dom.table(dom.tr(dom.td("Message subject"), dom.td(h.Subject)), h.SupersededByID != 0 ? dom.tr(dom.td("Superseded by webhook ID"), dom.td("" + h.SupersededByID)) : []), dom.br(), dom.h2("Results"), dom.table(dom.thead(dom.tr(dom.th("Start"), dom.th("Duration"), dom.th("Success"), dom.th("Code"), dom.th("Error"), dom.th("URL"), dom.th("Response"))), dom.tbody((h.Results || []).length === 0 ? dom.tr(dom.td(attr.colspan("7"), "No results.")) : [], (h.Results || []).map((r) => dom.tr(dom.td(age(r.Start, false, nowSecs2)), dom.td(Math.round(r.Duration / 1e6) + "ms"), dom.td(r.Success ? "\u2713" : ""), dom.td("" + (r.Code || "")), dom.td(r.Error), dom.td(r.URL), dom.td(r.Response))))), dom.br()), dom.div(dom.h2("Webhook JSON body"), dom.pre(dom._class("literal"), JSON.stringify(JSON.parse(h.Payload), void 0, "	")))));
		}, "popupDetails");
		let tbody = dom.tbody();
		const render = /* @__PURE__ */ __name(() => {
			const ntbody = dom.tbody(dom._class("loadend"), hooks.length === 0 ? dom.tr(dom.td(attr.colspan("14"), "No retired webhooks.")) : [], hooks.map((h) => dom.tr(dom.td("" + h.ID), dom.td(h.Success ? "\u2713" : ""), dom.td(age(h.LastActivity, false, nowSecs)), dom.td(age(new Date(h.Submitted), false, nowSecs)), dom.td("" + (h.QueueMsgID || "")), dom.td("" + h.FromID), dom.td("" + h.MessageID), dom.td(h.Account || "-"), dom.td(h.IsIncoming ? "incoming" : h.OutgoingEvent), dom.td(formatExtra(h.Extra)), dom.td("" + h.Attempts), dom.td(h.Results && h.Results.length > 0 ? h.Results[h.Results.length - 1].Error : []), dom.td(h.URL), dom.td(dom.clickbutton("Details", /* @__PURE__ */ __name(function click() {
				popupDetails(h);
			}, "click"))))));
			tbody.replaceWith(ntbody);
			tbody = ntbody;
		}, "render");
		render();
		return dom.div(
			crumbs(crumblink("Mox Admin", "#"), crumblink("Webhook queue", "#webhookqueue"), "Retired webhooks"),
			dom.h2("Retired webhooks"),
			dom.table(dom._class("hover"), style({ width: "100%" }), dom.thead(dom.tr(dom.td("Filter"), dom.td(), dom.td(filterLastActivity = dom.input(attr.form("hooksfilter"), style({ width: "7em" }), attr.title('Example: ">-1h" for filtering last activity for webhooks more than 1 hour ago.'))), dom.td(filterSubmitted = dom.input(attr.form("hooksfilter"), style({ width: "7em" }), attr.title('Example: "<-1h" for filtering webhooks submitted more than 1 hour ago.'))), dom.td(), dom.td(), dom.td(), dom.td(filterAccount = dom.input(attr.form("hooksfilter"), style({ width: "8em" }))), dom.td(filterEvent = dom.select(
				attr.form("hooksfilter"),
				/* @__PURE__ */ __name(function change() {
					filterForm.requestSubmit();
				}, "change"),
				dom.option(""),
				// note: outgoing hook events are in ../webhook/webhook.go, ../mox-/config.go ../webadmin/admin.ts and ../webapi/gendoc.sh. keep in sync.
				["incoming", "delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized"].map((s) => dom.option(s))
			)), dom.td(), dom.td(), dom.td(), dom.td(
				attr.colspan("2"),
				style({ textAlign: "right" }),
				// Less content shifting while rendering.
				"Sort ",
				sortElem = dom.select(attr.form("hooksfilter"), /* @__PURE__ */ __name(function change() {
					filterForm.requestSubmit();
				}, "change"), dom.option("Last activity \u2193", attr.value("nextattempt-desc")), dom.option("Last activity \u2191", attr.value("nextattempt-asc")), dom.option("Submitted \u2193", attr.value("submitted-desc")), dom.option("Submitted \u2191", attr.value("submitted-asc"))),
				" ",
				dom.submitbutton("Apply", attr.form("hooksfilter")),
				" ",
				dom.clickbutton("Reset", attr.form("hooksfilter"), /* @__PURE__ */ __name(function click() {
					filterForm.reset();
					filterForm.requestSubmit();
				}, "click"))
			)), dom.tr(dom.th("ID"), dom.th("Success"), dom.th("Last"), dom.th("Submitted"), dom.th("Queue Msg ID", attr.title("ID of queued message this event is about.")), dom.th("FromID"), dom.th("MessageID"), dom.th("Account"), dom.th("Event"), dom.th("Extra"), dom.th("Attempts"), dom.th("Error"), dom.th("URL"), dom.th("Actions"))), tbody, dom.tfoot(dom.tr(dom.td(attr.colspan("14"), dom.clickbutton("Load more", attr.title("Try to load more entries. You can still try to load more entries when at the end of the list, new entries may have been appended since the previous call."), /* @__PURE__ */ __name(async function click(e) {
				if (hooks.length === 0) {
					sort.LastID = 0;
					sort.Last = null;
				} else {
					const last = hooks[hooks.length - 1];
					sort.LastID = last.ID;
					if (sort.Field === "Submitted") {
						sort.Last = last.Submitted;
					} else {
						sort.Last = last.LastActivity;
					}
				}
				tbody.classList.add("loadstart");
				const l = await check(e.target, client.HookRetiredList(filter, sort)) || [];
				hooks.push(...l);
				render();
			}, "click")))))),
			// Filtering.
			filterForm = dom.form(
				attr.id("hooksfilter"),
				// Referenced by input elements in table row.
				/* @__PURE__ */ __name(async function submit(e) {
					e.preventDefault();
					e.stopPropagation();
					filter = {
						Max: filter.Max,
						IDs: [],
						Account: filterAccount.value,
						Event: filterEvent.value,
						Submitted: filterSubmitted.value,
						LastActivity: filterLastActivity.value
					};
					sort = {
						Field: sortElem.value.startsWith("lastactivity") ? "LastActivity" : "Submitted",
						LastID: 0,
						Last: null,
						Asc: sortElem.value.endsWith("asc")
					};
					tbody.classList.add("loadstart");
					hooks = await check({ disabled: false }, client.HookRetiredList(filter, sort)) || [];
					render();
				}, "submit")
			)
		);
	}, "hooksRetiredList");
	var webserver = /* @__PURE__ */ __name(async () => {
		let conf = await client.WebserverConfig();
		let fieldset;
		let redirectRows = [];
		let redirectsTbody;
		let noredirect;
		const redirectRow = /* @__PURE__ */ __name((t) => {
			let row;
			let from;
			let to;
			const root = dom.tr(dom.td(from = dom.input(attr.required(""), attr.value(domainName(t[0])))), dom.td(to = dom.input(attr.required(""), attr.value(domainName(t[1])))), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(function click() {
				redirectRows = redirectRows.filter((r) => r !== row);
				row.root.remove();
				noredirect.style.display = redirectRows.length ? "none" : "";
			}, "click"))));
			const get = /* @__PURE__ */ __name(() => [from.value, to.value], "get");
			row = { root, from, to, get };
			redirectRows.push(row);
			return row;
		}, "redirectRow");
		const makeHeaders = /* @__PURE__ */ __name((h) => {
			let view;
			let rows = [];
			let tbody;
			let norow;
			const headerRow = /* @__PURE__ */ __name((k, v) => {
				let row;
				let key;
				let value;
				const root2 = dom.tr(dom.td(key = dom.input(attr.required(""), attr.value(k))), dom.td(value = dom.input(attr.required(""), attr.value(v))), dom.td(dom.clickbutton("Remove", /* @__PURE__ */ __name(function click() {
					rows = rows.filter((x) => x !== row);
					row.root.remove();
					norow.style.display = rows.length ? "none" : "";
				}, "click"))));
				const get2 = /* @__PURE__ */ __name(() => [row.key.value, row.value.value], "get");
				row = { root: root2, key, value, get: get2 };
				rows.push(row);
				return row;
			}, "headerRow");
			const add = dom.clickbutton("Add", /* @__PURE__ */ __name(function click() {
				const row = headerRow("", "");
				tbody.appendChild(row.root);
				norow.style.display = rows.length ? "none" : "";
			}, "click"));
			const root = dom.table(tbody = dom.tbody(Object.entries(h).sort().map((t) => headerRow(t[0], t[1])), norow = dom.tr(style({ display: rows.length ? "none" : "" }), dom.td(attr.colspan("3"), "None added."))));
			const get = /* @__PURE__ */ __name(() => Object.fromEntries(rows.map((row) => row.get())), "get");
			view = { root, add, get };
			return view;
		}, "makeHeaders");
		let handlerRows = [];
		let handlersTbody;
		let nohandler;
		let moveButtonsVisible = false;
		const handlerRow = /* @__PURE__ */ __name((wh) => {
			let row;
			let handlerType;
			let staticView = null;
			let redirectView = null;
			let forwardView = null;
			let internalView = null;
			let moveButtons;
			const makeWebStatic = /* @__PURE__ */ __name((ws) => {
				let view;
				let stripPrefix;
				let rootPath;
				let listFiles;
				let continueNotFound;
				let responseHeaders = makeHeaders(ws.ResponseHeaders || {});
				const get2 = /* @__PURE__ */ __name(() => {
					return {
						StripPrefix: stripPrefix.value,
						Root: rootPath.value,
						ListFiles: listFiles.checked,
						ContinueNotFound: continueNotFound.checked,
						ResponseHeaders: responseHeaders.get()
					};
				}, "get");
				const root2 = dom.table(dom.tr(dom.td("Type"), dom.td("StripPrefix", attr.title("Path to strip from the request URL before evaluating to a local path. If the requested URL path does not start with this prefix and ContinueNotFound it is considered non-matching and next WebHandlers are tried. If ContinueNotFound is not set, a file not found (404) is returned in that case.")), dom.td("Root", attr.title("Directory to serve files from for this handler. Keep in mind that relative paths are relative to the working directory of mox.")), dom.td("ListFiles", attr.title("If set, and a directory is requested, and no index.html is present that can be served, a file listing is returned. Results in 403 if ListFiles is not set. If a directory is requested and the URL does not end with a slash, the response is a redirect to the path with trailing slash.")), dom.td("ContinueNotFound", attr.title("If a requested URL does not exist, don't return a file not found (404) response, but consider this handler non-matching and continue attempts to serve with later WebHandlers, which may be a reverse proxy generating dynamic content, possibly even writing a static file for a next request to serve statically. If ContinueNotFound is set, HTTP requests other than GET and HEAD do not match. This mechanism can be used to implement the equivalent of 'try_files' in other webservers.")), dom.td(dom.span("Response headers", attr.title("Headers to add to the response. Useful for cache-control, content-type, etc. By default, Content-Type headers are automatically added for recognized file types, unless added explicitly through this setting. For directory listings, a content-type header is skipped.")), " ", responseHeaders.add)), dom.tr(dom.td(dom.select(attr.required(""), dom.option("Static", attr.selected("")), dom.option("Redirect"), dom.option("Forward"), dom.option("Internal"), /* @__PURE__ */ __name(function change(e) {
					makeType(e.target.value);
				}, "change"))), dom.td(stripPrefix = dom.input(attr.value(ws.StripPrefix || ""))), dom.td(rootPath = dom.input(attr.required(""), attr.placeholder("web/..."), attr.value(ws.Root || ""))), dom.td(listFiles = dom.input(attr.type("checkbox"), ws.ListFiles ? attr.checked("") : [])), dom.td(continueNotFound = dom.input(attr.type("checkbox"), ws.ContinueNotFound ? attr.checked("") : [])), dom.td(responseHeaders)));
				view = { root: root2, get: get2 };
				return view;
			}, "makeWebStatic");
			const makeWebRedirect = /* @__PURE__ */ __name((wr) => {
				let view;
				let baseURL;
				let origPathRegexp;
				let replacePath;
				let statusCode;
				const get2 = /* @__PURE__ */ __name(() => {
					return {
						BaseURL: baseURL.value,
						OrigPathRegexp: origPathRegexp.value,
						ReplacePath: replacePath.value,
						StatusCode: statusCode.value ? parseInt(statusCode.value) : 0
					};
				}, "get");
				const root2 = dom.table(dom.tr(dom.td("Type"), dom.td("BaseURL", attr.title("Base URL to redirect to. The path must be empty and will be replaced, either by the request URL path, or by OrigPathRegexp/ReplacePath. Scheme, host, port and fragment stay intact, and query strings are combined. If empty, the response redirects to a different path through OrigPathRegexp and ReplacePath, which must then be set. Use a URL without scheme to redirect without changing the protocol, e.g. //newdomain/. If a redirect would send a request to a URL with the same scheme, host and path, the WebRedirect does not match so a next WebHandler can be tried. This can be used to redirect all plain http traffic to https.")), dom.td("OrigPathRegexp", attr.title("Regular expression for matching path. If set and path does not match, a 404 is returned. The HTTP path used for matching always starts with a slash.")), dom.td("ReplacePath", attr.title("Replacement path for destination URL based on OrigPathRegexp. Implemented with Go's Regexp.ReplaceAllString: $1 is replaced with the text of the first submatch, etc. If both OrigPathRegexp and ReplacePath are empty, BaseURL must be set and all paths are redirected unaltered.")), dom.td("StatusCode", attr.title("Status code to use in redirect, e.g. 307. By default, a permanent redirect (308) is returned."))), dom.tr(dom.td(dom.select(attr.required(""), dom.option("Static"), dom.option("Redirect", attr.selected("")), dom.option("Forward"), dom.option("Internal"), /* @__PURE__ */ __name(function change(e) {
					makeType(e.target.value);
				}, "change"))), dom.td(baseURL = dom.input(attr.placeholder("empty or https://target/path?q=1#frag or //target/..."), attr.value(wr.BaseURL || ""))), dom.td(origPathRegexp = dom.input(attr.placeholder("^/old/(.*)"), attr.value(wr.OrigPathRegexp || ""))), dom.td(replacePath = dom.input(attr.placeholder("/new/$1"), attr.value(wr.ReplacePath || ""))), dom.td(statusCode = dom.input(style({ width: "4em" }), attr.type("number"), attr.value(wr.StatusCode ? "" + wr.StatusCode : ""), attr.min("300"), attr.max("399")))));
				view = { root: root2, get: get2 };
				return view;
			}, "makeWebRedirect");
			const makeWebForward = /* @__PURE__ */ __name((wf) => {
				let view;
				let stripPath;
				let url;
				let responseHeaders = makeHeaders(wf.ResponseHeaders || {});
				const get2 = /* @__PURE__ */ __name(() => {
					return {
						StripPath: stripPath.checked,
						URL: url.value,
						ResponseHeaders: responseHeaders.get()
					};
				}, "get");
				const root2 = dom.table(dom.tr(dom.td("Type"), dom.td("StripPath", attr.title("Strip the matching WebHandler path from the WebHandler before forwarding the request.")), dom.td("URL", attr.title("URL to forward HTTP requests to, e.g. http://127.0.0.1:8123/base. If StripPath is false the full request path is added to the URL. Host headers are sent unmodified. New X-Forwarded-{For,Host,Proto} headers are set. Any query string in the URL is ignored. Requests are made using Go's net/http.DefaultTransport that takes environment variables HTTP_PROXY and HTTPS_PROXY into account. Websocket connections are forwarded and data is copied between client and backend without looking at the framing. The websocket 'version' and 'key'/'accept' headers are verified during the handshake, but other websocket headers, including 'origin', 'protocol' and 'extensions' headers, are not inspected and the backend is responsible for verifying/interpreting them.")), dom.td(dom.span("Response headers", attr.title("Headers to add to the response. Useful for adding security- and cache-related headers.")), " ", responseHeaders.add)), dom.tr(dom.td(dom.select(attr.required(""), dom.option("Static"), dom.option("Redirect"), dom.option("Forward", attr.selected("")), dom.option("Internal"), /* @__PURE__ */ __name(function change(e) {
					makeType(e.target.value);
				}, "change"))), dom.td(stripPath = dom.input(attr.type("checkbox"), wf.StripPath || wf.StripPath === void 0 ? attr.checked("") : [])), dom.td(url = dom.input(attr.required(""), attr.placeholder("http://127.0.0.1:8888"), attr.value(wf.URL || ""))), dom.td(responseHeaders)));
				view = { root: root2, get: get2 };
				return view;
			}, "makeWebForward");
			const makeWebInternal = /* @__PURE__ */ __name((wi) => {
				let view;
				let basePath;
				let service;
				const get2 = /* @__PURE__ */ __name(() => {
					return {
						BasePath: basePath.value,
						Service: service.value
					};
				}, "get");
				const root2 = dom.table(dom.tr(dom.td("Type"), dom.td("Base path", attr.title("Path to use as root of internal service, e.g. /webmail/.")), dom.td("Service")), dom.tr(dom.td(dom.select(attr.required(""), dom.option("Static"), dom.option("Redirect"), dom.option("Forward"), dom.option("Internal", attr.selected("")), /* @__PURE__ */ __name(function change(e) {
					makeType(e.target.value);
				}, "change"))), dom.td(basePath = dom.input(attr.value(wi.BasePath), attr.required(""), attr.placeholder("/.../"))), dom.td(service = dom.select(dom.option("Admin", attr.value("admin")), dom.option("Account", attr.value("account")), dom.option("Webmail", attr.value("webmail")), dom.option("Webapi", attr.value("webapi")), prop({ value: wi.Service })))));
				view = { root: root2, get: get2 };
				return view;
			}, "makeWebInternal");
			let logName;
			let domain2;
			let pathRegexp;
			let toHTTPS;
			let compress;
			let details;
			const detailsRoot = /* @__PURE__ */ __name((root2) => {
				details.replaceWith(root2);
				details = root2;
			}, "detailsRoot");
			const makeType = /* @__PURE__ */ __name((s) => {
				if (s === "Static") {
					staticView = makeWebStatic(wh.WebStatic || {
						StripPrefix: "",
						Root: "",
						ListFiles: false,
						ContinueNotFound: false,
						ResponseHeaders: {}
					});
					detailsRoot(staticView.root);
				} else if (s === "Redirect") {
					redirectView = makeWebRedirect(wh.WebRedirect || {
						BaseURL: "",
						OrigPathRegexp: "",
						ReplacePath: "",
						StatusCode: 0
					});
					detailsRoot(redirectView.root);
				} else if (s === "Forward") {
					forwardView = makeWebForward(wh.WebForward || {
						StripPath: false,
						URL: "",
						ResponseHeaders: {}
					});
					detailsRoot(forwardView.root);
				} else if (s === "Internal") {
					internalView = makeWebInternal(wh.WebInternal || {
						BasePath: "",
						Service: "admin"
					});
					detailsRoot(internalView.root);
				} else {
					throw new Error("unknown handler type");
				}
				handlerType = s;
			}, "makeType");
			const moveHandler = /* @__PURE__ */ __name((row2, oindex, nindex) => {
				row2.root.remove();
				handlersTbody.insertBefore(row2.root, handlersTbody.children[nindex]);
				handlerRows.splice(oindex, 1);
				handlerRows.splice(nindex, 0, row2);
			}, "moveHandler");
			const root = dom.tr(dom.td(
				dom.table(dom.tr(dom.td("LogName", attr.title("Name used during logging for requests matching this handler. If empty, the index of the handler in the list is used.")), dom.td("Domain", attr.title("Request must be for this domain to match this handler.")), dom.td("Path Regexp", attr.title("Request must match this path regular expression to match this handler. Must start with with a ^.")), dom.td("To HTTPS", attr.title("Redirect plain HTTP (non-TLS) requests to HTTPS.")), dom.td("Compress", attr.title("Transparently compress responses (currently with gzip) if the client supports it, the status is 200 OK, no Content-Encoding is set on the response yet and the Content-Type of the response hints that the data is compressible (text/..., specific application/... and .../...+json and .../...+xml). For static files only, a cache with compressed files is kept."))), dom.tr(dom.td(logName = dom.input(attr.value(wh.LogName || ""))), dom.td(domain2 = dom.input(attr.required(""), attr.placeholder("example.org"), attr.value(domainName(wh.DNSDomain)))), dom.td(pathRegexp = dom.input(attr.required(""), attr.placeholder("^/"), attr.value(wh.PathRegexp || ""))), dom.td(toHTTPS = dom.input(attr.type("checkbox"), attr.title("Redirect plain HTTP (non-TLS) requests to HTTPS"), !wh.DontRedirectPlainHTTP ? attr.checked("") : [])), dom.td(compress = dom.input(attr.type("checkbox"), attr.title("Transparently compress responses."), wh.Compress ? attr.checked("") : [])))),
				// Replaced with a call to makeType, below (and later when switching types).
				details = dom.table()
			), dom.td(dom.td(
				dom.clickbutton("Remove", /* @__PURE__ */ __name(function click() {
					handlerRows = handlerRows.filter((r) => r !== row);
					row.root.remove();
					nohandler.style.display = handlerRows.length ? "none" : "";
				}, "click")),
				" ",
				// We show/hide the buttons to move when clicking the Move button.
				moveButtons = dom.span(style({ display: moveButtonsVisible ? "" : "none" }), dom.clickbutton("\u2191\u2191", attr.title("Move to top."), /* @__PURE__ */ __name(function click() {
					const index2 = handlerRows.findIndex((r) => r === row);
					if (index2 > 0) {
						moveHandler(row, index2, 0);
					}
				}, "click")), " ", dom.clickbutton("\u2191", attr.title("Move one up."), /* @__PURE__ */ __name(function click() {
					const index2 = handlerRows.findIndex((r) => r === row);
					if (index2 > 0) {
						moveHandler(row, index2, index2 - 1);
					}
				}, "click")), " ", dom.clickbutton("\u2193", attr.title("Move one down."), /* @__PURE__ */ __name(function click() {
					const index2 = handlerRows.findIndex((r) => r === row);
					if (index2 + 1 < handlerRows.length) {
						moveHandler(row, index2, index2 + 1);
					}
				}, "click")), " ", dom.clickbutton("\u2193\u2193", attr.title("Move to bottom."), /* @__PURE__ */ __name(function click() {
					const index2 = handlerRows.findIndex((r) => r === row);
					if (index2 + 1 < handlerRows.length) {
						moveHandler(row, index2, handlerRows.length - 1);
					}
				}, "click")))
			)));
			const get = /* @__PURE__ */ __name(() => {
				const wh2 = {
					LogName: logName.value,
					Domain: domain2.value,
					PathRegexp: pathRegexp.value,
					DontRedirectPlainHTTP: !toHTTPS.checked,
					Compress: compress.checked,
					Name: "",
					DNSDomain: { ASCII: "", Unicode: "" }
				};
				if (handlerType === "Static" && staticView != null) {
					wh2.WebStatic = staticView.get();
				} else if (handlerType === "Redirect" && redirectView !== null) {
					wh2.WebRedirect = redirectView.get();
				} else if (handlerType === "Forward" && forwardView !== null) {
					wh2.WebForward = forwardView.get();
				} else if (handlerType === "Internal" && internalView !== null) {
					wh2.WebInternal = internalView.get();
				} else {
					throw new Error("unknown WebHandler type");
				}
				return wh2;
			}, "get");
			if (wh.WebStatic) {
				handlerType = "Static";
			} else if (wh.WebRedirect) {
				handlerType = "Redirect";
			} else if (wh.WebForward) {
				handlerType = "Forward";
			} else if (wh.WebInternal) {
				handlerType = "Internal";
			} else {
				throw new Error("unknown WebHandler type");
			}
			makeType(handlerType);
			row = { root, moveButtons, get };
			handlerRows.push(row);
			return row;
		}, "handlerRow");
		const gatherConf = /* @__PURE__ */ __name(() => {
			return {
				WebDomainRedirects: redirectRows.map((row) => row.get()),
				WebHandlers: handlerRows.map((row) => row.get())
			};
		}, "gatherConf");
		const handlerActions = /* @__PURE__ */ __name(() => {
			return [
				"Action ",
				dom.clickbutton("Add", /* @__PURE__ */ __name(function click() {
					const nwh = {
						LogName: "",
						Domain: "",
						PathRegexp: "^/",
						DontRedirectPlainHTTP: false,
						Compress: false,
						WebForward: {
							StripPath: true,
							URL: ""
						},
						Name: "",
						DNSDomain: { ASCII: "", Unicode: "" }
					};
					const row = handlerRow(nwh);
					handlersTbody.appendChild(row.root);
					nohandler.style.display = handlerRows.length ? "none" : "";
				}, "click")),
				" ",
				dom.clickbutton("Move", /* @__PURE__ */ __name(function click() {
					moveButtonsVisible = !moveButtonsVisible;
					for (const row of handlerRows) {
						row.moveButtons.style.display = moveButtonsVisible ? "" : "none";
					}
				}, "click"))
			];
		}, "handlerActions");
		return dom.div(crumbs(crumblink("Mox Admin", "#"), "Webserver config"), dom.form(fieldset = dom.fieldset(dom.h2("Domain redirects", attr.title("Corresponds with WebDomainRedirects in domains.conf")), dom.p("Incoming requests for these domains are redirected to the target domain, with HTTPS."), dom.table(dom.thead(dom.tr(dom.th("From"), dom.th("To"), dom.th("Action ", dom.clickbutton("Add", /* @__PURE__ */ __name(function click() {
			const row = redirectRow([{ ASCII: "", Unicode: "" }, { ASCII: "", Unicode: "" }]);
			redirectsTbody.appendChild(row.root);
			noredirect.style.display = redirectRows.length ? "none" : "";
		}, "click"))))), redirectsTbody = dom.tbody((conf.WebDNSDomainRedirects || []).sort().map((t) => redirectRow([t[0], t[1]])), noredirect = dom.tr(style({ display: redirectRows.length ? "none" : "" }), dom.td(attr.colspan("3"), "No redirects.")))), dom.br(), dom.h2("Handlers", attr.title("Corresponds with WebHandlers in domains.conf")), dom.p("Each incoming request is matched against the configured handlers, in order. The first matching handler serves the request. System handlers such as for ACME validation, MTA-STS and autoconfig, come first. Then these webserver handlers. Finally the internal service handlers for admin, account, webmail and webapi configured in mox.conf. Don't forget to save after making a change."), dom.table(dom._class("long"), dom.thead(dom.tr(dom.th(), dom.th(handlerActions()))), handlersTbody = dom.tbody((conf.WebHandlers || []).map((wh) => handlerRow(wh)), nohandler = dom.tr(style({ display: handlerRows.length ? "none" : "" }), dom.td(attr.colspan("2"), "No handlers."))), dom.tfoot(dom.tr(dom.th(), dom.th(handlerActions())))), dom.br(), dom.submitbutton("Save", attr.title("Save config. If the configuration has changed since this page was loaded, an error will be returned. After saving, the changes take effect immediately."))), /* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			conf = await check(fieldset, client.WebserverConfigSave(conf, gatherConf()));
		}, "submit")));
	}, "webserver");
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
				if (h == "") {
					root = await index();
				} else if (h === "config") {
					root = await config();
				} else if (h === "loglevels") {
					root = await loglevels();
				} else if (h === "accounts") {
					root = await accounts();
				} else if (h === "accounts/loginattempts") {
					root = await loginattempts();
				} else if (t[0] === "accounts" && t.length === 3 && t[1] === "l") {
					root = await account(t[2]);
				} else if (t[0] === "accounts" && t.length === 4 && t[1] === "l" && t[3] === "loginattempts") {
					root = await accountloginattempts(t[2]);
				} else if (t[0] === "domains" && t.length === 2) {
					root = await domain(t[1]);
				} else if (t[0] === "domains" && t.length === 4 && t[2] === "alias") {
					root = await domainAlias(t[1], t[3]);
				} else if (t[0] === "domains" && t.length === 3 && t[2] === "dmarc") {
					root = await domainDMARC(t[1]);
				} else if (t[0] === "domains" && t.length === 4 && t[2] === "dmarc" && parseInt(t[3])) {
					root = await domainDMARCReport(t[1], parseInt(t[3]));
				} else if (t[0] === "domains" && t.length === 3 && t[2] === "dnscheck") {
					root = await domainDNSCheck(t[1]);
				} else if (t[0] === "domains" && t.length === 3 && t[2] === "dnsrecords") {
					root = await domainDNSRecords(t[1]);
				} else if (h === "queue") {
					root = await queueList();
				} else if (h === "queue/retired") {
					root = await retiredList();
				} else if (h === "webhookqueue") {
					root = await hooksList();
				} else if (h === "webhookqueue/retired") {
					root = await hooksRetiredList();
				} else if (h === "tlsrpt") {
					root = await tlsrptIndex();
				} else if (h === "tlsrpt/reports") {
					root = await tlsrptReports();
				} else if (t[0] === "tlsrpt" && t[1] === "reports" && t.length === 3) {
					root = await domainTLSRPT(t[2]);
				} else if (t[0] === "tlsrpt" && t[1] === "reports" && t.length === 4 && parseInt(t[3])) {
					root = await domainTLSRPTID(t[2], parseInt(t[3]));
				} else if (h === "tlsrpt/results") {
					root = await tlsrptResults();
				} else if (t[0] == "tlsrpt" && t[1] == "results" && (t[2] === "rcptdom" || t[2] == "host") && t.length === 4) {
					root = await tlsrptResultsPolicyDomain(t[2] === "rcptdom", t[3]);
				} else if (h === "dmarc") {
					root = await dmarcIndex();
				} else if (h === "dmarc/reports") {
					root = await dmarcReports();
				} else if (h === "dmarc/evaluations") {
					root = await dmarcEvaluations();
				} else if (t[0] == "dmarc" && t[1] == "evaluations" && t.length === 3) {
					root = await dmarcEvaluationsDomain(t[2]);
				} else if (h === "mtasts") {
					root = await mtasts();
				} else if (h === "dnsbl") {
					root = await dnsbl();
				} else if (h === "routes") {
					root = await globalRoutes();
				} else if (h === "webserver") {
					root = await webserver();
				} else {
					root = dom.div("page not found");
				}
				if (window.moxBeforeDisplay) {
					moxBeforeDisplay(root);
				}
				dom._kids(page, root);
			} catch (err) {
				console.log("error", err);
				window.alert("Error: " + errmsg(err));
				curhash = window.location.hash;
				return;
			}
			curhash = window.location.hash;
			page.classList.remove("loading");
		}, "hashChange");
		window.addEventListener("hashchange", hashChange);
		hashChange();
	}, "init");
	window.addEventListener("load", init);
})();
