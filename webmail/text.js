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

	// .js/webmail/api.js
	var Validation;
	(function(Validation2) {
		Validation2[Validation2["ValidationUnknown"] = 0] = "ValidationUnknown";
		Validation2[Validation2["ValidationStrict"] = 1] = "ValidationStrict";
		Validation2[Validation2["ValidationDMARC"] = 2] = "ValidationDMARC";
		Validation2[Validation2["ValidationRelaxed"] = 3] = "ValidationRelaxed";
		Validation2[Validation2["ValidationPass"] = 4] = "ValidationPass";
		Validation2[Validation2["ValidationNeutral"] = 5] = "ValidationNeutral";
		Validation2[Validation2["ValidationTemperror"] = 6] = "ValidationTemperror";
		Validation2[Validation2["ValidationPermerror"] = 7] = "ValidationPermerror";
		Validation2[Validation2["ValidationFail"] = 8] = "ValidationFail";
		Validation2[Validation2["ValidationSoftfail"] = 9] = "ValidationSoftfail";
		Validation2[Validation2["ValidationNone"] = 10] = "ValidationNone";
	})(Validation || (Validation = {}));
	var ThreadMode;
	(function(ThreadMode2) {
		ThreadMode2["ThreadOff"] = "off";
		ThreadMode2["ThreadOn"] = "on";
		ThreadMode2["ThreadUnread"] = "unread";
	})(ThreadMode || (ThreadMode = {}));
	var AttachmentType;
	(function(AttachmentType2) {
		AttachmentType2["AttachmentIndifferent"] = "";
		AttachmentType2["AttachmentNone"] = "none";
		AttachmentType2["AttachmentAny"] = "any";
		AttachmentType2["AttachmentImage"] = "image";
		AttachmentType2["AttachmentPDF"] = "pdf";
		AttachmentType2["AttachmentArchive"] = "archive";
		AttachmentType2["AttachmentSpreadsheet"] = "spreadsheet";
		AttachmentType2["AttachmentDocument"] = "document";
		AttachmentType2["AttachmentPresentation"] = "presentation";
	})(AttachmentType || (AttachmentType = {}));
	var ViewMode;
	(function(ViewMode2) {
		ViewMode2["ModeText"] = "text";
		ViewMode2["ModeHTML"] = "html";
		ViewMode2["ModeHTMLExt"] = "htmlext";
	})(ViewMode || (ViewMode = {}));
	var SecurityResult;
	(function(SecurityResult2) {
		SecurityResult2["SecurityResultError"] = "error";
		SecurityResult2["SecurityResultNo"] = "no";
		SecurityResult2["SecurityResultYes"] = "yes";
		SecurityResult2["SecurityResultUnknown"] = "unknown";
	})(SecurityResult || (SecurityResult = {}));
	var Quoting;
	(function(Quoting2) {
		Quoting2["Default"] = "";
		Quoting2["Bottom"] = "bottom";
		Quoting2["Top"] = "top";
	})(Quoting || (Quoting = {}));
	var structTypes = { "Address": true, "Attachment": true, "ChangeMailboxAdd": true, "ChangeMailboxCounts": true, "ChangeMailboxKeywords": true, "ChangeMailboxRemove": true, "ChangeMailboxRename": true, "ChangeMailboxSpecialUse": true, "ChangeMsgAdd": true, "ChangeMsgFlags": true, "ChangeMsgRemove": true, "ChangeMsgThread": true, "ComposeMessage": true, "Domain": true, "DomainAddressConfig": true, "Envelope": true, "EventStart": true, "EventViewChanges": true, "EventViewErr": true, "EventViewMsgs": true, "EventViewReset": true, "File": true, "Filter": true, "Flags": true, "ForwardAttachments": true, "FromAddressSettings": true, "Mailbox": true, "Message": true, "MessageAddress": true, "MessageEnvelope": true, "MessageItem": true, "NotFilter": true, "Page": true, "ParsedMessage": true, "Part": true, "Query": true, "RecipientSecurity": true, "Request": true, "Ruleset": true, "Settings": true, "SpecialUse": true, "SubmitMessage": true };
	var stringsTypes = { "AttachmentType": true, "CSRFToken": true, "Localpart": true, "Quoting": true, "SecurityResult": true, "ThreadMode": true, "ViewMode": true };
	var intsTypes = { "ModSeq": true, "UID": true, "Validation": true };
	var types = {
		"Request": { "Name": "Request", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "SSEID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Cancel", "Docs": "", "Typewords": ["bool"] }, { "Name": "Query", "Docs": "", "Typewords": ["Query"] }, { "Name": "Page", "Docs": "", "Typewords": ["Page"] }] },
		"Query": { "Name": "Query", "Docs": "", "Fields": [{ "Name": "OrderAsc", "Docs": "", "Typewords": ["bool"] }, { "Name": "Threading", "Docs": "", "Typewords": ["ThreadMode"] }, { "Name": "Filter", "Docs": "", "Typewords": ["Filter"] }, { "Name": "NotFilter", "Docs": "", "Typewords": ["NotFilter"] }] },
		"Filter": { "Name": "Filter", "Docs": "", "Fields": [{ "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxChildrenIncluded", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Words", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Oldest", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Newest", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["AttachmentType"] }, { "Name": "Labels", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Headers", "Docs": "", "Typewords": ["[]", "[]", "string"] }, { "Name": "SizeMin", "Docs": "", "Typewords": ["int64"] }, { "Name": "SizeMax", "Docs": "", "Typewords": ["int64"] }] },
		"NotFilter": { "Name": "NotFilter", "Docs": "", "Fields": [{ "Name": "Words", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["AttachmentType"] }, { "Name": "Labels", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Page": { "Name": "Page", "Docs": "", "Fields": [{ "Name": "AnchorMessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Count", "Docs": "", "Typewords": ["int32"] }, { "Name": "DestMessageID", "Docs": "", "Typewords": ["int64"] }] },
		"MessageItem": { "Name": "MessageItem", "Docs": "", "Fields": [{ "Name": "Message", "Docs": "", "Typewords": ["Message"] }, { "Name": "Envelope", "Docs": "", "Typewords": ["MessageEnvelope"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["[]", "Attachment"] }, { "Name": "IsSigned", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsEncrypted", "Docs": "", "Typewords": ["bool"] }, { "Name": "MatchQuery", "Docs": "", "Typewords": ["bool"] }, { "Name": "MoreHeaders", "Docs": "", "Typewords": ["[]", "[]", "string"] }] },
		"Message": { "Name": "Message", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UID", "Docs": "", "Typewords": ["UID"] }, { "Name": "MailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "CreateSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Expunged", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsReject", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailboxOrigID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MailboxDestinedID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Received", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "SaveDate", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "RemoteIP", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked1", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked2", "Docs": "", "Typewords": ["string"] }, { "Name": "RemoteIPMasked3", "Docs": "", "Typewords": ["string"] }, { "Name": "EHLODomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFrom", "Docs": "", "Typewords": ["string"] }, { "Name": "MailFromLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "MailFromDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "RcptToLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "RcptToDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromLocalpart", "Docs": "", "Typewords": ["Localpart"] }, { "Name": "MsgFromDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromOrgDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "EHLOValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "MailFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "MsgFromValidated", "Docs": "", "Typewords": ["bool"] }, { "Name": "EHLOValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "MailFromValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "MsgFromValidation", "Docs": "", "Typewords": ["Validation"] }, { "Name": "DKIMDomains", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "OrigEHLODomain", "Docs": "", "Typewords": ["string"] }, { "Name": "OrigDKIMDomains", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }, { "Name": "SubjectBase", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageHash", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ThreadID", "Docs": "", "Typewords": ["int64"] }, { "Name": "ThreadParentIDs", "Docs": "", "Typewords": ["[]", "int64"] }, { "Name": "ThreadMissingLink", "Docs": "", "Typewords": ["bool"] }, { "Name": "ThreadMuted", "Docs": "", "Typewords": ["bool"] }, { "Name": "ThreadCollapsed", "Docs": "", "Typewords": ["bool"] }, { "Name": "IsMailingList", "Docs": "", "Typewords": ["bool"] }, { "Name": "DSN", "Docs": "", "Typewords": ["bool"] }, { "Name": "ReceivedTLSVersion", "Docs": "", "Typewords": ["uint16"] }, { "Name": "ReceivedTLSCipherSuite", "Docs": "", "Typewords": ["uint16"] }, { "Name": "ReceivedRequireTLS", "Docs": "", "Typewords": ["bool"] }, { "Name": "Seen", "Docs": "", "Typewords": ["bool"] }, { "Name": "Answered", "Docs": "", "Typewords": ["bool"] }, { "Name": "Flagged", "Docs": "", "Typewords": ["bool"] }, { "Name": "Forwarded", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Notjunk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Phishing", "Docs": "", "Typewords": ["bool"] }, { "Name": "MDNSent", "Docs": "", "Typewords": ["bool"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }, { "Name": "TrainedJunk", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "MsgPrefix", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Preview", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ParsedBuf", "Docs": "", "Typewords": ["nullable", "string"] }] },
		"MessageEnvelope": { "Name": "MessageEnvelope", "Docs": "", "Fields": [{ "Name": "Date", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "Sender", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "CC", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "BCC", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "InReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }] },
		"MessageAddress": { "Name": "MessageAddress", "Docs": "", "Fields": [{ "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "User", "Docs": "", "Typewords": ["string"] }, { "Name": "Domain", "Docs": "", "Typewords": ["Domain"] }] },
		"Domain": { "Name": "Domain", "Docs": "", "Fields": [{ "Name": "ASCII", "Docs": "", "Typewords": ["string"] }, { "Name": "Unicode", "Docs": "", "Typewords": ["string"] }] },
		"Attachment": { "Name": "Attachment", "Docs": "", "Fields": [{ "Name": "Path", "Docs": "", "Typewords": ["[]", "int32"] }, { "Name": "Filename", "Docs": "", "Typewords": ["string"] }, { "Name": "Part", "Docs": "", "Typewords": ["Part"] }] },
		"Part": { "Name": "Part", "Docs": "", "Fields": [{ "Name": "BoundaryOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "HeaderOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "BodyOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "EndOffset", "Docs": "", "Typewords": ["int64"] }, { "Name": "RawLineCount", "Docs": "", "Typewords": ["int64"] }, { "Name": "DecodedSize", "Docs": "", "Typewords": ["int64"] }, { "Name": "MediaType", "Docs": "", "Typewords": ["string"] }, { "Name": "MediaSubType", "Docs": "", "Typewords": ["string"] }, { "Name": "ContentTypeParams", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "ContentID", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentDescription", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentTransferEncoding", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentDisposition", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentMD5", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentLanguage", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "ContentLocation", "Docs": "", "Typewords": ["nullable", "string"] }, { "Name": "Envelope", "Docs": "", "Typewords": ["nullable", "Envelope"] }, { "Name": "Parts", "Docs": "", "Typewords": ["[]", "Part"] }, { "Name": "Message", "Docs": "", "Typewords": ["nullable", "Part"] }] },
		"Envelope": { "Name": "Envelope", "Docs": "", "Fields": [{ "Name": "Date", "Docs": "", "Typewords": ["timestamp"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "From", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "Sender", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "CC", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "BCC", "Docs": "", "Typewords": ["[]", "Address"] }, { "Name": "InReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "MessageID", "Docs": "", "Typewords": ["string"] }] },
		"Address": { "Name": "Address", "Docs": "", "Fields": [{ "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "User", "Docs": "", "Typewords": ["string"] }, { "Name": "Host", "Docs": "", "Typewords": ["string"] }] },
		"ParsedMessage": { "Name": "ParsedMessage", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Part", "Docs": "", "Typewords": ["Part"] }, { "Name": "Headers", "Docs": "", "Typewords": ["{}", "[]", "string"] }, { "Name": "ViewMode", "Docs": "", "Typewords": ["ViewMode"] }, { "Name": "Texts", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "HasHTML", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListReplyAddress", "Docs": "", "Typewords": ["nullable", "MessageAddress"] }, { "Name": "TextPaths", "Docs": "", "Typewords": ["[]", "[]", "int32"] }, { "Name": "HTMLPath", "Docs": "", "Typewords": ["[]", "int32"] }] },
		"FromAddressSettings": { "Name": "FromAddressSettings", "Docs": "", "Fields": [{ "Name": "FromAddress", "Docs": "", "Typewords": ["string"] }, { "Name": "ViewMode", "Docs": "", "Typewords": ["ViewMode"] }] },
		"ComposeMessage": { "Name": "ComposeMessage", "Docs": "", "Fields": [{ "Name": "From", "Docs": "", "Typewords": ["string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Cc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Bcc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "TextBody", "Docs": "", "Typewords": ["string"] }, { "Name": "ResponseMessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "DraftMessageID", "Docs": "", "Typewords": ["int64"] }] },
		"SubmitMessage": { "Name": "SubmitMessage", "Docs": "", "Fields": [{ "Name": "From", "Docs": "", "Typewords": ["string"] }, { "Name": "To", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Cc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "Bcc", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "ReplyTo", "Docs": "", "Typewords": ["string"] }, { "Name": "Subject", "Docs": "", "Typewords": ["string"] }, { "Name": "TextBody", "Docs": "", "Typewords": ["string"] }, { "Name": "Attachments", "Docs": "", "Typewords": ["[]", "File"] }, { "Name": "ForwardAttachments", "Docs": "", "Typewords": ["ForwardAttachments"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "ResponseMessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "UserAgent", "Docs": "", "Typewords": ["string"] }, { "Name": "RequireTLS", "Docs": "", "Typewords": ["nullable", "bool"] }, { "Name": "FutureRelease", "Docs": "", "Typewords": ["nullable", "timestamp"] }, { "Name": "ArchiveThread", "Docs": "", "Typewords": ["bool"] }, { "Name": "ArchiveReferenceMailboxID", "Docs": "", "Typewords": ["int64"] }, { "Name": "DraftMessageID", "Docs": "", "Typewords": ["int64"] }] },
		"File": { "Name": "File", "Docs": "", "Fields": [{ "Name": "Filename", "Docs": "", "Typewords": ["string"] }, { "Name": "DataURI", "Docs": "", "Typewords": ["string"] }] },
		"ForwardAttachments": { "Name": "ForwardAttachments", "Docs": "", "Fields": [{ "Name": "MessageID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Paths", "Docs": "", "Typewords": ["[]", "[]", "int32"] }] },
		"Mailbox": { "Name": "Mailbox", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["int64"] }, { "Name": "CreateSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "ModSeq", "Docs": "", "Typewords": ["ModSeq"] }, { "Name": "Expunged", "Docs": "", "Typewords": ["bool"] }, { "Name": "ParentID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Name", "Docs": "", "Typewords": ["string"] }, { "Name": "UIDValidity", "Docs": "", "Typewords": ["uint32"] }, { "Name": "UIDNext", "Docs": "", "Typewords": ["UID"] }, { "Name": "Archive", "Docs": "", "Typewords": ["bool"] }, { "Name": "Draft", "Docs": "", "Typewords": ["bool"] }, { "Name": "Junk", "Docs": "", "Typewords": ["bool"] }, { "Name": "Sent", "Docs": "", "Typewords": ["bool"] }, { "Name": "Trash", "Docs": "", "Typewords": ["bool"] }, { "Name": "Keywords", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "HaveCounts", "Docs": "", "Typewords": ["bool"] }, { "Name": "Total", "Docs": "", "Typewords": ["int64"] }, { "Name": "Deleted", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unread", "Docs": "", "Typewords": ["int64"] }, { "Name": "Unseen", "Docs": "", "Typewords": ["int64"] }, { "Name": "Size", "Docs": "", "Typewords": ["int64"] }] },
		"RecipientSecurity": { "Name": "RecipientSecurity", "Docs": "", "Fields": [{ "Name": "STARTTLS", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "MTASTS", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "DNSSEC", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "DANE", "Docs": "", "Typewords": ["SecurityResult"] }, { "Name": "RequireTLS", "Docs": "", "Typewords": ["SecurityResult"] }] },
		"Settings": { "Name": "Settings", "Docs": "", "Fields": [{ "Name": "ID", "Docs": "", "Typewords": ["uint8"] }, { "Name": "Signature", "Docs": "", "Typewords": ["string"] }, { "Name": "Quoting", "Docs": "", "Typewords": ["Quoting"] }, { "Name": "ShowAddressSecurity", "Docs": "", "Typewords": ["bool"] }, { "Name": "ShowHTML", "Docs": "", "Typewords": ["bool"] }, { "Name": "NoShowShortcuts", "Docs": "", "Typewords": ["bool"] }, { "Name": "ShowHeaders", "Docs": "", "Typewords": ["[]", "string"] }] },
		"Ruleset": { "Name": "Ruleset", "Docs": "", "Fields": [{ "Name": "SMTPMailFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "MsgFromRegexp", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "HeadersRegexp", "Docs": "", "Typewords": ["{}", "string"] }, { "Name": "IsForward", "Docs": "", "Typewords": ["bool"] }, { "Name": "ListAllowDomain", "Docs": "", "Typewords": ["string"] }, { "Name": "AcceptRejectsToMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Comment", "Docs": "", "Typewords": ["string"] }, { "Name": "VerifiedDNSDomain", "Docs": "", "Typewords": ["Domain"] }, { "Name": "ListAllowDNSDomain", "Docs": "", "Typewords": ["Domain"] }] },
		"EventStart": { "Name": "EventStart", "Docs": "", "Fields": [{ "Name": "SSEID", "Docs": "", "Typewords": ["int64"] }, { "Name": "LoginAddress", "Docs": "", "Typewords": ["MessageAddress"] }, { "Name": "Addresses", "Docs": "", "Typewords": ["[]", "MessageAddress"] }, { "Name": "DomainAddressConfigs", "Docs": "", "Typewords": ["{}", "DomainAddressConfig"] }, { "Name": "MailboxName", "Docs": "", "Typewords": ["string"] }, { "Name": "Mailboxes", "Docs": "", "Typewords": ["[]", "Mailbox"] }, { "Name": "Introbox", "Docs": "", "Typewords": ["string"] }, { "Name": "RejectsMailbox", "Docs": "", "Typewords": ["string"] }, { "Name": "Settings", "Docs": "", "Typewords": ["Settings"] }, { "Name": "AccountPath", "Docs": "", "Typewords": ["string"] }, { "Name": "Version", "Docs": "", "Typewords": ["string"] }] },
		"DomainAddressConfig": { "Name": "DomainAddressConfig", "Docs": "", "Fields": [{ "Name": "LocalpartCatchallSeparators", "Docs": "", "Typewords": ["[]", "string"] }, { "Name": "LocalpartCaseSensitive", "Docs": "", "Typewords": ["bool"] }] },
		"EventViewErr": { "Name": "EventViewErr", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }, { "Name": "Err", "Docs": "", "Typewords": ["string"] }] },
		"EventViewReset": { "Name": "EventViewReset", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }] },
		"EventViewMsgs": { "Name": "EventViewMsgs", "Docs": "", "Fields": [{ "Name": "ViewID", "Docs": "", "Typewords": ["int64"] }, { "Name": "RequestID", "Docs": "", "Typewords": ["int64"] }, { "Name": "MessageItems", "Docs": "", "Typewords": ["[]", "[]", "MessageItem"] }, { "Name": "ParsedMessage", "Docs": "", "Typewords": ["nullable", "ParsedMessage"] }, { "Name": "ViewEnd", "Docs": "", "Typewords": ["bool"] }] },
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
		"UID": { "Name": "UID", "Docs": "", "Values": null },
		"ModSeq": { "Name": "ModSeq", "Docs": "", "Values": null },
		"Validation": { "Name": "Validation", "Docs": "", "Values": [{ "Name": "ValidationUnknown", "Value": 0, "Docs": "" }, { "Name": "ValidationStrict", "Value": 1, "Docs": "" }, { "Name": "ValidationDMARC", "Value": 2, "Docs": "" }, { "Name": "ValidationRelaxed", "Value": 3, "Docs": "" }, { "Name": "ValidationPass", "Value": 4, "Docs": "" }, { "Name": "ValidationNeutral", "Value": 5, "Docs": "" }, { "Name": "ValidationTemperror", "Value": 6, "Docs": "" }, { "Name": "ValidationPermerror", "Value": 7, "Docs": "" }, { "Name": "ValidationFail", "Value": 8, "Docs": "" }, { "Name": "ValidationSoftfail", "Value": 9, "Docs": "" }, { "Name": "ValidationNone", "Value": 10, "Docs": "" }] },
		"CSRFToken": { "Name": "CSRFToken", "Docs": "", "Values": null },
		"ThreadMode": { "Name": "ThreadMode", "Docs": "", "Values": [{ "Name": "ThreadOff", "Value": "off", "Docs": "" }, { "Name": "ThreadOn", "Value": "on", "Docs": "" }, { "Name": "ThreadUnread", "Value": "unread", "Docs": "" }] },
		"AttachmentType": { "Name": "AttachmentType", "Docs": "", "Values": [{ "Name": "AttachmentIndifferent", "Value": "", "Docs": "" }, { "Name": "AttachmentNone", "Value": "none", "Docs": "" }, { "Name": "AttachmentAny", "Value": "any", "Docs": "" }, { "Name": "AttachmentImage", "Value": "image", "Docs": "" }, { "Name": "AttachmentPDF", "Value": "pdf", "Docs": "" }, { "Name": "AttachmentArchive", "Value": "archive", "Docs": "" }, { "Name": "AttachmentSpreadsheet", "Value": "spreadsheet", "Docs": "" }, { "Name": "AttachmentDocument", "Value": "document", "Docs": "" }, { "Name": "AttachmentPresentation", "Value": "presentation", "Docs": "" }] },
		"Localpart": { "Name": "Localpart", "Docs": "", "Values": null },
		"ViewMode": { "Name": "ViewMode", "Docs": "", "Values": [{ "Name": "ModeText", "Value": "text", "Docs": "" }, { "Name": "ModeHTML", "Value": "html", "Docs": "" }, { "Name": "ModeHTMLExt", "Value": "htmlext", "Docs": "" }] },
		"SecurityResult": { "Name": "SecurityResult", "Docs": "", "Values": [{ "Name": "SecurityResultError", "Value": "error", "Docs": "" }, { "Name": "SecurityResultNo", "Value": "no", "Docs": "" }, { "Name": "SecurityResultYes", "Value": "yes", "Docs": "" }, { "Name": "SecurityResultUnknown", "Value": "unknown", "Docs": "" }] },
		"Quoting": { "Name": "Quoting", "Docs": "", "Values": [{ "Name": "Default", "Value": "", "Docs": "" }, { "Name": "Bottom", "Value": "bottom", "Docs": "" }, { "Name": "Top", "Value": "top", "Docs": "" }] }
	};
	var parser = {
		Request: /* @__PURE__ */ __name((v) => parse("Request", v), "Request"),
		Query: /* @__PURE__ */ __name((v) => parse("Query", v), "Query"),
		Filter: /* @__PURE__ */ __name((v) => parse("Filter", v), "Filter"),
		NotFilter: /* @__PURE__ */ __name((v) => parse("NotFilter", v), "NotFilter"),
		Page: /* @__PURE__ */ __name((v) => parse("Page", v), "Page"),
		MessageItem: /* @__PURE__ */ __name((v) => parse("MessageItem", v), "MessageItem"),
		Message: /* @__PURE__ */ __name((v) => parse("Message", v), "Message"),
		MessageEnvelope: /* @__PURE__ */ __name((v) => parse("MessageEnvelope", v), "MessageEnvelope"),
		MessageAddress: /* @__PURE__ */ __name((v) => parse("MessageAddress", v), "MessageAddress"),
		Domain: /* @__PURE__ */ __name((v) => parse("Domain", v), "Domain"),
		Attachment: /* @__PURE__ */ __name((v) => parse("Attachment", v), "Attachment"),
		Part: /* @__PURE__ */ __name((v) => parse("Part", v), "Part"),
		Envelope: /* @__PURE__ */ __name((v) => parse("Envelope", v), "Envelope"),
		Address: /* @__PURE__ */ __name((v) => parse("Address", v), "Address"),
		ParsedMessage: /* @__PURE__ */ __name((v) => parse("ParsedMessage", v), "ParsedMessage"),
		FromAddressSettings: /* @__PURE__ */ __name((v) => parse("FromAddressSettings", v), "FromAddressSettings"),
		ComposeMessage: /* @__PURE__ */ __name((v) => parse("ComposeMessage", v), "ComposeMessage"),
		SubmitMessage: /* @__PURE__ */ __name((v) => parse("SubmitMessage", v), "SubmitMessage"),
		File: /* @__PURE__ */ __name((v) => parse("File", v), "File"),
		ForwardAttachments: /* @__PURE__ */ __name((v) => parse("ForwardAttachments", v), "ForwardAttachments"),
		Mailbox: /* @__PURE__ */ __name((v) => parse("Mailbox", v), "Mailbox"),
		RecipientSecurity: /* @__PURE__ */ __name((v) => parse("RecipientSecurity", v), "RecipientSecurity"),
		Settings: /* @__PURE__ */ __name((v) => parse("Settings", v), "Settings"),
		Ruleset: /* @__PURE__ */ __name((v) => parse("Ruleset", v), "Ruleset"),
		EventStart: /* @__PURE__ */ __name((v) => parse("EventStart", v), "EventStart"),
		DomainAddressConfig: /* @__PURE__ */ __name((v) => parse("DomainAddressConfig", v), "DomainAddressConfig"),
		EventViewErr: /* @__PURE__ */ __name((v) => parse("EventViewErr", v), "EventViewErr"),
		EventViewReset: /* @__PURE__ */ __name((v) => parse("EventViewReset", v), "EventViewReset"),
		EventViewMsgs: /* @__PURE__ */ __name((v) => parse("EventViewMsgs", v), "EventViewMsgs"),
		EventViewChanges: /* @__PURE__ */ __name((v) => parse("EventViewChanges", v), "EventViewChanges"),
		ChangeMsgAdd: /* @__PURE__ */ __name((v) => parse("ChangeMsgAdd", v), "ChangeMsgAdd"),
		Flags: /* @__PURE__ */ __name((v) => parse("Flags", v), "Flags"),
		ChangeMsgRemove: /* @__PURE__ */ __name((v) => parse("ChangeMsgRemove", v), "ChangeMsgRemove"),
		ChangeMsgFlags: /* @__PURE__ */ __name((v) => parse("ChangeMsgFlags", v), "ChangeMsgFlags"),
		ChangeMsgThread: /* @__PURE__ */ __name((v) => parse("ChangeMsgThread", v), "ChangeMsgThread"),
		ChangeMailboxRemove: /* @__PURE__ */ __name((v) => parse("ChangeMailboxRemove", v), "ChangeMailboxRemove"),
		ChangeMailboxAdd: /* @__PURE__ */ __name((v) => parse("ChangeMailboxAdd", v), "ChangeMailboxAdd"),
		ChangeMailboxRename: /* @__PURE__ */ __name((v) => parse("ChangeMailboxRename", v), "ChangeMailboxRename"),
		ChangeMailboxCounts: /* @__PURE__ */ __name((v) => parse("ChangeMailboxCounts", v), "ChangeMailboxCounts"),
		ChangeMailboxSpecialUse: /* @__PURE__ */ __name((v) => parse("ChangeMailboxSpecialUse", v), "ChangeMailboxSpecialUse"),
		SpecialUse: /* @__PURE__ */ __name((v) => parse("SpecialUse", v), "SpecialUse"),
		ChangeMailboxKeywords: /* @__PURE__ */ __name((v) => parse("ChangeMailboxKeywords", v), "ChangeMailboxKeywords"),
		UID: /* @__PURE__ */ __name((v) => parse("UID", v), "UID"),
		ModSeq: /* @__PURE__ */ __name((v) => parse("ModSeq", v), "ModSeq"),
		Validation: /* @__PURE__ */ __name((v) => parse("Validation", v), "Validation"),
		CSRFToken: /* @__PURE__ */ __name((v) => parse("CSRFToken", v), "CSRFToken"),
		ThreadMode: /* @__PURE__ */ __name((v) => parse("ThreadMode", v), "ThreadMode"),
		AttachmentType: /* @__PURE__ */ __name((v) => parse("AttachmentType", v), "AttachmentType"),
		Localpart: /* @__PURE__ */ __name((v) => parse("Localpart", v), "Localpart"),
		ViewMode: /* @__PURE__ */ __name((v) => parse("ViewMode", v), "ViewMode"),
		SecurityResult: /* @__PURE__ */ __name((v) => parse("SecurityResult", v), "SecurityResult"),
		Quoting: /* @__PURE__ */ __name((v) => parse("Quoting", v), "Quoting")
	};
	var defaultOptions = { slicesNullable: true, mapsNullable: true, nullableOptional: true };
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

	// .js/webmail/lib.js
	var cssStyleDark = dom.style(attr.type("text/css"));
	document.head.prepend(cssStyleDark);
	var styleSheetDark = cssStyleDark.sheet;
	styleSheetDark.insertRule("@media (prefers-color-scheme: dark) {}");
	var darkModeRule = styleSheetDark.cssRules[0];
	var cssStyle = dom.style(attr.type("text/css"));
	document.head.prepend(cssStyle);
	var styleSheet = cssStyle.sheet;
	var cssRules = {};
	var ensureCSS = /* @__PURE__ */ __name((selector, styles2, important) => {
		const checkConsistency = location.hostname === "localhost";
		if (cssRules[selector]) {
			if (checkConsistency) {
				const exp = JSON.stringify(styles2);
				if (cssRules[selector] !== exp) {
					throw new Error("duplicate css rule for selector " + selector + ", had " + cssRules[selector] + ", next " + exp);
				}
			}
			return;
		}
		cssRules[selector] = checkConsistency ? JSON.stringify(styles2) : "x";
		const index = styleSheet.cssRules.length;
		styleSheet.insertRule(selector + " {}", index);
		const st = styleSheet.cssRules[index].style;
		let darkst;
		for (let [k, v] of Object.entries(styles2)) {
			if (!k.startsWith("--")) {
				k = k.replace(/[A-Z]/g, (s) => "-" + s.toLowerCase());
			}
			if (Array.isArray(v)) {
				if (v.length !== 2) {
					throw new Error("2 elements required for light/dark mode style, got " + v.length);
				}
				if (!darkst) {
					const darkIndex = darkModeRule.cssRules.length;
					darkModeRule.insertRule(selector + " {}", darkIndex);
					darkst = darkModeRule.cssRules[darkIndex].style;
				}
				st.setProperty(k, "" + v[0], important ? "important" : "");
				darkst.setProperty(k, "" + v[1], important ? "important" : "");
			} else {
				st.setProperty(k, "" + v, important ? "important" : "");
			}
		}
	}, "ensureCSS");
	var css = /* @__PURE__ */ __name((className, styles2, important) => {
		ensureCSS("." + className, styles2, important);
		return dom._class(className);
	}, "css");
	ensureCSS(":root", {
		"--color": ["black", "#ddd"],
		"--colorMild": ["#555", "#bbb"],
		"--colorMilder": ["#666", "#aaa"],
		"--backgroundColor": ["white", "#222"],
		"--backgroundColorMild": ["#f8f8f8", "#080808"],
		"--backgroundColorMilder": ["#999", "#777"],
		"--borderColor": ["#ccc", "#333"],
		"--mailboxesTopBackgroundColor": ["#fdfdf1", "#1a1200"],
		"--msglistBackgroundColor": ["#f5ffff", "#04130d"],
		"--boxShadow": ["0 0 20px rgba(0, 0, 0, 0.1)", "0px 0px 20px #000"],
		"--buttonBackground": ["#eee", "#222"],
		"--buttonBorderColor": ["#888", "#666"],
		"--buttonHoverBackground": ["#ddd", "#333"],
		"--overlayOpaqueBackgroundColor": ["#eee", "#011"],
		"--overlayBackgroundColor": ["rgba(0, 0, 0, 0.2)", "rgba(0, 0, 0, 0.5)"],
		"--popupColor": ["black", "white"],
		"--popupBackgroundColor": ["white", "#313233"],
		"--popupBorderColor": ["#ccc", "#555"],
		"--highlightBackground": ["gold", "#a70167"],
		"--highlightBorderColor": ["#8c7600", "#fd1fa7"],
		"--highlightBackgroundHover": ["#ffbd21", "#710447"],
		"--mailboxActiveBackground": ["linear-gradient(135deg, #ffc7ab 0%, #ffdeab 100%)", "linear-gradient(135deg, #b63d00 0%, #8c5a0d 100%)"],
		"--mailboxHoverBackgroundColor": ["#eee", "#421f15"],
		"--msgItemActiveBackground": ["linear-gradient(135deg, #8bc8ff 0%, #8ee5ff 100%)", "linear-gradient(135deg, #045cac 0%, #027ba0 100%)"],
		"--msgItemHoverBackgroundColor": ["#eee", "#073348"],
		"--msgItemFocusBorderColor": ["#2685ff", "#2685ff"],
		"--buttonTristateOnBackground": ["#c4ffa9", "#277e00"],
		"--buttonTristateOffBackground": ["#ffb192", "#bf410f"],
		"--warningBackgroundColor": ["#ffca91", "#a85700"],
		"--successBackground": ["#d2f791", "#1fa204"],
		"--emphasisBackground": ["#666", "#aaa"],
		// For authentication/security results.
		"--underlineGreen": "#50c40f",
		"--underlineRed": "#e15d1c",
		"--underlineBlue": "#09f",
		"--underlineGrey": "#888",
		"--quoted1Color": ["#03828f", "#71f2ff"],
		// red
		"--quoted2Color": ["#c7445c", "#ec4c4c"],
		// green
		"--quoted3Color": ["#417c10", "#73e614"],
		// blue
		"--scriptSwitchUnderlineColor": ["#dca053", "#e88f1e"],
		"--linkColor": ["#096bc2", "#63b6ff"],
		"--linkVisitedColor": ["#0704c1", "#c763ff"]
	});
	var styles = {
		color: "var(--color)",
		colorMild: "var(--colorMild)",
		colorMilder: "var(--colorMilder)",
		backgroundColor: "var(--backgroundColor)",
		backgroundColorMild: "var(--backgroundColorMild)",
		backgroundColorMilder: "var(--backgroundColorMilder)",
		borderColor: "var(--borderColor)",
		mailboxesTopBackgroundColor: "var(--mailboxesTopBackgroundColor)",
		msglistBackgroundColor: "var(--msglistBackgroundColor)",
		boxShadow: "var(--boxShadow)",
		buttonBackground: "var(--buttonBackground)",
		buttonBorderColor: "var(--buttonBorderColor)",
		buttonHoverBackground: "var(--buttonHoverBackground)",
		overlayOpaqueBackgroundColor: "var(--overlayOpaqueBackgroundColor)",
		overlayBackgroundColor: "var(--overlayBackgroundColor)",
		popupColor: "var(--popupColor)",
		popupBackgroundColor: "var(--popupBackgroundColor)",
		popupBorderColor: "var(--popupBorderColor)",
		highlightBackground: "var(--highlightBackground)",
		highlightBorderColor: "var(--highlightBorderColor)",
		highlightBackgroundHover: "var(--highlightBackgroundHover)",
		mailboxActiveBackground: "var(--mailboxActiveBackground)",
		mailboxHoverBackgroundColor: "var(--mailboxHoverBackgroundColor)",
		msgItemActiveBackground: "var(--msgItemActiveBackground)",
		msgItemHoverBackgroundColor: "var(--msgItemHoverBackgroundColor)",
		msgItemFocusBorderColor: "var(--msgItemFocusBorderColor)",
		buttonTristateOnBackground: "var(--buttonTristateOnBackground)",
		buttonTristateOffBackground: "var(--buttonTristateOffBackground)",
		warningBackgroundColor: "var(--warningBackgroundColor)",
		successBackground: "var(--successBackground)",
		emphasisBackground: "var(--emphasisBackground)",
		// For authentication/security results.
		underlineGreen: "var(--underlineGreen)",
		underlineRed: "var(--underlineRed)",
		underlineBlue: "var(--underlineBlue)",
		underlineGrey: "var(--underlineGrey)",
		quoted1Color: "var(--quoted1Color)",
		quoted2Color: "var(--quoted2Color)",
		quoted3Color: "var(--quoted3Color)",
		scriptSwitchUnderlineColor: "var(--scriptSwitchUnderlineColor)",
		linkColor: "var(--linkColor)",
		linkVisitedColor: "var(--linkVisitedColor)"
	};
	var styleClasses = {
		// For quoted text, with multiple levels of indentations.
		quoted: [
			css("quoted1", { color: styles.quoted1Color }),
			css("quoted2", { color: styles.quoted2Color }),
			css("quoted3", { color: styles.quoted3Color })
		],
		// When text switches between unicode scripts.
		scriptswitch: css("scriptswitch", { textDecoration: "underline 2px", textDecorationColor: styles.scriptSwitchUnderlineColor }),
		textMild: css("textMild", { color: styles.colorMild }),
		// For keywords (also known as flags/labels/tags) on messages.
		keyword: css("keyword", { padding: "0 .15em", borderRadius: ".15em", fontWeight: "normal", fontSize: ".9em", margin: "0 .15em", whiteSpace: "nowrap", background: styles.highlightBackground, color: styles.color, border: "1px solid", borderColor: styles.highlightBorderColor }),
		msgHeaders: css("msgHeaders", { marginBottom: "1ex", width: "100%" })
	};
	ensureCSS(".msgHeaders td", { wordBreak: "break-word" });
	ensureCSS(".keyword.keywordCollapsed", { opacity: 0.75 }), // Generic styling.
	ensureCSS("html", { backgroundColor: "var(--backgroundColor)", color: "var(--color)" });
	ensureCSS("*", { fontSize: "inherit", fontFamily: "'ubuntu', 'lato', sans-serif", margin: 0, padding: 0, boxSizing: "border-box" });
	ensureCSS(".mono, .mono *", { fontFamily: "'ubuntu mono', monospace" });
	ensureCSS("table td, table th", { padding: ".15em .25em" });
	ensureCSS(".pad", { padding: ".5em" });
	ensureCSS("iframe", { border: 0 });
	ensureCSS("img, embed, video, iframe", { backgroundColor: "white", color: "black" });
	ensureCSS("a", { color: styles.linkColor });
	ensureCSS("a:visited", { color: styles.linkVisitedColor });
	ensureCSS(".textmulti > *:nth-child(even)", { backgroundColor: ["#f4f4f4", "#141414"] });
	ensureCSS(".textmulti > *", {
		padding: "2ex .5em",
		margin: "-.5em"
		/* compensate pad */
	});
	ensureCSS(".textmulti > *:first-child", { padding: ".5em" });
	var imageTypes = [
		"image/avif",
		"image/webp",
		"image/gif",
		"image/png",
		"image/jpeg",
		"image/apng",
		"image/svg+xml"
	];
	var isImage = /* @__PURE__ */ __name((a) => imageTypes.includes((a.Part.MediaType + "/" + a.Part.MediaSubType).toLowerCase()), "isImage");
	var addLinks = /* @__PURE__ */ __name((text) => {
		const re = RegExp("(?:(http|https)://|mailto:)([:%0-9a-zA-Z._~!$&'/()*+,;=-]+@)?([\\[\\]0-9a-zA-Z.-]+)(:[0-9]+)?([:@%0-9a-zA-Z._~!$&'/()*+,;=-]*)(\\?[:@%0-9a-zA-Z._~!$&'/()*+,;=?-]*)?(#[:@%0-9a-zA-Z._~!$&'/()*+,;=?-]*)?");
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
			if (!text || /^[ \t\r\n]/.test(text)) {
				if (/[)>][!,.:;?]$/.test(url)) {
					text = url.substring(url.length - 2) + text;
					url = url.substring(0, url.length - 2);
				} else if (/[)>!,.:;?]$/.test(url)) {
					text = url.substring(url.length - 1) + text;
					url = url.substring(0, url.length - 1);
				}
			}
			r.push(dom.a(url, attr.href(url), url.startsWith("mailto:") ? [] : [attr.target("_blank"), attr.rel("noopener noreferrer")]));
		}
		return r;
	}, "addLinks");
	var renderText = /* @__PURE__ */ __name((text) => {
		return dom.div(text.split("\n").map((line) => {
			let q = 0;
			for (const c of line) {
				if (c == ">") {
					q++;
				} else if (c !== " ") {
					break;
				}
			}
			if (q == 0) {
				return [addLinks(line), "\n"];
			}
			return dom.div(styleClasses.quoted[q % styleClasses.quoted.length], addLinks(line));
		}));
	}, "renderText");

	// .js/webmail/text.js
	var init = /* @__PURE__ */ __name(async () => {
		const pm = parser.ParsedMessage(parsedMessage);
		const mi = parser.MessageItem(messageItem);
		const root = dom.div(dom.div(dom._class("pad", "mono", "textmulti"), css("msgTextPreformatted", { whiteSpace: "pre-wrap" }), (pm.Texts || []).map((t) => renderText(t.replace(/\r\n/g, "\n"))), (mi.Attachments || []).filter((f) => isImage(f)).map((f) => {
			const pathStr = [0].concat(f.Path || []).join(".");
			return dom.div(dom.div(css("msgAttachment", { flexGrow: 1, display: "flex", alignItems: "center", justifyContent: "center", maxHeight: "calc(100% - 50px)" }), dom.img(attr.src("view/" + pathStr), attr.title(f.Filename), css("msgAttachmentImage", { maxWidth: "100%", maxHeight: "100%", boxShadow: styles.boxShadow }))));
		})));
		if (typeof moxBeforeDisplay !== "undefined") {
			moxBeforeDisplay(root);
		}
		dom._kids(document.body, root);
	}, "init");
	init().catch((err) => {
		window.alert("Error: " + (err.message || "(no message)"));
	});
})();
