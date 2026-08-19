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
		// MessageItem returns a MessageItem for a message.
		async MessageItem(msgID) {
			const fn = "MessageItem";
			const paramTypes = [["int64"]];
			const returnTypes = [["MessageItem"]];
			const params = [msgID];
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
		async MessageMove(messageIDs, mailboxID, markSeen) {
			const fn = "MessageMove";
			const paramTypes = [["[]", "int64"], ["int64"], ["bool"]];
			const returnTypes = [];
			const params = [messageIDs, mailboxID, markSeen];
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
		async SettingsSave(settings2) {
			const fn = "SettingsSave";
			const paramTypes = [["Settings"]];
			const returnTypes = [];
			const params = [settings2];
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
			params = params.map((v, index) => verifyArg("params[" + index + "]", v, paramTypes[index], false, false, types, options));
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
						result = result.map((v, index) => verifyArg("result[" + index + "]", v, returnTypes[index], true, true, types, options));
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
	var join = /* @__PURE__ */ __name((l, efn) => {
		const r = [];
		const n = l.length;
		for (let i = 0; i < n; i++) {
			r.push(l[i]);
			if (i < n - 1) {
				r.push(efn());
			}
		}
		return r;
	}, "join");
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
	var displayName = /* @__PURE__ */ __name((s) => {
		const specials = /[()<>\[\]:;@\\,."]/;
		if (specials.test(s)) {
			return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"';
		}
		return s;
	}, "displayName");
	var formatDomain = /* @__PURE__ */ __name((dom2) => dom2.Unicode || dom2.ASCII, "formatDomain");
	var formatAddress = /* @__PURE__ */ __name((a) => {
		let s = "<" + a.User + "@" + formatDomain(a.Domain) + ">";
		if (a.Name) {
			s = displayName(a.Name) + " " + s;
		}
		return s;
	}, "formatAddress");
	var formatAddressElem = /* @__PURE__ */ __name((a) => {
		if (!a.Domain.Unicode) {
			return formatAddress(a);
		}
		return dom.span(a.Name ? [displayName(a.Name), " "] : "", "<", a.User, "@", dom.span(attr.title(a.Domain.ASCII), formatDomain(a.Domain)), ">");
	}, "formatAddressElem");
	var formatAddressValidated = /* @__PURE__ */ __name((a, m, use) => {
		const domainText = /* @__PURE__ */ __name((domstr, ascii) => {
			if (!use) {
				return domstr;
			}
			const extra = domstr === ascii ? "" : "; domain " + ascii;
			let name = "";
			let color = "";
			let title = "";
			switch (m.MsgFromValidation) {
				case Validation.ValidationStrict:
					name = "Strict";
					color = styles.underlineGreen;
					title = "Message would have matched a strict DMARC policy.";
					break;
				case Validation.ValidationDMARC:
					name = "DMARC";
					color = styles.underlineGreen;
					title = "Message matched DMARC policy of domain.";
					break;
				case Validation.ValidationRelaxed:
					name = "Relaxed";
					color = styles.underlineGreen;
					title = "Domain did not have a DMARC policy, but message would match a relaxed policy if it had existed.";
					break;
				case Validation.ValidationNone:
					if (m.IsForward || m.IsMailingList) {
						name = "Forwardlist";
						color = styles.underlineBlue;
						title = "Message would not pass DMARC policy, but came in through a configured mailing list or forwarding address.";
					} else {
						name = "Bad";
						color = styles.underlineRed;
						title = "Either domain did not have a DMARC policy, or message did not adhere to it.";
					}
					break;
				default:
					name = "Unknown";
					title = "Unknown DMARC verification result.";
					return dom.span(attr.title(title + extra), domstr);
			}
			return dom.span(attr.title(title + extra), css("addressValidation" + name, { borderBottom: "1.5px solid", borderBottomColor: color, textDecoration: "none" }), domstr);
		}, "domainText");
		let l = [];
		if (a.Name) {
			l.push(a.Name + " ");
		}
		l.push("<" + a.User + "@");
		l.push(domainText(formatDomain(a.Domain), a.Domain.ASCII));
		l.push(">");
		return l;
	}, "formatAddressValidated");
	var formatAddressShort = /* @__PURE__ */ __name((a, junk) => {
		const n = a.Name;
		if (!junk && n && !n.includes("<") && !n.includes("@") && !n.includes(">")) {
			return n;
		}
		return "<" + a.User + "@" + formatDomain(a.Domain) + ">";
	}, "formatAddressShort");
	var formatEmail = /* @__PURE__ */ __name((a) => a.User + "@" + formatDomain(a.Domain), "formatEmail");
	var equalAddress = /* @__PURE__ */ __name((a, b) => {
		return (!a.User || !b.User || a.User === b.User) && a.Domain.ASCII === b.Domain.ASCII;
	}, "equalAddress");
	var addressList = /* @__PURE__ */ __name((allAddrs, l) => {
		if (l.length <= 5 || allAddrs) {
			return dom.span(join(l.map((a) => formatAddressElem(a)), () => ", "));
		}
		let elem = dom.span(join(l.slice(0, 4).map((a) => formatAddressElem(a)), () => ", "), " ", dom.clickbutton("More...", attr.title("More addresses:\n" + l.slice(4).map((a) => formatAddress(a)).join(",\n")), /* @__PURE__ */ __name(function click() {
			const nelem = dom.span(join(l.map((a) => formatAddressElem(a)), () => ", "), " ", dom.clickbutton("Less...", /* @__PURE__ */ __name(function click2() {
				elem.replaceWith(addressList(allAddrs, l));
			}, "click")));
			elem.replaceWith(nelem);
			elem = nelem;
		}, "click")));
		return elem;
	}, "addressList");
	var loadMsgheaderView = /* @__PURE__ */ __name((msgheaderelem, mi, moreHeaders, refineKeyword, allAddrs) => {
		const msgenv = mi.Envelope;
		const received = mi.Message.Received;
		const receivedlocal = new Date(received.getTime());
		const msgHeaderFieldStyle = css("msgHeaderField", { textAlign: "right", color: styles.colorMild, whiteSpace: "nowrap" });
		const msgAttrStyle = css("msgAttr", { padding: "0px 0.15em", fontSize: ".9em" });
		dom._kids(
			msgheaderelem,
			// todo: make addresses clickable, start search (keep current mailbox if any)
			dom.tr(dom.td("From:", msgHeaderFieldStyle), dom.td(style({ width: "100%" }), dom.div(css("msgFromReceivedSpread", { display: "flex", justifyContent: "space-between" }), dom.div(join((msgenv.From || []).map((a) => formatAddressValidated(a, mi.Message, !!msgenv.From && msgenv.From.length === 1)), () => ", ")), dom.div(attr.title("Received: " + received.toString() + ";\nDate header in message: " + (msgenv.Date ? msgenv.Date.toString() : "(missing/invalid)")), receivedlocal.toDateString() + " " + receivedlocal.toTimeString().split(" ")[0])))),
			(msgenv.ReplyTo || []).length === 0 ? [] : dom.tr(dom.td("Reply-To:", msgHeaderFieldStyle), dom.td(join((msgenv.ReplyTo || []).map((a) => formatAddressElem(a)), () => ", "))),
			dom.tr(dom.td("To:", msgHeaderFieldStyle), dom.td(addressList(allAddrs, msgenv.To || []))),
			(msgenv.CC || []).length === 0 ? [] : dom.tr(dom.td("Cc:", msgHeaderFieldStyle), dom.td(addressList(allAddrs, msgenv.CC || []))),
			(msgenv.BCC || []).length === 0 ? [] : dom.tr(dom.td("Bcc:", msgHeaderFieldStyle), dom.td(addressList(allAddrs, msgenv.BCC || []))),
			dom.tr(dom.td("Subject:", msgHeaderFieldStyle), dom.td(dom.div(css("msgSubjectAttrsSpread", { display: "flex", justifyContent: "space-between" }), dom.div(msgenv.Subject || ""), dom.div(mi.Message.IsForward ? dom.span(msgAttrStyle, "Forwarded", attr.title("Message came in from a forwarded address. Some message authentication policies, like DMARC, were not evaluated.")) : [], mi.Message.IsMailingList ? dom.span(msgAttrStyle, "Mailing list", attr.title("Message was received from a mailing list. Some message authentication policies, like DMARC, were not evaluated.")) : [], mi.Message.ReceivedTLSVersion === 1 ? dom.span(msgAttrStyle, css("msgAttrNoTLS", { borderBottom: "1.5px solid", borderBottomColor: styles.underlineRed }), "Without TLS", attr.title("Message received (last hop) without TLS.")) : [], mi.Message.ReceivedTLSVersion > 1 && !mi.Message.ReceivedRequireTLS ? dom.span(msgAttrStyle, css("msgAttrTLS", { borderBottom: "1.5px solid", borderBottomColor: styles.underlineGreen }), "With TLS", attr.title("Message received (last hop) with TLS.")) : [], mi.Message.ReceivedRequireTLS ? dom.span(css("msgAttrRequireTLS", { padding: ".1em .3em", fontSize: ".9em", backgroundColor: styles.successBackground, border: "1px solid", borderColor: styles.borderColor, borderRadius: "3px" }), "With RequireTLS", attr.title("Transported with RequireTLS, ensuring TLS along the entire delivery path from sender to recipient, with TLS certificate verification through MTA-STS and/or DANE.")) : [], mi.IsSigned ? dom.span(msgAttrStyle, css("msgAttrSigned", { backgroundColor: styles.colorMild, color: styles.backgroundColorMild, borderRadius: ".15em" }), "Message has a signature") : [], mi.IsEncrypted ? dom.span(msgAttrStyle, css("msgAttrEncrypted", { backgroundColor: styles.colorMild, color: styles.backgroundColorMild, borderRadius: ".15em" }), "Message is encrypted") : [], refineKeyword ? (mi.Message.Keywords || []).map((kw) => dom.clickbutton(styleClasses.keyword, dom._class("keywordButton"), kw, /* @__PURE__ */ __name(async function click() {
				await refineKeyword(kw);
			}, "click"))) : [])))),
			(mi.MoreHeaders || []).map((t) => dom.tr(dom.td(t[0] + ":", msgHeaderFieldStyle), dom.td(t[1]))),
			// Ensure width of all possible additional headers is taken into account, to
			// prevent different layout between messages when not all headers are present.
			dom.tr(dom.td(moreHeaders.map((s) => dom.div(s + ":", msgHeaderFieldStyle, style({ visibility: "hidden", height: 0 })))), dom.td())
		);
	}, "loadMsgheaderView");

	// .js/webmail/webmail.js
	var reloadURL = URL.parse(window.location.href);
	if (reloadURL?.search.startsWith("?v=")) {
		const l = reloadURL.search.split("&", 2);
		reloadURL.search = l.length === 2 ? "?" + l[1] : "";
		window.location.href = reloadURL.toString();
	}
	var ConsistencyError = class extends Error {
		static {
			__name(this, "ConsistencyError");
		}
	};
	var zindexes = {
		splitter: "1",
		compose: "2",
		searchView: "3",
		searchbar: "4",
		popup: "5",
		popover: "5",
		attachments: "5",
		shortcut: "6",
		login: "7"
	};
	ensureCSS(".button", { display: "inline-block" });
	ensureCSS("button, .button, select", { backgroundColor: styles.buttonBackground, border: "1px solid", borderColor: styles.buttonBorderColor, borderRadius: ".15em", padding: "0 .15em" });
	ensureCSS("button, .button, select, a.button:visited", { color: styles.color });
	ensureCSS("button.active, .button.active, button.active:hover, .button.active:hover", { backgroundColor: styles.highlightBackground });
	ensureCSS("button:hover:not(:disabled), .button:hover:not(:disabled), select:hover:not(:disabled)", { backgroundColor: styles.buttonHoverBackground });
	ensureCSS("button.active:hover:not(:disabled), .button.active:hover:not(:disabled)", { backgroundColor: styles.highlightBackgroundHover });
	ensureCSS("button:disabled, .button:disabled, select:disabled", { opacity: 0.5 });
	ensureCSS("input, textarea", { backgroundColor: styles.backgroundColor, color: styles.color, border: "1px solid", borderColor: "#888", borderRadius: ".15em", padding: "0 .15em" });
	ensureCSS("input:hover:not(:disabled), textarea:hover:not(:disabled)", { borderColor: styles.colorMilder });
	ensureCSS(".btngroup button, .btngroup .button", { borderRadius: 0, borderRightWidth: 0 });
	ensureCSS(".btngroup button:first-child, .btngroup .button:first-child", { borderRadius: ".15em 0 0 .15em" });
	ensureCSS(".btngroup button:last-child, .btngroup .button:last-child", { borderRadius: "0 .15em .15em 0", borderRightWidth: "1px" });
	var keywordButtonStyle = css("keywordButton", { cursor: "pointer" });
	ensureCSS(".keywordButton:hover:not(:disabled)", { backgroundColor: styles.highlightBackgroundHover });
	var yscrollStyle = css("yscroll", { overflowY: "scroll", position: "absolute", top: 0, bottom: 0, left: 0, right: 0 });
	var yscrollAutoStyle = css("yscrollAuto", { overflowY: "auto", position: "absolute", top: 0, bottom: 0, left: 0, right: 0 });
	css("autosize", { display: "inline-grid", maxWidth: "90vw" });
	ensureCSS(".autosize.input", { gridArea: "1 / 2" });
	ensureCSS(".autosize::after", { content: "attr(data-value)", marginRight: "1em", lineHeight: 0, visibility: "hidden", whiteSpace: "pre-wrap", overflowX: "hidden" });
	var moxversion;
	var moxgoos;
	var moxgoarch;
	var log = /* @__PURE__ */ __name(() => {
	}, "log");
	try {
		if (localStorage.getItem("log") || location.hostname === "localhost") {
			log = console.log;
		}
	} catch (err) {
	}
	var accountSettings;
	var introboxMailbox = "";
	var defaultSettings = {
		mailboxesWidth: 240,
		layout: "auto",
		// Automatic switching between left/right and top/bottom layout, based on screen width.
		leftWidthPct: 50,
		// Split in percentage of remaining width for left/right layout.
		topHeightPct: 40,
		// Split in percentage of remaining height for top/bottom layout.
		msglistflagsWidth: 40,
		// Width in pixels of flags column in message list.
		msglistageWidth: 70,
		// Width in pixels of age column.
		msglistfromPct: 30,
		// Percentage of remaining width in message list to use for "from" column. The remainder is for the subject.
		refine: "",
		// Refine filters, e.g. '', 'attachments', 'read', 'unread', 'flagged', 'label:...'.
		orderAsc: false,
		// Order from most recent to least recent by default.
		ignoreErrorsUntil: 0,
		// For unhandled javascript errors/rejected promises, we normally show a popup for details, but users can ignore them for a week at a time.
		mailboxCollapsed: {},
		// Mailboxes that are collapsed.
		showAllHeaders: false,
		// Whether to show all message headers.
		threading: ThreadMode.ThreadOn,
		checkConsistency: location.hostname === "localhost",
		// Enable UI update consistency checks, default only for local development.
		composeWidth: 0,
		composeViewportWidth: 0,
		composeHeight: 0,
		composeViewportHeight: 0
	};
	var parseSettings = /* @__PURE__ */ __name(() => {
		try {
			const v = window.localStorage.getItem("settings");
			if (!v) {
				return { ...defaultSettings };
			}
			const x = JSON.parse(v);
			const def = defaultSettings;
			const getString = /* @__PURE__ */ __name((k, ...l) => {
				const v2 = x[k];
				if (typeof v2 !== "string" || l.length > 0 && !l.includes(v2)) {
					return def[k];
				}
				return v2;
			}, "getString");
			const getBool = /* @__PURE__ */ __name((k) => {
				const v2 = x[k];
				return typeof v2 === "boolean" ? v2 : def[k];
			}, "getBool");
			const getInt = /* @__PURE__ */ __name((k) => {
				const v2 = x[k];
				return typeof v2 === "number" ? v2 : def[k];
			}, "getInt");
			let mailboxCollapsed = x.mailboxCollapsed;
			if (!mailboxCollapsed || typeof mailboxCollapsed !== "object") {
				mailboxCollapsed = def.mailboxCollapsed;
			}
			return {
				refine: getString("refine"),
				orderAsc: getBool("orderAsc"),
				mailboxesWidth: getInt("mailboxesWidth"),
				leftWidthPct: getInt("leftWidthPct"),
				topHeightPct: getInt("topHeightPct"),
				msglistflagsWidth: getInt("msglistflagsWidth"),
				msglistageWidth: getInt("msglistageWidth"),
				msglistfromPct: getInt("msglistfromPct"),
				ignoreErrorsUntil: getInt("ignoreErrorsUntil"),
				layout: getString("layout", "auto", "leftright", "topbottom"),
				mailboxCollapsed,
				showAllHeaders: getBool("showAllHeaders"),
				threading: getString("threading", ThreadMode.ThreadOff, ThreadMode.ThreadOn, ThreadMode.ThreadUnread),
				checkConsistency: getBool("checkConsistency"),
				composeWidth: getInt("composeWidth"),
				composeViewportWidth: getInt("composeViewportWidth"),
				composeHeight: getInt("composeHeight"),
				composeViewportHeight: getInt("composeViewportHeight")
			};
		} catch (err) {
			console.log("getting settings from localstorage", err);
			return { ...defaultSettings };
		}
	}, "parseSettings");
	var settingsPut = /* @__PURE__ */ __name((nsettings) => {
		settings = nsettings;
		try {
			window.localStorage.setItem("settings", JSON.stringify(nsettings));
		} catch (err) {
			console.log("storing settings in localstorage", err);
		}
	}, "settingsPut");
	var settings = parseSettings();
	var accountAddresses = [];
	var loginAddress = null;
	var domainAddressConfigs = {};
	var rejectsMailbox = "";
	var lastServerVersion = "";
	var scheduledTimers = /* @__PURE__ */ new Map();
	var login = /* @__PURE__ */ __name(async (reason) => {
		popupOpen = true;
		return new Promise((resolve, _) => {
			const origFocus = document.activeElement;
			let reasonElem;
			let fieldset;
			let autosize;
			let username;
			let password;
			const root = dom.div(css("loginOverlay", { position: "absolute", top: 0, right: 0, bottom: 0, left: 0, backgroundColor: styles.overlayOpaqueBackgroundColor, display: "flex", alignItems: "center", justifyContent: "center", zIndex: zindexes.login, animation: "fadein .15s ease-in" }), dom.div(style({ display: "flex", flexDirection: "column", alignItems: "center" }), reasonElem = reason ? dom.div(css("sessionError", { marginBottom: "2ex", textAlign: "center" }), reason) : dom.div(), dom.div(css("loginPopup", {
				backgroundColor: styles.popupBackgroundColor,
				boxShadow: styles.boxShadow,
				border: "1px solid",
				borderColor: styles.popupBorderColor,
				borderRadius: ".25em",
				padding: "1em",
				maxWidth: "95vw",
				overflowX: "auto",
				maxHeight: "95vh",
				overflowY: "auto",
				marginBottom: "20vh"
			}), dom.form(/* @__PURE__ */ __name(async function submit(e) {
				e.preventDefault();
				e.stopPropagation();
				reasonElem.remove();
				try {
					fieldset.disabled = true;
					const loginToken = await client.LoginPrep();
					const token = await client.Login(loginToken, username.value, password.value);
					try {
						window.localStorage.setItem("webmailcsrftoken", token);
					} catch (err) {
						console.log("saving csrf token in localStorage", err);
					}
					root.remove();
					if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
						origFocus.focus();
					}
					popupOpen = false;
					resolve(token);
				} catch (err) {
					console.log("login error", err);
					window.alert("Error: " + errmsg(err));
				} finally {
					fieldset.disabled = false;
				}
			}, "submit"), fieldset = dom.fieldset(dom.h1("Mail"), dom.label(style({ display: "block", marginBottom: "2ex" }), dom.div("Email address", style({ marginBottom: ".5ex" })), autosize = dom.span(dom._class("autosize"), username = dom.input(attr.required(""), attr.autocomplete("email"), attr.placeholder("jane@example.org"), /* @__PURE__ */ __name(function change() {
				autosize.dataset.value = username.value;
			}, "change"), /* @__PURE__ */ __name(function input() {
				autosize.dataset.value = username.value;
			}, "input")))), dom.label(style({ display: "block", marginBottom: "2ex" }), dom.div("Password", style({ marginBottom: ".5ex" })), password = dom.input(attr.type("password"), attr.autocomplete("current-password"), attr.required(""))), dom.div(style({ textAlign: "center" }), dom.submitbutton("Login")))))));
			document.body.appendChild(root);
			username.focus();
		});
	}, "login");
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
	var client = new Client().withOptions({ csrfHeader: "x-mox-csrf", login }).withAuthToken(localStorageGet("webmailcsrftoken") || "");
	var link = /* @__PURE__ */ __name((href, anchorOpt) => dom.a(attr.href(href), attr.rel("noopener noreferrer"), attr.target("_blank"), anchorOpt || href), "link");
	var envelopeIdentity = /* @__PURE__ */ __name((l) => {
		for (const a of l) {
			const ma = accountAddresses.find((aa) => (!aa.User || aa.User === a.User) && aa.Domain.ASCII === a.Domain.ASCII);
			if (ma) {
				return { Name: ma.Name, User: a.User, Domain: a.Domain };
			}
		}
		return null;
	}, "envelopeIdentity");
	var shortcutElem = dom.div(css("shortcutFlash", { fontSize: "2em", position: "absolute", left: ".25em", bottom: ".25em", backgroundColor: "#888", padding: "0.25em .5em", color: "white", borderRadius: ".15em" }));
	var shortcutTimer = 0;
	var showShortcut = /* @__PURE__ */ __name((c) => {
		if (accountSettings?.NoShowShortcuts) {
			return;
		}
		if (shortcutTimer) {
			window.clearTimeout(shortcutTimer);
		}
		shortcutElem.remove();
		dom._kids(shortcutElem, c);
		document.body.appendChild(shortcutElem);
		shortcutTimer = window.setTimeout(() => {
			shortcutElem.remove();
			shortcutTimer = 0;
		}, 1500);
	}, "showShortcut");
	var shortcutCmd = /* @__PURE__ */ __name(async (cmdfn, shortcuts) => {
		let shortcut = "";
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
	}, "shortcutCmd");
	var clickCmd = /* @__PURE__ */ __name((cmdfn, shortcuts) => {
		return /* @__PURE__ */ __name(async function click() {
			shortcutCmd(cmdfn, shortcuts);
		}, "click");
	}, "clickCmd");
	var enterCmd = /* @__PURE__ */ __name((cmdfn, shortcuts) => {
		return /* @__PURE__ */ __name(async function keydown(e) {
			if (e.key === "Enter") {
				e.stopPropagation();
				shortcutCmd(cmdfn, shortcuts);
			}
		}, "keydown");
	}, "enterCmd");
	var keyHandler = /* @__PURE__ */ __name((shortcuts) => {
		return async (k, e) => {
			const fn = shortcuts[k];
			if (fn) {
				e.preventDefault();
				e.stopPropagation();
				fn();
			}
		};
	}, "keyHandler");
	var formatSize = /* @__PURE__ */ __name((size) => size > 1024 * 1024 ? (size / (1024 * 1024)).toFixed(1) + "mb" : Math.ceil(size / 1024) + "kb", "formatSize");
	var parseSearchSize = /* @__PURE__ */ __name((s) => {
		s = s.trim();
		if (!s) {
			return ["", 0];
		}
		const digits = s.match(/^([0-9]+)/)?.[1];
		if (!digits) {
			return ["", 0];
		}
		let num = parseInt(digits);
		if (isNaN(num)) {
			return ["", 0];
		}
		const suffix = s.substring(digits.length).trim().toLowerCase();
		if (["b", "kb", "mb", "gb"].includes(suffix)) {
			return [digits + suffix, num * Math.pow(2, 10 * ["b", "kb", "mb", "gb"].indexOf(suffix))];
		}
		if (["k", "m", "g"].includes(suffix)) {
			return [digits + suffix + "b", num * Math.pow(2, 10 * (1 + ["k", "m", "g"].indexOf(suffix)))];
		}
		return ["", 0];
	}, "parseSearchSize");
	var fixDate = /* @__PURE__ */ __name((dt) => {
		const t = dt.split("-");
		if (t.length !== 3) {
			return dt;
		}
		if (t[1].length === 1) {
			t[1] = "0" + t[1];
		}
		if (t[2].length === 1) {
			t[2] = "0" + t[2];
		}
		return t.join("-");
	}, "fixDate");
	var parseSearchDateTime = /* @__PURE__ */ __name((s, isstart) => {
		const t = s.split("T", 2);
		if (t.length === 2) {
			const d = /* @__PURE__ */ new Date(fixDate(t[0]) + "T" + t[1]);
			return d ? d.toJSON() : void 0;
		} else if (t.length === 1) {
			const fds = fixDate(t[0]);
			if (!isNaN(Date.parse(fds))) {
				const d = new Date(fds);
				if (!isstart) {
					d.setDate(d.getDate() + 1);
				}
				return d.toJSON();
			} else {
				const tm = t[0];
				const now = /* @__PURE__ */ new Date();
				const pad0 = /* @__PURE__ */ __name((v) => v <= 9 ? "0" + v : "" + v, "pad0");
				const d = /* @__PURE__ */ new Date([now.getFullYear(), pad0(now.getMonth() + 1), pad0(now.getDate())].join("-") + "T" + tm);
				return d ? d.toJSON() : void 0;
			}
		}
		return void 0;
	}, "parseSearchDateTime");
	var dquote = /* @__PURE__ */ __name((s) => '"' + s.replaceAll('"', '""') + '"', "dquote");
	var needsDquote = /* @__PURE__ */ __name((s) => /[ \t"]/.test(s), "needsDquote");
	var packToken = /* @__PURE__ */ __name((t) => (t[0] ? "-" : "") + (t[1] ? t[1] + ":" : "") + (t[2] || needsDquote(t[3]) ? dquote(t[3]) : t[3]), "packToken");
	var parseSearchTokens = /* @__PURE__ */ __name((s) => {
		if (!s) {
			return [];
		}
		const l = [];
		let not = false;
		let quoted = false;
		let quoteend = false;
		let t = "";
		let tquoted = false;
		const add = /* @__PURE__ */ __name(() => {
			if (t && (tquoted || !t.includes(":"))) {
				l.push([not, "", tquoted, t]);
			} else if (t) {
				const tag = t.split(":", 1)[0];
				l.push([not, tag, tquoted, t.substring(tag.length + 1)]);
			}
			t = "";
			quoted = false;
			quoteend = false;
			tquoted = false;
			not = false;
		}, "add");
		[...s].forEach((c) => {
			if (quoteend) {
				if (c === '"') {
					t += '"';
					quoteend = false;
				} else if (t) {
					add();
				}
			} else if (quoted && c === '"') {
				quoteend = true;
			} else if (c === '"') {
				quoted = true;
				if (!t) {
					tquoted = true;
				}
			} else if (!quoted && (c === " " || c === "	")) {
				add();
			} else if (c === "-" && !t && !tquoted && !not) {
				not = true;
			} else {
				t += c;
			}
		});
		add();
		return l;
	}, "parseSearchTokens");
	var newFilter = /* @__PURE__ */ __name(() => {
		return {
			MailboxID: 0,
			MailboxChildrenIncluded: false,
			MailboxName: "",
			Attachments: AttachmentType.AttachmentIndifferent,
			SizeMin: 0,
			SizeMax: 0
		};
	}, "newFilter");
	var newNotFilter = /* @__PURE__ */ __name(() => {
		return {
			Attachments: AttachmentType.AttachmentIndifferent
		};
	}, "newNotFilter");
	var parseSearch = /* @__PURE__ */ __name((searchquery, mailboxlistView) => {
		const tokens = parseSearchTokens(searchquery);
		const fpos = newFilter();
		fpos.MailboxID = -1;
		const notf = newNotFilter();
		const strs = { Oldest: "", Newest: "", SizeMin: "", SizeMax: "" };
		tokens.forEach((t) => {
			const [not, tag, _, s] = t;
			const f = not ? notf : fpos;
			if (!not) {
				if (tag === "mb" || tag === "mailbox") {
					const mb = mailboxlistView.findMailboxByName(s);
					if (mb) {
						fpos.MailboxID = mb.ID;
					} else if (s === "") {
						fpos.MailboxID = 0;
					} else {
						fpos.MailboxName = s;
						fpos.MailboxID = 0;
					}
					return;
				} else if (tag === "submb") {
					fpos.MailboxChildrenIncluded = true;
					return;
				} else if (tag === "start") {
					const dt = parseSearchDateTime(s, true);
					if (dt) {
						fpos.Oldest = new Date(dt);
						strs.Oldest = s;
						return;
					}
				} else if (tag === "end") {
					const dt = parseSearchDateTime(s, false);
					if (dt) {
						fpos.Newest = new Date(dt);
						strs.Newest = s;
						return;
					}
				} else if (tag === "a" || tag === "attachments") {
					if (s === "none" || s === "any" || s === "image" || s === "pdf" || s === "archive" || s === "zip" || s === "spreadsheet" || s === "document" || s === "presentation") {
						fpos.Attachments = s;
						return;
					}
				} else if (tag === "h" || tag === "header") {
					const k = s.split(":")[0];
					const v = s.substring(k.length + 1);
					if (!fpos.Headers) {
						fpos.Headers = [[k, v]];
					} else {
						fpos.Headers.push([k, v]);
					}
					return;
				} else if (tag === "minsize") {
					const [str, size] = parseSearchSize(s);
					if (str) {
						fpos.SizeMin = size;
						strs.SizeMin = str;
						return;
					}
				} else if (tag === "maxsize") {
					const [str, size] = parseSearchSize(s);
					if (str) {
						fpos.SizeMax = size;
						strs.SizeMax = str;
						return;
					}
				}
			}
			if (tag === "f" || tag === "from") {
				f.From = f.From || [];
				f.From.push(s);
				return;
			} else if (tag === "t" || tag === "to") {
				f.To = f.To || [];
				f.To.push(s);
				return;
			} else if (tag === "s" || tag === "subject") {
				f.Subject = f.Subject || [];
				f.Subject.push(s);
				return;
			} else if (tag === "l" || tag === "label") {
				f.Labels = f.Labels || [];
				f.Labels.push(s);
				return;
			}
			f.Words = f.Words || [];
			f.Words.push((tag ? tag + ":" : "") + s);
		});
		return [fpos, notf, strs];
	}, "parseSearch");
	var errmsg = /* @__PURE__ */ __name((err) => "" + (err.message || "(no error message)"), "errmsg");
	var datalistgen = 1;
	var newAddressComplete = /* @__PURE__ */ __name(() => {
		let datalist;
		let completeMatches;
		let completeSearch;
		let completeFull;
		let aborter = {};
		return /* @__PURE__ */ __name(async function keydown(e) {
			const target = e.target;
			if (!datalist) {
				datalist = dom.datalist(attr.id("list-" + datalistgen++));
				target.parentNode.insertBefore(datalist, target);
				target.setAttribute("list", datalist.id);
			}
			const search = target.value;
			if (e.key === "Tab") {
				const matches = (completeMatches || []).filter((s) => s.includes(search));
				if (matches.length > 0) {
					target.value = matches[0];
					return;
				} else if ((completeMatches || []).length === 0 && !search) {
					return;
				}
			}
			if (completeSearch && search.includes(completeSearch) && completeFull) {
				dom._kids(datalist, (completeMatches || []).filter((s) => s.includes(search)).map((s) => dom.option(s)));
				return;
			} else if (search === completeSearch) {
				return;
			}
			if (aborter.abort) {
				aborter.abort();
			}
			aborter = {};
			try {
				[completeMatches, completeFull] = await withStatus("Autocompleting addresses", client.withOptions({ aborter }).CompleteRecipient(search));
				completeSearch = search;
				dom._kids(datalist, (completeMatches || []).map((s) => dom.option(s)));
			} catch (err) {
				log("autocomplete error", errmsg(err));
			} finally {
				aborter = {};
			}
		}, "keydown");
	}, "newAddressComplete");
	var flagList = /* @__PURE__ */ __name((miv) => {
		const msgflags = [];
		const othermsgflags = [];
		let l = msgflags;
		const seen = /* @__PURE__ */ new Set();
		const flag = /* @__PURE__ */ __name((v, char, name) => {
			if (v && !seen.has(name)) {
				l.push([name, char]);
				seen.add(name);
			}
		}, "flag");
		const addFlags = /* @__PURE__ */ __name((mi) => {
			const m = mi.Message;
			flag(m.Answered, "r", "Replied/answered");
			flag(m.Flagged, "!", "Flagged");
			flag(m.Forwarded, "f", "Forwarded");
			flag(m.Junk, "j", "Junk");
			flag(m.Deleted, "D", "Deleted, used in IMAP, message will likely be removed soon.");
			flag(m.Draft, "d", "Draft");
			flag(m.Phishing, "p", "Phishing");
			flag(!m.Junk && !m.Notjunk, "?", "Unclassified, neither junk nor not junk: message does not contribute to spam classification of new incoming messages");
			flag(mi.Attachments && mi.Attachments.length > 0 ? true : false, "a", "Has at least one attachment");
			if (m.ThreadMuted) {
				flag(true, "m", "Muted, new messages are automatically marked as read.");
			}
		}, "addFlags");
		addFlags(miv.messageitem);
		if (miv.isCollapsedThreadRoot()) {
			l = othermsgflags;
			for (miv of miv.descendants()) {
				addFlags(miv.messageitem);
			}
		}
		const msgItemFlagStyle = css("msgItemFlag", { marginRight: "1px", fontWeight: "normal", fontSize: ".9em" });
		return msgflags.map((t) => dom.span(msgItemFlagStyle, t[1], attr.title(t[0]))).concat(othermsgflags.map((t) => dom.span(msgItemFlagStyle, css("msgItemFlagCollapsed", { color: styles.colorMilder }), t[1], attr.title(t[0]))));
	}, "flagList");
	var refineFilters = /* @__PURE__ */ __name((f, notf) => {
		const refine = settings.refine;
		if (refine) {
			f = { ...f };
			notf = { ...notf };
			if (refine === "unread") {
				notf.Labels = [...notf.Labels || []];
				notf.Labels = (notf.Labels || []).concat(["\\Seen"]);
			} else if (refine === "read") {
				f.Labels = [...f.Labels || []];
				f.Labels = (f.Labels || []).concat(["\\Seen"]);
			} else if (refine === "attachments") {
				f.Attachments = "any";
			} else if (refine === "flagged") {
				f.Labels = [...f.Labels || []];
				f.Labels = (f.Labels || []).concat(["\\Flagged"]);
			} else if (refine.startsWith("label:")) {
				f.Labels = [...f.Labels || []];
				f.Labels = (f.Labels || []).concat([refine.substring("label:".length)]);
			}
		}
		return [f, notf];
	}, "refineFilters");
	var startDrag = /* @__PURE__ */ __name((e, move) => {
		if (e.buttons !== 1) {
			return Promise.resolve();
		}
		return new Promise((resolve, _) => {
			e.preventDefault();
			e.stopPropagation();
			const stop = /* @__PURE__ */ __name(() => {
				document.body.removeEventListener("mousemove", move);
				document.body.removeEventListener("mouseup", stop);
				resolve();
			}, "stop");
			document.body.addEventListener("mousemove", move);
			document.body.addEventListener("mouseup", stop);
		});
	}, "startDrag");
	var focusPlaceholder = /* @__PURE__ */ __name((s) => {
		let orig = "";
		return [
			/* @__PURE__ */ __name(function focus(e) {
				const target = e.target;
				orig = target.getAttribute("placeholder") || "";
				target.setAttribute("placeholder", s);
			}, "focus"),
			/* @__PURE__ */ __name(function blur(e) {
				const target = e.target;
				if (orig) {
					target.setAttribute("placeholder", orig);
				} else {
					target.removeAttribute("placeholder");
				}
			}, "blur")
		];
	}, "focusPlaceholder");
	var parseLocationHash = /* @__PURE__ */ __name((mailboxlistView) => {
		let hash = decodeURIComponent((window.location.hash || "#").substring(1));
		let editMsgid = 0;
		const em = hash.match(/,compose:([0-9]+)$/);
		if (em) {
			editMsgid = parseInt(em[1]);
			hash = hash.substring(0, hash.length - em[0].length);
		}
		const m = hash.match(/,([0-9]+)$/);
		let msgid = 0;
		if (m) {
			msgid = parseInt(m[1]);
			hash = hash.substring(0, hash.length - m[0].length);
		}
		let initmailbox, initsearch;
		if (hash.startsWith("search ")) {
			initsearch = hash.substring("search ".length).trim();
		}
		let f, notf;
		if (initsearch) {
			[f, notf] = parseSearch(initsearch, mailboxlistView);
		} else {
			initmailbox = hash;
			if (!initmailbox) {
				initmailbox = "Inbox";
			}
			f = newFilter();
			const mb = mailboxlistView.findMailboxByName(initmailbox);
			if (mb) {
				f.MailboxID = mb.ID;
			} else {
				f.MailboxName = initmailbox;
			}
			notf = newNotFilter();
		}
		return [initsearch, msgid, editMsgid, f, notf];
	}, "parseLocationHash");
	var statusElem;
	var withStatus = /* @__PURE__ */ __name(async (action, promise, disablable, noAlert) => {
		let elem;
		let id = window.setTimeout(() => {
			elem = dom.span(action + "... ");
			statusElem.appendChild(elem);
			id = 0;
		}, 1e3);
		let origFocus = document.activeElement;
		try {
			if (disablable) {
				disablable.disabled = true;
			}
			return await promise;
		} catch (err) {
			if (id) {
				window.clearTimeout(id);
				id = 0;
			}
			if (err.code === "sherpa:aborted") {
				throw err;
			}
			if (!noAlert) {
				window.alert("Error: " + action + ": " + errmsg(err));
			}
			throw err;
		} finally {
			if (disablable) {
				disablable.disabled = false;
			}
			if (disablable && origFocus && document.activeElement !== origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
				origFocus.focus();
			}
			if (id) {
				window.clearTimeout(id);
			}
			if (elem) {
				elem.remove();
			}
		}
	}, "withStatus");
	var withDisabled = /* @__PURE__ */ __name(async (elem, p) => {
		try {
			elem.disabled = true;
			return await p;
		} catch (err) {
			log({ err });
			window.alert("Error: " + errmsg(err));
			throw err;
		} finally {
			elem.disabled = false;
		}
	}, "withDisabled");
	var popover = /* @__PURE__ */ __name((target, opts, ...kids) => {
		const origFocus = document.activeElement;
		const pos = target.getBoundingClientRect();
		const close = /* @__PURE__ */ __name(() => {
			if (!root.parentNode) {
				return;
			}
			root.remove();
			if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
				origFocus.focus();
			}
		}, "close");
		const posx = opts.fullscreen ? style({ left: 0, right: 0 }) : pos.x < window.innerWidth / 3 ? style({ left: "" + pos.x + "px" }) : style({ right: "" + (window.innerWidth - pos.x - pos.width) + "px" });
		const posy = opts.fullscreen ? style({ top: 0, bottom: 0 }) : pos.y + pos.height > window.innerHeight * 2 / 3 ? style({ bottom: "" + (window.innerHeight - (pos.y - 1)) + "px", maxHeight: "" + (pos.y - 1 - 10) + "px" }) : style({ top: "" + (pos.y + pos.height + 1) + "px", maxHeight: "" + (window.innerHeight - (pos.y + pos.height + 1) - 10) + "px" });
		let content;
		const root = dom.div(css("popoverOverlay", { position: "absolute", left: 0, right: 0, top: 0, bottom: 0, zIndex: zindexes.popover, backgroundColor: styles.overlayBackgroundColor }), /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
			close();
		}, "click"), /* @__PURE__ */ __name(function keydown(e) {
			if (e.key === "Escape") {
				e.stopPropagation();
				close();
			}
		}, "keydown"), content = dom.div(attr.tabindex("0"), css("popoverContent", {
			position: "absolute",
			overflowY: "auto"
		}), posx, posy, opts.transparent ? [] : [
			css("popoverContentOpaque", {
				backgroundColor: styles.popupBackgroundColor,
				padding: "1em",
				borderRadius: ".15em",
				boxShadow: styles.boxShadow,
				border: "1px solid",
				borderColor: styles.popupBorderColor,
				color: styles.popupColor
			}),
			/* @__PURE__ */ __name(function click(e) {
				e.stopPropagation();
			}, "click")
		], ...kids));
		document.body.appendChild(root);
		const first = root.querySelector("input, select, textarea, button");
		if (first && first instanceof HTMLElement) {
			first.focus();
		} else {
			content.focus();
		}
		return close;
	}, "popover");
	var popupOpen = false;
	var popup = /* @__PURE__ */ __name((...kids) => {
		const origFocus = document.activeElement;
		const close = /* @__PURE__ */ __name(() => {
			if (!root.parentNode) {
				return;
			}
			popupOpen = false;
			root.remove();
			if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
				origFocus.focus();
			}
		}, "close");
		let content;
		const root = dom.div(css("popupOverlay", { position: "absolute", top: 0, right: 0, bottom: 0, left: 0, backgroundColor: styles.overlayBackgroundColor, display: "flex", alignItems: "center", justifyContent: "center", zIndex: zindexes.popup }), /* @__PURE__ */ __name(function keydown(e) {
			if (e.key === "Escape") {
				e.stopPropagation();
				close();
			}
		}, "keydown"), /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
			close();
		}, "click"), content = dom.div(attr.tabindex("0"), css("popupContent", { backgroundColor: styles.popupBackgroundColor, boxShadow: styles.boxShadow, border: "1px solid", borderColor: styles.popupBorderColor, borderRadius: ".25em", padding: "1em", maxWidth: "95vw", overflowX: "auto", maxHeight: "95vh", overflowY: "auto" }), /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
		}, "click"), kids));
		popupOpen = true;
		document.body.appendChild(root);
		content.focus();
		return close;
	}, "popup");
	var cmdSettings = /* @__PURE__ */ __name(async () => {
		let fieldset;
		let signature;
		let quoting;
		let showAddressSecurity;
		let showHTML;
		let showShortcuts;
		let showHeaders;
		if (!accountSettings) {
			throw new Error("No account settings fetched yet.");
		}
		const remove = popup(css("popupSettings", { minWidth: "30em" }), style({ maxWidth: "50em" }), dom.h1("Settings"), dom.form(/* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			e.stopPropagation();
			const accSet = {
				ID: accountSettings.ID,
				Signature: signature.value,
				Quoting: quoting.value,
				ShowAddressSecurity: showAddressSecurity.checked,
				ShowHTML: showHTML.checked,
				NoShowShortcuts: !showShortcuts.checked,
				ShowHeaders: showHeaders.value.split("\n").map((s) => s.trim()).filter((s) => !!s)
			};
			await withDisabled(fieldset, client.SettingsSave(accSet));
			accountSettings = accSet;
			remove();
		}, "submit"), fieldset = dom.fieldset(dom.label(style({ margin: "1ex 0", display: "block" }), dom.div("Signature"), signature = dom.textarea(new String(accountSettings.Signature), style({ width: "100%" }), attr.rows("" + Math.max(3, 1 + accountSettings.Signature.split("\n").length)))), dom.label(style({ margin: "1ex 0", display: "block" }), dom.div("Reply above/below original"), attr.title("Auto: If text is selected, only the replied text is quoted and editing starts below. Otherwise, the full message is quoted and editing starts at the top."), quoting = dom.select(dom.option(attr.value(""), "Auto"), dom.option(attr.value("bottom"), "Bottom", accountSettings.Quoting === Quoting.Bottom ? attr.selected("") : []), dom.option(attr.value("top"), "Top", accountSettings.Quoting === Quoting.Top ? attr.selected("") : []))), dom.label(style({ margin: "1ex 0", display: "block" }), showAddressSecurity = dom.input(attr.type("checkbox"), accountSettings.ShowAddressSecurity ? attr.checked("") : []), " Show address security indications", attr.title("Show bars underneath address input fields, indicating support for STARTTLS/DNSSEC/DANE/MTA-STS/RequireTLS.")), dom.label(style({ margin: "1ex 0", display: "block" }), showHTML = dom.input(attr.type("checkbox"), accountSettings.ShowHTML ? attr.checked("") : []), " Show email as HTML instead of text by default for first-time senders", attr.title("Whether to show HTML or text is remembered per sender. This sets the default for unknown correspondents.")), dom.label(style({ margin: "1ex 0", display: "block" }), showShortcuts = dom.input(attr.type("checkbox"), accountSettings.NoShowShortcuts ? [] : attr.checked("")), " Show shortcut keys in bottom left after interaction with mouse"), dom.label(style({ margin: "1ex 0", display: "block" }), dom.div("Show additional headers"), showHeaders = dom.textarea(new String((accountSettings.ShowHeaders || []).join("\n")), style({ width: "100%" }), attr.rows("" + Math.max(3, 1 + (accountSettings.ShowHeaders || []).length))), dom.div(style({ fontStyle: "italic" }), "One header name per line, for example Delivered-To, X-Mox-Reason, User-Agent, ...; Refresh mailbox view for changes to take effect.")), dom.div(style({ marginTop: "2ex" }), 'Register "mailto:" links with the browser/operating system to compose a message in webmail.', dom.br(), dom.clickbutton("Register", attr.title("In most browsers, registering is only allowed on HTTPS URLs. Your browser may ask for confirmation. If nothing appears to happen, the registration may already have been present."), /* @__PURE__ */ __name(function click() {
			if (!window.navigator.registerProtocolHandler) {
				window.alert('Registering a protocol handler ("mailto:") is not supported by your browser.');
				return;
			}
			try {
				window.navigator.registerProtocolHandler("mailto", "#compose %s");
				window.alert('"mailto:"-links have been registered');
			} catch (err) {
				window.alert('Error registering "mailto:" protocol handler: ' + errmsg(err));
			}
		}, "click")), " ", dom.clickbutton("Unregister", attr.title("Not all browsers implement unregistering via JavaScript."), /* @__PURE__ */ __name(function click() {
			if (!window.navigator.unregisterProtocolHandler) {
				window.alert('Unregistering a protocol handler ("mailto:") via JavaScript is not supported by your browser. See your browser settings to unregister.');
				return;
			}
			try {
				window.navigator.unregisterProtocolHandler("mailto", "#compose %s");
			} catch (err) {
				window.alert('Error unregistering "mailto:" protocol handler: ' + errmsg(err));
				return;
			}
			window.alert('"mailto:" protocol handler unregistered.');
		}, "click"))), dom.br(), dom.div(dom.submitbutton("Save")))));
	}, "cmdSettings");
	var cmdHelp = /* @__PURE__ */ __name(async () => {
		popup(css("popupHelp", { padding: "1em 1em 2em 1em" }), dom.h1("Help and keyboard shortcuts"), dom.div(style({ display: "flex" }), dom.div(style({ width: "40em" }), dom.table(dom.tr(dom.td(attr.colspan("2"), dom.h2("Global", style({ margin: "0" })))), [
			["c", "compose new message"],
			["/", "search"],
			["i", "open inbox"],
			["?", "help"],
			["ctrl ?", "tooltip for focused element"],
			["ctrl m", "focus message"]
		].map((t) => dom.tr(dom.td(t[0]), dom.td(t[1]))), dom.tr(dom.td(attr.colspan("2"), dom.h2("Mailbox", style({ margin: "0" })))), [
			["\u2190", "collapse"],
			["\u2192", "expand"],
			["b", "show more actions"]
		].map((t) => dom.tr(dom.td(t[0]), dom.td(t[1]))), dom.tr(dom.td(attr.colspan("2"), dom.h2("Message list", style({ margin: "1ex 0 0 0" })))), dom.tr(dom.td("\u2193", ", j"), dom.td("down one message"), dom.td(attr.rowspan("6"), css("helpSideNote", { color: "#888", borderLeft: "2px solid", borderLeftColor: "#888", paddingLeft: ".5em" }), dom.div("hold ctrl to only move focus", attr.title("ctrl-l and ctrl-u are left for the browser the handle")), dom.div("hold shift to expand selection"))), [
			[["\u2191", ", k"], "up one message"],
			["PageDown, l", "down one screen"],
			["PageUp, h", "up one screen"],
			["End, .", "to last message"],
			["Home, ,", "to first message"],
			["Space", "toggle selection of message"]
		].map((t) => dom.tr(dom.td(t[0]), dom.td(t[1]))), [
			["", ""],
			["d, Delete", "move to trash folder"],
			["D", "delete permanently"],
			["q", "move to junk folder"],
			["Q", "mark not junk"],
			["a", "move to archive folder"],
			["M", "mark unread and clear (non)junk flags"],
			["m", "mark read"],
			["u", "to next unread message"],
			["p", "to root of thread or previous thread"],
			["n", "to root of next thread"],
			["S", "select thread messages"],
			["C", "toggle thread collapse"],
			["X", "toggle thread mute, automatically marking new messages as read"],
			["\u2190", "collapse thread"],
			["\u2192", "expand thread"]
		].map((t) => dom.tr(dom.td(t[0]), dom.td(t[1]))))), dom.div(style({ width: "40em" }), dom.table(dom.tr(dom.td(attr.colspan("2"), dom.h2("Compose", style({ margin: "0" })))), [
			["ctrl Enter", "send message"],
			["ctrl shift Enter", "send message and archive thread"],
			["ctrl w", "close message"],
			["ctrl O", "add To"],
			["ctrl C", "add Cc"],
			["ctrl B", "add Bcc"],
			["ctrl Y", "add Reply-To"],
			["ctrl Backspace", "remove current address if empty"],
			["ctrl +", "add address of same type"]
		].map((t) => dom.tr(dom.td(t[0]), dom.td(t[1]))), dom.tr(dom.td(attr.colspan("2"), dom.h2("Message", style({ margin: "1ex 0 0 0" })))), [
			["r", "reply or list reply"],
			["R", "reply all"],
			["f", "forward message"],
			["e", "edit draft"],
			["v", "view attachments"],
			["t", "view text version"],
			["T", "view HTML version"],
			["o", "open message in new tab"],
			["O", "show raw message"],
			["ctrl p", "print message"],
			["I", "toggle internals"],
			["ctrl i", "toggle all headers"],
			["alt k, alt ArrowUp", "scroll up"],
			["alt j, alt ArrowDown", "scroll down"],
			["alt K", "scroll to top"],
			["alt J", "scroll to end"]
		].map((t) => dom.tr(dom.td(t[0]), dom.td(t[1]))), dom.tr(dom.td(dom.h2("Attachments", style({ margin: "1ex 0 0 0" })))), [
			["left, h", "previous attachment"],
			["right, l", "next attachment"],
			["0", "first attachment"],
			["$", "next attachment"],
			["d", "download"]
		].map((t) => dom.tr(dom.td(t[0]), dom.td(t[1])))), dom.div(style({ marginTop: "2ex", marginBottom: "1ex" }), dom.span("Underdotted text", attr.title("Underdotted text shows additional information on hover.")), " show an explanation or additional information when hovered."), dom.div(style({ marginBottom: "1ex" }), "Multiple messages can be selected by clicking messages while holding the control and/or shift keys. Dragging messages and dropping them on a mailbox moves the messages to that mailbox."), dom.div(style({ marginBottom: "1ex" }), "Text that changes ", dom.span(attr.title("Unicode blocks, e.g. from basic latin to cyrillic, or to emoticons."), '"character groups"'), " without whitespace has an ", dom.span(dom._class("scriptswitch"), "orange underline"), ", which can be a sign of an intent to mislead (e.g. phishing)."), dom.div(style({ marginTop: "2ex" }), "Mox is open source email server software, this is version ", moxversion, ", see ", dom.a(attr.href("licenses.txt"), "licenses"), ".", dom.br(), "Feedback, including bug reports, is appreciated! ", link("https://github.com/mjl-/mox/issues/new")))));
	}, "cmdHelp");
	var cmdTooltip = /* @__PURE__ */ __name(async () => {
		let elems = [];
		if (document.activeElement && document.activeElement !== document.body) {
			if (document.activeElement.getAttribute("title")) {
				elems = [document.activeElement];
			}
			elems = [...elems, ...document.activeElement.querySelectorAll("[title]")];
		}
		if (elems.length === 0) {
			const seen = {};
			elems = [...document.body.querySelectorAll("[title]:not(.notooltip):not(.silenttitle)")].filter((e) => {
				const title = e.getAttribute("title") || "";
				if (seen[title]) {
					return false;
				}
				seen[title] = true;
				return !(e instanceof HTMLInputElement || e instanceof HTMLSelectElement || e instanceof HTMLButtonElement || e instanceof HTMLTextAreaElement || e instanceof HTMLAnchorElement || e.getAttribute("tabindex") || e.closest("[tabindex]"));
			});
		}
		if (elems.length === 0) {
			window.alert("No active elements with tooltips found.");
			return;
		}
		popover(document.body, { transparent: true, fullscreen: true }, ...elems.map((e) => {
			const title = e.getAttribute("title") || "";
			const pos = e.getBoundingClientRect();
			return dom.div(css("tooltipContent", { position: "absolute", backgroundColor: ["black", "white"], color: ["white", "black"], borderRadius: ".15em", padding: ".15em .25em", maxWidth: "50em" }), pos.x < window.innerWidth / 3 ? style({ left: "" + pos.x + "px" }) : style({ right: "" + (window.innerWidth - pos.x - pos.width) + "px" }), pos.y + pos.height > window.innerHeight * 2 / 3 ? style({ bottom: "" + (window.innerHeight - (pos.y - 2)) + "px", maxHeight: "" + (pos.y - 2) + "px" }) : style({ top: "" + (pos.y + pos.height + 2) + "px", maxHeight: "" + (window.innerHeight - (pos.y + pos.height + 2)) + "px" }), title);
		}));
	}, "cmdTooltip");
	var composeView = null;
	var compose = /* @__PURE__ */ __name((opts, listMailboxes, setLocationHash) => {
		log("compose", opts);
		if (composeView) {
			window.alert("Can only compose one message at a time.");
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
		let replyToCell, toCell, ccCell, bccCell;
		let toRow, replyToRow, ccRow, bccRow;
		let toViews = [], replytoViews = [], ccViews = [], bccViews = [];
		let forwardAttachmentViews = [];
		let draftMessageID = opts.draftMessageID || 0;
		let draftSaveTimer = 0;
		let draftSavePromise = Promise.resolve(0);
		let draftLastText = opts.body;
		const draftCancelSaveTimer = /* @__PURE__ */ __name(() => {
			if (draftSaveTimer) {
				window.clearTimeout(draftSaveTimer);
				draftSaveTimer = 0;
			}
		}, "draftCancelSaveTimer");
		const draftScheduleSave = /* @__PURE__ */ __name(() => {
			if (draftSaveTimer || body.value === draftLastText) {
				return;
			}
			draftSaveTimer = window.setTimeout(async () => {
				draftSaveTimer = 0;
				await withStatus("Saving draft", draftSave());
				draftScheduleSave();
			}, 60 * 1e3);
		}, "draftScheduleSave");
		const draftSave = /* @__PURE__ */ __name(async () => {
			draftCancelSaveTimer();
			let replyTo = "";
			if (replytoViews && replytoViews.length === 1 && replytoViews[0].input.value) {
				replyTo = replytoViews[0].input.value;
			}
			const cm = {
				From: customFrom ? customFrom.value : from.value,
				To: toViews.map((v) => v.input.value).filter((s) => s),
				Cc: ccViews.map((v) => v.input.value).filter((s) => s),
				Bcc: bccViews.map((v) => v.input.value).filter((s) => s),
				ReplyTo: replyTo,
				Subject: subject.value,
				TextBody: body.value,
				ResponseMessageID: opts.responseMessageID || 0,
				DraftMessageID: draftMessageID
			};
			const mbdrafts = listMailboxes().find((mb) => mb.Draft);
			if (!mbdrafts) {
				throw new Error("no designated drafts mailbox");
			}
			draftSavePromise = client.MessageCompose(cm, mbdrafts.ID);
			try {
				draftMessageID = await draftSavePromise;
				cv.MsgID = draftMessageID;
				setLocationHash();
			} finally {
				draftSavePromise = Promise.resolve(0);
			}
			draftLastText = cm.TextBody;
		}, "draftSave");
		const unsavedChanges = /* @__PURE__ */ __name(() => opts.body !== body.value && (!draftMessageID || draftLastText !== body.value), "unsavedChanges");
		const cmdClose = /* @__PURE__ */ __name(async () => {
			draftCancelSaveTimer();
			await draftSavePromise;
			if (unsavedChanges()) {
				const action = await new Promise((resolve) => {
					const remove = popup(dom.p(dom.b("Message has unsaved changes")), dom.br(), dom.div(dom.clickbutton("Save draft", /* @__PURE__ */ __name(function click() {
						resolve("save");
						remove();
					}, "click")), " ", draftMessageID ? dom.clickbutton("Remove draft", /* @__PURE__ */ __name(function click() {
						resolve("remove");
						remove();
					}, "click")) : [], " ", dom.clickbutton("Discard changes", /* @__PURE__ */ __name(function click() {
						resolve("discard");
						remove();
					}, "click")), " ", dom.clickbutton("Cancel", /* @__PURE__ */ __name(function click() {
						resolve("cancel");
						remove();
					}, "click"))));
				});
				if (action === "save") {
					await withStatus("Saving draft", draftSave());
				} else if (action === "remove") {
					if (draftMessageID) {
						await withStatus("Removing draft", client.MessageDelete([draftMessageID]));
					}
				} else if (action === "cancel") {
					return;
				}
			}
			composeElem.remove();
			composeView = null;
			setLocationHash();
		}, "cmdClose");
		const cmdSave = /* @__PURE__ */ __name(async () => {
			draftCancelSaveTimer();
			await draftSavePromise;
			await withStatus("Saving draft", draftSave());
		}, "cmdSave");
		const submit = /* @__PURE__ */ __name(async (archive) => {
			draftCancelSaveTimer();
			await draftSavePromise;
			const files = await new Promise((resolve, reject) => {
				const l = [];
				if (attachments.files && attachments.files.length === 0) {
					resolve(l);
					return;
				}
				[...attachments.files].forEach((f) => {
					const fr = new window.FileReader();
					fr.addEventListener("load", () => {
						l.push({ Filename: f.name, DataURI: fr.result });
						if (attachments.files && l.length === attachments.files.length) {
							resolve(l);
						}
					});
					fr.addEventListener("error", () => {
						reject(fr.error);
					});
					fr.readAsDataURL(f);
				});
			});
			let replyTo = "";
			if (replytoViews && replytoViews.length === 1 && replytoViews[0].input.value) {
				replyTo = replytoViews[0].input.value;
			}
			const forwardAttachmentPaths = forwardAttachmentViews.filter((v) => v.checkbox.checked).map((v) => v.path);
			const message = {
				From: customFrom ? customFrom.value : from.value,
				To: toViews.map((v) => v.input.value).filter((s) => s),
				Cc: ccViews.map((v) => v.input.value).filter((s) => s),
				Bcc: bccViews.map((v) => v.input.value).filter((s) => s),
				ReplyTo: replyTo,
				UserAgent: "moxwebmail/" + moxversion,
				Subject: subject.value,
				TextBody: body.value,
				Attachments: files,
				ForwardAttachments: forwardAttachmentPaths.length === 0 ? { MessageID: 0, Paths: [] } : { MessageID: opts.attachmentsMessageItem.Message.ID, Paths: forwardAttachmentPaths },
				IsForward: opts.isForward || false,
				ResponseMessageID: opts.responseMessageID || 0,
				RequireTLS: requiretls.value === "" ? null : requiretls.value === "yes",
				FutureRelease: scheduleTime.value ? new Date(scheduleTime.value) : null,
				ArchiveThread: archive,
				ArchiveReferenceMailboxID: opts.archiveReferenceMailboxID || 0,
				DraftMessageID: draftMessageID
			};
			await client.MessageSubmit(message);
			composeElem.remove();
			composeView = null;
			setLocationHash();
		}, "submit");
		const cmdSend = /* @__PURE__ */ __name(async () => {
			await withStatus("Sending email", submit(false), fieldset);
		}, "cmdSend");
		const cmdSendArchive = /* @__PURE__ */ __name(async () => {
			await withStatus("Sending email and archive", submit(true), fieldset);
		}, "cmdSendArchive");
		const cmdAddTo = /* @__PURE__ */ __name(async () => {
			newAddrView("", true, true, toViews, toBtn, toCell, toRow);
		}, "cmdAddTo");
		const cmdAddCc = /* @__PURE__ */ __name(async () => {
			newAddrView("", true, false, ccViews, ccBtn, ccCell, ccRow);
		}, "cmdAddCc");
		const cmdAddBcc = /* @__PURE__ */ __name(async () => {
			newAddrView("", true, false, bccViews, bccBtn, bccCell, bccRow);
		}, "cmdAddBcc");
		const cmdReplyTo = /* @__PURE__ */ __name(async () => {
			newAddrView("", false, false, replytoViews, replyToBtn, replyToCell, replyToRow, true);
		}, "cmdReplyTo");
		const cmdCustomFrom = /* @__PURE__ */ __name(async () => {
			if (customFrom) {
				return;
			}
			customFrom = dom.input(attr.value(from.value), attr.required(""), focusPlaceholder("Jane <jane@example.org>"));
			from.replaceWith(customFrom);
			customFromBtn.remove();
		}, "cmdCustomFrom");
		const shortcuts = {
			"ctrl Enter": cmdSend,
			"ctrl shift Enter": cmdSendArchive,
			"ctrl w": cmdClose,
			"ctrl O": cmdAddTo,
			"ctrl C": cmdAddCc,
			"ctrl B": cmdAddBcc,
			"ctrl Y": cmdReplyTo,
			"ctrl s": cmdSave,
			"ctrl S": cmdClose
			// ctrl Backspace and ctrl = (+) not included, they are handled by keydown handlers on in the inputs they remove/add.
		};
		const newAddrView = /* @__PURE__ */ __name((addr, isRecipient, isTo, views, btn, cell, row, single) => {
			if (single && views.length !== 0) {
				return;
			}
			let rcptSecPromise = null;
			let rcptSecAddr = "";
			let rcptSecAborter = {};
			let autosizeElem, inputElem, securityBar;
			const fetchRecipientSecurity = /* @__PURE__ */ __name(() => {
				if (!accountSettings?.ShowAddressSecurity) {
					return;
				}
				if (inputElem.value === rcptSecAddr) {
					return;
				}
				securityBar.style.borderImage = "";
				rcptSecAddr = inputElem.value;
				if (!inputElem.value) {
					return;
				}
				if (rcptSecAborter.abort) {
					rcptSecAborter.abort();
					rcptSecAborter.abort = void 0;
				}
				const color = /* @__PURE__ */ __name((v2) => {
					if (v2 === SecurityResult.SecurityResultYes) {
						return styles.underlineGreen;
					} else if (v2 === SecurityResult.SecurityResultNo) {
						return styles.underlineRed;
					} else if (v2 === SecurityResult.SecurityResultUnknown) {
						return "transparent";
					}
					return styles.underlineGrey;
				}, "color");
				const setBar = /* @__PURE__ */ __name((c0, c1, c2, c3, c4) => {
					const stops = [
						c0 + " 0%",
						c0 + " 19%",
						"transparent 19%",
						"transparent 20%",
						c1 + " 20%",
						c1 + " 39%",
						"transparent 39%",
						"transparent 40%",
						c2 + " 40%",
						c2 + " 59%",
						"transparent 59%",
						"transparent 60%",
						c3 + " 60%",
						c3 + " 79%",
						"transparent 79%",
						"transparent 80%",
						c4 + " 80%",
						c4 + " 100%"
					].join(", ");
					securityBar.style.borderImage = "linear-gradient(to right, " + stops + ") 1";
				}, "setBar");
				const aborter = {};
				rcptSecAborter = aborter;
				rcptSecPromise = client.withOptions({ aborter }).RecipientSecurity(inputElem.value);
				rcptSecPromise.then((rs) => {
					setBar(color(rs.STARTTLS), color(rs.MTASTS), color(rs.DNSSEC), color(rs.DANE), color(rs.RequireTLS));
					const implemented = [];
					const check = /* @__PURE__ */ __name((v2, s) => {
						if (v2) {
							implemented.push(s);
						}
					}, "check");
					check(rs.STARTTLS === SecurityResult.SecurityResultYes, "STARTTLS");
					check(rs.MTASTS === SecurityResult.SecurityResultYes, "MTASTS");
					check(rs.DNSSEC === SecurityResult.SecurityResultYes, "DNSSEC");
					check(rs.DANE === SecurityResult.SecurityResultYes, "DANE");
					check(rs.RequireTLS === SecurityResult.SecurityResultYes, "RequireTLS");
					const status = "Security mechanisms known to be implemented by the recipient domain: " + (implemented.length === 0 ? "(none)" : implemented.join(", ")) + ".";
					inputElem.setAttribute("title", status + "\n\n" + recipientSecurityTitle);
					aborter.abort = void 0;
					v.recipientSecurity = rs;
					if (isRecipient) {
						let reqtls = opts.isList !== true;
						const walk = /* @__PURE__ */ __name((l) => {
							for (const v2 of l) {
								if (v2.recipientSecurity?.RequireTLS !== SecurityResult.SecurityResultYes || v2.recipientSecurity?.MTASTS !== SecurityResult.SecurityResultYes && v2.recipientSecurity?.DANE !== SecurityResult.SecurityResultYes) {
									reqtls = false;
									break;
								}
							}
						}, "walk");
						walk(toViews);
						walk(ccViews);
						walk(bccViews);
						if (requiretls.value === "" || requiretls.value === "yes") {
							requiretls.value = reqtls ? "yes" : "";
						}
					}
				}, () => {
					setBar("#888", "#888", "#888", "#888", "#888");
					inputElem.setAttribute("title", "Error fetching security mechanisms known to be implemented by the recipient domain...\n\n" + recipientSecurityTitle);
					aborter.abort = void 0;
					if (requiretls.value === "yes") {
						requiretls.value = "";
					}
				});
			}, "fetchRecipientSecurity");
			const recipientSecurityTitle = "Description of security mechanisms recipient domains may implement:\n1. STARTTLS: Opportunistic (unverified) TLS with STARTTLS, successfully negotiated during the most recent delivery attempt.\n2. MTA-STS: For PKIX/WebPKI-verified TLS.\n3. DNSSEC: MX DNS records are DNSSEC-signed.\n4. DANE: First delivery destination host implements DANE for verified TLS.\n5. RequireTLS: SMTP extension for verified TLS delivery into recipient mailbox, support detected during the most recent delivery attempt.\n\nChecks STARTTLS, DANE and RequireTLS cover the most recently used delivery path, not necessarily all possible delivery paths.\n\nThe bars below the input field indicate implementation status by the recipient domain:\n- Red, not implemented/unsupported\n- Green, implemented/supported\n- Gray, error while determining\n- Absent/white, unknown or skipped (e.g. no previous delivery attempt, or DANE check skipped due to DNSSEC-lookup error)";
			const root = dom.span(autosizeElem = dom.span(dom._class("autosize"), inputElem = dom.input(focusPlaceholder("Jane <jane@example.org>"), style({ width: "auto" }), attr.value(addr), newAddressComplete(), accountSettings?.ShowAddressSecurity ? attr.title(recipientSecurityTitle) : [], /* @__PURE__ */ __name(function keydown(e) {
				if (e.key === "Backspace" && e.ctrlKey && inputElem.value === "" && !(isTo && views.length === 1)) {
					remove();
				} else if (e.key === "=" && e.ctrlKey) {
					newAddrView("", isRecipient, isTo, views, btn, cell, row, single);
				} else {
					return;
				}
				e.preventDefault();
				e.stopPropagation();
			}, "keydown"), /* @__PURE__ */ __name(function input() {
				autosizeElem.dataset.value = inputElem.value;
			}, "input"), /* @__PURE__ */ __name(function change() {
				autosizeElem.dataset.value = inputElem.value;
				fetchRecipientSecurity();
			}, "change"), /* @__PURE__ */ __name(function paste(e) {
				const data = e.clipboardData?.getData("text/plain");
				if (typeof data !== "string" || data === "") {
					return;
				}
				const split = data.split(",");
				if (split.length <= 1) {
					return;
				}
				autosizeElem.dataset.value = inputElem.value = split[0];
				let last;
				for (const rest of split.splice(1)) {
					last = newAddrView(rest.trim(), isRecipient, isTo, views, btn, cell, row, single);
				}
				last.input.focus();
				e.preventDefault();
				e.stopPropagation();
			}, "paste")), securityBar = dom.span(css("securitybar", {
				margin: "0 1px",
				borderBottom: "1.5px solid",
				borderBottomColor: "transparent"
			}))), " ", dom.clickbutton("-", style({ padding: "0 .25em" }), attr.arialabel("Remove address."), attr.title("Remove address."), /* @__PURE__ */ __name(function click() {
				remove();
				if (single && views.length === 0) {
					btn.style.display = "";
				}
			}, "click")), " ");
			autosizeElem.dataset.value = inputElem.value;
			const remove = /* @__PURE__ */ __name(() => {
				const i = views.indexOf(v);
				views.splice(i, 1);
				root.remove();
				if (views.length === 0) {
					row.style.display = "none";
				}
				if (views.length === 0 && single) {
					btn.style.display = "";
				}
				let next = cell.querySelector("input");
				if (!next) {
					let tr = row.nextSibling;
					while (tr) {
						next = tr.querySelector("input");
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
			}, "remove");
			const v = { root, input: inputElem, isRecipient, recipientSecurity: null };
			fetchRecipientSecurity();
			views.push(v);
			cell.appendChild(v.root);
			row.style.display = "";
			if (single) {
				btn.style.display = "none";
			}
			inputElem.focus();
			return v;
		}, "newAddrView");
		let noAttachmentsWarning;
		const checkAttachments = /* @__PURE__ */ __name(() => {
			const missingAttachments = !attachments.files?.length && !forwardAttachmentViews.find((v) => v.checkbox.checked) && !!body.value.split("\n").find((s) => !s.startsWith(">") && s.match(/attach(ed|ment)/));
			noAttachmentsWarning.style.display = missingAttachments ? "" : "none";
		}, "checkAttachments");
		const normalizeUser = /* @__PURE__ */ __name((a) => {
			let user = a.User;
			const domconf = domainAddressConfigs[a.Domain.ASCII];
			for (const sep of domconf.LocalpartCatchallSeparators || []) {
				user = user.split(sep)[0];
			}
			const localpartCaseSensitive = domconf.LocalpartCaseSensitive;
			if (!localpartCaseSensitive) {
				user = user.toLowerCase();
			}
			return user;
		}, "normalizeUser");
		const addressSelf = /* @__PURE__ */ __name((addr) => {
			return accountAddresses.find((a) => a.Domain.ASCII === addr.Domain.ASCII && (a.User === "" || normalizeUser(a) === normalizeUser(addr)));
		}, "addressSelf");
		let haveFrom = false;
		const fromOptions = accountAddresses.filter((a) => a.User).map((a) => {
			const selected = opts.from && opts.from.length === 1 && equalAddress(a, opts.from[0]) || loginAddress && equalAddress(a, loginAddress) && (!opts.from || envelopeIdentity(opts.from));
			const o = dom.option(formatAddress(a), selected ? attr.selected("") : []);
			if (selected) {
				haveFrom = true;
			}
			return o;
		});
		if (!haveFrom && opts.from && opts.from.length === 1) {
			const a = addressSelf(opts.from[0]);
			if (a) {
				const fromAddr = { Name: a.Name, User: opts.from[0].User, Domain: a.Domain };
				const o = dom.option(formatAddress(fromAddr), attr.selected(""));
				fromOptions.unshift(o);
			}
		}
		let scheduleLink;
		let scheduleElem;
		let scheduleTime;
		let scheduleWeekday;
		const pad0 = /* @__PURE__ */ __name((v) => v >= 10 ? "" + v : "0" + v, "pad0");
		const localdate = /* @__PURE__ */ __name((d) => [d.getFullYear(), pad0(d.getMonth() + 1), pad0(d.getDate())].join("-"), "localdate");
		const localdatetime = /* @__PURE__ */ __name((d) => localdate(d) + "T" + pad0(d.getHours()) + ":" + pad0(d.getMinutes()) + ":00", "localdatetime");
		const weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
		const scheduleTimeChanged = /* @__PURE__ */ __name(() => {
			log("datetime change", scheduleTime.value);
			dom._kids(scheduleWeekday, weekdays[new Date(scheduleTime.value).getDay()]);
		}, "scheduleTimeChanged");
		let resizeLast = null;
		let resizeTimer = 0;
		const initWidth = window.innerWidth === settings.composeViewportWidth ? settings.composeWidth : 0;
		const initHeight = window.innerHeight === settings.composeViewportHeight ? settings.composeHeight : 0;
		const composeTextMildStyle = css("composeTextMild", { textAlign: "right", color: styles.colorMild });
		const composeCellStyle = css("composeCell", { lineHeight: "1.5" });
		const composeElem = dom.div(css("composePopup", {
			position: "fixed",
			bottom: "1ex",
			right: "1ex",
			zIndex: zindexes.compose,
			backgroundColor: styles.popupBackgroundColor,
			boxShadow: styles.boxShadow,
			border: "1px solid",
			borderColor: styles.popupBorderColor,
			padding: "1em",
			minWidth: "40em",
			maxWidth: "95vw",
			borderRadius: ".25em",
			display: "flex",
			flexDirection: "column"
		}), initWidth ? style({ width: initWidth + "px" }) : [], initHeight ? style({ height: initHeight + "px" }) : [], dom.div(css("composeResizeGrab", { position: "absolute", marginTop: "-1em", marginLeft: "-1em", width: "1em", height: "1em", cursor: "nw-resize" }), /* @__PURE__ */ __name(async function mousedown(e) {
			page.style.pointerEvents = "none";
			resizeLast = null;
			await startDrag(e, (e2) => {
				if (resizeLast) {
					const bounds = composeElem.getBoundingClientRect();
					const width = Math.round(bounds.width + resizeLast.x - e2.clientX);
					const height = Math.round(bounds.height + resizeLast.y - e2.clientY);
					composeElem.style.width = width + "px";
					composeElem.style.height = height + "px";
					body.removeAttribute("rows");
					if (resizeTimer) {
						window.clearTimeout(resizeTimer);
					}
					resizeTimer = window.setTimeout(() => {
						settingsPut({ ...settings, composeWidth: width, composeHeight: height, composeViewportWidth: window.innerWidth, composeViewportHeight: window.innerHeight });
					}, 1e3);
				}
				resizeLast = { x: e2.clientX, y: e2.clientY };
			});
			page.style.pointerEvents = "";
		}, "mousedown")), dom.form(css("composeForm", {
			flexGrow: "1",
			display: "flex",
			flexDirection: "column"
		}), fieldset = dom.fieldset(css("composeFields", {
			flexGrow: "1",
			display: "flex",
			flexDirection: "column"
		}), dom.table(style({ width: "100%" }), dom.tr(dom.td(composeTextMildStyle, dom.span("From:")), dom.td(dom.div(css("composeButtonsSpread", { display: "flex", gap: "1em", justifyContent: "space-between" }), dom.div(from = dom.select(attr.required(""), style({ width: "auto" }), fromOptions), " ", toBtn = dom.clickbutton("To", clickCmd(cmdAddTo, shortcuts)), " ", ccBtn = dom.clickbutton("Cc", clickCmd(cmdAddCc, shortcuts)), " ", bccBtn = dom.clickbutton("Bcc", clickCmd(cmdAddBcc, shortcuts)), " ", replyToBtn = dom.clickbutton("ReplyTo", clickCmd(cmdReplyTo, shortcuts)), " ", customFromBtn = dom.clickbutton("From", attr.title("Set custom From address/name."), clickCmd(cmdCustomFrom, shortcuts))), dom.div(listMailboxes().find((mb) => mb.Draft) ? [
			dom.clickbutton("Save", attr.title("Save draft message."), clickCmd(cmdSave, shortcuts)),
			" "
		] : [], dom.clickbutton("Close", attr.title("Close window, saving draft message if body has changed or a draft was saved earlier."), clickCmd(cmdClose, shortcuts)))))), toRow = dom.tr(dom.td("To:", composeTextMildStyle), toCell = dom.td(composeCellStyle)), replyToRow = dom.tr(dom.td("Reply-To:", composeTextMildStyle), replyToCell = dom.td(composeCellStyle)), ccRow = dom.tr(dom.td("Cc:", composeTextMildStyle), ccCell = dom.td(composeCellStyle)), bccRow = dom.tr(dom.td("Bcc:", composeTextMildStyle), bccCell = dom.td(composeCellStyle)), dom.tr(dom.td("Subject:", composeTextMildStyle), dom.td(subjectAutosize = dom.span(
			dom._class("autosize"),
			style({ width: "100%" }),
			// Without 100% width, the span takes minimal width for input, we want the full table cell.
			subject = dom.input(style({ width: "100%" }), attr.value(opts.subject || ""), attr.required(""), focusPlaceholder("subject..."), /* @__PURE__ */ __name(function input() {
				subjectAutosize.dataset.value = subject.value;
			}, "input"))
		)))), body = dom.textarea(
			dom._class("mono"),
			style({
				flexGrow: "1",
				width: "100%"
			}),
			initHeight === 0 ? attr.rows("15") : [],
			// Drives default size, removed on compose window resize.
			// Explicit string object so it doesn't get the highlight-unicode-block-changes
			// treatment, which would cause characters to disappear.
			new String(opts.body || ""),
			prop({ selectionStart: opts.editOffset || 0, selectionEnd: opts.editOffset || 0 }),
			/* @__PURE__ */ __name(function keyup(e) {
				if (e.key === "Enter") {
					checkAttachments();
				}
			}, "keyup"),
			!listMailboxes().find((mb) => mb.Draft) ? [] : /* @__PURE__ */ __name(function input() {
				draftScheduleSave();
			}, "input")
		), !(opts.attachmentsMessageItem && opts.attachmentsMessageItem.Attachments && opts.attachmentsMessageItem.Attachments.length > 0) ? [] : dom.div(style({ margin: ".5em 0" }), "Forward attachments: ", forwardAttachmentViews = (opts.attachmentsMessageItem?.Attachments || []).map((a) => {
			const filename = a.Filename || "(unnamed)";
			const size = formatSize(a.Part.DecodedSize);
			const checkbox = dom.input(attr.type("checkbox"), /* @__PURE__ */ __name(function change() {
				checkAttachments();
			}, "change"));
			const root = dom.label(checkbox, " " + filename + " ", dom.span("(" + size + ") ", styleClasses.textMild));
			const v = {
				path: a.Path || [],
				root,
				checkbox
			};
			return v;
		}), dom.label(styleClasses.textMild, dom.input(attr.type("checkbox"), /* @__PURE__ */ __name(function change(e) {
			forwardAttachmentViews.forEach((v) => v.checkbox.checked = e.target.checked);
		}, "change")), " (Toggle all)")), noAttachmentsWarning = dom.div(style({ display: "none" }), css("composeNoAttachmentsWarning", { backgroundColor: styles.warningBackgroundColor, padding: "0.15em .25em", margin: ".5em 0" }), "Message mentions attachments, but no files are attached."), dom.label(style({ margin: "1ex 0", display: "block" }), "Attachments ", attachments = dom.input(attr.type("file"), attr.multiple(""), /* @__PURE__ */ __name(function change() {
			checkAttachments();
		}, "change"))), dom.label(style({ margin: "1ex 0", display: "block" }), attr.title("How to use TLS for message delivery over SMTP:\n\nDefault: Delivery attempts follow the policies published by the recipient domain: Verification with MTA-STS and/or DANE, or optional opportunistic unverified STARTTLS if the domain does not specify a policy.\n\nWith RequireTLS: For sensitive messages, you may want to require verified TLS. The recipient destination domain SMTP server must support the REQUIRETLS SMTP extension for delivery to succeed. It is automatically chosen when the destination domain mail servers of all recipients are known to support it.\n\nFallback to insecure: If delivery fails due to MTA-STS and/or DANE policies specified by the recipient domain, and the content is not sensitive, you may choose to ignore the recipient domain TLS policies so delivery can succeed."), "TLS ", requiretls = dom.select(dom.option(attr.value(""), "Default"), dom.option(attr.value("yes"), "With RequireTLS"), dom.option(attr.value("no"), "Fallback to insecure"))), dom.div(scheduleLink = dom.a(attr.href(""), "Schedule", /* @__PURE__ */ __name(function click(e) {
			e.preventDefault();
			scheduleTime.value = localdatetime(/* @__PURE__ */ new Date());
			scheduleTimeChanged();
			scheduleLink.style.display = "none";
			scheduleElem.style.display = "";
			scheduleTime.setAttribute("required", "");
		}, "click")), scheduleElem = dom.div(style({ display: "none" }), dom.clickbutton("Start of next day", /* @__PURE__ */ __name(function click(e) {
			e.preventDefault();
			const d = new Date(scheduleTime.value);
			const nextday = new Date(d.getTime() + 24 * 3600 * 1e3);
			scheduleTime.value = localdate(nextday) + "T09:00:00";
			scheduleTimeChanged();
		}, "click")), " ", dom.clickbutton("+1 hour", /* @__PURE__ */ __name(function click(e) {
			e.preventDefault();
			const d = new Date(scheduleTime.value);
			scheduleTime.value = localdatetime(new Date(d.getTime() + 3600 * 1e3));
			scheduleTimeChanged();
		}, "click")), " ", dom.clickbutton("+1 day", /* @__PURE__ */ __name(function click(e) {
			e.preventDefault();
			const d = new Date(scheduleTime.value);
			scheduleTime.value = localdatetime(new Date(d.getTime() + 24 * 3600 * 1e3));
			scheduleTimeChanged();
		}, "click")), " ", dom.clickbutton("Now", /* @__PURE__ */ __name(function click(e) {
			e.preventDefault();
			scheduleTime.value = localdatetime(/* @__PURE__ */ new Date());
			scheduleTimeChanged();
		}, "click")), " ", dom.clickbutton("Cancel", /* @__PURE__ */ __name(function click(e) {
			e.preventDefault();
			scheduleLink.style.display = "";
			scheduleElem.style.display = "none";
			scheduleTime.removeAttribute("required");
			scheduleTime.value = "";
		}, "click")), dom.div(style({ marginTop: "1ex" }), scheduleTime = dom.input(attr.type("datetime-local"), /* @__PURE__ */ __name(function change() {
			scheduleTimeChanged();
		}, "change")), " in local timezone " + (Intl.DateTimeFormat().resolvedOptions().timeZone || "") + ", ", scheduleWeekday = dom.span()))), dom.div(style({ margin: "3ex 0 1ex 0", display: "block" }), dom.submitbutton("Send"), " ", opts.responseMessageID && listMailboxes().find((mb) => mb.Archive) ? dom.clickbutton("Send and archive thread", clickCmd(cmdSendArchive, shortcuts)) : [])), /* @__PURE__ */ __name(async function submit2(e) {
			e.preventDefault();
			shortcutCmd(cmdSend, shortcuts);
		}, "submit")));
		subjectAutosize.dataset.value = subject.value;
		(opts.to && opts.to.length > 0 ? opts.to : [""]).forEach((s) => newAddrView(s, true, true, toViews, toBtn, toCell, toRow));
		(opts.cc || []).forEach((s) => newAddrView(s, true, false, ccViews, ccBtn, ccCell, ccRow));
		(opts.bcc || []).forEach((s) => newAddrView(s, true, false, bccViews, bccBtn, bccCell, bccRow));
		if (opts.replyto) {
			newAddrView(opts.replyto, false, false, replytoViews, replyToBtn, replyToCell, replyToRow, true);
		}
		if (!opts.cc || !opts.cc.length) {
			ccRow.style.display = "none";
		}
		if (!opts.bcc || !opts.bcc.length) {
			bccRow.style.display = "none";
		}
		if (!opts.replyto) {
			replyToRow.style.display = "none";
		}
		document.body.appendChild(composeElem);
		if (toViews.length > 0 && !toViews[0].input.value) {
			toViews[0].input.focus();
		} else {
			body.focus();
		}
		const cv = {
			root: composeElem,
			MsgID: draftMessageID,
			key: keyHandler(shortcuts),
			unsavedChanges,
			save: cmdSave
		};
		composeView = cv;
		setLocationHash();
	}, "compose");
	var composeDraft = /* @__PURE__ */ __name(async (mi, pm, listMailboxes, setLocationHash) => {
		const m = mi.Message;
		const draftMailboxID = listMailboxes().find((mb) => mb.Draft)?.ID;
		if (m.MailboxID !== draftMailboxID) {
			throw new Error("only messages in draft mailbox can be edited");
		}
		const env = mi.Envelope;
		let refMsgID = 0;
		if (env.InReplyTo) {
			refMsgID = await withStatus("Looking up referenced message", client.MessageFindMessageID(env.InReplyTo));
		}
		const isForward = !!env.Subject.match(/^\[?fwd?:/i) || !!env.Subject.match(/\(fwd\)[ \t]*$/i);
		const opts = {
			from: env.From || [],
			to: (env.To || []).map((a) => formatAddress(a)),
			cc: (env.CC || []).map((a) => formatAddress(a)),
			bcc: (env.BCC || []).map((a) => formatAddress(a)),
			replyto: env.ReplyTo && env.ReplyTo.length > 0 ? formatAddress(env.ReplyTo[0]) : "",
			subject: env.Subject,
			isForward,
			body: pm.Texts && pm.Texts.length > 0 ? pm.Texts[0].replace(/\r/g, "") : "",
			responseMessageID: refMsgID,
			draftMessageID: m.ID
		};
		compose(opts, listMailboxes, setLocationHash);
	}, "composeDraft");
	var labelsPopover = /* @__PURE__ */ __name((e, msgs, possibleLabels) => {
		if (msgs.length === 0) {
			return;
		}
		const knownLabels = possibleLabels();
		const activeLabels = (msgs[0].Keywords || []).filter((kw) => msgs.filter((m) => (m.Keywords || []).includes(kw)).length === msgs.length);
		const msgIDs = msgs.map((m) => m.ID);
		let fieldsetnew;
		let newlabel;
		const remove = popover(e.target, {}, dom.div(css("popoverLabels", { display: "flex", flexDirection: "column", gap: "1ex" }), knownLabels.map((l) => dom.div(dom.label(dom.input(attr.type("checkbox"), activeLabels.includes(l) ? attr.checked("") : [], style({ marginRight: ".5em" }), attr.title("Add/remove this label to the message(s), leaving other labels unchanged."), /* @__PURE__ */ __name(async function change(e2) {
			if (activeLabels.includes(l)) {
				await withStatus("Removing label", client.FlagsClear(msgIDs, [l]), e2.target);
				activeLabels.splice(activeLabels.indexOf(l), 1);
			} else {
				await withStatus("Adding label", client.FlagsAdd(msgIDs, [l]), e2.target);
				activeLabels.push(l);
			}
		}, "change")), " ", dom.span(styleClasses.keyword, l))))), dom.hr(style({ margin: "2ex 0" })), dom.form(/* @__PURE__ */ __name(async function submit(e2) {
			e2.preventDefault();
			await withStatus("Adding new label", client.FlagsAdd(msgIDs, [newlabel.value]), fieldsetnew);
			remove();
		}, "submit"), fieldsetnew = dom.fieldset(dom.div(newlabel = dom.input(focusPlaceholder("new-label"), attr.required(""), attr.title('New label to add/set on the message(s), must be lower-case, ascii-only, without spaces and without the following special characters: (){%*"].')), " ", dom.submitbutton("Add new label", attr.title("Add this label to the message(s), leaving other labels unchanged."))))));
	}, "labelsPopover");
	var movePopover = /* @__PURE__ */ __name((e, mailboxes, msgs) => {
		if (msgs.length === 0) {
			return;
		}
		let msgsMailboxID = msgs[0].MailboxID && msgs.filter((m) => m.MailboxID === msgs[0].MailboxID).length === msgs.length ? msgs[0].MailboxID : 0;
		const remove = popover(e.target, {}, dom.div(css("popoverMove", { display: "flex", flexDirection: "column", gap: ".25em" }), mailboxes.map((mb) => dom.div(dom.clickbutton(mb.Name, mb.ID === msgsMailboxID ? attr.disabled("") : [], /* @__PURE__ */ __name(async function click() {
			const moveMsgs = msgs.filter((m) => m.MailboxID !== mb.ID);
			const msgIDs = moveMsgs.map((m) => m.ID);
			await withStatus("Moving to mailbox", client.MessageMove(msgIDs, mb.ID, false));
			if (moveMsgs.length === 1) {
				await moveAskRuleset(moveMsgs[0].ID, moveMsgs[0].MailboxID, mb, mailboxes);
			}
			remove();
		}, "click"))))));
	}, "movePopover");
	var moveAskRuleset = /* @__PURE__ */ __name(async (msgID, mbSrcID, mbDst, mailboxes) => {
		const mbSrc = mailboxes.find((mb) => mb.ID === mbSrcID);
		if (!mbSrc || isSpecialUse(mbDst) || isSpecialUse(mbSrc)) {
			return;
		}
		const [listID, msgFrom, isRemove, rcptTo, ruleset] = await withStatus("Checking rulesets", client.RulesetSuggestMove(msgID, mbSrc.ID, mbDst.ID));
		if (!ruleset) {
			return;
		}
		const what = listID ? ['list with id "', listID, '"'] : ['address "', msgFrom, '"'];
		if (isRemove) {
			const remove2 = popup(dom.h1("Remove rule?"), dom.p(style({ maxWidth: "30em" }), "Would you like to remove the server-side rule that automatically delivers messages from ", what, ' to mailbox "', mbDst.Name, '"?'), dom.br(), dom.div(dom.clickbutton("Yes, remove rule", /* @__PURE__ */ __name(async function click() {
				await withStatus("Remove ruleset", client.RulesetRemove(rcptTo, ruleset));
				remove2();
			}, "click")), " ", dom.clickbutton("Not now", /* @__PURE__ */ __name(async function click() {
				remove2();
			}, "click"))), dom.br(), dom.div(style({ marginBottom: "1ex" }), dom.clickbutton("No, and don't ask again for ", what, /* @__PURE__ */ __name(async function click() {
				await withStatus("Store ruleset response", client.RulesetMessageNever(rcptTo, listID, msgFrom, true));
				remove2();
			}, "click"))), dom.div(dom.clickbutton(`No, and don't ask again when moving messages out of "`, mbSrc.Name, '"', /* @__PURE__ */ __name(async function click() {
				await withStatus("Store ruleset response", client.RulesetMailboxNever(mbSrc.ID, false));
				remove2();
			}, "click"))));
			return;
		}
		const remove = popup(dom.h1("Add rule?"), dom.p(style({ maxWidth: "30em" }), "Would you like to create a server-side ruleset that automatically delivers future messages from ", what, ' to mailbox "', mbDst.Name, '"?'), dom.br(), dom.div(dom.clickbutton("Yes, add rule", /* @__PURE__ */ __name(async function click() {
			await withStatus("Add ruleset", client.RulesetAdd(rcptTo, ruleset));
			remove();
		}, "click")), " ", dom.clickbutton("Not now", /* @__PURE__ */ __name(async function click() {
			remove();
		}, "click"))), dom.br(), dom.div(style({ marginBottom: "1ex" }), dom.clickbutton("No, and don't ask again for ", what, /* @__PURE__ */ __name(async function click() {
			await withStatus("Store ruleset response", client.RulesetMessageNever(rcptTo, listID, msgFrom, false));
			remove();
		}, "click"))), dom.div(dom.clickbutton(`No, and don't ask again when moving messages to "`, mbDst.Name, '"', /* @__PURE__ */ __name(async function click() {
			await withStatus("Store ruleset response", client.RulesetMailboxNever(mbDst.ID, true));
			remove();
		}, "click"))));
	}, "moveAskRuleset");
	var isSpecialUse = /* @__PURE__ */ __name((mb) => mb.Archive || mb.Draft || mb.Junk || mb.Sent || mb.Trash, "isSpecialUse");
	var newMsgitemView = /* @__PURE__ */ __name((mi, msglistView, otherMailbox, listMailboxes, receivedTime, initialCollapsed) => {
		let ageTimer = 0;
		const identityTag = /* @__PURE__ */ __name((s, title) => dom.span(css("msgItemIdentity", { padding: "0 .15em", marginLeft: ".15em", borderRadius: ".15em", fontWeight: "normal", fontSize: ".9em", whiteSpace: "nowrap", backgroundColor: styles.backgroundColorMilder, color: styles.color, border: "1px solid", borderColor: styles.colorMilder }), s, attr.title(title)), "identityTag");
		const identityHeader = [];
		if (!envelopeIdentity(mi.Envelope.From || []) && !envelopeIdentity(mi.Envelope.To || [])) {
			if (envelopeIdentity(mi.Envelope.CC || [])) {
				identityHeader.push(identityTag("cc", "You are in the CC header"));
			}
			if (envelopeIdentity(mi.Envelope.BCC || [])) {
				identityHeader.push(identityTag("bcc", "You are in the BCC header"));
			}
			if (identityHeader.length === 0) {
				identityHeader.push(identityTag("-", "You are not in any To, From, CC, BCC header. Could message to a mailing list or Bcc without Bcc message header."));
			}
		}
		const remove = /* @__PURE__ */ __name(() => {
			msgitemView.root.remove();
			if (ageTimer) {
				window.clearTimeout(ageTimer);
				ageTimer = 0;
			}
		}, "remove");
		const age = /* @__PURE__ */ __name((date) => {
			const r = dom.span(dom._class("notooltip"), attr.title(date.toString()));
			const set = /* @__PURE__ */ __name(() => {
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
				let nextSecs = 0;
				for (let i = 0; i < periods.length; i++) {
					const p = periods[i];
					if (t >= 2 * p || i === periods.length - 1) {
						const n = Math.round(t / p);
						s = "" + n + suffix[i];
						const prev = Math.floor(t / p);
						nextSecs = Math.ceil((prev + 1) * p - t);
						break;
					}
				}
				if (t < 60) {
					s = "<1min";
					nextSecs = 60 - t;
					negative = "";
				}
				dom._kids(r, negative + s);
				if (nextSecs < 14 * 24 * 3600) {
					ageTimer = window.setTimeout(set, nextSecs * 1e3);
				} else {
					ageTimer = 0;
				}
			}, "set");
			set();
			return r;
		}, "age");
		const render = /* @__PURE__ */ __name(() => {
			const mi2 = msgitemView.messageitem;
			const m = mi2.Message;
			if (ageTimer) {
				window.clearTimeout(ageTimer);
				ageTimer = 0;
			}
			const keywords = (m.Keywords || []).map((kw) => dom.span(styleClasses.keyword, kw));
			if (msgitemView.isCollapsedThreadRoot()) {
				const keywordsSeen = /* @__PURE__ */ new Set();
				for (const kw of m.Keywords || []) {
					keywordsSeen.add(kw);
				}
				for (const miv of msgitemView.descendants()) {
					for (const kw of miv.messageitem.Message.Keywords || []) {
						if (!keywordsSeen.has(kw)) {
							keywordsSeen.add(kw);
							keywords.push(dom.span(styleClasses.keyword, dom._class("keywordCollapsed"), kw));
						}
					}
				}
			}
			let threadIndent = 0;
			for (let miv = msgitemView; miv.parent; miv = miv.parent) {
				threadIndent++;
			}
			let threadChar = "";
			let threadCharTitle = "";
			if (msgitemView.parent) {
				threadChar = "\u21B3";
				if (msgitemView.parent.messageitem.Message.MessageID === mi2.Message.MessageID) {
					threadChar = "\u2248";
					threadCharTitle = "Same Message-ID.";
				} else if (mi2.Message.ThreadMissingLink || (mi2.Message.ThreadParentIDs || []).length > 0 && (mi2.Message.ThreadParentIDs || [])[0] !== msgitemView.parent.messageitem.Message.ID) {
					threadChar = "\u21AF";
					threadCharTitle = "Immediate parent message is missing.";
				}
			}
			const isUnread = /* @__PURE__ */ __name(() => !mi2.Message.Seen || msgitemView.isCollapsedThreadRoot() && !!msgitemView.findDescendant((miv) => !miv.messageitem.Message.Seen), "isUnread");
			const isRelevant = /* @__PURE__ */ __name(() => !mi2.Message.ThreadMuted && mi2.MatchQuery || msgitemView.isCollapsedThreadRoot() && msgitemView.findDescendant((miv) => !miv.messageitem.Message.ThreadMuted && miv.messageitem.MatchQuery), "isRelevant");
			const received = /* @__PURE__ */ __name(() => {
				let r = mi2.Message.Received;
				if (!msgitemView.isCollapsedThreadRoot()) {
					return r;
				}
				msgitemView.descendants().forEach((dmiv) => {
					if (settings.orderAsc && dmiv.messageitem.Message.Received.getTime() < r.getTime()) {
						r = dmiv.messageitem.Message.Received;
					} else if (!settings.orderAsc && dmiv.messageitem.Message.Received.getTime() > r.getTime()) {
						r = dmiv.messageitem.Message.Received;
					}
				});
				return r;
			}, "received");
			const isThreadLast = /* @__PURE__ */ __name(() => {
				let miv = msgitemView.threadRoot();
				while (miv.kids.length > 0) {
					miv = miv.kids[miv.kids.length - 1];
				}
				return miv === msgitemView;
			}, "isThreadLast");
			const mailboxtags = [];
			const mailboxIDs = /* @__PURE__ */ new Set();
			const addMailboxTag = /* @__PURE__ */ __name((mb, isCollapsedKid) => {
				let name = mb.Name;
				mailboxIDs.add(mb.ID);
				if (name.length > 8 + 1 + 3 + 1 + 8 + 4) {
					const t = name.split("/");
					const first = t[0];
					const last = t[t.length - 1];
					if (first.length + last.length <= 8 + 8) {
						name = first + "/.../" + last;
					} else {
						name = first.substring(0, 8) + "/.../" + last.substring(0, 8);
					}
				}
				const e = dom.span(css("msgItemMailbox", { padding: "0 .15em", marginLeft: ".15em", borderRadius: ".15em", fontWeight: "normal", fontSize: ".9em", whiteSpace: "nowrap", background: styles.backgroundColorMilder, color: ["white", "#ddd"], border: "1px solid", borderColor: styles.colorMilder }), isCollapsedKid ? css("msgItemMailboxCollapsed", { background: "#eee", color: "#333" }, true) : [], name === mb.Name ? [] : attr.title(mb.Name), name);
				mailboxtags.push(e);
			}, "addMailboxTag");
			const othermb = otherMailbox(m.MailboxID);
			if (othermb) {
				addMailboxTag(othermb, false);
			}
			if (msgitemView.isCollapsedThreadRoot()) {
				for (const miv of msgitemView.descendants()) {
					const m2 = miv.messageitem.Message;
					if (!mailboxIDs.has(m2.MailboxID) && otherMailbox(m2.MailboxID)) {
						const mb = listMailboxes().find((mb2) => mb2.ID === m2.MailboxID);
						if (!mb) {
							throw new ConsistencyError("missing mailbox for message in thread");
						}
						addMailboxTag(mb, true);
					}
				}
			}
			const correspondentAddrs = /* @__PURE__ */ __name((miv) => {
				let fromAddrs = miv.messageitem.Envelope.From || [];
				let toAddrs = [];
				if (listMailboxes().find((mb) => mb.ID === miv.messageitem.Message.MailboxID)?.Sent) {
					toAddrs = [...miv.messageitem.Envelope.To || [], ...miv.messageitem.Envelope.CC || [], ...miv.messageitem.Envelope.BCC || []];
				}
				return [fromAddrs, toAddrs];
			}, "correspondentAddrs");
			const correspondents = /* @__PURE__ */ __name(() => {
				let fromAddrs = [];
				let toAddrs = [];
				let junk = m.Junk || !!listMailboxes().find((mb) => mb.ID === m.MailboxID && (mb.Name === rejectsMailbox || mb.Junk));
				if (msgitemView.isCollapsedThreadRoot()) {
					;
					[msgitemView, ...msgitemView.descendants()].forEach((miv) => {
						const [fa2, ta2] = correspondentAddrs(miv);
						fromAddrs = [...fromAddrs, ...fa2];
						toAddrs = [...toAddrs, ...ta2];
						junk = junk || miv.messageitem.Message.Junk;
					});
				} else {
					[fromAddrs, toAddrs] = correspondentAddrs(msgitemView);
				}
				const seen = /* @__PURE__ */ new Set();
				let fa = [];
				let ta = [];
				for (const a of fromAddrs) {
					const k = a.User + "@" + a.Domain.ASCII;
					if (!seen.has(k)) {
						seen.add(k);
						fa.push(a);
					}
				}
				for (const a of toAddrs) {
					const k = a.User + "@" + a.Domain.ASCII;
					if (!seen.has(k)) {
						seen.add(k);
						ta.push(a);
					}
				}
				let title = fa.map((a) => formatAddress(a)).join(", ");
				if (ta.length > 0) {
					if (title) {
						title += ",\n";
					}
					title += "addressed: " + ta.map((a) => formatAddress(a)).join(", ");
				}
				return [
					attr.title(title),
					join([
						...fa.map((a) => formatAddressShort(a, junk)),
						...ta.map((a) => dom.span(style({ fontStyle: "italic" }), formatAddressShort(a, junk)))
					], () => ", ")
				];
			}, "correspondents");
			const msgItemCellStyle = css("msgItemCell", { padding: "2px 4px" });
			const msgItemStyle = css("msgItem", { display: "flex", userSelect: "none", cursor: "pointer", borderRadius: ".15em", border: "1px solid transparent" });
			ensureCSS(".msgItem.focus", { borderColor: styles.msgItemFocusBorderColor, border: "1px solid" });
			ensureCSS(".msgItem:hover", { backgroundColor: styles.msgItemHoverBackgroundColor });
			ensureCSS(".msgItem.active", { background: styles.msgItemActiveBackground });
			const active = msgitemView.root && msgitemView.root.classList.contains("active");
			const focus = msgitemView.root && msgitemView.root.classList.contains("focus");
			const elem = dom.div(
				msgItemStyle,
				active ? dom._class("active") : [],
				focus ? dom._class("focus") : [],
				attr.draggable("true"),
				/* @__PURE__ */ __name(function dragstart(e) {
					if (!msglistView.selected().includes(msgitemView)) {
						e.preventDefault();
						window.alert("Can only drag items in selection.");
						return;
					}
					e.dataTransfer.setData("application/vnd.mox.messages", JSON.stringify(msglistView.selected().map((miv) => [miv.messageitem.Message.MailboxID, miv.messageitem.Message.ID])));
				}, "dragstart"),
				// Thread root with kids can be collapsed/expanded with double click.
				settings.threading !== ThreadMode.ThreadOff && !msgitemView.parent && msgitemView.kids.length > 0 ? /* @__PURE__ */ __name(function dblclick(e) {
					e.stopPropagation();
					if (settings.threading === ThreadMode.ThreadOn) {
						withStatus("Saving thread expand/collapse", client.ThreadCollapse([msgitemView.messageitem.Message.ID], !msgitemView.collapsed));
					}
					if (msgitemView.collapsed) {
						msglistView.threadExpand(msgitemView);
					} else {
						msglistView.threadCollapse(msgitemView);
						msglistView.viewportEnsureMessages();
					}
				}, "dblclick") : [],
				isUnread() ? css("msgItemUnread", { fontWeight: "bold" }) : [],
				// Relevant means not muted and matching the query.
				isRelevant() ? [] : css("msgItemNotRelevant", { opacity: ".4" }),
				dom.div(msgItemCellStyle, dom._class("msgItemFlags"), dom.div(css("msgItemFlagsSpread", { display: "flex", justifyContent: "space-between" }), dom.div(flagList(msgitemView)), !msgitemView.parent && msgitemView.kids.length > 0 && msgitemView.collapsed ? dom.clickbutton("" + (1 + msgitemView.descendants().length), attr.tabindex("-1"), attr.title("Expand thread."), attr.arialabel("Expand thread."), /* @__PURE__ */ __name(function click(e) {
					e.stopPropagation();
					if (settings.threading === ThreadMode.ThreadOn) {
						withStatus("Saving thread expanded", client.ThreadCollapse([msgitemView.messageitem.Message.ID], false));
					}
					msglistView.threadExpand(msgitemView);
				}, "click")) : [], !msgitemView.parent && msgitemView.kids.length > 0 && !msgitemView.collapsed ? dom.clickbutton("-", style({ width: "1em" }), attr.tabindex("-1"), attr.title("Collapse thread."), attr.arialabel("Collapse thread."), /* @__PURE__ */ __name(function click(e) {
					e.stopPropagation();
					if (settings.threading === ThreadMode.ThreadOn) {
						withStatus("Saving thread expanded", client.ThreadCollapse([msgitemView.messageitem.Message.ID], true));
					}
					msglistView.threadCollapse(msgitemView);
					msglistView.viewportEnsureMessages();
				}, "click")) : [])),
				dom.div(
					msgItemCellStyle,
					dom._class("msgItemFrom"),
					dom.div(css("msgItemFromSpread", { display: "flex", justifyContent: "space-between" }), dom.div(dom._class("silenttitle"), css("msgItemFromText", { whiteSpace: "nowrap", overflow: "hidden" }), correspondents()), identityHeader),
					// Thread messages are connected by a vertical bar. The first and last message are
					// only half the height of the item, to indicate start/end, and so it stands out
					// from any thread above/below.
					(msgitemView.parent || msgitemView.kids.length > 0) && !msgitemView.threadRoot().collapsed ? dom.div(css("msgItemThreadBar", { position: "absolute", right: 0, top: 0, bottom: 0, borderRight: "2px solid", borderRightColor: styles.colorMilder }), !msgitemView.parent ? css("msgItemThreadBarFirst", { top: "50%", bottom: "-1px" }) : isThreadLast() ? css("msgItemThreadBarLast", { top: "-1px", bottom: "50%" }) : css("msgItemThreadBarMiddle", { top: "-1px", bottom: "-1px" })) : []
				),
				dom.div(msgItemCellStyle, css("msgItemSubject", { position: "relative" }), dom.div(css("msgItemSubjectSpread", { display: "flex", justifyContent: "space-between", position: "relative" }), dom.div(css("msgItemSubjectText", { whiteSpace: "nowrap", overflow: "hidden" }), threadIndent > 0 ? dom.span(threadChar, style({ paddingLeft: threadIndent / 2 + "em" }), css("msgItemThreadChar", { opacity: ".75", fontWeight: "normal" }), threadCharTitle ? attr.title(threadCharTitle) : []) : [], msgitemView.parent ? [] : mi2.Envelope.Subject || "(no subject)", dom.span(css("msgItemSubjectSnippet", { fontWeight: "normal", color: styles.colorMilder }), " " + (mi2.Message.Preview || ""))), dom.div(keywords, mailboxtags))),
				dom.div(msgItemCellStyle, dom._class("msgItemAge"), age(received())),
				/* @__PURE__ */ __name(function click(e) {
					e.preventDefault();
					e.stopPropagation();
					msglistView.click(msgitemView, e.ctrlKey, e.shiftKey);
				}, "click")
			);
			msgitemView.root.replaceWith(elem);
			msgitemView.root = elem;
		}, "render");
		const msgitemView = {
			root: dom.div(),
			messageitem: mi,
			receivedTime,
			kids: [],
			parent: null,
			collapsed: initialCollapsed,
			threadRoot: /* @__PURE__ */ __name(() => {
				let miv = msgitemView;
				while (miv.parent) {
					miv = miv.parent;
				}
				return miv;
			}, "threadRoot"),
			isCollapsedThreadRoot: /* @__PURE__ */ __name(() => !msgitemView.parent && msgitemView.collapsed && msgitemView.kids.length > 0, "isCollapsedThreadRoot"),
			descendants: /* @__PURE__ */ __name(() => {
				let l = [];
				const walk = /* @__PURE__ */ __name((miv) => {
					for (const kmiv of miv.kids) {
						l.push(kmiv);
						walk(kmiv);
					}
				}, "walk");
				walk(msgitemView);
				return l;
			}, "descendants"),
			// We often just need to know if a descendant with certain properties exist. No
			// need to create an array, then call find on it.
			findDescendant: /* @__PURE__ */ __name((matchfn) => {
				const walk = /* @__PURE__ */ __name((miv) => {
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
				}, "walk");
				return walk(msgitemView);
			}, "findDescendant"),
			lastDescendant: /* @__PURE__ */ __name(() => {
				let l = msgitemView;
				if (l.kids.length === 0) {
					return null;
				}
				while (l.kids.length > 0) {
					l = l.kids[l.kids.length - 1];
				}
				return l;
			}, "lastDescendant"),
			remove,
			render
		};
		return msgitemView;
	}, "newMsgitemView");
	var attachmentView = null;
	var newMsgView = /* @__PURE__ */ __name((miv, msglistView, listMailboxes, setLocationHash, possibleLabels, messageLoaded, refineKeyword, parsedMessageOpt) => {
		const mi = miv.messageitem;
		const m = mi.Message;
		const fromAddress = mi.Envelope.From && mi.Envelope.From.length === 1 ? formatEmail(mi.Envelope.From[0]) : "";
		let parsedMessageResolve = /* @__PURE__ */ __name(() => {
		}, "parsedMessageResolve");
		let parsedMessageReject = /* @__PURE__ */ __name(() => {
		}, "parsedMessageReject");
		let parsedMessagePromise = new Promise((resolve, reject) => {
			parsedMessageResolve = resolve;
			parsedMessageReject = reject;
		});
		const react = /* @__PURE__ */ __name(async (to, cc, bcc, forward) => {
			const pm = await parsedMessagePromise;
			let body = "";
			const sel = window.getSelection();
			let haveSel = false;
			if (sel && sel.toString()) {
				body = sel.toString();
				haveSel = true;
			} else if (pm.Texts && pm.Texts.length > 0) {
				body = pm.Texts[0];
			}
			body = body.replace(/\r/g, "").replace(/\n\n\n\n*/g, "\n\n").trim();
			let editOffset = 0;
			if (forward) {
				const env = mi.Envelope;
				const subject2 = env.Subject ? [env.Subject] : [];
				const date = pm.Headers?.Date || [];
				const from = (env.From || []).map((a) => formatAddress(a));
				const replyTo = (env.ReplyTo || []).map((a) => formatAddress(a));
				const to2 = (env.To || []).map((a) => formatAddress(a));
				const cc2 = (env.CC || []).map((a) => formatAddress(a));
				let prefix = `

---- Forwarded Message ----
`;
				const padspace = /* @__PURE__ */ __name((s, size) => s + " ".repeat(size - s.length), "padspace");
				const add = /* @__PURE__ */ __name((k, l) => {
					if (l.length === 0) {
						return;
					}
					const last = l.length - 1;
					l.map((v, i) => {
						prefix += padspace(k, 10) + " " + v;
						if (i < last) {
							prefix += ",";
						}
						prefix += "\n";
						k = "";
					});
				}, "add");
				add("Subject:", subject2);
				add("Date:", date);
				add("From:", from);
				add("Reply-To:", replyTo);
				add("To:", to2);
				add("Cc:", cc2);
				body = prefix + "\n" + body;
			} else {
				body = body.split("\n").map((line) => "> " + line).join("\n");
				let sig = accountSettings?.Signature || "";
				if (!accountSettings?.Quoting && haveSel || accountSettings?.Quoting === Quoting.Bottom) {
					body += "\n\n";
					editOffset = body.length;
					body += "\n\n" + sig;
				} else {
					let onWroteLine = "";
					if (mi.Envelope.Date && mi.Envelope.From && mi.Envelope.From.length === 1) {
						const from = mi.Envelope.From[0];
						const name = from.Name || formatEmail(from);
						const dt = mi.Envelope.Date.getFullYear() === 1 ? m.Received : mi.Envelope.Date;
						const datetime = dt.toLocaleDateString(void 0, { weekday: "short", year: "numeric", month: "short", day: "numeric" }) + " at " + dt.toLocaleTimeString();
						onWroteLine = "On " + datetime + ", " + name + " wrote:\n";
					}
					body = "\n\n" + sig + "\n" + onWroteLine + body;
				}
			}
			const subjectPrefix = forward ? "Fwd:" : "Re:";
			let subject = mi.Envelope.Subject || "";
			subject = (RegExp("^" + subjectPrefix, "i").test(subject) ? "" : subjectPrefix + " ") + subject;
			const opts = {
				from: mi.Envelope.To || void 0,
				to: to.map((a) => formatAddress(a)),
				cc: cc.map((a) => formatAddress(a)),
				bcc: bcc.map((a) => formatAddress(a)),
				subject,
				body,
				isForward: forward,
				attachmentsMessageItem: forward ? mi : void 0,
				responseMessageID: m.ID,
				isList: m.IsMailingList,
				editOffset,
				// For "send and archive", we only move messages from the current open mailbox
				// (fallback to mailbox of response message for search results) to the archive
				// mailbox. We don't want to move messages in other mailboxes, like Sent, Trash, or
				// for cross-posted messages in other mailboxes.
				archiveReferenceMailboxID: msglistView.activeMailbox()?.ID || m.MailboxID
			};
			compose(opts, listMailboxes, setLocationHash);
		}, "react");
		const reply = /* @__PURE__ */ __name(async (all) => {
			const contains = /* @__PURE__ */ __name((l, a) => !!l.find((e) => equalAddress(e, a)), "contains");
			let to = [];
			let cc = [];
			let bcc = [];
			if ((mi.Envelope.From || []).length === 1 && envelopeIdentity(mi.Envelope.From || [])) {
				to = mi.Envelope.To || [];
			} else {
				if (mi.Envelope.ReplyTo && mi.Envelope.ReplyTo.length > 0) {
					to = mi.Envelope.ReplyTo;
				} else {
					to = mi.Envelope.From || [];
				}
				if (all) {
					for (const a of mi.Envelope.To || []) {
						if (!contains(to, a) && !envelopeIdentity([a])) {
							to.push(a);
						}
					}
				}
			}
			if (all) {
				cc = mi.Envelope.CC || [];
				bcc = mi.Envelope.BCC || [];
			}
			cc = cc.filter((a, i) => !envelopeIdentity([a]) && !contains(to, a) && !contains(cc.slice(0, i), a));
			bcc = bcc.filter((a) => !envelopeIdentity([a]));
			await react(to, cc, bcc, false);
		}, "reply");
		const cmdForward = /* @__PURE__ */ __name(async () => {
			react([], [], [], true);
		}, "cmdForward");
		const cmdReplyList = /* @__PURE__ */ __name(async () => {
			const pm = await parsedMessagePromise;
			if (pm.ListReplyAddress) {
				await react([pm.ListReplyAddress], [], [], false);
			}
		}, "cmdReplyList");
		const cmdReply = /* @__PURE__ */ __name(async () => {
			await reply(false);
		}, "cmdReply");
		const cmdReplyAll = /* @__PURE__ */ __name(async () => {
			await reply(true);
		}, "cmdReplyAll");
		const cmdPrint = /* @__PURE__ */ __name(async () => {
			if (urlType) {
				window.open("msg/" + m.ID + "/msg" + urlType + "#print", "_blank");
			}
		}, "cmdPrint");
		const cmdOpenNewTab = /* @__PURE__ */ __name(async () => {
			if (urlType) {
				window.open("msg/" + m.ID + "/msg" + urlType, "_blank");
			}
		}, "cmdOpenNewTab");
		const cmdOpenRaw = /* @__PURE__ */ __name(async () => {
			window.open("msg/" + m.ID + "/raw", "_blank");
		}, "cmdOpenRaw");
		const cmdOpenRawPart = /* @__PURE__ */ __name(async () => {
			const pm = await parsedMessagePromise;
			let path = null;
			if (urlType === "text" && pm.TextPaths && pm.TextPaths.length > 0) {
				path = pm.TextPaths[0];
			} else if ((urlType === "html" || urlType === "htmlexternal") && pm.HTMLPath) {
				path = pm.HTMLPath;
			}
			if (!path) {
				window.alert("Part not found.");
				return;
			}
			window.open("msg/" + m.ID + "/viewtext/" + [0, ...path].join("."), "_blank");
		}, "cmdOpenRawPart");
		const cmdDownloadRaw = /* @__PURE__ */ __name(async () => {
			window.open("msg/" + m.ID + "/rawdl", "_blank");
		}, "cmdDownloadRaw");
		const cmdViewAttachments = /* @__PURE__ */ __name(async () => {
			if (attachments.length > 0) {
				view(attachments[0]);
			}
		}, "cmdViewAttachments");
		const cmdComposeDraft = /* @__PURE__ */ __name(async () => {
			const pm = await parsedMessagePromise;
			composeDraft(mi, pm, listMailboxes, setLocationHash);
		}, "cmdComposeDraft");
		const cmdToggleHeaders = /* @__PURE__ */ __name(async () => {
			settingsPut({ ...settings, showAllHeaders: !settings.showAllHeaders });
			const pm = await parsedMessagePromise;
			loadHeaderDetails(pm);
		}, "cmdToggleHeaders");
		let textbtn, htmlbtn, htmlextbtn;
		const activeBtn = /* @__PURE__ */ __name((b) => {
			for (const xb of [textbtn, htmlbtn, htmlextbtn]) {
				if (xb) {
					xb.classList.toggle("active", xb === b);
				}
			}
		}, "activeBtn");
		const fromAddressSettingsSave = /* @__PURE__ */ __name(async (mode) => {
			const froms = mi.Envelope.From || [];
			if (froms.length === 1) {
				await withStatus("Saving view mode settings for address", client.FromAddressSettingsSave({ FromAddress: froms[0].User + "@" + (froms[0].Domain.Unicode || froms[0].Domain.ASCII), ViewMode: mode }));
			}
		}, "fromAddressSettingsSave");
		const cmdShowText = /* @__PURE__ */ __name(async () => {
			if (!textbtn) {
				return;
			}
			loadText(await parsedMessagePromise);
			activeBtn(textbtn);
			await fromAddressSettingsSave(ViewMode.ModeText);
		}, "cmdShowText");
		const cmdShowHTML = /* @__PURE__ */ __name(async () => {
			if (!htmlbtn || !htmlextbtn) {
				return;
			}
			loadHTML();
			activeBtn(htmlbtn);
			await fromAddressSettingsSave(ViewMode.ModeHTML);
		}, "cmdShowHTML");
		const cmdShowHTMLExternal = /* @__PURE__ */ __name(async () => {
			if (!htmlbtn || !htmlextbtn) {
				return;
			}
			loadHTMLexternal();
			activeBtn(htmlextbtn);
			await fromAddressSettingsSave(ViewMode.ModeHTMLExt);
		}, "cmdShowHTMLExternal");
		const cmdShowHTMLCycle = /* @__PURE__ */ __name(async () => {
			if (urlType === "html") {
				await cmdShowHTMLExternal();
			} else {
				await cmdShowHTML();
			}
		}, "cmdShowHTMLCycle");
		const cmdShowInternals = /* @__PURE__ */ __name(async () => {
			const pm = await parsedMessagePromise;
			const mimepart = /* @__PURE__ */ __name((p) => dom.li((p.MediaType + "/" + p.MediaSubType).toLowerCase(), p.ContentTypeParams ? " " + JSON.stringify(p.ContentTypeParams) : [], p.Parts && p.Parts.length === 0 ? [] : dom.ul(css("internalsList", { listStyle: "disc", marginLeft: "1em" }), (p.Parts || []).map((pp) => mimepart(pp)))), "mimepart");
			popup(css("popupInternals", { display: "flex", gap: "1em" }), dom.div(dom.h1("Mime structure"), dom.ul(css("internalsList", { listStyle: "disc", marginLeft: "1em" }), mimepart(pm.Part))), dom.div(css("internalsMessage", { whiteSpace: "pre-wrap", tabSize: 4, maxWidth: "50%" }), dom.h1("Message"), JSON.stringify(m, void 0, "	")), dom.div(css("internalsParts", { whiteSpace: "pre-wrap", tabSize: 4, maxWidth: "50%" }), dom.h1("Part"), JSON.stringify(pm.Part, void 0, "	")));
		}, "cmdShowInternals");
		const cmdUp = /* @__PURE__ */ __name(async () => {
			msgscrollElem.scrollTo({ top: msgscrollElem.scrollTop - 3 * msgscrollElem.getBoundingClientRect().height / 4, behavior: "smooth" });
		}, "cmdUp");
		const cmdDown = /* @__PURE__ */ __name(async () => {
			msgscrollElem.scrollTo({ top: msgscrollElem.scrollTop + 3 * msgscrollElem.getBoundingClientRect().height / 4, behavior: "smooth" });
		}, "cmdDown");
		const cmdHome = /* @__PURE__ */ __name(async () => {
			msgscrollElem.scrollTo({ top: 0 });
		}, "cmdHome");
		const cmdEnd = /* @__PURE__ */ __name(async () => {
			msgscrollElem.scrollTo({ top: msgscrollElem.scrollHeight });
		}, "cmdEnd");
		const shortcuts = {
			e: cmdComposeDraft,
			I: cmdShowInternals,
			o: cmdOpenNewTab,
			O: cmdOpenRaw,
			"ctrl p": cmdPrint,
			f: cmdForward,
			r: cmdReply,
			R: cmdReplyAll,
			v: cmdViewAttachments,
			t: cmdShowText,
			T: cmdShowHTMLCycle,
			"ctrl i": cmdToggleHeaders,
			"alt j": cmdDown,
			"alt k": cmdUp,
			"alt ArrowDown": cmdDown,
			"alt ArrowUp": cmdUp,
			"alt J": cmdEnd,
			"alt K": cmdHome,
			// For showing shortcuts only, handled in msglistView.
			a: msglistView.cmdArchive,
			d: msglistView.cmdTrash,
			D: msglistView.cmdDelete,
			q: msglistView.cmdJunk,
			Q: msglistView.cmdMarkNotJunk,
			m: msglistView.cmdMarkRead,
			M: msglistView.cmdMarkUnread
		};
		let urlType;
		let msgbuttonElem, msgheaderElem, msgattachmentElem, msgmodeElem;
		let msgheaderFullElem;
		const msgmetaElem = dom.div(
			css("msgmeta", { backgroundColor: styles.backgroundColorMild, borderBottom: "5px solid", borderBottomColor: ["white", "black"], maxHeight: "90%", overflowY: "auto" }),
			attr.role("region"),
			attr.arialabel("Buttons and headers for message"),
			msgbuttonElem = dom.div(),
			dom.div(attr.arialive("assertive"), dom.table(styleClasses.msgHeaders, msgheaderElem = dom.tbody()), msgheaderFullElem = dom.table(), msgattachmentElem = dom.div(), msgmodeElem = dom.div()),
			// Explicit separator that separates headers from body, to
			// prevent HTML messages from faking UI elements.
			dom.div(css("headerBodySeparator", { height: "2px", backgroundColor: styles.borderColor }))
		);
		const msgscrollElem = dom.div(dom._class("pad"), yscrollAutoStyle, attr.role("region"), attr.arialabel("Message body"), css("msgscroll", { backgroundColor: styles.backgroundColor }));
		const msgcontentElem = dom.div(css("scrollparent", { position: "relative", flexGrow: "1" }));
		const trashMailboxID = listMailboxes().find((mb) => mb.Trash)?.ID;
		const draftMailboxID = listMailboxes().find((mb) => mb.Draft)?.ID;
		const loadButtons = /* @__PURE__ */ __name((pm) => {
			dom._kids(msgbuttonElem, dom.div(dom._class("pad"), m.MailboxID === draftMailboxID ? dom.clickbutton("Edit", attr.title("Continue editing this draft message."), clickCmd(cmdComposeDraft, shortcuts)) : [], " ", !pm || !pm.ListReplyAddress ? [] : dom.clickbutton("Reply to list", attr.title("Compose a reply to this mailing list."), clickCmd(cmdReplyList, shortcuts)), " ", pm && pm.ListReplyAddress && formatEmail(pm.ListReplyAddress) === fromAddress ? [] : dom.clickbutton("Reply", attr.title("Compose a reply to the sender of this message."), clickCmd(cmdReply, shortcuts)), " ", (mi.Envelope.To || []).length <= 1 && (mi.Envelope.CC || []).length === 0 && (mi.Envelope.BCC || []).length === 0 ? [] : dom.clickbutton("Reply all", attr.title("Compose a reply to all participants of this message."), clickCmd(cmdReplyAll, shortcuts)), " ", dom.clickbutton("Forward", attr.title("Compose a forwarding message, optionally including attachments."), clickCmd(cmdForward, shortcuts)), " ", dom.clickbutton("Archive", attr.title("Move to the Archive mailbox."), clickCmd(msglistView.cmdArchive, shortcuts)), " ", m.MailboxID === trashMailboxID ? dom.clickbutton("Delete", attr.title("Permanently delete message."), clickCmd(msglistView.cmdDelete, shortcuts)) : dom.clickbutton("Trash", attr.title("Move to the Trash mailbox."), clickCmd(msglistView.cmdTrash, shortcuts)), " ", dom.clickbutton("Junk", attr.title("Move to Junk mailbox, marking as junk and causing this message to be used in spam classification of new incoming messages."), clickCmd(msglistView.cmdJunk, shortcuts)), " ", dom.clickbutton("Move to...", /* @__PURE__ */ __name(function click(e) {
				movePopover(e, listMailboxes(), [m]);
			}, "click")), " ", dom.clickbutton("Labels...", attr.title("Add/remove labels."), /* @__PURE__ */ __name(function click(e) {
				labelsPopover(e, [m], possibleLabels);
			}, "click")), " ", dom.clickbutton("More...", attr.title("Show more actions."), /* @__PURE__ */ __name(function click(e) {
				popover(e.target, { transparent: true }, dom.div(css("popupMore", { display: "flex", flexDirection: "column", gap: ".5ex", textAlign: "right" }), [
					dom.clickbutton("Print", attr.title("Print message, opens in new tab and opens print dialog."), clickCmd(cmdPrint, shortcuts)),
					dom.clickbutton("Mark Not Junk", attr.title("Mark as not junk, causing this message to be used in spam classification of new incoming messages."), clickCmd(msglistView.cmdMarkNotJunk, shortcuts)),
					dom.clickbutton("Mark Read", clickCmd(msglistView.cmdMarkRead, shortcuts)),
					dom.clickbutton("Mark Unread", clickCmd(msglistView.cmdMarkUnread, shortcuts)),
					dom.clickbutton("Mute thread", clickCmd(msglistView.cmdMute, shortcuts)),
					dom.clickbutton("Unmute thread", clickCmd(msglistView.cmdUnmute, shortcuts)),
					dom.clickbutton("Open in new tab", clickCmd(cmdOpenNewTab, shortcuts)),
					dom.clickbutton("Download raw original message", clickCmd(cmdDownloadRaw, shortcuts)),
					dom.clickbutton("Export as ...", /* @__PURE__ */ __name(function click2(e2) {
						popoverExport(e2.target, "", [m.ID]);
					}, "click")),
					dom.clickbutton("Show raw original message in new tab", clickCmd(cmdOpenRaw, shortcuts)),
					dom.clickbutton("Show currently displayed part as decoded text", clickCmd(cmdOpenRawPart, shortcuts)),
					dom.clickbutton("Show internals in popup", clickCmd(cmdShowInternals, shortcuts))
				].map((b) => dom.div(b))));
			}, "click"))));
		}, "loadButtons");
		loadButtons(parsedMessageOpt || null);
		loadMsgheaderView(msgheaderElem, miv.messageitem, accountSettings.ShowHeaders || [], refineKeyword, false);
		const headerTextMildStyle = css("headerTextMild", { textAlign: "right", color: styles.colorMild });
		const loadHeaderDetails = /* @__PURE__ */ __name((pm) => {
			const table = dom.table(css("msgHeaderDetails", { width: "100%" }), !settings.showAllHeaders ? [] : Object.entries(pm.Headers || {}).sort().map((t) => (t[1] || []).map((v) => dom.tr(dom.td(t[0] + ":", headerTextMildStyle), dom.td(v)))));
			msgheaderFullElem.replaceWith(table);
			msgheaderFullElem = table;
		}, "loadHeaderDetails");
		const isText = /* @__PURE__ */ __name((a) => ["text", "message"].includes(a.Part.MediaType.toLowerCase()), "isText");
		const isPDF = /* @__PURE__ */ __name((a) => (a.Part.MediaType + "/" + a.Part.MediaSubType).toLowerCase() === "application/pdf", "isPDF");
		const isViewable = /* @__PURE__ */ __name((a) => isText(a) || isImage(a) || isPDF(a), "isViewable");
		const attachments = mi.Attachments || [];
		let beforeViewFocus;
		const view = /* @__PURE__ */ __name((a) => {
			if (!beforeViewFocus) {
				beforeViewFocus = document.activeElement;
			}
			const pathStr = [0].concat(a.Path || []).join(".");
			const index = attachments.indexOf(a);
			const cmdViewPrev = /* @__PURE__ */ __name(async () => {
				if (index > 0) {
					popupRoot.remove();
					view(attachments[index - 1]);
				}
			}, "cmdViewPrev");
			const cmdViewNext = /* @__PURE__ */ __name(async () => {
				if (index < attachments.length - 1) {
					popupRoot.remove();
					view(attachments[index + 1]);
				}
			}, "cmdViewNext");
			const cmdViewFirst = /* @__PURE__ */ __name(async () => {
				popupRoot.remove();
				view(attachments[0]);
			}, "cmdViewFirst");
			const cmdViewLast = /* @__PURE__ */ __name(async () => {
				popupRoot.remove();
				view(attachments[attachments.length - 1]);
			}, "cmdViewLast");
			const cmdViewClose = /* @__PURE__ */ __name(async () => {
				popupRoot.remove();
				if (beforeViewFocus && beforeViewFocus instanceof HTMLElement && beforeViewFocus.parentNode) {
					beforeViewFocus.focus();
				}
				attachmentView = null;
				beforeViewFocus = null;
			}, "cmdViewClose");
			const attachShortcuts = {
				h: cmdViewPrev,
				ArrowLeft: cmdViewPrev,
				l: cmdViewNext,
				ArrowRight: cmdViewNext,
				"0": cmdViewFirst,
				"$": cmdViewLast,
				Escape: cmdViewClose
			};
			const attachmentsArrowStyle = css("attachmentsArrow", { color: styles.backgroundColor, backgroundColor: styles.color, width: "2em", height: "2em", borderRadius: "1em", lineHeight: "2em", textAlign: "center", fontWeight: "bold" });
			const attachmentsIframeStyle = css("attachmentsIframe", { flexGrow: 1, boxShadow: styles.boxShadow, margin: "0 5em" });
			let content;
			const popupRoot = dom.div(css("attachmentsOverlay", { position: "fixed", left: 0, right: 0, top: 0, bottom: 0, backgroundColor: styles.overlayBackgroundColor, display: "flex", flexDirection: "column", alignContent: "stretch", padding: "1em", zIndex: zindexes.attachments }), /* @__PURE__ */ __name(function click(e) {
				e.stopPropagation();
				cmdViewClose();
			}, "click"), attr.tabindex("0"), !(index > 0) ? [] : dom.div(css("attachmentsPrevious", { position: "absolute", left: "1em", top: 0, bottom: 0, fontSize: "1.5em", width: "2em", display: "flex", alignItems: "center", cursor: "pointer" }), dom.div(dom._class("silenttitle"), attachmentsArrowStyle, attr.title("To previous viewable attachment."), "\u2190"), attr.tabindex("0"), clickCmd(cmdViewPrev, attachShortcuts), enterCmd(cmdViewPrev, attachShortcuts)), dom.div(css("attachmentsDownloadHeaderBox", { textAlign: "center", paddingBottom: "30px" }), dom.span(dom._class("pad"), /* @__PURE__ */ __name(function click(e) {
				e.stopPropagation();
			}, "click"), css("attachmentsDownloadHeader", { backgroundColor: styles.popupBackgroundColor, color: styles.popupColor, boxShadow: styles.boxShadow, border: "1px solid", borderColor: styles.popupBorderColor, borderRadius: ".25em" }), a.Filename || "(unnamed)", " - ", formatSize(a.Part.DecodedSize), " - ", dom.a("Download", attr.download(""), attr.href("msg/" + m.ID + "/download/" + pathStr), /* @__PURE__ */ __name(function click(e) {
				e.stopPropagation();
			}, "click")))), isImage(a) ? dom.div(css("attachmentsImageBox", { flexGrow: 1, display: "flex", alignItems: "center", justifyContent: "center", maxHeight: "calc(100% - 50px)", margin: "0 5em" }), dom.img(css("attachmentsImage", { maxWidth: "100%", maxHeight: "100%", boxShadow: styles.boxShadow, margin: "0 30px" }), attr.src("msg/" + m.ID + "/view/" + pathStr))) : isText(a) ? dom.iframe(attr.title("Attachment shown as text."), attachmentsIframeStyle, attr.src("msg/" + m.ID + "/viewtext/" + pathStr)) : isPDF(a) ? dom.iframe(attr.title("Attachment as PDF."), attachmentsIframeStyle, attr.src("msg/" + m.ID + "/view/" + pathStr)) : content = dom.div(/* @__PURE__ */ __name(function click(e) {
				e.stopPropagation();
			}, "click"), css("attachmentsBinary", { minWidth: "30em", padding: "2ex", boxShadow: styles.boxShadow, backgroundColor: styles.popupBackgroundColor, margin: "0 5em", textAlign: "center" }), dom.div(style({ marginBottom: "2ex" }), "Attachment could be a binary file."), dom.clickbutton("View as text", /* @__PURE__ */ __name(function click() {
				content.replaceWith(dom.iframe(attr.title("Attachment shown as text, though it could be a binary file."), attachmentsIframeStyle, attr.src("msg/" + m.ID + "/viewtext/" + pathStr)));
			}, "click"))), !(index < attachments.length - 1) ? [] : dom.div(css("attachmentsNext", { position: "absolute", right: "1em", top: 0, bottom: 0, fontSize: "1.5em", width: "2em", display: "flex", alignItems: "center", cursor: "pointer" }), dom.div(dom._class("silenttitle"), attachmentsArrowStyle, attr.title("To next viewable attachment."), "\u2192"), attr.tabindex("0"), clickCmd(cmdViewNext, attachShortcuts), enterCmd(cmdViewNext, attachShortcuts)));
			document.body.appendChild(popupRoot);
			popupRoot.focus();
			attachmentView = { key: keyHandler(attachShortcuts) };
		}, "view");
		var filesAll = false;
		const renderAttachments = /* @__PURE__ */ __name(() => {
			const l = mi.Attachments || [];
			dom._kids(msgattachmentElem, l && l.length === 0 ? [] : dom.div(css("inlineAttachmentsSeparator", { borderTop: "1px solid", borderTopColor: styles.borderColor }), dom.div(dom._class("pad"), "Attachments: ", l.slice(0, filesAll ? l.length : 4).map((a) => {
				const name = a.Filename || "(unnamed)";
				const viewable = isViewable(a);
				const size = formatSize(a.Part.DecodedSize);
				const eye = "\u{1F441}";
				const dl = "\u2913";
				const dlurl = "msg/" + m.ID + "/download/" + [0].concat(a.Path || []).join(".");
				const viewbtn = dom.clickbutton(eye, viewable ? " " + name : style({ padding: "0px 0.25em" }), attr.title("View this file. Size: " + size), style({ lineHeight: "1.5" }), /* @__PURE__ */ __name(function click() {
					view(a);
				}, "click"));
				const dlbtn = dom.a(dom._class("button"), attr.download(""), attr.href(dlurl), dl, viewable ? style({ padding: "0px 0.25em" }) : " " + name, attr.title("Download this file. Size: " + size), style({ lineHeight: "1.5" }));
				if (viewable) {
					return [dom.span(dom._class("btngroup"), urlType === "text" && isImage(a) ? style({ opacity: ".6" }) : [], viewbtn, dlbtn), " "];
				}
				return [dom.span(dom._class("btngroup"), dlbtn, viewbtn), " "];
			}), filesAll || l.length < 6 ? [] : dom.clickbutton("More...", /* @__PURE__ */ __name(function click() {
				filesAll = true;
				renderAttachments();
			}, "click")), " ", dom.a("Download all as zip", attr.download(""), style({ color: "inherit" }), attr.href("msg/" + m.ID + "/attachments.zip")))));
		}, "renderAttachments");
		renderAttachments();
		const root = dom.div(css("msgViewRoot", { position: "absolute", top: 0, right: 0, bottom: 0, left: 0, display: "flex", flexDirection: "column" }));
		dom._kids(root, msgmetaElem, msgcontentElem);
		const loadText = /* @__PURE__ */ __name((pm) => {
			urlType = "text";
			const elem = dom.div(dom._class("mono", "textmulti"), style({ whiteSpace: "pre-wrap" }), (pm.Texts || []).map((t) => renderText(t.replace(/\r\n/g, "\n"))), (mi.Attachments || []).filter((f) => isImage(f)).map((f) => {
				const pathStr = [0].concat(f.Path || []).join(".");
				return dom.div(dom.div(css("msgAttachmentBox", { flexGrow: 1, display: "flex", alignItems: "center", justifyContent: "center", maxHeight: "calc(100% - 50px)" }), dom.img(attr.src("msg/" + m.ID + "/view/" + pathStr), attr.title(f.Filename), css("msgInlineImage", { boxShadow: styles.boxShadow, maxWidth: "100%", maxHeight: "100%" }))));
			}));
			dom._kids(msgcontentElem);
			dom._kids(msgscrollElem, elem);
			dom._kids(msgcontentElem, msgscrollElem);
			renderAttachments();
		}, "loadText");
		const loadHTML = /* @__PURE__ */ __name(() => {
			urlType = "html";
			dom._kids(msgcontentElem, dom.iframe(attr.tabindex("0"), attr.title("HTML version of message with images inlined, without external resources loaded."), attr.src("msg/" + m.ID + "/" + urlType), css("msgIframeHTML", { position: "absolute", width: "100%", height: "100%" })));
			renderAttachments();
		}, "loadHTML");
		const loadHTMLexternal = /* @__PURE__ */ __name(() => {
			urlType = "htmlexternal";
			dom._kids(msgcontentElem, dom.iframe(attr.tabindex("0"), attr.title("HTML version of message with images inlined and with external resources loaded."), attr.src("msg/" + m.ID + "/" + urlType), css("msgIframeHTML", { position: "absolute", width: "100%", height: "100%" })));
			renderAttachments();
		}, "loadHTMLexternal");
		const mv = {
			root,
			messageitem: mi,
			key: keyHandler(shortcuts),
			aborter: { abort: /* @__PURE__ */ __name(() => {
			}, "abort") },
			updateKeywords: /* @__PURE__ */ __name(async (modseq, keywords) => {
				mi.Message.ModSeq = modseq;
				mi.Message.Keywords = keywords;
				loadMsgheaderView(msgheaderElem, miv.messageitem, accountSettings.ShowHeaders || [], refineKeyword, false);
			}, "updateKeywords")
		};
		(async () => {
			let pm;
			if (parsedMessageOpt) {
				pm = parsedMessageOpt;
				parsedMessageResolve(pm);
			} else {
				const promise = withStatus("Loading message", client.withOptions({ aborter: mv.aborter }).ParsedMessage(m.ID));
				try {
					pm = await promise;
				} catch (err) {
					if (err instanceof Error) {
						parsedMessageReject(err);
					} else {
						parsedMessageReject(new Error("fetching message failed"));
					}
					throw err;
				}
				parsedMessageResolve(pm);
			}
			loadButtons(pm);
			loadHeaderDetails(pm);
			const msgHeaderSeparatorStyle = css("msgHeaderSeparator", { borderTop: "1px solid", borderTopColor: styles.borderColor });
			const msgModeWarningStyle = css("msgModeWarning", { backgroundColor: styles.warningBackgroundColor, padding: "0 .15em" });
			const htmlNote = "In the HTML viewer, the following potentially dangerous functionality is disabled: submitting forms, starting a download from a link, navigating away from this page by clicking a link. If a link does not work, try explicitly opening it in a new tab.";
			const haveText = pm.Texts && pm.Texts.length > 0;
			if (!haveText && !pm.HasHTML) {
				dom._kids(msgcontentElem);
				dom._kids(msgmodeElem, dom.div(dom._class("pad"), msgHeaderSeparatorStyle, dom.span("No textual content", msgModeWarningStyle)));
			} else if (haveText && !pm.HasHTML) {
				loadText(pm);
				dom._kids(msgmodeElem);
			} else {
				const text = haveText && pm.ViewMode == ViewMode.ModeText;
				dom._kids(msgmodeElem, dom.div(dom._class("pad"), msgHeaderSeparatorStyle, !haveText ? dom.span("HTML-only message", attr.title(htmlNote), msgModeWarningStyle, style({ marginRight: ".25em" })) : [], dom.span(dom._class("btngroup"), haveText ? textbtn = dom.clickbutton(text ? dom._class("active") : [], "Text", clickCmd(cmdShowText, shortcuts)) : [], htmlbtn = dom.clickbutton(text || !text && pm.ViewMode == ViewMode.ModeHTMLExt ? [] : dom._class("active"), "HTML", attr.title(htmlNote), /* @__PURE__ */ __name(async function click() {
					showShortcut("T");
					await cmdShowHTML();
				}, "click")), htmlextbtn = dom.clickbutton(text || !text && pm.ViewMode != ViewMode.ModeHTMLExt ? [] : dom._class("active"), "HTML with external resources", attr.title(htmlNote), clickCmd(cmdShowHTMLExternal, shortcuts)))));
				if (text) {
					loadText(pm);
				} else if (pm.ViewMode == ViewMode.ModeHTMLExt) {
					loadHTMLexternal();
				} else {
					loadHTML();
				}
			}
			messageLoaded();
			const tidAdd = /* @__PURE__ */ __name((tid) => {
				const l = scheduledTimers.get(miv.messageitem.Message.ID) || [];
				l.push(tid);
				scheduledTimers.set(miv.messageitem.Message.ID, l);
			}, "tidAdd");
			const tidRemove = /* @__PURE__ */ __name((tid) => {
				const l = scheduledTimers.get(miv.messageitem.Message.ID) || [];
				const i = l.indexOf(tid);
				if (i >= 0) {
					l.splice(i, 1);
				}
				if (l.length === 0) {
					scheduledTimers.delete(miv.messageitem.Message.ID);
				}
			}, "tidRemove");
			if (!miv.messageitem.Message.Seen) {
				const tid = window.setTimeout(async () => {
					if (!miv.messageitem.Message.Seen && miv.messageitem.Message.ID === msglistView.activeMessageID()) {
						await withStatus("Marking current message as read", client.FlagsAdd([miv.messageitem.Message.ID], ["\\seen"]));
					}
					tidRemove(tid);
				}, 500);
				tidAdd(tid);
			}
			if (!miv.messageitem.Message.Junk && !miv.messageitem.Message.Notjunk) {
				const tid = window.setTimeout(async () => {
					const mailboxSpecial = /* @__PURE__ */ __name(() => !!listMailboxes().find((mb) => mb.ID === miv.messageitem.Message.MailboxID && (mb.Name === rejectsMailbox || mb.Name == introboxMailbox)), "mailboxSpecial");
					if (!miv.messageitem.Message.Junk && !miv.messageitem.Message.Notjunk && miv.messageitem.Message.Seen && miv.messageitem.Message.ID === msglistView.activeMessageID() && !mailboxSpecial()) {
						await withStatus("Marking current message as not junk", client.FlagsAdd([miv.messageitem.Message.ID], ["$notjunk"]));
					}
					tidRemove(tid);
				}, 5 * 1e3);
				tidAdd(tid);
			}
		})();
		return mv;
	}, "newMsgView");
	var newMsglistView = /* @__PURE__ */ __name((msgElem, activeMailbox, listMailboxes, setLocationHash, otherMailbox, possibleLabels, scrollElemHeight, refineKeyword, viewportEnsureMessages) => {
		let msgitemViews = [];
		let collapsedMsgitemViews = [];
		let oldThreadMessageItems = [];
		let selected = [];
		let focus = null;
		let msgView = null;
		const moveActionMsgIDs = /* @__PURE__ */ __name((skipMBID) => {
			const sentMailboxID = listMailboxes().find((mb) => mb.Sent)?.ID;
			const effselected = mlv.selected();
			return effselected.filter((miv) => miv.messageitem.Message.MailboxID !== skipMBID).map((miv) => miv.messageitem.Message).filter((m) => effselected.length === 1 || !sentMailboxID || m.MailboxID !== sentMailboxID || !otherMailbox(sentMailboxID)).map((m) => m.ID);
		}, "moveActionMsgIDs");
		const cmdArchive = /* @__PURE__ */ __name(async () => {
			const mb = listMailboxes().find((mb2) => mb2.Archive);
			if (mb) {
				await withStatus("Moving to archive mailbox", client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID, true));
			} else {
				window.alert("No mailbox configured for archiving yet.");
			}
		}, "cmdArchive");
		const cmdDelete = /* @__PURE__ */ __name(async () => {
			if (!window.confirm("Are you sure you want to permanently delete?")) {
				return;
			}
			const ids = mlv.selected().map((miv) => miv.messageitem.Message.ID);
			for (const id of ids) {
				for (const tid of scheduledTimers.get(id) || []) {
					window.clearTimeout(tid);
				}
				scheduledTimers.delete(id);
			}
			await withStatus("Permanently deleting messages", client.MessageDelete(ids));
		}, "cmdDelete");
		const cmdTrash = /* @__PURE__ */ __name(async () => {
			const mb = listMailboxes().find((mb2) => mb2.Trash);
			if (mb) {
				await withStatus("Moving to trash mailbox", client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID, true));
			} else {
				window.alert("No mailbox configured for trash yet.");
			}
		}, "cmdTrash");
		const cmdJunk = /* @__PURE__ */ __name(async () => {
			const mb = listMailboxes().find((mb2) => mb2.Junk);
			if (mb) {
				await withStatus("Moving to junk mailbox", client.MessageMove(moveActionMsgIDs(mb.ID), mb.ID, true));
			} else {
				window.alert("No mailbox configured for junk yet.");
			}
		}, "cmdJunk");
		const cmdMarkNotJunk = /* @__PURE__ */ __name(async () => {
			await withStatus("Marking as not junk", client.FlagsAdd(mlv.selected().map((miv) => miv.messageitem.Message.ID), ["$notjunk"]));
		}, "cmdMarkNotJunk");
		const cmdMarkRead = /* @__PURE__ */ __name(async () => {
			await withStatus("Marking as read", client.FlagsAdd(mlv.selected().map((miv) => miv.messageitem.Message.ID), ["\\seen"]));
		}, "cmdMarkRead");
		const cmdMarkUnread = /* @__PURE__ */ __name(async () => {
			await withStatus("Marking as not read", client.FlagsClear(mlv.selected().map((miv) => miv.messageitem.Message.ID), ["\\seen", "$junk", "$notjunk"]));
		}, "cmdMarkUnread");
		const cmdMute = /* @__PURE__ */ __name(async () => {
			const l = mlv.selected();
			await withStatus("Muting thread", client.ThreadMute(l.map((miv) => miv.messageitem.Message.ID), true));
			const oldstate = state();
			for (const miv of l) {
				if (!miv.parent && miv.kids.length > 0 && !miv.collapsed) {
					threadCollapse(miv, false);
				}
			}
			updateState(oldstate);
			viewportEnsureMessages();
		}, "cmdMute");
		const cmdUnmute = /* @__PURE__ */ __name(async () => {
			await withStatus("Unmuting thread", client.ThreadMute(mlv.selected().map((miv) => miv.messageitem.Message.ID), false));
		}, "cmdUnmute");
		const selectedRoots = /* @__PURE__ */ __name(() => {
			const mivs = [];
			mlv.selected().forEach((miv) => {
				const mivroot = miv.threadRoot();
				if (!mivs.includes(mivroot)) {
					mivs.push(mivroot);
				}
			});
			return mivs;
		}, "selectedRoots");
		const cmdToggleMute = /* @__PURE__ */ __name(async () => {
			if (settings.threading === ThreadMode.ThreadOff) {
				alert("Toggle muting threads is only available when threading is enabled.");
				return;
			}
			const rootmivs = selectedRoots();
			const unmuted = !!rootmivs.find((miv) => !miv.messageitem.Message.ThreadMuted);
			await withStatus(unmuted ? "Muting" : "Unmuting", client.ThreadMute(rootmivs.map((miv) => miv.messageitem.Message.ID), unmuted ? true : false));
			if (unmuted) {
				const oldstate = state();
				rootmivs.forEach((miv) => {
					if (!miv.collapsed) {
						threadCollapse(miv, false);
					}
				});
				updateState(oldstate);
				viewportEnsureMessages();
			}
		}, "cmdToggleMute");
		const cmdToggleCollapse = /* @__PURE__ */ __name(async () => {
			if (settings.threading === ThreadMode.ThreadOff) {
				alert("Toggling thread collapse/expand is only available when threading is enabled.");
				return;
			}
			const rootmivs = selectedRoots();
			const collapse = !!rootmivs.find((miv) => !miv.collapsed);
			const oldstate = state();
			if (collapse) {
				rootmivs.forEach((miv) => {
					if (!miv.collapsed) {
						threadCollapse(miv, false);
					}
				});
				selected = rootmivs;
				if (focus) {
					focus = focus.threadRoot();
				}
				viewportEnsureMessages();
			} else {
				rootmivs.forEach((miv) => {
					if (miv.collapsed) {
						threadExpand(miv, false);
					}
				});
			}
			updateState(oldstate);
			if (settings.threading === ThreadMode.ThreadOn) {
				const action = collapse ? "Collapsing" : "Expanding";
				await withStatus(action, client.ThreadCollapse(rootmivs.map((miv) => miv.messageitem.Message.ID), collapse));
			}
		}, "cmdToggleCollapse");
		const cmdSelectThread = /* @__PURE__ */ __name(async () => {
			if (!focus) {
				return;
			}
			const oldstate = state();
			selected = msgitemViews.filter((miv) => miv.messageitem.Message.ThreadID === focus.messageitem.Message.ThreadID);
			updateState(oldstate);
		}, "cmdSelectThread");
		const cmdCollapseExpand = /* @__PURE__ */ __name(async (collapse) => {
			if (settings.threading === ThreadMode.ThreadOff) {
				alert("Toggling thread collapse/expand is only available when threading is enabled.");
				return;
			}
			const oldstate = state();
			const rootmivs = selectedRoots();
			rootmivs.forEach((miv) => {
				if (miv.collapsed !== collapse) {
					if (collapse) {
						threadCollapse(miv, false);
					} else {
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
			if (settings.threading === ThreadMode.ThreadOn) {
				const action = collapse ? "Collapsing" : "Expanding";
				await withStatus(action, client.ThreadCollapse(rootmivs.map((miv) => miv.messageitem.Message.ID), collapse));
			}
		}, "cmdCollapseExpand");
		const cmdCollapse = /* @__PURE__ */ __name(async () => cmdCollapseExpand(true), "cmdCollapse");
		const cmdExpand = /* @__PURE__ */ __name(async () => cmdCollapseExpand(false), "cmdExpand");
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
			ArrowRight: cmdExpand
		};
		const checkConsistency = /* @__PURE__ */ __name((checkSelection) => {
			if (!settings.checkConsistency) {
				return;
			}
			const mivseen = /* @__PURE__ */ new Set();
			const threadActive = /* @__PURE__ */ new Set();
			for (const miv of msgitemViews) {
				const id = miv.messageitem.Message.ID;
				if (mivseen.has(id)) {
					log("duplicate Message.ID", { id, mivseenSize: mivseen.size });
					throw new ConsistencyError("duplicate Message.ID in msgitemViews");
				}
				mivseen.add(id);
				if (!miv.root.parentNode) {
					throw new ConsistencyError("msgitemView.root not in dom");
				}
				threadActive.add(miv.messageitem.Message.ThreadID);
			}
			const colseen = /* @__PURE__ */ new Set();
			for (const miv of collapsedMsgitemViews) {
				const id = miv.messageitem.Message.ID;
				if (colseen.has(id)) {
					throw new ConsistencyError("duplicate Message.ID in collapsedMsgitemViews");
				}
				colseen.add(id);
				if (mivseen.has(id)) {
					throw new ConsistencyError("Message.ID in both collapsedMsgitemViews and msgitemViews");
				}
				threadActive.add(miv.messageitem.Message.ThreadID);
			}
			if (settings.threading !== ThreadMode.ThreadOff) {
				const oldseen = /* @__PURE__ */ new Set();
				for (const mi of oldThreadMessageItems) {
					const id = mi.Message.ID;
					if (oldseen.has(id)) {
						throw new ConsistencyError("duplicate Message.ID in oldThreadMessageItems");
					}
					oldseen.add(id);
					if (mivseen.has(id)) {
						throw new ConsistencyError("Message.ID in both msgitemViews and oldThreadMessageItems");
					}
					if (colseen.has(id)) {
						throw new ConsistencyError("Message.ID in both collapsedMsgitemViews and oldThreadMessageItems");
					}
					if (threadActive.has(mi.Message.ThreadID)) {
						throw new ConsistencyError("threadid both in active and in old thread list");
					}
				}
			}
			msgitemViews.forEach((miv, i) => {
				if (miv.collapsed) {
					for (const dmiv of miv.descendants()) {
						if (!colseen.has(dmiv.messageitem.Message.ID)) {
							throw new ConsistencyError("descendant message id missing from collapsedMsgitemViews");
						}
					}
					return;
				}
				for (const dmiv of miv.descendants()) {
					i++;
					if (!mivseen.has(dmiv.messageitem.Message.ID)) {
						throw new ConsistencyError("descendant missing from msgitemViews");
					}
					if (msgitemViews[i] !== dmiv) {
						throw new ConsistencyError("descendant not at expected position in msgitemViews");
					}
				}
			});
			if (!checkSelection) {
				return;
			}
			const selseen = /* @__PURE__ */ new Set();
			for (const miv of selected) {
				const id = miv.messageitem.Message.ID;
				if (selseen.has(id)) {
					throw new ConsistencyError("duplicate miv in selected");
				}
				selseen.add(id);
				if (!mivseen.has(id)) {
					throw new ConsistencyError("selected id not in msgitemViews");
				}
			}
			if (focus) {
				const id = focus.messageitem.Message.ID;
				if (!mivseen.has(id)) {
					throw new ConsistencyError("focus set to unknown miv");
				}
			}
		}, "checkConsistency");
		const state = /* @__PURE__ */ __name(() => {
			const active = {};
			for (const miv of mlv.selected()) {
				active[miv.messageitem.Message.ID] = miv;
			}
			return { active, focus };
		}, "state");
		const updateState = /* @__PURE__ */ __name(async (oldstate, initial, parsedMessageOpt) => {
			const newstate = state();
			if (oldstate.focus !== newstate.focus) {
				if (oldstate.focus) {
					oldstate.focus.root.classList.toggle("focus", false);
				}
				if (newstate.focus) {
					newstate.focus.root.classList.toggle("focus", true);
					newstate.focus.root.scrollIntoView({ block: initial ? "center" : "nearest" });
				}
			}
			let activeChanged = false;
			for (const id in oldstate.active) {
				if (!newstate.active[id]) {
					oldstate.active[id].root.classList.toggle("active", false);
					activeChanged = true;
				}
			}
			for (const id in newstate.active) {
				if (!oldstate.active[id]) {
					newstate.active[id].root.classList.toggle("active", true);
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
			} else if (effselected.length === 1) {
				msgElem.classList.toggle("loading", true);
				const loaded = /* @__PURE__ */ __name(() => {
					msgElem.classList.toggle("loading", false);
				}, "loaded");
				msgView = newMsgView(effselected[0], mlv, listMailboxes, setLocationHash, possibleLabels, loaded, refineKeyword, parsedMessageOpt);
				dom._kids(msgElem, msgView);
			} else {
				const trashMailboxID = listMailboxes().find((mb) => mb.Trash)?.ID;
				const allTrash = trashMailboxID && !effselected.find((miv) => miv.messageitem.Message.MailboxID !== trashMailboxID);
				dom._kids(msgElem, dom.div(attr.role("region"), attr.arialabel("Buttons for multiple messages"), css("multimsgBg", { position: "absolute", top: 0, right: 0, bottom: 0, left: 0, display: "flex", alignItems: "center", justifyContent: "center" }), dom.div(css("multimsgBox", { backgroundColor: styles.backgroundColor, border: "1px solid", borderColor: styles.borderColor, padding: "4ex", borderRadius: ".25em" }), dom.div(style({ textAlign: "center", marginBottom: "4ex" }), "" + effselected.length + " messages selected"), dom.div(dom.clickbutton("Archive", attr.title("Move to the Archive mailbox. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox."), clickCmd(cmdArchive, shortcuts)), " ", allTrash ? dom.clickbutton("Delete", attr.title("Permanently delete messages."), clickCmd(cmdDelete, shortcuts)) : dom.clickbutton("Trash", attr.title("Move to the Trash mailbox. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox."), clickCmd(cmdTrash, shortcuts)), " ", dom.clickbutton("Junk", attr.title("Move to Junk mailbox, marking as junk and causing this message to be used in spam classification of new incoming messages. Messages in the designated Sent mailbox are only moved if a single message is selected, or the current mailbox is the Sent mailbox."), clickCmd(cmdJunk, shortcuts)), " ", dom.clickbutton("Move to...", /* @__PURE__ */ __name(function click(e) {
					const sentMailboxID = listMailboxes().find((mb) => mb.Sent)?.ID;
					movePopover(e, listMailboxes(), effselected.map((miv) => miv.messageitem.Message).filter((m) => effselected.length === 1 || !sentMailboxID || m.MailboxID !== sentMailboxID || !otherMailbox(sentMailboxID)));
				}, "click")), " ", dom.clickbutton("Labels...", attr.title("Add/remove labels ..."), /* @__PURE__ */ __name(function click(e) {
					labelsPopover(e, effselected.map((miv) => miv.messageitem.Message), possibleLabels);
				}, "click")), " ", dom.clickbutton("Mark Not Junk", attr.title("Mark as not junk, causing this message to be used in spam classification of new incoming messages."), clickCmd(cmdMarkNotJunk, shortcuts)), " ", dom.clickbutton("Mark Read", clickCmd(cmdMarkRead, shortcuts)), " ", dom.clickbutton("Mark Unread", clickCmd(cmdMarkUnread, shortcuts)), " ", dom.clickbutton("Mute thread", clickCmd(cmdMute, shortcuts)), " ", dom.clickbutton("Unmute thread", clickCmd(cmdUnmute, shortcuts)), " ", dom.clickbutton("Export as...", /* @__PURE__ */ __name(function click(e) {
					popoverExport(e.target, "", effselected.map((miv) => miv.messageitem.Message.ID));
				}, "click"))))));
			}
			setLocationHash();
		}, "updateState");
		const moveFocus = /* @__PURE__ */ __name((miv) => {
			const oldstate = state();
			focus = miv;
			updateState(oldstate);
		}, "moveFocus");
		const threadExpand = /* @__PURE__ */ __name((miv, changeState) => {
			if (miv.parent) {
				throw new ConsistencyError("cannot expand non-root");
			}
			const oldstate = state();
			miv.collapsed = false;
			const mivl = miv.descendants();
			miv.render();
			mivl.forEach((dmiv) => dmiv.render());
			for (const miv2 of mivl) {
				collapsedMsgitemViews.splice(collapsedMsgitemViews.indexOf(miv2), 1);
			}
			const pi = msgitemViews.indexOf(miv);
			msgitemViews.splice(pi + 1, 0, ...mivl);
			const next = miv.root.nextSibling;
			for (const miv2 of mivl) {
				mlv.root.insertBefore(miv2.root, next);
			}
			if (changeState) {
				updateState(oldstate);
			}
		}, "threadExpand");
		const threadCollapse = /* @__PURE__ */ __name((miv, changeState) => {
			if (miv.parent) {
				throw new ConsistencyError("cannot expand non-root");
			}
			const oldstate = state();
			miv.collapsed = true;
			const mivl = miv.descendants();
			collapsedMsgitemViews.push(...mivl);
			let select = [miv, ...mivl].find((xmiv) => selected.indexOf(xmiv) >= 0);
			let seli = selected.length;
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
			if (changeState) {
				updateState(oldstate);
			}
			miv.render();
		}, "threadCollapse");
		const threadToggle = /* @__PURE__ */ __name(() => {
			const oldstate = state();
			const roots = msgitemViews.filter((miv) => !miv.parent && miv.kids.length > 0);
			roots.forEach((miv) => {
				let wantCollapsed = miv.messageitem.Message.ThreadCollapsed;
				if (settings.threading === ThreadMode.ThreadUnread) {
					wantCollapsed = !miv.messageitem.Message.Seen && !miv.findDescendant((miv2) => !miv2.messageitem.Message.Seen);
				}
				if (miv.collapsed === wantCollapsed) {
					return;
				}
				if (wantCollapsed) {
					threadCollapse(miv, false);
				} else {
					threadExpand(miv, false);
				}
			});
			updateState(oldstate);
			viewportEnsureMessages();
		}, "threadToggle");
		const removeSelected = /* @__PURE__ */ __name((miv) => {
			const si = selected.indexOf(miv);
			if (si >= 0) {
				selected.splice(si, 1);
			}
			if (focus === miv) {
				const i = msgitemViews.indexOf(miv);
				if (i > 0) {
					focus = msgitemViews[i - 1];
				} else if (i + 1 < msgitemViews.length) {
					focus = msgitemViews[i + 1];
				} else {
					focus = null;
				}
			}
		}, "removeSelected");
		const removeUID = /* @__PURE__ */ __name((mailboxID, uid) => {
			const match = /* @__PURE__ */ __name((miv) => miv.messageitem.Message.MailboxID === mailboxID && miv.messageitem.Message.UID === uid, "match");
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
			const ti = oldThreadMessageItems.findIndex((mi) => mi.Message.MailboxID === mailboxID && mi.Message.UID === uid);
			if (ti >= 0) {
				oldThreadMessageItems.splice(ti, 1);
			}
			return 0;
		}, "removeUID");
		const removeCollapsed = /* @__PURE__ */ __name((ci) => {
			const miv = collapsedMsgitemViews[ci];
			collapsedMsgitemViews.splice(ci, 1);
			removeSelected(miv);
			const trmiv = miv.threadRoot();
			const pmiv = miv.parent;
			if (!pmiv) {
				throw new ConsistencyError("removing collapsed miv, but has no parent");
			}
			miv.parent = null;
			const pki = pmiv.kids.indexOf(miv);
			if (pki < 0) {
				throw new ConsistencyError("miv not in parent.kids");
			}
			pmiv.kids.splice(pki, 1, ...miv.kids);
			miv.kids.forEach((kmiv) => kmiv.parent = pmiv);
			miv.kids = [];
			pmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
			trmiv.render();
			return;
		}, "removeCollapsed");
		const removeExpanded = /* @__PURE__ */ __name((i) => {
			log("removeExpanded", { i });
			const miv = msgitemViews[i];
			removeSelected(miv);
			const pmiv = miv.parent;
			miv.parent = null;
			if (miv.kids.length === 0) {
				miv.remove();
				msgitemViews.splice(i, 1);
				if (pmiv) {
					const pki2 = pmiv.kids.indexOf(miv);
					if (pki2 < 0) {
						throw new ConsistencyError("miv not in parent.kids");
					}
					pmiv.kids.splice(pki2, 1);
					miv.parent = null;
					pmiv.render();
				}
				return;
			}
			if (!pmiv) {
				const next2 = miv.root.nextSibling;
				miv.remove();
				msgitemViews.splice(i, 1);
				if (miv.collapsed) {
					msgitemViews.splice(i, 0, ...miv.kids);
					for (const kmiv of miv.kids) {
						const pki2 = collapsedMsgitemViews.indexOf(kmiv);
						if (pki2 < 0) {
							throw new ConsistencyError("cannot find collapsed kid in collapsedMsgitemViews");
						}
						collapsedMsgitemViews.splice(pki2, 1);
						kmiv.collapsed = true;
						kmiv.parent = null;
						kmiv.render();
						mlv.root.insertBefore(kmiv.root, next2);
					}
				} else {
					miv.kids.forEach((kmiv) => {
						kmiv.collapsed = false;
						kmiv.parent = null;
						kmiv.render();
						const lastDesc = kmiv.lastDescendant();
						if (lastDesc) {
							lastDesc.render();
						}
					});
				}
				miv.kids = [];
				return;
			}
			const odmivs = pmiv.descendants();
			const pi = msgitemViews.indexOf(pmiv);
			if (pi < 0) {
				throw new ConsistencyError("cannot find parent of removed miv");
			}
			msgitemViews.splice(pi + 1, odmivs.length);
			const pki = pmiv.kids.indexOf(miv);
			if (pki < 0) {
				throw new Error("did not find miv in parent.kids");
			}
			pmiv.kids.splice(pki, 1);
			pmiv.kids.push(...miv.kids);
			miv.kids.forEach((kmiv) => {
				kmiv.parent = pmiv;
			});
			miv.kids = [];
			pmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
			const ndmivs = pmiv.descendants();
			if (ndmivs.length !== odmivs.length - 1) {
				throw new ConsistencyError("unexpected new descendants counts during remove");
			}
			msgitemViews.splice(pi + 1, 0, ...ndmivs);
			odmivs.forEach((ndimv) => ndimv.remove());
			const next = pmiv.root.nextSibling;
			for (const ndmiv of ndmivs) {
				mlv.root.insertBefore(ndmiv.root, next);
			}
			pmiv.render();
			ndmivs.forEach((dmiv) => dmiv.render());
		}, "removeExpanded");
		const possiblyTakeoutOldThreads = /* @__PURE__ */ __name((threadIDs) => {
			const hasMatch = /* @__PURE__ */ __name((mivs, threadID) => mivs.find((miv) => miv.messageitem.Message.ThreadID === threadID && miv.messageitem.MatchQuery), "hasMatch");
			const takeoutOldThread = /* @__PURE__ */ __name((mivs, threadID, visible) => {
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
						} else if (i > 0) {
							focus = mivs[i - 1];
						}
					}
					const si = selected.indexOf(miv);
					if (si >= 0) {
						selected.splice(si, 1);
					}
					miv.parent = null;
					miv.kids = [];
					oldThreadMessageItems.push(mi);
					log("took out old thread message", { mi });
				}
			}, "takeoutOldThread");
			for (const threadID of threadIDs) {
				if (hasMatch(msgitemViews, threadID) || hasMatch(collapsedMsgitemViews, threadID)) {
					log("still have query-matching message for thread", { threadID });
					continue;
				}
				takeoutOldThread(msgitemViews, threadID, true);
				takeoutOldThread(collapsedMsgitemViews, threadID, false);
			}
		}, "possiblyTakeoutOldThreads");
		const mlv = {
			root: dom.div(),
			updateFlags: /* @__PURE__ */ __name((mailboxID, uid, modseq, mask, flags, keywords) => {
				const updateMessageFlags = /* @__PURE__ */ __name((m) => {
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
				}, "updateMessageFlags");
				let miv = msgitemViews.find((miv2) => miv2.messageitem.Message.MailboxID === mailboxID && miv2.messageitem.Message.UID === uid);
				if (!miv) {
					miv = collapsedMsgitemViews.find((miv2) => miv2.messageitem.Message.MailboxID === mailboxID && miv2.messageitem.Message.UID === uid);
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
				const mi = oldThreadMessageItems.find((mi2) => mi2.Message.MailboxID === mailboxID && mi2.Message.UID === uid);
				if (mi) {
					updateMessageFlags(mi.Message);
				} else {
					log("could not find msgitemView for uid", uid);
				}
			}, "updateFlags"),
			// Add messages to view, either messages to fill the view with complete threads, or
			// individual messages delivered later.
			addMessageItems: /* @__PURE__ */ __name((messageItems, isChange, requestMsgID) => {
				if (messageItems.length === 0) {
					return;
				}
				messageItems.forEach((mil) => {
					if (!mil) {
						return;
					}
					const threadID = mil[0].Message.ThreadID;
					const hasMatch = !!mil.find((mi) => mi.MatchQuery);
					if (hasMatch) {
						let i = 0;
						while (i < oldThreadMessageItems.length) {
							const omi = oldThreadMessageItems[i];
							if (omi.Message.ThreadID === threadID) {
								oldThreadMessageItems.splice(i, 1);
								if (!mil.find((mi) => mi.Message.ID === omi.Message.ID)) {
									mil.push(omi);
									log("resurrected old message");
								} else {
									log("dropped old thread message");
								}
							} else {
								i++;
							}
						}
					} else {
						const match = /* @__PURE__ */ __name((miv) => miv.messageitem.Message.ThreadID === threadID, "match");
						if (!msgitemViews.find(match) && !collapsedMsgitemViews.find(match)) {
							log("adding new message(s) to oldTheadMessageItems");
							for (const mi of mil) {
								const ti = oldThreadMessageItems.findIndex((tmi) => tmi.Message.ID === mi.Message.ID);
								if (ti) {
									oldThreadMessageItems[ti] = mi;
								} else {
									oldThreadMessageItems.push(mi);
								}
							}
							return;
						}
					}
					if (isChange) {
						const threadIDs = /* @__PURE__ */ new Set();
						let i = 0;
						while (i < mil.length) {
							const mi = mil[i];
							let miv = msgitemViews.find((miv2) => miv2.messageitem.Message.ID === mi.Message.ID);
							if (!miv) {
								miv = collapsedMsgitemViews.find((miv2) => miv2.messageitem.Message.ID === mi.Message.ID);
							}
							if (miv) {
								miv.messageitem = mi;
								miv.render();
								mil.splice(i, 1);
								miv.threadRoot().render();
								threadIDs.add(mi.Message.ThreadID);
							} else {
								i++;
							}
						}
						log("processed changes for messages with thread", { threadIDs, mil });
						if (mil.length === 0) {
							const oldstate2 = state();
							possiblyTakeoutOldThreads(threadIDs);
							updateState(oldstate2);
							return;
						}
					}
					let receivedTime = mil[0].Message.Received.getTime();
					const tmiv = msgitemViews.find((miv) => miv.messageitem.Message.ThreadID === mil[0].Message.ThreadID);
					if (tmiv) {
						receivedTime = tmiv.receivedTime;
					} else {
						for (const mi of mil) {
							const t = mi.Message.Received.getTime();
							if (settings.orderAsc && t < receivedTime || !settings.orderAsc && t > receivedTime) {
								receivedTime = t;
							}
						}
					}
					const m = /* @__PURE__ */ new Map();
					for (const mi of mil) {
						m.set(mi.Message.ID, newMsgitemView(mi, mlv, otherMailbox, listMailboxes, receivedTime, false));
					}
					let roots = [];
					if (settings.threading === ThreadMode.ThreadOff) {
						roots = [...m.values()];
					} else {
						nextmiv: for (const [_, miv] of m) {
							for (const pid of miv.messageitem.Message.ThreadParentIDs || []) {
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
					for (const [_, miv] of m) {
						miv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
					}
					if (settings.threading !== ThreadMode.ThreadOff) {
						nextroot: for (let i = 0; i < roots.length; ) {
							const miv = roots[i];
							for (const pid of miv.messageitem.Message.ThreadParentIDs || []) {
								const pi = msgitemViews.findIndex((xmiv) => xmiv.messageitem.Message.ID === pid);
								let parentmiv;
								let collapsed;
								if (pi >= 0) {
									parentmiv = msgitemViews[pi];
									collapsed = parentmiv.collapsed;
									log("found parent", { pi });
								} else {
									parentmiv = collapsedMsgitemViews.find((xmiv) => xmiv.messageitem.Message.ID === pid);
									collapsed = true;
								}
								if (!parentmiv) {
									log("no parentmiv", pid);
									continue;
								}
								const trmiv = parentmiv.threadRoot();
								if (collapsed !== trmiv.collapsed) {
									log("collapsed mismatch", { collapsed, "trmiv.collapsed": trmiv.collapsed, trmiv });
									throw new ConsistencyError("mismatch between msgitemViews/collapsedMsgitemViews and threadroot collapsed");
								}
								let prevLastDesc = null;
								if (!trmiv.collapsed) {
									const ndesc = parentmiv.descendants().length;
									log("removing descendants temporarily", { ndesc });
									prevLastDesc = parentmiv.lastDescendant();
									msgitemViews.splice(pi + 1, ndesc);
								}
								miv.parent = parentmiv;
								parentmiv.kids.push(miv);
								parentmiv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
								if (trmiv.collapsed) {
									collapsedMsgitemViews.push(miv, ...miv.descendants());
									miv.render();
									miv.descendants().forEach((miv2) => miv2.render());
									trmiv.render();
								} else {
									const desc = parentmiv.descendants();
									log("inserting parent descendants again", { pi, desc });
									msgitemViews.splice(pi + 1, 0, ...desc);
									const i2 = msgitemViews.indexOf(miv);
									if (i2 < 0) {
										throw new ConsistencyError("cannot find miv just inserted");
									}
									const l = [miv, ...miv.descendants()];
									l.forEach((miv2) => miv2.render());
									const next = i2 + 1 < msgitemViews.length ? msgitemViews[i2 + 1].root : null;
									log("inserting l before next, or appending", { next, l });
									if (next) {
										for (const miv2 of l) {
											log("inserting miv", { root: miv2.root, before: next });
											mlv.root.insertBefore(miv2.root, next);
										}
									} else {
										mlv.root.append(...l.map((e) => e.root));
									}
									msgitemViews[i2 - 1].render();
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
					const sign = settings.threading === ThreadMode.ThreadOff && settings.orderAsc ? -1 : 1;
					roots.sort((miva, mivb) => sign * (mivb.messageitem.Message.Received.getTime() - miva.messageitem.Message.Received.getTime()));
					let nextmivindex;
					if (tmiv) {
						nextmivindex = msgitemViews.indexOf(tmiv.threadRoot());
					} else {
						nextmivindex = msgitemViews.findIndex((miv) => !settings.orderAsc && miv.receivedTime <= receivedTime || settings.orderAsc && receivedTime <= miv.receivedTime);
					}
					for (const miv of roots) {
						miv.collapsed = settings.threading === ThreadMode.ThreadOn && miv.messageitem.Message.ThreadCollapsed;
						if (settings.threading === ThreadMode.ThreadUnread) {
							miv.collapsed = miv.messageitem.Message.Seen && !miv.findDescendant((dmiv) => !dmiv.messageitem.Message.Seen);
						}
						if (requestMsgID > 0 && miv.collapsed) {
							miv.collapsed = !miv.findDescendant((dmiv) => dmiv.messageitem.Message.ID === requestMsgID);
						}
						const takeThreadRoot = /* @__PURE__ */ __name((xmiv) => {
							log("taking threadRoot", { id: xmiv.messageitem.Message.ID });
							const xdmiv = xmiv.descendants();
							xdmiv.forEach((xdmiv2) => xdmiv2.remove());
							xmiv.remove();
							miv.kids.push(xmiv);
							xmiv.parent = miv;
							miv.kids.sort((miva, mivb) => miva.messageitem.Message.Received.getTime() - mivb.messageitem.Message.Received.getTime());
							return 1 + xdmiv.length;
						}, "takeThreadRoot");
						if (settings.threading !== ThreadMode.ThreadOff) {
							for (let i = 0; i < msgitemViews.length; ) {
								const xmiv = msgitemViews[i];
								if (!xmiv.parent && xmiv.messageitem.Message.ThreadID === miv.messageitem.Message.ThreadID && (xmiv.messageitem.Message.ThreadParentIDs || []).includes(miv.messageitem.Message.ID)) {
									msgitemViews.splice(i, takeThreadRoot(xmiv));
									nextmivindex = i;
								} else {
									i++;
								}
							}
							for (let i = 0; i < collapsedMsgitemViews.length; ) {
								const xmiv = collapsedMsgitemViews[i];
								if (!xmiv.parent && xmiv.messageitem.Message.ThreadID === miv.messageitem.Message.ThreadID && (xmiv.messageitem.Message.ThreadParentIDs || []).includes(miv.messageitem.Message.ID)) {
									takeThreadRoot(xmiv);
									collapsedMsgitemViews.splice(i, 1);
								} else {
									i++;
								}
							}
						}
						let l = miv.descendants();
						miv.render();
						l.forEach((kmiv) => kmiv.render());
						if (miv.collapsed) {
							collapsedMsgitemViews.push(...l);
							l = [miv];
						} else {
							l = [miv, ...l];
						}
						if (nextmivindex < 0) {
							mlv.root.append(...l.map((miv2) => miv2.root));
							msgitemViews.push(...l);
						} else {
							const next = msgitemViews[nextmivindex].root;
							for (const miv2 of l) {
								mlv.root.insertBefore(miv2.root, next);
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
					} else if (msgitemViews.length > 0) {
						selected = [msgitemViews[0]];
					}
				}
				updateState(oldstate);
			}, "addMessageItems"),
			// Remove messages, they can be in different threads.
			removeUIDs: /* @__PURE__ */ __name((mailboxID, uids) => {
				const oldstate = state();
				const hadSelected = selected.length > 0;
				const threadIDs = /* @__PURE__ */ new Set();
				uids.forEach((uid) => {
					const threadID = removeUID(mailboxID, uid);
					log("removed message with thread", { threadID });
					if (threadID) {
						threadIDs.add(threadID);
					}
				});
				possiblyTakeoutOldThreads(threadIDs);
				if (hadSelected && focus && selected.length === 0) {
					selected = [focus];
				}
				updateState(oldstate);
			}, "removeUIDs"),
			// Set new muted/collapsed flags for messages in thread.
			updateMessageThreadFields: /* @__PURE__ */ __name((messageIDs, muted, collapsed) => {
				for (const id of messageIDs) {
					let miv = msgitemViews.find((miv2) => miv2.messageitem.Message.ID === id);
					if (!miv) {
						miv = collapsedMsgitemViews.find((miv2) => miv2.messageitem.Message.ID === id);
					}
					if (miv) {
						miv.messageitem.Message.ThreadMuted = muted;
						miv.messageitem.Message.ThreadCollapsed = collapsed;
						const mivthr = miv.threadRoot();
						if (mivthr.collapsed) {
							mivthr.render();
						} else {
							miv.render();
						}
					} else {
						const mi = oldThreadMessageItems.find((mi2) => mi2.Message.ID === id);
						if (mi) {
							mi.Message.ThreadMuted = muted;
							mi.Message.ThreadCollapsed = collapsed;
						}
					}
				}
			}, "updateMessageThreadFields"),
			// For location hash.
			activeMessageID: /* @__PURE__ */ __name(() => selected.length === 1 ? selected[0].messageitem.Message.ID : 0, "activeMessageID"),
			redraw: /* @__PURE__ */ __name((miv) => {
				miv.root.classList.toggle("focus", miv === focus);
				miv.root.classList.toggle("active", selected.indexOf(miv) >= 0);
			}, "redraw"),
			clear: /* @__PURE__ */ __name(() => {
				dom._kids(mlv.root);
				msgitemViews.forEach((miv) => miv.remove());
				msgitemViews = [];
				collapsedMsgitemViews = [];
				oldThreadMessageItems = [];
				focus = null;
				selected = [];
				dom._kids(msgElem);
				msgView = null;
				setLocationHash();
			}, "clear"),
			unselect: /* @__PURE__ */ __name(() => {
				const oldstate = state();
				selected = [];
				updateState(oldstate);
			}, "unselect"),
			select: /* @__PURE__ */ __name((miv) => {
				const oldstate = state();
				focus = miv;
				selected = [miv];
				updateState(oldstate);
			}, "select"),
			selected: /* @__PURE__ */ __name(() => {
				const l = [];
				for (const miv of selected) {
					l.push(miv);
					if (miv.collapsed) {
						l.push(...miv.descendants());
					}
				}
				return l;
			}, "selected"),
			openMessage: /* @__PURE__ */ __name((parsedMessage) => {
				let miv = msgitemViews.find((miv2) => miv2.messageitem.Message.ID === parsedMessage.ID);
				if (!miv) {
					return false;
				}
				const oldstate = state();
				focus = miv;
				selected = [miv];
				updateState(oldstate, true, parsedMessage);
				return true;
			}, "openMessage"),
			click: /* @__PURE__ */ __name((miv, ctrl, shift) => {
				if (msgitemViews.length === 0) {
					return;
				}
				const oldstate = state();
				if (shift) {
					const mivindex = msgitemViews.indexOf(miv);
					let recentindex;
					if (selected.length > 0) {
						let o = selected.length - 1;
						recentindex = msgitemViews.indexOf(selected[o]);
						while (o > 0) {
							if (selected[o - 1] === msgitemViews[recentindex - 1]) {
								recentindex--;
							} else if (selected[o - 1] === msgitemViews[recentindex + 1]) {
								recentindex++;
							} else {
								break;
							}
							o--;
						}
					} else {
						recentindex = mivindex;
					}
					const oselected = selected;
					if (mivindex < recentindex) {
						selected = msgitemViews.slice(mivindex, recentindex + 1);
						selected.reverse();
					} else {
						selected = msgitemViews.slice(recentindex, mivindex + 1);
					}
					if (ctrl) {
						selected = oselected.filter((e) => !selected.includes(e)).concat(selected);
					}
				} else if (ctrl) {
					const index = selected.indexOf(miv);
					if (index < 0) {
						selected.push(miv);
					} else {
						selected.splice(index, 1);
					}
				} else {
					selected = [miv];
				}
				focus = miv;
				updateState(oldstate);
			}, "click"),
			key: /* @__PURE__ */ __name(async (k, e) => {
				const moveKeys = [
					" ",
					"ArrowUp",
					"ArrowDown",
					"PageUp",
					"h",
					"H",
					"PageDown",
					"l",
					"L",
					"j",
					"J",
					"k",
					"K",
					"Home",
					",",
					"<",
					"End",
					".",
					">",
					"n",
					"N",
					"p",
					"P",
					"u",
					"U"
				];
				if (!e.altKey && !e.metaKey && moveKeys.includes(e.key)) {
					const moveclick = /* @__PURE__ */ __name((index, clip) => {
						if (clip && index < 0) {
							index = 0;
						} else if (clip && index >= msgitemViews.length) {
							index = msgitemViews.length - 1;
						}
						if (index < 0 || index >= msgitemViews.length) {
							return;
						}
						if (e.ctrlKey) {
							moveFocus(msgitemViews[index]);
						} else {
							mlv.click(msgitemViews[index], false, e.shiftKey);
						}
					}, "moveclick");
					let i = msgitemViews.findIndex((miv) => miv === focus);
					if (e.key === " ") {
						if (i >= 0) {
							mlv.click(msgitemViews[i], e.ctrlKey, e.shiftKey);
						}
					} else if (e.key === "ArrowUp" || e.key === "k" || e.key === "K") {
						moveclick(i - 1, e.key === "K");
					} else if (e.key === "ArrowDown" || e.key === "j" || e.key === "J") {
						moveclick(i + 1, e.key === "J");
					} else if (e.key === "PageUp" || e.key === "h" || e.key === "H" || e.key === "PageDown" || e.key === "l" || e.key === "L") {
						if (e.key === "l" && e.ctrlKey) {
							return;
						}
						if (msgitemViews.length > 0) {
							let n = Math.max(1, Math.floor(scrollElemHeight() / mlv.itemHeight()) - 1);
							if (e.key === "PageUp" || e.key === "h" || e.key === "H") {
								n = -n;
							}
							moveclick(i + n, true);
						}
					} else if (e.key === "Home" || e.key === "," || e.key === "<") {
						moveclick(0, true);
					} else if (e.key === "End" || e.key === "." || e.key === ">") {
						moveclick(msgitemViews.length - 1, true);
					} else if (e.key === "n" || e.key === "N") {
						if (i < 0) {
							moveclick(0, true);
						} else {
							const tid = msgitemViews[i].messageitem.Message.ThreadID;
							for (; i < msgitemViews.length; i++) {
								if (msgitemViews[i].messageitem.Message.ThreadID !== tid) {
									moveclick(i, true);
									break;
								}
							}
						}
					} else if (e.key === "p" || e.key === "P") {
						if (i < 0) {
							moveclick(0, true);
						} else {
							let thrmiv = msgitemViews[i].threadRoot();
							if (thrmiv === msgitemViews[i]) {
								if (i - 1 >= 0) {
									thrmiv = msgitemViews[i - 1].threadRoot();
								}
							}
							moveclick(msgitemViews.indexOf(thrmiv), true);
						}
					} else if (e.key === "u" || e.key === "U") {
						if (e.key === "u" && e.ctrlKey) {
							return;
						}
						for (i = i < 0 ? 0 : i + 1; i < msgitemViews.length; i += 1) {
							if (!msgitemViews[i].messageitem.Message.Seen || msgitemViews[i].collapsed && msgitemViews[i].findDescendant((miv) => !miv.messageitem.Message.Seen)) {
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
				} else if (msgView) {
					msgView.key(k, e);
				} else {
					log("key not handled", k);
				}
			}, "key"),
			mailboxes: /* @__PURE__ */ __name(() => listMailboxes(), "mailboxes"),
			activeMailbox: /* @__PURE__ */ __name(() => activeMailbox(), "activeMailbox"),
			itemHeight: /* @__PURE__ */ __name(() => msgitemViews.length > 0 ? msgitemViews[0].root.getBoundingClientRect().height : 25, "itemHeight"),
			threadExpand: /* @__PURE__ */ __name((miv) => threadExpand(miv, true), "threadExpand"),
			threadCollapse: /* @__PURE__ */ __name((miv) => threadCollapse(miv, true), "threadCollapse"),
			threadToggle,
			viewportEnsureMessages,
			cmdArchive,
			cmdTrash,
			cmdDelete,
			cmdJunk,
			cmdMarkNotJunk,
			cmdMarkRead,
			cmdMarkUnread,
			cmdMute,
			cmdUnmute
		};
		return mlv;
	}, "newMsglistView");
	var popoverExport = /* @__PURE__ */ __name((reference, mailboxName, messageIDs) => {
		let format;
		let archive;
		let mboxbtn;
		const removeExport = popover(reference, {}, dom.h1("Export"), dom.form(/* @__PURE__ */ __name(function submit() {
			window.setTimeout(() => removeExport(), 100);
		}, "submit"), attr.target("_blank"), attr.method("POST"), attr.action("export"), dom.input(attr.type("hidden"), attr.name("csrf"), attr.value(localStorageGet("webmailcsrftoken") || "")), dom.input(attr.type("hidden"), attr.name("mailbox"), attr.value(mailboxName)), dom.input(attr.type("hidden"), attr.name("messageids"), attr.value((messageIDs || []).join(","))), format = dom.input(attr.type("hidden"), attr.name("format")), archive = dom.input(attr.type("hidden"), attr.name("archive")), dom.div(css("exportFields", { display: "flex", flexDirection: "column", gap: ".5ex" }), mailboxName ? dom.div(dom.label(dom.input(attr.type("checkbox"), attr.name("recursive"), attr.value("on"), /* @__PURE__ */ __name(function change(e) {
			mboxbtn.disabled = e.target.checked;
		}, "change")), " Recursive")) : [], dom.div(!mailboxName && !messageIDs ? "Mbox " : mboxbtn = dom.submitbutton("Mbox", attr.title("Export as mbox file, not wrapped in an archive."), /* @__PURE__ */ __name(function click() {
			format.value = "mbox";
			archive.value = "none";
		}, "click")), " ", dom.submitbutton("zip", /* @__PURE__ */ __name(function click() {
			format.value = "mbox";
			archive.value = "zip";
		}, "click")), " ", dom.submitbutton("tgz", /* @__PURE__ */ __name(function click() {
			format.value = "mbox";
			archive.value = "tgz";
		}, "click")), " ", dom.submitbutton("tar", /* @__PURE__ */ __name(function click() {
			format.value = "mbox";
			archive.value = "tar";
		}, "click"))), dom.div("Maildir ", dom.submitbutton("zip", /* @__PURE__ */ __name(function click() {
			format.value = "maildir";
			archive.value = "zip";
		}, "click")), " ", dom.submitbutton("tgz", /* @__PURE__ */ __name(function click() {
			format.value = "maildir";
			archive.value = "tgz";
		}, "click")), " ", dom.submitbutton("tar", /* @__PURE__ */ __name(function click() {
			format.value = "maildir";
			archive.value = "tar";
		}, "click"))))));
	}, "popoverExport");
	var newMailboxView = /* @__PURE__ */ __name((xmb, mailboxlistView, otherMailbox) => {
		const plusbox = "\u229E";
		const minusbox = "\u229F";
		const cmdCollapse = /* @__PURE__ */ __name(async () => {
			settings.mailboxCollapsed[mbv.mailbox.ID] = true;
			settingsPut(settings);
			mailboxlistView.updateHidden();
			mbv.root.focus();
		}, "cmdCollapse");
		const cmdExpand = /* @__PURE__ */ __name(async () => {
			delete settings.mailboxCollapsed[mbv.mailbox.ID];
			settingsPut(settings);
			mailboxlistView.updateHidden();
			mbv.root.focus();
		}, "cmdExpand");
		const collapseElem = dom.span(dom._class("mailboxCollapse"), minusbox, /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
			cmdCollapse();
		}, "click"));
		const expandElem = dom.span(plusbox, /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
			cmdExpand();
		}, "click"));
		let name, unread;
		let actionBtn;
		const cmdOpenActions = /* @__PURE__ */ __name(async () => {
			const trashmb = mailboxlistView.mailboxes().find((mb) => mb.Trash);
			const remove = popover(actionBtn, { transparent: true }, dom.div(style({ display: "flex", flexDirection: "column", gap: ".5ex" }), dom.div(dom.clickbutton("Mark as read", attr.title("Mark all messages in the mailbox and its sub mailboxes as read."), /* @__PURE__ */ __name(async function click() {
				remove();
				const mailboxIDs = [mbv.mailbox.ID, ...mailboxlistView.mailboxes().filter((mb) => mb.Name.startsWith(mbv.mailbox.Name + "/")).map((mb) => mb.ID)];
				await withStatus("Marking mailboxes as read", client.MailboxesMarkRead(mailboxIDs));
			}, "click"))), dom.div(dom.clickbutton("Create mailbox", attr.title("Create new mailbox within this mailbox."), /* @__PURE__ */ __name(function click(e) {
				let fieldset;
				let name2;
				const ref = e.target;
				const removeCreate = popover(ref, {}, dom.form(/* @__PURE__ */ __name(async function submit(e2) {
					e2.preventDefault();
					await withStatus("Creating mailbox", client.MailboxCreate(mbv.mailbox.Name + "/" + name2.value), fieldset);
					removeCreate();
				}, "submit"), fieldset = dom.fieldset(dom.label("Name ", name2 = dom.input(attr.required("yes"))), " ", dom.submitbutton("Create"))));
				remove();
				name2.focus();
			}, "click"))), dom.div(dom.clickbutton("Move to trash", attr.title("Move mailbox, its messages and its mailboxes to the trash."), /* @__PURE__ */ __name(async function click() {
				if (!trashmb) {
					window.alert("No mailbox configured for trash yet.");
					return;
				}
				if (!window.confirm("Are you sure you want to move this mailbox, its messages and its mailboxes to the trash?")) {
					return;
				}
				remove();
				await withStatus("Moving mailbox to trash", client.MailboxRename(mbv.mailbox.ID, trashmb.Name + "/" + mbv.mailbox.Name));
			}, "click"))), dom.div(dom.clickbutton("Delete mailbox", attr.title("Permanently delete this mailbox and all its messages."), /* @__PURE__ */ __name(async function click() {
				if (!window.confirm("Are you sure you want to permanently delete this mailbox and all its messages?")) {
					return;
				}
				remove();
				await withStatus("Deleting mailbox", client.MailboxDelete(mbv.mailbox.ID));
			}, "click"))), dom.div(dom.clickbutton("Empty mailbox", attr.title("Remove all messages from the mailbox, but not mailboxes inside this mailbox or their messages."), /* @__PURE__ */ __name(async function click() {
				if (!window.confirm("Are you sure you want to empty this mailbox, permanently removing its messages? Mailboxes inside this mailbox are not affected.")) {
					return;
				}
				remove();
				await withStatus("Emptying mailbox", client.MailboxEmpty(mbv.mailbox.ID));
			}, "click"))), dom.div(dom.clickbutton("Rename mailbox", /* @__PURE__ */ __name(function click() {
				remove();
				let fieldset, name2;
				const remove2 = popover(actionBtn, {}, dom.form(/* @__PURE__ */ __name(async function submit(e) {
					e.preventDefault();
					await withStatus("Renaming mailbox", client.MailboxRename(mbv.mailbox.ID, name2.value), fieldset);
					remove2();
				}, "submit"), fieldset = dom.fieldset(dom.label("Name ", name2 = dom.input(attr.required(""), attr.value(mbv.mailbox.Name), prop({ selectionStart: 0, selectionEnd: mbv.mailbox.Name.length }))), " ", dom.submitbutton("Rename"))));
				name2.focus();
			}, "click"))), dom.div(dom.clickbutton("Set role for mailbox...", attr.title("Set a special-use role on the mailbox, making it the designated mailbox for either Archived, Sent, Draft, Trashed or Junk messages."), /* @__PURE__ */ __name(async function click() {
				remove();
				const setUse = /* @__PURE__ */ __name(async (set) => {
					const mb = { ...mbv.mailbox };
					mb.Archive = mb.Draft = mb.Junk = mb.Sent = mb.Trash = false;
					set(mb);
					await withStatus("Marking mailbox as special use", client.MailboxSetSpecialUse(mb));
				}, "setUse");
				popover(actionBtn, { transparent: true }, dom.div(style({ display: "flex", flexDirection: "column", gap: ".5ex" }), dom.div(dom.clickbutton("Archive", /* @__PURE__ */ __name(async function click2() {
					await setUse((mb) => {
						mb.Archive = true;
					});
				}, "click"))), dom.div(dom.clickbutton("Draft", /* @__PURE__ */ __name(async function click2() {
					await setUse((mb) => {
						mb.Draft = true;
					});
				}, "click"))), dom.div(dom.clickbutton("Junk", /* @__PURE__ */ __name(async function click2() {
					await setUse((mb) => {
						mb.Junk = true;
					});
				}, "click"))), dom.div(dom.clickbutton("Sent", /* @__PURE__ */ __name(async function click2() {
					await setUse((mb) => {
						mb.Sent = true;
					});
				}, "click"))), dom.div(dom.clickbutton("Trash", /* @__PURE__ */ __name(async function click2() {
					await setUse((mb) => {
						mb.Trash = true;
					});
				}, "click")))));
			}, "click"))), dom.div(dom.clickbutton("Export as...", /* @__PURE__ */ __name(function click() {
				popoverExport(actionBtn, mbv.mailbox.Name, null);
				remove();
			}, "click")))));
		}, "cmdOpenActions");
		let drags = 0;
		const mailboxItemStyle = css("mailboxItem", { cursor: "pointer", borderRadius: ".15em", userSelect: "none" });
		ensureCSS(".mailboxItem.dropping", { background: styles.highlightBackground }, true);
		ensureCSS(".mailboxItem:hover", { backgroundColor: styles.mailboxHoverBackgroundColor });
		ensureCSS(".mailboxItem.active", { background: styles.mailboxActiveBackground });
		ensureCSS(".mailboxHoverOnly", { visibility: "hidden" });
		ensureCSS(".mailboxItem:hover .mailboxHoverOnly, .mailboxItem:focus .mailboxHoverOnly", { visibility: "visible" });
		ensureCSS(".mailboxCollapse", { visibility: "hidden" });
		ensureCSS(".mailboxItem:hover .mailboxCollapse, .mailboxItem:focus .mailboxCollapse", { visibility: "visible" });
		const root = dom.div(mailboxItemStyle, attr.tabindex("0"), /* @__PURE__ */ __name(async function keydown(e) {
			if (e.key === "Enter") {
				e.stopPropagation();
				await withStatus("Opening mailbox", mbv.open(true));
			} else if (e.key === "ArrowLeft") {
				e.stopPropagation();
				if (!mailboxlistView.mailboxLeaf(mbv)) {
					cmdCollapse();
				}
			} else if (e.key === "ArrowRight") {
				e.stopPropagation();
				if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
					cmdExpand();
				}
			} else if (e.key === "b") {
				cmdOpenActions();
			}
		}, "keydown"), /* @__PURE__ */ __name(async function dblclick() {
			if (mailboxlistView.mailboxLeaf(mbv)) {
				return;
			}
			if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
				cmdExpand();
			} else {
				cmdCollapse();
			}
		}, "dblclick"), /* @__PURE__ */ __name(async function click() {
			mbv.root.focus();
			await withStatus("Opening mailbox", mbv.open(true));
		}, "click"), /* @__PURE__ */ __name(function dragover(e) {
			e.preventDefault();
			e.dataTransfer.dropEffect = "move";
		}, "dragover"), /* @__PURE__ */ __name(function dragenter(e) {
			e.stopPropagation();
			drags++;
			mbv.root.classList.toggle("dropping", true);
		}, "dragenter"), /* @__PURE__ */ __name(function dragleave(e) {
			e.stopPropagation();
			drags--;
			if (drags <= 0) {
				mbv.root.classList.toggle("dropping", false);
			}
		}, "dragleave"), /* @__PURE__ */ __name(async function drop(e) {
			e.preventDefault();
			mbv.root.classList.toggle("dropping", false);
			const sentMailboxID = mailboxlistView.mailboxes().find((mb) => mb.Sent)?.ID;
			const mailboxMsgIDs = JSON.parse(e.dataTransfer.getData("application/vnd.mox.messages"));
			const msgIDs = mailboxMsgIDs.filter((mbMsgID) => mbMsgID[0] !== xmb.ID).filter((mbMsgID) => mailboxMsgIDs.length === 1 || !sentMailboxID || mbMsgID[0] !== sentMailboxID || !otherMailbox(sentMailboxID)).map((mbMsgID) => mbMsgID[1]);
			await withStatus("Moving to " + xmb.Name, client.MessageMove(msgIDs, xmb.ID, false));
			if (msgIDs.length === 1) {
				const msgID = msgIDs[0];
				const mbSrcID = mailboxMsgIDs.find((mbMsgID) => mbMsgID[1] === msgID)[0];
				await moveAskRuleset(msgID, mbSrcID, xmb, mailboxlistView.mailboxes());
			}
		}, "drop"), dom.div(css("mailbox", { padding: ".15em .25em", display: "flex", justifyContent: "space-between" }), name = dom.div(css("mailboxName", { whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" })), dom.div(style({ whiteSpace: "nowrap" }), actionBtn = dom.clickbutton(
			dom._class("mailboxHoverOnly"),
			"...",
			attr.tabindex("-1"),
			// Without, tab breaks because this disappears when mailbox loses focus.
			attr.arialabel("Mailbox actions"),
			attr.title("Actions on mailbox, like deleting, emptying, renaming."),
			/* @__PURE__ */ __name(function click(e) {
				e.stopPropagation();
				cmdOpenActions();
			}, "click")
		), " ", unread = dom.b(dom._class("silenttitle")))));
		const update = /* @__PURE__ */ __name(() => {
			let moreElems = [];
			if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
				moreElems = [" ", expandElem];
			} else if (!mailboxlistView.mailboxLeaf(mbv)) {
				moreElems = [" ", collapseElem];
			}
			let ntotal = mbv.mailbox.Total;
			let nunread = mbv.mailbox.Unread;
			if (settings.mailboxCollapsed[mbv.mailbox.ID]) {
				const prefix = mbv.mailbox.Name + "/";
				for (const mb of mailboxlistView.mailboxes()) {
					if (mb.Name.startsWith(prefix)) {
						ntotal += mb.Total;
						nunread += mb.Unread;
					}
				}
			}
			dom._kids(name, dom.span(mbv.parents > 0 ? style({ paddingLeft: "" + mbv.parents * 2 / 3 + "em" }) : [], mbv.shortname, attr.title("Total messages: " + ntotal), moreElems));
			dom._kids(unread, nunread === 0 ? ["", attr.title("")] : ["" + nunread, attr.title("" + nunread + " unread")]);
		}, "update");
		const mbv = {
			root,
			// Set by update(), typically through MailboxlistView updateMailboxNames after inserting.
			shortname: "",
			parents: 0,
			hidden: false,
			update,
			mailbox: xmb,
			open: /* @__PURE__ */ __name(async (load) => {
				await mailboxlistView.openMailboxView(mbv, load, false);
			}, "open"),
			setCounts: /* @__PURE__ */ __name((total, unread2) => {
				mbv.mailbox.Total = total;
				mbv.mailbox.Unread = unread2;
				mailboxlistView.updateCounts();
			}, "setCounts"),
			setSpecialUse: /* @__PURE__ */ __name((specialUse) => {
				mbv.mailbox.Archive = specialUse.Archive;
				mbv.mailbox.Draft = specialUse.Draft;
				mbv.mailbox.Junk = specialUse.Junk;
				mbv.mailbox.Sent = specialUse.Sent;
				mbv.mailbox.Trash = specialUse.Trash;
			}, "setSpecialUse"),
			setKeywords: /* @__PURE__ */ __name((keywords) => {
				mbv.mailbox.Keywords = keywords;
			}, "setKeywords")
		};
		return mbv;
	}, "newMailboxView");
	var newMailboxlistView = /* @__PURE__ */ __name((msglistView, requestNewView, updatePageTitle, setLocationHash, unloadSearch, otherMailbox) => {
		let mailboxViews = [];
		let mailboxViewActive;
		const updateMailboxNames = /* @__PURE__ */ __name(() => {
			const draftmb = mailboxViews.find((mbv) => mbv.mailbox.Draft)?.mailbox;
			const sentmb = mailboxViews.find((mbv) => mbv.mailbox.Sent)?.mailbox;
			const archivemb = mailboxViews.find((mbv) => mbv.mailbox.Archive)?.mailbox;
			const trashmb = mailboxViews.find((mbv) => mbv.mailbox.Trash)?.mailbox;
			const junkmb = mailboxViews.find((mbv) => mbv.mailbox.Junk)?.mailbox;
			const stem = /* @__PURE__ */ __name((s) => s.split("/")[0], "stem");
			const special = [
				(mb) => stem(mb.Name) === "Inbox",
				(mb) => introboxMailbox !== "" && stem(mb.Name) === stem(introboxMailbox),
				// not "specialuse"
				(mb) => draftmb && stem(mb.Name) === stem(draftmb.Name),
				(mb) => sentmb && stem(mb.Name) === stem(sentmb.Name),
				(mb) => archivemb && stem(mb.Name) === stem(archivemb.Name),
				(mb) => trashmb && stem(mb.Name) === stem(trashmb.Name),
				(mb) => junkmb && stem(mb.Name) === stem(junkmb.Name)
			];
			mailboxViews.sort((mbva, mbvb) => {
				const ai = special.findIndex((fn) => fn(mbva.mailbox));
				const bi = special.findIndex((fn) => fn(mbvb.mailbox));
				if (ai < 0 && bi >= 0) {
					return 1;
				} else if (ai >= 0 && bi < 0) {
					return -1;
				} else if (ai >= 0 && bi >= 0 && ai !== bi) {
					return ai < bi ? -1 : 1;
				}
				const la = mbva.mailbox.Name.split("/");
				const lb = mbvb.mailbox.Name.split("/");
				let n = Math.min(la.length, lb.length);
				for (let i = 0; i < n; i++) {
					if (la[i] === lb[i]) {
						continue;
					}
					return la[i] < lb[i] ? -1 : 1;
				}
				return mbva.mailbox.Name < mbvb.mailbox.Name ? -1 : 1;
			});
			let prevmailboxname = "";
			mailboxViews.forEach((mbv) => {
				const mb = mbv.mailbox;
				let shortname = mb.Name;
				let parents = 0;
				if (prevmailboxname) {
					let prefix = "";
					for (const s of prevmailboxname.split("/")) {
						const nprefix = prefix + s + "/";
						if (mb.Name.startsWith(nprefix)) {
							prefix = nprefix;
							parents++;
						} else {
							break;
						}
					}
					shortname = mb.Name.substring(prefix.length);
				}
				mbv.shortname = shortname;
				mbv.parents = parents;
				mbv.update();
				prevmailboxname = mb.Name;
			});
			updateHidden();
		}, "updateMailboxNames");
		const mailboxHidden = /* @__PURE__ */ __name((mb, mailboxesMap) => {
			let s = "";
			for (const e of mb.Name.split("/")) {
				if (s) {
					s += "/";
				}
				s += e;
				const pmb = mailboxesMap[s];
				if (pmb && settings.mailboxCollapsed[pmb.ID] && s !== mb.Name) {
					return true;
				}
			}
			return false;
		}, "mailboxHidden");
		const mailboxLeaf = /* @__PURE__ */ __name((mbv) => {
			const index = mailboxViews.findIndex((v) => v === mbv);
			const prefix = mbv.mailbox.Name + "/";
			const r = index < 0 || index + 1 >= mailboxViews.length || !mailboxViews[index + 1].mailbox.Name.startsWith(prefix);
			return r;
		}, "mailboxLeaf");
		const updateHidden = /* @__PURE__ */ __name(() => {
			const mailboxNameMap = {};
			mailboxViews.forEach((mbv) => mailboxNameMap[mbv.mailbox.Name] = mbv.mailbox);
			for (const mbv of mailboxViews) {
				mbv.hidden = mailboxHidden(mbv.mailbox, mailboxNameMap);
			}
			mailboxViews.forEach((mbv) => mbv.update());
			dom._kids(mailboxesElem, mailboxViews.filter((mbv) => !mbv.hidden));
		}, "updateHidden");
		const root = dom.div();
		const mailboxesElem = dom.div();
		dom._kids(root, dom.div(attr.role("region"), attr.arialabel("Mailboxes"), dom.div(dom.h1("Mailboxes", css("mailboxesTitle", { display: "inline", fontSize: "inherit" })), " ", dom.clickbutton("...", attr.arialabel("Mailboxes actions"), attr.title("Actions on mailboxes like creating a new mailbox or exporting all email."), /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
			const remove = popover(e.target, { transparent: true }, dom.div(css("mailboxesActions", { display: "flex", flexDirection: "column", gap: ".5ex" }), dom.div(dom.clickbutton("Create mailbox", attr.arialabel("Create new mailbox."), attr.title("Create new mailbox."), style({ padding: "0 .25em" }), /* @__PURE__ */ __name(function click2(e2) {
				let fieldset;
				let name;
				const ref = e2.target;
				const removeCreate = popover(ref, {}, dom.form(/* @__PURE__ */ __name(async function submit(e3) {
					e3.preventDefault();
					await withStatus("Creating mailbox", client.MailboxCreate(name.value), fieldset);
					removeCreate();
				}, "submit"), fieldset = dom.fieldset(dom.label("Name ", name = dom.input(attr.required("yes"), focusPlaceholder("Lists/Go/Nuts"))), " ", dom.submitbutton("Create"))));
				remove();
				name.focus();
			}, "click"))), dom.div(dom.clickbutton("Export as...", /* @__PURE__ */ __name(function click2(e2) {
				const ref = e2.target;
				popoverExport(ref, "", null);
				remove();
			}, "click")))));
		}, "click"))), mailboxesElem));
		const loadMailboxes = /* @__PURE__ */ __name((mailboxes, mbnameOpt) => {
			mailboxViews = mailboxes.map((mb) => newMailboxView(mb, mblv, otherMailbox));
			updateMailboxNames();
			if (mbnameOpt) {
				const mbv = mailboxViews.find((mbv2) => mbv2.mailbox.Name === mbnameOpt);
				if (mbv) {
					openMailboxView(mbv, false, false);
				}
			}
		}, "loadMailboxes");
		const closeMailbox = /* @__PURE__ */ __name(() => {
			if (!mailboxViewActive) {
				return;
			}
			mailboxViewActive.root.classList.toggle("active", false);
			mailboxViewActive = null;
			updatePageTitle();
		}, "closeMailbox");
		const openMailboxView = /* @__PURE__ */ __name(async (mbv, load, focus) => {
			unloadSearch();
			if (mailboxViewActive) {
				mailboxViewActive.root.classList.toggle("active", false);
			}
			mailboxViewActive = mbv;
			mbv.root.classList.toggle("active", true);
			updatePageTitle();
			if (load) {
				setLocationHash();
				const f = newFilter();
				f.MailboxID = mbv.mailbox.ID;
				await withStatus("Requesting messages", requestNewView(true, f, newNotFilter()));
			} else {
				msglistView.clear();
				setLocationHash();
			}
			if (focus) {
				mbv.root.focus();
			}
		}, "openMailboxView");
		const mblv = {
			root,
			loadMailboxes,
			closeMailbox,
			openMailboxView,
			mailboxLeaf,
			updateHidden,
			updateCounts: /* @__PURE__ */ __name(() => mailboxViews.forEach((mbv) => mbv.update()), "updateCounts"),
			activeMailbox: /* @__PURE__ */ __name(() => mailboxViewActive ? mailboxViewActive.mailbox : null, "activeMailbox"),
			mailboxes: /* @__PURE__ */ __name(() => mailboxViews.map((mbv) => mbv.mailbox), "mailboxes"),
			findMailboxByID: /* @__PURE__ */ __name((id) => mailboxViews.find((mbv) => mbv.mailbox.ID === id)?.mailbox || null, "findMailboxByID"),
			findMailboxByName: /* @__PURE__ */ __name((name) => mailboxViews.find((mbv) => mbv.mailbox.Name === name)?.mailbox || null, "findMailboxByName"),
			openMailboxID: /* @__PURE__ */ __name(async (id, focus) => {
				const mbv = mailboxViews.find((mbv2) => mbv2.mailbox.ID === id);
				if (mbv) {
					await openMailboxView(mbv, false, focus);
				} else {
					throw new Error("unknown mailbox");
				}
			}, "openMailboxID"),
			addMailbox: /* @__PURE__ */ __name((mb) => {
				const mbv = newMailboxView(mb, mblv, otherMailbox);
				mailboxViews.push(mbv);
				updateMailboxNames();
			}, "addMailbox"),
			renameMailbox: /* @__PURE__ */ __name((mailboxID, newName) => {
				const mbv = mailboxViews.find((mbv2) => mbv2.mailbox.ID === mailboxID);
				if (!mbv) {
					throw new Error("rename event: unknown mailbox");
				}
				mbv.mailbox.Name = newName;
				updateMailboxNames();
			}, "renameMailbox"),
			removeMailbox: /* @__PURE__ */ __name((mailboxID) => {
				const mbv = mailboxViews.find((mbv2) => mbv2.mailbox.ID === mailboxID);
				if (!mbv) {
					throw new Error("remove event: unknown mailbox");
				}
				if (mbv === mailboxViewActive) {
					const inboxv = mailboxViews.find((mbv2) => mbv2.mailbox.Name === "Inbox");
					if (inboxv) {
						openMailboxView(inboxv, true, false);
					}
				}
				const index = mailboxViews.findIndex((mbv2) => mbv2.mailbox.ID === mailboxID);
				mailboxViews.splice(index, 1);
				updateMailboxNames();
			}, "removeMailbox"),
			setMailboxCounts: /* @__PURE__ */ __name((mailboxID, total, unread) => {
				const mbv = mailboxViews.find((mbv2) => mbv2.mailbox.ID === mailboxID);
				if (!mbv) {
					throw new Error("mailbox message/unread count changed: unknown mailbox");
				}
				mbv.setCounts(total, unread);
				if (mbv === mailboxViewActive) {
					updatePageTitle();
				}
			}, "setMailboxCounts"),
			setMailboxSpecialUse: /* @__PURE__ */ __name((mailboxID, specialUse) => {
				const mbv = mailboxViews.find((mbv2) => mbv2.mailbox.ID === mailboxID);
				if (!mbv) {
					throw new Error("special-use flags changed: unknown mailbox");
				}
				mbv.setSpecialUse(specialUse);
				updateMailboxNames();
			}, "setMailboxSpecialUse"),
			setMailboxKeywords: /* @__PURE__ */ __name((mailboxID, keywords) => {
				const mbv = mailboxViews.find((mbv2) => mbv2.mailbox.ID === mailboxID);
				if (!mbv) {
					throw new Error("keywords changed: unknown mailbox");
				}
				mbv.setKeywords(keywords);
			}, "setMailboxKeywords")
		};
		return mblv;
	}, "newMailboxlistView");
	var newSearchView = /* @__PURE__ */ __name((searchbarElem, mailboxlistView, startSearch, searchViewClose) => {
		let form;
		let words, mailbox, mailboxkids, from, to, oldestDate, oldestTime, newestDate, newestTime, subject, flagViews, labels, minsize, maxsize;
		let attachmentNone, attachmentAny, attachmentImage, attachmentPDF, attachmentArchive, attachmentSpreadsheet, attachmentDocument, attachmentPresentation;
		const makeDateTime = /* @__PURE__ */ __name((dt, tm) => {
			if (!dt && !tm) {
				return "";
			}
			if (!dt) {
				const now = /* @__PURE__ */ new Date();
				const pad0 = /* @__PURE__ */ __name((v) => v <= 9 ? "0" + v : "" + v, "pad0");
				dt = [now.getFullYear(), pad0(now.getMonth() + 1), pad0(now.getDate())].join("-");
			}
			if (dt && tm) {
				return dt + "T" + tm;
			}
			return dt;
		}, "makeDateTime");
		const packString = /* @__PURE__ */ __name((s) => needsDquote(s) ? dquote(s) : s, "packString");
		const packNotString = /* @__PURE__ */ __name((s) => "-" + (needsDquote(s) || s.startsWith("-") ? dquote(s) : s), "packNotString");
		const updateSearchbar = /* @__PURE__ */ __name(() => {
			let tokens = [];
			if (mailbox.value && mailbox.value !== "-1") {
				const v = mailbox.value === "0" ? "" : mailbox.selectedOptions[0].text;
				tokens.push([false, "mb", false, v]);
			}
			if (mailboxkids.checked) {
				tokens.push([false, "submb", false, ""]);
			}
			tokens.push(...parseSearchTokens(words.value));
			tokens.push(...parseSearchTokens(from.value).map((t) => [t[0], "f", false, t[3]]));
			tokens.push(...parseSearchTokens(to.value).map((t) => [t[0], "t", false, t[3]]));
			const start = makeDateTime(oldestDate.value, oldestTime.value);
			if (start) {
				tokens.push([false, "start", false, start]);
			}
			const end = makeDateTime(newestDate.value, newestTime.value);
			if (end) {
				tokens.push([false, "end", false, end]);
			}
			tokens.push(...parseSearchTokens(subject.value).map((t) => [t[0], "s", false, t[3]]));
			const check = /* @__PURE__ */ __name((elem, tag, value) => {
				if (elem.checked) {
					tokens.push([false, tag, false, value]);
				}
			}, "check");
			check(attachmentNone, "a", "none");
			check(attachmentAny, "a", "any");
			check(attachmentImage, "a", "image");
			check(attachmentPDF, "a", "pdf");
			check(attachmentArchive, "a", "archive");
			check(attachmentSpreadsheet, "a", "spreadsheet");
			check(attachmentDocument, "a", "document");
			check(attachmentPresentation, "a", "presentation");
			tokens.push(...flagViews.filter((fv) => fv.active !== null).map((fv) => {
				return [!fv.active, "l", false, fv.flag];
			}));
			tokens.push(...parseSearchTokens(labels.value).map((t) => [t[0], "l", t[2], t[3]]));
			tokens.push(...headerViews.filter((hv) => hv.key.value).map((hv) => [false, "h", false, hv.key.value + ":" + hv.value.value]));
			const minstr = parseSearchSize(minsize.value)[0];
			if (minstr) {
				tokens.push([false, "minsize", false, minstr]);
			}
			const maxstr = parseSearchSize(maxsize.value)[0];
			if (maxstr) {
				tokens.push([false, "maxsize", false, maxstr]);
			}
			searchbarElem.value = tokens.map(packToken).join(" ");
		}, "updateSearchbar");
		const setDateTime = /* @__PURE__ */ __name((s, dateElem, timeElem) => {
			if (!s) {
				return;
			}
			const t = s.split("T", 2);
			const dt = t.length === 2 || t[0].includes("-") ? t[0] : "";
			const tm = t.length === 2 ? t[1] : t[0].includes(":") ? t[0] : "";
			if (dt) {
				dateElem.value = dt;
			}
			if (tm) {
				timeElem.value = tm;
			}
		}, "setDateTime");
		const updateForm = /* @__PURE__ */ __name(() => {
			const [f, notf, strs] = parseSearch(searchbarElem.value, mailboxlistView);
			form.reset();
			const packTwo = /* @__PURE__ */ __name((l, lnot) => (l || []).map(packString).concat((lnot || []).map(packNotString)).join(" "), "packTwo");
			if (f.MailboxName) {
				const o = [...mailbox.options].find((o2) => o2.text === f.MailboxName) || mailbox.options[0];
				if (o) {
					o.selected = true;
				}
			} else if (f.MailboxID === -1) {
				mailbox.options[0].selected = true;
			} else {
				const id = "" + f.MailboxID;
				const o = [...mailbox.options].find((o2) => o2.value === id) || mailbox.options[0];
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
				presentation: attachmentPresentation
			}[f.Attachments];
			if (elem) {
				attachmentChecks(elem, true);
			}
			const otherlabels = [];
			const othernotlabels = [];
			flagViews.forEach((fv) => fv.active = null);
			const setLabels = /* @__PURE__ */ __name((flabels, other, not) => {
				(flabels || []).forEach((l) => {
					l = l.toLowerCase();
					const fv = flagViews.find((fv2) => fv2.flag.toLowerCase() === l);
					if (fv) {
						fv.active = !not;
						fv.update();
					} else {
						other.push(l);
					}
				});
			}, "setLabels");
			setLabels(f.Labels, otherlabels, false);
			setLabels(notf.Labels, othernotlabels, true);
			labels.value = packTwo(otherlabels, othernotlabels);
			headerViews.slice(1).forEach((hv) => hv.root.remove());
			headerViews = [headerViews[0]];
			if (f.Headers && f.Headers.length > 0) {
				(f.Headers || []).forEach((kv, index) => {
					const [k, v] = kv || ["", ""];
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
		}, "updateForm");
		const attachmentChecks = /* @__PURE__ */ __name((elem, set) => {
			if (elem.checked || set) {
				for (const e of [attachmentNone, attachmentAny, attachmentImage, attachmentPDF, attachmentArchive, attachmentSpreadsheet, attachmentDocument, attachmentPresentation]) {
					if (e !== elem) {
						e.checked = false;
					} else if (set) {
						e.checked = true;
					}
				}
			}
		}, "attachmentChecks");
		const changeHandlers = [
			/* @__PURE__ */ __name(function change() {
				updateSearchbar();
			}, "change"),
			/* @__PURE__ */ __name(function keyup() {
				updateSearchbar();
			}, "keyup")
		];
		const attachmentHandlers = [
			/* @__PURE__ */ __name(function change(e) {
				attachmentChecks(e.target);
			}, "change"),
			/* @__PURE__ */ __name(function mousedown(e) {
				const target = e.target;
				if (e.buttons === 1 && target.checked) {
					target.checked = false;
					e.preventDefault();
				}
			}, "mousedown"),
			...changeHandlers
		];
		let headersCell;
		let headerViews;
		const newHeaderView = /* @__PURE__ */ __name((first) => {
			let key, value;
			const root2 = dom.div(style({ display: "flex" }), key = dom.input(focusPlaceholder("Header name"), style({ width: "40%" }), changeHandlers), dom.div(style({ width: ".5em" })), value = dom.input(focusPlaceholder("Header value"), style({ flexGrow: 1 }), changeHandlers), dom.div(style({ width: "2.5em", paddingLeft: ".25em" }), dom.clickbutton("+", style({ padding: "0 .25em" }), attr.arialabel("Add row for another header filter."), attr.title("Add row for another header filter."), /* @__PURE__ */ __name(function click() {
				addHeaderView();
			}, "click")), " ", first ? [] : dom.clickbutton("-", style({ padding: "0 .25em" }), attr.arialabel("Remove row."), attr.title("Remove row."), /* @__PURE__ */ __name(function click() {
				root2.remove();
				const index = headerViews.findIndex((v) => v === hv);
				headerViews.splice(index, 1);
				updateSearchbar();
			}, "click"))));
			const hv = { root: root2, key, value };
			return hv;
		}, "newHeaderView");
		const addHeaderView = /* @__PURE__ */ __name(() => {
			const hv = newHeaderView(false);
			headersCell.appendChild(hv.root);
			headerViews.push(hv);
		}, "addHeaderView");
		const setPeriod = /* @__PURE__ */ __name((d) => {
			newestDate.value = "";
			newestTime.value = "";
			const pad0 = /* @__PURE__ */ __name((v) => v <= 9 ? "0" + v : "" + v, "pad0");
			const dt = [d.getFullYear(), pad0(d.getMonth() + 1), pad0(d.getDate())].join("-");
			const tm = "" + pad0(d.getHours()) + ":" + pad0(d.getMinutes());
			oldestDate.value = dt;
			oldestTime.value = tm;
			updateSearchbar();
		}, "setPeriod");
		const searchTableStyle = css("searchTable", { width: "100%" });
		ensureCSS(".searchTable td", { padding: ".25em" });
		const root = dom.div(css("searchOverlay", { position: "absolute", left: 0, right: 0, top: 0, bottom: 0, backgroundColor: styles.overlayBackgroundColor, zIndex: zindexes.compose }), /* @__PURE__ */ __name(function click(e) {
			e.stopPropagation();
			searchViewClose();
		}, "click"), /* @__PURE__ */ __name(function keyup(e) {
			if (e.key === "Escape") {
				e.stopPropagation();
				searchViewClose();
			}
		}, "keyup"), dom.search(
			css("searchContent", { position: "absolute", width: "50em", padding: ".5ex", backgroundColor: styles.popupBackgroundColor, boxShadow: styles.boxShadow, border: "1px solid", borderColor: styles.popupBorderColor, color: styles.popupColor, borderRadius: ".15em" }),
			/* @__PURE__ */ __name(function click(e) {
				e.stopPropagation();
			}, "click"),
			// This is a separate form, inside the form with the overall search field because
			// when updating the form based on the parsed searchbar, we first need to reset it.
			form = dom.form(dom.table(searchTableStyle, dom.tr(dom.td(dom.label("Mailbox", attr.for("searchMailbox")), attr.title("Filter by mailbox, including children of the mailbox.")), dom.td(mailbox = dom.select(attr.id("searchMailbox"), style({ width: "100%" }), dom.option("All mailboxes except Trash/Junk/Rejects", attr.value("-1")), dom.option("All mailboxes", attr.value("0")), changeHandlers), dom.div(style({ paddingTop: ".5ex" }), dom.label(mailboxkids = dom.input(attr.type("checkbox"), changeHandlers), " Also search in mailboxes below the selected mailbox.")))), dom.tr(dom.td(dom.label("Text", attr.for("searchWords"))), dom.td(words = dom.input(attr.id("searchWords"), attr.title("Filter by text, case-insensitive, substring match, not necessarily whole words."), focusPlaceholder('word "exact match" -notword'), style({ width: "100%" }), changeHandlers))), dom.tr(dom.td(dom.label("From", attr.for("searchFrom"))), dom.td(from = dom.input(attr.id("searchFrom"), style({ width: "100%" }), focusPlaceholder("Address or name"), newAddressComplete(), changeHandlers))), dom.tr(dom.td(dom.label("To", attr.for("searchTo")), attr.title("Search on addressee, including Cc and Bcc headers.")), dom.td(to = dom.input(attr.id("searchTo"), focusPlaceholder("Address or name, also matches Cc and Bcc addresses"), style({ width: "100%" }), newAddressComplete(), changeHandlers))), dom.tr(dom.td(dom.label("Subject", attr.for("searchSubject"))), dom.td(subject = dom.input(attr.id("searchSubject"), style({ width: "100%" }), focusPlaceholder('"exact match"'), changeHandlers))), dom.tr(dom.td("Received between", style({ whiteSpace: "nowrap" })), dom.td(style({ lineHeight: 2 }), dom.div(oldestDate = dom.input(attr.type("date"), focusPlaceholder("2023-07-20"), changeHandlers), oldestTime = dom.input(attr.type("time"), focusPlaceholder("23:10"), changeHandlers), " ", dom.clickbutton("x", style({ padding: "0 .3em" }), attr.arialabel("Clear start date."), attr.title("Clear start date."), /* @__PURE__ */ __name(function click() {
				oldestDate.value = "";
				oldestTime.value = "";
				updateSearchbar();
			}, "click")), " and ", newestDate = dom.input(attr.type("date"), focusPlaceholder("2023-07-20"), changeHandlers), newestTime = dom.input(attr.type("time"), focusPlaceholder("23:10"), changeHandlers), " ", dom.clickbutton("x", style({ padding: "0 .3em" }), attr.arialabel("Clear end date."), attr.title("Clear end date."), /* @__PURE__ */ __name(function click() {
				newestDate.value = "";
				newestTime.value = "";
				updateSearchbar();
			}, "click"))), dom.div(dom.clickbutton("1 day", /* @__PURE__ */ __name(function click() {
				setPeriod(new Date((/* @__PURE__ */ new Date()).getTime() - 24 * 3600 * 1e3));
			}, "click")), " ", dom.clickbutton("1 week", /* @__PURE__ */ __name(function click() {
				setPeriod(new Date((/* @__PURE__ */ new Date()).getTime() - 7 * 24 * 3600 * 1e3));
			}, "click")), " ", dom.clickbutton("1 month", /* @__PURE__ */ __name(function click() {
				setPeriod(new Date((/* @__PURE__ */ new Date()).getTime() - 31 * 24 * 3600 * 1e3));
			}, "click")), " ", dom.clickbutton("1 year", /* @__PURE__ */ __name(function click() {
				setPeriod(new Date((/* @__PURE__ */ new Date()).getTime() - 365 * 24 * 3600 * 1e3));
			}, "click"))))), dom.tr(dom.td("Attachments"), dom.td(dom.label(style({ whiteSpace: "nowrap" }), attachmentNone = dom.input(attr.type("radio"), attr.name("attachments"), attr.value("none"), attachmentHandlers), " None"), " ", dom.label(style({ whiteSpace: "nowrap" }), attachmentAny = dom.input(attr.type("radio"), attr.name("attachments"), attr.value("any"), attachmentHandlers), " Any"), " ", dom.label(style({ whiteSpace: "nowrap" }), attachmentImage = dom.input(attr.type("radio"), attr.name("attachments"), attr.value("image"), attachmentHandlers), " Images"), " ", dom.label(style({ whiteSpace: "nowrap" }), attachmentPDF = dom.input(attr.type("radio"), attr.name("attachments"), attr.value("pdf"), attachmentHandlers), " PDFs"), " ", dom.label(style({ whiteSpace: "nowrap" }), attachmentArchive = dom.input(attr.type("radio"), attr.name("attachments"), attr.value("archive"), attachmentHandlers), " Archives"), " ", dom.label(style({ whiteSpace: "nowrap" }), attachmentSpreadsheet = dom.input(attr.type("radio"), attr.name("attachments"), attr.value("spreadsheet"), attachmentHandlers), " Spreadsheets"), " ", dom.label(style({ whiteSpace: "nowrap" }), attachmentDocument = dom.input(attr.type("radio"), attr.name("attachments"), attr.value("document"), attachmentHandlers), " Documents"), " ", dom.label(style({ whiteSpace: "nowrap" }), attachmentPresentation = dom.input(attr.type("radio"), attr.name("attachments"), attr.value("presentation"), attachmentHandlers), " Presentations"), " ")), dom.tr(dom.td("Labels"), dom.td(style({ lineHeight: 2 }), join(flagViews = Object.entries({ Read: "\\Seen", Replied: "\\Answered", Flagged: "\\Flagged", Deleted: "\\Deleted", Draft: "\\Draft", Forwarded: "$Forwarded", Junk: "$Junk", NotJunk: "$NotJunk", Phishing: "$Phishing", MDNSent: "$MDNSent" }).map((t) => {
				const [name, flag] = t;
				const v = {
					active: null,
					flag,
					root: dom.clickbutton(name, /* @__PURE__ */ __name(function click() {
						if (v.active === null) {
							v.active = true;
						} else if (v.active === true) {
							v.active = false;
						} else {
							v.active = null;
						}
						v.update();
						updateSearchbar();
					}, "click")),
					update: /* @__PURE__ */ __name(() => {
						css("searchFlagTrue", { backgroundColor: styles.buttonTristateOnBackground }, true);
						css("searchFlagFalse", { backgroundColor: styles.buttonTristateOffBackground }, true);
						v.root.classList.toggle("searchFlagTrue", v.active === true);
						v.root.classList.toggle("searchFlagFalse", v.active === false);
					}, "update")
				};
				return v;
			}), () => " "), " ", labels = dom.input(focusPlaceholder('todo -done "-dashingname"'), attr.title("User-defined labels."), changeHandlers))), dom.tr(dom.td("Headers"), headersCell = dom.td(headerViews = [newHeaderView(true)])), dom.tr(dom.td("Size between"), dom.td(minsize = dom.input(style({ width: "6em" }), focusPlaceholder("10kb"), changeHandlers), " and ", maxsize = dom.input(style({ width: "6em" }), focusPlaceholder("1mb"), changeHandlers)))), dom.div(style({ padding: "1ex", textAlign: "right" }), dom.submitbutton("Search")), /* @__PURE__ */ __name(async function submit2(e) {
				e.preventDefault();
				await searchView.submit();
			}, "submit"))
		));
		const submit = /* @__PURE__ */ __name(async () => {
			const [f, notf, _] = parseSearch(searchbarElem.value, mailboxlistView);
			await startSearch(f, notf);
		}, "submit");
		let loaded = false;
		const searchView = {
			root,
			submit,
			ensureLoaded: /* @__PURE__ */ __name(() => {
				if (loaded || mailboxlistView.mailboxes().length === 0) {
					return;
				}
				loaded = true;
				dom._kids(mailbox, dom.option("All mailboxes except Trash/Junk/Rejects", attr.value("-1")), dom.option("All mailboxes", attr.value("0")), mailboxlistView.mailboxes().map((mb) => dom.option(mb.Name, attr.value("" + mb.ID))));
				searchView.updateForm();
			}, "ensureLoaded"),
			updateForm
		};
		return searchView;
	}, "newSearchView");
	var parseComposeMailto = /* @__PURE__ */ __name((mailto) => {
		const u = new URL(mailto);
		const addresses = /* @__PURE__ */ __name((s) => s.split(",").filter((s2) => !!s2), "addresses");
		const opts = {};
		opts.to = addresses(u.pathname).map((s) => decodeURIComponent(s));
		for (const [xk, v] of new URLSearchParams(u.search)) {
			const k = xk.toLowerCase();
			if (k === "to") {
				opts.to = [...opts.to, ...addresses(v)];
			} else if (k === "cc") {
				opts.cc = [...opts.cc || [], ...addresses(v)];
			} else if (k === "bcc") {
				opts.bcc = [...opts.bcc || [], ...addresses(v)];
			} else if (k === "subject") {
				opts.subject = v;
			} else if (k === "body") {
				opts.body = v;
			}
		}
		return opts;
	}, "parseComposeMailto");
	var init = /* @__PURE__ */ __name(async () => {
		let connectionElem;
		let layoutElem;
		let accountElem;
		let loginAddressElem;
		let msglistscrollElem;
		let queryactivityElem;
		const listendElem = dom.div(css("msgListEnd", { borderTop: "1px solid", borderColor: styles.borderColor, color: styles.colorMilder, margin: "1ex" }));
		const listloadingElem = dom.div(css("msgListLoading", { textAlign: "center", padding: ".15em 0", color: styles.colorMild, border: "1px solid", borderColor: styles.borderColor, margin: "1ex", backgroundColor: styles.backgroundColorMild }), "loading...");
		const listerrElem = dom.div(css("msgListErr", { textAlign: "center", padding: ".15em 0", color: styles.colorMild, border: "1px solid", borderColor: styles.borderColor, margin: "1ex", backgroundColor: styles.backgroundColorMild }));
		let sseID = 0;
		let viewSequence = 0;
		let viewID = 0;
		let search = {
			active: false,
			// Whether a search is active.
			query: ""
			// The query, as shown in the searchbar. Used in location hash.
		};
		let requestSequence = 0;
		let requestID = 0;
		let requestAnchorMessageID = 0;
		let requestViewEnd = false;
		let requestFilter = newFilter();
		let requestNotFilter = newNotFilter();
		let requestMsgID = 0;
		[moxversion, moxgoos, moxgoarch] = await client.Version();
		const updatePageTitle = /* @__PURE__ */ __name(() => {
			const mb = mailboxlistView && mailboxlistView.activeMailbox();
			const addr = loginAddress ? loginAddress.User + "@" + formatDomain(loginAddress.Domain) : "";
			if (!mb) {
				document.title = [addr, "Mox Webmail"].join(" - ");
			} else {
				document.title = ["(" + mb.Unread + ") " + mb.Name, addr, "Mox Webmail"].join(" - ");
			}
		}, "updatePageTitle");
		const setLocationHash = /* @__PURE__ */ __name(() => {
			const msgid = requestMsgID || msglistView.activeMessageID();
			let trail = msgid ? "," + msgid : "";
			if (composeView && composeView.MsgID) {
				trail += ",compose:" + composeView.MsgID;
			}
			let hash;
			const mb = mailboxlistView && mailboxlistView.activeMailbox();
			if (mb) {
				hash = "#" + mb.Name + trail;
			} else if (search.active) {
				hash = "#search " + search.query + trail;
			} else {
				hash = "#";
			}
			const l = window.location;
			const url = l.protocol + "//" + l.host + l.pathname + l.search + hash;
			window.history.replaceState(void 0, "", url);
		}, "setLocationHash");
		const loadSearch = /* @__PURE__ */ __name((q) => {
			search = { active: true, query: q };
			searchbarElem.value = q;
			searchbarElem.classList.toggle("searchbarActive", true);
			searchbarElemBox.style.flexGrow = "4";
		}, "loadSearch");
		const unloadSearch = /* @__PURE__ */ __name(() => {
			searchbarElem.value = "";
			searchbarElem.classList.toggle("searchbarActive", false);
			searchbarElem.style.zIndex = "";
			searchbarElemBox.style.flexGrow = "";
			search = { active: false, query: "" };
			searchView.root.remove();
		}, "unloadSearch");
		const clearList = /* @__PURE__ */ __name(() => {
			msglistView.clear();
			listendElem.remove();
			listloadingElem.remove();
			listerrElem.remove();
		}, "clearList");
		const requestNewView = /* @__PURE__ */ __name(async (clearMsgID, filterOpt, notFilterOpt) => {
			if (!sseID) {
				throw new Error("not connected");
			}
			if (clearMsgID) {
				requestMsgID = 0;
			}
			msglistView.root.classList.toggle("loading", true);
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
		}, "requestNewView");
		const requestMessages = /* @__PURE__ */ __name(async (scrollBounds, destMessageID) => {
			const fetchCount = Math.max(50, 3 * Math.ceil(scrollBounds.height / msglistView.itemHeight()));
			const page2 = {
				AnchorMessageID: requestAnchorMessageID,
				Count: fetchCount,
				DestMessageID: destMessageID
			};
			requestSequence++;
			requestID = requestSequence;
			const [f, notf] = refineFilters(requestFilter, requestNotFilter);
			const query = {
				OrderAsc: settings.orderAsc,
				Threading: settings.threading,
				Filter: f,
				NotFilter: notf
			};
			const request = {
				ID: requestID,
				SSEID: sseID,
				ViewID: viewID,
				Cancel: false,
				Query: query,
				Page: page2
			};
			dom._kids(queryactivityElem, "loading...");
			msglistscrollElem.appendChild(listloadingElem);
			await client.Request(request);
		}, "requestMessages");
		let msgElem = dom.div(css("msgElem", { position: "absolute", right: 0, left: 0, top: 0, bottom: 0, backgroundColor: styles.backgroundColorMild }));
		const possibleLabels = /* @__PURE__ */ __name(() => {
			if (requestFilter.MailboxID > 0) {
				const mb = mailboxlistView.findMailboxByID(requestFilter.MailboxID);
				if (mb) {
					return mb.Keywords || [];
				}
			}
			const all = {};
			mailboxlistView.mailboxes().forEach((mb) => {
				for (const k of mb.Keywords || []) {
					all[k] = void 0;
				}
			});
			const l = Object.keys(all);
			l.sort();
			return l;
		}, "possibleLabels");
		const refineKeyword = /* @__PURE__ */ __name(async (kw) => {
			settingsPut({ ...settings, refine: "label:" + kw });
			refineToggleActive(refineLabelBtn);
			dom._kids(refineLabelBtn, "Label: " + kw);
			await withStatus("Requesting messages", requestNewView(false));
		}, "refineKeyword");
		const viewportEnsureMessages = /* @__PURE__ */ __name(async () => {
			const bounds = msglistscrollElem.getBoundingClientRect();
			if (msglistscrollElem.scrollTop < msglistscrollElem.scrollHeight - 3 * bounds.height) {
				return;
			}
			await withStatus("Requesting more messages", requestMessages(bounds, 0));
		}, "viewportEnsureMessages");
		const otherMailbox = /* @__PURE__ */ __name((mailboxID) => requestFilter.MailboxID !== mailboxID ? mailboxlistView.findMailboxByID(mailboxID) || null : null, "otherMailbox");
		const listMailboxes = /* @__PURE__ */ __name(() => mailboxlistView.mailboxes(), "listMailboxes");
		const activeMailbox = /* @__PURE__ */ __name(() => mailboxlistView.activeMailbox(), "activeMailbox");
		const msglistView = newMsglistView(msgElem, activeMailbox, listMailboxes, setLocationHash, otherMailbox, possibleLabels, () => msglistscrollElem ? msglistscrollElem.getBoundingClientRect().height : 0, refineKeyword, viewportEnsureMessages);
		const mailboxlistView = newMailboxlistView(msglistView, requestNewView, updatePageTitle, setLocationHash, unloadSearch, otherMailbox);
		let refineUnreadBtn, refineReadBtn, refineAttachmentsBtn, refineFlaggedBtn, refineLabelBtn;
		const refineToggleActive = /* @__PURE__ */ __name((btn) => {
			for (const e of [refineUnreadBtn, refineReadBtn, refineAttachmentsBtn, refineFlaggedBtn, refineLabelBtn]) {
				e.classList.toggle("active", e === btn);
			}
			if (btn !== null && btn !== refineLabelBtn) {
				dom._kids(refineLabelBtn, "Label");
			}
		}, "refineToggleActive");
		const refineToggle = /* @__PURE__ */ __name(async (refine, btn) => {
			if (settings.refine === refine) {
				settingsPut({ ...settings, refine: "" });
				refineToggleActive(null);
			} else {
				settingsPut({ ...settings, refine });
				refineToggleActive(btn);
			}
			dom._kids(refineLabelBtn, settings.refine.startsWith("label:") ? "Label: " + settings.refine.substring("label:".length) : "Label");
			await withStatus("Requesting messages", requestNewView(false));
		}, "refineToggle");
		let threadMode;
		const msgColumnDraggerStyle = css("msgColumnDragger", { position: "absolute", top: 0, bottom: 0, width: "1px", backgroundColor: styles.popupBorderColor, left: "2.5px" });
		let msglistElem = dom.div(css("msgList", { backgroundColor: styles.msglistBackgroundColor, position: "absolute", left: "0", right: 0, top: 0, bottom: 0, display: "flex", flexDirection: "column" }), dom.div(attr.role("region"), attr.arialabel("Filter and sorting buttons for message list"), css("msgListFilterSorting", { display: "flex", justifyContent: "space-between", backgroundColor: styles.backgroundColorMild, borderBottom: "1px solid", borderBottomColor: styles.borderColor, padding: ".25em .5em" }), dom.div(dom.h1("Refine:", css("refineTitle", { fontWeight: "normal", fontSize: "inherit", display: "inline", margin: 0 }), attr.title("Refine message listing with quick filters. These refinement filters are in addition to any search criteria, but the refine attachment filter overrides a search attachment criteria.")), " ", dom.span(dom._class("btngroup"), refineUnreadBtn = dom.clickbutton(settings.refine === "unread" ? dom._class("active") : [], "Unread", attr.title("Only show messages marked as unread."), /* @__PURE__ */ __name(async function click(e) {
			await refineToggle("unread", e.target);
		}, "click")), refineReadBtn = dom.clickbutton(settings.refine === "read" ? dom._class("active") : [], "Read", attr.title("Only show messages marked as read."), /* @__PURE__ */ __name(async function click(e) {
			await refineToggle("read", e.target);
		}, "click")), refineAttachmentsBtn = dom.clickbutton(settings.refine === "attachments" ? dom._class("active") : [], "Attachments", attr.title("Only show messages with attachments."), /* @__PURE__ */ __name(async function click(e) {
			await refineToggle("attachments", e.target);
		}, "click")), refineFlaggedBtn = dom.clickbutton(settings.refine === "flagged" ? dom._class("active") : [], "Flagged", attr.title("Only show flagged/starred messages."), /* @__PURE__ */ __name(async function click(e) {
			await refineToggle("flagged", e.target);
		}, "click")), refineLabelBtn = dom.clickbutton(settings.refine.startsWith("label:") ? [dom._class("active"), "Label: " + settings.refine.substring("label:".length)] : "Label", attr.title("Only show messages with the selected label."), /* @__PURE__ */ __name(async function click(e) {
			const labels = possibleLabels();
			const remove = popover(e.target, {}, dom.div(style({ display: "flex", flexDirection: "column", gap: "1ex" }), labels.map((l) => {
				const selectLabel = /* @__PURE__ */ __name(async () => {
					await refineToggle("label:" + l, e.target);
					remove();
				}, "selectLabel");
				return dom.div(dom.clickbutton(styleClasses.keyword, keywordButtonStyle, l, /* @__PURE__ */ __name(async function click2() {
					await selectLabel();
				}, "click")));
			}), labels.length === 0 ? dom.div("No labels yet, set one on a message first.") : []));
		}, "click"))), " ", dom.clickbutton("x", style({ padding: "0 .25em" }), attr.arialabel("Clear refinement filters."), attr.title("Clear refinement filters."), /* @__PURE__ */ __name(async function click(e) {
			settingsPut({ ...settings, refine: "" });
			refineToggleActive(e.target);
			await withStatus("Requesting messages", requestNewView(false));
		}, "click"))), dom.div(queryactivityElem = dom.span(), " ", threadMode = dom.select(attr.arialabel("Thread modes."), attr.title("Off: Threading disabled, messages are shown individually.\nOn: Group messages in threads, expanded by default except when (previously) manually collapsed.\nUnread: Only expand thread with unread messages, ignoring and not saving whether they were manually collapsed."), dom.option("Threads: Off", attr.value(ThreadMode.ThreadOff), settings.threading === ThreadMode.ThreadOff ? attr.selected("") : []), dom.option("Threads: On", attr.value(ThreadMode.ThreadOn), settings.threading === ThreadMode.ThreadOn ? attr.selected("") : []), dom.option("Threads: Unread", attr.value(ThreadMode.ThreadUnread), settings.threading === ThreadMode.ThreadUnread ? attr.selected("") : []), /* @__PURE__ */ __name(async function change() {
			let reset = settings.threading === ThreadMode.ThreadOff;
			settingsPut({ ...settings, threading: threadMode.value });
			reset = reset || settings.threading === ThreadMode.ThreadOff;
			if (reset) {
				await withStatus("Requesting messages", requestNewView(false));
			} else {
				msglistView.threadToggle();
			}
		}, "change")), " ", dom.clickbutton("\u2191\u2193", attr.title("Toggle sorting by date received."), settings.orderAsc ? dom._class("invert") : [], /* @__PURE__ */ __name(async function click(e) {
			settingsPut({ ...settings, orderAsc: !settings.orderAsc });
			e.target.classList.toggle("invert", settings.orderAsc);
			await withStatus("Requesting messages", requestNewView(true));
		}, "click")))), dom.div(style({ height: "1ex", position: "relative" }), dom.div(dom._class("msgItemFlags")), dom.div(dom._class("msgItemFlagsOffset"), css("msgItemFlagsGrab", { position: "absolute", width: "6px", top: 0, bottom: 0, marginLeft: "-3px", cursor: "ew-resize" }), dom.div(msgColumnDraggerStyle), /* @__PURE__ */ __name(function mousedown(e) {
			startDrag(e, (e2) => {
				const bounds = msglistscrollElem.getBoundingClientRect();
				const width = Math.round(e2.clientX - bounds.x);
				settingsPut({ ...settings, msglistflagsWidth: width });
				updateMsglistWidths();
			});
		}, "mousedown")), dom.div(dom._class("msgItemFrom")), dom.div(dom._class("msgItemFromOffset"), css("msgItemFlagsGrab", { position: "absolute", width: "6px", top: 0, bottom: 0, marginLeft: "-3px", cursor: "ew-resize" }), dom.div(msgColumnDraggerStyle), /* @__PURE__ */ __name(function mousedown(e) {
			startDrag(e, (e2) => {
				const bounds = msglistscrollElem.getBoundingClientRect();
				const x = Math.round(e2.clientX - bounds.x - lastflagswidth);
				const width = bounds.width - lastflagswidth - lastagewidth;
				const pct = 100 * x / width;
				settingsPut({ ...settings, msglistfromPct: pct });
				updateMsglistWidths();
			});
		}, "mousedown")), dom.div(dom._class("msgItemSubject")), dom.div(dom._class("msgItemSubjectOffset"), css("msgItemFlagsGrab", { position: "absolute", width: "6px", top: 0, bottom: 0, marginLeft: "-3px", cursor: "ew-resize" }), dom.div(msgColumnDraggerStyle), /* @__PURE__ */ __name(function mousedown(e) {
			startDrag(e, (e2) => {
				const bounds = msglistscrollElem.getBoundingClientRect();
				const width = Math.round(bounds.x + bounds.width - e2.clientX);
				settingsPut({ ...settings, msglistageWidth: width });
				updateMsglistWidths();
			});
		}, "mousedown")), dom.div(dom._class("msgItemAge"))), dom.div(style({ flexGrow: "1", position: "relative" }), msglistscrollElem = dom.div(yscrollStyle, attr.role("region"), attr.arialabel("Message list"), /* @__PURE__ */ __name(async function scroll() {
			if (!sseID || requestViewEnd || requestID) {
				return;
			}
			await viewportEnsureMessages();
		}, "scroll"), dom.div(style({ width: "100%", borderSpacing: "0" }), msglistView))));
		let searchbarElem;
		const startSearch = /* @__PURE__ */ __name(async (f, notf) => {
			if (!sseID) {
				window.alert("Error: not connect");
				return;
			}
			if (f.Attachments !== "" && settings.refine === "attachments") {
				settingsPut({ ...settings, refine: "" });
				refineToggleActive(null);
			}
			search = { active: true, query: searchbarElem.value };
			mailboxlistView.closeMailbox();
			setLocationHash();
			searchbarElem.classList.toggle("searchbarActive", true);
			searchView.root.remove();
			searchbarElem.blur();
			document.body.focus();
			await withStatus("Requesting messages", requestNewView(true, f, notf));
		}, "startSearch");
		const searchViewClose = /* @__PURE__ */ __name(() => {
			if (!search.active) {
				unloadSearch();
			} else {
				searchbarElem.value = search.query;
				searchView.root.remove();
			}
		}, "searchViewClose");
		let mailboxesElem, topcomposeboxElem, mailboxessplitElem;
		let splitElem;
		let searchbarElemBox;
		const searchbarInitial = /* @__PURE__ */ __name(() => {
			const mailboxActive = mailboxlistView.activeMailbox();
			if (mailboxActive && mailboxActive.Name !== "Inbox") {
				return packToken([false, "mb", false, mailboxActive.Name]) + " ";
			}
			return "";
		}, "searchbarInitial");
		const ensureSearchView = /* @__PURE__ */ __name(() => {
			if (searchView.root.parentElement) {
				return;
			}
			searchView.ensureLoaded();
			const pos = searchbarElem.getBoundingClientRect();
			const child = searchView.root.firstChild;
			child.style.left = "" + pos.x + "px";
			child.style.top = "" + (pos.y + pos.height + 2) + "px";
			searchbarElem.parentElement.appendChild(searchView.root);
			searchbarElemBox.style.flexGrow = "4";
			searchbarElem.style.zIndex = zindexes.searchbar;
		}, "ensureSearchView");
		const cmdSearch = /* @__PURE__ */ __name(async () => {
			searchbarElem.focus();
			if (!searchbarElem.value) {
				searchbarElem.value = searchbarInitial();
			}
			ensureSearchView();
			searchView.updateForm();
		}, "cmdSearch");
		const cmdCompose = /* @__PURE__ */ __name(async () => {
			let body = "";
			let sig = accountSettings?.Signature || "";
			if (sig) {
				body += "\n\n" + sig;
			}
			compose({ body, editOffset: 0 }, listMailboxes, setLocationHash);
		}, "cmdCompose");
		const cmdOpenInbox = /* @__PURE__ */ __name(async () => {
			const mb = mailboxlistView.findMailboxByName("Inbox");
			if (mb) {
				await mailboxlistView.openMailboxID(mb.ID, true);
				const f = newFilter();
				f.MailboxID = mb.ID;
				await withStatus("Requesting messages", requestNewView(true, f, newNotFilter()));
			}
		}, "cmdOpenInbox");
		const cmdFocusMsg = /* @__PURE__ */ __name(async () => {
			const btn = msgElem.querySelector("button");
			if (btn && btn instanceof HTMLElement) {
				btn.focus();
			}
		}, "cmdFocusMsg");
		const shortcuts = {
			i: cmdOpenInbox,
			"/": cmdSearch,
			"?": cmdHelp,
			"ctrl ?": cmdTooltip,
			c: cmdCompose,
			"ctrl m": cmdFocusMsg,
			"ctrl !": cmdSettings
		};
		const topMailboxesStyle = css("topMailboxes", { backgroundColor: styles.mailboxesTopBackgroundColor });
		css("searchbarActive", { background: styles.mailboxActiveBackground });
		const webmailroot = dom.div(css("webmailRoot", { display: "flex", flexDirection: "column", alignContent: "stretch", height: "100dvh" }), dom.div(topMailboxesStyle, style({ display: "flex" }), attr.role("region"), attr.arialabel("Top bar"), topcomposeboxElem = dom.div(dom._class("pad"), style({ width: settings.mailboxesWidth + "px", textAlign: "center" }), dom.clickbutton("Compose", attr.title("Compose new email message."), /* @__PURE__ */ __name(function click() {
			shortcutCmd(cmdCompose, shortcuts);
		}, "click"))), dom.div(dom._class("pad"), css("searchbarBox", { paddingLeft: 0, display: "flex", flexGrow: 1 }), searchbarElemBox = dom.search(style({ display: "flex", marginRight: ".5em" }), dom.form(style({ display: "flex", flexGrow: 1 }), searchbarElem = dom.input(attr.placeholder("Search..."), style({ position: "relative", width: "100%" }), attr.title("Search messages based on criteria like matching free-form text, in a mailbox, labels, addressees."), focusPlaceholder('word "with space" -notword mb:Inbox f:from@x.example t:rcpt@x.example start:2023-7-1 end:2023-7-8 s:"subject" a:images l:$Forwarded h:Reply-To:other@x.example minsize:500kb'), /* @__PURE__ */ __name(function click() {
			cmdSearch();
			showShortcut("/");
		}, "click"), /* @__PURE__ */ __name(function focus() {
			searchbarElemBox.style.flexGrow = "4";
			if (!searchbarElem.value) {
				searchbarElem.value = searchbarInitial();
			}
		}, "focus"), /* @__PURE__ */ __name(function blur() {
			if (searchbarElem.value === searchbarInitial()) {
				searchbarElem.value = "";
			}
			if (!search.active) {
				searchbarElemBox.style.flexGrow = "";
			}
		}, "blur"), /* @__PURE__ */ __name(function change() {
			searchView.updateForm();
		}, "change"), /* @__PURE__ */ __name(function keyup(e) {
			if (e.key === "Escape") {
				e.stopPropagation();
				searchViewClose();
				return;
			}
			if (searchbarElem.value && searchbarElem.value !== searchbarInitial()) {
				ensureSearchView();
			}
			searchView.updateForm();
		}, "keyup")), dom.clickbutton("x", attr.arialabel("Cancel and clear search and open Inbox."), attr.title("Cancel and clear search and open Inbox."), style({ marginLeft: ".25em", padding: "0 .3em" }), /* @__PURE__ */ __name(async function click() {
			searchbarElem.value = "";
			if (!search.active) {
				return;
			}
			const mb = mailboxlistView.findMailboxByName("Inbox");
			if (!mb) {
				window.alert("Cannot find inbox.");
				return;
			}
			await mailboxlistView.openMailboxID(mb.ID, true);
			const f = newFilter();
			f.MailboxID = mb.ID;
			await withStatus("Requesting messages", requestNewView(true, f, newNotFilter()));
		}, "click")), /* @__PURE__ */ __name(async function submit(e) {
			e.preventDefault();
			await searchView.submit();
		}, "submit"))), connectionElem = dom.div(), statusElem = dom.div(css("status", { marginLeft: ".5em", flexGrow: "1" }), attr.role("status")), dom.div(style({ paddingLeft: "1em" }), layoutElem = dom.select(attr.title("Layout of message list and message panes. Top/bottom has message list above message view. Left/Right has message list left, message view right. Auto selects based on window width and automatically switches on resize. Wide screens get left/right, smaller screens get top/bottom."), dom.option("Auto layout", attr.value("auto"), settings.layout === "auto" ? attr.selected("") : []), dom.option("Top/bottom", attr.value("topbottom"), settings.layout === "topbottom" ? attr.selected("") : []), dom.option("Left/right", attr.value("leftright"), settings.layout === "leftright" ? attr.selected("") : []), /* @__PURE__ */ __name(function change() {
			settingsPut({ ...settings, layout: layoutElem.value });
			if (layoutElem.value === "auto") {
				autoselectLayout();
			} else {
				selectLayout(layoutElem.value);
			}
		}, "change")), " ", dom.clickbutton("Tooltip", attr.title('Show tooltips, based on the title attributes (underdotted text) for the focused element and all user interface elements below it. Use the keyboard shortcut "ctrl ?" instead of clicking on the tooltip button, which changes focus to the tooltip button.'), clickCmd(cmdTooltip, shortcuts)), " ", dom.clickbutton("Help", attr.title("Show popup with basic usage information and a keyboard shortcuts."), clickCmd(cmdHelp, shortcuts)), " ", dom.clickbutton("Settings", attr.title("Change settings for composing messages."), clickCmd(cmdSettings, shortcuts)), " ", accountElem = dom.span(), " ", loginAddressElem = dom.span(), " ", dom.clickbutton("Logout", attr.title("Logout, invalidating this session."), /* @__PURE__ */ __name(async function click(e) {
			await withStatus("Logging out", client.Logout(), e.target);
			localStorageRemove("webmailcsrftoken");
			if (eventSource) {
				eventSource.close();
				eventSource = null;
			}
			window.location.reload();
		}, "click"))))), dom.div(css("mailboxesListMsgBox", { flexGrow: "1", position: "relative" }), mailboxesElem = dom.div(topMailboxesStyle, style({ width: settings.mailboxesWidth + "px" }), css("mailboxesBox", { display: "flex", flexDirection: "column", alignContent: "stretch", position: "absolute", left: 0, top: 0, bottom: 0 }), dom.div(dom._class("pad"), yscrollAutoStyle, style({ flexGrow: "1", position: "relative" }), mailboxlistView.root)), mailboxessplitElem = dom.div(css("mailboxesListGrab", { position: "absolute", width: "5px", top: 0, bottom: 0, cursor: "ew-resize", zIndex: zindexes.splitter }), style({ left: "calc(" + settings.mailboxesWidth + "px - 2px)" }), dom.div(css("mailboxesListLine", { position: "absolute", width: "1px", top: 0, bottom: 0, left: "2px", right: "2px", backgroundColor: styles.popupBorderColor })), /* @__PURE__ */ __name(function mousedown(e) {
			startDrag(e, (e2) => {
				mailboxesElem.style.width = Math.round(e2.clientX) + "px";
				topcomposeboxElem.style.width = Math.round(e2.clientX) + "px";
				mailboxessplitElem.style.left = "calc(" + e2.clientX + "px - 2px)";
				splitElem.style.left = "calc(" + e2.clientX + "px + 1px)";
				settingsPut({ ...settings, mailboxesWidth: Math.round(e2.clientX) });
			});
		}, "mousedown")), splitElem = dom.div(css("listMsgBox", { position: "absolute", left: "calc(" + settings.mailboxesWidth + "px + 1px)", right: 0, top: 0, bottom: 0, borderTop: "1px solid", borderTopColor: styles.borderColor }))));
		const searchView = newSearchView(searchbarElem, mailboxlistView, startSearch, searchViewClose);
		document.body.addEventListener("keydown", async (e) => {
			switch (e.key) {
				case "OS":
				case "Control":
				case "Shift":
				case "Alt":
					return;
			}
			if (popupOpen) {
				return;
			}
			if ((e.target instanceof window.HTMLInputElement || e.target instanceof window.HTMLTextAreaElement || e.target instanceof window.HTMLSelectElement) && !e.ctrlKey && !e.altKey && !e.metaKey) {
				return;
			}
			let l = [];
			if (e.ctrlKey) {
				l.push("ctrl");
			}
			if (e.altKey) {
				l.push("alt");
			}
			if (e.metaKey) {
				l.push("meta");
			}
			if (e.key.length > 1 && e.shiftKey) {
				l.push("shift");
			}
			l.push(e.key);
			const k = l.join(" ");
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
		let currentLayout = "";
		const selectLayout = /* @__PURE__ */ __name((want) => {
			if (want === currentLayout) {
				return;
			}
			if (want === "leftright") {
				let left, split, right;
				dom._kids(splitElem, left = dom.div(css("layoutLeft", { position: "absolute", left: 0, top: 0, bottom: 0 }), style({ width: "calc(" + settings.leftWidthPct + "% - 1px)" }), msglistElem), split = dom.div(css("listMsgLeftRightGrab", { position: "absolute", width: "5px", top: 0, bottom: 0, cursor: "ew-resize", zIndex: zindexes.splitter }), style({ left: "calc(" + settings.leftWidthPct + "% - 2px)" }), dom.div(css("listMsgLeftRightLine", { position: "absolute", backgroundColor: styles.popupBorderColor, top: 0, bottom: 0, width: "1px", left: "2px", right: "2px" })), /* @__PURE__ */ __name(async function mousedown(e) {
					right.style.pointerEvents = "none";
					await startDrag(e, (e2) => {
						const bounds = left.getBoundingClientRect();
						const x = Math.round(e2.clientX - bounds.x);
						left.style.width = "calc(" + x + "px - 1px)";
						split.style.left = "calc(" + x + "px - 2px)";
						right.style.left = "calc(" + x + "px + 1px)";
						settingsPut({ ...settings, leftWidthPct: Math.round(100 * bounds.width / splitElem.getBoundingClientRect().width) });
						updateMsglistWidths();
					});
					right.style.pointerEvents = "";
				}, "mousedown")), right = dom.div(css("layoutRight", { position: "absolute", right: 0, top: 0, bottom: 0 }), style({ left: "calc(" + settings.leftWidthPct + "% + 1px)" }), msgElem));
			} else {
				let top, split, bottom;
				dom._kids(splitElem, top = dom.div(css("layoutTop", { position: "absolute", top: 0, left: 0, right: 0 }), style({ height: "calc(" + settings.topHeightPct + "% - 1px)" }), msglistElem), split = dom.div(css("listMsgTopBottomGrab", { position: "absolute", height: "5px", left: "0", right: "0", cursor: "ns-resize", zIndex: zindexes.splitter }), style({ top: "calc(" + settings.topHeightPct + "% - 2px)" }), dom.div(css("listmsgTopBottomLine", { position: "absolute", backgroundColor: styles.popupBorderColor, left: 0, right: 0, height: "1px", top: "2px", bottom: "2px" })), /* @__PURE__ */ __name(function mousedown(e) {
					startDrag(e, (e2) => {
						const bounds = top.getBoundingClientRect();
						const y = Math.round(e2.clientY - bounds.y);
						top.style.height = "calc(" + y + "px - 1px)";
						split.style.top = "calc(" + y + "px - 2px)";
						bottom.style.top = "calc(" + y + "px + 1px)";
						settingsPut({ ...settings, topHeightPct: Math.round(100 * bounds.height / splitElem.getBoundingClientRect().height) });
					});
				}, "mousedown")), bottom = dom.div(css("layoutBottom", { position: "absolute", bottom: 0, left: 0, right: 0 }), style({ top: "calc(" + settings.topHeightPct + "% + 1px)" }), msgElem));
			}
			currentLayout = want;
			checkMsglistWidth();
		}, "selectLayout");
		const autoselectLayout = /* @__PURE__ */ __name(() => {
			const want = window.innerWidth <= 2 * 2560 / 3 ? "topbottom" : "leftright";
			selectLayout(want);
		}, "autoselectLayout");
		const styleElem = dom.style(attr.type("text/css"));
		document.head.appendChild(styleElem);
		const stylesheet = styleElem.sheet;
		let lastmsglistwidth = -1;
		const checkMsglistWidth = /* @__PURE__ */ __name(() => {
			const width = msglistscrollElem.getBoundingClientRect().width;
			if (lastmsglistwidth === width || width <= 0) {
				return;
			}
			updateMsglistWidths();
		}, "checkMsglistWidth");
		let lastflagswidth, lastagewidth;
		let rulesInserted = false;
		const updateMsglistWidths = /* @__PURE__ */ __name(() => {
			const width = msglistscrollElem.clientWidth - 2;
			lastmsglistwidth = width;
			let flagswidth = settings.msglistflagsWidth;
			let agewidth = settings.msglistageWidth;
			let frompct = settings.msglistfromPct;
			if (flagswidth + agewidth > width) {
				flagswidth = Math.floor(width / 2);
				agewidth = width - flagswidth;
			}
			const remain = width - (flagswidth + agewidth);
			const fromwidth = Math.floor(frompct * remain / 100);
			const subjectwidth = Math.floor(remain - fromwidth);
			const cssRules2 = [
				[".msgItemFlags", { width: flagswidth }],
				[".msgItemFrom", { width: fromwidth, position: "relative" }],
				[".msgItemSubject", { width: subjectwidth }],
				[".msgItemAge", { width: agewidth, "text-align": "right" }],
				[".msgItemFlagsOffset", { left: flagswidth }],
				[".msgItemFromOffset", { left: flagswidth + fromwidth }],
				[".msgItemSubjectOffset", { left: flagswidth + fromwidth + subjectwidth }]
			];
			if (!rulesInserted) {
				cssRules2.forEach((rule, i) => {
					stylesheet.insertRule(rule[0] + "{}", i);
				});
				rulesInserted = true;
			}
			cssRules2.forEach((rule, i) => {
				const r = stylesheet.cssRules[i];
				for (const k in rule[1]) {
					let v = rule[1][k];
					if (typeof v !== "string") {
						v = "" + v + "px";
					}
					r.style.setProperty(k, v);
				}
			});
			lastflagswidth = flagswidth;
			lastagewidth = agewidth;
		}, "updateMsglistWidths");
		if (layoutElem.value === "auto") {
			autoselectLayout();
		} else {
			selectLayout(layoutElem.value);
		}
		if (window.moxBeforeDisplay) {
			moxBeforeDisplay(webmailroot);
		}
		dom._kids(page, webmailroot);
		checkMsglistWidth();
		window.addEventListener("resize", function() {
			if (layoutElem.value === "auto") {
				autoselectLayout();
			}
			checkMsglistWidth();
		});
		window.addEventListener("hashchange", async (e) => {
			const hash = decodeURIComponent(window.location.hash);
			if (hash.startsWith("#compose ")) {
				try {
					const opts = parseComposeMailto(hash.substring("#compose ".length));
					if (e.oldURL) {
						const ou = new URL(e.oldURL);
						window.location.hash = ou.hash;
					} else {
						window.location.hash = "";
					}
					(async () => {
						if (opts.subject && opts.subject.includes("=?")) {
							opts.subject = await withStatus("Decoding MIME words for subject", client.DecodeMIMEWords(opts.subject));
						}
						compose(opts, listMailboxes, setLocationHash);
					})();
				} catch (err) {
					window.alert("Error parsing compose mailto URL: " + errmsg(err));
					window.location.hash = "";
				}
				return;
			}
			const [search2, msgid, editMsgid, f, notf] = parseLocationHash(mailboxlistView);
			requestMsgID = msgid;
			if (search2) {
				mailboxlistView.closeMailbox();
				loadSearch(search2);
			} else {
				unloadSearch();
				await mailboxlistView.openMailboxID(f.MailboxID, false);
			}
			if (editMsgid) {
				(async () => {
					try {
						const [mi, pm] = await withStatus("Loading compose message", Promise.all([client.MessageItem(editMsgid), client.ParsedMessage(editMsgid)]));
						await composeDraft(mi, pm, listMailboxes, setLocationHash);
					} catch (err) {
						window.alert("Error opening draft message: " + errmsg(err));
					}
				})();
			}
			await withStatus("Requesting messages", requestNewView(false, f, notf));
		});
		let eventSource = null;
		let connecting = false;
		let noreconnect = false;
		let noreconnectTimer = 0;
		let shutdownReconnectTimer = 0;
		let leaving = false;
		window.addEventListener("beforeunload", (e) => {
			if (composeView && composeView.unsavedChanges()) {
				e.preventDefault();
			} else {
				leaving = true;
				if (eventSource) {
					eventSource.close();
					eventSource = null;
					sseID = 0;
				}
			}
		});
		window.addEventListener("pageshow", async (e) => {
			if (e.persisted && !eventSource && !connecting) {
				noreconnect = false;
				connect(false);
			}
		});
		window.addEventListener("focus", () => {
			if (!eventSource && !connecting) {
				noreconnect = false;
				connect(true);
			}
		});
		const showNotConnected = /* @__PURE__ */ __name(() => {
			dom._kids(connectionElem, attr.role("status"), dom.span(css("connectionStatus", { backgroundColor: styles.warningBackgroundColor, padding: "0 .15em", borderRadius: ".15em" }), "Not connected", attr.title("Not receiving real-time updates, including of new deliveries.")), " ", dom.clickbutton("Reconnect", /* @__PURE__ */ __name(function click() {
				if (!eventSource && !connecting) {
					noreconnect = false;
					connect(true);
				}
			}, "click")));
		}, "showNotConnected");
		const capitalizeFirst = /* @__PURE__ */ __name((s) => s.charAt(0).toUpperCase() + s.slice(1), "capitalizeFirst");
		let openComposeOptions;
		let connectOpenComposeMessageID = 0;
		const connect = /* @__PURE__ */ __name(async (isreconnect) => {
			if (shutdownReconnectTimer) {
				window.clearTimeout(shutdownReconnectTimer);
				shutdownReconnectTimer = 0;
			}
			connectionElem.classList.toggle("loading", true);
			dom._kids(connectionElem);
			connectionElem.classList.toggle("loading", false);
			noreconnect = isreconnect;
			connecting = true;
			let token;
			try {
				token = await withStatus("Fetching token for connection with real-time updates", client.Token(), void 0, true);
			} catch (err) {
				connecting = false;
				noreconnect = true;
				dom._kids(statusElem, capitalizeFirst(err.message || "Error fetching connection token") + ", not automatically retrying. ");
				showNotConnected();
				return;
			}
			const h = decodeURIComponent(window.location.hash);
			if (h.startsWith("#compose ")) {
				try {
					openComposeOptions = parseComposeMailto(h.substring("#compose ".length));
				} catch (err) {
					window.alert("Error parsing mailto URL: " + errmsg(err));
				}
				window.location.hash = "";
			}
			let [searchQuery, msgid, editMsgid, f, notf] = parseLocationHash(mailboxlistView);
			if (editMsgid && !composeView) {
				connectOpenComposeMessageID = editMsgid;
			}
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
				NotFilter: notf
			};
			const page2 = {
				AnchorMessageID: 0,
				Count: fetchCount,
				DestMessageID: msgid
			};
			viewSequence++;
			viewID = viewSequence;
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
				Page: page2
			};
			let slow = "";
			try {
				const debug = JSON.parse(localStorage.getItem("sherpats-debug") || "null");
				if (debug && debug.waitMinMsec && debug.waitMaxMsec) {
					slow = "&waitMinMsec=" + debug.waitMinMsec + "&waitMaxMsec=" + debug.waitMaxMsec;
				}
			} catch (err) {
			}
			eventSource = new window.EventSource("events?singleUseToken=" + encodeURIComponent(token) + "&request=" + encodeURIComponent(JSON.stringify(request)) + slow);
			let eventID = window.setTimeout(() => dom._kids(statusElem, "Connecting... "), 1e3);
			eventSource.addEventListener("open", (e) => {
				log("eventsource open", { e });
				if (eventID) {
					window.clearTimeout(eventID);
					eventID = 0;
				}
				dom._kids(statusElem);
				dom._kids(connectionElem);
			});
			const sseError = /* @__PURE__ */ __name((errmsg2, addNotRetrying) => {
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
				document.title = ["(not connected)", loginAddress ? loginAddress.User + "@" + formatDomain(loginAddress.Domain) : "", "Mox Webmail"].filter((s) => s).join(" - ");
				dom._kids(connectionElem);
				if (noreconnect) {
					let msg = capitalizeFirst(errmsg2);
					if (addNotRetrying) {
						msg += ", not automatically retrying. ";
					}
					dom._kids(statusElem, msg);
					showNotConnected();
					listloadingElem.remove();
					listendElem.remove();
				} else {
					connect(true);
				}
			}, "sseError");
			eventSource.addEventListener("error", (e) => {
				log("eventsource error", { e }, JSON.stringify(e));
				sseError("Connection failed", true);
			});
			eventSource.addEventListener("fatalErr", (e) => {
				const errmsg2 = JSON.parse(e.data) || "(no error message)";
				sseError('Server error: "' + errmsg2 + '"', true);
			});
			eventSource.addEventListener("serverShutdown", (_) => {
				noreconnect = true;
				sseError("Server shutting down, will try to reconnect in a few seconds", false);
				shutdownReconnectTimer = window.setTimeout(() => {
					connect(true);
				}, 3e3 + Math.floor(Math.random() * 5e3));
			});
			const checkParse = /* @__PURE__ */ __name((fn) => {
				try {
					return fn();
				} catch (err) {
					window.alert("invalid event from server: " + (err.message || "(no message)"));
					throw err;
				}
			}, "checkParse");
			eventSource.addEventListener("start", (e) => {
				const data = JSON.parse(e.data);
				if (lastServerVersion && data.Version !== lastServerVersion) {
					let reload = true;
					if (composeView && composeView.unsavedChanges()) {
						try {
							withStatus("Saving before reloading due to server update", composeView.save());
						} catch (err) {
							window.alert("Server was updated, and webmail wants to reload to get the latest changes, but encountered an error while saving changes your open draft message. Please reload at your earliest convenience.");
							reload = false;
						}
					}
					if (reload) {
						const u = URL.parse(window.location.href);
						u.search = "?v=" + data.Version + (u.search ? "&" + u.search.substring(1) : "");
						window.location.href = u.toString();
						return;
					}
				}
				lastServerVersion = data.Version;
				const start = checkParse(() => parser.EventStart(data));
				log("event start", start);
				accountSettings = start.Settings;
				introboxMailbox = start.Introbox;
				connecting = false;
				sseID = start.SSEID;
				loginAddress = start.LoginAddress;
				dom._kids(accountElem, start.AccountPath ? dom.a(attr.href(start.AccountPath), "Account") : []);
				const loginAddr = formatEmail(loginAddress);
				dom._kids(loginAddressElem, loginAddr);
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
				if (openComposeOptions) {
					(async () => {
						if (openComposeOptions.subject && openComposeOptions.subject.includes("=?")) {
							openComposeOptions.subject = await withStatus("Decoding MIME words for subject", client.DecodeMIMEWords(openComposeOptions.subject));
						}
						compose(openComposeOptions, listMailboxes, setLocationHash);
						openComposeOptions = void 0;
					})();
				}
				if (connectOpenComposeMessageID) {
					(async () => {
						const editMsgid2 = connectOpenComposeMessageID;
						connectOpenComposeMessageID = 0;
						try {
							const [mi, pm] = await withStatus("Loading compose message", Promise.all([client.MessageItem(editMsgid2), client.ParsedMessage(editMsgid2)]));
							await composeDraft(mi, pm, listMailboxes, setLocationHash);
						} catch (err) {
							window.alert("Error opening draft message: " + errmsg(err));
						}
					})();
				}
				let mailboxName = start.MailboxName;
				let mb = (start.Mailboxes || []).find((mb2) => mb2.Name === start.MailboxName);
				if (mb) {
					requestFilter.MailboxID = mb.ID;
				}
				if (mailboxName === "") {
					mailboxName = (start.Mailboxes || []).find((mb2) => mb2.ID === requestFilter.MailboxID)?.Name || "";
				}
				mailboxlistView.loadMailboxes(start.Mailboxes || [], search.active ? void 0 : mailboxName);
				if (searchView.root.parentElement) {
					searchView.ensureLoaded();
				}
				if (!mb) {
					updatePageTitle();
				}
				dom._kids(queryactivityElem, "loading...");
				msglistscrollElem.appendChild(listloadingElem);
				noreconnectTimer = window.setTimeout(() => {
					noreconnect = false;
					noreconnectTimer = 0;
				}, 5 * 1e3);
			});
			eventSource.addEventListener("viewErr", async (e) => {
				const viewErr = checkParse(() => parser.EventViewErr(JSON.parse(e.data)));
				log("event viewErr", viewErr);
				if (viewErr.ViewID !== viewID || viewErr.RequestID !== requestID) {
					log("received viewErr for other viewID or requestID", { expected: { viewID, requestID }, got: { viewID: viewErr.ViewID, requestID: viewErr.RequestID } });
					return;
				}
				viewID = 0;
				requestID = 0;
				dom._kids(queryactivityElem);
				listloadingElem.remove();
				listerrElem.remove();
				dom._kids(listerrElem, "Error from server during request for messages: " + viewErr.Err);
				msglistscrollElem.appendChild(listerrElem);
				window.alert("Error from server during request for messages: " + viewErr.Err);
			});
			eventSource.addEventListener("viewReset", async (e) => {
				const viewReset = checkParse(() => parser.EventViewReset(JSON.parse(e.data)));
				log("event viewReset", viewReset);
				if (viewReset.ViewID !== viewID || viewReset.RequestID !== requestID) {
					log("received viewReset for other viewID or requestID", { expected: { viewID, requestID }, got: { viewID: viewReset.ViewID, requestID: viewReset.RequestID } });
					return;
				}
				clearList();
				dom._kids(queryactivityElem, "loading...");
				msglistscrollElem.appendChild(listloadingElem);
				window.alert("Could not find message to continue scrolling, resetting the view.");
			});
			eventSource.addEventListener("viewMsgs", async (e) => {
				const viewMsgs = checkParse(() => parser.EventViewMsgs(JSON.parse(e.data)));
				log("event viewMsgs", viewMsgs);
				if (viewMsgs.ViewID !== viewID || viewMsgs.RequestID !== requestID) {
					log("received viewMsgs for other viewID or requestID", { expected: { viewID, requestID }, got: { viewID: viewMsgs.ViewID, requestID: viewMsgs.RequestID } });
					return;
				}
				msglistView.root.classList.toggle("loading", false);
				if (viewMsgs.MessageItems) {
					msglistView.addMessageItems(viewMsgs.MessageItems || [], false, requestMsgID);
				}
				if (viewMsgs.ParsedMessage) {
					const ok = msglistView.openMessage(viewMsgs.ParsedMessage);
					if (!ok) {
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
			eventSource.addEventListener("viewChanges", async (e) => {
				const viewChanges = checkParse(() => parser.EventViewChanges(JSON.parse(e.data)));
				log("event viewChanges", viewChanges);
				if (viewChanges.ViewID !== viewID) {
					log("received viewChanges for other viewID", { expected: viewID, got: viewChanges.ViewID });
					return;
				}
				try {
					(viewChanges.Changes || []).forEach((tc) => {
						if (!tc) {
							return;
						}
						const [tag, x] = tc;
						if (tag === "ChangeMailboxCounts") {
							const c = parser.ChangeMailboxCounts(x);
							mailboxlistView.setMailboxCounts(c.MailboxID, c.Total, c.Unread);
						} else if (tag === "ChangeMailboxSpecialUse") {
							const c = parser.ChangeMailboxSpecialUse(x);
							mailboxlistView.setMailboxSpecialUse(c.MailboxID, c.SpecialUse);
						} else if (tag === "ChangeMailboxKeywords") {
							const c = parser.ChangeMailboxKeywords(x);
							mailboxlistView.setMailboxKeywords(c.MailboxID, c.Keywords || []);
						} else if (tag === "ChangeMsgAdd") {
							const c = parser.ChangeMsgAdd(x);
							msglistView.addMessageItems([c.MessageItems || []], true, 0);
						} else if (tag === "ChangeMsgRemove") {
							const c = parser.ChangeMsgRemove(x);
							msglistView.removeUIDs(c.MailboxID, c.UIDs || []);
						} else if (tag === "ChangeMsgFlags") {
							const c = parser.ChangeMsgFlags(x);
							msglistView.updateFlags(c.MailboxID, c.UID, c.ModSeq, c.Mask, c.Flags, c.Keywords || []);
						} else if (tag === "ChangeMsgThread") {
							const c = parser.ChangeMsgThread(x);
							if (c.MessageIDs) {
								msglistView.updateMessageThreadFields(c.MessageIDs, c.Muted, c.Collapsed);
							}
						} else if (tag === "ChangeMailboxRemove") {
							const c = parser.ChangeMailboxRemove(x);
							mailboxlistView.removeMailbox(c.MailboxID);
						} else if (tag === "ChangeMailboxAdd") {
							const c = parser.ChangeMailboxAdd(x);
							mailboxlistView.addMailbox(c.Mailbox);
						} else if (tag === "ChangeMailboxRename") {
							const c = parser.ChangeMailboxRename(x);
							mailboxlistView.renameMailbox(c.MailboxID, c.NewName);
						} else {
							throw new Error("unknown change tag " + tag);
						}
					});
				} catch (err) {
					window.alert("Error processing changes (reloading advised): " + errmsg(err));
				}
			});
		}, "connect");
		connect(false);
	}, "init");
	window.addEventListener("load", async () => {
		try {
			await init();
		} catch (err) {
			window.alert("Error: " + errmsg(err));
		}
	});
	var origLocation = {
		href: window.location.href,
		protocol: window.location.protocol,
		host: window.location.host,
		pathname: window.location.pathname,
		search: window.location.search
	};
	var showUnhandledError = /* @__PURE__ */ __name((err, lineno, colno) => {
		console.log("unhandled error", err);
		if (settings.ignoreErrorsUntil > (/* @__PURE__ */ new Date()).getTime() / 1e3) {
			return;
		}
		let stack = err.stack || "";
		if (stack) {
			log({ stack });
			const loc = origLocation;
			stack = "\n" + stack.replaceAll(loc.href, "webmail.html").replaceAll(loc.protocol + "//" + loc.host + loc.pathname + loc.search, "webmail.html");
		} else {
			stack = " (not available)";
		}
		const xerrmsg = err.toString();
		const box = dom.div(css("unhandledErrorBox", { position: "absolute", bottom: "1ex", left: "1ex", backgroundColor: "rgba(255, 110, 110, .9)", maxWidth: "14em", padding: ".25em .5em", borderRadius: ".25em", fontSize: ".8em", wordBreak: "break-all", zIndex: zindexes.shortcut }), dom.div(style({ marginBottom: ".5ex" }), "" + xerrmsg), dom.clickbutton("Details", /* @__PURE__ */ __name(function click() {
			box.remove();
			let msg = `Mox version: ${moxversion} (${moxgoos}/${moxgoarch})
Browser: ${window.navigator.userAgent}
File: webmail.html
Lineno: ${lineno || "-"}
Colno: ${colno || "-"}
Message: ${xerrmsg}

Stack trace: ${stack}
`;
			const body = `[Hi! Please replace this text with an explanation of what you did to trigger this errors. It will help us reproduce the problem. The more details, the more likely it is we can find and fix the problem. If you don't know how or why it happened, that's ok, it is still useful to report the problem. If no stack trace was found and included below, and you are a developer, you can probably find more details about the error in the browser developer console. Thanks!]

Details of the error and browser:

\`\`\`
` + msg + "```\n";
			const remove = popup(style({ maxWidth: "60em" }), dom.h1("A JavaScript error occurred"), dom.pre(dom._class("mono"), css("unhandledErrorMsg", { backgroundColor: styles.backgroundColorMild, padding: "1ex", borderRadius: ".15em", border: "1px solid", borderColor: styles.borderColor, whiteSpace: "pre-wrap" }), msg), dom.br(), dom.div("There is a good chance this is a bug in Mox Webmail."), dom.div('Consider filing a bug report ("issue") at ', link("https://github.com/mjl-/mox/issues/new?title=" + encodeURIComponent('mox webmail js error: "' + xerrmsg + '"') + "&body=" + encodeURIComponent(body), "https://github.com/mjl-/mox/issues/new"), ". The link includes the error details."), dom.div("Before reporting you could check previous ", link('https://github.com/mjl-/mox/issues?q=is%3Aissue+"mox+webmail+js+error%3A"', "webmail bug reports"), "."), dom.br(), dom.div("Your feedback will help improve mox, thanks!"), dom.br(), dom.div(style({ textAlign: "right" }), dom.clickbutton("Close and silence errors for 1 week", /* @__PURE__ */ __name(function click2() {
				remove();
				settingsPut({ ...settings, ignoreErrorsUntil: Math.round((/* @__PURE__ */ new Date()).getTime() / 1e3 + 7 * 24 * 3600) });
			}, "click")), " ", dom.clickbutton("Close", /* @__PURE__ */ __name(function click2() {
				remove();
			}, "click"))));
		}, "click")), " ", dom.clickbutton("Ignore", /* @__PURE__ */ __name(function click() {
			box.remove();
		}, "click")));
		document.body.appendChild(box);
	}, "showUnhandledError");
	window.addEventListener("unhandledrejection", (e) => {
		if (!e.reason) {
			return;
		}
		const err = e.reason;
		if (err instanceof EvalError || err instanceof RangeError || err instanceof ReferenceError || err instanceof SyntaxError || err instanceof TypeError || err instanceof URIError || err instanceof ConsistencyError) {
			showUnhandledError(err, 0, 0);
		} else {
			console.log("unhandled promiserejection", err, e.promise);
		}
	});
	window.addEventListener("error", (e) => {
		showUnhandledError(e.error, e.lineno, e.colno);
	});
})();
