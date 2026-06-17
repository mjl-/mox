// Javascript is generated from typescript, do not modify generated javascript because changes will be overwritten.

// We build CSS rules in JS. For several reasons:
// - To keep the style definitions closer to their use.
// - To make it easier to provide both light/regular and dark mode colors.
// - To use class names for styling, instead of the the many inline styles.
//   Makes it easier to look through a DOM, and easier to change the style of all
//   instances of a class.

const cssStyleDark = dom.style(attr.type('text/css'))
document.head.prepend(cssStyleDark)
const styleSheetDark = cssStyleDark.sheet!
styleSheetDark.insertRule('@media (prefers-color-scheme: dark) {}')
const darkModeRule = styleSheetDark.cssRules[0] as CSSMediaRule

// We keep the default/regular styles and dark-mode styles in separate stylesheets.
const cssStyle = dom.style(attr.type('text/css'))
document.head.prepend(cssStyle)
const styleSheet = cssStyle.sheet!

let cssRules: { [selector: string]: string} = {} // For ensuring a selector has a single definition.
// Ensure a selector has the given style properties. If a style value is an array,
// it must have 2 elements. The first is the default value, the second used for a
// rule for dark mode.
const ensureCSS = (selector: string, styles: { [prop: string]: string | number | string[] }, important?: boolean) => {
	// Check that a selector isn't added again with different styling. Only during development.
	const checkConsistency = location.hostname === 'localhost'
	if (cssRules[selector]) {
		if (checkConsistency) {
			const exp = JSON.stringify(styles)
			if (cssRules[selector] !== exp) {
				throw new Error('duplicate css rule for selector '+selector+', had '+cssRules[selector] + ', next '+exp)
			}
		}
		return
	}
	cssRules[selector] = checkConsistency ? JSON.stringify(styles) : 'x'

	const index = styleSheet.cssRules.length
	styleSheet.insertRule(selector + ' {}', index)
	const st = (styleSheet.cssRules[index] as CSSStyleRule).style
	let darkst: CSSStyleDeclaration | undefined
	for (let [k, v] of Object.entries(styles)) {
		// We've kept the camel-case in our code which we had from when we did "st[prop] =
		// value". It is more convenient as object keys. So convert to kebab-case, but only
		// if this is not a css property.
		if (!k.startsWith('--')) {
			k = k.replace(/[A-Z]/g, s => '-'+s.toLowerCase())
		}
		if (Array.isArray(v)) {
			if (v.length !== 2) {
				throw new Error('2 elements required for light/dark mode style, got '+v.length)
			}
			if (!darkst) {
				const darkIndex = darkModeRule.cssRules.length
				darkModeRule.insertRule(selector + ' {}', darkIndex)
				darkst = (darkModeRule.cssRules[darkIndex] as CSSStyleRule).style
			}
			st.setProperty(k, ''+v[0], important ? 'important' : '')
			darkst.setProperty(k, ''+v[1], important ? 'important' : '')
		} else {
			st.setProperty(k, ''+v, important ? 'important' : '')
		}
	}
}

// Ensure CSS styling exists for a class, returning the same kind of object
// returned by dom._class, for use with dom.*-building functions.
const css = (className: string, styles: { [prop: string]: string | number | string[] }, important?: boolean): { _class: string[] } => {
	ensureCSS('.'+className, styles, important)
	return dom._class(className)
}

// todo: reduce number of colors. hopefully we can derive some colors from a few base colors (making them brighter/darker, or shifting hue, etc). then make them configurable through settings.
// todo: add the standard padding and border-radius, perhaps more.
// We define css variables, making them easy to override.

// Base colour tokens. Each value is [light, dark]. These drive the automatic
// light/dark behaviour (:root + prefers-color-scheme) AND the forced-scheme
// rules (html.scheme-light / html.scheme-dark) added below.
const baseTokens: { [v: string]: string[] } = {
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
	'--underlineGreen': ['#50c40f', '#50c40f'],
	'--underlineRed': ['#e15d1c', '#e15d1c'],
	'--underlineBlue': ['#09f', '#09f'],
	'--underlineGrey': ['#888', '#888'],
	'--quoted1Color': ['#03828f', '#71f2ff'],
	'--quoted2Color': ['#c7445c', '#ec4c4c'],
	'--quoted3Color': ['#417c10', '#73e614'],
	'--scriptSwitchUnderlineColor': ['#dca053', '#e88f1e'],
	'--linkColor': ['#096bc2', '#63b6ff'],
	'--linkVisitedColor': ['#0704c1', '#c763ff'],

	// New in phase 2. Accent is unused by the classic look (so adds no visual
	// change); the modern theme (stage 2) routes accented elements through it.
	'--accent': ['#2b6cff', '#2b6cff'],
	'--accentText': ['#ffffff', '#ffffff'],
	'--radius': ['.4em', '.4em'],
}

ensureCSS(':root', baseTokens)

// pickScheme returns a single-valued token map (light=index 0, dark=index 1)
// for use in a forced-scheme rule.
const pickScheme = (i: number): { [v: string]: string } => {
	const m: { [v: string]: string } = {}
	for (const [k, v] of Object.entries(baseTokens)) {
		m[k] = v[i]
	}
	return m
}

// High-contrast token maps: maximal contrast, solid borders, no faint tints.
const hcLightTokens: { [v: string]: string } = {
	'--color': '#000000', '--colorMild': '#000000', '--colorMilder': '#1a1a1a',
	'--backgroundColor': '#ffffff', '--backgroundColorMild': '#ffffff', '--backgroundColorMilder': '#000000',
	'--borderColor': '#000000', '--mailboxesTopBackgroundColor': '#ffffff', '--msglistBackgroundColor': '#ffffff',
	'--boxShadow': '0 0 0 1px #000',
	'--buttonBackground': '#ffffff', '--buttonBorderColor': '#000000', '--buttonHoverBackground': '#e6e6e6',
	'--overlayOpaqueBackgroundColor': '#ffffff', '--overlayBackgroundColor': 'rgba(0,0,0,0.5)',
	'--popupColor': '#000000', '--popupBackgroundColor': '#ffffff', '--popupBorderColor': '#000000',
	'--highlightBackground': '#0044cc', '--highlightBorderColor': '#000000', '--highlightBackgroundHover': '#0033aa',
	'--mailboxActiveBackground': '#0044cc', '--mailboxHoverBackgroundColor': '#d6e4ff',
	'--msgItemActiveBackground': '#0044cc', '--msgItemHoverBackgroundColor': '#d6e4ff', '--msgItemFocusBorderColor': '#0044cc',
	'--buttonTristateOnBackground': '#006600', '--buttonTristateOffBackground': '#990000',
	'--warningBackgroundColor': '#ffdd00', '--successBackground': '#006600', '--emphasisBackground': '#000000',
	'--underlineGreen': '#006600', '--underlineRed': '#990000', '--underlineBlue': '#0044cc', '--underlineGrey': '#000000',
	'--quoted1Color': '#000000', '--quoted2Color': '#000000', '--quoted3Color': '#000000',
	'--scriptSwitchUnderlineColor': '#990000',
	'--linkColor': '#0000ee', '--linkVisitedColor': '#551a8b',
	'--accent': '#0044cc', '--accentText': '#ffffff', '--radius': '.4em',
}
const hcDarkTokens: { [v: string]: string } = {
	'--color': '#ffffff', '--colorMild': '#ffffff', '--colorMilder': '#e6e6e6',
	'--backgroundColor': '#000000', '--backgroundColorMild': '#000000', '--backgroundColorMilder': '#ffffff',
	'--borderColor': '#ffffff', '--mailboxesTopBackgroundColor': '#000000', '--msglistBackgroundColor': '#000000',
	'--boxShadow': '0 0 0 1px #fff',
	'--buttonBackground': '#000000', '--buttonBorderColor': '#ffffff', '--buttonHoverBackground': '#1a1a1a',
	'--overlayOpaqueBackgroundColor': '#000000', '--overlayBackgroundColor': 'rgba(0,0,0,0.7)',
	'--popupColor': '#ffffff', '--popupBackgroundColor': '#000000', '--popupBorderColor': '#ffffff',
	'--highlightBackground': '#66aaff', '--highlightBorderColor': '#ffffff', '--highlightBackgroundHover': '#3388ff',
	'--mailboxActiveBackground': '#0066ff', '--mailboxHoverBackgroundColor': '#003366',
	'--msgItemActiveBackground': '#0066ff', '--msgItemHoverBackgroundColor': '#003366', '--msgItemFocusBorderColor': '#66aaff',
	'--buttonTristateOnBackground': '#00cc00', '--buttonTristateOffBackground': '#ff5555',
	'--warningBackgroundColor': '#ffdd00', '--successBackground': '#00cc00', '--emphasisBackground': '#ffffff',
	'--underlineGreen': '#00ff00', '--underlineRed': '#ff5555', '--underlineBlue': '#66aaff', '--underlineGrey': '#ffffff',
	'--quoted1Color': '#ffffff', '--quoted2Color': '#ffffff', '--quoted3Color': '#ffffff',
	'--scriptSwitchUnderlineColor': '#ffaa00',
	'--linkColor': '#66aaff', '--linkVisitedColor': '#cc99ff',
	'--accent': '#66aaff', '--accentText': '#000000', '--radius': '.4em',
}

// Forced schemes: a class on <html> overrides the auto (:root + media query)
// tokens. Specificity of html.scheme-* (0,1,1) beats :root (0,1,0).
ensureCSS('html.scheme-light', pickScheme(0))
ensureCSS('html.scheme-dark', pickScheme(1))
ensureCSS('html.scheme-hclight', hcLightTokens)
ensureCSS('html.scheme-hcdark', hcDarkTokens)

// Modern message list: 2-line layout with avatar, subject line and preview line.
ensureCSS('.theme-modern .msgItem', {
	display: 'grid',
	// Far-left "flags" column holds the thread expand/collapse control (the flag
	// letters themselves are hidden); it is ~0 wide when there is no control.
	gridTemplateColumns: 'auto auto minmax(0, 1fr) auto',
	gridTemplateAreas: '"flags avatar from age" "flags avatar subject subject"',
	columnGap: '.5em',
	alignItems: 'center',
	padding: '.45em .6em',
	border: '1px solid transparent',
	borderRadius: 'var(--radius)',
	// Positioning context for the full-height thread connector bar.
	position: 'relative',
	// Configurable list text size (1 = 100%); set via --ml-scale by applyAppearance.
	fontSize: 'calc(1em * var(--ml-scale, 1))',
})
ensureCSS('.theme-modern .msgItemCell', {padding: 0, width: 'auto'})
// Override the runtime column widths set by updateMsglistWidths.
// Keep the flags cell (it holds the thread expand/collapse control); hide only the
// flag letters.
ensureCSS('.theme-modern .msgItemFlags', {gridArea: 'flags', display: 'flex', alignItems: 'center', padding: 0, width: 'auto'})
ensureCSS('.theme-modern .msgItemFlag', {display: 'none'})
// Thread connector: a full-height vertical line on the left, anchored to the whole
// item (not the from cell). The first/last/middle variant classes still set
// top/bottom for the half-bars at thread ends.
ensureCSS('.theme-modern .msgItemFrom', {gridArea: 'from', width: 'auto', position: 'static'})
// Configurable per-element weight/style (defaults: sender bold, the rest normal).
ensureCSS('.theme-modern .msgItemFromText', {fontWeight: 'var(--ml-from-weight, bold)', fontStyle: 'var(--ml-from-style, normal)'})
ensureCSS('.theme-modern .msgItemThreadBar', {left: '.55em', right: 'auto', borderLeft: '2px solid var(--colorMild)', borderRight: 'none'})
// The bar is anchored to the full item (which has .45em vertical padding), so the
// default ±1px end offsets fall short of the row edges and leave seams between
// rows. Overshoot by half an em so consecutive segments overlap into one solid
// line, and shape the thread ends: the root gets a short tail reaching up toward
// the collapse control, the last message a short stub marking the end.
ensureCSS('.theme-modern .msgItemThreadBarMiddle', {top: '-.5em', bottom: '-.5em'})
ensureCSS('.theme-modern .msgItemThreadBarFirst', {top: '40%', bottom: '-.5em'})
ensureCSS('.theme-modern .msgItemThreadBarLast', {top: '-.5em', bottom: '50%'})
ensureCSS('.theme-modern .msgItemSubject', {gridArea: 'subject', width: 'auto'})
ensureCSS('.theme-modern .msgItemAge', {gridArea: 'age', width: 'auto', color: 'var(--colorMilder)', fontWeight: 'var(--ml-date-weight, normal)', fontStyle: 'var(--ml-date-style, normal)'})
ensureCSS('.theme-modern .msgItemAvatar', {
	display: 'flex',
	gridArea: 'avatar',
	alignItems: 'center',
	justifyContent: 'center',
	width: '34px',
	height: '34px',
	borderRadius: '50%',
	color: '#fff',
	fontWeight: 'bold',
	alignSelf: 'center',
})
// Subject and preview flow inline within a 2-line clamped box: the subject takes
// priority (a long subject wraps to the second line), and the muted preview fills
// whatever room is left.
ensureCSS('.theme-modern .msgItemSubjectText', {display: '-webkit-box', WebkitBoxOrient: 'vertical', WebkitLineClamp: '2', overflow: 'hidden', whiteSpace: 'normal'})
ensureCSS('.theme-modern .msgItemSubjectTitle', {display: 'inline', fontWeight: 'var(--ml-subj-weight, normal)', fontStyle: 'var(--ml-subj-style, normal)'})
ensureCSS('.theme-modern .msgItemSubjectSnippet', {display: 'inline', margin: 0, fontWeight: 'var(--ml-prev-weight, normal)', fontStyle: 'var(--ml-prev-style, normal)'})
// Unread emphasis, selected in Settings and reflected as an html.unread-* class:
// accent bar on the left (default and "barbold"), bold sender/subject ("bold" and
// "barbold"), an accent-tinted row ("tint"), or a left dot ("dot"). All modern-only.
ensureCSS('.theme-modern.unread-bar .msgItem.msgItemUnread, .theme-modern.unread-barbold .msgItem.msgItemUnread', {boxShadow: 'inset .2em 0 0 var(--accent)'})
ensureCSS('.theme-modern.unread-bold .msgItem.msgItemUnread .msgItemFromText, .theme-modern.unread-bold .msgItem.msgItemUnread .msgItemSubjectTitle, .theme-modern.unread-barbold .msgItem.msgItemUnread .msgItemFromText, .theme-modern.unread-barbold .msgItem.msgItemUnread .msgItemSubjectTitle', {fontWeight: 'bold'})
ensureCSS('.theme-modern.unread-tint .msgItem.msgItemUnread', {background: 'color-mix(in srgb, var(--accent) 10%, transparent)'})
ensureCSS('.theme-modern.unread-dot .msgItem.msgItemUnread::after', {content: '""', position: 'absolute', left: '.2em', top: '50%', transform: 'translateY(-50%)', width: '.5em', height: '.5em', borderRadius: '50%', background: 'var(--accent)'})
// Selection and hover use the accent tint and rounded corners (override classic).
ensureCSS('.theme-modern .msgItem.active', {background: 'color-mix(in srgb, var(--accent) 18%, transparent)'}, true)
ensureCSS('.theme-modern .msgItem:hover', {backgroundColor: 'color-mix(in srgb, var(--accent) 10%, transparent)'}, true)

// Modern top bar: pill search, accent Compose button.
ensureCSS('.theme-modern .searchbarElem', {borderRadius: '1em', padding: '.2em .8em'})
ensureCSS('.theme-modern .composeButton', {background: 'var(--accent)', color: 'var(--accentText)', borderColor: 'transparent'}, true)
ensureCSS('.theme-modern .composeButton:hover:not(:disabled)', {background: 'color-mix(in srgb, var(--accent) 85%, var(--color))'}, true)

// Modern folder list: icons, rounded accent-tinted active row, hover, count badge.
ensureCSS('.theme-modern .mailboxItem', {borderRadius: 'var(--radius)'})
ensureCSS('.theme-modern .mailboxItem.active', {background: 'color-mix(in srgb, var(--accent) 18%, transparent)'}, true)
ensureCSS('.theme-modern .mailboxItem:hover', {backgroundColor: 'color-mix(in srgb, var(--accent) 10%, transparent)'}, true)
ensureCSS('.theme-modern .mailboxIcon', {display: 'inline-block', width: '1.3em', marginRight: '.3em', textAlign: 'center', flex: 'none'})
ensureCSS('.theme-modern .mailboxUnread:not(:empty)', {background: 'var(--accent)', color: 'var(--accentText)', borderRadius: '1em', padding: '0 .5em', fontSize: '.85em', fontWeight: 'normal'})

// Modern reading pane: reorder the header into a flex column — large subject, then
// avatar+sender (with a Details disclosure), then the action pills, then the detail
// block (the classic header table is collapsed by default). Classic is untouched
// because the modern elements are display:none there.
ensureCSS('.theme-modern .msgmeta', {display: 'flex', flexDirection: 'column', padding: '.6em .8em', gap: '.15em'})
ensureCSS('.theme-modern .msgModernSubject', {display: 'block', order: '1', margin: '.1em 0 .2em', fontSize: 'calc(1.5em * var(--mv-subj-scale, 1))', fontWeight: '600', lineHeight: '1.25'})
ensureCSS('.theme-modern .msgModernSender', {display: 'flex', order: '2', alignItems: 'center', gap: '.6em', marginBottom: '.35em'})
ensureCSS('.theme-modern .msgButtons', {order: '3'})
ensureCSS('.theme-modern .msgDetails', {order: '4'})
ensureCSS('.theme-modern .headerBodySeparator', {order: '5'})

// Avatar + sender identity line.
ensureCSS('.theme-modern .msgModernAvatar', {display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none', width: '40px', height: '40px', borderRadius: '50%', color: '#fff', fontWeight: 'bold'})
ensureCSS('.theme-modern .msgModernSenderText', {display: 'flex', flexDirection: 'column', minWidth: '0'})
ensureCSS('.theme-modern .msgModernSenderName', {fontWeight: 'var(--mv-sender-weight, 600)', fontStyle: 'var(--mv-sender-style, normal)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'})
ensureCSS('.theme-modern .msgModernSenderTime', {color: 'var(--colorMild)', fontSize: '.9em'})
// Header actions live at the right end of the sender line: the mode dropdown
// (Text/HTML) and the Details disclosure, both small rounded pills like the other
// modern buttons. The classic inline Text/HTML row is hidden here.
ensureCSS('.theme-modern .msgModernSenderActions', {marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '.4em', flex: 'none'})
ensureCSS('.theme-modern .msgModernSenderActions button', {borderRadius: '1em', padding: '.15em .7em', fontSize: '.85em'}, true)
ensureCSS('.theme-modern .msgMode', {display: 'none'})

// Details (recipients + date) collapsed by default; the Details toggle reveals the
// classic header table.
ensureCSS('.theme-modern .msgmeta .msgHeaders', {display: 'none'})
ensureCSS('.theme-modern .msgmeta.detailsExpanded .msgHeaders', {display: 'table'})

// Action buttons as pills, with an accent Reply. (important to beat the generic
// button rules, which tie on specificity by source order.)
ensureCSS('.theme-modern .msgmeta .msgButtons button', {borderRadius: '1em', padding: '.25em .9em'}, true)
ensureCSS('.theme-modern .msgmeta .msgReplyButton', {background: 'var(--accent)', color: 'var(--accentText)', borderColor: 'transparent'}, true)
ensureCSS('.theme-modern .msgmeta .msgReplyButton:hover:not(:disabled)', {background: 'color-mix(in srgb, var(--accent) 85%, var(--color))'}, true)

// Comfortable body padding.
ensureCSS('.theme-modern .msgscroll', {padding: '1em 1.2em'})

// Modern message-list filter/sort toolbar: drop the "Refine:" label, keep both
// groups on a single nowrap row, render the quick filters as compact rounded
// icon pills so it fits even at narrow widths.
ensureCSS('.theme-modern .refineTitle', {display: 'none'})
ensureCSS('.theme-modern .msgListFilterSorting', {padding: '.3em .5em', gap: '.5em', alignItems: 'center'})
ensureCSS('.theme-modern .msgListFilterSorting > div', {display: 'flex', alignItems: 'center', gap: '.35em', flexWrap: 'nowrap'})
ensureCSS('.theme-modern .msgListFilterSorting .btngroup', {display: 'inline-flex', alignItems: 'center', gap: '.3em'})
// Textual toolbar controls (Label, ↑↓) are compact rounded pills.
ensureCSS('.theme-modern .msgListFilterSorting button', {borderRadius: '1em', padding: '.2em .7em', fontSize: '.85em', lineHeight: '1.3', border: '1px solid transparent'}, true)
ensureCSS('.theme-modern .msgListFilterSorting select', {borderRadius: '1em', fontSize: '.85em', padding: '.15em .5em'})
// Active filter / inverted sort takes the accent.
ensureCSS('.theme-modern .msgListFilterSorting button.active, .theme-modern .msgListFilterSorting button.invert', {background: 'var(--accent)', color: 'var(--accentText)', borderColor: 'transparent'}, true)
// Quick filters render as equal, borderless circular icon buttons (text collapsed via
// font-size:0; the glyph comes from a centred ::before), tinted on hover.
ensureCSS('.theme-modern .msgListFilterSorting .refineIcon', {fontSize: '0', width: '1.9rem', height: '1.9rem', padding: '0', borderRadius: '50%', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', background: 'transparent', border: '1px solid transparent'}, true)
ensureCSS('.theme-modern .msgListFilterSorting .refineIcon:hover', {background: 'color-mix(in srgb, var(--accent) 14%, transparent)'}, true)
ensureCSS('.theme-modern .refineUnread::before', {content: '"\u{1F4E9}"', fontSize: '1rem', lineHeight: '1'})
ensureCSS('.theme-modern .refineRead::before', {content: '"\u{1F4D6}"', fontSize: '1rem', lineHeight: '1'})
ensureCSS('.theme-modern .refineAttachments::before', {content: '"\u{1F4CE}"', fontSize: '1rem', lineHeight: '1'})
ensureCSS('.theme-modern .refineClear::before', {content: '"✕"', fontSize: '1rem', lineHeight: '1'})
ensureCSS('.theme-modern .refineLabel::before', {content: '"\u{1F3F7}"', fontSize: '1rem', lineHeight: '1'})

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
}
const styleClasses = {
	// For quoted text, with multiple levels of indentations.
	quoted: [
		css('quoted1', {color: styles.quoted1Color}),
		css('quoted2', {color: styles.quoted2Color}),
		css('quoted3', {color: styles.quoted3Color}),
	],
	// When text switches between unicode scripts.
	scriptswitch: css('scriptswitch', {textDecoration: 'underline 2px', textDecorationColor: styles.scriptSwitchUnderlineColor}),
	textMild: css('textMild', {color: styles.colorMild}),
	// For keywords (also known as flags/labels/tags) on messages.
	keyword: css('keyword', {padding: '0 .15em', borderRadius: '.15em', fontWeight: 'normal', fontSize: '.9em', margin: '0 .15em', whiteSpace: 'nowrap', background: styles.highlightBackground, color: styles.color, border: '1px solid', borderColor: styles.highlightBorderColor}),
	msgHeaders: css('msgHeaders', {marginBottom: '1ex', width: '100%'}),
}

ensureCSS('.msgHeaders td', {wordBreak: 'break-word'}) // Prevent horizontal scroll bar for long header values.
ensureCSS('.keyword.keywordCollapsed', {opacity: .75}),

// Generic styling.
ensureCSS('html', {backgroundColor: 'var(--backgroundColor)', color: 'var(--color)'})
ensureCSS('*', {fontSize: 'inherit', fontFamily: "'ubuntu', 'lato', sans-serif", margin: 0, padding: 0, boxSizing: 'border-box'})
ensureCSS('.mono, .mono *', {fontFamily: "'ubuntu mono', monospace"})
ensureCSS('table td, table th', {padding: '.15em .25em'})
ensureCSS('.pad', {padding: '.5em'})
ensureCSS('iframe', {border: 0})
ensureCSS('img, embed, video, iframe', {backgroundColor: 'white', color: 'black'})
ensureCSS('a', {color: styles.linkColor})
ensureCSS('a:visited', {color: styles.linkVisitedColor})

// For message view with multiple inline elements (often a single text and multiple messages).
ensureCSS('.textmulti > *:nth-child(even)', {backgroundColor: ['#f4f4f4', '#141414']})
ensureCSS('.textmulti > *', {padding: '2ex .5em', margin: '-.5em' /* compensate pad */ })
ensureCSS('.textmulti > *:first-child', {padding: '.5em'})


// join elements in l with the results of calls to efn. efn can return
// HTMLElements, which cannot be inserted into the dom multiple times, hence the
// function.
const join = (l: any, efn: () => any): any[] => {
	const r: any[] = []
	const n = l.length
	for (let i = 0; i < n; i++) {
		r.push(l[i])
		if (i < n-1) {
			r.push(efn())
		}
	}
	return r
}

// From https://developer.mozilla.org/en-US/docs/Web/Media/Formats/Image_types
const imageTypes = [
	'image/avif',
	'image/webp',
	'image/gif',
	'image/png',
	'image/jpeg',
	'image/apng',
	'image/svg+xml',
]
const isImage = (a: api.Attachment) => imageTypes.includes((a.Part.MediaType + '/' + a.Part.MediaSubType).toLowerCase())

// addLinks turns a line of text into alternating strings and links. Links that
// would end with interpunction followed by whitespace are returned with that
// interpunction moved to the next string instead.
const addLinks = (text: string): (HTMLAnchorElement | string)[] => {
	// todo: look at ../rfc/3986 and fix up regexp. we should probably accept utf-8.
	const re = RegExp('(?:(http|https):\/\/|mailto:)([:%0-9a-zA-Z._~!$&\'/()*+,;=-]+@)?([\\[\\]0-9a-zA-Z.-]+)(:[0-9]+)?([:@%0-9a-zA-Z._~!$&\'/()*+,;=-]*)(\\?[:@%0-9a-zA-Z._~!$&\'/()*+,;=?-]*)?(#[:@%0-9a-zA-Z._~!$&\'/()*+,;=?-]*)?')
	const r = []
	while (text.length > 0) {
		const l = re.exec(text)
		if (!l) {
			r.push(text)
			break
		}
		let s = text.substring(0, l.index)
		let url = l[0]
		text = text.substring(l.index+url.length)
		r.push(s)
		// If URL ends with interpunction, and next character is whitespace or end, don't
		// include the interpunction in the URL.
		if (!text || /^[ \t\r\n]/.test(text)) {
			if (/[)>][!,.:;?]$/.test(url)) {
				text = url.substring(url.length-2)+text
				url = url.substring(0, url.length-2)
			} else if (/[)>!,.:;?]$/.test(url)) {
				text = url.substring(url.length-1)+text
				url = url.substring(0, url.length-1)
			}
		}
		r.push(dom.a(url, attr.href(url), url.startsWith('mailto:') ? [] : [attr.target('_blank'), attr.rel('noopener noreferrer')]))
	}
	return r
}

// renderText turns text into a renderable element with ">" interpreted as quoted
// text (with different levels), and URLs replaced by links.
const renderText = (text: string): HTMLElement => {
	return dom.div(text.split('\n').map(line => {
		let q = 0
		for (const c of line) {
			if (c == '>') {
				q++
			} else if (c !== ' ') {
				break
			}
		}

		if (q == 0) {
			return [addLinks(line), '\n']
		}
		return dom.div(styleClasses.quoted[q%styleClasses.quoted.length], addLinks(line))
	}))
}

const displayName = (s: string) => {
	// ../rfc/5322:1216
	// ../rfc/5322:1270
	// todo: need support for group addresses (eg "undisclosed recipients").
	// ../rfc/5322:697
	const specials = /[()<>\[\]:;@\\,."]/
	if (specials.test(s)) {
		return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
	}
	return s
}

const formatDomain = (dom: api.Domain) => dom.Unicode || dom.ASCII

// format an address with both name and email address.
const formatAddress = (a: api.MessageAddress): string => {
	let s = '<' + a.User + '@' + formatDomain(a.Domain) + '>'
	if (a.Name) {
		s = displayName(a.Name) + ' ' + s
	}
	return s
}

// Like formatAddress, but returns an element with a title (for hover) with the ASCII domain, in case of IDN.
const formatAddressElem = (a: api.MessageAddress): string | HTMLElement => {
	if (!a.Domain.Unicode) {
		return formatAddress(a)
	}
	return dom.span(a.Name ? [displayName(a.Name), ' '] : '', '<', a.User, '@', dom.span(attr.title(a.Domain.ASCII), formatDomain(a.Domain)), '>')
}

// like formatAddress, but underline domain with dmarc-like validation if appropriate.
const formatAddressValidated = (a: api.MessageAddress, m: api.Message, use: boolean): (string | HTMLElement)[] => {
	const domainText = (domstr: string, ascii: string): HTMLElement | string => {
		if (!use) {
			return domstr
		}
		const extra = domstr === ascii ? '' : '; domain '+ascii
		// We want to show how "approved" this message is given the message From's domain.
		// We have MsgFromValidation available. It's not the greatest, being a mix of
		// potential strict validations, actual DMARC policy validation, potential relaxed
		// validation, but no explicit fail or (temporary) errors. We also don't know if
		// historic messages were from a mailing list. We could add a heuristic based on
		// List-Id headers, but it would be unreliable...
		// todo: add field to Message with the exact results.
		let name = ''
		let color = ''
		let title = ''
		switch (m.MsgFromValidation) {
		case api.Validation.ValidationStrict:
			name = 'Strict'
			color = styles.underlineGreen
			title = 'Message would have matched a strict DMARC policy.'
			break
		case api.Validation.ValidationDMARC:
			name = 'DMARC'
			color = styles.underlineGreen
			title = 'Message matched DMARC policy of domain.'
			break
		case api.Validation.ValidationRelaxed:
			name = 'Relaxed'
			color = styles.underlineGreen
			title = 'Domain did not have a DMARC policy, but message would match a relaxed policy if it had existed.'
			break;
		case api.Validation.ValidationNone:
			if (m.IsForward || m.IsMailingList) {
				name = 'Forwardlist'
				color = styles.underlineBlue
				title = 'Message would not pass DMARC policy, but came in through a configured mailing list or forwarding address.'
			} else {
				name = 'Bad'
				color = styles.underlineRed
				title = 'Either domain did not have a DMARC policy, or message did not adhere to it.'
			}
			break;
		default:
			// Also for zero value, when unknown. E.g. for sent messages added with IMAP.
			name = 'Unknown'
			title = 'Unknown DMARC verification result.'
			return dom.span(attr.title(title+extra), domstr)
		}
		return dom.span(attr.title(title+extra), css('addressValidation'+name, {borderBottom: '1.5px solid', borderBottomColor: color, textDecoration: 'none'}), domstr)
	}

	let l: (string | HTMLElement)[] = []
	if (a.Name) {
		l.push(a.Name + ' ')
	}
	l.push('<' + a.User + '@')
	l.push(domainText(formatDomain(a.Domain), a.Domain.ASCII))
	l.push('>')
	return l
}

// format just the name if present and it doesn't look like an address, or otherwise just the email address.
const formatAddressShort = (a: api.MessageAddress, junk: boolean): string => {
	const n = a.Name
	if (!junk && n && !n.includes('<') && !n.includes('@') && !n.includes('>')) {
		return n
	}
	return '<' + a.User + '@' + formatDomain(a.Domain) + '>'
}

// return just the email address.
const formatEmail = (a: api.MessageAddress) => a.User + '@' + formatDomain(a.Domain)

const equalAddress = (a: api.MessageAddress, b: api.MessageAddress) => {
	return (!a.User || !b.User || a.User === b.User) && a.Domain.ASCII === b.Domain.ASCII
}

const addressList = (allAddrs: boolean, l: api.MessageAddress[]) => {
	if (l.length <= 5 || allAddrs) {
		return dom.span(join(l.map(a => formatAddressElem(a)), () => ', '))
	}
	let elem = dom.span(
		join(
			l.slice(0, 4).map(a => formatAddressElem(a)),
			() => ', '
		),
		' ',
		dom.clickbutton('More...', attr.title('More addresses:\n'+l.slice(4).map(a => formatAddress(a)).join(',\n')), function click() {
			const nelem = dom.span(
				join(l.map(a => formatAddressElem(a)), () => ', '),
				' ',
				dom.clickbutton('Less...', function click() {
					elem.replaceWith(addressList(allAddrs, l))
				}),
			)
			elem.replaceWith(nelem)
			elem = nelem
		})
	)
	return elem
}

// loadMsgheaderView loads the common message headers into msgheaderelem.
// if refineKeyword is set, labels are shown and a click causes a call to
// refineKeyword.
const loadMsgheaderView = (msgheaderelem: HTMLTableSectionElement, mi: api.MessageItem, moreHeaders: string[], refineKeyword: null | ((kw: string) => Promise<void>), allAddrs: boolean) => {
	const msgenv = mi.Envelope
	const received = mi.Message.Received
	const receivedlocal = new Date(received.getTime())
	// Similar to webmail.ts:/headerTextMildStyle
	const msgHeaderFieldStyle = css('msgHeaderField', {textAlign: 'right', color: styles.colorMild, whiteSpace: 'nowrap'})
	const msgAttrStyle = css('msgAttr', {padding: '0px 0.15em', fontSize: '.9em'})
	dom._kids(msgheaderelem,
		// todo: make addresses clickable, start search (keep current mailbox if any)
		dom.tr(
			dom.td('From:', msgHeaderFieldStyle),
			dom.td(
				style({width: '100%'}),
				dom.div(css('msgFromReceivedSpread', {display: 'flex', justifyContent: 'space-between'}),
					dom.div(join((msgenv.From || []).map(a => formatAddressValidated(a, mi.Message, !!msgenv.From && msgenv.From.length === 1)), () => ', ')),
					dom.div(
						attr.title('Received: ' + received.toString() + ';\nDate header in message: ' + (msgenv.Date ? msgenv.Date.toString() : '(missing/invalid)')),
						receivedlocal.toDateString() + ' ' + receivedlocal.toTimeString().split(' ')[0],
					),
				)
			),
		),
		(msgenv.ReplyTo || []).length === 0 ? [] : dom.tr(
			dom.td('Reply-To:', msgHeaderFieldStyle),
			dom.td(join((msgenv.ReplyTo || []).map(a => formatAddressElem(a)), () => ', ')),
		),
		dom.tr(
			dom.td('To:', msgHeaderFieldStyle),
			dom.td(addressList(allAddrs, msgenv.To || [])),
		),
		(msgenv.CC || []).length === 0 ? [] : dom.tr(
			dom.td('Cc:', msgHeaderFieldStyle),
			dom.td(addressList(allAddrs, msgenv.CC || [])),
		),
		(msgenv.BCC || []).length === 0 ? [] : dom.tr(
			dom.td('Bcc:', msgHeaderFieldStyle),
			dom.td(addressList(allAddrs, msgenv.BCC || [])),
		),
		dom.tr(
			dom.td('Subject:', msgHeaderFieldStyle),
			dom.td(
				dom.div(css('msgSubjectAttrsSpread', {display: 'flex', justifyContent: 'space-between'}),
					dom.div(msgenv.Subject || ''),
					dom.div(
						mi.Message.IsForward ? dom.span(msgAttrStyle, 'Forwarded', attr.title('Message came in from a forwarded address. Some message authentication policies, like DMARC, were not evaluated.')) : [],
						mi.Message.IsMailingList ? dom.span(msgAttrStyle, 'Mailing list', attr.title('Message was received from a mailing list. Some message authentication policies, like DMARC, were not evaluated.')) : [],
						mi.Message.ReceivedTLSVersion === 1 ? dom.span(msgAttrStyle, css('msgAttrNoTLS', {borderBottom: '1.5px solid', borderBottomColor: styles.underlineRed}), 'Without TLS', attr.title('Message received (last hop) without TLS.')) : [],
						mi.Message.ReceivedTLSVersion > 1 && !mi.Message.ReceivedRequireTLS ? dom.span(msgAttrStyle, css('msgAttrTLS', {borderBottom: '1.5px solid', borderBottomColor: styles.underlineGreen}), 'With TLS', attr.title('Message received (last hop) with TLS.')) : [],
						mi.Message.ReceivedRequireTLS ? dom.span(css('msgAttrRequireTLS', {padding: '.1em .3em', fontSize: '.9em', backgroundColor: styles.successBackground, border: '1px solid', borderColor: styles.borderColor, borderRadius: '3px'}), 'With RequireTLS', attr.title('Transported with RequireTLS, ensuring TLS along the entire delivery path from sender to recipient, with TLS certificate verification through MTA-STS and/or DANE.')) : [],
						mi.IsSigned ? dom.span(msgAttrStyle, css('msgAttrSigned', {backgroundColor: styles.colorMild, color: styles.backgroundColorMild, borderRadius: '.15em'}), 'Message has a signature') : [],
						mi.IsEncrypted ? dom.span(msgAttrStyle, css('msgAttrEncrypted', {backgroundColor: styles.colorMild, color: styles.backgroundColorMild, borderRadius: '.15em'}), 'Message is encrypted') : [],
						refineKeyword ? (mi.Message.Keywords || []).map(kw =>
							dom.clickbutton(styleClasses.keyword, dom._class('keywordButton'), kw, async function click() {
								await refineKeyword(kw)
							}),
						) : [],
					),
				)
			),
		),
		(mi.MoreHeaders || []).map(t =>
			dom.tr(
				dom.td(t![0]+':', msgHeaderFieldStyle),
				dom.td(t![1]),
			),
		),
		// Ensure width of all possible additional headers is taken into account, to
		// prevent different layout between messages when not all headers are present.
		dom.tr(
			dom.td(moreHeaders.map(s => dom.div(s+':', msgHeaderFieldStyle, style({visibility: 'hidden', height: 0})))),
			dom.td(),
		),
	)
}
