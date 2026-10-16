package vulnetix.rules.vnx_node_012

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-012",
	"name": "Client-side XSS via innerHTML or v-html",
	"description": "Raw HTML written into the page from a value an attacker can shape. Sinks: jQuery $(...).html(value), Vue v-html and Svelte {@html value} in every file, and insertAdjacentHTML(position, html), document.write/writeln and React dangerouslySetInnerHTML={{ __html: value }} in HTML and template pages and Vue/Svelte components. Each sink is reported once, by its owner: an assignment to innerHTML/outerHTML is reported by VNX-NODE-027, and insertAdjacentHTML, document.write and dangerouslySetInnerHTML in a JavaScript/TypeScript file by VNX-NODE-005, not here. Reported when the value (1) reads a DOM source (location.hash/search/href/pathname, document.URL/referrer/cookie/documentURI, window.name, URLSearchParams, localStorage/sessionStorage.getItem, a message event's .data, an input's .value) directly or through a variable assigned from one in the 20 lines above (two hops), (2) builds markup by splicing a non-literal into an HTML string ('<p>' + res.message + '</p>', `<li>${todo.title}</li>`), directly or in a variable assigned a few lines above, (3) is a property of a response object (res/response/data/json/result/body/payload), or (4) for v-html, dangerouslySetInnerHTML and {@html}, is any non-constant expression. Not reported: string literals and literal-only concatenation, a ternary between literals, a value passed through DOMPurify/sanitize/escape/encode/xss helpers, the jQuery .html() getter, textContent/innerText, comments and string literals, minified files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-012/",
	"languages": ["node", "html"],
	"severity": "high",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xss", "dom", "client-side"],
}

_msg := "Untrusted data written into the DOM as HTML (cross-site scripting): markup or script in it runs in the user's session. Use textContent or framework bindings, or pass the value through DOMPurify.sanitize first"

_is_target(path) if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".html", ".htm", ".erb", ".ejs", ".hbs", ".njk"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_file_gate := `insertAdjacentHTML|document\.write|\.html\s*\(|v-html|dangerouslySetInnerHTML|\{@html`

_src := `\blocation\.(?:hash|search|href|pathname)\b|\bdocument\.(?:URL|documentURI|referrer|cookie|baseURI)\b|\bwindow\.name\b|\bURLSearchParams\b|\b(?:localStorage|sessionStorage)\.getItem\s*\(|\b(?:event|evt|e|ev|msg|message)\.data\b`

_sanitized := `(?i)sanitize|purify|escape|encode|\bxss\s*\(|filterxss|\bhe\.|\.text\s*\(\s*\)|textcontent|innertext`

_response_value := `^\s*(?:res|resp|response|data|json|result|results|body|payload)(?:\.[\w$]+|\[[^\]]+\])+\s*;?\s*$`

# A quoted string holding ${ is the inside of a template literal (`a '${x}'`)
# and is kept, so the interpolation stays visible.
_blank(s) := regex.replace(s, `'(?:[^'\\$]|\\.|\$[^{'])*'|"(?:[^"\\$]|\\.|\$[^{"])*"`, "''")

_opens(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The call's text after its opening parenthesis, continued over at most six
# further lines while its parentheses are open.
_call_text(lines, i, rest) := rest if _opens(rest) < 0

_call_text(lines, i, rest) := t if {
	_opens(rest) >= 0
	last := min([count(lines) - 1, i + 6])
	last >= i + 1
	t := concat(" ", array.concat([rest], array.slice(lines, i + 1, last + 1)))
}

_call_text(lines, i, rest) := rest if {
	_opens(rest) >= 0
	i + 1 > count(lines) - 1
}

# The first top-level argument; strings, template literals and bracketed
# groups (two levels deep) are taken whole.
_arg_re := "^(?:'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`(?:[^`\\\\]|\\\\.)*`|\\((?:[^()]|\\([^()]*\\))*\\)|\\[(?:[^\\[\\]]|\\[[^\\[\\]]*\\])*\\]|\\{(?:[^{}]|\\{[^{}]*\\})*\\}|[^,()\\[\\]{}'\"`])*"

_first_arg(t) := regex.find_n(_arg_re, trim_left(t, " \t"), 1)[0]

_refs(text, names) if {
	some n in names
	contains(text, n)
	regex.match(concat("", [`(?:^|[^\w.$])`, n, `(?:\s*$|\s*[^\s:\w$])`]), text)
}

# Names assigned from a DOM source in the 20 lines above, and one further hop
# (params = new URLSearchParams(location.search); q = params.get('q')).
_tainted(lines, i) := t if {
	t1 := helpers.tainted_names(lines, i, 20, _src)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 20]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		_refs(l, t1)
		v := helpers.assigned_first(l)
	}
	t := t1 | t2
}

# The expression parts of a value: everything outside string and template
# literals, plus the ${...} interpolations of its template literals.
_exprs(v) := concat(" ", array.concat(
	[regex.replace(_blank(regex.replace(v, "`[^`]*`", "''")), `''`, "")],
	[m[1] | some m in regex.find_all_string_submatch_n(`\$\{([^}]*)\}`, v, -1)],
))

# No identifier in any expression part, other than an UPPER_CASE constant
# (LOGO_SVG): the value is constant.
_constant(v) if not regex.match(`[A-Za-z_$]`, regex.replace(_exprs(v), `\b[A-Z][A-Z0-9_]*[A-Z0-9]\b`, ""))

# Sanitiser and encoder calls replaced by an empty literal, so a value that
# encodes one part (encodeURIComponent(q)) and splices the raw value into
# another is still seen. unescape() decodes and is not one of them.
_strip(v) := regex.replace(
	regex.replace(v, `\bunescape\s*\(`, "decodeURIComponent("),
	`(?i)[\w$.]*(?:sanitize|purify|escape|encode|xss)[\w$]*\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`,
	"''",
)

# cond ? 'literal' : 'literal' writes one of two constants.
_literal_choice(v) if regex.match("^[^?]+\\?\\s*(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\\s*:\\s*(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\\s*;?\\s*$", v)

# The line with template literals and then strings blanked, so a sink spelled
# inside either is not a call.
_code(line) := _blank(regex.replace(line, "`[^`]*`", "``"))

# Bundled library copies are not the project's code.
_third_party(path) if regex.match(`(^|/)(vendors?|third[-_]?party|bower_components|node_modules|dist|libs|plugins)/`, path)

_third_party(path) if regex.match(`(?i)(^|/)[^/]*(jquery|bootstrap|angular|prototype|mootools|html5shiv|modernizr|wysihtml|lte-ie7)[^/]*\.js$`, path)

_third_party(path) if regex.match(`(^|/)[A-Za-z][\w.-]*-v?\d+\.\d+(\.\d+)?(-min)?\.js$|[.-]min\.js$|\.bundle\.js$`, path)

# Markup in a literal, with a non-literal spliced in by + or ${...}.
_builds_markup(v) if {
	regex.match("['\"`][^'\"`]*<[A-Za-z/!]", v)
	regex.match("\\$\\{|\\+", v)
	regex.match(`[A-Za-z_$]`, _exprs(v))
}

# A variable assigned such markup in the 10 lines above.
_markup_var(v, lines, i) if {
	i > 0
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_$][\w$]*)\s*;?\s*$`, v, 1)
	count(m) > 0
	name := m[0][1]
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	contains(l, name)
	not helpers.is_comment_line(l)
	helpers.assigned_first(l) == name
	rhs := substring(l, indexof(l, "=") + 1, -1)
	_builds_markup(rhs)
	not regex.match(_sanitized, rhs)
}

_dangerous(v, _, _, _) if regex.match(_src, v)

_dangerous(v, lines, i, _) if _refs(v, _tainted(lines, i))

_dangerous(v, _, _, _) if _builds_markup(v)

_dangerous(v, lines, i, _) if _markup_var(v, lines, i)

_dangerous(v, _, _, _) if regex.match(_response_value, v)

_dangerous(v, _, _, "raw") if not _constant(v)

# ── Sink values ──────────────────────────────────────────────────────────

_value2(line, lines, i) := [v, "dom"] if {
	regex.match(`\.insertAdjacentHTML\s*\(`, _code(line))
	parts := regex.split(`\.insertAdjacentHTML\s*\(`, line)
	t := _call_text(lines, i, concat(" ", array.slice(parts, 1, count(parts))))
	first := _first_arg(t)
	after := trim_left(substring(trim_left(t, " \t"), count(first), -1), " \t,")
	v := _first_arg(after)
}

_value3(line, lines, i) := [v, "dom"] if {
	regex.match(`\bdocument\.write(?:ln)?\s*\(`, _code(line))
	parts := regex.split(`\bdocument\.write(?:ln)?\s*\(`, line)
	v := _first_arg(_call_text(lines, i, concat(" ", array.slice(parts, 1, count(parts)))))
}

_jq_re := `(?:\$|\bjQuery)(?:\([^)]*\))?(?:\.[\w$]+(?:\([^)]*\))?)*\.html\s*\(`

_value4(line, lines, i) := [v, "dom"] if {
	regex.match(_jq_re, _code(line))
	parts := regex.split(`\.html\s*\(`, line)
	v := _first_arg(_call_text(lines, i, concat(" ", array.slice(parts, 1, count(parts)))))
}

_value5(line, _, _) := [v, "raw"] if {
	m := regex.find_all_string_submatch_n(`\bv-html\s*=\s*"([^"]*)"`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_value6(line, _, _) := [v, "raw"] if {
	m := regex.find_all_string_submatch_n(`dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(.*?)\s*\}\}`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_value7(line, _, _) := [v, "raw"] if {
	m := regex.find_all_string_submatch_n(`\{@html\s+([^}]*)\}`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# One line can hold more than one sink, so each kind is its own function.
# Each sink is reported once, by the rule that owns it: an innerHTML/outerHTML
# assignment by VNX-NODE-027 in every file type, and insertAdjacentHTML,
# document.write and dangerouslySetInnerHTML in a JavaScript/TypeScript file by
# VNX-NODE-005. This rule keeps jQuery .html(), v-html and {@html}, and the
# other sinks where VNX-NODE-005 does not look (inline scripts of HTML and
# template pages, Vue and Svelte components).
_values(path, line, lines, i) := (({p | p := _value4(line, lines, i)} | {p | p := _value5(line, lines, i)}) | {p | p := _value7(line, lines, i)}) if _js_file(path)

_values(path, line, lines, i) := (((({p | p := _value2(line, lines, i)} | {p | p := _value3(line, lines, i)}) | {p | p := _value4(line, lines, i)}) | {p | p := _value5(line, lines, i)}) | {p | p := _value6(line, lines, i)}) | {p | p := _value7(line, lines, i)} if not _js_file(path)

_js_file(path) if regex.match(`\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$`, path)

findings contains finding if {
	some path, content in input.file_contents
	_is_target(path)
	not _third_party(path)
	regex.match(_file_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_file_gate, line)
	not helpers.is_comment_line(line)
	some pair in _values(path, line, lines, i)
	v := _strip(pair[0])
	trim_space(v) != ""
	not regex.match(_sanitized, v)
	not _literal_choice(v)
	_dangerous(v, lines, i, pair[1])
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
