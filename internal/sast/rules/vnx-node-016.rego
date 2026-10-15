package vulnetix.rules.vnx_node_016

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-016",
	"name": "ReDoS via user-controlled regular expression",
	"description": "A regular expression is compiled from the incoming request: the pattern (first argument) of new RegExp(...) or RegExp(...), or the argument of String.prototype.match/matchAll (which compile a string argument as a pattern), is a req/request query, body, params, headers or cookies value, a Koa ctx.query/ctx.request.body value, or a variable assigned (or destructured) from one in the 25 lines above, directly or through one intermediate assignment such as '^' + prefix. A client can then send a pattern with catastrophic backtracking ((a+)+$) that blocks the event loop for every user. Not reported: patterns passed through an escape function (lodash escapeRegExp, escape-string-regexp, a .replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') in the lines above), the linear-time RE2 engine, regex literals, patterns from configuration or constants, String.replace/split/includes (a string argument there is matched literally), .search() (too often a search-client method), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-016/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1333],
	"capec": ["CAPEC-197"],
	"attack_technique": ["T1499.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["redos", "regex", "dos"],
}

_msg := "Regular expression compiled from request input (ReDoS): a pattern with catastrophic backtracking blocks the Node.js event loop. Escape the input (escapeRegExp) to match it literally, or use the linear-time re2 engine"

_is_js(path) if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies|payload)\b|\breq\.(?:param|get|header)\s*\(|\bctx\.(?:request\.)?(?:query|body|params|headers|querystring)\b`

_sinks := [
	`(?:^|[^\w$.])(?:new\s+)?RegExp\s*\(`,
	`\.(?:match|matchAll)\s*\(`,
]

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

_binding(item) := v if {
	lhs := trim_space(split(item, "=")[0])
	parts := split(lhs, ":")
	v := trim_left(trim_space(parts[count(parts) - 1]), ".")
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

_destructured(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	contains(l, "{")
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*(.*)$`, l, 1)
	count(m) > 0
	regex.match(_src, m[0][2])
	some item in split(m[0][1], ",")
	v := _binding(item)
}

# One further hop through an assignment that uses a tainted name, unless that
# assignment picks the value from a fixed list ([...].includes(x) ? x : y).
_tainted(lines, i) := t if {
	t1 := _direct(lines, i) | _destructured(lines, i)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 25]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		_refs(l, t1)
		v := helpers.assigned_first(l)
		not regex.match(`\]\s*\.includes\s*\(`, l)
	}
	t := t1 | t2
}

# Names assigned from a request value. A lookup keyed by one (a session
# fetched with req.cookies.token, a record found by req.params.id) returns
# server data, not the client's string.
_direct(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_src, l)
	not regex.match(_lookup_re, l)
	v := helpers.assigned_first(l)
}

_lookup_re := `=\s*(?:await\s+)?[\w.$?]+\.(?:get|findOne|findByPk|findById|findUnique|verify|decode|has)\(\s*(?:req|request|ctx)\b|=\s*[A-Z][A-Z0-9_]*\s*\[`

_reaches(a, _, _) if regex.match(_src, a)

_reaches(a, lines, i) if _refs(a, _tainted(lines, i))

_escaped(a) if regex.match(`(?i)escape|quote`, a)

_guard_re := `(?i)escape[-_]?(?:string[-_]?)?reg|\\\$&`

_guarded(lines, i) if regex.match(_guard_re, helpers.code_window(lines, i, 25, 0))

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	regex.match(`RegExp|\.match`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _blank(line)
	some sink in _sinks
	regex.match(sink, code)
	parts := regex.split(sink, code)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	t := _call_text(lines, i, rest)
	a := _first_arg(t)
	trim_space(a) != ""
	not startswith(trim_space(a), "/")
	not _escaped(a)
	_reaches(a, lines, i)
	not _guarded(lines, i)
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
