package vulnetix.rules.vnx_node_011

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-011",
	"name": "Node.js server-side template injection",
	"description": "A template engine compiles or renders a template SOURCE built from the incoming request: the first argument of ejs.render/compile, pug or jade render/compile/compileClient, Handlebars/hbs/Hogan compile/precompile, nunjucks renderString/compile (and Environment.renderString), lodash _.template, doT template/compile, Mustache.render, Eta/Squirrelly render/renderString/compile or swig render/compile is a req/request query, body, params, headers or cookies value, a Koa ctx.query/ctx.request.body value, or a variable assigned (or destructured) from one in the 25 lines above, directly or through one intermediate assignment such as 'Hello ' + name. Template directives in that source run on the server (RCE). Not reported: request values passed as the template's data or context (res.render('view', { q: req.query.q }), ejs.render(fileTemplate, { user: req.body })), renderFile and precompiled templates, constant template strings, comments and string literals. eval and new Function are VNX-NODE-002; a template source taken from the database (stored SSTI) or through helper functions is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-011/",
	"languages": ["node"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [1336],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["ssti", "template-injection", "ejs", "pug"],
}

_msg := "Template source built from request input (server-side template injection): template directives in it execute on the server. Load templates from files or constants and pass user values only as the render context"

_is_js(path) if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies|payload)\b|\breq\.(?:param|get|header)\s*\(|\bctx\.(?:request\.)?(?:query|body|params|headers|querystring)\b`

_sinks := [
	`(?:^|[^\w$.])(?:ejs|pug|jade)\.(?:render|compile|compileClient)\s*\(`,
	`(?:^|[^\w$.])(?:Handlebars|handlebars|hbs|Hogan|hogan)\.(?:compile|precompile)\s*\(`,
	`(?:^|[^\w$.])nunjucks\.(?:renderString|compile)\s*\(|\.renderString\s*\(`,
	`(?:^|[^\w$.])(?:_|lodash)\.template\s*\(`,
	`(?:^|[^\w$.])(?:doT|dot)\.(?:template|compile)\s*\(`,
	`(?:^|[^\w$.])(?:Mustache|mustache)\.render\s*\(`,
	`(?:^|[^\w$.])(?:Eta|eta|Sqrl|sqrl|squirrelly|swig)\.(?:render|renderString|compile)\s*\(`,
]

_file_gate := `ejs|pug|jade|andlebars|hbs|ogan|nunjucks|renderString|template|doT|dot|ustache|Eta|eta|Sqrl|squirrelly|swig`

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

_lookup_re := `=\s*(?:await\s+)?[\w.$?]+\.(?:get|findOne|findByPk|findById|findUnique|verify|decode|has)\(\s*(?:req|request|ctx)\b`

_reaches(a, _, _) if regex.match(_src, a)

_reaches(a, lines, i) if _refs(a, _tainted(lines, i))

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	regex.match(_file_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _blank(line)
	some sink in _sinks
	regex.match(sink, code)
	parts := regex.split(sink, line)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	t := _call_text(lines, i, rest)
	a := _first_arg(t)
	trim_space(a) != ""
	_reaches(a, lines, i)
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
