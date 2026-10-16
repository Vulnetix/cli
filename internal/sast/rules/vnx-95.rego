# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_95

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-95",
	"name": "Template Injection (Eval Injection)",
	"description": "HTTP request data becomes the SOURCE of a server-side template, whose directives the engine then evaluates (Jinja2/Mako/ERB reach arbitrary code execution). Reported: the template-source (first) argument of Python Flask render_template_string, Jinja2 env.from_string, and jinja2/mako/django Template (bare only when imported from those packages, or an alias of that import); Node ejs render/compile, pug/jade render/compile/compileClient, Handlebars/hbs precompile/compile, nunjucks renderString/compile, lodash _.template, doT template, Mustache render, swig render/compile and Eta render/renderString; Ruby ERB.new, Erubi::Engine.new, Erubis::Eruby.new, Haml::Engine.new, Slim::Template.new, Tilt templates and Rails render inline:. The argument must be request data (Flask/Django request.args/form/values/json/data/GET/POST/cookies/headers, Express/Koa req or ctx query/body/params/headers/cookies, Rails params/cookies/request.body) directly, interpolated, concatenated, or through a variable assigned from it, or from such a variable, in the 25 lines above. Not reported: request data passed as template context (render_template(name, x=...), ejs.render(layout, {name}), ERB with binding over a constant template), templates loaded from files, Python string.Template (substitution only), names in comments or string literals. Flows through helper functions, collections or other files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-95/",
	"languages": ["node", "python", "ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [95],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["template-injection", "ssti", "eval-injection", "cwe-95"],
}

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "rb" if endswith(path, ".rb")

_gate := {
	"js": `ejs|pug|jade|andlebars|hbs|nunjucks|\.template\s*\(|Mustache|mustache|swig|[Ee]ta\.|renderString`,
	"py": `render_template_string|from_string|Template`,
	"rb": `ERB|Erubi|Haml|Slim::|Tilt::|inline:`,
}

_src := {
	"js": `\b(?:req|request)\.(?:query|body|params|headers|cookies|signedCookies)\b|\bctx\.(?:query|params|request\.body|request\.query)\b`,
	"py": `\brequest\.(?:args|form|values|json|get_json|data|cookies|headers|GET|POST|body|query_params|stream)\b`,
	"rb": `\bparams\b\s*(?:\[|\.(?:fetch|require|permit|dig|to_unsafe_h)\b)|\bcookies\s*\[|\brequest\.(?:body|params|query_string|raw_post|headers|cookies|GET|POST)\b`,
}

# Sink regexes, tested on the line with string literals blanked; the capture
# is read from the original line and is the text after the opening paren.
_sinks := {
	"js": [
		`\b(?:ejs|pug|jade|swig)\.(?:render|compile|compileClient)\s*\((.*)$`,
		`\b(?:Handlebars|handlebars|hbs|Hogan|hogan)\.(?:compile|precompile)\s*\((.*)$`,
		`\b(?:nunjucks|env|nunjucksEnv)\.(?:renderString|compile)\s*\((.*)$`,
		`(?:^|[^\w$.])(?:_|lodash|doT|dot)\.template\s*\((.*)$`,
		`\b(?:Mustache|mustache)\.render\s*\((.*)$`,
		`\b(?:Eta|eta)\.(?:render|renderString)\s*\((.*)$`,
	],
	"py": [
		`(?:^|[^\w.])render_template_string\s*\((.*)$`,
		`\.from_string\s*\((.*)$`,
		`\b(?:jinja2|mako\.template|django\.template)\.Template\s*\((.*)$`,
	],
	"rb": [
		`\b(?:ERB|Erubi::Engine|Erubis::Eruby|Erubis::EscapedEruby|Haml::Engine|Haml::Template|Slim::Template|Tilt::\w*Template)\.new\b\s*\(?(.*)$`,
		`\brender\s*\(?\s*inline:\s*(.*)$`,
	],
}

# Bare Template( in Python counts only when Template, or an alias of it, is
# imported from jinja2, mako.template or django.template.
_py_template_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+(?:jinja2|mako\.template|django\.template)\s+import\s+([^\n#]*)`, content, -1)
	some part in split(m[1], ",")
	p := trim_space(trim(part, "()"))
	_imports_template(p)
	n := _import_name(p)
}

_imports_template(p) if p == "Template"

_imports_template(p) if startswith(p, "Template ")

_import_name(p) := n if {
	ws := [w | some w in split(p, " "); w != ""]
	count(ws) == 3
	ws[1] == "as"
	n := ws[2]
}

_import_name(p) := "Template" if p == "Template"

_blank(line) := regex.replace(regex.replace(line, `"(?:\\.|[^"\\])*"`, `""`), `'(?:\\.|[^'\\])*'`, `''`)

_assign_re := `^\s*(?:(?:final|var|let|const|val|my|local)\s+)?(?:[A-Za-z_][\w<>\[\]\.?]*\s+)?\$?([A-Za-z_]\w*)\s*(?:,\s*\$?[A-Za-z_]\w*\s*)*(?::\s*[\w<>\[\]\|\. ]+?\s*)?(?::=|\.=|\+=|=)[^=~>]`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{\s*([A-Za-z_]\w*)`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_t1(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(src, l)
	not helpers.is_comment_line(l)
	v := _assigned(l)
}

# The second hop reads the assignment with non-interpolating literals blanked,
# so PAGE = "<h1>{{ name }}</h1>" does not take taint from a variable `name`.
_t2(lang, lines, i, n1) := {v |
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	v := _assigned(l)
	not v in n1
	some n in n1
	regex.match(concat("", [`=.*\b`, n, `\b`]), _strip(lang, l))
	not helpers.is_comment_line(l)
}

# A triple-quoted f-string assigned over several lines takes taint from any
# {expression} inside it that names a tainted variable.
_fblock(lines, j) := concat(" ", array.slice(lines, j, min(ends) + 1)) if {
	regex.match(`=\s*[fF][rR]?(?:"""|''')`, lines[j])
	ends := [k |
		some k in numbers.range(j + 1, min([j + 20, count(lines) - 1]))
		_closes(lines[k])
	]
	count(ends) > 0
}

_closes(l) if contains(l, `"""`)

_closes(l) if contains(l, "'''")

_t3(lang, lines, i, n1) := {v |
	lang == "py"
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	v := _assigned(lines[j])
	not v in n1
	some n in n1
	regex.match(concat("", [`\{[^}]*\b`, n, `\b`]), _fblock(lines, j))
}

_tainted(lang, lines, i, src, arg) if regex.match(src, arg)

_tainted(lang, lines, i, src, arg) if {
	not regex.match(src, arg)
	n1 := _t1(lines, i, src)
	names := (n1 | _t2(lang, lines, i, n1)) | _t3(lang, lines, i, n1)
	some n in names
	regex.match(concat("", [`\b`, n, `\b`]), arg)
}

# Text after the opening paren, or the next line when the call breaks there.
_arg_text(lines, i, rest) := rest if trim_space(rest) != ""

_arg_text(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

# The first argument: up to the first comma or closing paren at depth 0.
_depth(s) := ((strings.count(s, "(") + strings.count(s, "[")) + strings.count(s, "{")) - ((strings.count(s, ")") + strings.count(s, "]")) + strings.count(s, "}"))

_first_arg(s) := substring(s, 0, min(ends)) if {
	ends := [k |
		some k in numbers.range(0, count(s) - 1)
		substring(s, k, 1) in {",", ")"}
		_depth(substring(s, 0, k)) == 0
	]
	count(ends) > 0
}

_first_arg(s) := s if {
	ends := [k |
		some k in numbers.range(0, count(s) - 1)
		substring(s, k, 1) in {",", ")"}
		_depth(substring(s, 0, k)) == 0
	]
	count(ends) == 0
}

_sink_rests(lang, line, code, names) := {m[0][1] |
	some re in _sinks[lang]
	regex.match(re, code)
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
} | {m[0][1] |
	some n in names
	re := concat("", [`(?:^|[^\w.])`, n, `\s*\((.*)$`])
	regex.match(re, code)
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	src := _src[lang]
	regex.match(concat("", ["(?m)", src]), content)
	names := _names(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	some rest in _sink_rests(lang, line, _blank(line), names)
	arg := _first_arg(_arg_text(lines, i, rest))
	_tainted(lang, lines, i, src, _strip(lang, arg))
	finding := {
		"rule_id": metadata.id,
		"message": "Server-side template injection: request data is the template source, so its directives are evaluated on the server; load templates from files and pass request data only as context variables",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Literals that cannot interpolate are blanked before the taint test, so a
# context variable named inside "{{ name }}" is not the template source.
_strip("py", s) := regex.replace(s, `(^|[^\w])[rbuRBU]?("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`, `$1""`)

_strip("js", s) := regex.replace(s, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)

_strip("rb", s) := regex.replace(s, `'(?:\\.|[^'\\])*'|"(?:\\.|#[^{]|[^"\\#])*"`, `""`)

_names("py", content) := _py_template_names(content)

_names(lang, _) := set() if lang != "py"
