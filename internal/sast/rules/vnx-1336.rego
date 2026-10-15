# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1336

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1336",
	"name": "Server-side template injection: template source built from request data",
	"description": "Request data becomes the SOURCE of a template that is then compiled, so an attacker can write template expressions that the engine evaluates on the server (server-side template injection, often remote code execution). Reported when the template-source argument (the first argument) reads the request directly or names a variable assigned from it, or from a string built from it (f-string, concatenation, format), within 30 lines above: Python flask render_template_string, Jinja2 Environment.from_string and jinja2.Template, Django Template and engines[...].from_string, Mako Template; Node.js Handlebars.compile, ejs.render/compile, pug.render/compile, nunjucks renderString, lodash _.template and doT.template. Sources: Flask/Django request.args/form/values/json/get_json/data/cookies/headers/GET/POST, Express/Koa req.body/query/params/headers/cookies and ctx.request.body/ctx.query. Not reported: a literal template with request data passed only as render context, templates loaded from files (render_template, res.render, get_template, a template read from disk), Python's string.Template, from_string on a Jinja2 SandboxedEnvironment (the documented mitigation, inline or through a name assigned one in the same file), comments and docstrings. Templates built from stored data (a database value) are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1336/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1336],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["template-injection", "ssti", "rce", "cwe-1336"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if {
	some ext in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_source := {
	"python": `\brequest\.(?:args|form|values|json|data|get_json|cookies|headers|GET|POST|body|query_params|files)\b`,
	"node": `\b(?:req|request)\.(?:body|query|params|headers|cookies)\b|\bctx\.(?:request\.(?:body|query)|query|params)\b`,
}

_fixed_sink := {
	"python": `(?:\brender_template_string|\.from_string|\bjinja2\.Template|\bmako\.template\.Template|\bdjango\.template\.Template)\s*\(`,
	"node": `(?:\b(?:Handlebars|handlebars|hbs)\.(?:compile|precompile)|\bejs\.(?:render|compile)|\bpug\.(?:render|compile)|\b(?:nunjucks|env|nunjucksEnv)\.renderString|\b(?:_|lodash)\.template|\bdoT\.template)\s*\(`,
}

_gate := {
	"python": ["render_template_string", "from_string", "Template"],
	"node": [".compile", ".render", "renderString", ".template", "precompile"],
}

# Names under which jinja2 / django / mako Template is imported in this file.
_template_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`from\s+(?:jinja2|django\.template|mako\.template)\s+import\s+\(?([^\n#)]+)`, content, -1)
	some item in split(m[1], ",")
	parts := regex.split(`\s+as\s+`, trim_space(item))
	parts[0] == "Template"
	n := trim_space(parts[count(parts) - 1])
	n != ""
}

_sink_re("python", content) := re if {
	names := _template_names(content)
	count(names) > 0
	re := concat("", [`(?:`, _fixed_sink.python, `|(?:^|[^\w.])(?:`, concat("|", names), `)\s*\()`])
}

_sink_re("python", content) := _fixed_sink.python if count(_template_names(content)) == 0

_sink_re("node", _) := _fixed_sink.node

# Non-interpolating string literals are text, not data flow. Python f-strings
# and JS template literals are kept: what they interpolate is the template.
_strip_strings("python", s) := regex.replace(s, `(^|[^fFrRbB\w])(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')`, `$1""`)

_strip_strings("node", s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# The first argument of the call: up to the first comma outside parentheses.
_first_arg(rest) := a if {
	m := regex.find_all_string_submatch_n(`^\s*((?:[^,()]|\((?:[^()]|\([^()]*\))*\))*)`, rest, 1)
	a := m[0][1]
}

# The call's argument text: the rest of the line, or the next code line when
# the call breaks right after its opening parenthesis.
_arg_text(lines, i, line, sink_re) := t if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:`, sink_re, `)(.*)$`]), line, 1)
	rest := m[0][1]
	trim_space(rest) != ""
	t := _first_arg(rest)
}

_arg_text(lines, i, line, sink_re) := t if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:`, sink_re, `)(.*)$`]), line, 1)
	trim_space(m[0][1]) == ""
	j := helpers.next_code_index(lines, i, 3)
	t := _first_arg(lines[j])
}

_word(v) := concat("", [`(?:^|[^\w.$])`, v, `\b`])

# Destructuring: const { template } = req.body
_destructured(lines, i, src) := {n |
	some j in numbers.range(max([0, i - 30]), i - 1)
	l := lines[j]
	contains(l, "{")
	regex.match(src, l)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=`, l, 1)
	count(m) > 0
	some item in split(m[0][1], ",")
	parts := split(trim_space(item), ":")
	n := trim_space(regex.replace(parts[count(parts) - 1], `=.*$`, ""))
	regex.match(`^[A-Za-z_$][\w$]*$`, n)
}

_hop1(lines, i, src) := helpers.tainted_names(lines, i, 30, src) | _destructured(lines, i, src)

# One more hop: a name assigned from a line that uses a hop-1 name.
_hop2(lines, i, names) := {w |
	count(names) > 0
	some k in numbers.range(max([0, i - 30]), i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	some v in names
	contains(l, v)
	regex.match(_word(v), l)
	w := helpers.assigned_first(l)
	w != v
}

_tainted_arg(lang, _, _, arg) if regex.match(_source[lang], arg)

_tainted_arg(lang, lines, i, arg) if {
	h1 := _hop1(lines, i, _source[lang])
	names := h1 | _hop2(lines, i, h1)
	some v in names
	contains(arg, v)
	regex.match(_word(v), arg)
}

# Inside a Python triple-quoted docstring.
_in_docstring(lines, i) if {
	before := concat("\n", array.slice(lines, max([0, i - 200]), i))
	count(regex.find_all_string_submatch_n(`"""|'''`, before, -1)) % 2 == 1
}

# Jinja2's sandbox is the documented mitigation: from_string on a
# SandboxedEnvironment (inline or through a name assigned one) is not reported.
_sandboxed("python", content, line) if {
	contains(content, "SandboxedEnvironment")
	regex.match(`SandboxedEnvironment\s*\([^)]*\)\s*\.\s*from_string`, line)
}

_sandboxed("python", content, line) if {
	contains(content, "SandboxedEnvironment")
	some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*)\s*\.\s*from_string\s*\(`, line, 1)
	recv := m[1]
	regex.match(concat("", [`(?m)^\s*`, replace(recv, ".", `\.`), `\s*(?::[^=\n]*)?=\s*(?:[\w.]+\.)?(?:Immutable)?SandboxedEnvironment\s*\(`]), content)
}

_gated(lang, content) if {
	some g in _gate[lang]
	contains(content, g)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gated(lang, content)
	regex.match(_source[lang], content)
	sink_re := _sink_re(lang, content)
	regex.match(sink_re, content)
	lines := split(content, "\n")
	some i, line in lines
	_gated(lang, line)
	not helpers.is_comment_line(line)
	regex.match(sink_re, line)
	not _in_docstring(lines, i)
	not _sandboxed(lang, content, line)
	raw := _arg_text(lines, i, line, sink_re)
	arg := _strip_strings(lang, raw)
	_tainted_arg(lang, lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Template source is built from request data and then compiled: an attacker can inject template expressions that run on the server (SSTI). Keep the template constant or load it from a file, and pass user data only as render context",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
