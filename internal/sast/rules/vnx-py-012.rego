package vulnetix.rules.vnx_py_012

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-012",
	"name": "Python server-side template injection",
	"description": "Request data becomes the source text of a server-side template, so an attacker writes template code ({{ ... }}, {% ... %}) that the engine evaluates, which in Jinja2 and Mako reaches arbitrary Python execution. Reported: the template-source argument of Flask render_template_string(), a Jinja2 or Django env.from_string(), and jinja2/mako/django Template() is request data (request.args/form/values/GET/POST/json/get_json()/data/cookies/headers/...) directly, or a variable assigned from request data up to 30 lines above, or a parameter of the enclosing route handler (a def decorated with @app.route/@router.get or whose first parameter is request), or an f-string, % format, .format() or + concatenation of such a value (also through one intermediate template variable, and across the lines of a triple-quoted template). Not reported: a constant template with the user value passed as render context (render_template_string('<h1>{{ name }}</h1>', name=name)), render_template() with a template file, templates formatted only from untainted variables or ALL_CAPS constants, string.Template and other lookalikes (PromptTemplate), framework wrappers that forward their own parameter, and the pattern in comments and strings. Flows through helper functions or more than one intermediate variable are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-012/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [1336],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["ssti", "template-injection", "flask", "jinja2"],
}

# ── String handling ─────────────────────────────────────────────────────

_str_re := `[rRbBuU]{0,2}(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')`

_fstr_re := `(?:^|[^\w])[rR]?[fF][rR]?(?:"""[^{]*?\{[\s\S]*?"""|'''[^{]*?\{[\s\S]*?'''|"(?:[^"\\\n{]|\\.)*\{(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n{]|\\.)*\{(?:[^'\\\n]|\\.)*')`

_blank(s) := regex.replace(regex.replace(s, _fstr_re, " FSTR "), _str_re, " QSTR ")

_code(line) := regex.replace(regex.replace(line, _str_re, " QSTR "), `#.*$`, "")

_arg_re := `^(?:[rRbBuUfF]{0,2}(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\[(?:[^\[\]]|\[[^\[\]]*\])*\]|\{[^{}]*\}|[^,()\[\]{}"'])*`

_first_arg(after) := m[0] if {
	m := regex.find_n(_arg_re, after, 1)
	count(m) > 0
}

_dyn_shape(b) if contains(b, "FSTR")

_dyn_shape(b) if regex.match(`QSTR\s*%`, b)

_dyn_shape(b) if regex.match(`[\w\)\]]\s*%\s*[\w(\[]`, b)

_dyn_shape(b) if regex.match(`\.format\s*\(`, b)

_dyn_shape(b) if contains(b, "+")

_outside_ids(b) := {m[1] |
	cleaned := regex.replace(regex.replace(b, `QSTR|FSTR`, " "), `([A-Za-z_]\w*)\s*=[^=]`, " ")
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)(\s*\()?`, cleaned, -1)
	m[2] == ""
}

_interp_ids(raw) := {m[1] |
	some f in regex.find_all_string_submatch_n(_fstr_re, raw, -1)
	some inner in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, f[0], -1)
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)(\s*\()?`, regex.replace(inner[1], `![rsa]$|:[^}]*$`, ""), -1)
	m[2] == ""
}

_ids(raw) := _outside_ids(_blank(raw)) | _interp_ids(raw)

# ── Taint ───────────────────────────────────────────────────────────────

_source_re := `\brequest\.(?:args|form|values|GET|POST|data|json|get_json|cookies|headers|body|files|query_params|params|get_data|REQUEST|match_info|query|stream)\b`

_direct(raw) if regex.match(_source_re, _code(raw))

# Variables assigned from request data in the 30 lines above.
_tainted(lines, i) := {v |
	some j in numbers.range(max([0, i - 30]), i - 1)
	i > 0
	contains(lines[j], "request")
	not helpers.is_comment_line(lines[j])
	regex.match(_source_re, _code(lines[j]))
	v := helpers.assigned_first(lines[j])
}

# Parameters of the enclosing handler: a def decorated as a route, or a Django
# view whose first parameter is request.
_def_index(lines, i) := max(ds) if {
	ds := [j | some j in numbers.range(max([0, i - 40]), i); regex.match(`^\s*(?:async\s+)?def\s`, lines[j])]
	count(ds) > 0
}

_handler(lines, d) if {
	some k in numbers.range(max([0, d - 3]), d - 1)
	d > 0
	regex.match(`^\s*@[\w\.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(`, lines[k])
}

_handler(lines, d) if regex.match(`^\s*(?:async\s+)?def\s+\w+\s*\(\s*request\b`, lines[d])

_route_params(lines, i) := {p |
	d := _def_index(lines, i)
	_handler(lines, d)
	m := regex.find_all_string_submatch_n(`def\s+\w+\s*\(([^)]*)\)`, lines[d], 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	p := regex.replace(trim_space(part), `\s*[:=][\s\S]*$`, "")
	regex.match(`^[A-Za-z_]\w*$`, p)
	not p in {"self", "cls", "request", "req"}
}

_taint(lines, i) := _tainted(lines, i) | _route_params(lines, i)

_benign_id(x) if regex.match(`^[A-Z][A-Z0-9_]*$`, x)

# A template built from a tainted value: request data in it, or a tainted name
# formatted into it.
_built_from_taint(raw, _) if _direct(raw)

_built_from_taint(raw, taint) if {
	_dyn_shape(_blank(raw))
	some x in _ids(raw)
	x in taint
}

# ── Sinks ───────────────────────────────────────────────────────────────

_engine_import := `(?m)^\s*(?:from|import)\s+(?:jinja2|mako|django\.template|django\b[\w\.]*\s+import\s+[^\n]*\bTemplate|tornado\.template)`

_sink_re(content) := `(?:(?:^|[^\w.])render_template_string|\.from_string|(?:^|[^\w])Template)\s*\(` if regex.match(_engine_import, content)

_sink_re(content) := `(?:^|[^\w.])render_template_string\s*\(` if not regex.match(_engine_import, content)

_bal(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

_after(lines, i, sink) := pieces[1] if {
	joined := concat("\n", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 6]))])
	pieces := regex.split(sink, joined)
	count(pieces) > 1
}

_open(s) if _bal(_code(s)) > 0

_open(s) if count(regex.find_all_string_submatch_n(`"""|'''`, s, -1)) % 2 == 1

_rhs(lines, _, first) := first if not _open(first)

_rhs(lines, j, first) := txt if {
	_open(first)
	last := min([count(lines) - 1, j + 8])
	txt := concat("\n", array.concat([first], [lines[k] | some k in numbers.range(j + 1, last)]))
}

# The bare template variable was assigned from request data or built from a
# tainted value a few lines up.
_var_tainted(lines, i, v, taint) if v in taint

_var_tainted(lines, i, v, taint) if {
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], v)
	not helpers.is_comment_line(lines[j])
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, v, `\s*\+?=\s*([^=][\s\S]*)$`]), lines[j], 1)
	count(m) > 0
	_built_from_taint(_rhs(lines, j, m[0][1]), taint)
}

_reported(lines, i, arg) if _built_from_taint(arg, _taint(lines, i))

_reported(lines, i, arg) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*$`, arg, 1)
	count(m) > 0
	v := m[0][1]
	not _benign_id(v)
	_var_tainted(lines, i, v, _taint(lines, i))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?:render_template_string|from_string|Template)\s*\(`, content)
	sink := _sink_re(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`render_template_string|from_string|Template`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(sink, code)
	not regex.match(`\bstring\.Template\s*\(|^\s*(?:async\s+)?def\s`, code)
	after := _after(lines, i, sink)
	arg := _first_arg(after)
	_reported(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Request data is used as the template source, so an attacker can write template code that the engine executes (server-side template injection); render a fixed template and pass the user value as context instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
