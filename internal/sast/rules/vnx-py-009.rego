package vulnetix.rules.vnx_py_009

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-009",
	"name": "Jinja2 autoescape disabled",
	"description": "Template autoescaping is turned off, so values rendered into HTML are emitted verbatim and user data becomes cross-site scripting. Reported: autoescape=False (or None/0) as a keyword argument (jinja2.Environment, SandboxedEnvironment, jinja2.Template, Jinja2Templates and any multi-line call) or as an attribute assignment (app.jinja_env.autoescape = False); an \"autoescape\": False dict entry or subscript (Flask jinja_options, Django TEMPLATES OPTIONS); a jinja2 Environment/SandboxedEnvironment created with no autoescape argument at all (Jinja2 does not escape by default) in a file that imports a web framework or names an .html template; and {% autoescape false %} blocks in .html/.j2/.jinja templates. Not reported: autoescape=True, select_autoescape() or a function, an Environment built from **options or whose autoescape is assigned later in the file, Environments in non-web code (code generators rendering .py.j2), other libraries' Environment classes (aws_cdk), class and def lines, test files and test templates, comparisons (autoescape == False), and the text inside strings and comments. Individual |safe filters and Markup() calls are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-009/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xss", "jinja2", "template", "web"],
}

_disabled := `(?:False|None|0)\b`

# String literals are blanked before matching, so a log message or a help text
# naming autoescape=False is not a configuration. A quoted "autoescape" key is
# turned into a token first so the dict and subscript forms survive blanking.
_strip(line) := regex.replace(
	regex.replace(line, `["']autoescape["']`, "AUTOESC"),
	`"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'`,
	`""`,
)

_bal(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

# The text of the call that opens on line i, up to the line that closes it
# (at most 10 lines).
_call_text(lines, i) := txt if {
	head := _strip(lines[i])
	_bal(head) <= 0
	txt := head
}

_call_text(lines, i) := txt if {
	head := _strip(lines[i])
	_bal(head) > 0
	last := min([count(lines) - 1, i + 10])
	ends := [j |
		some j in numbers.range(i + 1, last)
		_bal(concat("\n", [_strip(lines[k]) | some k in numbers.range(i, j)])) <= 0
	]
	end := min(array.concat([last], ends))
	txt := concat("\n", [_strip(lines[k]) | some k in numbers.range(i, end)])
}

# autoescape=False as a keyword argument or an attribute assignment
# (app.jinja_env.autoescape = False), or as a dict entry / subscript
# ({"autoescape": False}, options["autoescape"] = False).
_explicit_off(code) if regex.match(concat("", [`(?:^|[^\w])autoescape\s*=\s*`, _disabled]), code)

_explicit_off(code) if regex.match(concat("", [`AUTOESC\s*(?::|\]\s*=)\s*`, _disabled]), code)

_py_web(content) if regex.match(`(?m)^\s*(?:from|import)\s+(?:flask|django|starlette|fastapi|aiohttp|bottle|tornado|pyramid|quart|sanic|falcon|werkzeug)\b`, content)

_py_web(content) if regex.match(`\.html?["']`, content)

# The Environment name is Jinja2's: jinja2.Environment(...), or imported from
# jinja2 under its own name.
_jinja_env_call(code, _) if regex.match(`(?:^|[^\w.])jinja2(?:\.sandbox)?\.(?:Sandboxed|ImmutableSandboxed)?Environment\s*\(`, code)

_jinja_env_call(code, content) if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])((?:Sandboxed|ImmutableSandboxed)?Environment)\s*\(`, code, 1)
	count(m) > 0
	name := m[0][1]
	regex.match(concat("", [`(?m)^\s*from\s+jinja2(?:\.sandbox)?\s+import\s+[^\n#]*\b`, name, `\b\s*(?:,|\)|$)`]), content)
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# A Python setting that turns autoescaping off.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "autoescape")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "autoescape")
	not helpers.is_comment_line(line)
	_explicit_off(_strip(line))
	finding := _finding(path, i, line, "Template autoescaping is disabled, so every value rendered into HTML is emitted verbatim and user data becomes cross-site scripting; use autoescape=True or select_autoescape() and mark trusted HTML with Markup explicitly")
}

# A Jinja2 Environment built without autoescape in a web application: Jinja2
# does not escape by default.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "Environment")
	regex.match(`(?m)^\s*(?:from\s+jinja2\b|import\s+jinja2\b)`, content)
	_py_web(content)
	not regex.match(`\.autoescape\s*=`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Environment")
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:class|def)\b`, line)
	code := _strip(line)
	_jinja_env_call(code, content)
	txt := _call_text(lines, i)
	not contains(txt, "autoescape")
	not contains(txt, "**")
	finding := _finding(path, i, line, "Jinja2 Environment created without autoescape: Jinja2 does not escape by default, so HTML templates rendered from it are open to cross-site scripting; pass autoescape=select_autoescape() (or True)")
}

# {% autoescape false %} in a Jinja2 or Django template.
findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(?:html?|j2|jinja2?|jinja-html|djhtml|tmpl)$`, path)
	not helpers.is_test_path(path)
	contains(content, "autoescape")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "autoescape")
	regex.match(`\{%-?\s*autoescape\s+(?:false|False|off)\s*-?%\}`, line)
	finding := _finding(path, i, line, "{% autoescape false %} turns escaping off for this block, so the values rendered inside it are emitted verbatim and user data becomes cross-site scripting; escape the values or mark only sanitised HTML as safe")
}
