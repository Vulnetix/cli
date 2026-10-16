# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_213

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-213",
	"name": "Exposure of Sensitive Information Due to Incompatible Policies",
	"description": "A health, status, info or debug endpoint returns the whole process environment or application configuration. The developer's policy says the endpoint shows runtime facts; the operator's policy puts database passwords, API keys and signing secrets in exactly those environment variables and config entries, so the endpoint publishes them. CWE-213 is about conflicting policies, which no line of code shows; this rule reports the most concrete form of that conflict. Reported: JavaScript/TypeScript process.env passed whole (alone, inside an object or spread, or JSON.stringify(process.env)) to res.send/json/end/write/render, ctx.body or reply.send, directly or through a variable assigned from it; Python dict(os.environ), os.environ.copy()/.items(), os.environ, app.config/current_app.config (whole or .items()), settings.__dict__ or vars(settings) inside jsonify, JsonResponse, JSONResponse, HttpResponse, make_response, Response, render_template or self.wfile.write, or returned (bare or in a dict) from a function that a route decorator (@app.get, @router.post, @app.route, @api_view) exposes; Go os.Environ() encoded or written to the http.ResponseWriter or a gin context, through a variable assigned from it a few lines above, or by a range over os.Environ() that writes each entry with no filter (if/continue) in between; Java System.getenv() or System.getProperties() with no argument, directly or through a variable assigned from it, returned from a controller or servlet, or placed in ResponseEntity, a body, a model attribute or the response writer. Not reported: the environment returned from a function no route exposes (a config loader), an environment filtered to a prefix or allow-list before it is written (a Go range with an if/continue, a Python comprehension with an if), single variables (process.env.PORT, os.environ.get('X'), System.getenv(\"X\")), Object.keys(process.env), environments copied for subprocesses, Spring Actuator exposure (VNX-JAVA-002), phpinfo() (VNX-PHP-008), comments, strings and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-213/",
	"languages": ["go", "java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [213],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["policy", "exposure", "environment", "configuration", "cwe-213"],
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "The whole environment or application configuration is returned to the client: every secret held in an environment variable or config entry (database passwords, API keys, signing keys) is published. Return only the fields the endpoint is meant to show",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_ext(path, exts) if {
	some e in exts
	endswith(path, e)
}

_strip_q(s) := regex.replace(s, `"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'`, `""`)

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_file(path) if {
	_ext(path, {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
	not endswith(path, ".min.js")
}

_js_env := `\bprocess\.env\b\s*([,)}\]]|$)`

_js_sink := `\b(res|resp|response|reply)\s*(\.\s*(status|code)\s*\([^)]*\)\s*)?\.\s*(send|json|jsonp|end|write|render)\s*\(|\bctx\.body\s*=`

findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "process.env")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "process.env")
	not helpers.is_comment_line(line)
	code := regex.replace(_strip_q(line), `Object\.keys\s*\(\s*process\.env\s*\)`, "")
	regex.match(_js_env, code)
	regex.match(_js_sink, code)
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "process.env")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "process.env")
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\], ]+)?=\s*(\{\s*\.\.\.\s*process\.env\s*[,}]|process\.env\s*;?\s*$|Object\.assign\(\s*\{\s*\}\s*,\s*process\.env\s*\))`, al, 1)
	count(m) > 0
	v := m[0][1]
	some i in numbers.range(a + 1, min([count(lines) - 1, a + 6]))
	line := lines[i]
	not helpers.is_comment_line(line)
	regex.match(_js_sink, line)
	regex.match(concat("", [`\(\s*`, v, `\s*[,)]|[{,]\s*(\w+\s*:\s*)?`, v, `\s*[,}]|=\s*`, v, `\s*;?\s*$`]), line)
	f := _finding(path, i, line)
}

# ── Python ───────────────────────────────────────────────────────────────

_py_env := `\bdict\(\s*os\.environ\s*\)|\bos\.environ\.(copy|items)\(\s*\)|\bos\.environ\s*([,)}\]]|$)|\b(current_)?app\.config\.items\(\s*\)|\bdict\(\s*(current_)?app\.config\s*\)|\b(current_)?app\.config\s*([,)}\]]|$)|\bsettings\.__dict__|\bvars\(\s*settings\s*\)`

_py_sink := `\b(jsonify|JsonResponse|JSONResponse|HttpResponse|make_response|Response|PlainTextResponse|ORJSONResponse|render_template|json_response)\s*\(|\b(self\.)?wfile\.write\s*\(`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`os\.environ|app\.config|settings`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(_py_env, code)
	regex.match(_py_sink, code)
	not regex.match(_py_filtered, code)
	f := _finding(path, i, line)
}

# A comprehension that keeps only some entries: {k: v for k, v in
# os.environ.items() if k in PUBLIC}.
_py_filtered := `\bfor\b[^\n]*\bin\s+[\w.]+(\.items\(\s*\))?\s+if\b`

# FastAPI, Flask and DRF views may return a dict: `return dict(os.environ)`
# in a function that a route decorator (up to eight lines above) exposes.
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`os\.environ|app\.config|settings`, content)
	regex.match(`(?m)^\s*@\w+(\.\w+)*\.(get|post|put|patch|delete|route|api_route)\s*\(|(?m)^\s*@api_view\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "return")
	regex.match(`^\s*return\b`, line)
	code := _strip_q(line)
	regex.match(_py_env, code)
	not regex.match(_py_sink, code)
	not regex.match(_py_filtered, code)
	_py_route_above(lines, i)
	f := _finding(path, i, line)
}

_py_route_above(lines, i) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	regex.match(`^\s*@\w+(\.\w+)*\.(get|post|put|patch|delete|route|api_route)\s*\(|^\s*@api_view\b`, lines[j])
	not _def_between(lines, j, i)
}

# Another function definition between the decorator and the return: the
# decorator belongs to a different function.
_def_between(lines, j, i) if {
	defs := [k |
		some k in helpers.span(j + 1, i - 1)
		k > j
		k < i
		regex.match(`^\s*(async\s+)?def\s`, lines[k])
	]
	count(defs) > 1
}

# ── Go ───────────────────────────────────────────────────────────────────

_go_sink := `\bjson\.NewEncoder\(\s*(w|rw|resp|res|writer|wr|c\.Writer)\s*\)\.Encode\s*\(|\bfmt\.Fprint\w*\s*\(\s*(w|rw|resp|res|writer|wr|c\.Writer)\s*,|\b(w|rw|resp|res|writer|wr)\.Write\s*\(|\b(c|ctx)\.(JSON|String|IndentedJSON|PureJSON|YAML|SendString)\s*\(|\bio\.WriteString\s*\(\s*(w|rw|resp|res|writer)\s*,`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "os.Environ()")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "os.Environ()")
	not helpers.is_comment_line(line)
	_go_writes(lines, i, line)
	f := _finding(path, i, line)
}

_go_writes(_, _, line) if regex.match(_go_sink, line)

# A range that writes every entry; an entry filter (if/continue) in between
# means only some are shown.
_go_writes(lines, i, line) if {
	regex.match(`^\s*for\s+.*\brange\s+os\.Environ\(\)`, line)
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	regex.match(_go_sink, lines[j])
	not _go_filtered(lines, i, j)
}

_go_filtered(lines, i, j) if {
	some k in numbers.range(i + 1, j)
	regex.match(`^\s*(if|switch|case)\b|\bcontinue\b`, lines[k])
}

# env := os.Environ() ... json.NewEncoder(w).Encode(env)
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "os.Environ()")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "os.Environ()")
	regex.match(`^\s*[A-Za-z_]\w*\s*:?=\s*os\.Environ\(\)\s*$`, line)
	v := helpers.assigned_first(line)
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_go_sink, l)
	regex.match(concat("", [`[(,]\s*`, v, `\s*[,)]`]), l)
	not _go_filtered(lines, i, j)
	f := _finding(path, j, l)
}

# ── Java ─────────────────────────────────────────────────────────────────

_java_web(content) if regex.match(`@(Rest)?Controller\b|@(Get|Post|Request)Mapping\b|\bHttpServlet\b|@Path\(|@GET\b`, content)

findings contains f if {
	some path, content in input.file_contents
	_ext(path, {".java", ".jsp"})
	regex.match(`System\.(getenv|getProperties)\(\s*\)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "System.")
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(`\bSystem\.(getenv|getProperties)\(\s*\)`, code)
	_java_out(content, code)
	f := _finding(path, i, line)
}

_java_out(_, code) if regex.match(`\bResponseEntity\b|\.body\s*\(|\.addAttribute\s*\(|\.addObject\s*\(|\.getWriter\(\)|\bout\.print|\.entity\s*\(`, code)

_java_out(content, code) if {
	regex.match(`^\s*return\s+System\.(getenv|getProperties)\(\s*\)`, code)
	_java_web(content)
}

# Map<String, String> env = System.getenv(); ... return env;
findings contains f if {
	some path, content in input.file_contents
	_ext(path, {".java", ".jsp"})
	regex.match(`System\.(getenv|getProperties)\(\s*\)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "System.")
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?[\w<>,\s?]+?\s+(\w+)\s*=\s*System\.(getenv|getProperties)\(\s*\)\s*;`, al, 1)
	count(m) > 0
	v := m[0][1]
	some i in numbers.range(a + 1, min([count(lines) - 1, a + 6]))
	line := lines[i]
	not helpers.is_comment_line(line)
	_java_returns(content, _strip_q(line), v)
	f := _finding(path, i, line)
}

_java_returns(content, code, v) if {
	regex.match(concat("", [`^\s*return\s+`, v, `\s*;`]), code)
	_java_web(content)
}

_java_returns(_, code, v) if {
	regex.match(`\bResponseEntity\b|\.body\s*\(|\.addAttribute\s*\(|\.addObject\s*\(|\.getWriter\(\)|\bout\.print|\.entity\s*\(`, code)
	regex.match(concat("", [`[(,]\s*`, v, `\s*[,)]`]), code)
}

# ── Argument of a call spread over several lines ─────────────────────────

_pd(l) := count(split(l, "(")) - count(split(l, ")"))

# A sink call opened up to eight lines above line i and still open on it.
_open_sink(lines, i, sink) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	regex.match(sink, _strip_q(lines[j]))
	sum([_pd(_strip_q(lines[k])) | some k in numbers.range(j, i - 1)]) > 0
}

# res.json({\n  env: process.env,\n})
findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "process.env")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "process.env")
	not helpers.is_comment_line(line)
	code := regex.replace(_strip_q(line), `Object\.keys\s*\(\s*process\.env\s*\)`, "")
	regex.match(_js_env, code)
	_open_sink(lines, i, _js_sink)
	f := _finding(path, i, line)
}

# jsonify(\n  environment=dict(os.environ),\n)
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`os\.environ|app\.config|settings`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(_py_env, code)
	not regex.match(_py_filtered, code)
	_open_sink(lines, i, _py_sink)
	f := _finding(path, i, line)
}
