# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_913

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-913",
	"name": "Request data evaluated as code (improper control of dynamically-managed code resources)",
	"description": "HTTP request data becomes code the process runs (CWE-913). Reported in Python: the code argument of the eval(), exec() and compile() builtins (bare or builtins.) carrying Flask/Django/DRF request data (request.args/form/values/json/data/GET/POST/cookies/headers/query_params, get_json()); in JavaScript/TypeScript: eval(), new Function()/Function(), vm.runInNewContext/runInThisContext/runInContext/compileFunction and new vm.Script given Express/Koa request data (req or request query/body/params/headers/cookies, ctx.query, ctx.request.body). The request value must appear in the call directly (also inside an f-string, template literal or concatenation) or through a variable assigned (also with a TypeScript type annotation) or destructured from it in the 15 lines above, with one further assignment followed (payload = request.get_json(); cond = payload[\"c\"]; eval(cond), or code = compile(src, ...); exec(code)). Not reported: ast.literal_eval, methods named eval (model.eval(), redis.eval), constant code strings, values passed through int()/float()/parseInt()/Number() first, values from configuration or the environment, comments and string literals. Overlaps VNX-94, which covers more languages.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-913/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [913],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["dynamic-code", "code-injection", "cwe-913"],
}

_py_src := `\brequest\.(?:args|form|values|json|data|GET|POST|cookies|COOKIES|headers|query_params|get_json\()`

_js_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies)\b|\bctx\.(?:query|request\.body|params)\b`

_py_sink := `(?:^|[^\w\.]|\bbuiltins\.)(?:eval|exec|compile)\s*\(`

_js_sink := `(?:^|[^\w\.]|\b(?:window|globalThis|global)\.)eval\s*\(|\bnew\s+Function\s*\(|(?:^|[^\w\.])Function\s*\(|\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\(`

_numeric := `\b(?:int|float|parseInt|parseFloat|Number|bool)\s*\(`

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}
	endswith(path, ext)
}

_src("py") := _py_src

_src("js") := _js_src

_sink("py") := _py_sink

_sink("js") := _js_sink

# The text from the sink call onward, on a line whose plain string literals
# were removed (template literals and f-strings with interpolation are kept).
_args(line, sink) := a if {
	locs := regex.find_all_string_submatch_n(sink, line, 1)
	count(locs) > 0
	idx := indexof(line, locs[0][0])
	a := substring(line, idx + count(locs[0][0]), -1)
}

_tainted(lines, i, src) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(src, prev)
	not regex.match(_numeric, prev)
	some v in _assigned(prev)
}

_assigned(line) := (_first(line) | _destructured(line)) | _typed(line)

_first(line) := {v | v := helpers.assigned_first(line)}

# const expr: string = req.query.expr as string
_typed(line) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*[^=]+=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# One further hop inside the window: payload = request.get_json() then
# condition = payload["condition"], or code = compile(src, ...).
_tainted2(lines, i, n1) := {v |
	count(n1) > 0
	re := concat("", [`=[^=].*\b(?:`, concat("|", n1), `)\b`])
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(re, prev)
	not regex.match(_numeric, prev)
	some v in _assigned(prev)
	not v in n1
}

# const { a, b } = req.body
_destructured(line) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	v := trim_space(split(trim_space(part), ":")[count(split(trim_space(part), ":")) - 1])
	v != ""
}

_uses_request(lines, i, args, src) if regex.match(src, args)

_uses_request(lines, i, args, src) if {
	n1 := _tainted(lines, i, src)
	some v in n1 | _tainted2(lines, i, n1)
	regex.match(concat("", [`\b`, v, `\b`]), args)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not endswith(path, ".min.js")
	regex.match(concat("", ["(?m)", _sink(lang)]), content)
	regex.match(_src(lang), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink(lang), line)
	not helpers.is_comment_line(line)
	code := regex.replace(line, `"[^"{}]*"|'[^'{}]*'`, `""`)
	regex.match(_sink(lang), code)
	args := _args(code, _sink(lang))
	not regex.match(_numeric, args)
	_uses_request(lines, i, args, _src(lang))
	finding := {
		"rule_id": metadata.id,
		"message": "Request data is evaluated as code (eval/exec/compile, new Function or vm): the requester chooses code the server runs. Parse the value as data instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
