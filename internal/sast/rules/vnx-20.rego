# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_20

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-20",
	"name": "Input validation performed but its result ignored or bypassed",
	"description": "Input validation is wired up but never decides anything, so invalid input is processed as if it were valid. Reported: a Spring handler that declares a BindingResult parameter and never reads it before the next method (the @Valid errors are swallowed); a Bean Validation validator.validate(...) call whose returned violations are discarded as a bare statement; express-validator chains (body/check/query/param/header/cookie(...).isX()) in a project that never calls validationResult(), so the checks only annotate the request; a Flask-WTF/WTForms form whose field .data is read in the function without form.validate() or validate_on_submit(); a pydantic Model.construct()/model_construct() fed from request data, which skips validation by design; and Go gin c.ShouldBind*/c.Bind* or validator Struct() calls whose error is discarded (a bare statement or assigned to _). Not reported: a BindingResult read in the method (hasErrors, or passed to a helper), violations assigned or chained, a validationResult call anywhere in the project's JavaScript (a shared middleware), a form validated in the same function, construct() on data that did not come from the request, a checked bind error, comments and strings. Data reaching a dangerous sink with no validation at all is the business of the injection and traversal rules, not this one.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-20/",
	"languages": ["go", "java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [20],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["input-validation", "cwe-20"],
}

_is_js(path) if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── Java: BindingResult never read ───────────────────────────────────────

_method_decl := `^\s*(@\w+(\([^)]*\))?\s+)*(public|private|protected)\s[^=;]*\(`

_method_end(lines, i) := e if {
	n := count(lines) - 1
	lim := min([n, i + 80])
	ends := [j |
		some j in numbers.range(i + 1, lim)
		regex.match(_method_decl, lines[j])
	]
	e := min(array.concat([lim], ends))
}

_used_after(lines, i, e, name) if {
	re := concat("", [`\b`, name, `\b`])
	some j in numbers.range(i + 1, e)
	not helpers.is_comment_line(lines[j])
	regex.match(re, _code(lines[j]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "BindingResult")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "BindingResult")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bBindingResult\s+(\w+)\s*[,)]`, line, 1)
	count(m) > 0
	name := m[0][1]
	e := _method_end(lines, i)
	not _used_after(lines, i, e, name)
	finding := _finding(path, i, line, "The handler declares a BindingResult but never reads it, so @Valid failures are collected and then ignored: the invalid object is processed as if it had passed. Check result.hasErrors() and return before using the object")
}

# ── Java: Bean Validation violations discarded ──────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "alidator")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".validate")
	# One object, optionally followed by validation groups (Foo.class): the
	# Bean Validation signature, which returns the violations. Spring's
	# Validator.validate(target, errors) returns void and records into errors.
	regex.match(`^\s*(this\.)?\w*[Vv]alidator\s*\.\s*validate\s*\(\s*[^,;()]+(\s*,\s*[\w.]+\.class)*\s*\)\s*;\s*(//.*)?$`, line)
	finding := _finding(path, i, line, "validator.validate(...) returns the constraint violations; discarding the result means invalid input is never rejected. Assign the returned set and reject the input when it is not empty")
}

# ── Node: express-validator chains with no validationResult ─────────────

_project_reads_validation_result if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "validationResult")
	some line in split(content, "\n")
	contains(line, "validationResult")
	not helpers.is_comment_line(line)
	regex.match(`\bvalidationResult\b`, _code(line))
}

_ev_chain := `(^|[^\w.$])(body|check|query|param|header|cookie)\s*\(\s*(['"][^'"]*['"]|\[[^\]]*\])?\s*\)\s*\.\s*(is|not|exists|optional|trim|escape|normalize|custom|matches|equals|contains|notEmpty|toInt|toFloat|toBoolean)\w*\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "express-validator")
	not helpers.is_test_path(path)
	not _project_reads_validation_result
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_ev_chain, line)
	finding := _finding(path, i, line, "express-validator chains only record errors on the request; nothing in this project calls validationResult(req), so the request is handled whether or not it passed. Add a middleware that returns 400/422 when validationResult(req) is not empty")
}

# ── Python: WTForms data read without validation ────────────────────────

_py_func_end(lines, i) := e if {
	n := count(lines) - 1
	lim := min([n, i + 60])
	ends := [j |
		some j in numbers.range(i + 1, lim)
		regex.match(`^(\S|\s*def\s)`, lines[j])
	]
	e := min(array.concat([lim], ends))
}

_py_func_start(lines, i) := s if {
	starts := [j |
		some j in numbers.range(max([0, i - 60]), i)
		regex.match(`^\s*(async\s+)?def\s`, lines[j])
	]
	s := max(array.concat([max([0, i - 60])], starts))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "Form(")
	contains(content, ".data")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Form(")
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\s*=\s*\w*Form\s*\(`, line, 1)
	count(m) > 0
	v := m[0][1]
	e := _py_func_end(lines, i)
	s := _py_func_start(lines, i)
	data_re := concat("", [`\b`, v, `\.\w+\.data\b`])
	some j in numbers.range(i + 1, e)
	regex.match(data_re, lines[j])
	not helpers.is_comment_line(lines[j])
	not _form_validated(lines, s, e, v)
	finding := _finding(path, i, line, "The form's field data is read without form.validate() or validate_on_submit(), so its validators never run and unchecked input is used. Call validate_on_submit() (or validate()) and use the data only when it returns True")
}

_form_validated(lines, s, e, v) if {
	re := concat("", [`\b`, v, `\.validate(_on_submit)?\s*\(`])
	some j in numbers.range(s, e)
	regex.match(re, lines[j])
	not helpers.is_comment_line(lines[j])
}

# ── Python: pydantic construct() fed from the request ───────────────────

_py_source := `\brequest\.(args|form|values|json|get_json|GET|POST|data|body|query_params)\b`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "construct(")
	contains(content, "pydantic")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "construct(")
	not helpers.is_comment_line(line)
	regex.match(`\.(model_)?construct\s*\(`, line)
	_py_from_request(lines, i, line)
	finding := _finding(path, i, line, "pydantic construct()/model_construct() builds the model without running any validation; fed from the request it accepts any types and values. Use Model(**data) or Model.model_validate(data)")
}

_py_from_request(_, _, line) if regex.match(_py_source, line)

# A name assigned from the request above, unless that assignment validated it
# (Model.model_validate(request.json) is the safe path).
_py_from_request(lines, i, line) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	regex.match(_py_source, prev)
	not helpers.is_comment_line(prev)
	not regex.match(`\b(model_validate|parse_obj|parse_raw|validate)\w*\s*\(`, prev)
	v := helpers.assigned_first(prev)
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

# ── Go: bind or validation error discarded ──────────────────────────────

_go_bind := `^\s*(_\s*=\s*)?\w+\.(ShouldBind|Bind|MustBindWith)\w*\s*\(.*\)\s*(//.*)?$`

_go_validate := `^\s*(_\s*=\s*)?\w*[Vv]alidat\w*\.Struct(Ctx|Partial|Except)?\s*\(.*\)\s*(//.*)?$`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, "Bind")
	_go_web_framework(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Bind")
	regex.match(_go_bind, line)
	finding := _finding(path, i, line, "The error from binding the request is discarded, so a body that failed its binding:\"required\"/min/max rules is processed anyway. Check the error and return 400 before using the value")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, "go-playground/validator")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".Struct")
	regex.match(_go_validate, line)
	finding := _finding(path, i, line, "The error from validator Struct() is discarded, so the validation never rejects anything. Check the returned error and stop when it is not nil")
}

_go_web_framework(content) if contains(content, "github.com/gin-gonic/gin")

_go_web_framework(content) if contains(content, "github.com/labstack/echo")
