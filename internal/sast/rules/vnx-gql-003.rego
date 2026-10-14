package vulnetix.rules.vnx_gql_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GQL-003",
	"name": "GraphQL query string injection via string concatenation",
	"description": "A GraphQL operation document is built from request data: a template literal, f-string, str.format, %-format or + concatenation whose text is a GraphQL document (query/mutation/subscription with a selection set, a gql`...`/graphql`...` tag, or an anonymous { field(...) } document assigned to a query/gql/document name) interpolates a request value directly (req.body/query/params, ctx.params, event.queryStringParameters, resolver args, request.args/form/json/GET/POST) or a variable assigned from one within the previous 12 lines, including destructuring (const { id } = req.body). The attacker can then add fields, aliases or directives, or reach resolvers the caller should not. Covers JavaScript/TypeScript and Python, and multi-line documents up to 8 lines after their opening. Not reported: operations that pass request data through a variables map (variables: {...}, variable_values=), fragment or constant interpolation, values converted with parseInt/Number/JSON.stringify or a sanitiser, SQL strings and other non-GraphQL templates, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-gql-003/",
	"languages": ["javascript", "typescript", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [943],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["graphql", "injection", "query-injection"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts|vue|svelte)$`, path)

_is_py(path) if endswith(path, ".py")

_window := 8

_taint_window := 12

# ── shared ───────────────────────────────────────────────────────────────

_sanitised(line) if regex.match(`(?i)(parseInt\(|parseFloat\(|\bNumber\(|\bBoolean\(|\bint\(|\bfloat\(|JSON\.stringify\(|json\.dumps\(|encodeURIComponent\(|escape\w*\(|sanitiz|sanitis|validat|\.replace\()`, line)

# Names on the left of `const { a, b: c = 1 } = <source>`.
_destructured(line) := {n |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	pieces := split(part, ":")
	last := trim_space(split(pieces[count(pieces) - 1], "=")[0])
	regex.match(`^[A-Za-z_$][\w$]*$`, last)
	n := last
}

_assigned(line) := {v | v := helpers.assigned_first(line)}

_tainted(lines, i, source_re) := {v |
	i > 0
	some j in numbers.range(max([0, i - _taint_window]), i - 1)
	prev := lines[j]
	regex.match(source_re, prev)
	not helpers.is_comment_line(prev)
	not _sanitised(prev)
	some v in (_assigned(prev) | _destructured(prev))
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_src := `\b(req|request)\.(body|query|params|headers|cookies)\b|\bctx\.(request|query|params)\b|\bevent\.(body|queryStringParameters|pathParameters)\b|searchParams\.get\(|\bargs\.[A-Za-z_]|location\.(search|hash)\b`

# A line that opens (or is) a GraphQL document inside a string.
_js_doc := `([\x60'"(]\s*(query|mutation|subscription)\b(\s+[A-Za-z_]\w*)?\s*(\([^)]*\))?\s*\{)|(\b(gql|graphql)\s*(\(\s*)?\x60)|((?i)\b\w*(query|gql|document|operation)\w*['"]?\s*[:=]\s*[\x60'"]\s*\{)|(^\s*(query|mutation|subscription)\b(\s+[A-Za-z_]\w*)?\s*(\([^)]*\))?\s*\{)`

_js_gate := `[\x60'"(]\s*(query|mutation|subscription)\b|\b(gql|graphql)\s*(\(\s*)?\x60|\b\w*(query|gql|document|operation)\w*['"]?\s*[:=]\s*[\x60'"]\s*\{`

_backticks(line) := count(indexof_n(line, "`"))

# The document opened on line j is still open on line i.
_js_open(_, j, i) if i == j

_js_open(lines, j, i) if {
	i > j
	_backticks(lines[j]) % 2 == 1
	every k in numbers.range(j + 1, i - 1) {
		_backticks(lines[k]) == 0
	}
}

_js_open(lines, j, i) if {
	i == j + 1
	endswith(trim_space(lines[j]), "+")
}

_js_inline(line) if regex.match(concat("", [`\$\{\s*(`, _js_src, `)`]), line)

_js_inline(line) if regex.match(concat("", [`[\x60'"]\s*\+\s*(`, _js_src, `)`]), line)

_js_uses(line, v) if regex.match(concat("", [`\$\{\s*`, v, `\b`]), line)

_js_uses(line, v) if regex.match(concat("", [`[\x60'"]\s*\+\s*`, v, `\b`]), line)

_js_uses(line, v) if regex.match(concat("", [`(^|[^\w.$])`, v, `\s*\+\s*[\x60'"]`]), line)

_js_hit(_, _, line) if _js_inline(line)

_js_hit(lines, i, line) if {
	some v in _tainted(lines, i, _js_src)
	_js_uses(line, v)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(_js_gate, content)
	lines := split(content, "\n")
	some j, start in lines
	regex.match(_js_doc, start)
	not helpers.is_comment_line(start)
	some i in numbers.range(j, min([j + _window, count(lines) - 1]))
	line := lines[i]
	_js_open(lines, j, i)
	not helpers.is_comment_line(line)
	_js_hit(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL query injection: request data is interpolated or concatenated into the operation document; use a static document and pass the value in the variables map",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Python ───────────────────────────────────────────────────────────────

_py_src := `\brequest\.(args|form|values|json|data|GET|POST|query_params|path_params|cookies|headers)\b|\brequest\.get_json\(`

# GraphQL document text: an operation with a selection set, or an anonymous
# `{{ field(` / `{{ field {{` document in an f-string or format string.
_py_doc := `\b(query|mutation|subscription)\b(\s+[A-Za-z_]\w*)?\s*(\([^)]*\))?\s*\{|\{\{\s*[A-Za-z_]\w*\s*(\(|\{\{)`

_py_fstring := `\b[fF][rR]?("""|'''|"|')`

_py_interp(v) := concat("", [`(^|[^{])\{\s*`, v, `\b[^{}]*\}`])

# Interpolation inside an f-string: `{request.args["id"]}` or `{v}` (not an
# escaped `{{`). The f-string may have opened a few lines up (triple quotes).
_py_hit(_, _, line, ctx) if {
	regex.match(_py_fstring, ctx)
	regex.match(concat("", [`(^|[^{])\{\s*(`, _py_src, `)`]), line)
}

_py_hit(lines, i, line, ctx) if {
	regex.match(_py_fstring, ctx)
	some v in _tainted(lines, i, _py_src)
	regex.match(_py_interp(v), line)
}

# .format(), % and + on the line that holds the document text.
_py_hit(_, _, line, _) if {
	regex.match(_py_doc, line)
	regex.match(concat("", [`(\.format\([^)]*|["']\s*%\s*\(?\s*|["']\s*\+\s*)(`, _py_src, `)`]), line)
}

_py_hit(lines, i, line, _) if {
	regex.match(_py_doc, line)
	some v in _tainted(lines, i, _py_src)
	_py_op_uses(line, v)
}

_py_op_uses(line, v) if regex.match(concat("", [`\.format\([^)]*\b`, v, `\b`]), line)

_py_op_uses(line, v) if regex.match(concat("", [`["']\s*%\s*\(?\s*`, v, `\b`]), line)

_py_op_uses(line, v) if regex.match(concat("", [`["']\s*\+\s*`, v, `\b`]), line)

_py_op_uses(line, v) if regex.match(concat("", [`(^|[^\w.])`, v, `\s*\+\s*["']`]), line)

findings contains finding if {
	some path, content in input.file_contents
	_is_py(path)
	regex.match(_py_doc, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[{%+]`, line)
	not helpers.is_comment_line(line)
	ctx := helpers.code_window(lines, i, 6, 0)
	regex.match(_py_doc, ctx)
	_py_hit(lines, i, line, ctx)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL query injection: request data is interpolated or concatenated into the operation document; use a static document and pass the value in variable_values",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
