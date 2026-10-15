# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1285

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1285",
	"name": "Improper Validation of Specified Index, Position, or Offset in Input",
	"description": "A position the client chose is used to index a list or array with no bounds check, so a negative value silently selects from the end (Python), an out-of-range value raises or yields undefined, and the client can read or remove an element it was never offered. Reported in Python: int(...) of a Flask/Django/DRF request value (request.args/form/values/json/GET/POST/data/query_params/view_args) used as a subscript x[v], or as the position of .pop(v)/.insert(v, ...), inline or through a variable assigned from it in the 15 lines above. JavaScript/TypeScript: parseInt/Number/parseFloat/unary + of req.body/query/params, or a req field named index, idx, pos, position, offset, slot, choice, row or column, used as a subscript x[v] or as the position of .splice(v, ...)/.at(v)/.charAt(v), inline, through a variable assigned in the 15 lines above, or through a position-named field destructured from the request (const { index } = req.body). Not reported: a comparison of the value (<, <=, >, >=, or a check against len()/.length) between the read and the use, slices (rows[offset:offset+20], .slice()), lookups keyed by a string (users[req.params.id], THEMES[name]), and text in comments and strings. Upper-bound-only checks are reported by VNX-839.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1285/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1285],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["improper-validation-of-specified-index", "bounds", "cwe-1285"],
}

_msg := "A client-supplied index or offset is used to index a list/array without a bounds check: a negative or out-of-range value selects or removes the wrong element, or fails. Check 0 <= index < len before using it"

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_py_req := `\brequest\s*\.\s*(?:args|form|values|json|GET|POST|data|query_params|view_args)\b`

_js_req := `\breq(?:uest)?\s*\.\s*(?:body|query|params)\b`

_idx_key := `(?i:index|idx|pos|position|offset|slot|choice|row|col|column)`

# A request value converted to (or named as) a position.
_src := {
	"py": concat("", [`\bint\s*\(\s*`, _py_req]),
	"js": concat("", [`(?:\b(?:parseInt|Number|parseFloat)\s*\(\s*|(?:^|[^\w+])\+\s*)`, _js_req, `|`, _js_req, `\s*(?:\.\s*\w*`, _idx_key, `\w*\b|\[\s*['"]\w*`, _idx_key, `\w*['"]\s*\])`]),
}

_gate := {"py": `int\s*\(\s*request\s*\.`, "js": `req(?:uest)?\s*\.\s*(?:body|query|params)`}

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`(\\\\.|[^`\\\\])*`", "``")

# Positional sinks around the value expression x.
_sink_res := {
	"py": [`[\w\])]\s*\[\s*X\s*\]`, `\.\s*(?:pop|insert)\s*\(\s*X\s*[,)]`],
	"js": [`[\w\])$]\s*\[\s*X\s*\]`, `\.\s*(?:splice|at|charAt)\s*\(\s*X\s*[,)]`],
}

_sink(lang, c, x) if {
	some t in _sink_res[lang]
	regex.match(replace(t, "X", x), c)
}

_cmp(v, l) if regex.match(concat("", [`\b`, v, `\b\s*(?:<|>[^>=]|>=|<=)`]), l)

_cmp(v, l) if regex.match(concat("", [`(?:[^=<>\-]|^)(?:<|>|<=|>=)\s*`, v, `\b`]), l)

_cmp(v, l) if regex.match(concat("", [`(?i)\b(?:max|min|abs|clamp\w*|valid\w*|in_range|inRange)\s*\([^)]*\b`, v, `\b`]), l)

_cmp(v, l) if regex.match(concat("", [`\b`, v, `\b\s+(?:not\s+)?in\s+range\s*\(`]), l)

_guarded(lines, j, i, v) if {
	some k in numbers.range(j, i)
	not helpers.is_comment_line(lines[k])
	_cmp(v, _code(lines[k]))
}

_reassigned(lines, j, i, v) if {
	i - 1 >= j + 1
	some k in numbers.range(j + 1, i - 1)
	helpers.assigned_first(lines[k]) == v
}

_src_names(lang, l) := _conv_names(lang, l) | _destr_names(lang, l)

_destr_names("py", _) := set()

_conv_names(lang, l) := {v |
	regex.match(_src[lang], l)
	not regex.match(`^\s*(?:if|elif|while|for|return)\b`, l)
	not regex.match(`(?i)\b(?:max|min|abs|clamp\w*)\s*\(`, l)
	v := helpers.assigned_first(l)
}

# const { index, pos: p } = req.body: a destructured position-named field.
_destr_names("js", l) := {v |
	m := regex.find_all_string_submatch_n(`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\s*\.\s*(?:body|query|params)\b`, l, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	p := trim_space(split(part, "=")[0])
	regex.match(concat("", [`^\w*`, _idx_key, `\w*`]), p)
	segs := split(p, ":")
	v := trim_space(segs[count(segs) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

# Variable form.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some j, l in lines
	contains(l, "req")
	not helpers.is_comment_line(l)
	some v in _src_names(lang, l)
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 15]))
	not helpers.is_comment_line(lines[i])
	c := _code(lines[i])
	contains(c, v)
	_sink(lang, c, concat("", [`\b`, v, `\b`]))
	not _reassigned(lines, j, i, v)
	not _guarded(lines, j, i, v)
	finding := _finding(path, i, lines[i])
}

# Inline form: x[int(request.args["i"])], arr.at(Number(req.params.slot)).
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "req")
	not helpers.is_comment_line(line)
	regex.match(_src[lang], line)
	_sink(lang, line, concat("", [`(?:`, _src[lang], `)(?:\[[^\]\[]*\]|[^\]\[])*?`]))
	_outside_string(line)
	finding := _finding(path, i, line)
}

_count(s, ch) := count(split(s, ch)) - 1

# The request expression is code, not text inside a string literal.
_outside_string(line) if {
	prefix := split(line, "req")[0]
	_count(prefix, "\"") % 2 == 0
	_count(prefix, "'") % 2 == 0
	_count(prefix, "`") % 2 == 0
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
