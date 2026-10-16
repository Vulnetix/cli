# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_914

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-914",
	"name": "Attribute name chosen by the request in setattr()",
	"description": "Python setattr() whose attribute-NAME argument comes from the HTTP request, so the client picks which attribute of the object it overwrites (is_admin, password_hash, a method). Reported: setattr(obj, name, value) where the name is Flask/Django/DRF request data (request.args/form/values/json/data/GET/POST/cookies/headers/query_params/body, get_json(), json.loads(request.body)) inline, a variable assigned from such a value in the 15 lines above, or the key of a for loop (up to 10 lines above) over such a mapping, a variable holding it, one subscript of it, or its .items()/.keys(), including a call split across lines. Not reported: a constant attribute name with a request value, a loop over a constant tuple, serializer validated_data or form cleaned_data (also of a form built from request.POST), getattr() reads, a loop whose key is checked against an allow-list (key in ALLOWED, key not in ALLOWED: continue) before the setattr, comments and string literals. Overlaps VNX-PY-016 (setattr loops) and VNX-627 (globals()/vars() writes).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-914/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [914],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["dynamic-attribute", "mass-assignment", "cwe-914"],
}

_src := `\brequest\.(?:args|form|values|json|data|body|GET|POST|cookies|COOKIES|headers|query_params|get_json\()`

_sink := `(?:^|[^\w\.])setattr\s*\(`

# The second argument of setattr(), read over the call line and the two
# lines after it.
_name_arg(lines, i) := n if {
	end := min([count(lines) - 1, i + 2])
	txt := concat(" ", [lines[k] | some k in numbers.range(i, end)])
	m := regex.find_all_string_submatch_n(`(?:^|[^\w\.])setattr\s*\(\s*[^,]+,\s*([^,]+?)\s*,`, txt, 1)
	count(m) > 0
	n := m[0][1]
}

_assigned(lines, i) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_src, prev)
	v := helpers.assigned_first(prev)
}

# Loop keys over request data or a variable holding it: for k, v in X.items()
_loop_key(lines, i, tainted) := {[k, j] |
	some j in numbers.range(max([0, i - 10]), i - 1)
	m := regex.find_all_string_submatch_n(`^\s*for\s+\(?\s*([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)?\)?\s+in\s+(.+):\s*$`, lines[j], 1)
	count(m) > 0
	_tainted_expr(m[0][2], tainted)
	k := m[0][1]
}

_tainted_expr(expr, _) if {
	regex.match(_src, expr)
	not regex.match(_validated, expr)
}

# The variable itself, its .items()/.keys(), or one subscript of it; not an
# attribute such as form.cleaned_data of a form built from the request.
_tainted_expr(expr, tainted) if {
	some v in tainted
	regex.match(concat("", [`^\s*`, v, `\s*(?:\[[^\]]+\]\s*)?(?:\.(?:items|keys)\s*\(\s*\))?\s*$`]), expr)
}

_validated := `\b(?:cleaned_data|validated_data)\b`

_guarded(lines, j, i, k) if {
	j + 1 <= i - 1
	some m in helpers.span(j + 1, i - 1)
	regex.match(concat("", [`\b`, k, `\s+(?:not\s+)?in\b|\b`, k, `\.startswith\(`]), lines[m])
}

_controlled(lines, i, name, _) if regex.match(_src, name)

_controlled(lines, i, name, tainted) if {
	some v in tainted
	name == v
}

_controlled(lines, i, name, tainted) if {
	some pair in _loop_key(lines, i, tainted)
	name == pair[0]
	not _guarded(lines, pair[1], i, name)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "setattr")
	regex.match(_src, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "setattr")
	not helpers.is_comment_line(line)
	code := regex.replace(line, `"[^"]*"|'[^']*'`, `""`)
	regex.match(_sink, code)
	name := _name_arg(lines, i)
	not regex.match(`^["']`, name)
	tainted := _assigned(lines, i)
	_controlled(lines, i, name, tainted)
	finding := {
		"rule_id": metadata.id,
		"message": "setattr() takes its attribute name from the request: the client chooses which attribute it overwrites (is_admin, password_hash, a method). Map allowed field names explicitly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
