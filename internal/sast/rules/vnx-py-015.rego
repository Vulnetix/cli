package vulnetix.rules.vnx_py_015

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-015",
	"name": "Python ReDoS via user-controlled regular expression",
	"description": "A value read from the request (Flask request.args/form/values/json, Django request.GET/POST, or a route parameter) is compiled or matched as the regular expression pattern of re or regex (compile, match, search, fullmatch, findall, finditer, sub, subn, split), directly or through one or two assignments. An attacker can supply a pattern with catastrophic backtracking to cause denial of service. Not reported: a pattern passed through re.escape(), a fixed or configured pattern, user text used only as the subject being searched, argparse and settings values, and comments or strings that merely mention the call.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-015/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1333],
	"capec": ["CAPEC-197"],
	"attack_technique": ["T1499.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["redos", "regex", "dos", "python"],
}

_is_py(path) if endswith(path, ".py")

_source := `request\.(args|form|values|GET|POST|json|data|cookies|headers|files|query_params)\b|get_json\s*\(`

# Names a module may be imported under: re and regex, and any `import re as x`.
_modules(content) := {"re", "regex"} | {a |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+(?:re|regex)\s+as\s+([A-Za-z_]\w*)`, content, -1)
	a := m[1]
}

# The sink: <module>.<fn>( with everything before it on the line (group 1) and
# the rest of the line after the opening parenthesis (group 2).
_sink_re(mods) := concat("", [`^(.*?)\b(?:`, concat("|", [m | some m in mods]), `)\.(?:compile|match|search|fullmatch|findall|finditer|sub|subn|split)\s*\((.*)$`])

# The pattern is the first argument. When the call is broken after the
# parenthesis it is on the next line.
_first_arg(lines, i, rest) := arg if {
	trim_space(rest) != ""
	arg := split(rest, ",")[0]
}

_first_arg(lines, i, rest) := arg if {
	trim_space(rest) == ""
	i + 1 < count(lines)
	arg := split(lines[i + 1], ",")[0]
}

# The match sits inside a string or docstring when an odd number of quotes
# precedes it.
_in_string(prefix) if count(split(prefix, "\"")) % 2 == 0

_in_string(prefix) if count(split(prefix, "'")) % 2 == 0

# Names holding request data: assigned from a request source, derived from one
# such name by one more assignment, or a route parameter of the handler above.
_tainted(lines, i) := (direct | derived) | route if {
	direct := helpers.tainted_names(lines, i, 25, _source)
	derived := {v |
		i > 0
		some j in numbers.range(max([0, i - 25]), i - 1)
		line := lines[j]
		not helpers.is_comment_line(line)
		some d in direct
		regex.match(concat("", [`\b`, d, `\b`]), line)
		v := helpers.assigned_first(line)
	}
	route := {p |
		i > 0
		some j in numbers.range(max([0, i - 25]), i - 1)
		some m in regex.find_all_string_submatch_n(`@\w+\.(?:route|get|post|put|delete|api_route)\s*\(.*<(?:\w+:)?(\w+)>`, lines[j], -1)
		p := m[1]
	}
}

_arg_tainted(arg, _) if regex.match(_source, arg)

_arg_tainted(arg, names) if {
	some n in names
	regex.match(concat("", [`\b`, n, `\b`]), arg)
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	content := input.file_contents[path]
	lines := split(content, "\n")
	re_sink := _sink_re(_modules(content))
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(re_sink, line, 1)
	count(m) > 0
	not _in_string(m[0][1])
	arg := _first_arg(lines, i, m[0][2])
	not contains(arg, "escape(")
	_arg_tainted(arg, _tainted(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "A request value is used as the regular expression pattern; an attacker can supply one with catastrophic backtracking (ReDoS) — use a fixed pattern, re.escape() the input, or google-re2",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
