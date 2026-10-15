# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1085

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1085",
	"name": "Invokable Control Element with Excessive Volume of Commented-out Code",
	"description": "A Python function or method whose body holds 5 or more comment lines that are commented-out code rather than prose: an assignment (`# total = amount`), a call statement (`# self.check_csrf(request)`), an import, a bare `return`/`raise`/`pass`/`break`/`continue` or a `return x`, `del x`, `assert x`, or a block header ending in a colon (`# if customer.is_vip:`, `# for x in y:`, `# else:`). Disabled code inside a function hides what the function used to check (a commented-out permission or CSRF call reads like a decision nobody recorded) and goes stale against the code around it. One finding per function, at its `def` line. Not reported: prose comments (`# If the customer is a reseller we apply ...`, `# Example: price(item, 3)`), fewer than 5 such lines, `#` lines inside a triple-quoted string in the function (a docstring, or a config or shell template the function writes), commented-out code at module level, and test files. The threshold is this rule's choice; CWE-1085 does not fix one.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1085/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1085],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["commented-out-code", "maintainability", "cwe-1085"],
}

_min_lines := 5

_max_body_lines := 400

_def_re := `^(\s*)(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(`

# A comment whose text parses as a Python statement.
_code_comment_re := `^\s*#+\s?\s*(?:[A-Za-z_][\w.]*(?:\[[^\]]*\])?\s*(?:[-+*/|&]?=)\s*[^=\s]|[A-Za-z_][\w.]*\(.*\)\s*$|import\s+[\w.]+|from\s+[\w.]+\s+import\s+\w|(?:return|raise|pass|break|continue)\s*$|(?:return|raise|del|assert|yield|await)\s+[^\s]+\s*$|(?:if|elif|while|with)\s+[^:]*:\s*$|for\s+[\w, ()]+\s+in\s+[^:]+:\s*$|(?:else|try|finally)\s*:\s*$|except\b[^:]*:\s*$|(?:async\s+)?def\s+\w+\s*\(.*\)\s*(?:->[^:]*)?:\s*$|print\s*\()`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_is_code(line) if {
	t := trim_space(line)
	t != ""
	not startswith(t, "#")
}

_body_end(lines, i, ind) := e if {
	limit := min([count(lines) - 1, i + _max_body_lines])
	outs := [k |
		some k in numbers.range(i + 1, limit)
		_is_code(lines[k])
		_indent(lines[k]) <= ind
		not regex.match(`^\s*[)\]}]`, lines[k])
	]
	e := _first_or(outs, limit + 1)
}

_first_or(xs, d) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

# Line k sits inside a triple-quoted string (a docstring, or a config or shell
# template whose own `#` lines are not Python) when an odd number of triple
# quotes opened since the def at line i.
_in_string(tq, i, k) if {
	n := sum([c | some p in tq; p[0] > i; p[0] < k; c := p[1]])
	n % 2 == 1
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(concat("", ["(?m)", _code_comment_re]), content)
	lines := split(content, "\n")
	# Lines holding triple quotes, with how many: once per file.
	tq := [[j, c] |
		some j, l in lines
		regex.match(`"""|'''`, l)
		c := count(regex.find_n(`"""|'''`, l, -1))
	]
	some i, line in lines
	regex.match(_def_re, line)
	ind := _indent(line)
	e := _body_end(lines, i, ind)
	e > i + _min_lines
	n := count([k |
		some k in numbers.range(i + 1, e - 1)
		_indent(lines[k]) > ind
		regex.match(_code_comment_re, lines[k])
		not _in_string(tq, i, k)
	])
	n >= _min_lines
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function holds %d lines of commented-out code; delete them (version control keeps the history) or restore them as live code", [n]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
