# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1117

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1117",
	"name": "Callable with Insufficient Behavioral Summary",
	"description": "A Python function or method whose behavioural summary is missing where it matters: a docstring that is empty or only a placeholder (\"\"\"\"\"\", \"\"\"TODO\"\"\", \"\"\"...\"\"\", \"\"\"Docstring\"\"\", \"\"\"Description\"\"\", on one line or split over three, a generator stub such as autoDocstring's \"\"\"_summary_, or only a to-do note such as \"\"\"TODO: write docstring.\"\"\"), on any function; and a public (name not starting with an underscore) top-level function or method whose body is 50 or more lines of code with no docstring at all. Not reported: short or private undocumented functions (an undocumented helper is not by itself a weakness), functions documented by a real docstring (a single-quoted string as the first statement is a docstring too), nested functions, test files, and the patterns inside comments. CWE-1117 is a maintainability weakness; the finding says the callable cannot be reviewed against a stated contract, not that it is exploitable.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1117/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1117],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["insufficient-callable-summary", "cwe-1117", "maintainability"],
}

_min_body := 50

_def_re := `^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Indent of a code line, or -1 for a blank or whole-line comment.
_code_indent(line) := -1 if trim_space(line) == ""

_code_indent(line) := -1 if {
	trim_space(line) != ""
	startswith(trim_space(line), "#")
}

_code_indent(line) := _indent(line) if {
	t := trim_space(line)
	t != ""
	not startswith(t, "#")
}

_placeholder_word := `(?:TODO|FIXME|XXX|TBD|\.\.\.|[Dd]ocstring|_?[Ss]ummary_?|_?[Dd]escription_?|[Ff]unction|[Mm]ethod|[Ii]nsert docstring here)?`

_one_line_placeholder := concat("", [`^\s*[rRuU]?(?:"""|''')\s*`, _placeholder_word, `[\s.:]*(?:"""|''')\s*$`])

_open_only := `^\s*[rRuU]?(?:"""|''')\s*$`

# A docstring that is only a to-do note ("""TODO: write docstring.""",
# """FIXME(ann) - document"""); """TODO items still open""" is prose.
_todo_only := `^\s*[rRuU]?(?:"""|''')\s*(?:TODO|FIXME|XXX|TBD)(?:\([^)]*\))?\s*[:-][^"']*(?:"""|''')\s*$`

# A generated template whose summary line is still the generator's stub
# (autoDocstring writes """_summary_ followed by _description_ fields).
_stub_open := `^\s*[rRuU]?(?:"""|''')\s*_(?:summary|description)_\s*$`

_close_only := `^\s*(?:"""|''')\s*$`

_mid_placeholder := concat("", [`^\s*`, _placeholder_word, `[\s.:]*$`])

# Any string literal as the first statement is a docstring, including a
# single-quoted one ('Compute totals.').
_docstring_start(line) if regex.match(`^\s*[rRbBuU]{0,2}["']`, line)

# The signature may wrap over several lines: it ends at the first line ending
# in `:` (ignoring a trailing comment).
_sig_end(lines, i) := e if {
	end := min([count(lines) - 1, i + 15])
	cands := [k |
		some k in numbers.range(i, end)
		regex.match(`:\s*(#.*)?$`, lines[k])
	]
	count(cands) > 0
	e := cands[0]
}

_first_body(lines, e) := helpers.next_code_index(lines, e, 6)

_placeholder_doc(lines, b) if regex.match(_one_line_placeholder, lines[b])

_placeholder_doc(lines, b) if regex.match(_todo_only, lines[b])

_placeholder_doc(lines, b) if regex.match(_stub_open, lines[b])

_placeholder_doc(lines, b) if {
	regex.match(_open_only, lines[b])
	b + 1 < count(lines)
	regex.match(_close_only, lines[b + 1])
}

_placeholder_doc(lines, b) if {
	regex.match(_open_only, lines[b])
	b + 2 < count(lines)
	regex.match(_mid_placeholder, lines[b + 1])
	regex.match(_close_only, lines[b + 2])
}

# Empty or placeholder docstring, on any function.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`(?:"""|''')`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_def_re, line)
	e := _sig_end(lines, i)
	b := _first_body(lines, e)
	_placeholder_doc(lines, b)
	finding := {
		"rule_id": metadata.id,
		"message": "Function docstring is empty or a placeholder: the callable has no behavioural summary to review it against",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Long public top-level function or method with no docstring at all.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	not regex.match(`(^|/)conftest\.py$`, path)
	regex.match(`(?m)^(?:    )?(?:async\s+)?def\s+[A-Za-z]`, content)
	lines := split(content, "\n")
	n := count(lines)
	ind := [_code_indent(l) | some l in lines]
	shallow := [k | some k, v in ind; v >= 0; v <= 4]
	some i, line in lines
	m := regex.find_all_string_submatch_n(_def_re, line, 1)
	count(m) > 0
	d := count(m[0][1])
	d <= 4
	not startswith(m[0][2], "_")
	e := _sig_end(lines, i)
	ends := [k | some k in shallow; k > e; ind[k] <= d]
	stop := min(array.concat([n], ends))
	stop - e > _min_body
	body := count([k | some k in helpers.span(e + 1, stop - 1); ind[k] > d])
	body >= _min_body
	_method_or_top(lines, ind, i, d)
	b := _first_body(lines, e)
	not _docstring_start(lines[b])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Public function %s has %d lines of code and no docstring summarising its behaviour", [m[0][2], body]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A def at column 0 is top level; a def at indent 4 must sit directly in a
# class (the nearest less-indented code line above opens a class or is a
# decorator chain under one), not in another function.
_method_or_top(_, _, _, 0)

_method_or_top(lines, ind, i, 4) if {
	above := [k | some k in numbers.range(max([0, i - 400]), i - 1); ind[k] == 0; not regex.match(`^@`, lines[k])]
	count(above) > 0
	regex.match(`^class\s`, lines[max(above)])
}
