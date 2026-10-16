# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1124

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1124",
	"name": "Excessively Deep Nesting",
	"description": "A Python control-flow statement (if, elif, else, for, while, try, except, finally, with, match, case; header-only or with an inline return/continue/break/pass/raise/yield body) nested inside five or more enclosing control blocks of the same function, measured by indentation relative to the enclosing def and that function's own indent step (4 spaces, 2 spaces or a tab). Reported once per function, on the first statement that reaches that depth. Code this deep hides which conditions guard a statement, and an access check or error branch at one level is easily misread at another. Not reported: nesting of four or fewer blocks, depth that comes from nested defs or classes (each function is measured from its own def), continuation lines inside brackets, comments, lines inside triple-quoted strings (a docstring's indented example) and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1124/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1124],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["deep-nesting", "cwe-1124", "maintainability"],
}

# Enclosing control blocks at which a statement is reported.
_max_enclosing := 5

_ctrl_re := `^\s*(?:(?:if|elif|else|for|async\s+for|while|try|except|finally|with|async\s+with|match|case)\b[^#]*:\s*(?:#.*)?$|(?:if|elif|else|while|for)\b[^#]*:\s*(?:return|continue|break|pass|raise|yield)\b)`

_def_re := `^\s*(?:async\s+)?def\s+[A-Za-z_]`

# Indent width, counting a tab as four columns.
_width(line) := count(lead) + 3 * count(regex.find_n(`\t`, lead, -1)) if {
	lead := regex.find_n(`^[ \t]*`, line, 1)[0]
}

_sig_end(lines, i) := e if {
	end := min([count(lines) - 1, i + 15])
	cands := [k |
		some k in numbers.range(i, end)
		regex.match(`:\s*(#.*)?$`, lines[k])
	]
	count(cands) > 0
	e := cands[0]
}

# The nearest def above line i that is less indented than it.
_enclosing_def(defs, i, w) := d if {
	cands := [k |
		some df in defs
		k := df[0]
		k < i
		df[1] < w
	]
	count(cands) > 0
	d := max(cands)
}

# Function base indent and its indent step, read from its first body line.
_frame(lines, d) := [dw, step] if {
	dw := _width(lines[d])
	e := _sig_end(lines, d)
	b := helpers.next_code_index(lines, e, 6)
	step := _width(lines[b]) - dw
	step > 0
}

_deep(lines, k, dw, step) if {
	regex.match(_ctrl_re, lines[k])
	(_width(lines[k]) - dw) / step - 1 >= _max_enclosing
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`(?m)^(?:\t{4,}|[ \t]{12,})(?:if|elif|else|for|while|try|except|finally|with|case|async)\b`, content)
	lines := split(content, "\n")
	defs := [[k, _width(l)] |
		some k, l in lines
		contains(l, "def ")
		regex.match(_def_re, l)
	]
	some i, line in lines
	regex.match(`^(?:\t{4,}|[ \t]{12,})\S`, line)
	regex.match(_ctrl_re, line)
	d := _enclosing_def(defs, i, _width(line))
	fr := _frame(lines, d)
	_deep(lines, i, fr[0], fr[1])
	not _earlier_deep(lines, defs, d, i, fr)
	not _in_string(lines, d, i)
	depth := format_int(((_width(line) - fr[0]) / fr[1]) - 1, 10)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Statement nested inside %s control blocks (threshold %d): extract the inner logic or return early", [depth, _max_enclosing]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_earlier_deep(lines, defs, d, i, fr) if {
	some k in helpers.span(d + 1, i - 1)
	_deep(lines, k, fr[0], fr[1])
	_enclosing_def(defs, k, _width(lines[k])) == d
	not _in_string(lines, d, k)
}

# Inside a triple-quoted string (a docstring's indented example): an odd
# number of triple quotes between the def and the line.
_in_string(lines, d, i) if {
	n := sum([count(regex.find_n(`"""|'''`, lines[k], -1)) | some k in numbers.range(d, i - 1)])
	n % 2 == 1
}
