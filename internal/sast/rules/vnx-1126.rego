# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1126

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1126",
	"name": "Declaration of Variable with Unnecessarily Wide Scope",
	"description": "Reports a Python global statement inside a function or method body (global counter, global a, b), which makes the function rebind a module-level variable: every caller, thread and request then shares and mutates that one binding, so state set for one caller leaks into the next. The finding is the global line itself. Not reported: a global statement at module level (it has no effect), nonlocal (closure scope), globals that are only module dunders such as __doc__ or __all__, the word 'global' in a comment, a string or prose, and test files (including conftest.py). A global line inside a triple-quoted string is not a statement and is not reported. Whether a particular module-level variable should be wider than its function is a design judgement; the rule reports the statement that widens it.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1126/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1126],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["wide-variable-scope", "cwe-1126"],
}

_global_re := `^(\s+)global\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?:#.*)?$`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The global line sits in a def: some def above with a smaller indent, and no
# code line between them at or below that def's indent (which would close it).
_in_function(lines, i) if {
	ig := _indent(lines[i])
	some d in numbers.range(max([0, i - 200]), i - 1)
	regex.match(`^\s*(?:async\s+)?def\s+\w+`, lines[d])
	id := _indent(lines[d])
	id < ig
	not _closed(lines, d, i, id)
	not _in_string(lines, d, i)
}

# Triple-quote delimiters on a line.
_tq(l) := count(regex.find_all_string_submatch_n(`"""|'''`, l, -1))

# Line k starts inside a triple-quoted string opened after the def at d: an
# odd number of delimiters between them. A docstring whose text sits at column
# zero does not close the def, and a template string is not a statement.
_in_string(lines, d, k) if {
	k > d
	n := sum([_tq(lines[j]) | some j in numbers.range(d, k - 1)])
	n % 2 == 1
}

_skip_path(path) if helpers.is_test_path(path)

_skip_path(path) if regex.match(`(^|/)conftest\.py$`, path)

_closed(lines, d, i, id) if {
	d + 1 <= i - 1
	some k in numbers.range(d + 1, i - 1)
	l := lines[k]
	trim_space(l) != ""
	not helpers.is_comment_line(l)
	_indent(l) <= id
	not regex.match(`^\s*[)\]}]`, l)
	not _in_string(lines, d, k)
}

_all_dunder(names) if {
	every n in split(names, ",") {
		regex.match(`^__\w+__$`, trim_space(n))
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "global ")
	not _skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "global ")
	m := regex.find_all_string_submatch_n(_global_re, line, 1)
	count(m) > 0
	not _all_dunder(m[0][2])
	_in_function(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function rebinds module-level variable(s) %s through a global statement: the state is shared by every caller. Pass the value in and return it, or keep it on an object", [trim_space(m[0][2])]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
