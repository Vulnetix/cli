# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1121

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1121",
	"name": "Excessive McCabe Cyclomatic Complexity",
	"description": "A Python top-level function or method whose McCabe cyclomatic complexity is 26 or more: one plus every if, elif, for, while, except and match-case statement in its body (nested functions included) plus every and/or in those statements' conditions, including a condition wrapped over several lines (if (a is None\n and b):). Above about 25 a function has more independent paths than can be tested or reviewed, and validation and authorisation checks get lost among them. Not reported: functions below the threshold however long, decisions in comprehensions and conditional expressions (not counted, so the measure errs low), prose and pseudo-code in the function's docstring and in comments, and test files. The finding is a maintainability signal, not an exploitable defect.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1121/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1121],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-mccabe", "cwe-1121", "maintainability"],
}

# Decision points (complexity minus one) at which a function is reported.
_threshold := 25

_def_re := `^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`

_indent(line) := count(line) - count(trim_left(line, " \t"))

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

# A decision statement starts with the keyword and ends its header with a
# colon; a docstring sentence that starts with "if" does not end that way.
_decision_re := `^\s*(?:if|elif|for|while|except|case|async\s+for)\b.*:\s*(?:#.*)?$`

# A condition wrapped over several lines: the header opens a parenthesis it
# does not close on this line (if (a is None\n        and b):).
_wrapped_re := `^\s*(?:if|elif|while)\s*\((?:[^()#]|\([^()]*\))*$`

# A continuation line of a wrapped condition that starts with and/or.
_cont_re := `^\s*(?:and|or)\s`

_bool_ops(line) := count(regex.find_n(`\s(?:and|or)\s`, regex.replace(regex.replace(line, `"[^"]*"|'[^']*'`, `""`), `#.*$`, ""), -1))

# Most lines start with no decision keyword: one cheap test settles them.
_kw_re := `^\s*(?:if|elif|for|while|except|case|async|and|or)\b`

_decisions(line) := 0 if not regex.match(_kw_re, line)

_decisions(line) := _keyword_decisions(line) if regex.match(_kw_re, line)

_keyword_decisions(line) := 1 + _bool_ops(line) if regex.match(_decision_re, line)

_keyword_decisions(line) := 1 + _bool_ops(line) if {
	not regex.match(_decision_re, line)
	regex.match(_wrapped_re, line)
}

_keyword_decisions(line) := _bool_ops(concat("", [" ", line])) if {
	not regex.match(_decision_re, line)
	not regex.match(_wrapped_re, line)
	regex.match(_cont_re, line)
}

_keyword_decisions(line) := 0 if {
	not regex.match(_decision_re, line)
	not regex.match(_wrapped_re, line)
	not regex.match(_cont_re, line)
}

# The last line of the function's docstring, or the signature's last line
# when it has none: pseudo-code in a docstring (if node is visited:) is prose.
_body_start(lines, e) := c if {
	b := helpers.next_code_index(lines, e, 4)
	m := regex.find_all_string_submatch_n(`^\s*[rRuU]?("""|''')`, lines[b], 1)
	count(m) > 0
	q := m[0][1]
	end := min([count(lines) - 1, b + 200])
	closers := [k |
		some k in numbers.range(b, end)
		_closes(lines[k], q, k == b)
	]
	count(closers) > 0
	c := closers[0]
}

_closes(line, q, false) if contains(line, q)

_closes(line, q, true) if count(split(line, q)) >= 3

_sig_end(lines, i) := e if {
	end := min([count(lines) - 1, i + 15])
	cands := [k |
		some k in numbers.range(i, end)
		regex.match(`:\s*(#.*)?$`, lines[k])
	]
	count(cands) > 0
	e := cands[0]
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "def ")

	# A file with fewer decision words than the threshold cannot hold a
	# function above it; find_n stops at the threshold.
	count(regex.find_n(`\b(?:if|elif|for|while|except|case|and|or)\b`, content, _threshold)) >= _threshold
	lines := split(content, "\n")
	n := count(lines)
	ind := [_code_indent(l) | some l in lines]

	# Lines that can end a top-level function or a method: any column-0 code,
	# and a def, class or decorator at indent 4 or less.
	terms := [k |
		some k, v in ind
		v >= 0
		v <= 4
		_terminator(lines[k], v)
	]
	dec := [_decisions(l) | some l in lines]
	some i in terms
	m := regex.find_all_string_submatch_n(_def_re, lines[i], 1)
	count(m) > 0
	d := count(m[0][1])
	e := _sig_end(lines, i)
	stop := min(array.concat([n], [k | some k in terms; k > e; ind[k] <= d]))
	stop - e > 12
	bs := _start_or_sig(lines, e)
	cc := sum([dec[k] | some k in numbers.range(bs + 1, stop - 1)])
	cc >= _threshold
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function %s has cyclomatic complexity %d (threshold %d): too many independent paths to test or review", [m[0][2], cc + 1, _threshold + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

_terminator(_, 0)

_terminator(line, v) if {
	v > 0
	regex.match(`^\s*(?:async\s+def|def|class|@)\b|^\s*@`, line)
}

_start_or_sig(lines, e) := s if s := _body_start(lines, e)

_start_or_sig(lines, e) := e if not _body_start(lines, e)
