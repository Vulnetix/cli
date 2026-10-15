# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1114

import rego.v1

metadata := {
	"id": "VNX-1114",
	"name": "Inappropriate Whitespace Style",
	"description": "Python indentation that mixes tabs and spaces, where whitespace decides which block a statement belongs to: a statement whose own indentation contains both a tab and a space, and, in a file that indents statements with both characters, the first statement of the less-used one. Mixed indentation makes the block structure depend on the tab width the reader assumes and raises TabError under Python 3 when it is ambiguous. Not reported: continuation lines inside brackets or after a backslash (their alignment does not affect blocks), whitespace-only lines, tabs inside string literals, lines inside triple-quoted strings, and comment lines.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1114/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1114],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["inappropriate-whitespace", "indentation", "cwe-1114"],
}

_ext(path) if endswith(path, ".py")

_ext(path) if endswith(path, ".pyw")

_lead(line) := substring(line, 0, count(line) - count(trim_left(line, " \t")))

_is_code(line) if {
	t := trim_space(line)
	t != ""
	not startswith(t, "#")
}

# lines on which a triple-quoted string opens or closes (odd number of quotes)
_toggles(lines) := [k |
	some k, l in lines
	contains(l, "\"\"\"")
	count(indexof_n(l, "\"\"\"")) % 2 == 1
] if true

_toggles2(lines) := [k |
	some k, l in lines
	contains(l, "'''")
	count(indexof_n(l, "'''")) % 2 == 1
] if true

_in_string(t1, t2, i) if count([k | some k in t1; k < i]) % 2 == 1

_in_string(t1, t2, i) if count([k | some k in t2; k < i]) % 2 == 1

# previous code line leaves a bracket or a backslash continuation open
_continuation(lines, i) if {
	ks := [k | some k in numbers.range(max([0, i - 5]), i - 1); k < i; _is_code(lines[k])]
	count(ks) > 0
	prev := trim_right(lines[ks[count(ks) - 1]], " \t\r")
	regex.match(`[(\[{,\\]$`, prev)
}

# a bracket opened in one of the ten lines above is still open here (strings
# and trailing comments are dropped before counting)
_continuation(lines, i) if {
	some k in numbers.range(max([0, i - 10]), i - 1)
	k < i
	contains(lines[k], "(")
	sum([_bdelta(lines[m]) | some m in numbers.range(k, i - 1)]) > 0
}

_continuation(lines, i) if {
	some k in numbers.range(max([0, i - 10]), i - 1)
	k < i
	regex.match(`[\[{]`, lines[k])
	sum([_bdelta(lines[m]) | some m in numbers.range(k, i - 1)]) > 0
}

_bdelta(l) := d if {
	s := regex.replace(l, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|#.*$`, "")
	d := (count(regex.find_n(`[(\[{]`, s, -1)) - count(regex.find_n(`[)\]}]`, s, -1)))
}

_stmt(lines, t1, t2, i) if {
	_is_code(lines[i])
	not _continuation(lines, i)
	not _in_string(t1, t2, i)
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	contains(content, "\t")
	regex.match(`(?m)^(?: +\t|\t+ )`, content)
	lines := split(content, "\n")
	t1 := _toggles(lines)
	t2 := _toggles2(lines)
	some i, line in lines
	regex.match(`^(?: +\t|\t+ )[ \t]*\S`, line)
	_stmt(lines, t1, t2, i)
	finding := _finding(path, i, line, "Indentation mixes tabs and spaces on one line; the block this statement belongs to depends on the tab width")
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	regex.match(`(?m)^\t+\S`, content)
	regex.match(`(?m)^ +\S`, content)
	lines := split(content, "\n")
	t1 := _toggles(lines)
	t2 := _toggles2(lines)
	indented := [k |
		some k, l in lines
		regex.match(`^(?:\t+|  *)\S`, l)
		count(_lead(l)) > 0
		_stmt(lines, t1, t2, k)
	]
	count(indented) > 1
	tabs := [k | some k in indented; startswith(lines[k], "\t")]
	spaces := [k | some k in indented; startswith(lines[k], " ")]
	count(tabs) > 0
	count(spaces) > 0
	m := _minority(tabs, spaces)
	i := m.lines[0]
	finding := _finding(path, i, lines[i], sprintf("File indents %d statements with %s but %d with %s, starting here; mixed indentation makes the block structure depend on the tab width", [m.major_n, m.major, count(m.lines), m.minor]))
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# the less-used indentation character is the deviation; on a tie, the one used second
_minority(tabs, spaces) := {"lines": tabs, "minor": "tabs", "major": "spaces", "major_n": count(spaces)} if {
	_tabs_minor(tabs, spaces)
} else := {"lines": spaces, "minor": "spaces", "major": "tabs", "major_n": count(tabs)}

_tabs_minor(tabs, spaces) if count(tabs) < count(spaces)

_tabs_minor(tabs, spaces) if {
	count(tabs) == count(spaces)
	spaces[0] < tabs[0]
}
