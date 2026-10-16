# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1235

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1235",
	"name": "Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations",
	"description": "Reports Java arithmetic on a boxed numeric type inside a loop, where every iteration unboxes the value, computes, and allocates a new wrapper object: a for loop whose counter is declared as Integer, Long, Short, Byte, Double, Float or Character (for (Integer i = 0; i < n; i++)), and a local variable declared as one of those wrapper types with a numeric initial value (Long sum = 0L) that is then updated with ++, --, +=, -=, *=, /= or x = x + ... inside a for, while or do loop opened after it within the next 40 lines, including a single-statement loop body on the loop header line. Not reported: primitive counters and accumulators, enhanced-for loops over a List<Integer> (the element must be boxed anyway), wrapper variables that are only compared or reassigned, updates outside the loop, fields declared with an access modifier, comments and strings. This is a performance weakness: in a hot path the allocations raise GC pressure and latency, which is how it becomes a denial-of-service concern.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1235/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1235],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["autoboxing", "cwe-1235"],
}

_boxed := `(?:Integer|Long|Short|Byte|Double|Float|Character)`

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── boxed loop counter ──────────────────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(concat("", [`for\s*\(\s*(?:final\s+)?`, _boxed, `\s+\w+\s*=`]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "for")
	regex.match(concat("", [`^\s*(?:\}\s*)?for\s*\(\s*(?:final\s+)?`, _boxed, `\s+\w+\s*=[^;]*;`]), line)
	finding := _finding(path, i, line, "The loop counter is a boxed wrapper type: each comparison unboxes it and each increment allocates a new object. Declare it as int/long")
}

# ── boxed local accumulator updated inside a loop ───────────────────────

_decl_re := concat("", [`^\s+(?:final\s+)?`, _boxed, `\s+([A-Za-z_]\w*)\s*=\s*(?:-?\d|\(\s*\w+\s*\)\s*-?\d|\w+\.valueOf\()`])

_loop_re := `^\s*(?:\}\s*)?(?:for|while|do)\b`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(concat("", [`(?m)^\s+(?:final\s+)?`, _boxed, `\s+\w+\s*=\s*[-(\d\w]`]), content)
	lines := split(content, "\n")
	n := count(lines) - 1
	some d, decl in lines
	regex.match(_boxed, decl)
	m := regex.find_all_string_submatch_n(_decl_re, decl, 1)
	count(m) > 0
	v := m[0][1]
	upd_re := concat("", [`(?:\b`, v, `\s*(?:\+\+|--|[-+*/]=)|(?:\+\+|--)`, v, `\b|\b`, v, `\s*=\s*`, v, `\s*[-+*/])`])
	some j in numbers.range(d + 2, min([n, d + 40]))
	regex.match(upd_re, lines[j])
	not helpers.is_comment_line(lines[j])
	not _scope_closed(lines, d, j)
	_in_loop(lines, d, j)
	finding := _finding(path, j, lines[j], sprintf("%s is a boxed wrapper updated inside a loop: every iteration unboxes it and allocates a new object. Declare it as the primitive type", [v]))
}

# A loop whose single-statement body sits on the header line:
#   for (Item it : items) grams += it.getGrams();
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(concat("", [`(?m)^\s+(?:final\s+)?`, _boxed, `\s+\w+\s*=\s*[-(\d\w]`]), content)
	regex.match(`(?m)^\s*(?:for|while)\s*\(.*\)\s*[\w+-]`, content)
	lines := split(content, "\n")
	n := count(lines) - 1
	some d, decl in lines
	regex.match(_boxed, decl)
	m := regex.find_all_string_submatch_n(_decl_re, decl, 1)
	count(m) > 0
	v := m[0][1]
	some j in numbers.range(d + 1, min([n, d + 40]))
	regex.match(_loop_re, lines[j])
	inline_re := concat("", [`^\s*(?:for|while)\s*\(.*\)\s*(?:\b`, v, `\s*(?:\+\+|--|[-+*/]=)|(?:\+\+|--)`, v, `\b|\b`, v, `\s*=\s*`, v, `\s*[-+*/])`])
	regex.match(inline_re, lines[j])
	not helpers.is_comment_line(lines[j])
	not _scope_closed(lines, d, j)
	finding := _finding(path, j, lines[j], sprintf("%s is a boxed wrapper updated inside a loop: every iteration unboxes it and allocates a new object. Declare it as the primitive type", [v]))
}

# The declaring block ends before j: a line shallower than the declaration.
_scope_closed(lines, d, j) if {
	id := _indent(lines[d])
	some k in helpers.span(d + 1, j - 1)
	trim_space(lines[k]) != ""
	_indent(lines[k]) < id
}

_in_loop(lines, d, j) if {
	some k in helpers.span(d + 1, j - 1)
	regex.match(_loop_re, lines[k])
	not helpers.is_comment_line(lines[k])
	ik := _indent(lines[k])
	_indent(lines[j]) > ik
	not _loop_closed(lines, k, j, ik)
}

_loop_closed(lines, k, j, ik) if {
	k + 1 <= j - 1
	some m in helpers.span(k + 1, j - 1)
	trim_space(lines[m]) != ""
	_indent(lines[m]) <= ik
}
