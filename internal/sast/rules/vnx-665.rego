# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_665

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-665",
	"name": "Improper Initialization",
	"description": "A Java static initializer swallows an exception, so the class finishes loading with its static state half set up (CWE-665): a catch clause (K&R or Allman braces) inside a static { } block whose body is empty or only prints the stack trace, writes to System.out/err or logs. The class is then usable, and every later caller meets the null keystore, connection or configuration far from the cause instead of an ExceptionInInitializerError at load time. The catch line is reported. Not reported: a catch that rethrows (ExceptionInInitializerError, IllegalStateException...), assigns a fallback value or returns, catches outside a static initializer (an empty catch in a method is a different weakness), comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-665/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [665],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["initialization", "static-initializer", "swallowed-exception", "cwe-665"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_static_open(lines, s) if regex.match(`^\s*static\s*\{\s*(?://.*)?$`, lines[s])

_static_open(lines, s) if {
	regex.match(`^\s*static\s*$`, lines[s])
	s + 1 < count(lines)
	regex.match(`^\s*\{\s*$`, lines[s + 1])
}

# The closing brace of the static block: the first `}` at or above the
# `static` line's indent after it.
_static_end(lines, s) := e if {
	is := _indent(lines[s])
	last := min([count(lines) - 1, s + 150])
	ends := [k |
		some k in numbers.range(s + 2, last)
		_indent(lines[k]) <= is
		startswith(trim_left(lines[k], " \t"), "}")
	]
	e := min(array.concat([last], ends))
}

_catch_re := `\bcatch\s*\([^)]*\)\s*\{(.*)$`

# One-line catch body: `catch (E e) {}` or `catch (E e) { log(e); }`.
_body(lines, k, rest) := [b] if {
	contains(rest, "}")
	b := substring(rest, 0, indexof(rest, "}"))
}

_body(lines, k, rest) := body if {
	not contains(rest, "}")
	ik := _indent(lines[k])
	last := min([count(lines) - 1, k + 15])
	closes := [c |
		some c in numbers.range(k + 1, last)
		_indent(lines[c]) <= ik
		startswith(trim_left(lines[c], " \t"), "}")
	]
	count(closes) > 0
	c := min(closes)
	body := array.concat([rest], [lines[j] | some j in helpers.span(k + 1, c - 1); j > k; j < c])
}

# The line holding the catch's opening brace and the text after it:
# `catch (E e) {` or, with Allman braces, `catch (E e)` then `{`.
_catch_open(lines, k) := [k, m[0][1]] if {
	m := regex.find_all_string_submatch_n(_catch_re, lines[k], 1)
	count(m) > 0
}

_catch_open(lines, k) := [k + 1, m[0][1]] if {
	regex.match(`\bcatch\s*\([^)]*\)\s*(?://.*)?$`, lines[k])
	k + 1 < count(lines)
	m := regex.find_all_string_submatch_n(`^\s*\{(.*)$`, lines[k + 1], 1)
	count(m) > 0
}

_ignorable(l) if trim_space(l) == ""

_ignorable(l) if helpers.is_comment_line(l)

_ignorable(l) if regex.match(`^\s*\w+\.printStackTrace\(\s*\)\s*;\s*$`, l)

_ignorable(l) if regex.match(`^\s*System\.(?:out|err)\.print\w*\(.*\)\s*;\s*$`, l)

_ignorable(l) if regex.match(`^\s*(?i:\w*log\w*)\.\w+\(.*\)\s*;\s*$`, l)

_swallowed(body) if {
	count([l | some l in body; not _ignorable(l)]) == 0
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?m)^\s*static\s*(?:\{|$)`, content)
	contains(content, "catch")
	lines := split(content, "\n")
	some s, sline in lines
	contains(sline, "static")
	_static_open(lines, s)
	e := _static_end(lines, s)
	some k in helpers.span(s + 1, e - 1)
	contains(lines[k], "catch")
	not helpers.is_comment_line(lines[k])
	[b, rest] := _catch_open(lines, k)
	body := _body(lines, b, rest)
	_swallowed(body)
	finding := {
		"rule_id": metadata.id,
		"message": "Static initializer swallows an exception: the class loads with its static state partly initialised and later callers fail far from the cause. Rethrow as ExceptionInInitializerError or assign a safe fallback",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": lines[k],
	}
}
