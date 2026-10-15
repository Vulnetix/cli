# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_390

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-390",
	"name": "Detection of Error Condition Without Action",
	"description": "A Java catch clause catches an exception and does nothing with it, so the failure is detected and then silently dropped and the program carries on with whatever partial state the try block left. Reported: a catch block whose body is empty (on one line, `catch (E e) {}`, or across lines with only blank lines before the closing brace, also with the opening brace on its own line), and a catch block whose only statement evaluates the exception and discards the result (`e.toString();`, `e.getMessage();`, on its own line or inline). Not reported: a catch block that logs, rethrows, returns, restores the interrupt flag or does anything else; an empty block that carries a comment explaining why (a documented decision); an exception variable named ignored, ignore, expected, unused or _ (Java's unnamed variable); test sources; and the pattern inside comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-390/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [390],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["error-handling", "cwe-390"],
}

# `catch (Type name) {` and whatever follows the brace on the same line.
_catch_re := `^(?:.*[};])?\s*catch\s*\(\s*(?:final\s+)?[\w.$|\s]+?\s+(\w+)\s*\)\s*\{(.*)$`

_deliberate := {"ignored", "ignore", "ignoredException", "expected", "unused", "_", "ignore_"}

# The body closes on the catch line with nothing in it.
_empty_body(_, _, _, rest, _) if regex.match(`^\s*\}`, rest)

# The body is on the following lines: only blank lines before the brace.
_empty_body(lines, i, _, rest, _) if {
	trim_space(rest) == ""
	j := _next_nonblank(lines, i)
	regex.match(`^\s*\}`, lines[j])
}

# On one line: `catch (E e) { e.getMessage(); }`.
_empty_body(_, _, v, rest, _) if regex.match(concat("", [`^\s*`, v, `\s*\.\s*(?:toString|getMessage|getLocalizedMessage|getCause)\s*\(\s*\)\s*;\s*\}`]), rest)

# The only statement evaluates the exception and drops the value.
_empty_body(lines, i, v, rest, _) if {
	trim_space(rest) == ""
	j := _next_nonblank(lines, i)
	regex.match(concat("", [`^\s*`, v, `\s*\.\s*(?:toString|getMessage|getLocalizedMessage|getCause)\s*\(\s*\)\s*;\s*$`]), lines[j])
	k := _next_nonblank(lines, j)
	regex.match(`^\s*\}`, lines[k])
}

_next_nonblank(lines, i) := j if {
	end := min([count(lines) - 1, i + 4])
	end >= i + 1
	cands := [k | some k in numbers.range(i + 1, end); trim_space(lines[k]) != ""]
	count(cands) > 0
	j := cands[0]
}

# String literals blanked so a quoted snippet is not code.
_unquote(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "catch")
	not helpers.is_test_path(path)
	regex.match(`(?m)catch\s*\([^)]*\)\s*(?:\{|$)`, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "catch")
	not helpers.is_comment_line(raw)
	line := _unquote(raw)
	c := _catch(lines, i, line)
	v := c[0]
	not _deliberate[v]
	_empty_body(lines, c[1], v, c[2], line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Exception '%s' is caught and dropped without any action: log it, rethrow it, or handle the failure (comment the block if ignoring it is deliberate)", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

# `catch (E e) {` with the brace on the catch line.
_catch(_, i, line) := [m[0][1], i, m[0][2]] if {
	m := regex.find_all_string_submatch_n(_catch_re, line, 1)
	count(m) > 0
}

# Allman style: `catch (E e)` and the brace alone on the next line.
_catch(lines, i, line) := [m[0][1], j, b[0][1]] if {
	m := regex.find_all_string_submatch_n(`^(?:.*[};])?\s*catch\s*\(\s*(?:final\s+)?[\w.$|\s]+?\s+(\w+)\s*\)\s*$`, line, 1)
	count(m) > 0
	j := _next_nonblank(lines, i)
	b := regex.find_all_string_submatch_n(`^\s*\{(.*)$`, _unquote(lines[j]), 1)
	count(b) > 0
}
