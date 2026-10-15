# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_835

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-835",
	"name": "Loop with Unreachable Exit Condition ('Infinite Loop')",
	"description": "A while loop whose condition compares a variable against a bound (while i < n, while (offset <= limit), while (tries != attempts)) but whose body never changes either side and has no other way out: the variable is never assigned, incremented or rebound, the bound variable is never assigned and the collection it is read from (len(q), q.size(), items.length) is never mutated through a method call, and the body has no break, return, throw, raise, yield or exit call. Once the condition is true it stays true, so the loop never ends (CPU exhaustion, a hung request). A bound may be a variable, a collection size or a numeric literal. Java, JavaScript/TypeScript and Python. Not reported: a body that blocks or yields (wait(), sleep(), join(), await) unless the variable is a local or parameter not written between its declaration and the loop, since a field, a global or a variable captured by a callback can be changed by another thread or handler; deliberate infinite loops (while True, while (true), for (;;)), which are almost always server or worker loops, do-while loops, a body that advances the variable in any form (i++, ++i, i += 1, i = next(i), tuple assignment, walrus, an inner for over it), a loop that exits by break/return/throw, conditions on fields or method calls alone, a body longer than 60 lines, and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-835/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [835],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["infinite-loop", "denial-of-service", "cwe-835"],
}

_brace_ext := {".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_kind(path) := "brace" if {
	some ext in _brace_ext
	endswith(path, ext)
}

_kind(path) := "py" if endswith(path, ".py")

_bound := `([A-Za-z_][\w\.]*(?:\(\))?|len\(\s*[A-Za-z_][\w\.]*\s*\)|\d+)`

_head_re := {
	"brace": concat("", [`^\s*while\s*\(\s*([A-Za-z_]\w*)\s*(<=|>=|<|>|!==|!=)\s*`, _bound, `\s*\)\s*\{\s*$`]),
	"py": concat("", [`^\s*while\s+\(?\s*([A-Za-z_]\w*)\s*(<=|>=|<|>|!=)\s*`, _bound, `\s*\)?\s*:\s*(#.*)?$`]),
}

# String literals blanked, so "offset=" + offset is not an assignment.
_strip(line) := regex.replace(line, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`[^`]*`", "\"\"")

_indent(line) := count(line) - count(trim_left(line, " \t"))

# End of a brace body: the first `}` at or above the header's indentation.
_body_end("brace", lines, i) := min(ends) if {
	ii := _indent(lines[i])
	ends := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 60]))
		_indent(lines[k]) <= ii
		startswith(trim_left(lines[k], " \t"), "}")
	]
	count(ends) > 0
}

# End of a Python body: the first code line at or above the header's
# indentation, or the end of the file.
_body_end("py", lines, i) := e if {
	ii := _indent(lines[i])
	last := min([count(lines) - 1, i + 60])
	ends := [k |
		some k in numbers.range(i + 1, last)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
		_indent(lines[k]) <= ii
	]
	e := _py_end(ends, last, count(lines))
}

_py_end(ends, _, _) := min(ends) if count(ends) > 0

_py_end(ends, last, n) := n if {
	count(ends) == 0
	last == n - 1
}

_writes(body, v) if regex.match(concat("", [`(?:^|[^\w.])`, v, `\s*(?:\+\+|--|(?:[-+*/%&|^:]|<<|>>>?|\*\*|//)?=(?:[^=]|$))`]), body)

_writes(body, v) if regex.match(concat("", [`(?:\+\+|--)\s*`, v, `\b`]), body)

_writes(body, v) if regex.match(concat("", [`(?m)(?:^|[^\w.])`, v, `\s*,[^=\n]*=(?:[^=]|$)`]), body)

_writes(body, v) if regex.match(concat("", [`(?m),\s*`, v, `\s*(?:,[^=\n]*)?=(?:[^=]|$)`]), body)

_writes(body, v) if regex.match(concat("", [`\bfor\s+`, v, `\s+in\b`]), body)

_exits(body) if regex.match(`\b(break|return|throw|raise|yield)\b|\b(System\.exit|process\.exit|sys\.exit|os\._exit|exit|quit|abort)\s*\(`, body)

# The bound side can change: a plain variable assigned in the body, or the
# object it is read from mutated by a method call or reassigned.
_bound_changes(body, b) if {
	regex.match(`^[A-Za-z_]\w*$`, b)
	_writes(body, b)
}

_bound_changes(body, b) if {
	not regex.match(`^[A-Za-z_]\w*$`, b)
	m := regex.find_all_string_submatch_n(`^(?:len\(\s*)?([A-Za-z_]\w*)`, b, 1)
	recv := m[0][1]
	_receiver_touched(body, recv)
}

# A body that blocks or yields (wait(), await, sleep(), join()) lets other
# code run: a field, a global or a variable captured by a callback can then be
# changed by another thread or handler. Such a loop is reported only when the
# variable is a local or parameter declared above and not written anywhere
# between its declaration and the loop.
_yields(body) if regex.match(`\bawait\b|\b(?:wait|sleep|join|park\w*|acquire|take|poll)\s*\(`, body)

_changed_elsewhere(k, lines, i, body, v) if {
	_yields(body)
	not _confined(k, lines, i, v)
}

_decl_re := {
	"brace": `\b(?:int|long|short|byte|char|double|float|var|let|Integer|Long|number)\s+%s\s*(?:[=;,)]|:\s*\w+\s*[=;,)])|[\(,]\s*%s\s*:\s*\w+\s*[,)=]`,
	"py": `^\s+%s\s*(?::\s*\w+\s*)?=[^=]|^\s*(?:async\s+)?def\s+\w+\s*\(.*\b%s\b`,
}

_confined(k, lines, i, v) if {
	re := sprintf(_decl_re[k], [v, v])
	some j in numbers.range(max([0, i - 40]), i - 1)
	regex.match(re, lines[j])
	not regex.match(`^\s*(?:@\w+\s+)*(?:private|protected|public|static|volatile|readonly)\b[^(]*$`, lines[j])
	not helpers.is_comment_line(lines[j])
	between := concat("\n", [_strip(lines[m]) | some m in numbers.range(j, i); m > j; m < i])
	not _writes(between, v)
	not regex.match(concat("", [`\b(?:global|nonlocal)\b[^\n]*\b`, v, `\b`]), between)
}

_receiver_touched(body, recv) if regex.match(concat("", [`\b`, recv, `\s*\.\s*\w+\s*\(`]), body)

_receiver_touched(body, recv) if _writes(body, recv)

_receiver_touched(body, recv) if regex.match(concat("", [`\b`, recv, `\s*\[[^\]]*\]\s*=(?:[^=]|$)`]), body)

findings contains finding if {
	some path, content in input.file_contents
	k := _kind(path)
	regex.match(`(?m)^\s*while\s*\(?\s*[A-Za-z_]\w*\s*[<>!]`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "while")
	m := regex.find_all_string_submatch_n(_head_re[k], line, 1)
	count(m) > 0
	v := m[0][1]
	b := m[0][3]
	e := _body_end(k, lines, i)
	e > i + 1
	body := concat("\n", [l | some j in numbers.range(i + 1, e - 1); l := _strip(lines[j]); not helpers.is_comment_line(lines[j])])
	not _writes(body, v)
	not _exits(body)
	not _bound_changes(body, b)
	not _changed_elsewhere(k, lines, i, body, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Loop condition on '%s' can never become false: the body never changes '%s' or '%s' and has no break, return or throw. Advance the loop variable or add an exit", [v, v, b]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
