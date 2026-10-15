# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_755

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-755",
	"name": "Interrupt or JVM error caught and swallowed",
	"description": "A Java catch block handles one of the exceptional conditions that must not be absorbed, and then carries on. Reported: catch (InterruptedException e), alone or in a multi-catch, whose body neither restores the interrupt (Thread.currentThread().interrupt()) nor rethrows nor leaves the loop or method (return, break), and is not the last statement of a thread body (run(), call() or a lambda, which ends right after it), so the thread's cancellation request is lost and shutdown, timeouts and executor cancellation stop working; and catch of a JVM Error (Error, VirtualMachineError, OutOfMemoryError, StackOverflowError, InternalError, ThreadDeath, LinkageError), alone or in a multi-catch, whose body neither rethrows nor ends the process (System.exit, Runtime.halt), so the program keeps running in a state the JVM has declared unrecoverable. Not reported: handlers that restore the interrupt, rethrow or wrap (throw ...), or return/break out of the work, an interrupt handler that ends a run()/call()/lambda body; catch (Throwable) and catch (Exception), which VNX-396 (discarded generic catch) and VNX-391 (empty catch) cover; test code, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-755/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [755],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["exceptional-conditions", "interrupted-exception", "cwe-755"],
}

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

_catch_re := `\bcatch\s*\(\s*(?:final\s+)?((?:[\w.]+\s*\|\s*)*[\w.]+)\s+\w+\s*\)`

_errors := {"Error", "VirtualMachineError", "OutOfMemoryError", "StackOverflowError", "InternalError", "ThreadDeath", "LinkageError"}

_types(code) := {t |
	m := regex.find_all_string_submatch_n(_catch_re, code, 1)
	count(m) > 0
	some raw in split(m[0][1], "|")
	parts := split(trim_space(raw), ".")
	t := parts[count(parts) - 1]
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The handler's body: text after the catch's `{` on its own line when it also
# closes there, otherwise the following lines up to the closing brace at the
# catch's indent (bounded to 40 lines).
_body(lines, i, code) := b if {
	after := regex.replace(code, `^.*?\bcatch\s*\([^)]*\)\s*\{`, "")
	contains(after, "}")
	b := after
} else := b if {
	ind := _indent(lines[i])
	limit := min([count(lines) - 1, i + 40])
	i + 1 <= limit
	ends := [k |
		some k in numbers.range(i + 1, limit)
		trim_space(lines[k]) != ""
		_indent(lines[k]) <= ind
	]
	e := min(array.concat([limit], ends))
	b := concat("\n", [_code(lines[k]) |
		some k in numbers.range(i, max([i, e - 1]))
		not helpers.is_comment_line(lines[k])
	])
}

# The line holding the handler's closing brace.
_handler_end(lines, i, code) := i if {
	after := regex.replace(code, `^.*?\bcatch\s*\([^)]*\)\s*\{`, "")
	contains(after, "}")
} else := e if {
	ind := _indent(lines[i])
	limit := min([count(lines) - 1, i + 40])
	i + 1 <= limit
	ends := [k |
		some k in numbers.range(i + 1, limit)
		trim_space(lines[k]) != ""
		_indent(lines[k]) <= ind
	]
	count(ends) > 0
	e := min(ends)
}

# The try statement is the last thing a thread body does (run(), call() or a
# lambda): the next code line after the handler closes that body, so the thread
# leaves the work right after the handler, which is as good as a return.
_nothing_follows(lines, i, code, "interrupt") if {
	h := _handler_end(lines, i, code)
	k := helpers.next_code_index(lines, h, 3)
	regex.match(`^\s*\}\s*;?\s*$|^\s*\}\s*\)\s*;?\s*$`, lines[k])
	ik := _indent(lines[k])
	k >= 1
	opens := [j |
		some j in numbers.range(max([0, k - 200]), k - 1)
		_indent(lines[j]) == ik
		regex.match(`\{\s*$`, lines[j])
	]
	count(opens) > 0
	opener := lines[opens[count(opens) - 1]]
	regex.match(`\b(void\s+run|call)\s*\(\s*\)|->\s*\{`, opener)
}

_kind(types, body) :="interrupt" if {
	"InterruptedException" in types
	not regex.match(`\.interrupt\s*\(\s*\)|\bthrow\b|\breturn\b|\bbreak\b`, body)
} else := "error" if {
	some t in types
	t in _errors
	not regex.match(`\bthrow\b|\bSystem\.exit\s*\(|\.halt\s*\(`, body)
}

_message := {
	"interrupt": "InterruptedException is caught and the interrupt is dropped: the thread no longer knows it was asked to stop. Call Thread.currentThread().interrupt() in the handler, rethrow, or exit the task",
	"error": "A JVM Error (OutOfMemoryError, StackOverflowError, ...) is caught and execution continues in an unrecoverable state. Let it propagate, or rethrow after cleanup",
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "catch")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "catch")
	not helpers.is_comment_line(line)
	code := _code(line)
	types := _types(code)
	count(types) > 0
	kind := _kind(types, _body(lines, i, code))
	not _nothing_follows(lines, i, code, kind)
	finding := {
		"rule_id": metadata.id,
		"message": _message[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
