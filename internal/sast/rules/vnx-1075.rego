# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1075

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1075",
	"name": "Unconditional Control Flow Transfer outside of Switch Block",
	"description": "A C goto that jumps backwards (in .c and .h files): goto L; where the label L: is defined earlier in the same function (no column-zero closing brace between the label and the goto, at most 400 lines above). A backward goto is a loop built from an unconditional jump, with no loop header to show its condition or bound, so it is easy to make it spin forever or re-run setup it should not. A retry that jumps forward to an error handler which then jumps back (try_again: ... goto socket_err; ... socket_err: ... goto try_again;) is such a loop and is reported. Not reported: forward gotos to a cleanup or error label further down (the accepted C error-unwinding idiom), a backward goto into an error-handling tail section (code after the label returns, exits, continues, breaks or jumps away at the label's own nesting level before the goto, so the jump cannot loop), a goto whose same-name label also appears below it in the same function, a label with the same name in an earlier function, labels further than 400 lines above, computed gotos (goto *ptr), and goto text inside comments (including a /* */ block whose lines carry no leading *) or string literals. Backward gotos in C++ files (.cc, .cpp, .cxx, .hpp, .hh) are reported by VNX-1119.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1075/",
	"languages": ["c"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1075],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["unconditional-control-flow", "backward-goto", "cwe-1075"],
}

# C sources and headers. C++ files belong to VNX-1119, which reports the
# same backward goto there; one line is one finding.
_c_file(path) if endswith(path, ".c")

_c_file(path) if endswith(path, ".h")

_goto_re := `\bgoto\s+([A-Za-z_]\w*)\s*;`

_label_re := `^\s*([A-Za-z_]\w*)\s*:(?:[^:]|$)`

_not_label := {"default", "public", "private", "protected", "case"}

# String and character literals blanked, so a "/*" glob opens no comment
# and "goto again;" in a message is not code.
_nostr(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# The line's code: literals blanked and trailing or inline comments removed.
_code(line) := regex.replace(_nostr(line), `//.*$|/\*.*?(?:\*/|$)`, "")

# The goto target named on a line of code.
_goto_target(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_goto_re, _code(line), 1)
	count(m) > 0
}

_is_label(line, name) if {
	m := regex.find_all_string_submatch_n(_label_re, line, 1)
	count(m) > 0
	m[0][1] == name
	not _not_label[name]
}

# A column-0 closing brace ends a function: a label above one belongs to an
# earlier function.
_crosses_function(lines, k, i) if {
	some j in numbers.range(k + 1, i - 1)
	startswith(lines[j], "}")
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Error-unwinding sections chain labels: write_error: ... goto error; jumps
# back to a handler that ends in return. That is not a loop. When the code
# under the label leaves the function (return, exit, abort) or the label's
# block (continue, break: a shared loop tail) or jumps on unconditionally at
# the label's own statement level before reaching the goto, control cannot
# come back round, so the goto is a chained handler.
#
# Unless the code under the label jumps forward, past that exit, to a second
# label that falls through to the goto (try_again: ... goto socket_err; ...
# return; socket_err: ... goto try_again;): that is a retry loop.
_exits_between(lines, k, i) if {
	b := helpers.next_code_index(lines, k, 6)
	bi := _indent(lines[b])
	exits := [j |
		some j in numbers.range(k + 1, i - 1)
		regex.match(`^\s*(?:return\b|continue\s*;|break\s*;|goto\s+\w+\s*;|exit\s*\(|abort\s*\(|_exit\s*\()`, lines[j])
		_indent(lines[j]) <= bi
	]
	count(exits) > 0
	not _loops_back(lines, k, max(exits), i)
}

_loops_back(lines, k, jx, i) if {
	some m in numbers.range(jx + 1, i - 1)
	lm := regex.find_all_string_submatch_n(_label_re, lines[m], 1)
	count(lm) > 0
	name := lm[0][1]
	not _not_label[name]
	some p in numbers.range(k + 1, jx - 1)
	_goto_target(lines[p]) == name
}

# Labels are unique within a function, so a label of the same name below the
# goto, before the function ends, is its target: the goto is forward.
_forward_label(lines, i, name) if {
	end := min([count(lines) - 1, i + 400])
	stops := [j | some j in numbers.range(i + 1, end); startswith(lines[j], "}")]
	last := min(array.concat([end], stops))
	some j in numbers.range(i + 1, last)
	contains(lines[j], name)
	_is_label(lines[j], name)
}

# The line sits inside a /* ... */ block opened at most 60 lines above (a
# commented-out or documented example whose lines carry no leading `*`).
_in_block_comment(lines, i) if {
	opens := [k | some k in numbers.range(max([0, i - 60]), i - 1); contains(_nostr(lines[k]), "/*")]
	count(opens) > 0
	o := opens[count(opens) - 1]
	not contains(regex.replace(_nostr(lines[o]), `^.*?/\*`, ""), "*/")
	not _closed_between(lines, o, i)
}

_closed_between(lines, o, i) if {
	some k in numbers.range(o + 1, i)
	k < i
	contains(lines[k], "*/")
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`\bgoto\s+[A-Za-z_]`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "goto")
	not helpers.is_comment_line(line)
	name := _goto_target(line)
	labels := [k |
		some k in numbers.range(max([0, i - 400]), i - 1)
		contains(lines[k], name)
		_is_label(lines[k], name)
	]
	count(labels) > 0
	k := max(labels)
	not _crosses_function(lines, k, i)
	not _exits_between(lines, k, i)
	not _forward_label(lines, i, name)
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Backward goto %s builds a loop from an unconditional jump; use a for/while/do loop with an explicit condition", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
