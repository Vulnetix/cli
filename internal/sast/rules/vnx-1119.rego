# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1119

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1119",
	"name": "Excessive Use of Unconditional Branching",
	"description": "A backward goto in C++ (.cc, .cpp, .cxx, .hpp, .hh files): goto <label>; where the label is defined earlier in the same function, so the goto builds a loop (retry, again, restart, top) out of unconditional jumps instead of a while/for/do statement. Backward jumps are what make goto-heavy code hard to follow and are how a retry path loops forever or re-enters with stale state. Not reported: forward gotos to a cleanup or error label (goto out, goto err, goto cleanup, the idiomatic C error-unwinding pattern), a label of the same name in an earlier function, gotos in comments and string literals, computed gotos (goto *ptr), a goto to a label that leaves through continue or break (a shared loop tail, not a loop), and a goto whose same-name label also appears below it in the same function (it is forward), and gotos inside a /* */ block whose lines carry no leading *. Backward gotos in C files (.c, .h) are reported by VNX-1075.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1119/",
	"languages": ["cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1119],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-unconditional-branching", "cwe-1119", "maintainability", "c", "cpp"],
}

# C++ sources and headers. A backward goto in C (.c, .h) is the same loop
# and is reported by VNX-1075; one line is one finding.
_ext(path) if regex.match(`\.(cc|cpp|cxx|hpp|hh)$`, path)

# String literals blanked, so a "/*" inside one opens no comment.
_nostr(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

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

_goto_re := `^(?:[^"'/]|/[^/*])*\bgoto\s+([A-Za-z_]\w*)\s*;`

_not_label := {"default", "public", "private", "protected", "case"}

_is_label(line, name) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*:(?:[^:]|$)`, line, 1)
	count(m) > 0
	m[0][1] == name
	not _not_label[name]
}

# A column-0 closing brace ends a function: a label above one belongs to an
# earlier function.
_crosses_function(lines, k, i) if {
	some j in helpers.span(k + 1, i - 1)
	regex.match(`^\}`, lines[j])
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Error-unwinding sections chain labels: write_error: ... goto error; jumps
# back to a handler that ends in return. That is not a loop. When the code
# under the label leaves the function (return, exit, abort) or the label's block (continue, break: a shared loop tail) or jumps on
# unconditionally at the label's own statement level before reaching the
# goto, control cannot come back round, so the goto is a chained handler.
#
# Unless the code under the label jumps forward, past that exit, to a second
# label that falls through to the goto (try_again: ... goto socket_err; ...
# return; socket_err: ... goto try_again;): that is a retry loop.
_exits_between(lines, k, i) if {
	b := helpers.next_code_index(lines, k, 6)
	bi := _indent(lines[b])
	exits := [j |
		some j in helpers.span(k + 1, i - 1)
		regex.match(`^\s*(?:return\b|continue\s*;|break\s*;|goto\s+\w+\s*;|exit\s*\(|abort\s*\(|_exit\s*\()`, lines[j])
		_indent(lines[j]) <= bi
	]
	count(exits) > 0
	not _loops_back(lines, k, max(exits), i)
}

_loops_back(lines, k, jx, i) if {
	some m in helpers.span(jx + 1, i - 1)
	lm := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*:(?:[^:]|$)`, lines[m], 1)
	count(lm) > 0
	name := lm[0][1]
	not _not_label[name]
	some p in helpers.span(k + 1, jx - 1)
	gm := regex.find_all_string_submatch_n(_goto_re, lines[p], 1)
	count(gm) > 0
	gm[0][1] == name
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	regex.match(`\bgoto\s+[A-Za-z_]`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "goto")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_goto_re, line, 1)
	count(m) > 0
	name := m[0][1]
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
		"message": sprintf("Backward goto %s: the label is defined %d lines above, so this jump is a loop written as an unconditional branch", [name, i - k]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Labels are unique within a function, so a label of the same name below the
# goto, before the function ends, is its target: the goto is forward, and the
# label above belongs to another function whose end the column-0 brace test
# could not see (inline C++ methods inside a class body are indented).
_forward_label(lines, i, name) if {
	end := min([count(lines) - 1, i + 400])
	stops := [j | some j in numbers.range(i + 1, end); regex.match(`^\}`, lines[j])]
	last := min(array.concat([end], stops))
	some j in numbers.range(i + 1, last)
	contains(lines[j], name)
	_is_label(lines[j], name)
}
