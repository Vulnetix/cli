# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1075

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1075",
	"name": "Unconditional Control Flow Transfer outside of Switch Block",
	"description": "A C goto that jumps backwards: goto L; where the label L: is defined earlier in the same function (no column-zero closing brace between the label and the goto, at most 150 lines above). A backward goto is a loop built from an unconditional jump, with no loop header to show its condition or bound, so it is easy to make it spin forever or re-run setup it should not. Not reported: forward gotos to a cleanup or error label further down (the accepted C error-unwinding idiom), a backward goto into an error-handling tail section (code after the label returns or jumps away at the label's own nesting level before the goto, so the jump cannot loop), a label with the same name in an earlier function, labels further than 150 lines above, and goto text inside comments (including a /* */ block whose lines carry no leading *) or string literals.",
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

_goto_re := `\bgoto\s+([A-Za-z_]\w*)\s*;`

_c_file(path) if endswith(path, ".c")

_c_file(path) if endswith(path, ".h")

# The label is defined above the goto, inside the same function.
_backward(lines, i, label) if {
	lo := max([0, i - 150])
	label_re := concat("", [`^\s*`, label, `\s*:([^:]|$)`])
	some k in numbers.range(lo, i - 1)
	regex.match(label_re, lines[k])
	not _function_end_between(lines, k, i)
	not _exits_between(lines, k, i)
}

_indent(line) := count(regex.find_all_string_submatch_n(`^[ \t]*`, line, 1)[0][0])

# Code after the label leaves the function or jumps away unconditionally
# before reaching the goto (a return or goto at the label's own nesting
# level): the label opens a tail section such as an error handler that the
# goto jumps back into, not a loop.
_exits_between(lines, k, i) if {
	body := [j | some j in numbers.range(k + 1, i - 1); trim_space(lines[j]) != ""]
	count(body) > 0
	base := _indent(lines[body[0]])
	some j in body
	_indent(lines[j]) <= base
	regex.match(`^\s*(return\b|goto\s+\w+\s*;|exit\s*\(|abort\s*\()`, lines[j])
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

# String literals blanked, so a "/*" glob opens no comment.
_nostr(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_function_end_between(lines, k, i) if {
	some j in numbers.range(k + 1, i - 1)
	startswith(lines[j], "}")
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`(?m)\bgoto\s+\w+\s*;`, content)
	lines := split(content, "\n")
	some i, line in lines
	i > 0
	contains(line, "goto")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_goto_re, line, 1)[0]
	not regex.match(`"[^"]*\bgoto\b|/\*.*\bgoto\b|//.*\bgoto\b`, line)
	_backward(lines, i, m[1])
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Backward goto %s builds a loop from an unconditional jump; use a for/while/do loop with an explicit condition", [m[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
