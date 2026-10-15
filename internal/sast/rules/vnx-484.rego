# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_484

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-484",
	"name": "Omitted Break Statement in Switch",
	"description": "A case or default label of a C, C++ or Java switch whose statements run into the next label of the same switch: the label has a body of its own, and its last statement is not a break, return, throw, continue, goto, yield or a call that does not return (exit, abort, System.exit), so control falls through into the next case. Not reported: stacked labels with no statements between them (case 1: case 2:), a fall-through marked as deliberate (a /* fall through */ or FALLTHROUGH comment, [[fallthrough]], __attribute__((fallthrough))), Java arrow labels (case X ->), which never fall through, the last label of a switch, and labels in comments or string literals. A body whose last statement is a bare if guarding the exit (if (x) return -1;, with no else) is reported, because the other branch falls through. A body ending in an inner block (an if/else or loop closed by a brace) is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-484/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [484],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["omitted-break", "switch", "fall-through", "cwe-484"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java"}

# One or more labels at the start of a line, then whatever follows them.
# `::` is allowed inside a label (case Kind::Login:); a char literal may hold a colon.
_label_re := `^\s*((?:(?:case\s+(?:'[^']*'|::|[^:'])+|default\s*):\s*)+)(.*)$`

_terminator_re := `(?:^|[^\w.])(?:break|return|throw|continue|goto|yield)\b|\b(?:exit|_exit|_Exit|abort|quick_exit|longjmp|siglongjmp|System\.exit|Runtime\.getRuntime\(\)\.halt|BUG)\s*\(|\bassert\s*\(\s*(?:0|false)\s*\)|\b(?:\w+_)?(?i:panic|abort|fatal|unreachable|terminate|die|exit|bug)(?:_\w+)?\s*\(|\b[a-z]\w*(?:Panic|Abort|Fatal|Exit|Die|Unreachable|Terminate)\s*\(|__builtin_unreachable|\[\[\s*(?:clang::|gnu::)?fallthrough\s*\]\]|__attribute__\s*\(\(\s*(?:__)?fallthrough|\bfallthrough\s*;|\bFALLTHROUGH\b|\bFALL_THROUGH\b`

# Deliberate-fallthrough annotation in a comment anywhere in the body.
_annot_re := `(?i)fall(?:s|ing)?[\s\-_]*thr(?:ough|u)|\bno\s*break\b|intentional`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])'`, `'x'`)

_is_label(line) if {
	regex.match(_label_re, _strip(line))
	not contains(line, "->")
}

_is_code(line) if {
	t := trim_space(line)
	t != ""
	not helpers.is_comment_line(line)
}

# The label opened at i falls through to the label at j.
_falls_through(lines, i, j, rest) if {
	body := [k | some k in numbers.range(i + 1, j - 1); k > i; k < j; _is_code(lines[k])]
	_has_body(lines, body, rest)
	braced := _is_braced(lines, i, body)
	last := _last_stmt(lines, body, rest, braced)
	not _terminates(last)
	not _annotated(lines, i, j)
}

# A terminator guarded by a bare if (no else) leaves on one branch only: the
# other branch falls into the next label.
_terminates(last) if {
	regex.match(_terminator_re, last)
	not _guarded(last)
}

_guarded(last) if {
	regex.match(`^if\s*\(`, last)
	not regex.match(`(?:^|[^\w])else(?:[^\w]|$)`, last)
	not regex.match(`\[\[\s*(?:clang::|gnu::)?fallthrough|__attribute__\s*\(\(\s*(?:__)?fallthrough|\bfallthrough\s*;|\bFALL_?THROUGH\b`, last)
}

_has_body(_, body, _) if count(body) > 0

_has_body(_, body, rest) if {
	count(body) == 0
	_stmt_text(rest) != ""
}

_stmt_text(rest) := t if {
	t := trim_space(regex.replace(rest, `//.*$|/\*.*?\*/`, ""))
}

# The last statement of the body. When the body is on the label's own line,
# that text. When the last line closes a brace: the braced case body's own
# close is looked through (case X: { ...; break; }); any other closing brace
# ends an inner if/else/loop whose paths cannot be judged line by line, so no
# statement is returned and nothing is reported.
_last_stmt(_, body, rest, _) := _stmt_text(rest) if count(body) == 0

_last_stmt(lines, body, _, _) := t if {
	count(body) > 0
	p := count(body) - 1
	not _brace_only(lines[body[p]])
	t := _stmt_at(lines, body, p)
}

_last_stmt(lines, body, _, braced) := t if {
	braced
	count(body) >= 2
	p := count(body) - 1
	_brace_only(lines[body[p]])
	not _brace_only(lines[body[p - 1]])
	not trim_space(lines[body[p - 1]]) == "{"
	t := _stmt_at(lines, body, p - 1)
}

_brace_only(l) if regex.match(`^\s*\}[\s;]*$`, l)

# The statement ending at body[p], joined with the continuation lines above it.
_stmt_at(lines, body, p) := t if {
	lo := max([0, p - 6])
	ends := [q |
		some q in numbers.range(lo, p - 1)
		q < p
		regex.match(`[;{}:]\s*(?://.*|/\*.*\*/\s*)?$`, lines[body[q]])
	]
	s := _first_after(ends, lo)
	t := concat(" ", [trim_space(lines[body[q]]) | some q in numbers.range(s, p)])
}

_first_after(ends, _) := max(ends) + 1 if count(ends) > 0

_first_after(ends, lo) := lo if count(ends) == 0

_is_braced(lines, i, body) := true if _braced(lines, i, body)

_is_braced(lines, i, body) := false if not _braced(lines, i, body)

_braced(lines, i, _) if endswith(trim_right(lines[i], " \t"), "{")

_braced(lines, _, body) if {
	count(body) > 0
	trim_space(lines[body[0]]) == "{"
}

_annotated(lines, i, j) if {
	some k in numbers.range(i, j)
	regex.match(_annot_re, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	contains(content, "case")
	regex.match(`(?m)^\s*case\s`, content)
	lines := split(content, "\n")
	labels := [k | some k, l in lines; regex.match(`^\s*(case\s|default\s*:)`, l); _is_label(l)]
	some x, i in labels
	line := lines[i]
	ii := _indent(line)
	# the next label of the same switch: same indent, no block closed between
	later := [j |
		some y, j in labels
		y > x
		j - i <= 120
		_indent(lines[j]) == ii
	]
	count(later) > 0
	j := later[0]
	not _closed(lines, i, j, ii)
	m := regex.find_all_string_submatch_n(_label_re, _strip(line), 1)
	rest := m[0][2]
	# several labels with bodies on one line is a deliberate unrolled
	# fall-through (Duff's device); a label inside a macro is expanded elsewhere
	not regex.match(`(^|[^\w])case\s`, rest)
	not endswith(trim_right(line, " \t"), "\\")
	not _in_macro(lines, i)
	_falls_through(lines, i, j, rest)
	finding := {
		"rule_id": metadata.id,
		"message": "This case falls through into the next label without a break, return or throw; add the missing break, or mark the fall-through as deliberate",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A line shallower than the label sits between i and j, or a closing brace at
# the label's own indent that is not the close of a braced case body: they are
# in different switches (the first one ended).
_closed(lines, i, j, ii) if {
	j - 1 >= i + 1
	some k in numbers.range(i + 1, j - 1)
	_is_code(lines[k])
	_indent(lines[k]) < ii
}

_closed(lines, i, j, ii) if {
	not endswith(trim_right(lines[i], " \t"), "{")
	j - 1 >= i + 1
	some k in numbers.range(i + 1, j - 1)
	_indent(lines[k]) == ii
	startswith(trim_space(lines[k]), "}")
}

_in_macro(lines, i) if {
	i > 0
	endswith(trim_right(lines[i - 1], " \t"), "\\")
}
