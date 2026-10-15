# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_769

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-769",
	"name": "Uncontrolled File Descriptor Consumption",
	"description": "Reports Python code that opens a new file or socket handle on every iteration of a loop and keeps it open: a handle assigned to a name inside a for/while body (`fh = open(p)`, `io.open`, `codecs.open`, `gzip.open`, `bz2.open`, `lzma.open`, `tarfile.open`, `os.open`, `socket.socket(...)`, `socket.create_connection(...)`, a lowercase receiver's `.open()` such as pathlib's `path.open()`) that the loop body never closes (`fh.close()`, a deferred `fh.close` passed to atexit.register or stack.callback, `os.close(fd)`, `with fh`, `contextlib.closing(fh)`), handles appended to a collection inside a loop (`handles.append(open(p))`), and a list, set or dict comprehension that opens one handle per element (`[open(p) for p in paths]`); neither form is followed by a close within 30 lines. Each iteration consumes a descriptor, so input with enough elements exhausts the process limit (EMFILE). CWE-769 is deprecated in favour of CWE-774; the number is kept for rule identity. Not reported: `with` blocks, handles closed or yielded in the loop body, a loop that breaks or returns after the open (the first-openable-candidate idiom), handles chained straight into a read (`open(p).read()`), generator expressions, handles opened outside a loop (VNX-775 reports a missing close there), comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-769/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [769],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["file-descriptor-exhaustion", "cwe-769"],
}

# The fixed openers, plus a lowercase receiver's .open() (pathlib's
# path.open(), wave/shelve/dbm.open).
_opener := `(?:open|io\.open|codecs\.open|gzip\.open|bz2\.open|lzma\.open|tarfile\.open|os\.open|socket\.socket|socket\.create_connection|[a-z_]\w*\.open)\(`

_assign_re := concat("", [`^\s*([A-Za-z_]\w*)\s*=\s*`, _opener])

_collect_re := concat("", [`\.(?:append|add|put|extend)\(\s*`, _opener])

_comprehension_re := concat("", [`[\[{]\s*(?:[\w.]+\s*:\s*)?`, _opener, `[^()]*(?:\([^()]*\)[^()]*)*\)\s+for\b`])

_indent(line) := count(line) - count(trim_left(line, " \t"))

_code_line(line) if {
	trim_space(line) != ""
	not helpers.is_comment_line(line)
}

# Lines that open or close a triple-quoted string; a line between an odd
# and the following even toggle is string content, not code.
_toggles(lines) := [k |
	some k, l in lines
	_odd_triples(l)
]

_odd_triples(l) if {
	n := count(regex.find_all_string_submatch_n(`"""|'''`, l, -1))
	n % 2 == 1
}

_in_string(toggles, i) if {
	before := [k | some k in toggles; k < i]
	count(before) % 2 == 1
}

# The nearest enclosing header matching re, within `span` lines above i.
_encloser(lines, i, span, re) := j if {
	ind := _indent(lines[i])
	cands := [k |
		some k in numbers.range(max([0, i - span]), i - 1)
		_indent(lines[k]) < ind
		regex.match(re, lines[k])
		not _dedent_between(lines, k, i)
	]
	count(cands) > 0
	j := max(cands)
}

_dedent_between(lines, k, i) if {
	k + 1 <= i - 1
	ik := _indent(lines[k])
	some m in numbers.range(k + 1, i - 1)
	_code_line(lines[m])
	_indent(lines[m]) <= ik
}

_loop_re := `^\s*(?:async\s+)?(?:for|while)\b.*:\s*(?:#.*)?$`

_def_re := `^\s*(?:async\s+)?def\s+\w+`

# Last line of the block opened at header j, bounded by `span` lines.
_block_end(lines, j, span) := e if {
	n := count(lines) - 1
	limit := min([n, j + span])
	ij := _indent(lines[j])
	outs := [k |
		some k in numbers.range(j + 1, limit)
		_code_line(lines[k])
		_indent(lines[k]) <= ij
	]
	e := min(array.concat([limit + 1], outs)) - 1
}

# fh.close() and a deferred fh.close (atexit.register, stack.callback)
_released(l, v) if regex.match(concat("", [`\b`, v, `\.close\b`]), l)

_released(l, v) if regex.match(concat("", [`\bclose\(\s*`, v, `\s*\)`]), l)

_released(l, v) if regex.match(concat("", [`\b(?:with|async\s+with)\s+`, v, `\b`]), l)

_released(l, v) if regex.match(concat("", [`\b(?:closing|enter_context|wrap_socket|register|append|add|put|push)\(\s*`, v, `\s*[,)]`]), l)

_released(l, v) if regex.match(concat("", [`^\s*(?:return|yield)\s+`, v, `\s*(?:,|$|\))`]), l)

_released(l, v) if regex.match(concat("", [`^\s*(?:return|yield)\s+[A-Z][\w.]*\(\s*(?:[^)]*,\s*)?`, v, `\b`]), l)

_released(l, v) if regex.match(concat("", [`^\s*[\w.]+(?:\[[^\]]*\])?\s*=\s*`, v, `\s*$`]), l)

_released(l, v) if regex.match(concat("", [`=\s*\(?\s*`, v, `\s*,|,\s*`, v, `\s*\)?\s*$`]), l)

_released_in(lines, a, b, v) if {
	some k in numbers.range(a, b)
	not helpers.is_comment_line(lines[k])
	_released(lines[k], v)
}

_no_close_after(lines, i) if {
	not _close_after(lines, i)
}

_close_after(lines, i) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 30]))
	not helpers.is_comment_line(lines[k])
	regex.match(`\.close\(|\bclosing\(|\bwith\s`, lines[k])
}

_candidate(line) if regex.match(_assign_re, line)

_candidate(line) if regex.match(_collect_re, line)

_candidate(line) if regex.match(_comprehension_re, line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(concat("", [`(?m)(?:=\s*|[\[{(:]\s*)`, _opener]), content)
	lines := split(content, "\n")
	toggles := _toggles(lines)
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	_candidate(line)
	not _in_string(toggles, i)
	_leaks(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "A new file or socket handle is opened per iteration and kept open; close it in the loop (with-block) or bound how many are held at once",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# fh = open(p) inside a loop body that never releases fh
_leaks(lines, i, line) if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	not regex.match(`\)\s*\.\w`, line)
	v := m[0][1]
	j := _encloser(lines, i, 40, _loop_re)
	e := _block_end(lines, j, 80)
	not _released_in(lines, i + 1, e, v)
	not _exits_loop(lines, i, e, j)
}

# The loop body breaks or returns after the open at the loop's own body
# level (the first-openable-candidate idiom), so handles do not pile up.
_exits_loop(lines, i, e, j) if {
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	regex.match(`^\s*(?:break|return)\b`, lines[k])
	_indent(lines[k]) <= _indent(lines[i])
	_indent(lines[k]) > _indent(lines[j])
}

# handles.append(open(p)) inside a loop
_leaks(lines, i, line) if {
	regex.match(_collect_re, line)
	not regex.match(`\)\s*\.\w`, line)
	_encloser(lines, i, 40, _loop_re)
	_no_close_after(lines, i)
}

# [open(p) for p in paths]
_leaks(lines, i, line) if {
	regex.match(_comprehension_re, line)
	_no_close_after(lines, i)
}
