# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_775

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-775",
	"name": "Missing Release of File Descriptor or Handle after Effective Lifetime",
	"description": "Reports a Python function that assigns a file or socket handle to a local name (`x = open(...)`, `io.open`, `codecs.open`, `gzip.open`, `bz2.open`, `lzma.open`, `tarfile.open`, `os.open`, `socket.socket(...)`, `socket.create_connection(...)`, a lowercase receiver's `.open()` such as pathlib's `p.open()`) and never releases it in that function: no `x.close()` or deferred `x.close` (atexit.register, stack.callback), `os.close(x)`, `with x`, `contextlib.closing(x)` or `enter_context(x)`. The descriptor then stays open until the garbage collector happens to finalise the object (never, for os.open's integer), which under load exhausts the process's descriptor limit. Not reported: handles opened in a `with` statement, handles the function returns, yields or wraps (`return x`, `yield from x`, `return Wrapper(x)`, `ctx.wrap_socket(x)`), stores on an object or in a collection (`self.sock = ...`, `self.files.append(x)`), handles chained straight into a read (`open(p).read()`), module-level handles (program lifetime), handles opened inside a loop body (VNX-769 reports those), `webbrowser.open(url)` (a flag, not a handle), comments, string literals and test files. This rule owns Python handle leaks; VNX-404 reports the Java ones.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-775/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [775],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["handle-leak", "cwe-775"],
}

_open_re := `^\s*([A-Za-z_]\w*)\s*=\s*(?:open|io\.open|codecs\.open|gzip\.open|bz2\.open|lzma\.open|tarfile\.open|os\.open|socket\.socket|socket\.create_connection|[a-z_]\w*\.open)\(`

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
	some m in helpers.span(k + 1, i - 1)
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

_released(l, v) if regex.match(concat("", [`\b`, v, `\.close\b`]), l)

_released(l, v) if regex.match(concat("", [`\bclose\(\s*`, v, `\s*\)`]), l)

_released(l, v) if regex.match(concat("", [`\b(?:with|async\s+with)\s+`, v, `\b`]), l)

_released(l, v) if regex.match(concat("", [`\b(?:closing|enter_context|wrap_socket|register|append|add|put|push)\(\s*`, v, `\s*[,)]`]), l)

_released(l, v) if regex.match(concat("", [`^\s*(?:return|yield(?:\s+from)?)\s+`, v, `\s*(?:,|$|\))`]), l)

_released(l, v) if regex.match(concat("", [`^\s*(?:return|yield)\s+[A-Z][\w.]*\(\s*(?:[^)]*,\s*)?`, v, `\b`]), l)

_released(l, v) if regex.match(concat("", [`^\s*[\w.]+(?:\[[^\]]*\])?\s*=\s*`, v, `\s*$`]), l)

_released(l, v) if regex.match(concat("", [`=\s*\(?\s*`, v, `\s*,|,\s*`, v, `\s*\)?\s*$`]), l)

_released_in(lines, a, b, v) if {
	some k in numbers.range(a, b)
	not helpers.is_comment_line(lines[k])
	_released(lines[k], v)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*\w+\s*=\s*(?:open|io\.open|codecs\.open|gzip\.open|bz2\.open|lzma\.open|tarfile\.open|os\.open|socket\.socket|socket\.create_connection|[a-z_]\w*\.open)\(`, content)
	lines := split(content, "\n")
	toggles := _toggles(lines)
	some i, line in lines
	contains(line, "(")
	m := regex.find_all_string_submatch_n(_open_re, line, 1)
	count(m) > 0
	not regex.match(`\)\s*\.\w`, line)
	# webbrowser.open returns a bool, not a handle
	not regex.match(`=\s*webbrowser\.open\(`, line)
	not _in_string(toggles, i)
	v := m[0][1]
	d := _encloser(lines, i, 200, _def_re)
	not _loop_inside(lines, i, d)
	e := _block_end(lines, d, 300)
	not _released_in(lines, i + 1, e, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Handle '%s' is opened here and never closed in this function; use a with-block or close it in a finally", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# a loop of this function encloses line i (VNX-769's shape)
_loop_inside(lines, i, d) if {
	j := _encloser(lines, i, 60, _loop_re)
	j > d
}
