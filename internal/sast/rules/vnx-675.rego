# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_675

import rego.v1



metadata := {
	"id": "VNX-675",
	"name": "Single-use operation repeated on the same handle (double close, relock, double unlock)",
	"description": "C or C++ code performs an operation that may happen only once per resource twice on the same handle in straight-line code: fclose(), close(), closedir() or pclose() (also ::close / std::fclose) of the same expression again within 20 lines (the second close of a FILE* is undefined behaviour, and the second close() of a descriptor number can close an unrelated file another thread has just opened under it), pthread_mutex_lock() of the same mutex again before its pthread_mutex_unlock() (a default mutex deadlocks), and pthread_mutex_unlock() twice without a lock in between (undefined behaviour). Not reported: a reassignment of the handle in between (fp = fopen(...), fd = -1, *fp = NULL, &fp passed to a function), an unlock (or lock) of the mutex in between, a return/goto/break/continue/exit/abort, an else/case/default, a preprocessor #else/#elif (alternative builds), or the end of the block holding the first call (an error path and its main path, two if/else branches), different handles, calls behind a condition on the same line, comments and string literals. free() twice is VNX-415; a format string with %n, which the original version of this rule matched, is not a CWE-675 weakness and is no longer reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-675/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [675],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["multiple-operations-single-call", "cwe-675", "double-close", "mutex"],
}

_c_exts := [".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx"]

_call_re := `^\s*(?:\(void\)\s*)?(?:(?:std)?::)?(fclose|close|closedir|pclose|pthread_mutex_lock|pthread_mutex_unlock)\s*\(\s*([^()]+?)\s*\)\s*;`

_esc(s) := regex.replace(s, `([.\[\]*&+?()|^$\\{}-])`, `\$1`)

# The operation that resets the state between two calls of `fn` on X.
_reset_fn("pthread_mutex_lock") := "pthread_mutex_unlock"

_reset_fn("pthread_mutex_unlock") := "pthread_mutex_lock"

_reset_fn(fn) := "" if fn in {"fclose", "close", "closedir", "pclose"}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_barrier := `^\s*(?:return\b|goto\b|break\b|continue\b|exit\s*\(|_exit\s*\(|abort\s*\(|else\b|\}\s*else\b|case\b|default\s*:|throw\b|[A-Za-z_]\w*\s*:\s*$)|^\}`

_stops(lines, j, _, _, _) if regex.match(_barrier, lines[j])

_stops(lines, j, ind, _, _) if _indent(lines[j]) < ind

# The handle is reassigned or handed out by address.
_stops(lines, j, _, x, _) if {
	base := trim_left(x, "&*")
	regex.match(concat("", [`(?:^|[^\w.>])\*?`, _esc(base), `\s*=[^=]|&\s*`, _esc(base), `\b`]), lines[j])
	not regex.match(concat("", [`^\s*(?:\(void\)\s*)?(?:(?:std)?::)?(?:fclose|close|closedir|pclose|pthread_mutex_lock|pthread_mutex_unlock|pthread_mutex_trylock)\s*\(\s*&?`, _esc(base), `\s*\)\s*;`]), lines[j])
}

_stops(lines, j, _, x, fn) if {
	r := _reset_fn(fn)
	r != ""
	contains(lines[j], r)
	contains(_nows(lines[j]), _nows(x))
}

_nows(s) := regex.replace(s, `\s+`, "")

_code(line) if {
	trim_space(line) != ""
	not regex.match(`^\s*(?://|/\*|\*(?:\s|/|$)|#)`, line)
}

_stop_line(lines, j, ind, x, fn) if {
	_code(lines[j])
	_stops(lines, j, ind, x, fn)
}

# #else / #elif: the two calls are in alternative preprocessor branches.
_stop_line(lines, j, _, _, _) if regex.match(`^\s*#\s*(?:else|elif|elifdef|elifndef)\b`, lines[j])

_region_end(lines, i, ind, x, fn) := e if {
	last := min([count(lines) - 1, i + 20])
	stops := [j |
		some j in numbers.range(i + 1, last)
		_stop_line(lines, j, ind, x, fn)
	]
	e := min(array.concat([last + 1], stops))
}

_in_block_comment(lines, i) if {
	start := max([0, i - 40])
	i > start
	marks := [j | some j in numbers.range(start, i - 1); _comment_mark(lines[j])]
	count(marks) > 0
	l := lines[max(marks)]
	contains(l, "/*")
	not contains(substring(l, indexof(l, "/*"), -1), "*/")
}

_comment_mark(l) if contains(l, "/*")

_comment_mark(l) if contains(l, "*/")

_what("pthread_mutex_lock") := "locked again before it was unlocked (a default mutex deadlocks)"

_what("pthread_mutex_unlock") := "unlocked a second time (undefined behaviour)"

_what(fn) := "closed a second time (undefined for a FILE*/DIR*; a reused descriptor number closes someone else's file)" if fn in {"fclose", "close", "closedir", "pclose"}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _c_exts
	endswith(path, ext)
	regex.match(`(?m)^\s*(?:\(void\)\s*)?(?:(?:std)?::)?(?:fclose|close|closedir|pclose|pthread_mutex_lock|pthread_mutex_unlock)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	m := regex.find_all_string_submatch_n(_call_re, line, 1)
	fn := m[0][1]
	x := m[0][2]
	not _in_block_comment(lines, i)
	e := _region_end(lines, i, _indent(line), x, fn)
	i + 1 <= e - 1
	some j in numbers.range(i + 1, e - 1)
	m2 := regex.find_all_string_submatch_n(_call_re, lines[j], 1)
	m2[0][1] == fn
	_nows(m2[0][2]) == _nows(x)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s(%s) was already called on line %d: the handle is %s", [fn, x, i + 1, _what(fn)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}
