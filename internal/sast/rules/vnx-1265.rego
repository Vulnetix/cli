# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1265

import rego.v1

metadata := {
	"id": "VNX-1265",
	"name": "Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls",
	"description": "strtok() keeps its position in hidden static state, so it is not reentrant: starting a second tokenization while one is in progress silently replaces the first, and the outer loop's next strtok(NULL, ...) continues through the wrong string or stops early. Reported, in C: inside the body of a for/while loop that iterates a strtok() tokenization (the loop begins on, or within three lines after, a strtok() call with a non-NULL string, and its header or body calls strtok(NULL, ...)), a line that starts another strtok() on a non-NULL string, or that calls a function defined in the same file whose body starts a strtok() tokenization (the nested call re-enters strtok). Not reported: strtok_r()/strtok_s(), a second tokenization that begins after the first loop has ended, a helper that does not call strtok(), a function calling itself, calls into other files (not visible to a line-oriented rule), text in comments and string literals. Signal handlers that call non-reentrant functions are reported by VNX-479 and VNX-828.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1265/",
	"languages": ["c"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1265],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["unintended-reentrant", "strtok", "c", "cwe-1265"],
}

_msg := "strtok() is re-entered while an outer strtok() loop is still tokenizing: its hidden static state is overwritten, so the outer loop continues through the wrong string. Use strtok_r() with a separate save pointer for each tokenization"

# String and char literals blanked; trailing // comments dropped.
_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), `//.*$`, "")

# A strtok() that starts a tokenization (its first argument is not NULL).
_starts(c) if {
	some m in regex.find_all_string_submatch_n(`\bstrtok\s*\(\s*([^,()]*(?:\([^()]*\))?[^,()]*),`, c, -1)
	not trim_space(m[1]) in {"NULL", "0", "nullptr", "(char *)NULL", "(char*)NULL"}
}

# A whole-line comment. Not helpers.is_comment_line: a C statement such as
# `*key = strtok(pair, "=");` begins with `*` and is code.
_is_comment(l) if regex.match(`^\s*(//|/\*|\*(\s|/|$))`, l)

_indent(line) :=count(line) - count(trim_left(line, " \t"))

_fn_re := `^(?:[A-Za-z_][\w \t\*]*?[\s\*])?([A-Za-z_]\w*)\s*\([^;]*$`

_keywords := {"if", "for", "while", "switch", "return", "sizeof", "do", "else"}

# Index of the enclosing function definition of line p.
_fn_index(starts, p) := max(array.concat([-1], [s | some s in starts; s <= p]))

# The loop over the tokenization begun at s: a for/while header on s or within
# three lines after it, whose body is braced.
_loop(lines, s) := j if {
	js := [k |
		some k in numbers.range(s, min([count(lines) - 1, s + 3]))
		regex.match(`(^|[^\w])(for|while)\s*\(`, _code(lines[k]))
	]
	count(js) > 0
	j := min(js)
}

_body_end(lines, j) := e if {
	ij := _indent(lines[j])
	es := [k |
		some k in numbers.range(j + 1, min([count(lines) - 1, j + 150]))
		_indent(lines[k]) <= ij
		startswith(trim_left(lines[k], " \t"), "}")
	]
	count(es) > 0
	e := min(es)
}

_continues(lines, j, e) if {
	some k in numbers.range(j, e)
	regex.match(`\bstrtok\s*\(\s*(NULL|0|nullptr)\s*,`, lines[k])
}

_nested(_, _, c, _) if _starts(c)

_nested(tok_fns, fname, c, _) if {
	some name in tok_fns
	name != fname
	regex.match(concat("", [`(^|[^\w.>])`, name, `\s*\(`]), c)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".c")
	contains(content, "strtok")
	regex.match(`\bstrtok\s*\(`, content)
	lines := split(content, "\n")
	codes := [_code(l) | some l in lines]
	fn_starts := [k |
		some k, l in lines
		m := regex.find_all_string_submatch_n(_fn_re, l, 1)
		count(m) > 0
		not m[0][1] in _keywords
	]
	fn_names := {k: n |
		some k in fn_starts
		n := regex.find_all_string_submatch_n(_fn_re, lines[k], 1)[0][1]
	}
	start_lines := [k |
		some k, c in codes
		contains(c, "strtok")
		not _is_comment(lines[k])
		_starts(c)
	]
	tok_fns := {fn_names[f] |
		some k in start_lines
		f := _fn_index(fn_starts, k)
		f >= 0
	}
	some s in start_lines
	j := _loop(lines, s)
	e := _body_end(lines, j)
	_continues(lines, j, e)
	f := _fn_index(fn_starts, s)
	fname := object.get(fn_names, f, "")
	some i in numbers.range(j + 1, e - 1)
	not _is_comment(lines[i])
	_nested(tok_fns, fname, codes[i], lines[i])
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
