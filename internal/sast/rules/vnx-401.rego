# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_401

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-401",
	"name": "Missing Release of Memory after Effective Lifetime (memory leak)",
	"description": "Reports two C/C++ memory-leak shapes. (1) A heap block held in a local variable (malloc, calloc, strdup, strndup, xmalloc, g_malloc, zmalloc, kmalloc and friends, or C++ `new`) is abandoned by a return or throw on a later error path before the variable is freed, deleted, stored, passed to another function or returned; the finding is on the leaking return. Returns guarded by the variable's own NULL check (nothing was allocated) are not reported. (2) `p = realloc(p, n)`: the result overwrites the only pointer to the old block, so a failed realloc leaks it; not reported when the old pointer was saved to another variable on the lines just before. Not reported: allocations stored straight into a struct member, a block passed to any function other than plain memory/string/IO helpers (ownership may move), goto-cleanup code, test files and comments. Paths through code more than 100 lines long, macros and ownership taken by callees are not modelled.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-401/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [401],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["memory-leak", "cwe-401"],
}

_c_file(path) if endswith(path, ".c")

_c_file(path) if endswith(path, ".cc")

_c_file(path) if endswith(path, ".cpp")

_c_file(path) if endswith(path, ".cxx")

# `char *buf = malloc(n);`, `buf = (char *) calloc(...)`, `T *p = new T(...)`.
# The left side is a plain local name: `s->buf = malloc(n)` is owned by s.
_alloc_re := `^\s*(?:[A-Za-z_][\w\s\*:<>,]*?[\s\*])?([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(?:(?:malloc|calloc|strdup|strndup|xmalloc|xcalloc|xstrdup|g_malloc0?|g_new0?|g_strdup|zmalloc|zcalloc|kmalloc|kzalloc|kcalloc)\s*\(|new\s+[A-Za-z_][\w:<>]*\s*[\[({;])`

_realloc_re := `^\s*([A-Za-z_][\w]*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*=\s*(?:\([^()]*\)\s*)?(?:realloc|xrealloc|g_realloc)\s*\(\s*([A-Za-z_][\w]*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*,`

# Calls that read or fill a buffer without taking ownership of it.
_non_owning := `\b(memcpy|memset|memmove|memcmp|strcpy|strncpy|strlcpy|strcat|strncat|strlcat|snprintf|sprintf|vsnprintf|sscanf|read|pread|fread|fgets|recv|recvfrom|write|fwrite|send|printf|fprintf|puts|fputs|strlen|strcmp|strncmp|strchr|strrchr|strstr|strtok|bzero|explicit_bzero|sizeof|assert)\s*\(`

_esc(v) := regex.replace(v, `([.\->])`, `\$1`)

# The block is released, handed off, stored or returned on line l.
_released(l, v) if regex.match(concat("", [`\b(free|delete)\b[^;]*\b`, v, `\b`]), l)

_released(l, v) if regex.match(concat("", [`=\s*(\([^()]*\)\s*)?`, v, `\s*[;,)]`]), l)

_released(l, v) if {
	regex.match(concat("", [`([(,]|^)\s*&?\s*`, v, `\s*[,)]`]), regex.replace(l, concat("", [_non_owning, `[^()]*\)`]), ""))
}

# An alias: `q = (T *)(p + 8)` keeps the block reachable through q.
_released(l, v) if regex.match(concat("", [`[^=!<>]=\s*(\([^()]*\)\s*)?\(?\s*`, v, `\b`]), l)

_released(l, v) if regex.match(concat("", [`\b`, v, `\s*=[^=]`]), l)

_exit(l) if {
	regex.match(`return|throw`, l)
	regex.match(`(^|[^\w])(return|throw)\b`, regex.replace(l, `"(\\.|[^"\\])*"`, `""`))
}

# A block closing at a shallower indent (or a case label) ends the scope the
# allocation lived in.
_indent(l) := count(l) - count(trim_left(l, " \t"))

_scope_end(l, ind) if {
	t := trim_left(l, " \t")
	count(l) - count(t) < ind
	regex.match(`^(\}|case\s|default\s*:)`, t)
}

_fn_end(lines, i) := e if {
	n := count(lines)
	hi := min([n, i + 100])
	ends := [k | some k in helpers.span(i + 1, hi - 1); startswith(lines[k], "}")]
	e := min(array.concat([hi], ends))
}

_null_check(v) := concat("", [`(!\s*`, v, `\b|\b`, v, `\s*==\s*(NULL|nullptr|0)\b|\b(NULL|nullptr)\s*==\s*`, v, `\b)`])

# The if that controls the return at k checks the variable itself for NULL.
_guarded(lines, i, k, v) if {
	ifs := [j |
		some j in numbers.range(max([i + 1, k - 3]), k)
		regex.match(`\bif\s*\(`, lines[j])
	]
	count(ifs) > 0
	regex.match(_null_check(v), lines[max(ifs)])
}

# The return sits in a braced block (logging first) opened by the NULL check:
# the nearest shallower-indented if within 8 lines, with nothing between it
# and the return at its own indent or shallower.
_guarded(lines, i, k, v) if {
	rind := _indent(lines[k])
	ifs := [j |
		some j in numbers.range(max([i + 1, k - 8]), k - 1)
		_indent(lines[j]) < rind
		regex.match(`\bif\s*\(`, lines[j])
	]
	count(ifs) > 0
	j := max(ifs)
	not _outdent_between(lines, j, k, _indent(lines[j]))
	regex.match(_null_check(v), lines[j])
}

_outdent_between(lines, j, k, iind) if {
	some m in helpers.span(j + 1, k - 1)
	trim_space(lines[m]) != ""
	_indent(lines[m]) <= iind
}

_leak_at(lines, i, v) := k if {
	e := _fn_end(lines, i)
	i + 1 < e
	ind := _indent(lines[i])
	stops := [j |
		some j in helpers.span(i + 1, e - 1)
		_stop(lines[j], v, ind)
		not _comment(lines[j])
	]
	limit := min(array.concat([e], stops))
	exits := [j |
		some j in numbers.range(i + 1, limit)
		j < limit
		_exit(lines[j])
		not helpers.is_comment_line(lines[j])
		not regex.match(concat("", [`\b`, v, `\b`]), lines[j])
		not _guarded(lines, i, j, v)
	]
	count(exits) > 0
	k := min(exits)
}

# helpers.is_comment_line counts a line starting with `*` as a block-comment
# continuation, but `*out = buf;` is a store through a pointer.
_comment(l) if {
	helpers.is_comment_line(l)
	not regex.match(`^\s*\*+\s*\(?\s*[A-Za-z_]\w*(\s*(->|\.)\s*\w+|\[[^\]]*\])*\s*\)?\s*=[^=].*;\s*$`, l)
}

_stop(l, v, _) if {
	contains(l, v)
	_released(l, v)
}

_stop(l, _, ind) if _scope_end(l, ind)

_cand(l) if contains(l, "alloc")

_cand(l) if contains(l, "dup")

_cand(l) if contains(l, "new")

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	not helpers.is_test_path(path)
	regex.match(`(?m)=\s*(\([^()]*\)\s*)?(\w*alloc\w*|\w*strn?dup|g_new0?|new)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	_cand(line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_alloc_re, line, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"return", "else", "if"}
	k := _leak_at(lines, i, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' was allocated on line %d and is not freed on this exit path: the memory leaks every time this branch is taken. Free it (or use a single cleanup label) before returning.", [v, i + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": lines[k],
	}
}

# p = realloc(p, n): a NULL result overwrites the only pointer to the block.
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	not helpers.is_test_path(path)
	contains(content, "realloc")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "realloc")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_realloc_re, line, 1)
	count(m) > 0
	m[0][1] == m[0][2]
	v := _esc(m[0][1])
	not _saved_before(lines, i, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s = realloc(%s, ...)' loses the original block when realloc fails and returns NULL. Assign the result to a temporary and replace the pointer only on success.", [m[0][1], m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_saved_before(lines, i, v) if {
	some j in numbers.range(max([0, i - 4]), i - 1)
	j < i
	regex.match(concat("", [`=\s*`, v, `\s*;`]), lines[j])
}
