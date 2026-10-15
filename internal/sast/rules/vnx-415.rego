# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_415

import rego.v1

metadata := {
	"id": "VNX-415",
	"name": "Double free",
	"description": "Reports a C or C++ pointer that is released twice on one path. Two shapes: a release (free, g_free, kfree, vfree, kvfree, OPENSSL_free, CRYPTO_free, xfree, std::free, delete or delete[] of a variable or member expression) followed within the next 20 lines by a second release of the same expression, with nothing in between that reassigns it (p = NULL, p = malloc(...), &p passed to a call, reassigning the struct that holds a member), leaves the path (return, break, continue, goto, exit, abort, throw at the release's nesting level) or starts another branch (else, case, default, #else, the end of the function); and the error-path shape, a release immediately followed by goto LABEL where the cleanup code under LABEL releases the same expression again without it having been nulled. Not reported: a pointer set to NULL or reassigned after the first release, releases on two branches of an if/else or switch, releases in different functions, a release inside a loop that reassigns the pointer (in its body or its while/for header, so a release after the loop closes is of another value), macro definitions, frees of different expressions, project-specific wrapper functions other than xfree, string literals and comments. Aliases (q = p; free(p); free(q)) are not tracked.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-415/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [415],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["double-free", "memory-safety", "cwe-415"],
}

_c_exts := [".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx"]

_c_file(path) if {
	some ext in _c_exts
	endswith(path, ext)
}

# ── Literals and comments ────────────────────────────────────────────────

_mask_strings(s) := regex.replace(regex.replace(s, `'(?:[^'\\]|\\.)'`, "'_'"), `"(?:[^"\\]|\\.)*"`, `""`)

_mask(s) := regex.replace(regex.replace(_mask_strings(s), `/\*.*?\*/`, " "), `(?://|/\*).*$`, "")

_comment_line(l) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, l)

_macro_line(lines, i) if regex.match(`^\s*#\s*define\b`, lines[i])

_macro_line(lines, i) if {
	i > 0
	endswith(trim_right(lines[i - 1], " \t\r"), "\\")
}

_macro_line(lines, i) if endswith(trim_right(lines[i], " \t\r"), "\\")

# ── The release ──────────────────────────────────────────────────────────

_ptr := `[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*`

_cast := `(?:\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|[A-Za-z_]\w*)\s*\*+\s*\)\s*)?`

_free_fns := `(?:std::)?(?:free|g_free|kfree|vfree|kvfree|OPENSSL_free|CRYPTO_free|xfree)`

_free_re := concat("", [`(?:^|[^\w.>:])`, _free_fns, `\s*\(\s*`, _cast, `(`, _ptr, `)\s*\)\s*;`])

_delete_re := concat("", [`(?:^|[^\w.>])delete\s*(?:\[\s*\]\s*)?(`, _ptr, `)\s*;`])

_released(code) := {[m[1], _after(code, m[0])] |
	some re in [_free_re, _delete_re]
	some m in regex.find_all_string_submatch_n(re, code, -1)
}

_after(code, matched) := substring(code, indexof(code, matched) + count(matched), -1)

_esc(e) := replace(e, ".", `\.`)

_base(e) := regex.find_n(`^[A-Za-z_]\w*`, e, 1)[0]

# A release of exactly e on this code text.
_releases(code, e) if {
	some r in _released(code)
	r[0] == e
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── What ends the path ───────────────────────────────────────────────────

_exit_re := `\b(?:return|break|continue|goto|exit|_exit|abort|longjmp|siglongjmp|throw)\b`

# Another branch or function begins: a release there is on a different path.
_branch(l) if regex.match(`^\s*(?:\}\s*)?(?:else\b|case\b|default\s*:|#\s*(?:else|elif)\b)`, l)

_branch(l) if startswith(l, "}")

# The expression (or the object holding it) gets a new value.
_reassigned(code, e) if regex.match(concat("", [`(?:^|[^\w.>*=!<])`, _esc(e), `\s*=(?:[^=]|$)`]), code)

_reassigned(code, e) if regex.match(concat("", [`&\s*\(?\s*`, _esc(e), `\b`]), code)

_reassigned(code, e) if {
	b := _base(e)
	b != e
	regex.match(concat("", [`(?:^|[^\w.>*=!<])`, b, `\s*=(?:[^=]|$)`]), code)
}

_reassigned(code, e) if regex.match(concat("", [`\b`, _esc(e), `\s*=\s*\w*realloc\s*\(`]), code)

# Line k, between the release at i and line j, ends the release's path.
_stops(lines, i, k, e) if {
	_branch(lines[k])
	_indent(lines[k]) <= _indent(lines[i])
}

_stops(lines, i, k, _) if startswith(lines[k], "}")

_stops(lines, i, k, _) if {
	_indent(lines[k]) <= _indent(lines[i])
	regex.match(_exit_re, _mask(lines[k]))
}

_stops(lines, _, k, e) if _reassigned(_mask(lines[k]), e)

# The release sits in a loop body and the loop closes before the second
# release: the loop header (while ((p = next())), for (p = first; p; ...))
# moves the pointer on, so the release after the loop is of another value.
_stops(lines, i, k, _) if {
	regex.match(`^\s*\}`, lines[k])
	ind := _indent(lines[k])
	ind < _indent(lines[i])
	_opens_loop(lines, i, ind)
}

_opens_loop(lines, i, ind) if {
	opener := [h |
		some h in numbers.range(max([0, i - 40]), i - 1)
		trim_space(lines[h]) != ""
		_indent(lines[h]) == ind
	]
	count(opener) > 0
	regex.match(`^\s*(?:\}\s*)?(?:while|for|do)\b`, lines[opener[count(opener) - 1]])
}

_clear_between(lines, i, j, e) if {
	j == i + 1
}

_clear_between(lines, i, j, e) if {
	j > i + 1
	not _any_stop(lines, i, j, e)
}

_any_stop(lines, i, j, e) if {
	some k in numbers.range(i + 1, j - 1)
	not _comment_line(lines[k])
	_stops(lines, i, k, e)
}

# The second release opens another branch itself: `else free(p);`.
_other_branch(lines, i, j) if {
	regex.match(`^\s*(?:\}\s*)?(?:else\b|case\b|default\s*:)`, lines[j])
	_indent(lines[j]) <= _indent(lines[i])
}

_code_line(lines, k) := c if {
	not _comment_line(lines[k])
	not _macro_line(lines, k)
	c := _mask(lines[k])
}

# ── Shape 1: the same pointer released again on the same path ────────────

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`free\s*\(|delete\b`, content)
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	regex.match(`free\s*\(|delete\b`, line)
	code := _code_line(lines, i)
	some r in _released(code)
	e := r[0]
	not regex.match(_exit_re, r[1])
	not _reassigned(r[1], e)
	j := _next_release(lines, i, n, e)
	_clear_between(lines, i, j, e)
	not _other_branch(lines, i, j)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is released again here after it was already released on line %d, with no reassignment in between: a double free corrupts the allocator and is commonly exploitable. Set the pointer to NULL after the first release, or release it in one place", [e, i + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

# The first later line (within 20) that releases e again.
_next_release(lines, i, n, e) := j if {
	end := min([n - 1, i + 20])
	end >= i + 1
	cands := [k |
		some k in numbers.range(i + 1, end)
		contains(lines[k], _tail(e))
		c := _code_line(lines, k)
		_releases(c, e)
	]
	count(cands) > 0
	j := cands[0]
}

_tail(e) := parts[count(parts) - 1] if {
	parts := regex.split(`->|\.`, e)
}

# ── Shape 2: release, goto cleanup, cleanup releases it again ────────────

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "goto")
	regex.match(`free\s*\(|delete\b`, content)
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	regex.match(`free\s*\(|delete\b`, line)
	code := _code_line(lines, i)
	some r in _released(code)
	e := r[0]
	not _reassigned(r[1], e)
	label := _goto_after(lines, i, n, r[1], e)
	_cleanup_releases(lines, i, n, label, e)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is released and then 'goto %s' jumps to cleanup code that releases it again: a double free on this error path. Set the pointer to NULL after releasing it here, or leave the release to the cleanup label", [e, label]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# goto on the release line itself.
_goto_after(_, _, _, rest, _) := m[1] if {
	m := regex.find_all_string_submatch_n(`\bgoto\s+([A-Za-z_]\w*)\s*;`, rest, 1)[0]
}

# goto on one of the next three code lines, in the same block, with no
# reassignment first.
_goto_after(lines, i, n, rest, e) := label if {
	not regex.match(`\bgoto\b`, rest)
	end := min([n - 1, i + 3])
	end >= i + 1
	gs := [[k, m[1]] |
		some k in numbers.range(i + 1, end)
		c := _code_line(lines, k)
		m := regex.find_all_string_submatch_n(`^\s*goto\s+([A-Za-z_]\w*)\s*;`, c, 1)[0]
		_indent(lines[k]) >= _indent(lines[i])
	]
	count(gs) > 0
	k := gs[0][0]
	not _any_stop_before_goto(lines, i, k, e)
	label := gs[0][1]
}

_any_stop_before_goto(lines, i, k, e) if {
	k > i + 1
	some m in numbers.range(i + 1, k - 1)
	not _comment_line(lines[m])
	c := _mask(lines[m])
	_branch_or_exit(lines, i, m, c, e)
}

_branch_or_exit(lines, i, m, c, e) if _reassigned(c, e)

_branch_or_exit(lines, i, m, c, _) if regex.match(_exit_re, c)

_branch_or_exit(lines, i, m, _, _) if _indent(lines[m]) < _indent(lines[i])

# The label below the goto (in the same function) whose next 20 lines release
# e before reassigning it.
_cleanup_releases(lines, i, n, label, e) if {
	end := min([n - 1, i + 300])
	labs := [k |
		some k in numbers.range(i + 1, end)
		regex.match(concat("", [`^\s*`, label, `\s*:`]), lines[k])
	]
	count(labs) > 0
	l := labs[0]
	not _function_ends(lines, i, l)
	lend := min([n - 1, l + 20])
	lend >= l + 1
	rels := [k |
		some k in numbers.range(l + 1, lend)
		contains(lines[k], _tail(e))
		_releases(_code_line(lines, k), e)
	]
	count(rels) > 0
	not _reassigned_between(lines, l, rels[0], e)
}

_function_ends(lines, i, l) if {
	some k in numbers.range(i + 1, l - 1)
	startswith(lines[k], "}")
}

_reassigned_between(lines, l, r, e) if {
	r > l + 1
	some k in numbers.range(l + 1, r - 1)
	_reassigned(_mask(lines[k]), e)
}
