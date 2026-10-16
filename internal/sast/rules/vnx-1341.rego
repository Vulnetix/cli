# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1341

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1341",
	"name": "Multiple Releases of Same Resource or Handle",
	"description": "The same pointer, descriptor or handle is released twice on one path in a C or C++ function: free, fclose, close, closedir, pclose, closesocket, CloseHandle, kfree, g_free, munmap, delete/delete[] and library releasers named *_free/*_destroy/*_close/*_cleanup (EVP_CIPHER_CTX_free, sqlite3_close, curl_easy_cleanup). Reported: a second release of the same expression later in the function with no reassignment (x = ..., &x passed out) and no exit (return, goto, break, continue, exit) of the first release's block between them, including a release inside an if that is followed by an unconditional release; and an error path that releases x and then jumps with goto to a cleanup label that releases x again. Not reported: a release followed by x = NULL or a new assignment, releases in exclusive branches (if/else, switch cases, #if/#else), an early release whose block returns, loops that release a different element each pass, releases in different functions, reference-count drops (*_unref, *_release), comments. Paths through other functions and aliases (q = p; free(p); free(q)) are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1341/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1341],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["double-release", "double-free", "memory-safety", "cwe-1341"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_target := `([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)`

_call_re := concat("", [`(?:^|[^\w.>])(?:free|fclose|close|closedir|pclose|closesocket|CloseHandle|kfree|vfree|g_free|munmap|[A-Za-z0-9]\w*_(?:free|destroy|close|cleanup))\s*\(\s*`, _target, `\s*[,)]`])

_delete_re := concat("", [`(?:^|[^\w])delete(?:\s+|\s*\[\s*\]\s*)`, _target, `\s*;`])

_indent(l) := count(l) - count(trim_left(l, " \t"))

_esc(x) := replace(replace(x, ".", `\.`), "->", `->`)

_exit_re := `^\s*(?:return\b|goto\b|break\s*;|continue\s*;|exit\s*\(|_exit\s*\(|abort\s*\(|longjmp\s*\(|throw\b)`

# x is reassigned or handed out by address on line l.
_reassigns(l, x) if regex.match(concat("", [`(?:^|[^\w.>])`, _esc(x), `\s*=[^=]`]), l)

_reassigns(l, x) if regex.match(concat("", [`&\s*`, _esc(x), `\b`]), l)

# The path from release j to release k is broken.
_broken(lines, j, k, x, _) if {
	some m in helpers.span(j + 1, k - 1)
	_reassigns(lines[m], x)
	not helpers.is_comment_line(lines[m])
}

# the first release's own line clears or reassigns it: close(fd); fd = -1;
_broken(lines, j, _, x, _) if _reassigns(_after_release(lines[j]), x)

# the first release's own line or block exits
_broken(lines, j, _, _, _) if regex.match(`\b(?:return|goto|break|continue)\b|\bexit\s*\(`, _after_release(lines[j]))

_broken(lines, j, k, _, ij) if {
	some m in helpers.span(j + 1, k - 1)
	_indent(lines[m]) == ij
	regex.match(_exit_re, lines[m])
	not _closed_before(lines, j, m, ij)
}

# exclusive branches: an else / case / default shallower than j
_broken(lines, j, k, _, ij) if {
	some m in numbers.range(j + 1, k)
	_indent(lines[m]) < ij
	regex.match(`^\s*(?:\}\s*)?(?:else\b|case\b.*:|default\s*:)`, lines[m])
}

# a braceless `if (c) free(p);` followed by an else at the same indent
_broken(lines, j, k, _, ij) if {
	regex.match(`^\s*(?:\}\s*)?(?:else\s+)?if\s*\(`, lines[j])
	some m in numbers.range(j + 1, k)
	_indent(lines[m]) <= ij
	regex.match(`^\s*(?:\}\s*)?else\b`, lines[m])
}

_broken(lines, j, k, _, _) if {
	some m in helpers.span(j + 1, k - 1)
	regex.match(`^\s*#\s*(?:else|elif)\b`, lines[m])
}

# function boundary
_broken(lines, j, k, _, _) if {
	some m in helpers.span(j + 1, k - 1)
	regex.match(`^\}`, lines[m])
}

# a block closes shallower than both releases: they are in different
# (indented) methods of a class or namespace, or different scopes
_broken(lines, j, k, _, ij) if {
	floor := min([ij, _indent(lines[k])])
	some m in helpers.span(j + 1, k - 1)
	regex.match(`^\s*\}`, lines[m])
	_indent(lines[m]) < floor
}

# The text after the first release call on the line.
_after_release(l) := regex.replace(l, `^.*?(?:(?:free|close|closedir|closesocket|CloseHandle|munmap|_destroy|_cleanup)\s*\([^()]*\)|\bdelete(?:\s+|\s*\[\s*\]\s*)[^;]*;)`, "")

_closed_before(lines, j, m, ij) if {
	j + 1 <= m - 1
	some n in helpers.span(j + 1, m - 1)
	_indent(lines[n]) < ij
	regex.match(`^\s*\}`, lines[n])
}

_hint := ["free(", "close(", "delete ", "delete[", "_destroy(", "_cleanup(", "CloseHandle(", "munmap(", "closedir(", "closesocket(", "free (", "close ("]

_has_hint(s) if {
	some h in _hint
	contains(s, h)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	_has_hint(content)
	lines := split(content, "\n")
	rel := array.concat(_call_rel(lines), _delete_rel(content, lines))
	count(rel) > 1
	some r in _reports(lines, rel)
	finding := {
		"rule_id": metadata.id,
		"message": r.msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line + 1,
		"snippet": lines[r.line],
	}
}

_straight_msg := "Resource released twice on the same path (double free / double close): nothing reassigns it or leaves the block between the two releases. Set it to NULL (or -1) after releasing, or release it in one place"

_goto_msg := "Resource released on an error path that then jumps to a cleanup label which releases it again (double free / double close). Release it only at the label, or set it to NULL before the goto"

_reports(lines, rel) := {r |
	some a in rel
	some b in rel
	a[1] == b[1]
	j := a[0]
	k := b[0]
	k > j
	k - j <= 60
	not _broken(lines, j, k, a[1], _indent(lines[j]))
	r := {"line": k, "msg": _straight_msg}
} | {r |
	some a in rel
	j := a[0]
	x := a[1]
	some label in _gotos(lines, j, x)
	l := _label_line(lines, j, label)
	_label_releases(lines, l, x, rel)
	r := {"line": j, "msg": _goto_msg}
}

# A goto within five lines of the release, at the release's indent, with no
# reassignment between.
_gotos(lines, j, x) := {label |
	ij := _indent(lines[j])
	some m in numbers.range(j, min([count(lines) - 1, j + 5]))
	gm := regex.find_all_string_submatch_n(`\bgoto\s+([A-Za-z_]\w*)\s*;`, lines[m], 1)
	count(gm) > 0
	_goto_level(lines, j, m, ij)
	not _reassign_between(lines, j, m, x)
	not _reassigns(_after_release(lines[j]), x)
	label := gm[0][1]
}

_goto_level(_, j, m, _) if m == j

_goto_level(lines, j, m, ij) if {
	m != j
	_indent(lines[m]) == ij
}

_reassign_between(lines, j, m, x) if {
	j + 1 <= m - 1
	some n in helpers.span(j + 1, m - 1)
	_reassigns(lines[n], x)
}

_label_line(lines, j, label) := l if {
	some l in numbers.range(j + 1, min([count(lines) - 1, j + 200]))
	regex.match(concat("", [`^\s*`, label, `\s*:`]), lines[l])
	not _fn_end_between(lines, j, l)
}

_fn_end_between(lines, j, l) if {
	some n in helpers.span(j + 1, l - 1)
	regex.match(`^\}`, lines[n])
}

# From the label down to the function's next return or end, x is released
# with no reassignment first.
_label_releases(lines, l, x, rel) if {
	some b in rel
	b[1] == x
	k := b[0]
	k > l
	k - l <= 30
	not _stop_between(lines, l, k, x)
}

_stop_between(lines, l, k, x) if {
	l + 1 <= k - 1
	some n in helpers.span(l + 1, k - 1)
	regex.match(`^\}|^\s*return\b`, lines[n])
}

_stop_between(lines, l, k, x) if {
	l + 1 <= k - 1
	some n in helpers.span(l + 1, k - 1)
	_reassigns(lines[n], x)
}

# Release calls, line by line: cheap substring and literal-led tests before
# the full expression.
_call_rel(lines) := [[i, x] |
	some i, l in lines
	contains(l, "(")
	regex.match(`free\s*\(|close\s*\(|_destroy\s*\(|_cleanup\s*\(|CloseHandle\s*\(|munmap\s*\(`, l)
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_call_re, l, -1)
	x := m[1]
	x != "NULL"
	x != "nullptr"
]

# delete / delete[] (C++), only in files that use it.
_delete_rel(content, _) := [] if not contains(content, "delete")

_delete_rel(content, lines) := [[i, x] |
	some i, l in lines
	contains(l, "delete")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_delete_re, l, -1)
	x := m[1]
	x != "NULL"
	x != "nullptr"
] if contains(content, "delete")
