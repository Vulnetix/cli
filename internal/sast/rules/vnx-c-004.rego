package vulnetix.rules.vnx_c_004

import rego.v1

metadata := {
	"id": "VNX-C-004",
	"name": "Use-after-free: pointer used after free()",
	"description": "Reports a C, C++ or Objective-C pointer that is used after it was released: free(p), g_free, kfree, vfree, kvfree, OPENSSL_free, std::free or C++ delete/delete[] of a variable or member expression (p, ctx->buf, s.data), followed within the next 15 lines, on the same path, by a dereference (p->x, p[i], *p), a call that takes it as an argument (memcpy(p, ...), printf(\"%s\", p)) or return p, before anything reassigns it (p = NULL, p = malloc(...), get(&p)) and before the path leaves (return, break, continue, goto, exit, an else or case label, the end of the function). Also reported: a for loop whose step advances through the pointer its body frees (for (p = head; p; p = p->next) free(p)). Not reported: a pointer nulled or reassigned after free, a comparison such as if (p) or p != NULL, sizeof(p), a use only on the other branch of an if/else or another case, a use of a different variable or a saved next pointer, frees inside #define macros, aliases (q = p; free(p); q->x), uses further than 15 lines away or in another function, string literals and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-004/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [416],
	"capec": ["CAPEC-123"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["use-after-free", "c", "memory-safety", "heap"],
}

# ── C source files ───────────────────────────────────────────────────────
# .m is Objective-C only when it looks like it; MATLAB also uses .m.

_c_exts := [".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".mm"]

_c_file(path, _) if {
	some ext in _c_exts
	endswith(path, ext)
}

_c_file(path, content) if {
	endswith(path, ".m")
	regex.match(`(?m)^\s*#\s*(?:import|include)\b|@(?:implementation|interface)\b`, content)
}

# ── Literals and comments ────────────────────────────────────────────────

_mask_chars(s) := regex.replace(s, `'(?:[^'\\]|\\.)'`, "'_'")

_mask_strings(s) := regex.replace(_mask_chars(s), `"(?:[^"\\]|\\.)*"`, `""`)

# Code text of a line: literals emptied, comments removed.
_mask(s) := regex.replace(regex.replace(_mask_strings(s), `/\*.*?\*/`, " "), `(?://|/\*).*$`, "")

_comment_line(l) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, l)

# Inside a /* ... */ block opened on an earlier line.
_in_block_comment(lines, i) if {
	start := max([0, i - 40])
	i > start
	marks := [j | some j in numbers.range(start, i - 1); _comment_mark(lines[j])]
	count(marks) > 0
	_opens_block(_mask_strings(lines[max(marks)]))
}

_comment_mark(l) if contains(l, "/*")

_comment_mark(l) if contains(l, "*/")

_opens_block(s) if {
	o := indexof_n(s, "/*")
	count(o) > 0
	not contains(s, "*/")
}

_opens_block(s) if {
	o := indexof_n(s, "/*")
	c := indexof_n(s, "*/")
	count(o) > 0
	count(c) > 0
	max(o) > max(c)
}

# A line that belongs to a macro definition: `#define` or a continuation.
_macro_line(lines, i) if regex.match(`^\s*#\s*define\b`, lines[i])

_macro_line(lines, i) if {
	i > 0
	endswith(trim_right(lines[i - 1], " \t\r"), "\\")
}

_macro_line(lines, i) if endswith(trim_right(lines[i], " \t\r"), "\\")

# ── The release ──────────────────────────────────────────────────────────

_ptr := `[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*`

_cast := `(?:\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|[A-Za-z_]\w*)\s*\*+\s*\)\s*)?`

_free_re := concat("", [
	`(?:^|[^\w.>:])(?:std::)?(?:free|g_free|kfree|vfree|kvfree|OPENSSL_free)\s*\(\s*`,
	_cast, `(`, _ptr, `)\s*\)\s*;`,
])

_delete_re := concat("", [`(?:^|[^\w.>])delete\s*(?:\[\s*\]\s*)?(`, _ptr, `)\s*;`])

# The released expression and the text after the release on its own line.
_released(code) := {[m[1], _after(code, m[0])] |
	some re in [_free_re, _delete_re]
	some m in regex.find_all_string_submatch_n(re, code, -1)
}

_after(code, matched) := substring(code, indexof(code, matched) + count(matched), -1)

_esc(e) := replace(e, ".", `\.`)

# ── What ends the path the release is on ─────────────────────────────────

# Lines that start another path or another function: the use there is not
# after the release.
_pre_stop(l) if regex.match(`^\s*(?:\}\s*)?(?:else\b|case\b|default\s*:|#\s*(?:else|elif|endif|define)\b)`, l)

_pre_stop(l) if regex.match(`^\s*[A-Za-z_]\w*\s*:\s*$`, l)

_pre_stop(l) if startswith(l, "}")

# A function or method definition (a class body holds several).
_pre_stop(l) if {
	not contains(l, ";")
	regex.match(`^\s*(?:[\w:<>*&~]+\s+)+[*&]*[\w:~]+\s*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{?\s*$`, l)
	not regex.match(`^\s*(?:if|for|while|switch|return|do|else|catch|sizeof)\b`, l)
}

# Lines after which the path has left or the pointer holds something else.
_post_stop(l, _) if regex.match(`\b(?:return|break|continue|goto|exit|_exit|abort|longjmp|siglongjmp|throw)\b`, l)

_post_stop(l, e) if regex.match(concat("", [`(?:^|[^\w.>*=!<])`, _esc(e), `\s*=[^=]`]), l)

_post_stop(l, e) if regex.match(concat("", [`&\s*\(?\s*`, _esc(e), `\b`]), l)

_post_stop(l, _) if regex.match(`\belse\b`, l)

# ── Uses ─────────────────────────────────────────────────────────────────

_not_a_use := {
	"sizeof", "if", "while", "for", "switch", "return", "defined", "assert", "offsetof",
	"_Alignof", "alignof", "typeof", "__typeof__", "decltype", "free", "g_free", "kfree",
	"vfree", "kvfree", "OPENSSL_free", "likely", "unlikely",
}

_uses(l, e) if regex.match(concat("", [`(?:^|[^\w.>])`, _esc(e), `\s*(?:->|\[)`]), l)

_uses(l, e) if regex.match(concat("", [`(?:^|[=(,;!?:]|\breturn)\s*\*\s*\(?\s*`, _esc(e), `\b`]), l)

_uses(l, e) if regex.match(concat("", [`\breturn\s+\(?\s*`, _esc(e), `\s*\)?\s*;`]), l)

_uses(l, e) if {
	re := concat("", [`\b([A-Za-z_]\w*)\s*\((?:[^()]*,)?\s*`, _esc(e), `\s*[,)]`])
	some m in regex.find_all_string_submatch_n(re, l, -1)
	not _not_a_use[m[1]]
}

_window := 15

# Indices of the lines containing `word`, found by splitting the file on it
# rather than visiting every line.
_word_lines(content, word) := {n |
	contains(content, word)
	parts := split(content, word)
	nls := [strings.count(p, "\n") | some p in parts]
	some k in numbers.range(1, count(parts) - 1)
	n := sum(array.slice(nls, 0, k))
}

# The first line after i on the release's path that uses e.
_use_after(lines, i, e) := j if {
	end := min([count(lines) - 1, i + _window])
	end >= i + 1
	codes := {k: c |
		some k in numbers.range(i + 1, end)
		not _comment_line(lines[k])
		c := _mask(lines[k])
	}
	pre := {k | some k, c in codes; _pre_stop(c)}
	post := {n | some k, c in codes; _post_stop(c, e); n := k + 1}
	limit := min((pre | post) | {end + 1})
	uses := {k | some k, c in codes; k < limit; _uses(c, e)}
	count(uses) > 0
	j := min(uses)
}

# C files that release memory at all, computed once for both rules.
_files[path] := content if {
	some path, content in input.file_contents
	_c_file(path, content)
	regex.match(`\b(?:free|g_free|kfree|vfree|kvfree|OPENSSL_free)\s*\(|\bdelete\b`, content)
}

findings contains finding if {
	some path, content in _files
	hits := _word_lines(content, "free") | _word_lines(content, "delete")
	count(hits) > 0
	lines := split(content, "\n")
	some i in hits
	line := lines[i]
	regex.match(`(?:^|[^\w.>:]|std::)(?:free|g_free|kfree|vfree|kvfree|OPENSSL_free)\s*\(|\bdelete\b`, line)
	not _comment_line(line)
	code := _mask(line)
	some rel in _released(code)
	e := rel[0]
	not _post_stop(rel[1], e)
	not _macro_line(lines, i)
	j := _use_after(lines, i, e)
	not _in_block_comment(lines, i)
	not _in_block_comment(lines, j)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is used after it was freed on line %d; set it to NULL after free() and do not touch freed memory", [e, i + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

# ── for (p = head; p; p = p->next) free(p); ──────────────────────────────

_for_step_re := `^\s*for\s*\(.*;\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*->\s*\w+\s*\)\s*\{?\s*$`

_indent(l) := count(l) - count(trim_left(l, " \t"))

findings contains finding if {
	some path, content in _files
	contains(content, "->")
	headers := regex.find_n(`\bfor\s*\([^;\n]*;[^;\n]*;\s*[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*->\s*\w+\s*\)`, content, -1)
	count(headers) > 0
	lines := split(content, "\n")
	hits := {k | some h in headers; some pos in indexof_n(content, h); k := strings.count(substring(content, 0, pos), "\n")}
	some k in hits
	line := lines[k]
	m := regex.find_all_string_submatch_n(_for_step_re, _mask(line), 1)
	count(m) > 0
	v := m[0][1]
	v == m[0][2]
	body := _loop_body(lines, k)
	_frees_in(body, v)
	not _leaves(body)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("The loop step reads '%s->...' after the body freed '%s'; save the next pointer before free()", [v, v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": line,
	}
}

# Body lines of the loop whose header is k: up to its closing brace at the
# header's indent, or the single statement of a braceless loop.
_loop_body(lines, k) := body if {
	endswith(trim_right(_mask(lines[k]), " \t\r"), "{")
	ik := _indent(lines[k])
	end := min([count(lines) - 1, k + 12])
	closes := [j |
		some j in numbers.range(k + 1, end)
		_indent(lines[j]) <= ik
		startswith(trim_left(lines[j], " \t"), "}")
	]
	stop := min(array.concat(closes, [end + 1]))
	body := [_mask(lines[j]) | some j in numbers.range(k + 1, stop - 1)]
}

_loop_body(lines, k) := [_mask(lines[j])] if {
	not endswith(trim_right(_mask(lines[k]), " \t\r"), "{")
	j := k + 1
	j < count(lines)
}

_frees_in(body, v) if {
	some c in body
	some rel in _released(c)
	rel[0] == v
}

_leaves(body) if {
	some c in body
	regex.match(`\b(?:return|break|goto)\b`, c)
}
