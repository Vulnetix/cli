# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_416

import rego.v1

metadata := {
	"id": "VNX-416",
	"name": "Use after free: stale pointer after realloc, or a pointer into a destroyed temporary",
	"description": "Reports two use-after-free shapes in C and C++ that VNX-C-004 (use after free()/delete) does not cover. First, the old pointer used after a successful realloc: q = realloc(p, n) (also reallocarray, g_realloc, g_try_realloc, OPENSSL_realloc) into a different variable, followed within 15 lines by a dereference of p (p->x, p[i], *p), a call that takes p, or return p, before p is reassigned (p = q, p = NULL); realloc may have moved and freed the block p points to. Uses inside the branch that tests the new pointer for NULL (the failure path, where p is still valid) are not reported, nor is p = realloc(p, n) itself (a leak, not a use after free). Second, C++ pointers and views kept into a temporary that is destroyed at the end of the statement: const char *s = (or return) the c_str()/data() of std::string(...) or std::string{...}, std::to_string(...), std::format/fmt::format(...), a stringstream .str(), .substr(...) or a parenthesised concatenation, std::filesystem::path .string()/.u8string()/.generic_string(), Qt toStdString(), a Qt toUtf8()/toLatin1()/toLocal8Bit() .constData()/.data(), with the pointer declared as char/wchar_t/uint8_t pointer or auto, and a std::string_view initialised from such a temporary string (std::string_view v = ..., or auto v = std::string_view(...)). The NULL test may wrap the realloc itself (if ((q = realloc(p, n)) == NULL) {, if (!(q = realloc(p, n)))); uses inside that failure block are not reported. A realloc failure test that returns on the same line (if (!q) return -1;) does not end the success path below it. Not reported: the temporary used inside the same full expression (printf(\"%s\", std::to_string(n).c_str())), c_str() of a named object, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-416/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [416],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["use-after-free", "dangling-pointer", "memory-safety", "cwe-416"],
}

_c_exts := [".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx"]

_cpp_exts := [".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h"]

_ext_in(path, exts) if {
	some ext in exts
	endswith(path, ext)
}

_mask_strings(s) := regex.replace(regex.replace(s, `'(?:[^'\\]|\\.)'`, "'_'"), `"(?:[^"\\]|\\.)*"`, `""`)

_mask(s) := regex.replace(regex.replace(_mask_strings(s), `/\*.*?\*/`, " "), `(?://|/\*).*$`, "")

_comment_line(l) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, l)

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── Shape 1: the old pointer after realloc ───────────────────────────────

_ptr := `[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*`

_realloc_re := concat("", [
	`(?:^|[^\w.>])(`, _ptr, `)\s*=\s*(?:\([^()]*\)\s*)?(?:realloc|reallocarray|g_realloc|g_try_realloc|OPENSSL_realloc)\s*\(\s*(`, _ptr, `)\s*,`,
])

_esc(e) := replace(e, ".", `\.`)

# A use of p: dereference, member access, index, a call argument, a return.
_use(code, p) if regex.match(concat("", [`(?:^|[^\w.>])`, _esc(p), `\s*(?:->|\[)`]), code)

_use(code, p) if regex.match(concat("", [`(?:^|[^\w)\]])\*\s*\(?\s*`, _esc(p), `\b`]), code)

_use(code, p) if regex.match(concat("", [`\breturn\s+\(?\s*`, _esc(p), `\s*\)?\s*;`]), code)

# An offset into p passed to a call: memcpy(p + len, ...).
_use(code, p) if regex.match(concat("", [`\b[A-Za-z_]\w*\s*\((?:[^;]*?,)?\s*`, _esc(p), `\s*\+\s*\w`]), code)

_use(code, p) if {
	m := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*\(([^;]*?[(,]\s*|\s*)`, _esc(p), `\s*[,)]`]), code, -1)
	some x in m
	not x[1] in _not_a_call
}

_not_a_call := {"if", "while", "for", "switch", "sizeof", "assert", "return", "defined", "likely", "unlikely"}

_reassigned(code, p) if regex.match(concat("", [`(?:^|[^\w.>*=!<])`, _esc(p), `\s*=[^=]`]), code)

_reassigned(code, p) if regex.match(concat("", [`&\s*\(?\s*`, _esc(p), `\b`]), code)

# The NULL test of the new pointer opens the failure branch.
_null_test(code, q) if regex.match(concat("", [`\bif\s*\(\s*(?:!\s*\(?\s*`, _esc(q), `\b|`, _esc(q), `\s*==\s*(?:NULL|0|nullptr)\b|(?:NULL|0|nullptr)\s*==\s*`, _esc(q), `\b|\(\s*`, _esc(q), `\s*=[^=].*\)\s*==\s*(?:NULL|0|nullptr)\b)`]), code)

# Line k is on the failure path: the test is on line k itself, or an
# enclosing (shallower) line between the realloc and k.
_on_failure_path(lines, i, k, q) if _null_test(_mask(lines[k]), q)

_on_failure_path(lines, i, k, q) if {
	# m == i: the realloc is itself inside the test,
	# if ((q = realloc(p, n)) == NULL) {.
	some m in numbers.range(i, k - 1)
	_indent(lines[m]) < _indent(lines[k])
	_null_test(_mask(lines[m]), q)
	not _closed_between(lines, m, k)
}

_closed_between(lines, m, k) if {
	k > m + 1
	some x in numbers.range(m + 1, k - 1)
	_indent(lines[x]) <= _indent(lines[m])
	startswith(trim_left(lines[x], " \t"), "}")
}

# The path leaves at the realloc's level, or the function ends.
_path_ends(lines, i, k) if startswith(lines[k], "}")

_path_ends(lines, i, k) if {
	_indent(lines[k]) <= _indent(lines[i])
	regex.match(`^\s*(?:\}\s*)?(?:else\b|case\b|default\s*:)|\b(?:return|break|continue|goto|exit|abort|throw)\b`, _mask(lines[k]))
}

findings contains finding if {
	some path, content in input.file_contents
	_ext_in(path, _c_exts)
	contains(content, "realloc")
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	contains(line, "realloc")
	not _comment_line(line)
	code := _mask(line)
	some m in regex.find_all_string_submatch_n(_realloc_re, code, -1)
	q := m[1]
	p := m[2]
	q != p
	k := _first_use(lines, i, n, p, q)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is used after realloc() on line %d moved its block into '%s': when realloc succeeds the old block may have been freed, so this is a use after free. Use '%s' (and assign it back to '%s') after checking it is not NULL", [p, i + 1, q, q, p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": lines[k],
	}
}

# The first line within 15 that uses p on the success path, with no
# reassignment or exit before it.
_first_use(lines, i, n, p, q) := k if {
	end := min([n - 1, i + 15])
	end >= i + 1
	marks := [[x, kind] |
		some x in numbers.range(i + 1, end)
		not _comment_line(lines[x])
		kind := _mark(lines, i, x, p, q)
	]
	count(marks) > 0
	marks[0][1] == "use"
	k := marks[0][0]
}

_mark(lines, i, x, p, q) := "stop" if {
	_reassigned(_mask(lines[x]), p)
} else := "use" if {
	_use(_mask(lines[x]), p)
	not _on_failure_path(lines, i, x, q)
} else := "stop" if {
	_path_ends(lines, i, x)

	# `if (!q) return -1;` leaves only on the failure path; the code below
	# it is the success path.
	not _null_test(_mask(lines[x]), q)
}

# ── Shape 2: a pointer into a temporary ──────────────────────────────────

# Expressions whose value is a temporary std::string / QByteArray.
_temp := `(?:(?:std::)?(?:to_string|to_wstring|string|wstring|format)\s*\(.*\)|(?:std::)?w?string\s*\{[^{};]*\}|fmt::format\s*\(.*\)|[\w\]\)>.-]+\.(?:str|substr)\s*\(.*\)|\((?:[^()]|\([^()]*\))*\+(?:[^()]|\([^()]*\))*\)(?:\s*\.\s*(?:toUtf8|toLatin1|toLocal8Bit)\s*\(\s*\))?|[\w\]\)>.-]+\.(?:toUtf8|toLatin1|toLocal8Bit)\s*\(\s*\)|(?:[\w\]>.:-]|\([^()]*\))+\.(?:string|u8string|wstring|generic_string|toStdString|toStdWString)\s*\(\s*\))`

_cstr_assign_re := concat("", [`(?:^|[;{]\s*|\s)(?:(?:const\s+)?(?:char|wchar_t|char16_t|char32_t|uint8_t|unsigned\s+char|auto)\s*(?:const\s*)?\*|(?:const\s+)?auto\s)\s*(?:const\s+)?[A-Za-z_]\w*\s*=\s*`, _temp, `\s*\.\s*(?:c_str|data|constData)\s*\(\s*\)\s*;`])

_cstr_return_re := concat("", [`\breturn\s+`, _temp, `\s*\.\s*(?:c_str|data|constData)\s*\(\s*\)\s*;`])

_view_re := `(?:\b(?:std::)?(?:w|u8|u16|u32)?string_view\s+[A-Za-z_]\w*\s*(?:=\s*|\{\s*)|\bauto\s+[A-Za-z_]\w*\s*=\s*(?:std::)?(?:w|u8|u16|u32)?string_view\s*[({]\s*)(?:(?:std::)?(?:to_string|to_wstring|format)\s*\(|(?:std::)?w?string\s*[({]|fmt::format\s*\(|[\w\]\)>.-]+\.(?:str|string|u8string|wstring|generic_string|toStdString)\s*\(\s*\)\s*[;}])`

_dangling(code) if regex.match(_cstr_assign_re, code)

_dangling(code) if regex.match(_cstr_return_re, code)

_dangling(code) if regex.match(_view_re, code)

findings contains finding if {
	some path, content in input.file_contents
	_ext_in(path, _cpp_exts)
	regex.match(`c_str|\.data\(|constData|string_view`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`c_str|\.data\(|constData|string_view`, line)
	not _comment_line(line)
	_dangling(_mask_strings(regex.replace(line, `//.*$`, "")))
	finding := {
		"rule_id": metadata.id,
		"message": "A pointer or string_view is kept into a temporary string that is destroyed at the end of this statement: every later use reads freed memory. Keep the string in a named variable (std::string s = ...; then s.c_str()) for as long as the pointer is used",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
