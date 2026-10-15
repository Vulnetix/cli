# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_788

import rego.v1

metadata := {
	"id": "VNX-788",
	"name": "Access of Memory Location After End of Buffer",
	"description": "Reports C/C++ off-by-one accesses one element past the end of an array declared in the same file: X[sizeof(X)], X[N] where the nearest declaration of X above is X[N] (N a number or constant), a for loop bounded by i <= N or i <= sizeof(X) that indexes X[i] in its body (six lines of a braced body, the single statement of an unbraced one), and n = read/recv/pread/fread(X, ..., sizeof(X)) (also ::read) followed by X[n] = ... (a full read leaves no room for the terminator). Arrays whose declaration is not in the file, struct members, pointer buffers, &X[N] (a valid one-past-the-end pointer) and bounds that are computed at run time are deliberately not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-788/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [788],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["oob-access-after-end", "cwe-788"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_c_file(path) if {
	some ext in _exts
	endswith(path, ext)
}

_is_comment(line) if regex.match(`^\s*(//|/\*|\*)`, line)

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_msg := "Access one element past the end of the array (an index equal to its size). Valid indexes run from 0 to size - 1"

_decl_re := `(?m)^\s*(?:(?:static|const|extern|unsigned|signed|struct|volatile|register|constexpr)\s+)*([A-Za-z_][\w:]*)\s+\**\s*([A-Za-z_]\w*)\s*\[\s*([0-9]+|[A-Z_][A-Z0-9_]*|k[A-Z]\w*)\s*\]\s*(?:\[[^\]]*\]\s*)*(?:;|=|,)`

# [name, size] for every array declared in the file (first dimension)
_decls(content) := {[m[2], m[3]] |
	some m in regex.find_all_string_submatch_n(_decl_re, content, -1)
	m[1] != "return"
}

# one alternation of every declared name[size], so a file with no use of a
# declared size is rejected by a single pass over its lines
_union(decls) := concat("|", [concat("", [`\b`, d[0], `\s*\[\s*`, d[1], `\s*\]`]) | some d in decls])

_is_decl_at(line, name, size) if {
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_][\w:]*)[\s*]+`, name, `\s*\[\s*`, size, `\s*\]`]), line, -1)
	not m[1] in {"return", "case", "else", "sizeof"}
}

_sizeof(name) := concat("", [`sizeof\s*(?:\(\s*`, name, `\s*\)|\s+`, name, `\b)`])

# X[sizeof(X)]
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`\[\s*sizeof\b`, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "sizeof")
	not _is_comment(raw)
	line := _strip_strings(raw)
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*\[\s*sizeof\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|\s+([A-Za-z_]\w*))\s*\]`, line, -1)
	m[1] == concat("", [m[2], m[3]])
	finding := _finding(path, i, raw)
}

# X[N] where X is declared X[N]
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	decls := _decls(content)
	count(decls) > 0
	union := _union(decls)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "[")
	regex.match(union, raw)
	not _is_comment(raw)
	line := _strip_strings(raw)
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.>])([A-Za-z_]\w*)\s*\[\s*([0-9]+|[A-Z_][A-Z0-9_]*|k[A-Z]\w*)\s*\]`, line, -1)
	name := m[1]
	[name, m[2]] in decls
	not regex.match(concat("", [`&\s*`, name, `\s*\[`]), line)
	not _is_decl_at(line, name, m[2])
	not regex.match(concat("", [`\bsizeof\s*\(?\s*`, name, `\s*\[`]), line)
	_nearest_size(lines, i, name) == m[2]
	finding := _finding(path, i, raw)
}

# for (...; i <= N; ...) X[i] with X declared X[N], or i <= sizeof(X)
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`for\s*\([^;]*;\s*[A-Za-z_]\w*\s*<=`, content)
	decls := _decls(content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "<=")
	not _is_comment(raw)
	some m in regex.find_all_string_submatch_n(`for\s*\([^;]*;\s*([A-Za-z_]\w*)\s*<=\s*(sizeof\s*\(?\s*[A-Za-z_]\w*\s*\)?|[0-9]+|[A-Z_][A-Z0-9_]*|k[A-Z]\w*)\s*;`, raw, 1)
	v := m[1]
	bound := m[2]
	body := concat("\n", [_strip_strings(l) | some l in array.slice(lines, i, _body_end(lines, i)); not _is_comment(l)])
	some am in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*\[\s*`, v, `\s*\]`]), body, -1)
	_bound_is_size(decls, lines, i, am[1], bound)
	finding := _finding(path, i, raw)
}

# A braced loop body is read for six lines; an unbraced one is the for line and
# the single statement after it, so the next loop's X[i] is not attributed to it.
_body_end(lines, i) := i + 6 if {
	regex.match(`\{\s*(//.*)?$`, lines[i])
} else := i + 6 if {
	count(lines) > i + 1
	regex.match(`^\s*\{`, lines[i + 1])
} else := i + 2

_bound_is_size(decls, lines, i, name, bound) if {
	[name, bound] in decls
	_nearest_size(lines, i, name) == bound
}

_bound_is_size(_, _, _, name, bound) if regex.match(concat("", [`^`, _sizeof(name), `$`]), bound)

# n = read(fd, X, sizeof X) ... X[n] = ...
_read_re := `\b([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?(?:::|std::)?(?:read|recv|pread)\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,\s*(sizeof\s*\(\s*[A-Za-z_]\w*\s*\)|[^,;)]+?)\s*[,)]`

_fread_re := `\b([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?fread\s*\(\s*([A-Za-z_]\w*)\s*,\s*1\s*,\s*(sizeof\s*\(\s*[A-Za-z_]\w*\s*\)|[^,;)]+?)\s*,`

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`\b(read|recv|pread|fread)\s*\(`, content)
	decls := _decls(content)
	lines := split(content, "\n")
	some j, src in lines
	regex.match(`\b(read|recv|pread|fread)\s*\(`, src)
	not _is_comment(src)
	some m in array.concat(regex.find_all_string_submatch_n(_read_re, src, 1), regex.find_all_string_submatch_n(_fread_re, src, 1))
	n := m[1]
	buf := m[2]
	size := trim_space(m[3])
	_full_size(decls, lines, j, buf, size)
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 6]))
	raw := lines[i]
	not _is_comment(raw)
	regex.match(concat("", [`\b`, buf, `\s*\[\s*`, n, `\s*\]\s*=[^=]`]), raw)
	finding := _finding(path, i, raw)
}

_full_size(_, _, _, buf, size) if regex.match(concat("", [`^`, _sizeof(buf), `$`]), size)

_full_size(decls, lines, j, buf, size) if {
	[buf, size] in decls
	_nearest_size(lines, j, buf) == size
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# The size of the nearest declaration of `name` at or above line i (within 300
# lines), when that declaration is an array; a nearer pointer or parameter
# declaration shadows an array of the same name elsewhere in the file.
_nearest_size(lines, i, name) := size if {
	re := concat("", [`(?:^\s*|[;{(,]\s*)(?:(?:static|const|unsigned|signed|struct|volatile|register|extern|constexpr)\s+)*([A-Za-z_][\w:]*)[\s*&]+`, name, `\s*(\[\s*([^\]]*?)\s*\]|=|;|,|\))`])
	decls := [m |
		some k in numbers.range(max([0, i - 300]), i)
		not _is_comment(lines[k])
		regex.match(re, lines[k])
		some m in regex.find_all_string_submatch_n(re, _strip_strings(lines[k]), 1)
		not m[1] in {"return", "case", "else", "goto", "sizeof", "do", "if", "while", "for", "switch"}
	]
	count(decls) > 0
	last := decls[count(decls) - 1]
	startswith(last[2], "[")
	size := last[3]
}
