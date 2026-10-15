# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_786

import rego.v1

metadata := {
	"id": "VNX-786",
	"name": "Access of Memory Location Before Start of Buffer",
	"description": "Reports C/C++ indexing that reaches before the start of a buffer when the length is zero or a call failed: X[strlen(Y) - 1] with no length or first-byte check in the three lines above, X[n - 1] where n was assigned from strlen() with no check of n in between, X[n] or X[n - 1] where n was assigned from read()/recv()/recvfrom()/readlink()/pread() (also ::read and std:: spellings, which return -1 on error) with no check of n in between, and a literal negative index on a name whose nearest declaration above is an array. Negative indexes on pointers or parameters (p[-1] into the middle of a buffer) lengths checked anywhere between the assignment and the index (including strlen(Y) == 0), and n = strlen(s) + 1 (never zero) are deliberately not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-786/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [786],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["buffer-oob", "cwe-786"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_c_file(path) if {
	some ext in _exts
	endswith(path, ext)
}

_is_comment(line) if regex.match(`^\s*(//|/\*|\*)`, line)

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_msg := "Index can fall before the start of the buffer (length 0 or a -1 error return makes it negative). Check the length/return value before indexing"

# X[strlen(Y) - 1]
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "strlen")
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "strlen")
	not _is_comment(raw)
	line := _strip_strings(raw)
	some m in regex.find_all_string_submatch_n(`\[\s*strlen\s*\(\s*([\w.>\-]+?)\s*\)\s*-\s*1\s*\]`, line, -1)
	y := m[1]
	win := concat("\n", [_strip_strings(l) | some l in array.slice(lines, max([0, i - 3]), i + 1); not _is_comment(l)])
	not _strlen_guard(win, y)
	finding := _finding(path, i, raw)
}

_q(s) := regex.replace(s, `([.\->])`, `\\$1`)

_strlen_guard(win, y) if regex.match(concat("", [`strlen\s*\(\s*`, _q(y), `\s*\)\s*(>|!=|>=|==|<|<=)`]), win)

_strlen_guard(win, y) if regex.match(concat("", [`\b`, _q(y), `\s*\[\s*0\s*\]`]), win)

_strlen_guard(win, y) if regex.match(concat("", [`(\(|&&|\|\||!)\s*\*\s*`, _q(y), `\b`]), win)

# n = strlen(..) / read(..); ... X[n - 1] or X[n]
_src_re := `\b([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?(?:::|std::)?(strlen|read|recv|recvfrom|readlink|pread)\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`\b(strlen|read|recv|recvfrom|readlink|pread)\s*\(`, content)
	lines := split(content, "\n")
	some j, src in lines
	contains(src, "=")
	regex.match(_src_re, src)
	not _is_comment(src)
	some m in regex.find_all_string_submatch_n(_src_re, src, -1)
	n := m[1]
	fn := m[2]
	# n = strlen(s) + 1 is never zero
	not regex.match(concat("", [`\b`, n, `\s*=\s*(?:\([^)]*\)\s*)?(?:::|std::)?`, fn, `\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\+`]), src)
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 6]))
	raw := lines[i]
	not _is_comment(raw)
	line := _strip_strings(raw)
	_sink(line, n, fn)
	not _guarded(lines, j, i, n)
	finding := _finding(path, i, raw)
}

_sink(line, n, _) if regex.match(concat("", [`\w\s*\[\s*`, n, `\s*-\s*1\s*\]`]), line)

_sink(line, n, fn) if {
	fn != "strlen"
	regex.match(concat("", [`\w\s*\[\s*`, n, `\s*\]`]), line)
}

_guarded(lines, j, i, n) if {
	some k in numbers.range(j, i)
	l := _strip_strings(lines[k])
	not _is_comment(l)
	_check(l, n)
}

# if ((n = read(...)) <= 0) checks the result on the assignment line itself
_guarded(lines, j, _, n) if regex.match(concat("", [n, `\s*=[^=;]*\)\s*\)\s*(<|<=|==|!=)\s*-?\d`]), lines[j])

_check(l, n) if regex.match(concat("", [`\b`, n, `\s*(<|<=|>|>=|==|!=)[^=]`]), l)

_check(l, n) if regex.match(concat("", [`(<|<=|>|>=|==|!=)\s*`, n, `\b`]), l)

_check(l, n) if regex.match(concat("", [`!\s*`, n, `\b`]), l)

_check(l, n) if regex.match(concat("", [`\(\s*`, n, `\s*(\)|&&|\|\|)`]), l)

_check(l, n) if regex.match(concat("", [`\b`, n, `\s*(&&|\|\|)`]), l)

# literal negative index on an array declared in this file (the nearest
# declaration of the name above the use is an array, not a pointer or parameter)
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`\w\s*\[\s*-\s*\d+\s*\]`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`\w\s*\[\s*-\s*\d+\s*\]`, raw)
	not _is_comment(raw)
	line := _strip_strings(raw)
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*\[\s*-\s*\d+\s*\]`, line, -1)
	name := m[1]
	_nearest_is_array(lines, i, name)
	finding := _finding(path, i, raw)
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

_nearest_is_array(lines, i, name) if {
	i > 0
	re := concat("", [`(?:^\s*|[;{(,]\s*)(?:(?:static|const|unsigned|signed|struct|volatile|register|extern)\s+)*([A-Za-z_]\w*)[\s*&]+`, name, `\s*(\[|=|;|,|\))`])
	decls := [[k, m] |
		some k in numbers.range(max([0, i - 300]), i - 1)
		not _is_comment(lines[k])
		regex.match(re, lines[k])
		some m in regex.find_all_string_submatch_n(re, lines[k], 1)
		not _keyword[m[1]]
	]
	count(decls) > 0
	last := decls[count(decls) - 1]
	last[1][2] == "["
}

_keyword := {"return", "case", "else", "goto", "sizeof", "do", "if", "while", "for", "switch"}
