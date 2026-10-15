# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_457

import rego.v1

metadata := {
	"id": "VNX-457",
	"name": "Use of Uninitialized Variable",
	"description": "C/C++ function-local variables read before anything is stored in them. A local scalar (int, long, char, double, size_t, intN_t, bool...) declared without an initialiser and without static/extern is reported at its first mention in the same block, within 25 lines, when that mention reads it: return v, v++/++v, a compound assignment (v += ...), the right-hand side of an assignment, an if/while/switch condition, a printf-family argument, or std::cout << v. A local char array declared without an initialiser is reported when its first mention is strcat/strncat/strlen/strdup/puts or a printf argument. Not reported: a first mention that assigns (v = ..., for (v = 0;...), cin >> v), takes the address (&v, scanf, FD_ZERO), or passes the variable to a call that may fill it (C++ references, macros), a variable assigned on every branch before the read, static and namespace-scope variables (zero-initialised), struct/class/union members, and comments or string literals. Flow across functions, through pointers and after the first mention is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-457/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [457],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["uninitialized", "cwe-457"],
}

_c_ext := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_is_c(path) if {
	some ext in _c_ext
	endswith(path, ext)
}

_type := `(?:(?:register|volatile|unsigned|signed|long|short)\s+)*(?:int|long|short|char|float|double|size_t|ssize_t|unsigned|signed|bool|_Bool|off_t|time_t|u?int(?:8|16|32|64)_t|u?intptr_t|ptrdiff_t)`

_decl_re := concat("", [`^([ \t]+)(`, _type, `)\s+(\*?)\s*([A-Za-z_]\w*)\s*(\[[^\]]+\])?\s*;\s*(?://.*|/\*.*)?$`])

_gate_re := concat("", [`(?m)^[ \t]+`, _type, `\s+\*?\s*[A-Za-z_]\w*\s*(?:\[[^\]]+\])?\s*;`])

_indent(line) := count(line) - count(trim_left(line, " \t"))

_blank_or_pp(l) if trim_space(l) == ""

_blank_or_pp(l) if startswith(trim_space(l), "#")

# The line that opens the declaration's block, skipping a lone Allman brace.
_opener(lines, i, ind) := op if {
	ks := [k |
		some d in numbers.range(1, min([i, 60]))
		k := i - d
		not _blank_or_pp(lines[k])
		_indent(lines[k]) < ind
	]
	count(ks) > 0
	k := ks[0]
	op := _with_prev(lines, k)
}

_with_prev(lines, k) := concat(" ", [lines[k - 1], lines[k]]) if {
	k > 0
	trim_space(lines[k]) == "{"
}

_with_prev(lines, k) := lines[k] if {
	not trim_space(lines[k]) == "{"
}

_with_prev(lines, 0) := lines[0] if trim_space(lines[0]) == "{"

_aggregate_scope(op) if regex.match(`^\s*(?:template\s*<[^>]*>\s*)?(?:typedef\s+)?(?:(?:static|const)\s+)*(?:struct|class|union|enum|namespace)\b[^()]*$|^\s*(?:public|private|protected)\s*:|extern\s+"C"`, op)

_strip(l) := regex.replace(regex.replace(l, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `//.*$|/\*.*?\*/`, "")

# Index of the first line after the declaration, inside its block, that names v.
_first_mention(lines, i, ind, v) := j if {
	last := min([count(lines) - 1, i + 25])
	last > i
	vre := concat("", [`\b`, v, `\b`])
	js := [k |
		some k in numbers.range(i + 1, last)
		contains(lines[k], v)
		not _ccomment(lines[k])
		regex.match(vre, _strip(lines[k]))
	]
	count(js) > 0
	j := js[0]
	not _block_ends(lines, i, j, ind)
}

_block_ends(lines, i, j, ind) if {
	i + 1 <= j - 1
	some k in numbers.range(i + 1, j - 1)
	not _blank_or_pp(lines[k])
	_indent(lines[k]) < ind
}

# Comment lines; a leading "*" counts only when it is not a dereference.
_ccomment(l) if startswith(trim_space(l), "//")

_ccomment(l) if startswith(trim_space(l), "/*")

_ccomment(l) if regex.match(`^\s*\*(?:\s|/|$)`, l)

_writes(l, v) if regex.match(concat("", [`(?:^|[^.>:\w])`, v, `\s*=[^=]`]), l)

_writes(l, v) if regex.match(concat("", [`&\s*`, v, `\b|>>\s*`, v, `\b|sizeof\s*\(?\s*`, v, `\b`]), l)

_reads_scalar(l, v) if regex.match(concat("", [`\breturn\s*\(?\s*`, v, `\s*\)?\s*;`]), l)

_reads_scalar(l, v) if regex.match(concat("", [`(?:^|[^.>:\w])`, v, `\s*(?:\+\+|--|[-+*/%&|^]=|<<=|>>=)|(?:\+\+|--)\s*`, v, `\b`]), l)

_reads_scalar(l, v) if regex.match(concat("", [`[^=!<>]=\s*[^;(]*?(?:^|[^.>:\w])`, v, `\b`]), l)

_reads_scalar(l, v) if regex.match(concat("", [`\b(?:if|while|switch)\s*\(\s*!?\s*`, v, `\s*(?:[<>=!]=?|\)|&&|\|\||[-+*/%])`]), l)

_reads_scalar(l, v) if regex.match(concat("", [`\b(?:f|s|sn|d)?printf\s*\([^;]*,\s*`, v, `\s*[,)]`]), l)

_reads_scalar(l, v) if regex.match(concat("", [`<<\s*`, v, `\s*(?:<<|;)`]), l)

_reads_array(l, v) if regex.match(concat("", [`\b(?:strn?cat|strlen|strdup|puts)\s*\(\s*`, v, `\s*[,)]|\b(?:f|s|sn)?printf\s*\([^;]*,\s*`, v, `\s*[,)]`]), l)

_report(m, l, v) if {
	m[5] == ""
	not _writes(l, v)
	_reads_scalar(l, v)
}

_report(m, l, v) if {
	m[5] != ""
	m[3] == ""
	endswith(m[2], "char")
	not _writes(l, v)
	_reads_array(l, v)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	endswith(trim_right(line, " \t\r"), ";")
	ms := regex.find_all_string_submatch_n(_decl_re, line, 1)
	count(ms) > 0
	m := ms[0]
	not regex.match(`\b(?:static|extern|thread_local|return|typedef)\b`, line)
	ind := _indent(line)
	v := m[4]
	j := _first_mention(lines, i, ind, v)
	l := _strip(lines[j])
	_report(m, l, v)
	op := _opener(lines, i, ind)
	not _aggregate_scope(op)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is declared without an initialiser and read here before any value is stored in it; initialise it at the declaration", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}
