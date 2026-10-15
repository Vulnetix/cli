# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_463

import rego.v1

metadata := {
	"id": "VNX-463",
	"name": "Deletion of Data Structure Sentinel",
	"description": "C/C++ code that overwrites a string's NUL terminator with another character and does not write a new one, so every later string operation on the buffer reads past its end. Reported: buf[strlen(buf)] = c (or wcslen), and buf[n] = c or buf[n++] = c where n was assigned strlen(buf) in the 10 lines above (and not changed since), when c is not '\\0'/0 and none of the next 3 code lines writes a NUL into the same buffer (buf[n + 1] = '\\0', buf[++n] = 0...). Not reported: a write of '\\0' at that position, an index other than the length (buf[n - 1]), a write into a different buffer than the one measured, an append that re-terminates on the following lines (a NUL store, or strcpy/snprintf into buf + n), a buffer next consumed with an explicit byte count (write/send/fwrite/memcpy of buf within 3 lines), comments and string literals. Lengths carried through structs or other functions are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-463/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [463],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["deletion-unexpected-state", "cwe-463"],
}

_c_ext := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_is_c(path) if {
	some ext in _c_ext
	endswith(path, ext)
}

_comment(l) if startswith(trim_space(l), "//")

_comment(l) if startswith(trim_space(l), "/*")

_comment(l) if regex.match(`^\s*\*(?:\s|/|$)`, l)

_strip(l) := regex.replace(regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$|/\*.*?\*/`, "")

_nul := `(?:'\\0'|'\\x00'|L?'\\0'|0|NUL|\(char\)\s*0|\(\w+\)\s*'\\0')`

_is_nul(v) if regex.match(concat("", [`^\s*`, _nul, `\s*$`]), v)

_strlen := `(?:std::)?(?:strlen|wcslen)\s*\(\s*`

# [buffer, value] for buf[strlen(buf)] = value
_overwrite(_, _, l) := [m[0][1], m[0][3]] if {
	m := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*\[\s*`, _strlen, `([A-Za-z_]\w*)\s*\)\s*\]\s*=\s*([^=;][^;]*);`]), l, 1)
	count(m) > 0
	m[0][1] == m[0][2]
}

# [buffer, value] for n = strlen(buf); ... buf[n] = value
_overwrite(lines, i, l) := [buf, m[0][3]] if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*(?:\+\+\s*)?\]\s*=\s*([^=;][^;]*);`, l, 1)
	count(m) > 0
	buf := m[0][1]
	idx := m[0][2]
	i > 0
	some d in numbers.range(1, min([i, 10]))
	j := i - d
	regex.match(concat("", [`\b`, idx, `\s*=\s*(?:\([\w ]+\)\s*)?`, _strlen, buf, `\s*\)`]), lines[j])
	not _changed(lines, j, i, idx)
}

_changed(lines, j, i, idx) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	regex.match(concat("", [`\b`, idx, `\s*(?:\+\+|--|[-+]?=[^=])|(?:\+\+|--)\s*`, idx, `\b`]), lines[k])
}

_reterminated(lines, i, buf) if {
	i + 1 < count(lines)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	regex.match(concat("", [`\b`, buf, `\s*\[[^\]]*\]\s*=\s*`, _nul, `\s*;`]), lines[k])
}

# A string copy or format into the bytes after the store writes a new terminator.
_reterminated(lines, i, buf) if {
	i + 1 < count(lines)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	regex.match(concat("", [`\b(?:strn?cpy|strlcpy|s?n?printf|wcsn?cpy|swprintf)\s*\(\s*(?:&\s*)?`, buf, `\s*(?:\+|\[)`]), lines[k])
}

# The buffer is next consumed with an explicit byte count, not as a string.
_reterminated(lines, i, buf) if {
	i + 1 < count(lines)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	regex.match(concat("", [`\b(?:write|send|sendto|fwrite|memcpy|memmove|SSL_write)\s*\([^;]*\b`, buf, `\s*,`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "len")
	regex.match(`(?:strlen|wcslen)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "]")
	regex.match(`\]\s*=[^=]`, line)
	not _comment(line)
	l := _strip(line)
	some o in {_overwrite(lines, i, l)}
	not _is_nul(o[1])
	not _reterminated(lines, i, o[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("This store overwrites the NUL terminator of '%s' and no new terminator is written; later string operations read past the end of the buffer", [o[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
