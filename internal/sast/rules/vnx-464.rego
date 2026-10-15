# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_464

import rego.v1

metadata := {
	"id": "VNX-464",
	"name": "Addition of Data Structure Sentinel",
	"description": "C/C++ code that stores a number parsed from input into an element of a character buffer, so an input of 0 places a NUL terminator in the middle of the string and silently truncates it (and other values may inject separators). Reported: buf[i] = atoi/atol/atoll/strtol/strtoul/strtoll/strtoull(...) or std::stoi/stol/stoul(...), optionally cast to char (C cast or static_cast<char>), and buf[i] = v where v was assigned such a conversion in the 5 lines above with no if/while test of v in between, when buf is declared in the same file as a char array or char pointer. Multi-dimensional char arrays (grid[r][c] = atoi(s)) are included. Not reported: stores into int/long arrays and unsigned char byte buffers (where 0 is data), a conversion used only as a condition (atoi(s) ? 'Y' : 'N'), a converted value range-checked before the store, constant characters and '\\0', comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-464/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [464],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["sentinel-added-data", "cwe-464"],
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

_conv := `(?:std::)?(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|stoi|stol|stoul)\s*\(`

_cast := `(?:\(\s*(?:unsigned\s+|signed\s+)?char\s*\)\s*|static_cast\s*<\s*(?:unsigned\s+|signed\s+)?char\s*>\s*\(\s*)?`

_direct_re := concat("", [`\b([A-Za-z_]\w*)\s*(?:\[[^\]]+\]\s*)+=\s*`, _cast, _conv])

_store_re := concat("", [`\b([A-Za-z_]\w*)\s*(?:\[[^\]]+\]\s*)+=\s*`, _cast, `([A-Za-z_]\w*)\s*\)?\s*;`])

# A conversion used only as a condition (atoi(s) ? 'Y' : 'N', atoi(s) > 0 ? ...) stores a constant.
_conditional(l) if contains(l, "?")

_conditional(l) if regex.match(concat("", [_conv, `[^;]*\)\s*(?:[<>]=?|[=!]=|&&|\|\|)`]), l)

# The buffer receiving a converted number.
_target(_, _, l) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_direct_re, l, 1)
	count(m) > 0
}

_target(lines, i, l) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_store_re, l, 1)
	count(m) > 0
	v := m[0][2]
	i > 0
	some d in numbers.range(1, min([i, 5]))
	j := i - d
	regex.match(concat("", [`\b`, v, `\s*=\s*(?:\([\w ]+\)\s*)?`, _conv]), lines[j])
	not _tested(lines, j, i, v)
}

_tested(lines, j, i, v) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	regex.match(concat("", [`\b(?:if|while)\s*\(.*\b`, v, `\b`]), lines[k])
}

# Declared as plain or signed char (a string); unsigned char is a byte buffer, where 0 is data.
_char_buffer(content, buf) if {
	ms := regex.find_all_string_submatch_n(concat("", [`(?m)(\w*)\s+char\s*\*?\s*`, buf, `\s*[\[;=,)]|(?:^|[(,;{])\s*()char\s*\*?\s*`, buf, `\s*[\[;=,)]`]), content, -1)
	some m in ms
	m[1] != "unsigned"
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`\b(?:ato(?:i|l|ll)|strto(?:l|ul|ll|ull)|sto(?:i|l|ul))\s*\(`, content)
	contains(content, "char")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "]")
	regex.match(`\]\s*=[^=]`, line)
	not _comment(line)
	l := _strip(line)
	some buf in {_target(lines, i, l)}
	_char_buffer(content, buf)
	not _conditional(l)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("A number parsed from input is stored into the character buffer '%s'; an input of 0 inserts a NUL terminator and truncates the string. Validate the range before storing it", [buf]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
