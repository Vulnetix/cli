# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_587

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-587",
	"name": "Assignment of a Fixed Address to a Pointer",
	"description": "An integer literal cast to a pointer type and assigned to a pointer, returned, bound by a #define, or dereferenced as a statement in C or C++: T *p = (T *)0x40020000; *(volatile uint32_t *)0x40021018 |= 4; p = (volatile uint32_t *)0x8000u; #define REG (*(volatile unsigned *)0x4000C000); reinterpret_cast<T *>(0x1F000000), including a cast whose literal continues on the next line. A hard-coded address ties the code to one memory layout and breaks (or becomes exploitable) when that layout changes. Only addresses of 0x1000 or above count. Not reported: null and sentinel values below the first page (0, -1, 0x100 list poison), all-ones values, well-known poison patterns (0xdeadbeef, 0xdeadc0de), casts to integer types, address arithmetic on a base pointer, casts compared with == or passed as arguments, comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-587/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [587],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["assigning-fixed-address", "cwe-587"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}

_lang(path) if {
	some ext in _exts
	endswith(path, ext)
}

# What binds the cast: a #define, an assignment or initialisation (not ==,
# !=, <=, >=), or a return.
_prefix := `(?:^\s*#\s*define\s+\w+(?:\([^)]*\))?\s+|[^=!<>]=\s*|\breturn\s+|^\s*\*\s*)[(*\s]*`

_cast := `(?:\((?:\s*(?:const|volatile|struct|union|unsigned|signed)\s+)*[\w:]+(?:\s+[\w:]+)*\s*\*+\s*(?:(?:const|volatile)\s*)*\)|reinterpret_cast\s*<[^<>]*\*\s*>)`

_value := `\s*\(?\s*(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\s*\)?\s*(?:[;),]|$|(?:[-+*/%&|^]|<<|>>)?=[^=])`

_same_line_re := concat("", [_prefix, _cast, _value])

_split_head_re := concat("", [_prefix, _cast, `\s*$`])

_split_tail_re := concat("", [`^`, _value])

# Lines that are only a comment; #define stays code.
_comment(line) if startswith(trim_space(line), "//")

_comment(line) if startswith(trim_space(line), "/*")

# A block-comment continuation (" * text"), not a dereference statement
# such as "*(volatile uint32_t *)0x40021018 |= 4;".
_comment(line) if {
	regex.match(`^\s*\*(?:\s|$)`, line)
	not regex.match(`^\s*\*\s*\(`, line)
}

_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$|/\*.*?\*/`, "")

# An address at or above the first page that is not a poison pattern.
_fixed(v) if {
	startswith(lower(v), "0x")
	h := trim_left(substring(lower(v), 2, -1), "0")
	count(h) >= 4
	not regex.match(`^f+$`, h)
	not regex.match(`dead|beef|c0de|cafe|babe|f00d|feed`, h)
}

_fixed(v) if {
	regex.match(`^[1-9][0-9]*$`, v)
	to_number(v) >= 4096
}

_hit(lines, i, c) if {
	m := regex.find_all_string_submatch_n(_same_line_re, c, -1)
	some x in m
	_fixed(x[1])
}

_hit(lines, i, c) if {
	regex.match(_split_head_re, c)
	i + 1 < count(lines)
	m := regex.find_all_string_submatch_n(_split_tail_re, _code(lines[i + 1]), 1)
	count(m) > 0
	_fixed(m[0][1])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	regex.match(`\*\s*(?:\)|>)\s*\(?\s*[0-9]`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "*")
	regex.match(`\*\s*(?:\)|>)`, line)
	not _comment(line)
	_hit(lines, i, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Pointer assigned a fixed, hard-coded address: the code depends on one memory layout and breaks or becomes exploitable when it changes. Take the address from the platform's linker map, device tree, mmap() or a named constant supplied by the board support package",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
