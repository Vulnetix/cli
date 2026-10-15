# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_686

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-686",
	"name": "Function Call With Incorrect Argument Type",
	"description": "A C or C++ printf- or scanf-family call with a literal format passes an argument whose type visibly does not match its conversion, which is undefined behaviour: the call reads the wrong number of bytes, or dereferences an integer as a pointer. Reported for printf, fprintf, sprintf, snprintf, dprintf and syslog when the argument count matches the format: a %d/%i/%u/%x/%o/%c (no l, ll, z or j modifier) given sizeof, strlen()/wcslen()/strnlen() or a C++ .size()/.length() (size_t, 64 bits on LP64); a %s given an integer or character literal, sizeof, strlen(), std::to_string(), .str() or a variable declared std::string in the file (missing .c_str()); an integer conversion given a string literal or .c_str(); a %f/%e/%g given an integer literal; and a bare variable whose declaration in the 60 lines above fixes its type (one type only, no pointer or array declaration of the name in view) passed to a conversion it cannot match: size_t, ssize_t, off_t, long or 64-bit integers, or float/double, to an unmodified %d/%u/%x/%c; double to %ld; an integer to %f; a number or char to %s. Reported for scanf, fscanf and sscanf: a conversion given a bare variable declared in the file as a plain int, long, short, unsigned, float, double, char or size_t instead of its address. Not reported: %zu/%zd and %lu, explicit casts, pointers and arrays passed to scanf, calls whose argument count differs from the format (VNX-685 reports those), calls split over several lines, macro-built formats, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-686/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [686],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["format-argument-type", "cwe-686"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_blank(s) := regex.replace(regex.replace(s, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_pre := `(?:^|[^\w.>])(?:std::)?`

_lit := `\s*"((?:\\.|[^"\\])*)"(.*)$`

_one := `\s*[^,"()]+(?:\([^()]*\))?\s*,`

_printf_res := [
	concat("", [_pre, `printf\s*\(`, _lit]),
	concat("", [_pre, `(?:fprintf|sprintf|dprintf|syslog)\s*\(`, _one, _lit]),
	concat("", [_pre, `snprintf\s*\(`, _one, _one, _lit]),
]

_scanf_res := [
	concat("", [_pre, `scanf\s*\(`, _lit]),
	concat("", [_pre, `(?:fscanf|sscanf)\s*\(`, _one, _lit]),
]

_pspec := `%[-+ #0']*(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|L|z|j|t|q|I64|I32)?([diouxXeEfFgGaAcspn])`

_sspec := `%(\*)?\d*(hh|h|ll|l|L|z|j|t|q|m)?([diouxXaAeEfFgGcspn]|\[\^?\]?[^\]]*\])`

_star("*") := ["*"]

_star(x) := [] if x != "*"

# Each argument the format consumes, in order: "*" for a * width or
# precision, else the length modifier and conversion ("", "d"), ("z", "u").
_printf_kinds(fmt) := ks if {
	f := replace(fmt, "%%", "")
	not regex.match(`%\d+\$`, f)
	specs := regex.find_all_string_submatch_n(_pspec, f, -1)
	count(indexof_n(f, "%")) == count(specs)
	ks := [k | some s in specs; some k in array.concat(array.concat(_star(s[1]), _star(s[2])), [[s[3], s[4]]])]
}

_scanf_kinds(fmt) := ks if {
	f := replace(fmt, "%%", "")
	not regex.match(`%\d+\$`, f)
	specs := regex.find_all_string_submatch_n(_sspec, f, -1)
	count(indexof_n(f, "%")) == count(specs)
	ks := [[s[2], s[3]] | some s in specs; s[1] != "*"]
}

_strip_nested(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "_"), `\([^()]*\)`, "_"), `\([^()]*\)`, "_")

_args(rest) := args if {
	r := _strip_nested(regex.replace(_blank(rest), `\{[^{}]*\}`, "_"))
	m := regex.find_all_string_submatch_n(`^\s*,([^()]*)\)`, r, 1)
	count(m) > 0
	args := [trim_space(a) | some a in split(m[0][1], ",")]
}

_int_conv(k) if {
	k != "*"
	k[0] in {"", "h", "hh"}
	k[1] in {"d", "i", "u", "o", "x", "X", "c"}
}

_size_t(a) if regex.match(`^sizeof(?:_|\s)`, a)

_size_t(a) if regex.match(`^(?:std::)?(?:strlen|wcslen|strnlen)_$`, a)

_size_t(a) if regex.match(`^[\w.>-]*[\w\]]\.(?:size|length)_$`, a)

_int_lit(a) if regex.match(`^-?(?:\d+|0[xX][0-9a-fA-F]+)[uUlL]*$`, a)

_mismatch(k, a, _) if {
	_int_conv(k)
	_size_t(a)
}

_mismatch(k, a, _) if {
	_int_conv(k)
	regex.match(`^(?:""|.*\.c_str_)$`, a)
}

_mismatch(k, a, content) if {
	k != "*"
	k[0] == ""
	k[1] == "s"
	_str_mismatch(a, content)
}

_mismatch(k, a, _) if {
	k != "*"
	k[1] in {"f", "F", "e", "E", "g", "G", "a", "A"}
	_int_lit(a)
}

# A bare variable whose declaration in the 60 lines above gives its type
# class. Exactly one class must match (a name redeclared with another type
# in a nearby scope is not judged), and no pointer or array declaration of
# the name may be in view.
_decl_q := `(?m)^\s*(?:(?:static|const|register|volatile)\s+)*`

_decl_tail(a) := concat("", [`\s+(?:[\w\s,=.+-]*?,\s*)?`, a, `\s*[;=,]`])

_class_re := {
	"wide": `(?:size_t|ssize_t|off_t|ptrdiff_t|u?int64_t|unsigned\s+long(?:\s+long)?(?:\s+int)?|long(?:\s+long)?(?:\s+int)?)`,
	"float": `(?:float|double|long\s+double)`,
	"int": `(?:int|short|short\s+int|unsigned|unsigned\s+int|unsigned\s+short|signed|u?int(?:8|16|32)_t|char|unsigned\s+char|signed\s+char|bool)`,
}

_decl_class(a, win) := c if {
	regex.match(`^[A-Za-z_]\w*$`, a)
	cs := {k | some k, t in _class_re; regex.match(concat("", [_decl_q, t, _decl_tail(a)]), win)}
	count(cs) == 1
	some c in cs
	not regex.match(concat("", [`\*\s*`, a, `\s*[,;=)\[]|\b`, a, `\s*\[`]), win)
}

_mismatch(k, a, win) if {
	_int_conv(k)
	_decl_class(a, win) in {"wide", "float"}
}

_mismatch(k, a, win) if {
	k != "*"
	k[0] == "l"
	k[1] in {"d", "i", "u", "o", "x", "X"}
	_decl_class(a, win) == "float"
}

_mismatch(k, a, win) if {
	k != "*"
	k[0] in {"", "l"}
	k[1] in {"f", "F", "e", "E", "g", "G", "a", "A"}
	_decl_class(a, win) in {"int", "wide"}
}

_str_mismatch(a, win) if _decl_class(a, win) in {"int", "wide", "float"}

_str_mismatch(a, _) if _int_lit(a)

_str_mismatch(a, _) if a == "''"

_str_mismatch(a, _) if _size_t(a)

_str_mismatch(a, _) if regex.match(`^(?:std::to_string_|std::w?string_|[\w.>-]*[\w\]]\.str_)$`, a)

_str_mismatch(a, content) if {
	regex.match(`^\w+$`, a)
	regex.match(concat("", [`\b(?:std::)?w?string\s*&?\s*`, a, `\b\s*[,;=)({]`]), content)
}

_plain_decl(a, win) if {
	regex.match(`^[A-Za-z_]\w*$`, a)
	regex.match(concat("", [`(?m)^\s*(?:(?:static|unsigned|signed|const|register)\s+)*(?:int|long|long\s+long|short|unsigned|float|double|char|size_t|ssize_t|u?int\d+_t)\s+(?:[\w\s,=.-]*?,\s*)?`, a, `\s*[;=,]`]), win)
	not regex.match(concat("", [`\*\s*`, a, `\s*[,;=)\[]`]), win)
}

_bad(lines, i, line) if {
	regex.match(`printf|syslog`, line)
	some re in _printf_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	ks := _printf_kinds(m[0][1])
	xs := _args(m[0][2])
	count(ks) == count(xs)
	some idx, k in ks
	_mismatch(k, xs[idx], helpers.code_window(lines, i, 60, 0))
}

_bad(lines, i, line) if {
	contains(line, "scanf")
	some re in _scanf_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	ks := _scanf_kinds(m[0][1])
	xs := _args(m[0][2])
	count(ks) == count(xs)
	some a in xs
	_plain_decl(a, helpers.code_window(lines, i, 40, 0))
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`printf|scanf|syslog`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`printf\s*\(|scanf\s*\(|syslog\s*\(`, line)
	not helpers.is_comment_line(line)
	regex.match(`printf\s*\(|scanf\s*\(|syslog\s*\(`, _blank(line))
	_bad(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Argument type does not match its format conversion: size_t passed to %d, a non-string to %s, a string to an integer conversion, or a scanf target passed by value instead of by address. Fix the conversion (%zu) or the argument (.c_str(), &var)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
