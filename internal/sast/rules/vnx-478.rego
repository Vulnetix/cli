# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_478

import rego.v1

metadata := {
	"id": "VNX-478",
	"name": "Missing Default Case in Multiple Condition Expression",
	"description": "Reports a switch statement with no default label whose cases are the only thing that gives a variable its value, when that variable is read after the switch: in C/C++ a local declared without an initializer (or as NULL/nullptr), in Java a local initialised to null. An unhandled value then leaves the variable uninitialised (undefined behaviour in C/C++) or null, which is the concrete failure CWE-478 describes. Not reported: a switch with a default label, a variable given a real value before the switch (the author's own default: an initialiser, a later plain assignment, or its address passed to an initialising call such as init(&v)), a variable the code after the switch does not read, Java switch expressions (x = switch ..., return switch ..., whose exhaustiveness the compiler checks), Go (every variable has a defined zero value), and comments. A switch without default that assigns nothing is not reported: on its own it is a style choice, not a defect.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-478/",
	"languages": ["c", "cpp", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [478],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-default", "cwe-478"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".java"}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "c" if {
	not endswith(path, ".java")
	some e in _exts
	endswith(path, e)
}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_indent(line) := count(line) - count(trim_left(line, " \t"))

# A switch statement, not a Java switch expression (`x = switch`, `return switch`).
_switch_re := `^\s*(?:\}\s*)?switch\s*\(.*\)\s*\{?\s*(?://.*)?$`

# Closing brace of the switch body: the first `}` at the switch's indent.
_switch_end(lines, i) := k if {
	ii := _indent(lines[i])
	ends := [j |
		some j in numbers.range(i + 1, min([count(lines) - 1, i + 300]))
		_indent(lines[j]) == ii
		startswith(trim_left(lines[j], " \t"), "}")
	]
	count(ends) > 0
	k := ends[0]
}

_has_default(lines, i, k) if {
	some j in numbers.range(i + 1, k - 1)
	regex.match(`^\s*(?:case\b[^:]*:\s*)?default\s*(?::|->)`, lines[j])
}

_assigned(lines, i, k) := {m[1] |
	some j in numbers.range(i + 1, k - 1)
	not _is_comment(lines[j])
	some m in regex.find_all_string_submatch_n(`(?:^|[:;{]|->)\s*([A-Za-z_]\w*)\s*=[^=]`, lines[j], -1)
}

_kw := {"return", "goto", "break", "case", "delete", "throw", "else", "continue", "new", "sizeof"}

# Declared without a value (C/C++) in the function above the switch.
_uninit_decl(lines, i, v, "c") if {
	some j in numbers.range(max([0, i - 40]), i - 1)
	not _is_comment(lines[j])
	m := regex.find_all_string_submatch_n(concat("", [`^\s*((?:(?:const|unsigned|signed|struct|enum|static|long|short)\s+)*[A-Za-z_][\w:<>]*)[\s\*&]+(?:[A-Za-z_]\w*\s*(?:=\s*[^,;]+)?,\s*\*?\s*)*\*?\s*`, v, `\s*(?:=\s*(?:NULL|nullptr|\(\w+\s*\*\)\s*0)\s*)?;`]), lines[j], 1)
	count(m) > 0
	not _kw[m[0][1]]
}

_uninit_decl(lines, i, v, "java") if {
	some j in numbers.range(max([0, i - 40]), i - 1)
	not _is_comment(lines[j])
	regex.match(concat("", [`^\s*(?:final\s+)?[A-Za-z_][\w.<>\[\], ]*\s+`, v, `\s*=\s*null\s*;`]), lines[j])
}

# Given a real value between its declaration and the switch: a plain
# assignment of something other than NULL/null/0 (`len = HEADER_LEN;`), or its
# address passed to an initialiser (`init_flags(&flags);`).
_set_before(lines, i, v) if {
	some j in numbers.range(max([0, i - 40]), i - 1)
	not _is_comment(lines[j])
	_indent(lines[j]) <= _indent(lines[i])
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[;{])\s*`, v, `\s*=\s*([^=;][^;]*)`]), lines[j], 1)
	count(m) > 0
	not trim_space(m[0][1]) in {"NULL", "nullptr", "null", "0"}
}

_set_before(lines, i, v) if {
	some j in numbers.range(max([0, i - 40]), i - 1)
	not _is_comment(lines[j])
	_indent(lines[j]) <= _indent(lines[i])
	regex.match(concat("", [`&\s*`, v, `\b`]), lines[j])
}

# Read after the switch: on a later code line and not as the target of a
# fresh assignment.
_read_after(lines, k, v) if {
	some j in numbers.range(k + 1, min([count(lines) - 1, k + 20]))
	not _is_comment(lines[j])
	regex.match(concat("", [`\b`, v, `\b`]), lines[j])
	not regex.match(concat("", [`^\s*`, v, `\s*=[^=]`]), lines[j])
}

# The code after the switch tests the variable against NULL/null: the null
# initialiser is the author's "not set" default and the miss is handled.
_null_checked_after(lines, k, v) if {
	some j in numbers.range(k + 1, min([count(lines) - 1, k + 20]))
	regex.match(concat("", [`\b`, v, `\s*[!=]=\s*(?:NULL|nullptr|null|0)\b|\b(?:NULL|nullptr|null)\s*[!=]=\s*`, v, `\b|!\s*`, v, `\b|\b(?:if|while)\s*\(\s*`, v, `\s*[)&|]|(?i:assert)\w*\s*\(\s*`, v, `\b|\bObjects\.\w+\(\s*`, v, `\b`]), lines[j])
}

# switch (x % N) with a case for every residue cannot miss a value.
_total_modulo(lines, i, k) if {
	m := regex.find_all_string_submatch_n(`%\s*(\d+)\s*\)\s*\{?\s*$`, lines[i], 1)
	count(m) > 0
	n := to_number(m[0][1])
	cases := [j | some j in numbers.range(i + 1, k - 1); regex.match(`^\s*case\b`, lines[j])]
	count(cases) >= n
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, "switch")
	regex.match(`(?m)^\s*(?:\}\s*)?switch\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "switch")
	regex.match(_switch_re, line)
	k := _switch_end(lines, i)
	not _has_default(lines, i, k)
	some v in _assigned(lines, i, k)
	_uninit_decl(lines, i, v, lang)
	not _set_before(lines, i, v)
	_read_after(lines, k, v)
	not _null_checked_after(lines, k, v)
	not _total_modulo(lines, i, k)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("switch has no default case and only its cases assign '%s', which is read afterwards: an unhandled value leaves it uninitialised or null. Add a default that assigns it or fails", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
