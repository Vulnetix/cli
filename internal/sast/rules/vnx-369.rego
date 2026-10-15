# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_369

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-369",
	"name": "Divide By Zero",
	"description": "A division or modulo (/, %, /=, %=, also with a cast of the divisor) whose divisor is a variable assigned, within the 25 lines above, from outside the program, in C, C++, Go and Java: strconv.Atoi/ParseInt/ParseUint, FormValue/PostFormValue, URL.Query(), Header.Get, os.Args, flag.Int/Uint, atoi/atol/strtol/strtoul, argv[], Integer.parseInt, Long.parseLong or getParameter, and in C and C++ a variable read by scanf, sscanf or fscanf into &v. Not reported: a Java division inside a try whose catch takes ArithmeticException, a divisor compared with 0 (or bounded by 1: n < 1, n >= 1) or tested as a condition in the twelve lines above, a divisor clamped with max(1, ...) or Math.max(1, ...), constant and computed divisors, test files, and a slash in a URL, path, string literal or comment.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-369/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [369],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["divide-by-zero", "cwe-369"],
}

_skip(path) if endswith(path, ".lock")

_skip(path) if endswith(path, ".sum")

_skip(path) if endswith(path, ".min.js")

_skip(path) if endswith(path, ".min.css")

_source := `(strconv\.(Atoi|ParseInt|ParseUint)\(|\.FormValue\(|\.PostFormValue\(|URL\.Query\(\)|\.Header\.Get\(|os\.Args|\bflag\.(Int|Uint)|\batoi\(|\batol\(|strtol\(|strtoul\(|argv\[|Integer\.parseInt\(|Long\.parseLong\(|getParameter\()`

# Strings and comments are not code: blank them before looking for an operator.
_code_only(line) := out if {
	a := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)
	b := regex.replace(a, "`[^`]*`", "``")
	c := regex.replace(b, `'(?:[^'\\]|\\.)'`, `''`)
	out := regex.replace(c, `//.*$`, "")
}

# True when a comparison of v against zero appears in the lines above or on
# the line itself (a guard, or a ternary that avoids the division).
_guarded(lines, i, v) if {
	some j in numbers.range(max([0, i - 12]), i)
	regex.match(concat("", [`\b`, v, `\b\s*(==|!=|<=|>=|<|>)\s*0\b`]), lines[j])
}

_guarded(lines, i, v) if {
	some j in numbers.range(max([0, i - 12]), i)
	regex.match(concat("", [`\b0\s*(==|!=|<=|>=|<|>)\s*`, v, `\b`]), lines[j])
}

_guarded(lines, i, v) if {
	some j in numbers.range(max([0, i - 12]), i)
	regex.match(concat("", [`\bif\s*\(?\s*!?`, v, `\s*(\)|\{)`]), lines[j])
}

# A lower bound of one (if (n < 1) ..., n >= 1) excludes zero as well.
_guarded(lines, i, v) if {
	some j in numbers.range(max([0, i - 12]), i)
	regex.match(concat("", [`\b`, v, `\b\s*(<|<=|>|>=)\s*1\b|\b1\s*(<|<=|>|>=)\s*`, v, `\b`]), lines[j])
}

# Clamped on assignment: n = max(1, n), int n = Math.max(1, parse(...)).
_clamped(lines, j, i, v) if {
	some k in numbers.range(j, i)
	regex.match(concat("", [`\b`, v, `\s*:?=\s*(?:[\w\.]+\.)?max\(`]), lines[k])
}

_exts := {".c", ".cc", ".cpp", ".cxx", ".go", ".java"}

_source_words := {"Atoi(", "ParseInt(", "ParseUint(", "FormValue(", "Query()", "Header.Get(", "os.Args", "flag.Int", "flag.Uint", "atoi(", "atol(", "strtol(", "strtoul(", "argv[", "parseInt(", "parseLong(", "getParameter("}

_has_source(text) if {
	some w in _source_words
	contains(text, w)
}

_div_re := `[\w\)\]]\s*[/%]=?\s*(?:\(\s*(?:unsigned\s+)?(?:int|long|short|double|float|size_t)\s*\)\s*|(?:u?int(?:8|16|32|64)?|float(?:32|64)|long|double|size_t)\(\s*)?([A-Za-z_]\w*)\b`

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	_has_source(content)
	lines := split(content, "\n")
	n := count(lines)

	# variables assigned from a source, with the line that assigns them
	some j, src in lines
	_has_source(src)
	not helpers.is_comment_line(src)
	regex.match(_source, src)
	v := helpers.assigned_first(src)
	some i in numbers.range(j + 1, min([n - 1, j + 25]))
	line := lines[i]
	contains(line, v)
	_has_div(line)
	not helpers.is_comment_line(line)
	some hit in regex.find_all_string_submatch_n(_div_re, _code_only(line), 5)
	hit[1] == v
	not _guarded(lines, i, v)
	not _clamped(lines, j, i, v)
	not _caught(lines, i, n)
	finding := {
		"rule_id": metadata.id,
		"message": "Division by a value read from outside the program without a zero check; test the divisor before dividing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java: the division sits in a try whose handler catches ArithmeticException.
_caught(lines, i, n) if {
	some k in numbers.range(i + 1, min([n - 1, i + 8]))
	regex.match(`catch\s*\(\s*(?:final\s+)?(?:java\.lang\.)?(?:ArithmeticException|RuntimeException|Exception)\b`, lines[k])
}

# C/C++: scanf/sscanf/fscanf read a number into &v.
findings contains finding if {
	some path, content in input.file_contents
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
	not helpers.is_test_path(path)
	contains(content, "scanf(")
	lines := split(content, "\n")
	n := count(lines)
	some j, src in lines
	contains(src, "scanf(")
	not helpers.is_comment_line(src)
	regex.match(`\b(?:f|s|v|vf|vs)?scanf(?:_s)?\s*\(`, src)
	some m in regex.find_all_string_submatch_n(`&\s*([A-Za-z_]\w*)\b`, src, 8)
	v := m[1]
	some i in numbers.range(j, min([n - 1, j + 25]))
	line := lines[i]
	contains(line, v)
	_has_div(line)
	not helpers.is_comment_line(line)
	some hit in regex.find_all_string_submatch_n(_div_re, _code_only(line), 5)
	hit[1] == v
	not _guarded(lines, i, v)
	not _clamped(lines, j, i, v)
	finding := {
		"rule_id": metadata.id,
		"message": "Division by a value read from outside the program without a zero check; test the divisor before dividing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_has_div(line) if contains(line, "/")

_has_div(line) if contains(line, "%")
