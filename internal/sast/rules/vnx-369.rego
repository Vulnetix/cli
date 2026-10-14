# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_369

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-369",
	"name": "Divide By Zero",
	"description": "A division whose divisor is a variable assigned from outside the program (a parsed number, a request value, a command-line argument) with no zero check in the lines above. The operator is found in code only: a URL, a path, a purl, a string literal or a comment that happens to contain a slash is not a division.",
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

findings contains finding if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".go", ".java"}
	some path in object.keys(input.file_contents)
	endswith(path, ext)
	not _skip(path)
	not helpers.is_test_path(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _code_only(line)
	m := regex.find_all_string_submatch_n(`[\w\)\]]\s*[/%]\s*([A-Za-z_]\w*)\b`, code, 5)
	some hit in m
	v := hit[1]
	some tainted in helpers.tainted_names(lines, i, 25, _source)
	tainted == v
	not _guarded(lines, i, v)
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
