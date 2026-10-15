# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1069

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1069",
	"name": "Empty Exception Block",
	"description": "A Java catch block whose body is empty: nothing but whitespace between its braces, written on one line (catch (IOException e) {}) or across lines (the brace on the next line, an empty line inside). The exception is swallowed with no log, rethrow, return or recorded decision, so a failure the program should react to disappears. Not reported: a body holding any statement or a comment (a comment records the decision to ignore), an exception variable named ignored/ignore/expected/unused or _ (the Java convention for a deliberate discard), test sources, and catch text inside string literals or comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1069/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1069],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["empty-exception-block", "cwe-1069"],
}

# The catch header: `catch (` ... `)` and whatever follows on the same line.
_catch_re := `\bcatch\s*\(([^()]*)\)(.*)$`

# A deliberately discarded exception, by the Java naming convention.
_discard_name(params) if regex.match(`(?i)\b(ignored?|expected|unused)\w*\s*$`, params)

_discard_name(params) if regex.match(`\s_\s*$`, params)

# The body is empty when, after the header, the next few lines contribute
# nothing but `{` and `}` once whitespace is removed.
_empty_body(lines, i, tail) if {
	rest := [trim_space(lines[k]) | some k in numbers.range(i + 1, min([i + 3, count(lines) - 1]))]
	joined := regex.replace(concat("", array.concat([tail], rest)), `\s+`, "")
	startswith(joined, "{}")
}

# The line with string and character literals blanked, so a catch inside a
# literal is not read as code and a literal earlier on the line does not hide
# a real catch after it. Comments are kept: one inside the braces is a body.
_code_part(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# A catch that sits after a comment opener on its line is comment text.
_commented_catch(code) if regex.match(`(//|/\*).*\bcatch\s*\(`, code)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`catch\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "catch")
	not helpers.is_comment_line(line)
	code := _code_part(line)
	not _commented_catch(code)
	m := regex.find_all_string_submatch_n(_catch_re, code, 1)[0]
	not _discard_name(m[1])
	_empty_body(lines, i, m[2])
	finding := {
		"rule_id": metadata.id,
		"message": "Empty catch block swallows the exception; log, rethrow or handle it, or name the variable 'ignored' and say why in a comment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
