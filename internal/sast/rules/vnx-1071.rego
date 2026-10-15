# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1071

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1071",
	"name": "Empty Code Block",
	"description": "A Java control-flow block with nothing between its braces: an if, else, else if, for, while, synchronized, try, finally or do whose body is empty on one line (if (x) {}) or across lines (the brace on the next line, an empty line inside), and an if or for whose body is a stray semicolon (if (token == null); or for (Item i : items);), which makes the block that follows run unconditionally and once. A while (...); is not reported: spinning on a condition that does the work is a common idiom. An empty block usually marks unfinished or deleted logic: a check that no longer does anything. Not reported: a block holding any statement or a comment (a comment records an intentional no-op such as a documented busy-wait), empty method and constructor bodies and lambdas (no-op overrides are legitimate), empty catch blocks (VNX-1069 owns those), try-with-resources, array initialisers, test sources, and the pattern inside string literals or comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1071/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1071],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["empty-code-block", "cwe-1071"],
}

# A header with a condition; the capture after the parenthesis is the rest of
# the line (the opening brace, or the whole empty body).
_paren_re := `^\s*(?:\}\s*)?(?:else\s+)?(?:if|while|for|synchronized)\s*\(([^{}]*)\)(.*)$`

# A header with no condition.
_bare_re := `^\s*(?:\}\s*)?(else|try|finally|do)(\s*\{.*|\s*)$`

# `if (cond);` and `for (...);`: the header closes the statement, so the
# block that follows runs once, unconditionally. `while (...);` is left out:
# it is the usual way to spin on a condition that does the work.
_semi_re := `^\s*(?:\}\s*)?(?:else\s+)?(?:if|for)\s*\(([^{}]*)\)\s*;\s*(?://.*)?$`

_empty_body(lines, i, tail) if {
	rest := [trim_space(lines[k]) | some k in numbers.range(i + 1, min([i + 3, count(lines) - 1]))]
	joined := regex.replace(concat("", array.concat([tail], rest)), `\s+`, "")
	startswith(joined, "{}")
}

# A condition whose own parenthesis closes early (`if (a) foo(b);`).
_closes_early(cond) if {
	some m in regex.find_all_string_submatch_n(`\)\s*([A-Za-z_$][\w$]*)`, cond, -1)
	m[1] != "instanceof"
}

_candidate(lines, i, line) if {
	m := regex.find_all_string_submatch_n(_paren_re, line, 1)[0]
	_empty_body(lines, i, m[2])
}

_candidate(lines, i, line) if {
	m := regex.find_all_string_submatch_n(_bare_re, line, 1)[0]
	_empty_body(lines, i, m[2])
}

_candidate(_, _, line) if {
	m := regex.find_all_string_submatch_n(_semi_re, line, 1)[0]
	count(regex.find_all_string_submatch_n(`\(`, m[1], -1)) == count(regex.find_all_string_submatch_n(`\)`, m[1], -1))
	not _closes_early(m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`(?m)(\{\s*\}|\{\s*$|\)\s*;\s*$)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(\}\s*)?(if|else|while|for|synchronized|try|finally|do)\b`, line)
	_candidate(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Empty code block: the branch, loop or try does nothing; finish or remove it, or say why in a comment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
