# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_483

import rego.v1

metadata := {
	"id": "VNX-483",
	"name": "Incorrect Block Delimitation",
	"description": "Reports two shapes where the braces do not say what the indentation says, in C, C++ and Java. (1) Misleading indentation: an if/else if/else/for/while without braces whose single guarded statement is immediately followed by a second statement at the same indentation, which looks guarded but always runs (the 'goto fail' bug). (2) An if whose condition is followed directly by a semicolon, if (x);, so the block below it runs unconditionally. Not reported: braced bodies, a braceless body followed by a dedented line, a blank line or a closing brace, else/case/default labels, preprocessor lines, conditions that span several lines, deliberate empty loops (while (*p++);, for (...);), the do { } while (x); terminator, and comments. A braceless if on its own is a style choice and is not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-483/",
	"languages": ["c", "cpp", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [483],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incorrect-block-delimitation", "misleading-indentation", "cwe-483"],
}

# Cheap prefilter before any regex: a header line ends with `)` or `else`
# (a trailing comment is rare enough on a braceless header to skip).
_header_end(t) if endswith(t, ")")

_header_end(t) if endswith(t, "else")

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java"}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

# Code with literals emptied and a trailing comment removed.
_code(line) := regex.replace(regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `/\*.*?\*/`, ""), `\s*//.*$`, "")

# Collapse balanced parenthesis groups (up to five deep) to P.
_collapse(s) := regex.replace(regex.replace(regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "P"), `\([^()]*\)`, "P"), `\([^()]*\)`, "P"), `\([^()]*\)`, "P"), `\([^()]*\)`, "P")

_ws(line) := substring(line, 0, count(line) - count(trim_left(line, " \t")))

# A braceless control header: the whole line is `if (...)`, `else if (...)`,
# `for (...)`, `while (...)` or `else`, with the condition closed on it.
_header(line) if {
	c := trim_space(_code(line))
	m := regex.find_all_string_submatch_n(`^(?:\}\s*)?(?:else\s+)?(?:if|for|while)\s*(\(.*)$`, c, 1)
	count(m) > 0
	trim_space(_collapse(m[0][1])) == "P"
}

_header(line) if regex.match(`^\s*(?:\}\s*)?else\s*$`, _code(line))

# A complete simple statement: ends in `;`, is not itself a header or a label.
_statement(line) if {
	c := trim_space(_code(line))
	endswith(c, ";")
	not regex.match(`^(?:\}|else\b|case\b|default\b|#|if\b|for\b|while\b|do\b)`, c)
	not contains(_collapse(c), "(")
}

findings contains finding if {
	some path, content in input.file_contents
	some e in _exts
	endswith(path, e)
	regex.match(`\b(?:if|for|while|else)\b`, content)
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	i + 2 < n
	regex.match(`^\s*(?:\}\s*)?(?:else|if|for|while)\b`, line)
	_header_end(trim_space(_code(line)))
	not _is_comment(line)
	not endswith(trim_space(line), "\\")
	_header(line)
	body := lines[i + 1]
	nxt := lines[i + 2]
	hw := _ws(line)
	bw := _ws(body)
	count(bw) > count(hw)
	startswith(bw, hw)
	_ws(nxt) == bw
	not _is_comment(body)
	not _is_comment(nxt)
	_statement(body)
	_statement(nxt)
	finding := {
		"rule_id": metadata.id,
		"message": "This statement is indented as if the braceless if/else/loop above guards it, but only the line before it is guarded: it always runs. Add braces around the intended block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 3,
		"snippet": nxt,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	some e in _exts
	endswith(path, e)
	contains(content, ";")
	regex.match(`\bif\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "if")
	contains(line, ";")
	regex.match(`^\s*(?:\}\s*)?(?:else\s+)?if\s*\(.*;\s*(?://.*)?$`, line)
	not _is_comment(line)
	c := trim_space(_code(line))
	m := regex.find_all_string_submatch_n(`^(?:\}\s*)?(?:else\s+)?if\s*(\(.*)$`, c, 1)
	count(m) > 0
	regex.match(`^P\s*;$`, trim_space(_collapse(m[0][1])))
	finding := {
		"rule_id": metadata.id,
		"message": "if (...); has an empty body: the semicolon ends the if, so the block below runs unconditionally. Remove the semicolon",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
