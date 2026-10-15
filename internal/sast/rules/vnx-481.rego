# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_481

import rego.v1

metadata := {
	"id": "VNX-481",
	"name": "Assigning instead of Comparing",
	"description": "Reports an if or while condition that is a bare assignment, if (x = y) or while (done = check()), in C, C++ and Java (where it compiles for booleans, if (isAdmin = true)): the condition takes the assigned value and the variable is overwritten, where a comparison (==) was almost always meant. Not reported: the conventional deliberate form with an extra pair of parentheses (if ((p = next())) and while ((c = getc(f)) != EOF)), comparisons (==, <=, >=, !=), the C++17 init-statement if (err = f(); err != 0), the comma operator, assignments in for headers or ordinary statements, and conditions inside strings and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-481/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [481],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["assignment-condition", "cwe-481"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java"}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `/\*.*?(?:\*/|$)`, ""), `//.*$`, "")

# `if (` / `while (` immediately followed by `lvalue =` (not ==), with no
# second parenthesis opening the condition.
_cond_assign := `\b(?:if|while)\s*\(\s*(\*?\s*[A-Za-z_][\w.]*(?:->[A-Za-z_]\w*|\[[^\]]*\])*)\s*=([^=][^(),;]*)([,;)(]?)`

findings contains finding if {
	some path, content in input.file_contents
	some e in _exts
	endswith(path, e)
	regex.match(`\b(?:if|while)\s*\(\s*\*?\s*[A-Za-z_][\w.\->\[\]]*\s*=[^=]`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	not _is_comment(line)
	m := regex.find_all_string_submatch_n(_cond_assign, _code(line), 1)
	count(m) > 0
	# `while (p = q, q = next(q), p)`: a comma operator, the condition is its
	# last operand.
	m[0][3] != ","
	# C++17 `if (err = f(); err != 0)`: the assignment is an init-statement,
	# a `;` inside the condition's own parentheses.
	not regex.match(`\bif\s*\((?:[^();]|\((?:[^()]|\([^()]*\))*\))*;`, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Condition assigns to '%s' instead of comparing it: use == (or wrap the assignment in a second pair of parentheses if it is deliberate)", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
