# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1122

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1122",
	"name": "Excessive Halstead Complexity",
	"description": "A single Python statement line whose expression packs 16 or more operators (arithmetic + - * / // % ** @, bitwise & | ^ ~ << >>, comparisons == != < > <= >=, and boolean and/or/not): the Halstead difficulty of that one expression is too high to read or verify, which is where an operator-precedence mistake, an off-by-one bound or a wrong mask in a security check hides. String literals and trailing comments are removed before counting. Not reported: chains of | alone (type unions and flag sets), negative numeric literals in tables, docstring rule lines (=====, -----), expressions broken over several lines (each physical line is measured on its own), def signatures and decorators (*args, **kwargs, -> annotations), whole-line comments, and test files. A line-level proxy for Halstead complexity, not a full per-function Halstead volume.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1122/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1122],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-halstead", "cwe-1122", "maintainability"],
}

_threshold := 16

_op_re := `\*\*|//|<<|>>|==|!=|<=|>=|[-+*/%&|^~<>@]|\band\b|\bor\b|\bnot\b`

# Remove string literals (so "a-b-c" and URLs do not count), a trailing
# comment, return annotations (->), argument-unpacking stars (*args,
# **kwargs) and the sign of a float exponent (1e-9).
_code_part(line) := c if {
	s := regex.replace(line, `[rRbBfFuU]{0,2}"(?:[^"\\]|\\.)*"|[rRbBfFuU]{0,2}'(?:[^'\\]|\\.)*'`, `S`)
	h := regex.replace(s, `#.*$`, "")
	u := regex.replace(h, `->|\*\*?(?:[A-Za-z_]\w*)?\s*(?:[,)]|$)|\b[eE][-+]\d`, " ")

	# A negative literal in a table ([-1, -2], (-1, 0), x = -3) is a value,
	# not an operation.
	c := regex.replace(u, `([\[(,=:]\s*)-(\d)`, "${1}${2}")
}

# A rule line in a docstring (=====, -----, ~~~~~) is punctuation, not
# operators.
_banner(line) if regex.match(`^\s*([-=~^*+#_.:|])[-=~^*+#_.:| ]*$`, line)

# A chain of | only is a type union (int | float | None) or a flag set
# (os.O_WRONLY | os.O_CREAT | ...): a list, not an expression to work out.
_union_only(code) if {
	contains(code, "|")
	not regex.match(`\*\*|//|<<|>>|==|!=|<=|>=|[-+*/%&^~<>@]|\band\b|\bor\b|\bnot\b`, code)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	count(line) >= 40
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:@|(?:async\s+)?def\s|class\s|import\s|from\s)`, line)
	not _banner(line)
	code := _code_part(line)
	not _union_only(code)
	n := count(regex.find_n(_op_re, code, -1))
	n >= _threshold
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Expression with %d operators on one line (threshold %d): split it into named intermediate values", [n, _threshold]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
