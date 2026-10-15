# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_482

import rego.v1

metadata := {
	"id": "VNX-482",
	"name": "Comparing instead of Assigning",
	"description": "Reports a statement that is only an equality comparison, x == y; (or x === y; in JavaScript/TypeScript, x == y on its own line in Python), and a for loop whose initialiser compares instead of assigning (for (i == 0; ...)), in C, C++, JavaScript, TypeScript and Python. The result is discarded, so the assignment that was meant (or, in a Python test, the assert that was meant) never happens. Not reported: comparisons that are part of a larger statement (assert, return, if, a call argument, an assignment, a ternary), continuation lines of a multi-line expression (the line before ends with an operator, a comma or an open bracket), a Python comparison directly under with pytest.raises(...)/self.assertRaises(...) (evaluated on purpose to prove __eq__ raises), Java and C# (where an expression statement that only compares does not compile), and comparisons inside strings and comments. The Java BigDecimal reference comparison the earlier version of this rule reported is covered by VNX-480.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-482/",
	"languages": ["c", "cpp", "javascript", "typescript", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [482],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["comparison-statement", "cwe-482"],
}

_brace_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_kind(path) := "py" if endswith(path, ".py")

_kind(path) := "brace" if {
	some e in _brace_exts
	endswith(path, e)
}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$)|#)`, line)

_lit := concat("", [`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`, "`[^`]*`"])

_code(line) := regex.replace(regex.replace(regex.replace(line, _lit, `""`), `/\*.*?\*/`, ""), `\s*(?://|#).*$`, "")

_indent(line) := count(line) - count(trim_left(line, " \t"))

_lvalue := `[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|->[A-Za-z_]\w*|\[[^\]]*\])*`

_keywords := {"return", "assert", "if", "elif", "while", "yield", "print", "await", "not", "case", "throw", "typeof", "delete", "void", "new", "else", "lambda", "del", "raise"}

_stmt_re("brace") := concat("", [`^\s*(`, _lvalue, `)\s*===?\s*[^=;][^;]*;?\s*$`])

_stmt_re("py") := concat("", [`^\s*(`, _lvalue, `)\s*==\s*[^=][^;]*$`])

_balanced(c) if {
	count(regex.find_all_string_submatch_n(`[(\[{]`, c, -1)) == count(regex.find_all_string_submatch_n(`[)\]}]`, c, -1))
}

_prev_code(lines, i) := j if {
	cands := [k |
		some k in numbers.range(max([0, i - 5]), i - 1)
		trim_space(lines[k]) != ""
		not _is_comment(lines[k])
	]
	count(cands) > 0
	j := cands[count(cands) - 1]
}

# The previous statement is complete, so this line starts a statement.
_starts_statement("brace", lines, i) if {
	not _prev_code(lines, i)
}

_starts_statement("brace", lines, i) if {
	p := trim_space(_code(lines[_prev_code(lines, i)]))
	regex.match(`(?:[;{}]|^(?:\}\s*)?else)$`, p)
}

_starts_statement("brace", lines, i) if {
	p := trim_space(_code(lines[_prev_code(lines, i)]))
	regex.match(`^(?:\}\s*)?(?:else\s+)?(?:if|for|while)\s*\(.*\)$`, p)
	_balanced(p)
}

_starts_statement("py", lines, i) if {
	not _prev_code(lines, i)
}

_starts_statement("py", lines, i) if {
	j := _prev_code(lines, i)
	p := trim_space(_code(lines[j]))
	endswith(p, ":")
	_indent(lines[i]) > _indent(lines[j])
}

_starts_statement("py", lines, i) if {
	j := _prev_code(lines, i)
	p := trim_space(_code(lines[j]))
	regex.match(`[\w)\]}"']$`, p)
	not regex.match(`\b(?:and|or|not|in|is|if|else|lambda)$`, p)
	_balanced(p)
	_indent(lines[i]) <= _indent(lines[j])
}

_hit(kind, lines, i, c) := v if {
	m := regex.find_all_string_submatch_n(_stmt_re(kind), c, 1)
	count(m) > 0
	v := m[0][1]
	not _keywords[v]
	_balanced(c)
	not regex.match(`\s(?:if|else|and|or|for|in)\s|\?|=>|\blambda\b|&&|\|\|`, c)
	_starts_statement(kind, lines, i)
	not _continues(kind, lines, i, c)
	not _under_raises(kind, lines, i)
}

# Python: `with pytest.raises(TypeError):` / `with self.assertRaises(...):`
# directly above evaluates the comparison on purpose, to prove __eq__ raises.
_under_raises("py", lines, i) if {
	j := _prev_code(lines, i)
	regex.match(`^\s*with\s.*\b(?:raises|assertRaises\w*)\s*\(.*:\s*$`, _code(lines[j]))
}

# The next code line continues this expression (a ternary, a chained call,
# a trailing operator), so the comparison is not a statement of its own. A
# brace-language line that already ends in `;` is complete.
_continues(kind, lines, i, c) if {
	not _terminated(kind, c)
	j := _next_code(lines, i)
	regex.match(`^\s*(?:[?:.&|+*/%<>,)\]-]|=[^=]|and\b|or\b|if\b|else\b|for\b)`, lines[j])
}

_terminated("brace", c) if endswith(trim_space(c), ";")

_next_code(lines, i) := j if {
	cands := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 5]))
		trim_space(lines[k]) != ""
		not _is_comment(lines[k])
	]
	count(cands) > 0
	j := cands[0]
}

_hit("brace", _, _, c) := v if {
	m := regex.find_all_string_submatch_n(`\bfor\s*\(\s*(?:(?:let|var|int|size_t|unsigned)\s+)?([A-Za-z_]\w*)\s*===?\s*[^=;][^;]*;`, c, 1)
	count(m) > 0
	v := m[0][1]
}

# Python: an odd number of triple quotes above the line puts it inside a
# docstring (a doctest example `x == y  # True` is prose). Only evaluated for
# a line that already matched.
_in_docstring("py", lines, i) if {
	above := concat("\n", array.slice(lines, 0, i))
	n := count(regex.find_all_string_submatch_n(`"""|'''`, above, -1))
	n % 2 == 1
}

# A line that starts with `lvalue ==`, or a for header that compares in its
# initialiser. (A whole-file multi-line regex gate cost more than splitting:
# the file is gated on the literal `==` and lines on this.)
_line_gate := `^\s*[A-Za-z_$][\w$.\[\]>"'-]*\s*==|\bfor\s*\(\s*[\w\s]*==`

findings contains finding if {
	some path, content in input.file_contents
	kind := _kind(path)
	contains(content, "==")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "==")
	count(line) < 300
	regex.match(_line_gate, line)
	not _is_comment(line)
	c := _code(line)
	v := _hit(kind, lines, i, c)
	not _in_docstring(kind, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("This statement only compares '%s' and discards the result: an assignment (=) or an assert was probably meant", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
