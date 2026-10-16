# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_561

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-561",
	"name": "Dead Code",
	"description": "Code that can never run. Two shapes are reported. Unreachable statements in JavaScript/TypeScript and Python: the first statement after an unconditional return, throw/raise, break or continue at the same indentation in the same block, in semicolon-terminated and semicolon-free (standard style) JavaScript alike (a cleanup, audit or log call placed after the exit, so it silently never happens). And blocks guarded by a literal false condition in Java, JavaScript/TypeScript and Python: if (false), if (0), while (false), if False:, elif 0:, while False:. Not reported: a closing brace, else/elif/except/catch/finally, a case/default label or a dedent after the exit; JavaScript function declarations after a return (hoisted); multi-line return expressions; braceless if bodies; the generator idioms `return` followed by `yield` and `if False: yield`; `if False:` guarding type-only imports; named constants such as if (DEBUG) and TYPE_CHECKING; Java statements after an exit (javac already rejects them); comments and string literals. Conditions that are always false through a comparison are VNX-570.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-561/",
	"languages": ["java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [561],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["dead-code", "unreachable-code", "cwe-561"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_indent(line) := substring(line, 0, count(line) - count(trim_left(line, " \t")))

_balanced(s) if {
	count(indexof_n(s, "(")) == count(indexof_n(s, ")"))
	count(indexof_n(s, "[")) == count(indexof_n(s, "]"))
	count(indexof_n(s, "{")) == count(indexof_n(s, "}"))
}

# ── Unreachable statement after an exit ──────────────────────────────────

_js_exit := `^\s*(?:return\b.*|throw\b.*|break(?:\s+\w+)?\s*|continue(?:\s+\w+)?\s*);\s*(?://.*)?$`

_py_exit := `^\s*(?:return\b.*|raise\b.*|break|continue)\s*(?:#.*)?$`

_exit_re := {"js": _js_exit, "py": _py_exit}

# Semicolon-free JavaScript (standard style): the exit ends the statement only
# when the next code line cannot continue it, so that line must begin with an
# identifier or keyword, not with . ( [ ` or an operator.
_js_exit_nosemi := `^\s*(?:return\b[^;]*|throw\b[^;]*|break(?:\s+\w+)?|continue(?:\s+\w+)?)\s*(?://.*)?$`

_exit_line(_, _, line, lang) if regex.match(_exit_re[lang], line)

_exit_line(lines, i, line, "js") if {
	regex.match(_js_exit_nosemi, line)
	j := helpers.next_code_index(lines, i, 6)
	regex.match(`^\s*[A-Za-z_$]`, lines[j])
	not regex.match(`^\s*(?:in|of|instanceof|as|satisfies)\b`, lines[j])
}

_js_ok_next := `^\s*(?:[\}\)\]]|case\b|default\b|else\b|catch\b|finally\b|function\b|async\s+function\b|var\b|export\s+(?:default\s+)?(?:async\s+)?function\b|[A-Za-z_$][\w$]*\s*:\s*(?:$|for\b|while\b|do\b|\{)|//|/\*|\*)`

_py_ok_next := `^\s*(?:[\}\)\]]|elif\b|else\b|except\b|finally\b|case\b|def\b|async\s+def\b|class\b|@|yield\b)`

_ok_next := {"js": _js_ok_next, "py": _py_ok_next}

_strip(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`[^`]*`", "``")

# The exit is the body of a braceless if/for/while/else above it.
_braceless_body(lines, i) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	not helpers.is_comment_line(lines[k])
	trim_space(lines[k]) != ""
	not _later_code(lines, k, i)
	t := trim_space(_strip(lines[k]))
	not endswith(t, "{")
	not endswith(t, ";")
	not endswith(t, "}")
}

# Some non-blank code line between k and i (exclusive).
_later_code(lines, k, i) if {
	some m in helpers.span(k + 1, i - 1)
	m < i
	trim_space(lines[m]) != ""
	not helpers.is_comment_line(lines[m])
}

_unreachable(lines, i, line, lang) if {
	_exit_line(lines, i, line, lang)
	s := _strip(line)
	_balanced(s)
	not regex.match(`[\\,\(\[\{+\-*/=&|?:]\s*(?:#.*)?$`, trim_space(s))
	j := helpers.next_code_index(lines, i, 6)
	_indent(lines[j]) == _indent(line)
	not regex.match(_ok_next[lang], lines[j])
	not _js_braceless(lines, i, lang)
}

_js_braceless(lines, i, "js") if _braceless_body(lines, i)

# Lines that open or close a block comment (JS) or a triple-quoted string
# (Python), with the net change in nesting each makes. A line is inside one
# when the marks above it leave it open.
_marks(lines, "js") := [[k, d] |
	some k, l in lines
	contains(l, "*")
	s := _strip(l)
	d := count(indexof_n(s, "/*")) - count(indexof_n(s, "*/"))
	d != 0
]

_marks(lines, "py") := [[k, d] |
	some k, l in lines
	regex.match(`"""|'''`, l)
	n := count(indexof_n(l, `"""`)) + count(indexof_n(l, "'''"))
	n % 2 == 1
	d := 1
]

_inside(marks, i) if {
	ds := [m[1] | some m in marks; m[0] < i]
	sum(ds) % 2 == 1
	count(ds) > 0
}

# ── Literal-false condition ──────────────────────────────────────────────

_false_re := {
	"js": `^\s*(?:\}\s*else\s+)?(?:if|while)\s*\(\s*(?:false|0)\s*\)`,
	"java": `^\s*(?:\}\s*else\s+)?(?:if|while)\s*\(\s*false\s*\)`,
	"py": `^\s*(?:if|elif|while)\s+(?:False|0)\s*:`,
}

_py_idiom(lines, i, line) if regex.match(`^\s*if\s+False\s*:\s*#`, line)

_py_idiom(lines, i, _) if {
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*(?:yield\b|import\b|from\s+\S+\s+import\b)`, lines[j])
}

_dead_block(lines, i, line, lang) if {
	regex.match(_false_re[lang], line)
	not _py_idiom_for(lang, lines, i, line)
}

_py_idiom_for("py", lines, i, line) if _py_idiom(lines, i, line)

_needle := {"js": `\b(?:return|throw|break|continue)\b|\b(?:if|while)\s*\(\s*(?:false|0)\s*\)`, "py": `(?m)^\s*(?:return|raise|break|continue)\b|\b(?:if|elif|while)\s+(?:False|0)\s*:`, "java": `\b(?:if|while)\s*\(\s*false\s*\)`}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	lang != "java"
	regex.match(_needle[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`return|throw|raise|break|continue`, line)
	not helpers.is_comment_line(line)
	not helpers.is_test_path(path)
	_unreachable(lines, i, line, lang)
	j := helpers.next_code_index(lines, i, 6)
	marks := _marks(lines, lang)
	not _inside(marks, i)
	not _inside(marks, j)
	finding := _finding(path, j, lines[j], "Unreachable statement: it follows an unconditional return, throw, break or continue in the same block and never runs")
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_needle[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`false|False|0`, line)
	not helpers.is_comment_line(line)
	not helpers.is_test_path(path)
	_dead_block(lines, i, line, lang)
	finding := _finding(path, i, line, "Block guarded by a literal false condition never runs; delete it or put it behind a named flag")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
