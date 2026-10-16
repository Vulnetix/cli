# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1024

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1024",
	"name": "Comparison of incompatible types (always false)",
	"description": "A value is compared for equality with a value of a type it can never equal, so the check is constantly false (or, negated, constantly true) and whatever it guards never runs or always runs. Java: x.equals(y) or Objects.equals(x, y) where x is declared in the file with exactly one type and y is a literal of another: a String against a number, boolean or char literal; a Long against an int literal (5 boxes to Integer, which never equals a Long) or a string; an Integer, Short or Byte against a long, decimal or string literal; a Double or Float against an int or string literal; a Boolean, Character, BigDecimal, BigInteger or UUID against a string literal (or, for Boolean and Character, a number); and a string literal's own .equals() given a number or boolean. Python: a value read as a string (input(), sys.argv[...], os.environ.get/os.getenv, Flask request.args/form/headers/cookies .get or [...], Django request.GET/POST .get) compared with == or != to an int or float literal, directly or through a variable assigned from it a few lines above and not converted since. Not reported: names declared with more than one type in the file, request.args.get(..., type=int), a .get() or os.getenv() with a numeric or boolean default (the value is a number when the key is absent), values converted with int()/float()/len()/bool(), ordering comparisons, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1024/",
	"languages": ["java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1024],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["comparison-of-incompatible-types", "always-false", "cwe-1024"],
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

# ── Java ─────────────────────────────────────────────────────────────────

_java_types := `String|Long|Integer|Short|Byte|Double|Float|Boolean|Character|BigDecimal|BigInteger|UUID|long|int|short|byte|double|float|boolean|char|var|Object|Number|Map|List|Set|Optional`

# Declared type of a name, when the file declares it with exactly one type.
_decl_type(content, name) := t if {
	all := regex.find_all_string_submatch_n(concat("", [`(?:^|[\s(,<])(?:final\s+)?(`, _java_types, `|[A-Z]\w*)(?:<[^<>;=]*>)?(?:\[\])?\s+`, name, `\s*[=;,):]`]), content, -1)
	types := {m[1] | some m in all}
	count(types) == 1
	some t in types
}

_lit_kind(a) := "int" if regex.match(`^-?\d+$`, a)

_lit_kind(a) := "long" if regex.match(`^-?\d+[lL]$`, a)

_lit_kind(a) := "decimal" if regex.match(`^-?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?[dDfF]?$|^-?\d+[dDfF]$`, a)

_lit_kind(a) := "bool" if regex.match(`^(?:true|false)$`, a)

_lit_kind(a) := "char" if regex.match(`^'(?:\\.|[^'\\])'$`, a)

_lit_kind(a) := "string" if regex.match(`^"(?:\\.|[^"\\])*"$`, a)

_incompatible("String", k) if k in {"int", "long", "decimal", "bool", "char"}

_incompatible("Long", k) if k in {"int", "decimal", "string", "bool", "char"}

_incompatible(t, k) if {
	t in {"Integer", "Short", "Byte"}
	k in {"long", "decimal", "string", "bool"}
}

_incompatible(t, k) if {
	t in {"Double", "Float"}
	k in {"int", "long", "string", "bool"}
}

_incompatible(t, k) if {
	t in {"Boolean", "Character"}
	k in {"int", "long", "decimal", "string"}
}

_incompatible("Boolean", "char")

_incompatible(t, "string") if t in {"BigDecimal", "BigInteger", "UUID"}

_incompatible(t, k) if {
	t in {"BigDecimal", "BigInteger"}
	k in {"int", "long", "decimal"}
}

_desc(t, k) := sprintf("%s compared with a %s literal", [t, k])

_strip(s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

findings contains _finding(path, i, line, sprintf("Comparison of incompatible types (%s): equals() between different types is always false, so this check never passes. Compare values of the same type (parse or convert first, use a long literal like 5L)", [msg])) if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\.equals\(|Objects\.equals\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "equals(")
	not helpers.is_comment_line(line)
	some pair in _java_pairs(line)
	t := _decl_type(content, pair[0])
	k := _lit_kind(pair[1])
	_incompatible(t, k)
	msg := _desc(t, k)
}

findings contains _finding(path, i, line, "String literal compared with a number or boolean: equals() between different types is always false. Compare with a string, or parse the string first") if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "\".equals(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "\".equals(")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`"(?:\\.|[^"\\])*"\.equals\(\s*(-?[\w.']+)\s*\)`, line, -1)
	_lit_kind(m[1]) in {"int", "long", "decimal", "bool", "char"}
	_outside_string(line, m[0])
}

# (receiver name, argument) pairs on a line, with the argument text kept raw
# so literals keep their kind; matches inside string literals are dropped.
_java_pairs(line) := {[m[1], trim_space(m[2])] |
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.])([a-z_]\w*)\.equals\(\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])'|-?[\w.]+)\s*\)`, line, -1)
	_outside_string(line, m[0])
} | {[m[1], trim_space(m[2])] |
	some m in regex.find_all_string_submatch_n(`Objects\.equals\(\s*([a-z_]\w*)\s*,\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])'|-?[\w.]+)\s*\)`, line, -1)
	_outside_string(line, m[0])
}

_outside_string(line, match) if {
	idx := indexof(line, match)
	idx >= 0
	strings.count(_strip_chars(substring(line, 0, idx + _lead(match))), "\"") % 2 == 0
}

# The receiver regex consumes one leading non-word character; it is not part of
# the call, and when it is a quote it opens a string the call sits inside.
_lead(match) := 1 if regex.match(`^\W`, match)

_lead(match) := 0 if not regex.match(`^\W`, match)

_strip_chars(s) := regex.replace(s, `\\.|'"'`, "")

# ── Python ───────────────────────────────────────────────────────────────

_py_source := `\binput\s*\(|\bsys\.argv\s*\[|\bos\.environ\.get\s*\(|\bos\.environ\s*\[|\bos\.getenv\s*\(|\brequest\.(?:args|form|values|headers|cookies)\.get\s*\(|\brequest\.(?:args|form|values|headers|cookies)\s*\[|\brequest\.(?:GET|POST)\.get\s*\(|\brequest\.(?:GET|POST)\s*\[`

_num := `-?\d+(?:\.\d+)?\b(?:\s*(?:$|[):,\]]|and\b|or\b|if\b|else\b))`

findings contains _finding(path, i, line, "String input compared with a number: input(), argv, environment and request values are strings, and a string never equals an int in Python, so this check is always false. Convert with int() first, or compare with a string") if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(_py_source, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[!=]=\s*-?\d`, line)
	not helpers.is_comment_line(line)
	code := regex.replace(line, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)
	_py_compared(lines, i, code)
}

# Directly: input() == 1, request.args.get("x") != 0.
_py_compared(_, _, code) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(\b(?:int|float|len|bool|Decimal)\s*\(\s*)?((?:`, _py_source, `)[^=!<>]*?)\s*[!=]=\s*`, _num]), code, -1)
	m[1] == ""
	not regex.match(`type\s*=\s*(?:int|float)`, m[2])
	not regex.match(`\.get(?:env)?\s*\(\s*""\s*,\s*(?:-?\d|True\b|False\b)`, m[2])
}

# Through a variable assigned from a source above and not converted since.
_py_compared(lines, i, code) if {
	some v in helpers.tainted_names(lines, i, 15, _py_source)
	regex.match(concat("", [`(?:^|[^\w.])`, v, `\s*[!=]=\s*`, _num]), code)
	not _py_converted(lines, i, v)
}

_py_converted(lines, i, v) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(concat("", [`\b`, v, `\s*=\s*(?:int|float|len|bool|Decimal|json\.loads)\s*\(|\b`, v, `\s*=.*\btype\s*=\s*(?:int|float)|\b`, v, `\s*=.*\.get(?:env)?\s*\(\s*(?:"[^"]*"|'[^']*')\s*,\s*(?:-?\d|True\b|False\b)`]), lines[j])
}
