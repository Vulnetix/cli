# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_783

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-783",
	"name": "Operator Precedence Logic Error",
	"description": "An expression is written so that the language's operator precedence groups it differently from what the code plainly intends, producing a wrong check or value (CWE-783). Reported, only for groupings that are wrong in the language of the file: an assignment of a call's result compared in the same unparenthesised if/while condition, which assigns the comparison instead (C/C++/JavaScript/PHP `if (fd = open(p, O_RDONLY) < 0)`, Python `if n := len(d) > LIMIT:`); a bitwise & tested with == or != without parentheses (C/C++/JavaScript/PHP `flags & MASK == 0`, which is `flags & (MASK == 0)`); a shift by a literal followed by + (`hi << 8 + lo`, which shifts by 8 + lo) in C, C++, Java, JavaScript, PHP, Python and C#; a negation applied before a comparison (`!user.role === \"admin\"`, `!strcmp(a, b) == 1`) in C/C++/JavaScript/PHP, and before instanceof or in in JavaScript; string concatenation taken as a ternary condition (JavaScript `\"a\" + flag ? x : y`, PHP `\"a\" . $flag ? x : y`) or compared with null before a ternary (Java/JavaScript/C# `\"a\" + v == null ? ...`); and an arithmetic or string-concatenation result used as the left side of ?? (JavaScript/TypeScript and C# `a + b ?? 0`, `\"Hello, \" + name ?? \"guest\"`). Not reported: the parenthesised forms, Go and Python bitwise/shift expressions (where & and << bind tighter than == and +), Java bitwise & on booleans, C++ stream insertion (`cout << 8 + n`), negations compared with a boolean, 0 or null where the result is the same either way, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-783/",
	"languages": ["c", "cpp", "java", "node", "php", "python", "csharp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [783],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["operator-precedence", "cwe-783"],
}

_ext_lang := {
	"c": "c", "h": "c",
	"cc": "cpp", "cpp": "cpp", "cxx": "cpp", "hpp": "cpp", "hh": "cpp",
	"java": "java",
	"js": "js", "mjs": "js", "cjs": "js", "jsx": "js", "ts": "js", "tsx": "js", "mts": "js", "cts": "js",
	"php": "php",
	"py": "py",
	"cs": "cs",
}

_lang(path) := _ext_lang[regex.replace(path, `^.*\.`, "")]

# Strings blanked (including template literals), then a trailing comment cut.
_blank(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`[^`]*`", "``")

_code(lang, line) := regex.replace(_blank(line), `\s#.*$`, "") if lang in {"py", "php"}

_code(lang, line) := regex.replace(_blank(line), `//.*$`, "") if not lang in {"py", "php"}

# An operand: identifier chain with optional indexes and one call.
_op := `\$?[A-Za-z_][\w.$]*(?:->\w+|::\w+)*(?:\[[^\]]*\])*(?:\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))?`

_call := `\$?[A-Za-z_][\w.$]*(?:->\w+|::\w+)*\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

# ── Shapes, keyed by the languages in which each grouping is wrong ───────

# Each shape: the languages in which the grouping is wrong, a substring the
# line must contain, the regex on the line with strings blanked ("re"), and
# a cheap single-line regex ("raw", led by a literal where possible) that the
# unblanked file must match before its lines are visited.
_s_assign := concat("", [`\b(?:if|while)\s*\(+\s*!?\s*\$?[A-Za-z_][\w.$]*(?:->\w+)*(?:\[[^\]]*\])*\s*=\s*`, _call, `\s*(?:===?|!==?|<=|>=|<|>)`])

_s_walrus := concat("", [`\b(?:if|elif|while)\s+[A-Za-z_]\w*\s*:=\s*`, _op, `\s*(?:==|!=|<=|>=|<|>)`])

_s_mask := `(\w+|[)\]])\s*&\s*(?:\$?[A-Za-z_][\w.]*|0[xX][0-9a-fA-F]+|\d+)\s*(?:===?|!==?)\s*[$\w(-]`

_s_mask_rev := `(?:===?|!==?)\s*(?:\$?[A-Za-z_][\w.]*|0[xX][0-9a-fA-F]+|\d+)\s*&\s*[$\w(]`

_s_shift := `(\w+|[)\]])\s*(?:<<|>>>?)\s*\d+\s*\+\s*[\w($]`

_s_not := concat("", [`(?:^|[^\w!=)\]$.])!\s*(`, _op, `)\s*(===?|!==?)\s*([^\s);&|,]+)`])

_s_not_inst := `(?:^|[^\w!=)\]$.])!\s*[$A-Za-z_][\w.$]*(?:\[[^\]]*\])*\s+(?:instanceof|in)\s+[$A-Za-z_(]`

_s_tern := concat("", [`\s*\+\s*`, _op, `\s*\?[^.?]`])

_s_php_tern := concat("", [`\s*\.\s*\$`, _op, `\s*\?[^?>-]`])

_s_null := concat("", [`\s*\+\s*`, _op, `\s*(?:===?|!==?)\s*null\s*\?`])

_s_coalesce := concat("", ["[\\w)\\]\"'`]", `\s*[+\-*/%]\s*`, _op, `\s*\?\?[^=]`])

_shapes := [
	{"langs": {"c", "cpp", "js", "php"}, "needle": "=", "re": _s_assign, "gates": [`if *\(`, `while *\(`],
		"raw": `(?:if|while) *\(+ *!? *[$\w.>\[\]-]+ *= *[$\w.:>-]+ *\(`,
		"msg": "The comparison binds tighter than =, so the variable receives the comparison result, not the call's value. Parenthesise the assignment: if ((x = f()) < 0)"},
	{"langs": {"py"}, "needle": ":=", "re": _s_walrus, "gates": [`:=`], "raw": `:= *[^\n(]*(?:\([^\n]*\))? *(?:[<>]=?|[=!]=)`,
		"msg": "The comparison binds tighter than :=, so the name receives a bool. Parenthesise the assignment: if (n := len(x)) > LIMIT:"},
	{"langs": {"c", "cpp", "js", "php"}, "needle": "&", "re": _s_mask, "gates": [`& *[$\w.]+ *[=!]=`], "raw": `[\w)\]] *& *[$\w.]+ *[=!]=`,
		"msg": "== binds tighter than &, so this computes x & (MASK == 0). Parenthesise the mask: (x & MASK) == 0"},
	{"langs": {"c", "cpp", "js", "php"}, "needle": "&", "re": _s_mask_rev, "gates": [`== *[$\w.]+ *&[^&=]`, `!= *[$\w.]+ *&[^&=]`], "raw": `[=!]= *[$\w.]+ *&[^&=]`,
		"msg": "== binds tighter than &, so this compares first and masks the boolean. Parenthesise the mask"},
	{"langs": {"c", "cpp", "java", "js", "php", "py", "cs"}, "needle": "+", "re": _s_shift, "gates": [`<< *\d+ *\+`, `>> *\d+ *\+`], "raw": `(?:<<|>>) *\d+ *\+`,
		"msg": "+ binds tighter than the shift, so this shifts by (N + y). Parenthesise the shift: (x << N) + y"},
	{"langs": {"c", "cpp", "js", "php"}, "needle": "!", "re": _s_not, "gates": [`! *[$\w]`], "raw": `! *[$\w][\w.$>-]*(?:\([^\n]*\))? *[=!]=`,
		"msg": "! binds tighter than the comparison, so the negated value is compared. Parenthesise: !(x === y), or use !=="},
	{"langs": {"js"}, "needle": "!", "re": _s_not_inst, "gates": [` instanceof `, ` in `], "raw": `! *[$\w][\w.$\[\]'"]* +(?:instanceof|in) `,
		"msg": "! binds tighter than instanceof/in, so a boolean is tested and the result is always false. Write !(x instanceof Y)"},
	{"langs": {"js"}, "needle": "?", "gates": [`\?`], "re": concat("", ["(?:\"\"|''|``)", _s_tern]), "raw": "[\"'`] *\\+ *[$\\w][^\\n?]*\\?[^.?]",
		"msg": "+ binds tighter than ?:, so the concatenated (always truthy) string is the condition. Parenthesise the ternary"},
	{"langs": {"php"}, "needle": "?", "gates": [`\?`], "re": concat("", [`(?:""|'')`, _s_php_tern]), "raw": `["'] *\. *\$[^\n?]*\?[^?>-]`,
		"msg": ". binds tighter than ?:, so the concatenated string is the condition. Parenthesise the ternary"},
	{"langs": {"java", "js", "cs"}, "needle": "null", "gates": [`= *null *\?`], "re": concat("", [`(?:""|'')`, _s_null]), "raw": `= *null *\?`,
		"msg": "+ binds tighter than ==, so the concatenated string is compared with null (never equal). Parenthesise the comparison"},
	{"langs": {"js", "cs"}, "needle": "??", "gates": [`\?\?[^=]`], "re": _s_coalesce, "raw": `\?\?[^=]`,
		"msg": "Arithmetic binds tighter than ??, so the default applies to the whole result, not the operand. Parenthesise: a + (b ?? 0)"},
]

_keywords := {"return", "case", "sizeof", "else", "do", "throw", "typeof", "await", "yield", "new", "delete", "echo", "print", "in", "of"}

# Shape-specific rejections.

# `$on = count($xs) > 0`: a size function compared to get a flag, on purpose.
_reject(0, m, _, _) if regex.match(`=\s*(?:count|sizeof|strlen|mb_strlen|len|length|size|empty|isset|in_array|array_key_exists)\s*\(`, m[0])

_reject(2, m, _, _) if m[1] in _keywords

# `a === b & c == d`: a non-short-circuit AND of two comparisons.
_reject(k, _, _, c) if {
	k in {2, 3}
	regex.match(`(?:==|!=)\s*[$\w.]+\s*&\s*[$\w.]+(?:\([^()]*\))?\s*(?:==|!=)`, c)
}

_reject(4, m, _, _) if m[1] in _keywords

# C++ stream insertion: `os << 8 + n` prints a sum.
_reject(4, _, "cpp", c) if regex.match(`std::|\bc(?:out|err|log)\b|\bendl\b|stream|""|<<[^\n]*<<|\b(?:os|out|ss|oss|log|str|buf)\s*<<`, c)

# A negation compared with a boolean, or with 0/null where (!x) == 0 and
# !(x == 0) agree; C++ `!operator==(o)`.
_reject(5, m, lang, _) if _neutral_rhs(lang, m[3])

_reject(5, m, _, _) if startswith(m[3], "!")

_reject(5, m, _, _) if startswith(m[1], "operator")

_neutral_rhs(_, r) if regex.match(`^(?:true|false|TRUE|FALSE|True|False)$`, r)

_neutral_rhs(lang, r) if {
	lang in {"c", "cpp", "php"}
	regex.match(`^(?:0|NULL|null|nullptr)$`, r)
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	some k, shape in _shapes
	lang in shape.langs
	contains(content, shape.needle)
	_gated(shape.gates, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, shape.needle)
	count(line) < 600
	regex.match(shape.raw, line)
	not helpers.is_comment_line(line)
	c := _code(lang, line)
	some m in regex.find_all_string_submatch_n(shape.re, c, -1)
	not _reject(k, m, lang, c)
	f := {
		"rule_id": metadata.id,
		"message": shape.msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_gated(gates, content) if {
	some g in gates
	regex.match(g, content)
}
