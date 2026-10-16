# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1025

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1025",
	"name": "Comparison Using Wrong Factors",
	"description": "A comparison that examines the wrong property of its operands, so it can succeed or fail regardless of the values the author meant to compare. Reported: in Java, == or != between object references where a value comparison was meant (a String literal operand, a String-returning call such as getParameter/getHeader/trim/toString, a variable declared String a few dozen lines above, or two variables declared Integer/Long/BigDecimal and other boxed types), and classes compared by name (getClass().getName()/getSimpleName() with equals or ==); in Python, `is`/`is not` against a str, bytes, number, list, dict or empty-tuple literal in an if/elif/while/assert/return statement (also the first line of a condition that wraps) or an assignment, and type(x).__name__ or x.__class__.__name__ compared with ==/!=; in JavaScript/TypeScript, ==/=== against a fresh [] or {} literal (always a different object), x.constructor.name compared with ==/===, and typeof compared with a string typeof never returns ('array', 'null', 'date', ...); in Go, err.Error() text compared with ==/!= with a non-empty literal or another error's text instead of errors.Is (directly or through a variable assigned err.Error() a few lines above), and switch err.Error() {, and reflect.TypeOf(x).Name()/String() or fmt.Sprintf(\"%T\") compared with ==; in PHP, loose ==/!= with an md5/sha1/hash/hash_hmac/crypt result, directly or through a variable assigned one a few lines above (\"0e...\" hashes compare as numbers), strcmp/strcasecmp(...) == 0 and !strcmp(...) (NULL == 0 when an argument is an array), and get_class() compared with a string literal. Not reported: err.Error() != \"\" (an emptiness test), comparisons with null/None/True/False, enums, primitives and char literals, equals()/Objects.equals/MessageDigest.isEqual/hash_equals/password_verify/errors.Is/instanceof/isinstance, strict === in PHP, a.intern() == b.intern(), get_class() against ::class or __CLASS__, timing-unsafe comparison of secrets (a different weakness), test code, comments and the pattern inside string literals. Two comparisons are reported by a more precise rule, so the line is reported once: a Java String compared with a string literal by == or != by VNX-597 (String compared with == instead of equals()), and a PHP loose comparison VNX-PHP-010 reports (a hash compared with ==, strcmp() == 0 on request data: PHP type juggling).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1025/",
	"languages": ["java", "python", "node", "go", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1025],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["comparison", "wrong-factors", "equality", "security-check", "cwe-1025"],
}

# The language is looked up by extension: one split and one object lookup
# per file instead of a chain of endswith tests.
_ext_lang := {
	"java": "java", "py": "py", "go": "go", "php": "php", "phtml": "php",
	"js": "js", "jsx": "js", "mjs": "js", "cjs": "js", "ts": "js", "tsx": "js", "mts": "js", "cts": "js",
}

_lang(path) := l if {
	parts := split(path, ".")
	l := _ext_lang[parts[count(parts) - 1]]
	not endswith(path, ".min.js")
}

_has_cmp(s) if contains(s, "==")

_has_cmp(s) if contains(s, "!=")

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# Substring prefilters per language: a line is only parsed when it carries
# the token one of its shapes needs.
_java_str_calls := {
	"getParameter", "getHeader", "getText", "toString", "trim", "strip", "toLowerCase",
	"toUpperCase", "substring", "concat", "replace", "getQueryString", "getRemoteUser",
	"nextLine", "readLine", ".name()",
}

_cand(line, "java") if {
	_has_cmp(line)
	contains(line, "\"")
}

_cand(line, "java") if {
	_has_cmp(line)
	_has_any(line, _java_str_calls)
}

_cand(line, "java") if contains(line, "getClass()")

_cand(line, "py") if {
	contains(line, " is ")
	regex.match(`^\s*(?:(?:if|elif|while|assert|return)\b|[\w.]+\s*=[^=])`, line)
}

_cand(line, "py") if {
	contains(line, "__name__")
	_has_cmp(line)
}

_cand(line, "js") if {
	_has_cmp(line)
	_has_any(line, {"[]", "{}", "[ ]", "{ }", "constructor.name"})
}

_cand(line, "go") if {
	_has_cmp(line)
	_has_any(line, {".Error()", "TypeOf(", ".Type()", "%T"})
}

_cand(line, "php") if {
	_has_cmp(line)
	_has_any(line, {"md5", "sha1", "hash", "crypt", "strcmp", "strcasecmp", "get_class"})
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/(test|it)/`, path)

# String literals become @S@ and a trailing // comment is dropped, so a
# comparison quoted in a message or a comment is not code.
_code(line, lang) := regex.replace(_blank(line, lang), `\s//.*$`, "") if lang in {"java", "js", "go", "php"}

_code(line, "py") := regex.replace(_blank(line, "py"), `\s#.*$`, "")

_blank(line, "js") := regex.replace(line, "\"(\\\\.|[^\"\\\\])*\"|'(\\\\.|[^'\\\\])*'|`[^`$]*`", "@S@")

_blank(line, "go") := regex.replace(replace(line, `""`, "@E@"),"\"(\\\\.|[^\"\\\\])*\"|`[^`]*`", "@S@")

_blank(line, lang) := regex.replace(line, `"(\\.|[^"\\])*"|'(\\.|[^'\\])*'`, "@S@") if lang in {"py", "php"}

# Java: a single-quoted literal is a char, which == compares by value.
_blank(line, "java") := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, "@S@"), `'(\\.|[^'\\])+'`, "@C@")

# ── Java ─────────────────────────────────────────────────────────────────

# A String literal on either side of == / !=.
_bad(_, code, "java", _, _) if regex.match(`(?:[!=]=\s*@S@|@S@\s*[!=]=)`, code)

# A call that returns a new String, compared by reference.
_str_call := `\.(?:getParameter|getHeader|getText|toString|trim|strip|toLowerCase|toUpperCase|substring|concat|replace|replaceAll|getQueryString|getRemoteUser|nextLine|readLine|name)\s*\((?:[^()]|\([^()]*\))*\)`

_bad(_, code, "java", _, _) if {
	m := regex.find_all_string_submatch_n(concat("", [_str_call, `\s*[!=]=\s*([\w@]+)`]), code, -1)
	some x in m
	x[1] != "null"
}

_bad(_, code, "java", _, _) if regex.match(concat("", [`[!=]=\s*[\w.]+`, _str_call]), code)

# Classes compared by name.
_bad(_, code, "java", _, _) if regex.match(`getClass\(\)\s*\.\s*get(?:Simple|Canonical|Type)?Name\(\)\s*(?:\.\s*(?:equals|equalsIgnoreCase|contentEquals)\s*\(|[!=]=)`, code)

_bad(_, code, "java", _, _) if regex.match(`(?:@S@\s*\.\s*equals(?:IgnoreCase)?\s*\(\s*|[!=]=\s*)[\w.]*getClass\(\)\s*\.\s*get(?:Simple|Canonical)?Name\(\)`, code)

# Operands of == / != : (left, right). A left operand can sit on the line
# above, so it may be empty.
_operands(code) := {[m[2], m[3]] |
	some m in regex.find_all_string_submatch_n(`(^|[^\w.@])([A-Za-z_]\w*)?\s*[!=]=\s*([A-Za-z_]\w*)\s*($|[)\];,?:&|])`, code, -1)
}

_decl_string := `\bString\s+([A-Za-z_]\w*)\s*[=;,)]`

_decl_boxed := `\b(?:Integer|Long|Short|Byte|Character|Double|Float|Boolean|BigInteger|BigDecimal)\s+([A-Za-z_]\w*)\s*[=;,)]`

# Declarations count from the enclosing method's signature down to the
# comparison, so a name reused with another type in an earlier method does
# not. Both are indexed once per file.
_method_re := `^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|abstract|synchronized)\s+)+[\w.<>\[\],?\s]*\b\w+\s*\(`

_modifiers := {"public ", "private ", "protected ", "static "}

_java_decls(lines) := {[m[1], j, "s"] |
	some j, l in lines
	contains(l, "String ")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_decl_string, l, -1)
} | {[m[1], j, "b"] |
	some j, l in lines
	_has_any(l, {"Integer ", "Long ", "Short ", "Byte ", "Character ", "Double ", "Float ", "Boolean ", "BigInteger ", "BigDecimal "})
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_decl_boxed, l, -1)
}

_method_starts(lines) := [j |
	some j, l in lines
	_has_any(l, _modifiers)
	regex.match(_method_re, l)
]

_scope_start(starts, i) := max(array.concat([max([0, i - 80])], [s | some s in starts; s <= i]))

_in_scope(decls, name, kind, lo, i) if {
	some d in decls
	d[0] == name
	d[2] == kind
	d[1] >= lo
	d[1] <= i
}

_ref_compare(op, decls, lo, i) if {
	not "null" in op
	some v in op
	_in_scope(decls, v, "s", lo, i)
}

_ref_compare(op, decls, lo, i) if {
	_in_scope(decls, op[0], "b", lo, i)
	_in_scope(decls, op[1], "b", lo, i)
}

# ── Python ───────────────────────────────────────────────────────────────

_py_literal_is := `\bis\s+(?:not\s+)?(?:@S@|[bfru]{1,2}@S@|-?\d|\[|\{|\(\s*\))`

_bad(_, code, "py", _, _) if {
	regex.match(_py_literal_is, code)
	regex.match(`^\s*(?:(?:if|elif|while|assert|return)\b|[\w.]+\s*=[^=])`, code)
}

_bad(_, code, "py", _, _) if regex.match(`(?:\b__class__|\btype\s*\([^()]*\))\s*\.\s*__(?:qual)?name__\s*[!=]=|[!=]=\s*[\w.]*(?:\b__class__|\btype\s*\([^()]*\))\s*\.\s*__(?:qual)?name__`, code)

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_bad(_, code, "js", _, _) if regex.match(`[!=]==?\s*(?:\[\s*\]|\{\s*\})\s*(?:$|[)\];,?:&|])|(?:^|[(\s!&|,=?:])(?:\[\s*\]|\{\s*\})\s*[!=]==?`, code)

_bad(_, code, "js", _, _) if regex.match(`\.constructor\.name\s*[!=]==?|[!=]==?\s*[\w.$]*\.constructor\.name\b`, code)

_typeof_values := {"undefined", "object", "boolean", "number", "bigint", "string", "symbol", "function", "unknown"}

# ── Go ───────────────────────────────────────────────────────────────────

_bad(_, code, "go", _, _) if regex.match(`\.Error\(\)\s*[!=]=\s*(?:@S@|[\w.]+\.Error\(\))|@S@\s*[!=]=\s*[\w.]+\.Error\(\)`, code)

_bad(_, code, "go", _, _) if regex.match(`(?:reflect\.TypeOf\([^()]*\)|\.Type\(\))\.(?:Name|String)\(\)\s*[!=]=|[!=]=\s*reflect\.TypeOf\([^()]*\)\.(?:Name|String)\(\)`, code)

# A switch on the error's text, with string cases.
_bad(_, code, "go", _, _) if regex.match(`^\s*switch\s+[\w.]+\.Error\(\)\s*\{`, code)

_cand(line, "go") if {
	contains(line, "switch")
	contains(line, ".Error()")
}

_bad(line, _, "go", _, _) if regex.match(`fmt\.Sprintf\(\s*"%T"\s*,[^()]*\)\s*[!=]=|[!=]=\s*fmt\.Sprintf\(\s*"%T"`, line)

# ── PHP ──────────────────────────────────────────────────────────────────

_php_hash := `\b(?:md5|sha1|hash|hash_hmac|crypt)\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_bad(_, code, "php", _, _) if regex.match(concat("", [_php_hash, `\s*(?:==|!=)\s*[^=]`]), code)

_bad(_, code, "php", _, _) if regex.match(concat("", [`(?:^|[^=!<>])(?:==|!=)\s*`, _php_hash]), code)

_bad(_, code, "php", _, _) if regex.match(`\bstr(?:case)?cmp\s*\((?:[^()]|\([^()]*\))*\)\s*(?:==|!=)\s*0\b|(?:^|[^=!<>])\b0\s*(?:==|!=)\s*str(?:case)?cmp\s*\(`, code)

_cand(line, "php") if contains(line, "cmp(")

# !strcmp(a, b) is true when strcmp returns NULL for an array argument.
_bad(_, code, "php", _, _) if regex.match(`(?:^|[^\w$>:])!\s*str(?:case)?cmp\s*\(`, code)

_bad(_, code, "php", _, _) if regex.match(`\bget_class\s*\([^()]*\)\s*[!=]==?\s*@S@|@S@\s*[!=]==?\s*get_class\s*\(`, code)

_msg := "This comparison examines the wrong property of its operands (object identity, a class or error name, a loose numeric conversion), so it can pass or fail regardless of the values meant. Compare values: equals()/Objects.equals in Java, == in Python, Array.isArray/length or instanceof in JavaScript, errors.Is/errors.As in Go, === or hash_equals in PHP"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# Whole-file gates: any of the language's line shapes also passes one of
# these, so ordinary files are never split into lines. Each expression
# starts with a literal, which Go's regexp finds with a substring search
# instead of trying every byte of the file.
_gate_res := {
	"java": [
		`[!=]=\s*"|"\s*[!=]=|getClass\(\)\s*\.\s*get(?:Simple|Canonical|Type)?Name|\.(?:getParameter|getHeader|getText|toString|trim|strip|toLowerCase|toUpperCase|substring|concat|replace|replaceAll|getQueryString|getRemoteUser|nextLine|readLine|name)\s*\([^\n]*\)\s*[!=]=|[!=]=\s*[\w.]+\.(?:getParameter|getHeader|getText|toString|trim|strip|toLowerCase|toUpperCase|substring|concat|replace|replaceAll|getQueryString|getRemoteUser|nextLine|readLine|name)\s*\(`,
	],
	"py": [
		`is\s+(?:not\s+)?(?:[bfru]{0,2}["']|-?\d|\[|\{|\(\s*\))`,
		`name__\s*[!=]=`,
		`==\s*[\w.]*(?:__class__|type\s*\()`,
		`!=\s*[\w.]*(?:__class__|type\s*\()`,
	],
	"js": [
		`==\s*[\[{]\s*[\]}]`,
		`!=\s*[\[{]\s*[\]}]`,
		`\[\s*\]\s*[!=]=`,
		`\{\s*\}\s*[!=]=`,
		`constructor\.name`,
	],
	"go": [
		`\.Error\(\)\s*[!=]=`,
		`==\s*[\w.]+\.Error\(\)`,
		`!=\s*[\w.]+\.Error\(\)`,
		`\.Type\(\)\.(?:Name|String)\(\)\s*[!=]=`,
		`switch\s+[\w.]+\.Error\(\)\s*\{`,
		`reflect\.TypeOf\(`,
		`"%T"`,
	],
	"php": [
		`md5\s*\([^\n]*[!=]=`,
		`sha1\s*\([^\n]*[!=]=`,
		`hash\s*\([^\n]*[!=]=`,
		`hash_hmac\s*\([^\n]*[!=]=`,
		`crypt\s*\([^\n]*[!=]=`,
		`strcmp\s*\([^\n]*[!=]=\s*0`,
		`strcasecmp\s*\([^\n]*[!=]=\s*0`,
		`!\s*str(?:case)?cmp\s*\(`,
		`get_class\s*\([^()\n]*\)\s*[!=]==?\s*["']`,
		`==[^\n]*?(?:md5|sha1|hash|hash_hmac|crypt|strcmp|strcasecmp|get_class)\s*\(`,
		`!=[^\n]*?(?:md5|sha1|hash|hash_hmac|crypt|strcmp|strcasecmp|get_class)\s*\(`,
	],
}

_gate(content, lang) if {
	some re in _gate_res[lang]
	regex.match(re, content)
}

# Substring gates run first: strings.Contains is far cheaper than a regex
# over a whole file.
_file_needles := {
	"java": {"\"", "getClass()"},
	"py": {" is ", "__name__"},
	"js": {
		"== [", "== {", "==[", "=={", "!= [", "!= {", "!=[", "!={", "[] =", "[] !", "{} =", "{} !",
		"constructor.name",
	},
	"go": {".Error()", "TypeOf(", ".Type()", "%T"},
	"php": {"md5(", "sha1(", "hash(", "hash_hmac(", "crypt(", "strcmp(", "strcasecmp(", "get_class("},
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _file_needles[lang])
	_gate(content, lang)
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 500
	_cand(line, lang)
	not helpers.is_comment_line(line)
	code := _code(line, lang)
	_bad(line, code, lang, lines, i)
	not _handed_over(lang, content, lines, i, line)
	finding := _finding(path, i, line)
}

# JavaScript: typeof compared with a string it never returns. The file's
# typeof comparisons are read in one pass, and only a file holding a value
# outside typeof's range is split into lines.
_typeof_re := "\\btypeof\\s*\\(?\\s*[\\w.$]+(?:\\[[^\\]]*\\])*\\s*\\)?\\s*[!=]==?\\s*[\"'`](\\w*)[\"'`]|[\"'`](\\w*)[\"'`]\\s*[!=]==?\\s*typeof\\b"

# The file-level form starts with the literal "typeof" so it is searched,
# not tried at every byte; the reversed spelling ("x" === typeof y) is
# rare and only needs a substring to send the file to the line pass.
_typeof_fwd_re := "typeof\\s*\\(?\\s*[\\w.$]+(?:\\[[^\\]]*\\])*\\s*\\)?\\s*[!=]==?\\s*[\"'`](\\w*)[\"'`]"

_bad_typeof(s) if {
	some m in regex.find_all_string_submatch_n(_typeof_re, s, -1)
	not concat("", [m[1], m[2]]) in _typeof_values
}

_typeof_file(content) if {
	some m in regex.find_all_string_submatch_n(_typeof_fwd_re, content, -1)
	not m[1] in _typeof_values
}

_typeof_file(content) if contains(content, "= typeof")

_typeof_file(content) if contains(content, "=typeof")

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	contains(content, "typeof")
	_typeof_file(content)
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 500
	contains(line, "typeof")
	not helpers.is_comment_line(line)
	_bad_typeof(line)
	finding := _finding(path, i, line)
}

# Java: == / != between variables declared String (one side) or boxed
# numbers (both sides) in the enclosing method.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_has_cmp(content)
	not _is_test(path)
	names := _java_decl_names(content)
	count(names) > 0
	lines := split(content, "\n")
	cands := [i |
		some i, line in lines
		_has_cmp(line)
		some raw in _operands(line)
		_has_any_in(raw, names)
		not helpers.is_comment_line(line)
	]
	count(cands) > 0
	decls := _java_decls(lines)
	starts := _method_starts(lines)
	some i in cands
	line := lines[i]
	some op in _operands(_code(line, "java"))
	_ref_compare(op, decls, _scope_start(starts, i), i)
	finding := _finding(path, i, line)
}

_has_any_in(op, names) if {
	some v in op
	v in names
}

# Go: a variable assigned err.Error() a few lines above, compared with a
# non-empty literal.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, ".Error()")
	not _is_test(path)
	lines := split(content, "\n")
	errvars := {[m[1], j] |
		some j, l in lines
		contains(l, ".Error()")
		some m in regex.find_all_string_submatch_n(`^\s*(\w+)\s*:?=\s*[\w.]+\.Error\(\)\s*$`, l, 1)
	}
	count(errvars) > 0
	some i, line in lines
	_has_cmp(line)
	contains(line, "\"")
	some ev in errvars
	ev[1] < i
	ev[1] >= i - 6
	not helpers.is_comment_line(line)
	regex.match(concat("", [`\b`, ev[0], `\s*[!=]=\s*"[^"]|"[^"]+"\s*[!=]=\s*`, ev[0], `\b`]), line)
	finding := _finding(path, i, line)
}

# Names declared String or boxed anywhere in the file, read from the whole
# content (each expression starts with a literal type name), so a file is
# only split when a comparison could involve one of them.
_java_decl_types := {
	"String", "Integer", "Long", "Short", "Byte", "Character", "Double", "Float", "Boolean", "BigInteger",
	"BigDecimal",
}

_java_decl_names(content) := {m[1] |
	some t in _java_decl_types
	contains(content, concat("", [t, " "]))
	some m in regex.find_all_string_submatch_n(concat("", [t, `\s+([A-Za-z_]\w*)\s*[=;,)]`]), content, -1)
}

# PHP: a variable assigned a hash a few lines above, then compared loosely.
_php_hash_assign := `^\s*\$(\w+)\s*=\s*(?:md5|sha1|hash|hash_hmac|crypt)\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "php"
	_has_any(content, {"md5(", "sha1(", "hash(", "hash_hmac(", "crypt("})
	regex.match(`=\s*(?:md5|sha1|hash|hash_hmac|crypt)\s*\(`, content)
	not _is_test(path)
	lines := split(content, "\n")
	hvars := {[m[1], j] |
		some j, l in lines
		contains(l, "(")
		some m in regex.find_all_string_submatch_n(_php_hash_assign, l, 1)
	}
	some hv in hvars
	some i in numbers.range(hv[1] + 1, min([count(lines) - 1, hv[1] + 8]))
	line := lines[i]
	_has_cmp(line)
	contains(line, hv[0])
	not helpers.is_comment_line(line)
	code := _code(line, "php")
	regex.match(concat("", [`\$`, hv[0], `\b\s*(?:==|!=)\s*[^=]|(?:^|[^=!<>])(?:==|!=)\s*\$`, hv[0], `\b`]), code)
	finding := _finding(path, i, line)
}

# ── comparisons other rules report ──────────────────────────────────────
# A Java String compared by == or != with a string literal is VNX-597's
# finding, and a PHP loose comparison that decides an authentication or
# integrity check (a hash compared with ==, strcmp() == 0) is VNX-PHP-010's.
# Each test below is that rule's own, so a line is handed over only when the
# other rule reports it.
_handed_over("java", content, _, _, line) if {
	contains(content, "String")
	contains(line, "\"")
	regex.match(`[=!]=\s*"|"\s*[=!]=`, line)
	c := regex.replace(regex.replace(regex.replace(line, `'(?:[^'\\]|\\.)'`, `''`), `"(?:[^"\\]|\\.)*"`, `""`), `\s*(?://|/\*).*$`, "")
	regex.match(`(?:[=!]=\s*""|""\s*[=!]=)`, c)
}

_handed_over("php", content, lines, i, line) if _r010_owns(content, lines, i, line)

# ── lines VNX-PHP-010 reports ───────────────────────────────────────────
# A PHP loose comparison or strcmp() test that decides an authentication or
# integrity check is VNX-PHP-010's finding (PHP type juggling). This is that
# rule's own test, kept in step with it, so a line is only handed over when
# it reports the line.
_r010_owns(content, lines, i, line) if {
	_r010_gate(content)
	regex.match(`[^=!](==|!=|<>)[^=]|\bstrn?(case)?cmp\s*\(`, line)
	_r010_report(_r010_masked(line), _r010_tainted(lines, i))
}

_r010_op := `(\$\w+(?:\s*\[[^\]]*\]|->\w+|::\$?\w+)*(?:\s*\((?:[^()]|\([^()]*\))*\))?|[A-Za-z_][\w\\]*(?:::\w+)?\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|-?\d[\w.]*|\w+)`

_r010_cmp_re := concat("", [_r010_op, `\s*(?:==|!=|<>)\s*`, _r010_op])

_r010_source_re := `\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\bjson_decode\s*\(|php://input|\$request->(input|get|query|post|header|cookie|json)\s*\(|\brequest\s*\(\s*['"]|\bgetallheaders\s*\(`

# Secret names are matched as whole identifier words (snake_case and
# camelCase are split), so author, hashtag, passenger or encoding do not
# count as auth, hash, pass or code.
_r010_secret_words := {
	"pass", "passwd", "password", "passphrase", "pwd", "pw", "token", "secret",
	"hash", "sig", "signature", "hmac", "otp", "nonce", "csrf", "xsrf", "apikey",
	"auth", "digest", "answer", "pin", "code", "totp", "mfa",
}

_r010_names_secret(s) if {
	norm := lower(regex.replace(s, `([a-z0-9])([A-Z])`, "${1}_${2}"))
	some w in regex.find_n(`[a-z]+`, norm, -1)
	_r010_secret_words[w]
}

_r010_names_secret(s) if regex.match(`(?i)api_?key`, s)

_r010_hash_re := `^(md5|sha1|hash|hash_hmac|crypt|md5_file|sha1_file|hash_file)\s*\(`

# A string literal that itself contains a comparison operator is prose.
# Literals are found left to right so quote pairs are matched correctly.
_r010_masked(line) := strings.replace_n(
	{lit: `''` |
		some lit in regex.find_n(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, line, -1)
		regex.match(`==|!=|<>`, lit)
	},
	line,
)

_r010_is_lit(op) if regex.match(`(?i)^(['"]|-?\d|true$|false$|null$)`, op)

_r010_magic_lit(op) if regex.match(`^['"]0e\d+['"]$`, op)

_r010_tainted(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 30]), i - 1)
	prev := lines[j]
	regex.match(_r010_source_re, prev)
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(_r010_direct_re, prev, 1)
	v := m[0][1]
}

# The assigned value IS the input (optionally through a trivial wrapper), not
# merely computed with it: $row = fetch_user($_POST['u']) is database data.
_r010_direct_re := `^\s*\$(\w+)\s*=\s*(?:(?:trim|strtolower|strtoupper|urldecode|rawurldecode|base64_decode|stripslashes|json_decode|isset|\(string\))\s*\(?\s*)*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|json_decode\s*\(|file_get_contents\s*\(\s*['"]php://input|\$request->|request\s*\(|getallheaders\s*\()`

_r010_is_user(op, _) if regex.match(`^\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b`, op)

_r010_is_user(op, tainted) if {
	m := regex.find_all_string_submatch_n(`^\$(\w+)`, op, 1)
	tainted[m[0][1]]
}

_r010_is_user(op, _) if regex.match(`^(\$request->(input|get|query|post|header|cookie)|request)\s*\(`, op)

_r010_juggles(l, r, _) if {
	regex.match(_r010_hash_re, l)
	not _r010_is_lit(r)
}

_r010_juggles(l, r, _) if {
	regex.match(_r010_hash_re, l)
	_r010_magic_lit(r)
}

_r010_juggles(l, r, tainted) if {
	_r010_is_user(l, tainted)
	not _r010_is_lit(r)
	not _r010_is_user(r, tainted)
	_r010_names_secret(concat(" ", [l, r]))
}

_r010_loose(code, tainted) if {
	some m in regex.find_all_string_submatch_n(_r010_cmp_re, code, -1)
	l := trim_space(m[1])
	r := trim_space(m[2])
	_r010_either(l, r, tainted)
}

_r010_either(l, r, tainted) if _r010_juggles(l, r, tainted)

_r010_either(l, r, tainted) if _r010_juggles(r, l, tainted)

_r010_strcmp_re := `\bstrn?(?:case)?cmp\s*\(((?:[^()]|\([^()]*\))*)\)`

_r010_strcmp_bypass(code, tainted) if {
	regex.match(`\bstrn?(?:case)?cmp\s*\((?:[^()]|\([^()]*\))*\)\s*(?:==|!=|<>)\s*0\b|\b0\s*(?:==|!=|<>)\s*strn?(?:case)?cmp\s*\(|!\s*strn?(?:case)?cmp\s*\(`, code)
	some m in regex.find_all_string_submatch_n(_r010_strcmp_re, code, -1)
	_r010_args_user(m[1], tainted)
}

_r010_args_user(args, _) if regex.match(_r010_source_re, args)

_r010_args_user(args, tainted) if {
	some v in tainted
	regex.match(concat("", [`\$`, v, `\b`]), args)
}


_r010_report(code, tainted) if _r010_loose(code, tainted)

_r010_report(code, tainted) if _r010_strcmp_bypass(code, tainted)

# Cheap whole-file gate: a comparison can only be reported in a file that
# reads input, hashes, or calls strcmp.
_r010_gate(content) if {
	some s in ["$_", "json_decode", "$request", "request(", "md5", "sha1", "hash", "crypt(", "cmp("]
	contains(content, s)
}
