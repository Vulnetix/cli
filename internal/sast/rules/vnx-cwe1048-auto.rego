# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1048

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1048",
	"name": "Invokable Control Element with Large Number of Outward Calls",
	"description": "A single function or method whose body calls 40 or more distinct functions or methods (CWE-1048, excessive fan-out). A function that reaches that many other units does too many jobs to be reviewed or tested as one, and a security check buried among them is easy to miss or bypass. Counted per function in Go, Java, JavaScript/TypeScript, PHP, Python and Ruby: each distinct callee name (receiver included, so db.Close and store.Close are two) in the body up to its closing brace, dedent or 'end', with string literals, PHP/Ruby heredoc text (a SQL query's COUNT( is not a call) and comment lines removed and language keywords ignored; Go and JavaScript/TypeScript signatures split over several lines and Java package-private methods are recognised; in Ruby a method sent without parentheses counts too. Repeated calls to the same function count once. Not reported: test files, vendored or minified code, AMD module wrappers and whole-page DOM-ready wrappers ($(document).ready(function () {, DOMContentLoaded listeners), functions whose body runs past 300 lines (measured only up to that window), and long functions that call few distinct things (a table-driven switch, a builder repeating one call).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1048/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1048],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["fan-out", "outward-calls", "code-quality", "maintainability", "cwe-1048"],
}

_threshold := 40

_window := 300

# a body shorter than this cannot hold 40 distinct calls in practice; skipping
# it saves the regex pass on almost every function
_min_body := 15

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "js" if {
	some ext in [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]
	endswith(path, ext)
	not endswith(path, ".d.ts")
	not endswith(path, ".min.js")
	not endswith(path, ".bundle.js")
}

_gate := {
	"go": `(?m)^func\b`,
	"java": `\(`,
	"php": `function`,
	"py": `def `,
	"rb": `def `,
	"js": `function|=>|\)\s*\{`,
}

_vendored(path) if regex.match(`(^|/)(node_modules|bower_components|vendor|third_party|site-packages|\.venv|dist|build|docs?)/`, path)

# front-end libraries copied into a static asset tree
_vendored(path) if regex.match(`(^|/)(static|public|assets|resources|wwwroot)/(.*/)?(js/)?(libs?|plugins|vendors?|bower)/[^/]*`, path)

_vendored(path) if regex.match(`(^|/)js/libs?/`, path)

_vendored(path) if regex.match(`(^|/)(jquery|bootstrap|lodash|underscore|angular|react-dom)[\w.-]*\.js$`, path)

# ── declarations: the leading indent of a function's first line ───────────

_decl("go", line) := "" if regex.match(`^func\b.*\{\s*$`, line)

_decl("py", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]*)(?:async[ \t]+)?def[ \t]+\w+[ \t]*\(`, line, 1)
	count(m) > 0
}

_decl("rb", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]*)def[ \t]+[\w.?!=\[\]]+`, line, 1)
	count(m) > 0
	not regex.match(`(;|\s)end\s*$`, line)
	not regex.match(`^\s*def\s+[\w.?!]+(\([^)]*\))?\s*=\s*\S`, line)
}

_decl("php", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]*)(?:(?:public|private|protected|static|final|abstract)[ \t]+)*function[ \t]+&?\w+[ \t]*\(`, line, 1)
	count(m) > 0
	not regex.match(`;\s*$`, line)
}

_decl("java", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]*)(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)[ \t]+)+(?:<[^>]+>[ \t]+)?(?:[\w.<>\[\]?, ]+[ \t]+)?\w+[ \t]*\(`, line, 1)
	count(m) > 0
	not regex.match(`;\s*$`, line)
	not regex.match(`\s(class|interface|enum|record|new)\s|=`, line)
}

# package-private method or constructor: `    Report run(Instant since) throws X {`
_decl("java", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]+)([\w.]+(?:<[^;=()]*>)?(?:\[\])*)[ \t]+(\w+)[ \t]*\([^;=]*\)(?:[ \t]*throws[ \t]+[\w., ]+)?[ \t]*\{\s*$`, line, 1)
	count(m) > 0
	not m[0][2] in {"return", "new", "else", "throw", "case", "yield", "await", "assert"}
	not m[0][3] in _keywords
}

_decl("js", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]*)(?:export[ \t]+)?(?:default[ \t]+)?(?:async[ \t]+)?function\b[^;]*\{\s*$`, line, 1)
	count(m) > 0
}

# a signature split over several lines: the first line ends at the opening
# parenthesis and the body opens on the line that closes the parameter list
_ml_start := {
	"go": `^()func\b[^{]*\(\s*$`,
	"js": `^([ \t]*)(?:export[ \t]+)?(?:(?:const|let|var)[ \t]+[\w$]+[ \t]*(?::[^=]+)?=[ \t]*(?:async[ \t]+)?|(?:default[ \t]+)?(?:async[ \t]+)?function\b[^(]*)\(\s*$`,
}

_ml_open := {
	"go": `^\)[^{]*\{\s*$`,
	"js": `^\)[^{]*(?:=>)?[ \t]*\{\s*$`,
}

# A string test that every declaration line passes, so the declaration
# regexes run on a few lines per file rather than on all of them.
_maybe_decl("go", line) if startswith(line, "func")

_maybe_decl("py", line) if contains(line, "def")

_maybe_decl("rb", line) if contains(line, "def")

_maybe_decl("php", line) if contains(line, "function")

_maybe_decl("java", line) if {
	contains(line, "(")
	not endswith(trim_right(line, " \t\r"), ";")
}

_maybe_decl("js", line) if endswith(trim_right(line, " \t\r"), "{")

_maybe_decl("js", line) if endswith(trim_right(line, " \t\r"), "(")

_decl_any(l, _, _, line) := ind if {
	_maybe_decl(l, line)
	ind := _decl(l, line)
}

_decl_any(l, lines, i, line) := ind if {
	_maybe_decl(l, line)
	not _decl(l, line)
	m := regex.find_all_string_submatch_n(_ml_start[l], line, 1)
	count(m) > 0
	ind := m[0][1]
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
	startswith(lines[k], ind)
	regex.match(_ml_open[l], trim_prefix(lines[k], ind))
}

_decl("js", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]*)(?:export[ \t]+)?(?:const|let|var)[ \t]+[\w$]+[ \t]*(?::[^=]+)?=[ \t]*(?:async[ \t]+)?(?:function\b[^;]*|(?:\([^)]*\)|[\w$]+)(?:[ \t]*:[^=]+)?[ \t]*=>[ \t]*)\{\s*$`, line, 1)
	count(m) > 0
}

# class methods: name(args) {
_decl("js", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]*)(?:(?:public|private|protected|static|async|override|get|set)[ \t]+)*([\w$]+)[ \t]*\([^)]*\)[ \t]*(?::[^{=]+)?\{\s*$`, line, 1)
	count(m) > 0
	not m[0][2] in _keywords
	not regex.match(`\bfunction\b|=>|['"\[]`, line)
}

# callbacks: app.post('/x', async (req, res) => {   /  .on('x', function (e) {
# An AMD/UMD module wrapper (define([...], function (require) {) is a file,
# not a function, and is not one.
_decl("js", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^([ \t]*)[\w$.]+\(.*(?:function[ \t]*[\w$]*[ \t]*\([^)]*\)|\([^)]*\)[ \t]*=>|[\w$]+[ \t]*=>)[ \t]*\{\s*$`, line, 1)
	count(m) > 0
	not regex.match(`^\s*([\w$]+\.)?(define|createModule)\(`, line)
	not _dom_ready(line)
}

# ── the line that ends a function body ────────────────────────────────────

_last(lines, i) := min([count(lines) - 1, i + _window])

# Lines that open with a closing brace, grouped by the indent before it, in
# line order. Built once per file, so finding where a function ends is a walk
# over the closers at its indent rather than a scan of the next 300 lines.
_closers(lines) := {ind: [k | some p in pairs; p[1] == ind; k := p[0]] |
	some ind in {p[1] | some p in pairs}
} if {
	pairs := [[k, ind] |
		some k, l in lines
		t := trim_left(l, " \t")
		startswith(t, "}")
		ind := substring(l, 0, count(l) - count(t))
	]
}

_end(lines, i, ind, l, cl) := e if {
	l in {"go", "java", "php", "js"}
	last := _last(lines, i)
	ends := [k | some k in object.get(cl, ind, []); k > i; k <= last]
	e := _first(ends, lines, i)
}

_end(lines, i, ind, "rb", _) := e if {
	ends := [k |
		some k in numbers.range(i + 1, _last(lines, i))
		regex.match(`^end\b`, trim_prefix(lines[k], ind))
		startswith(lines[k], ind)
		_indent(lines[k]) == count(ind)
	]
	e := _first(ends, lines, i)
}

_end(lines, i, ind, "py", _) := e if {
	ends := [k |
		some k in numbers.range(i + 1, _last(lines, i))
		l := lines[k]
		t := trim_space(l)
		t != ""
		not startswith(t, "#")
		_indent(l) <= count(ind)
		not startswith(t, ")")
	]
	count(ends) > 0
	e := ends[0]
}

# a body that runs past the window is measured over the window
_end(lines, i, ind, "py", _) := _last(lines, i) + 1 if {
	every k in numbers.range(i + 1, _last(lines, i)) {
		_py_inside(lines[k], ind)
	}
}

_py_inside(l, _) if trim_space(l) == ""

_py_inside(l, _) if startswith(trim_space(l), "#")

_py_inside(l, _) if startswith(trim_space(l), ")")

_py_inside(l, ind) if _indent(l) > count(ind)

_indent(line) := count(line) - count(trim_left(line, " \t"))

# the first closing line, or the end of the window when the body runs past it
_first(ends, _, _) := ends[0] if count(ends) > 0

_first(ends, lines, i) := _last(lines, i) + 1 if count(ends) == 0

# ── callees ────────────────────────────────────────────────────────────────

_strings(l) := `"""[\s\S]*?"""|'{3}[\s\S]*?'{3}|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'` if l == "py"

# PHP and Ruby double-quoted strings may span lines (SQL, heredoc-like text)
_strings(l) := `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\\n])*'` if l in {"php", "rb"}

_strings(l) := _str_default if not l in {"py", "php", "rb"}

_str_default := "\"(?:\\\\.|[^\"\\\\\\n])*\"|'(?:\\\\.|[^'\\\\\\n])*'|`[^`]*`"

_call_re := `[$A-Za-z_][\w$]*(?:(?:\.|->|::)[$A-Za-z_][\w$]*)*\s*\(`

_keywords := {
	"if", "for", "foreach", "while", "switch", "catch", "return", "function", "typeof", "sizeof",
	"elif", "not", "and", "or", "in", "super", "this", "self", "new", "await", "yield", "throw",
	"case", "when", "unless", "until", "do", "else", "def", "func", "lambda", "assert", "del",
	"with", "except", "raise", "isset", "empty", "array", "list", "echo", "print", "require",
	"require_once", "include", "include_once", "use", "match", "fn", "defer", "go", "select",
	"range", "len", "cap", "make", "append", "panic", "recover", "delete", "instanceof", "void",
	"synchronized", "elseif", "unset", "exit", "die", "async", "end", "begin", "rescue", "then",
	"import", "from", "class", "struct", "interface", "map", "chan", "string", "int", "byte",
	"float64", "int64", "error", "bool", "rune", "uint", "int32", "uint64", "uint8", "puts",
}

_clean(c) := trim_prefix(trim_prefix(trim_prefix(trim_prefix(regex.replace(c, `\s*\($`, ""), "$this->"), "this."), "self."), "$")

_leaf(c) := parts[count(parts) - 1] if parts := regex.split(`\.|->|::`, c)

_calls(body, _) := {c |
	some m in regex.find_all_string_submatch_n(_call_re, body, -1)
	c := _clean(m[0])
	not _leaf(c) in _keywords
}

_sends(body, "rb") := {c |
	some m in regex.find_all_string_submatch_n(`\.([a-z_]\w*[?!]?)`, body, -1)
	c := concat("", [".", m[1]])
}

_sends(_, l) := set() if l != "rb"

# A whole-page DOM-ready wrapper ($(document).ready(function () {, $(function
# () {, DOMContentLoaded/load listeners) holds a script's functions, like an
# AMD wrapper; it is not itself a unit of work.
_dom_ready(line) if regex.match(`^\s*(\$|jQuery)\(\s*(document|window|function|\(\s*\)\s*=>|async)`, line)

_dom_ready(line) if regex.match(`^\s*(document|window)\.addEventListener\(\s*['"](DOMContentLoaded|load)['"]`, line)

# The text of PHP (<<<SQL) and Ruby (<<~SQL, <<-SQL) heredocs: a SQL query's
# COUNT( and SUM( are not calls. Lines from the opener's next line through the
# terminator.
_heredoc_lines(_, _, _, l) := set() if not l in {"php", "rb"}

_heredoc_lines(lines, i, e, l) := {x |
	l in {"php", "rb"}
	some k in helpers.span(i + 1, e - 1)
	contains(lines[k], "<<")
	m := regex.find_all_string_submatch_n(`<<[~-]?['"]?([A-Z_][A-Z0-9_]*)['"]?`, lines[k], 1)
	count(m) > 0
	term := concat("", [`^\s*`, m[0][1], `\b`])
	ends := [k2 | some k2 in helpers.span(k + 1, e - 1); regex.match(term, lines[k2])]
	count(ends) > 0
	some x in numbers.range(k + 1, ends[0])
}

# Fewer than 40 opening parentheses cannot hold 40 distinct calls. Ruby sends
# methods without parentheses, so its bodies are always counted.
_enough_parens(_, _, _, "rb")

_enough_parens(lines, i, e, l) if {
	l != "rb"
	count(indexof_n(concat("\n", array.slice(lines, i + 1, e)), "(")) >= _threshold
}

findings contains finding if {
	some path, content in input.file_contents
	l := _lang(path)
	not _vendored(path)
	not helpers.is_test_path(path)
	regex.match(_gate[l], content)
	lines := split(content, "\n")
	cl := _closers(lines)
	some i, line in lines
	ind := _decl_any(l, lines, i, line)
	e := _end(lines, i, ind, l, cl)
	e - i > _min_body
	_enough_parens(lines, i, e, l)
	skip := _heredoc_lines(lines, i, e, l)
	body := regex.replace(concat("\n", [x | some k in helpers.span(i + 1, e - 1); not k in skip; x := lines[k]; not helpers.is_comment_line(x)]), _strings(l), `""`)
	callees := _calls(body, l) | _sends(body, l)
	n := count(callees)
	n >= _threshold
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("This function calls %d distinct functions or methods in %d lines; a unit with that much fan-out does too many jobs to review or test as one, and a security check among them is easy to miss. Split it into smaller functions with one responsibility each", [n, e - i]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
