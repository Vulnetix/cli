package vulnetix.rules.vnx_java_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-001",
	"name": "Command injection via Runtime.exec() or a shell ProcessBuilder",
	"description": "Reports a Java OS command whose text is built at run time: Runtime.getRuntime().exec() (directly, or through a variable assigned from Runtime.getRuntime()) whose command is a concatenation or String.format/concat with a non-constant value, a request value (getParameter, getHeader, getQueryString, getCookies, getInputStream, readLine, a @RequestParam/@PathVariable/@RequestHeader parameter), or a variable assigned from either within the 40 lines above; and a ProcessBuilder or ProcessBuilder.command() that runs a shell (sh/bash -c, cmd /c, powershell -Command), inline or through a list built with add(\"-c\"), whose script is built the same way. The enclosing method (at most 120 lines up) is read before reporting: an operand that provably holds a constant at the call is not run-time data, namely a literal or constant expression it was last assigned on every path, the taken side of an if/else or ternary whose condition folds to a constant (integer literals and int locals assigned once), the selected case of a switch on a constant, the element a list index or map key actually holds when that is a literal, and the result of a method in the same file (including a nested class) whose every return is constant. A value the analysis cannot resolve (a condition on run-time data, a call into another class, a collection filled in a loop or passed elsewhere) stays reported. Not reported: a constant command or one concatenated only from literals and UPPER_CASE constants, an exec(String[]) or ProcessBuilder argument list that does not invoke a shell (no shell parses its arguments), a command that arrives as a plain method parameter (a wrapper; its callers decide), environment arrays, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-001/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "dangerous-function"],
}

# ── Shared expression helpers ────────────────────────────────────────────

# String and char literals emptied, so a quoted "+" or "exec(" is not code.
_strip(s) := regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)'`, `''`)

_joined(lines, i, span, strip) := concat(" ", [t |
	some k in numbers.range(i, min([count(lines) - 1, i + span]))
	t := _maybe_strip(lines[k], strip)
])

_maybe_strip(l, true) := _strip(l)

_maybe_strip(l, false) := l

# The text after the call opened by `re` on line i, up to the first `;`,
# over up to four lines (a call broken across lines).
_after(text, re) := a if {
	m := regex.find_all_string_submatch_n(concat("", [re, `([^;]*)`]), text, 1)
	count(m) > 0
	a := m[0][count(m[0]) - 1]
}

_const_ident(id) if regex.match(`^(?:\w+\.)*[A-Z][A-Z0-9_]*$`, id)

_const_ident(id) if id in {"true", "false", "null"}

_nonconst_operand(")")

_nonconst_operand(id) if {
	id != ")"
	not _const_ident(id)
}

# A `+` with a non-literal, non-constant operand on either side.
_nonconst_concat(expr) if {
	s := regex.replace(expr, `\+\+|\+=`, " ")
	contains(s, "+")
	some m in regex.find_all_string_submatch_n(`\+\s*([A-Za-z_][\w.]*)|([A-Za-z_][\w.]*|\))\s*\+`, s, -1)
	_nonconst_operand(concat("", [m[1], m[2]]))
}

_formats(expr) if regex.match(`\b(?:String|MessageFormat)\.format\s*\([^)]*,\s*[A-Za-z_(]|\.formatted\s*\(\s*[A-Za-z_]|\.concat\s*\(\s*[A-Za-z_]`, expr)

_kw := {"new", "null", "true", "false", "this", "super", "return", "instanceof", "final"}

# Local names an expression reads (not fields after a dot, not calls).
_idents(expr) := {v |
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w."'])([a-z_]\w*)(\s*\()?`, expr, -1)
	m[2] == ""
	v := m[1]
	not v in _kw
}

_src_re := `\b(?:getParameter(?:Values|Map)?|getHeaders?|getQueryString|getCookies|getInputStream|getReader|getPathInfo|readLine|nextLine)\s*\(`

_param_re := `@(?:RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue|QueryParam|PathParam|FormParam|HeaderParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w.]+(?:<[^>]*>)?(?:\[\])?\s+`

_win(i) := max([0, i - 40])

# The right-hand side of an assignment to v on line j (up to `;`).
_rhs(lines, j, v) := r if {
	pat := concat("", [`(?:^|[^\w.])`, v, `\s*(?:\[\s*\])?\s*\+?=\s*([^=;][^;]*|$)`])
	regex.match(pat, _strip(lines[j]))
	not helpers.is_comment_line(lines[j])
	r := _after(_joined(lines, j, 6, true), concat("", [`(?:^|[^\w.])`, v, `\s*(?:\[\s*\])?\s*\+?=`]))
}

# v holds a request value: assigned from a source, or an annotated parameter.
_src_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	regex.match(_src_re, _rhs(lines, j, v))
}

_src_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i)
	contains(lines[j], v)
	regex.match(concat("", [_param_re, v, `\b`]), _strip(lines[j]))
}

# v holds run-time built text or a request value.
_tainted(lines, i, v) if _src_tainted(lines, i, v)

_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	_dynamic(r)
}

_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	some w in _idents(r)
	w != v
	_src_tainted(lines, j, w)
}

# cmd += value: appending a non-constant builds the text at run time.
_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], "+=")
	contains(lines[j], v)
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, v, `\s*\+=\s*([^;]*)`]), _strip(lines[j]), 1)
	count(m) > 0
	_nonconst_concat(concat("", ["x + ", m[0][1]]))
}

_dynamic(e) if _nonconst_concat(e)

_dynamic(e) if _formats(e)

_dynamic(e) if regex.match(_src_re, e)

_bad(_, _, a) if _dynamic(a)

_bad(lines, i, a) if {
	some v in _idents(a)
	_tainted(lines, i, v)
}

# ── Rule-specific ────────────────────────────────────────────────────────

_shell_re := `(?i)"(?:/usr)?(?:/bin/)?(?:ba|z|k|da)?sh"\s*,\s*"-c"|"(?:[\w:\\]*\\)?cmd(?:\.exe)?"\s*,\s*"/c"|"(?:pwsh|powershell)(?:\.exe)?"\s*,\s*"-(?:c|command)"`

_exec_re := `(?:Runtime\.getRuntime\(\)|\b[a-z_]\w*)\s*\.exec\s*\(`

_runtime_vars(lines) := {v |
	some l in lines
	contains(l, "Runtime.getRuntime()")
	some m in regex.find_all_string_submatch_n(`\b([a-z_]\w*)\s*=\s*Runtime\.getRuntime\(\)\s*;`, l, -1)
	v := m[1]
}

_is_runtime_exec(line, _) if regex.match(`Runtime\.getRuntime\(\)\s*\.exec\s*\(`, line)

_is_runtime_exec(line, rvars) if {
	some m in regex.find_all_string_submatch_n(`\b([a-z_]\w*)\s*\.exec\s*\(`, line, -1)
	m[1] in rvars
}

# exec(...) with a dynamic command. A String[] literal is an argument list:
# only a shell inside it parses the text.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, ".exec")
	contains(content, "Runtime")
	lines := split(content, "\n")
	rvars := _runtime_vars(lines)
	some i, line in lines
	contains(line, ".exec")
	not helpers.is_comment_line(line)
	sline := _strip(line)
	_is_runtime_exec(sline, rvars)
	a := _after(_joined(lines, i, 4, true), _exec_re)
	_exec_reportable(lines, i, a)
	_exec_reportable(lines, i, helpers.flow_fold(a, i, helpers.flow_consts(lines, i)))
	finding := _finding(path, i, line, "Runtime.exec() runs a command built from run-time data; pass a fixed program and an argument list (ProcessBuilder) and validate every argument against an allowlist")
}

_exec_reportable(lines, i, a) if {
	not regex.match(`^\s*new\s+String\s*\[\s*\]`, a)
	_bad(lines, i, a)
}

_exec_reportable(lines, i, a) if {
	regex.match(`^\s*new\s+String\s*\[\s*\]`, a)
	regex.match(_shell_re, _after(_joined(lines, i, 4, false), `\.exec\s*\(`))
	_bad(lines, i, a)
}

# ProcessBuilder / command() that runs a shell with a built script.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "ProcessBuilder")
	regex.match(`(?i)"(?:-c|/c|-command)"`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`new\s+ProcessBuilder\s*\(|\.command\s*\(`, line)
	not helpers.is_comment_line(line)
	raw := _after(_joined(lines, i, 4, false), `(?:new\s+ProcessBuilder|\.command)\s*\(`)
	regex.match(_shell_re, raw)
	a := _after(_joined(lines, i, 4, true), `(?:new\s+ProcessBuilder|\.command)\s*\(`)
	_bad(lines, i, a)
	_bad(lines, i, helpers.flow_fold(a, i, helpers.flow_consts(lines, i)))
	finding := _finding(path, i, line, "ProcessBuilder runs a shell with a script built from run-time data; run the program directly with an argument list and validate every argument against an allowlist")
}

# A list that a shell -c will run: list.add("sh"); list.add("-c");
# list.add("echo " + param); new ProcessBuilder(list) / pb.command(list).
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "ProcessBuilder")
	regex.match(`(?i)\.add\s*\(\s*"(?:-c|/c|-command)"\s*\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(?:new\s+ProcessBuilder|\.command)\s*\(\s*([a-z_]\w*)\s*\)`, line, 1)
	count(m) > 0
	lst := m[0][1]
	_shell_list(lines, i, lst)
	_shell_list_live(lines, i, lst, helpers.flow_consts(lines, i))
	finding := _finding(path, i, line, "ProcessBuilder runs a shell with a script built from run-time data; run the program directly with an argument list and validate every argument against an allowlist")
}

_shell_list(lines, i, lst) if {
	some j in numbers.range(_win(i), i - 1)
	regex.match(concat("", [`\b`, lst, `\.add\s*\(\s*"(?i:-c|/c|-command)"\s*\)`]), lines[j])
	some k in numbers.range(_win(i), i - 1)
	contains(lines[k], lst)
	not helpers.is_comment_line(lines[k])
	a := _after(_strip(lines[k]), concat("", [`\b`, lst, `\.add\s*\(`]))
	_bad(lines, k, a)
}

# The same list, with operands that hold a constant at the call folded away.
_shell_list_live(lines, i, lst, consts) if {
	some k in numbers.range(_win(i), i - 1)
	contains(lines[k], lst)
	not helpers.is_comment_line(lines[k])
	a := _after(_strip(lines[k]), concat("", [`\b`, lst, `\.add\s*\(`]))
	_bad(lines, k, helpers.flow_fold(a, k, consts))
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
