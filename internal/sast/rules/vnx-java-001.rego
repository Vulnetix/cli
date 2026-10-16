package vulnetix.rules.vnx_java_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-001",
	"name": "Command injection via Runtime.exec() or a shell ProcessBuilder",
	"description": "Reports a Java OS command whose text is built at run time: Runtime.getRuntime().exec() (directly, or through a variable assigned from Runtime.getRuntime()) whose command is a concatenation or String.format/concat with a non-constant value, a request value (getParameter, getHeader, getQueryString, getCookies, getInputStream, readLine, a @RequestParam/@PathVariable/@RequestHeader parameter), or a variable assigned from either within the 40 lines above; and a ProcessBuilder or ProcessBuilder.command() that runs a shell (sh/bash -c, cmd /c, powershell -Command), inline or through a list built with add(\"-c\"), whose script is built the same way. The enclosing method (at most 120 lines up) is read before reporting: an operand that provably holds a constant at the call is not run-time data, namely a literal or constant expression it was last assigned on every path, the taken side of an if/else or ternary whose condition folds to a constant (integer literals and int locals assigned once), the selected case of a switch on a constant, the element a list index or map key actually holds when that is a literal, and the result of a method in the same file (including a nested class) whose every return is constant. A value the analysis cannot resolve (a condition on run-time data, a call into another class that is handed a run-time value, a collection filled in a loop or passed elsewhere) stays reported. Also reported: Runtime.exec(cmd, envp[, dir]) whose environment array (a String[] local or an inline array) carries a request value, since one attacker-chosen entry such as LD_PRELOAD, PATH or BASH_ENV changes what the child runs; and a shell started through an argument array held in a local (String[] args = {a1, a2, ...} handed to new ProcessBuilder(args), pb.command(args) or exec(args), where the first two elements are a shell and its flag, directly or through locals assigned as literals on any branch) when a later element carries a request value or a non-constant operand. A call into code the analysis cannot see is read as inert, and its value is constant, when it is not named like a source (read*, next*, getParameter*, getHeader*, getCookie*, getenv, getProperty, query, execute), every argument is a constant, and its receiver is a type name, a new expression with constant arguments, or a local built from such a call that is only ever called with constant arguments; a call handed a run-time argument, made on a run-time receiver or named like a source stays reported. Not reported: a constant command or one concatenated only from literals and UPPER_CASE constants, an exec(String[]) or ProcessBuilder argument list that does not invoke a shell (no shell parses its arguments), a command that arrives as a plain method parameter (a wrapper; its callers decide), comments and string literals. Calls into other classes of the project are read from that class's own source (a method summary one level deep, overloads told apart by arity, an interface or base type joined over its project subclasses): a call whose every return is constant is constant, a call that returns a function of its arguments or of the constructor argument its receiver was built with is exactly as tainted as that argument, and an opaque method (it reads a request value, or a field a setter changes), a simple class name declared by two files, a class outside the project or a type with an anonymous subclass stays reported. exec(args) where args is a String[] local is judged by the argument-array rule alone, not as a command string. A call chain of constant operands nested up to four deep (new String(decode(encode(name.getBytes())))) is folded as constant.",
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
	_exec_reportable(lines, i, helpers.flow_fold(helpers.flow_xrw(lines, i, a), i, helpers.flow_consts(lines, i)))
	finding := _finding(path, i, line, "Runtime.exec() runs a command built from run-time data; pass a fixed program and an argument list (ProcessBuilder) and validate every argument against an allowlist")
}

_exec_reportable(lines, i, a) if {
	not regex.match(`^\s*new\s+String\s*\[\s*\]`, a)
	not _argv_local_cmd(lines, i, a)
	_bad(lines, i, a)
}

# exec(args) where args is a String[] local: no shell parses an argument array
# unless its first two elements are one, and the argument-array rule below
# reads exactly that (with the elements followed through the method).
_argv_local_cmd(lines, i, a) if {
	m := regex.find_all_string_submatch_n(`^\s*([a-z_]\w*)\s*[,)]`, a, 1)
	count(m) > 0
	some k in helpers.span(_fstart(lines, i), i - 1)
	regex.match(concat("", [`\bString\s*\[\s*\]\s+`, m[0][1], `\b|\bString\s+`, m[0][1], `\s*\[\s*\]`]), lines[k])
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
	_bad(lines, i, helpers.flow_fold(helpers.flow_xrw(lines, i, a), i, helpers.flow_consts(lines, i)))
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
	_bad(lines, k, helpers.flow_fold(helpers.flow_xrw(lines, k, a), k, consts))
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

# ── Environment arrays and argument arrays held in locals ───────────────
# Runtime.exec(cmd, envp[, dir]) hands the environment to the child: one
# attacker-chosen entry is LD_PRELOAD, PATH or BASH_ENV. And a shell started
# through an argument array held in a local (String[] args = {a1, a2, ...})
# parses the element after "-c" however the array was filled. Both are read
# from the method with the shared in-method flow, so a request value that
# reaches an element through locals, collections or a helper called with it
# is followed, and a value that provably holds a constant is not.

_req_src_re := `\.get\w*Parameter\w*\s*\(|\.(?:getHeaders?|getQueryString|getPathInfo|getRequestURI|getCookies|getInputStream|getReader)\s*\(|\b\w*[Cc]ookie\.getValue\s*\(|\b(?:readLine|nextLine)\s*\(`

_req_not_src_re := `\.get(?:Init|Type|Generic|Context|Servlet)\w*Parameter\w*\s*\(`

_req_src(s) if {
	regex.match(_req_src_re, s)
	regex.match(_req_src_re, regex.replace(s, _req_not_src_re, ""))
}

_num_san_re := `Integer\.parseInt\s*\(|Long\.parseLong\s*\(`

_fstart(lines, i) := max([0, helpers.flow_method_start(lines, i) - 1])

_fassigned(line) := v if {
	s := regex.replace(line, `^\s*(?:\}\s*)?(?:else\s+)?(?:if\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*)?`, "")
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?(?:[\w.]+(?:<[^=;]*>)?(?:\[\])*\s+)?(\w+)\s*(?:\+=|=(?:[^=]|$))`, s, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"if", "return", "else", "case", "this"}
}

_ftext(lines, j) := lines[j] if regex.match(`;\s*$`, lines[j])

_ftext(lines, j) := concat(" ", [lines[k] | some k in numbers.range(j, e)]) if {
	not regex.match(`;\s*$`, lines[j])
	last := min([count(lines) - 1, j + 6])
	ends := [k | some k in numbers.range(j, last); regex.match(`;\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

_fseeds(lines, i) := {v |
	some j in numbers.range(_fstart(lines, i), i - 1)
	not helpers.is_comment_line(lines[j])
	v := _fassigned(lines[j])
	_req_src(_ftext(lines, j))
} | {m[1] |
	some j in numbers.range(_fstart(lines, i), i)
	contains(lines[j], "@")
	not helpers.is_comment_line(lines[j])
	some m in regex.find_all_string_submatch_n(concat("", [_param_re, `(\w+)`]), _strip(lines[j]), -1)
}

# The text carries a request value: read directly, or through the method.
_fdirty(_, _, text) if _req_src(text)

_fdirty(lines, i, text) if {
	seeds := _fseeds(lines, i) | helpers.flow_carrier_seeds(lines, i, _req_src_re)
	helpers.flow_reaches(lines, i, text, seeds, _num_san_re)
}

# Top-level comma separated pieces of an argument or element list.
_pieces(s) := [trim_space(m[0]) |
	some m in regex.find_all_string_submatch_n(`(?:"(?:[^"\\]|\\.)*"|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\{[^{}]*\}|[^,"(){}])+`, s, -1)
]

# exec(cmd, envp[, dir]) with a request value in the environment.
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
	_is_runtime_exec(_strip(line), rvars)
	a := _after(_joined(lines, i, 4, true), _exec_re)
	ps := _pieces(_exec_args(a))
	count(ps) >= 2
	not regex.match(`^\s*new\s+String\s*\[\s*\]`, ps[0])
	_fdirty(lines, i, ps[1])
	finding := _finding(path, i, line, "Runtime.exec() passes a request value in the child's environment (LD_PRELOAD, PATH, BASH_ENV); build the environment from fixed names and validated values")
}

# The argument list of the call whose opening bracket `_after` consumed: the
# text up to its closing bracket.
_exec_args(a) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*)\)`, a, 1)
	count(m) > 0
} else := a

# A shell started through an argument array held in a local.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`ProcessBuilder|\.exec\s*\(`, content)
	regex.match(`(?i)"(?:-c|/c|-command)"|=\s*"(?:-c|/c|-command)"`, content)
	lines := split(content, "\n")
	rvars := _runtime_vars(lines)
	some i, line in lines
	not helpers.is_comment_line(line)
	arr := _argv_local(line, rvars)
	defs := _argv_defs(lines, i, arr)
	count(defs) > 0
	some d in defs
	_argv_shell(lines, i, d)
	_argv_live(lines, i, d)
	finding := _finding(path, i, line, "A shell is started with a script built from run-time data; run the program directly with an argument list and validate every argument against an allowlist")
}

_argv_local(line, _) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`(?:new\s+ProcessBuilder|\.command)\s*\(\s*([a-z_]\w*)\s*\)`, line, 1)
	count(m) > 0
}

_argv_local(line, rvars) := m[0][1] if {
	_is_runtime_exec(_strip(line), rvars)
	m := regex.find_all_string_submatch_n(`\.exec\s*\(\s*([a-z_]\w*)\s*[,)]`, line, 1)
	count(m) > 0
}

# The element lists of every array literal assigned to arr above line i.
_argv_defs(lines, i, arr) := [_pieces(m[0][1]) |
	some j in numbers.range(_fstart(lines, i), i - 1)
	contains(lines[j], arr)
	not helpers.is_comment_line(lines[j])
	t := _ftext(lines, j)
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, arr, `\s*=\s*(?:new\s+String\s*\[\s*\]\s*)?\{(.*)\}\s*;`]), t, 1)
	count(m) > 0
]

# The literal values a shell/flag element can hold: itself, or what a local
# of that name is assigned as a plain string literal above.
_lit_vals(_, _, tok) := {substring(t, 1, count(t) - 2)} if {
	t := trim_space(tok)
	regex.match(`^"[^"\\]*"$`, t)
}

_lit_vals(lines, i, tok) := {m[0][1] |
	some j in numbers.range(_fstart(lines, i), i - 1)
	contains(lines[j], tok)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:[\w.]+\s+)?`, trim_space(tok), `\s*=\s*"([^"\\]*)"\s*;`]), lines[j], 1)
	count(m) > 0
} if regex.match(`^[a-z_]\w*$`, trim_space(tok))

_argv_shell(lines, i, d) if {
	count(d) >= 3
	some p in _lit_vals(lines, i, d[0])
	regex.match(`(?i)^(?:(?:/usr)?(?:/bin/)?(?:ba|z|k|da)?sh|(?:[\w:\\]*\\)?cmd(?:\.exe)?|(?:pwsh|powershell)(?:\.exe)?)$`, p)
	some q in _lit_vals(lines, i, d[1])
	regex.match(`(?i)^(?:-c|/c|-command)$`, q)
}

# An element after the shell flag carries a request value or is built from a
# non-constant operand.
_argv_live(lines, i, d) if {
	some k in numbers.range(2, count(d) - 1)
	e := d[k]
	_fdirty(lines, i, e)
}

_argv_live(lines, i, d) if {
	some k in numbers.range(2, count(d) - 1)
	e := _strip(d[k])
	_bad(lines, i, e)
	_bad(lines, i, helpers.flow_fold(helpers.flow_xrw(lines, i, e), i, helpers.flow_consts(lines, i)))
}
