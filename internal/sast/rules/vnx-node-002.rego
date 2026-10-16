package vulnetix.rules.vnx_node_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-002",
	"name": "eval() or new Function() in JavaScript",
	"description": "Dynamic code evaluation in JavaScript/TypeScript with an argument that is not a constant: eval(x) (also window./globalThis./global.eval), new Function(...) or Function(...) whose parameter or body list contains anything other than string literals, vm.runInNewContext/runInThisContext/runInContext/compileFunction and new vm.Script with a non-literal source, and setTimeout/setInterval given a code string built by concatenation or template-literal interpolation. If any part of the code is user-controlled this is remote code execution. Not reported: eval or Function over string literals only (bundler escape hatches such as eval(\"require('x')\")), a method that happens to be called eval or evaluate (redis.eval, page.evaluate, mathjs evaluate), the pattern inside a string literal or comment, declarations (declare function eval), timers given a function, minified files and lines longer than 400 characters, and evaluators whose argument carries Express/Koa request data (directly or through a variable assigned or destructured from it), which are reported by VNX-94.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-002/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-35"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["code-injection", "dangerous-function"],
}

_is_js(path) if regex.match(`\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$`, path)

_file_gate := `(?m)(?:\beval\s*\)?\s*\(|\bFunction\s*\(|\bvm\.|(?:setTimeout|setInterval)\s*\(\s*['"\x60])`

# A template literal with interpolation becomes the identifier TPLX (it is an
# expression); every other string literal collapses to "" so a sink spelled
# inside one disappears and a constant argument is recognisable.
_strip(line) := regex.replace(
	regex.replace(line, `\x60(?:[^\x60\\]|\\.)*\$\{(?:[^\x60\\]|\\.)*\x60`, "TPLX"),
	`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60`, `""`,
)

_sinks := [
	{"re": `(?:^|[^\w$.])(?:(?:window|globalThis|global|self)\.)?eval\s*\((.*)$`, "what": "eval()", "stop": `[,)].*$`},
	{"re": `(?:^|[^\w$.])(?:new\s+)?Function\s*\((.*)$`, "what": "Function constructor", "stop": `\).*$`},
	{"re": `\(\s*0\s*,\s*(?:(?:window|globalThis|global|self)\.)?eval\s*\)\s*\((.*)$`, "what": "indirect eval()", "stop": `[,)].*$`},
	{"re": `(?:^|[^\w$.])vm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\((.*)$`, "what": "vm code execution", "stop": `[,)].*$`},
	{"re": `(?:^|[^\w$.])new\s+vm\.Script\s*\((.*)$`, "what": "vm.Script", "stop": `[,)].*$`},
]

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(_file_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) <= 400
	regex.match(`eval|Function|vm\.`, line)
	not helpers.is_comment_line(line)
	s := _strip(line)
	some sink in _sinks
	m := regex.find_all_string_submatch_n(sink.re, s, 1)
	count(m) > 0
	not regex.match(`\bfunction\s+eval\b`, s)
	_dynamic(_arg(lines, i, m[0][1]), sink.stop)
	not _vnx94_reports(path, content, lines, i, line)
	finding := _finding(path, i, line, sprintf("%s with a non-constant argument executes generated code; if any part is user-controlled this is code injection. Parse data (JSON.parse) or use a safe evaluator instead", [sink.what]))
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(_file_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) <= 400
	regex.match(`set(?:Timeout|Interval)\s*\(\s*['"\x60]`, line)
	not helpers.is_comment_line(line)
	s := _strip(line)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w$.])(?:window\.)?(?:setTimeout|setInterval)\s*\((.*)$`, s, 1)
	count(m) > 0
	regex.match(`^\s*(?:""\s*\+|TPLX)`, m[0][1])
	not _vnx94_reports(path, content, lines, i, line)
	finding := _finding(path, i, line, "setTimeout/setInterval with a code string built from variables is evaluated like eval(); pass a function instead")
}

# vm functions bound by destructuring: const { runInNewContext } = require("vm")
# or import { runInContext } from "node:vm". Only names the file binds from vm.
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(`(?:require\(\s*['"](?:node:)?vm['"]\s*\)|from\s+['"](?:node:)?vm['"])`, content)
	some name in ["runInNewContext", "runInThisContext", "runInContext", "compileFunction"]
	contains(content, name)
	regex.match(sprintf(`\{[^}]*\b%s\b[^}]*\}\s*(?:=\s*require\(\s*['"](?:node:)?vm['"]|from\s+['"](?:node:)?vm['"])`, [name]), content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) <= 400
	contains(line, name)
	not helpers.is_comment_line(line)
	s := _strip(line)
	m := regex.find_all_string_submatch_n(sprintf(`(?:^|[^\w$.])%s\s*\((.*)$`, [name]), s, 1)
	count(m) > 0
	_dynamic(_arg(lines, i, m[0][1]), `[,)].*$`)
	not _vnx94_reports(path, content, lines, i, line)
	finding := _finding(path, i, line, "vm code execution with a non-constant argument executes generated code; vm is not a security sandbox, so user-controlled code here is code injection")
}

# The argument text: the rest of the line, or the next line when the call
# breaks right after its opening parenthesis.
_arg(lines, i, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := _strip(lines[i + 1]) if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

# Up to the end of the argument(s) the sink compiles (the first argument for
# eval and vm, every argument for Function), anything but string literals,
# commas and whitespace is an expression.
_dynamic(arg, stop) if {
	head := regex.replace(arg, stop, "")
	regex.match(`[\w$]`, regex.replace(head, `""`, ""))
}

# ── Lines VNX-94 owns ────────────────────────────────────────────────────
# An evaluator whose argument carries Express/Koa request data is code
# injection and is reported by VNX-94, so the line is not reported a second
# time here. This mirrors the JavaScript branch of VNX-94 exactly; keep the
# two in step when either changes.
_v94_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies|signedCookies)\b|\bctx\.(?:query|params|request\.body|request\.query)\b`

_v94_gate := `eval|Function|vm\.|setTimeout|setInterval`

_v94_sinks := [
	{"gate": `(?:^|[^\w.$])(?:(?:window|globalThis|global)\.)?eval\s*\(`, "arg": `(?:^|[^\w.$])(?:(?:window|globalThis|global)\.)?eval\s*\((.*)$`, "timer": false},
	{"gate": `\bnew\s+Function\s*\(|(?:^|[^\w.$])Function\s*\(`, "arg": `\bFunction\s*\((.*)$`, "timer": false},
	{"gate": `\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(`, "arg": `\bvm\.\w+\s*\((.*)$`, "timer": false},
	{"gate": `\bnew\s+vm\.Script\s*\(`, "arg": `\bvm\.Script\s*\((.*)$`, "timer": false},
	{"gate": `(?:^|[^\w.$])set(?:Timeout|Interval)\s*\(`, "arg": `\bset(?:Timeout|Interval)\s*\((.*)$`, "timer": true},
]

_v94_sanitised := `\bintval\s*\(|\(int\)|\bparseInt\s*\(|\bparseFloat\s*\(|\bNumber\s*\(|(?:^|[^\w.])(?:int|float)\s*\(|\bInteger\s*\(|\bFloat\s*\(|\.to_[if]\b|\bliteral_eval\s*\(|\babs\s*\(`

_v94_assign_re := `^\s*(?:(?:final|var|let|const|val|my|local)\s+)?(?:[A-Za-z_][\w<>\[\]\.?]*\s+)?\$?([A-Za-z_]\w*)\s*(?:,\s*\$?[A-Za-z_]\w*\s*)*(?::\s*[\w<>\[\]\|\. ]+?\s*)?(?::=|\.=|\+=|=)[^=~>]`

_v94_guard_re := `\bin_array\s*\(|\barray_key_exists\s*\(|\bpreg_match\s*\(|\.includes\s*\(|\.include\?\s*\(|\.has\s*\(|\bin\s+[A-Z_][A-Z0-9_]+\b|\bfullmatch\s*\(|\bre\.match\s*\(`

_v94_blank(line) := regex.replace(regex.replace(line, `"(?:\\.|[^"\\])*"`, `""`), `'(?:\\.|[^'\\])*'`, `''`)

_v94_plain_blank(l) := regex.replace(l, `(^|[^\w])("(?:\\.|[^"\\#$])*"|'(?:\\.|[^'\\])*')`, `$1""`)

_v94_destructured(line) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	pieces := split(trim_space(part), ":")
	v := trim_left(trim_space(pieces[count(pieces) - 1]), ".")
	regex.match(`^[A-Za-z_]\w*$`, v)
}

_v94_names(line) := {v |
	m := regex.find_all_string_submatch_n(_v94_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
} | _v94_destructured(line)

_v94_t1(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(_v94_src, l)
	not helpers.is_comment_line(l)
	not regex.match(_v94_sanitised, l)
	some v in _v94_names(l)
}

_v94_t2(lines, i, n1) := {v |
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	some v in _v94_names(l)
	not v in n1
	some n in n1
	regex.match(concat("", [`=.*\b`, n, `\b`]), _v94_plain_blank(l))
	not helpers.is_comment_line(l)
	not regex.match(_v94_sanitised, l)
}

_v94_guarded(lines, i, n) if {
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	regex.match(_v94_guard_re, l)
	regex.match(concat("", [`\b`, n, `\b`]), l)
	not helpers.is_comment_line(l)
}

_v94_tainted(lines, i, arg) if regex.match(_v94_src, arg)

_v94_tainted(lines, i, arg) if {
	not regex.match(_v94_src, arg)
	n1 := _v94_t1(lines, i)
	some n in n1 | _v94_t2(lines, i, n1)
	regex.match(concat("", [`\b`, n, `\b`]), arg)
	not _v94_guarded(lines, i, n)
}

_v94_continues(rest) if regex.match(`[,(+.]\s*$`, rest)

_v94_arg_text(lines, i, rest) := rest if {
	trim_space(rest) != ""
	not _v94_continues(rest)
}

_v94_arg_text(lines, i, rest) := concat(" ", array.concat([rest], array.slice(lines, i + 1, i + 3))) if {
	trim_space(rest) != ""
	_v94_continues(rest)
}

_v94_arg_text(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_v94_skip(sink, arg) if {
	sink.timer
	regex.match(`^\s*(?:function\b|async\b|\(|[A-Za-z_$][\w$]*\s*=>)`, arg)
}

_vnx94_reports(path, content, lines, i, line) if {
	regex.match(`\.(?:js|jsx|ts|tsx|mjs|cjs)$`, path)
	regex.match(_v94_gate, content)
	regex.match(concat("", ["(?m)", _v94_src]), content)
	regex.match(_v94_gate, line)
	code := _v94_blank(line)
	some sink in _v94_sinks
	regex.match(sink.gate, code)
	m := regex.find_all_string_submatch_n(sink.arg, line, 1)
	count(m) > 0
	arg := _v94_arg_text(lines, i, m[0][1])
	not _v94_skip(sink, arg)
	not regex.match(_v94_sanitised, arg)
	_v94_tainted(lines, i, arg)
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
