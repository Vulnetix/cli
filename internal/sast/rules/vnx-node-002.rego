package vulnetix.rules.vnx_node_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-002",
	"name": "eval() or new Function() in JavaScript",
	"description": "Dynamic code evaluation in JavaScript/TypeScript with an argument that is not a constant: eval(x) (also window./globalThis./global.eval), new Function(...) or Function(...) whose parameter or body list contains anything other than string literals, vm.runInNewContext/runInThisContext/runInContext/compileFunction and new vm.Script with a non-literal source, and setTimeout/setInterval given a code string built by concatenation or template-literal interpolation. If any part of the code is user-controlled this is remote code execution. Not reported: eval or Function over string literals only (bundler escape hatches such as eval(\"require('x')\")), a method that happens to be called eval or evaluate (redis.eval, page.evaluate, mathjs evaluate), the pattern inside a string literal or comment, declarations (declare function eval), timers given a function, minified files and lines longer than 400 characters.",
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

_file_gate := `(?m)(?:\beval\s*\(|\bFunction\s*\(|\bvm\.|(?:setTimeout|setInterval)\s*\(\s*['"\x60])`

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
	finding := _finding(path, i, line, "setTimeout/setInterval with a code string built from variables is evaluated like eval(); pass a function instead")
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

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
