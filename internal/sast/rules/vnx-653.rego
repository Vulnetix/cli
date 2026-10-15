# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_653

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-653",
	"name": "Improper Isolation or Compartmentalization",
	"description": "Untrusted content is given a boundary that does not isolate it (CWE-653). Python: exec() or eval() of a non-literal code argument whose globals replace __builtins__ with {}, None or a hand-picked dict, inline, as dict(__builtins__={...}), or through a globals name assigned that way in the same file, including a call broken after its parenthesis; stripping builtins is not a sandbox (object.__subclasses__() and frame walking reach everything), so the code runs with the interpreter's full privileges. JavaScript/TypeScript, in files that import electron: webPreferences that turn the renderer boundary off, contextIsolation: false, nodeIntegration: true, nodeIntegrationInSubFrames: true, nodeIntegrationInWorker: true or sandbox: false (quoted keys too), which give page script (and any XSS in it) Node.js and the preload's privileges. Not reported: exec/eval of a string literal, globals that keep the real __builtins__, code run in a separate process, the secure Electron values, sandbox: false outside an electron file (payment SDK modes), comments and string literals. Arbitrary exec/eval of non-constant code is VNX-PY-002 and vm.* is VNX-NODE-002.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-653/",
	"languages": ["python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [653],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["sandbox", "isolation", "electron", "cwe-653"],
}

_strip(line) := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`(?:[^`\\\\]|\\\\.)*`", `""`)

# ── Python: exec/eval with stripped builtins ──────────────────────────────

_call_re := `(?:^|[^\w.]|builtins\.)(?:exec|eval)\s*\(\s*([^\s])`

_restricted_names(lines) := {g |
	some l in lines
	contains(l, "__builtins__")
	not helpers.is_comment_line(l)
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:=\s*\{.*["']__builtins__["']\s*:\s*(?:\{|None\b|dict\()|=\s*dict\(.*\b__builtins__\s*=\s*(?:\{|None\b|dict\()|\[\s*["']__builtins__["']\s*\]\s*=\s*(?:\{|None\b|dict\())`, l, 1)
	count(m) > 0
	g := m[0][1]
}

_py_restricted_call(lines, i, _) if {
	window := concat("\n", [lines[j] | some j in numbers.range(i, min([count(lines) - 1, i + 2]))])
	regex.match(`["']__builtins__["']\s*:\s*(?:\{|None\b|dict\()|\bdict\(\s*__builtins__\s*=\s*(?:\{|None\b|dict\()`, window)
}

_py_restricted_call(lines, i, names) if {
	window := concat("\n", [lines[j] | some j in numbers.range(i, min([count(lines) - 1, i + 2]))])
	some g in names
	regex.match(concat("", [`,\s*`, g, `\b`]), window)
}

_call_open := `(?:^|[^\w.]|builtins\.)(?:exec|eval)\s*\(\s*$`

# The code argument starts on the call line ...
_code_arg_not_literal(lines, i, line) if {
	m := regex.find_all_string_submatch_n(_call_re, _strip(line), 1)
	count(m) > 0
	not m[0][1] in {"\"", "'"}
}

# ... or on the next line when the call breaks after its parenthesis.
_code_arg_not_literal(lines, i, line) if {
	regex.match(_call_open, _strip(line))
	i + 1 < count(lines)
	nxt := trim_left(lines[i + 1], " \t")
	nxt != ""
	not substring(nxt, 0, 1) in {"\"", "'"}
	not startswith(nxt, "#")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "__builtins__")
	regex.match(`(?:exec|eval)\s*\(`, content)
	lines := split(content, "\n")
	names := _restricted_names(lines)
	some i, line in lines
	regex.match(`(?:exec|eval)\s*\(`, line)
	not helpers.is_comment_line(line)
	_code_arg_not_literal(lines, i, line)
	_py_restricted_call(lines, i, names)
	finding := _finding(path, i, line, "exec/eval with a stripped __builtins__ is not a sandbox: the code can recover every builtin and run with the process's privileges. Run untrusted code in a separate, unprivileged process or use a real expression parser")
}

# ── Electron: renderer isolation turned off ──────────────────────────────

_js_ext := {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}

_electron_off := `\b(?:contextIsolation['"]?\s*:\s*false|nodeIntegration['"]?\s*:\s*true|nodeIntegrationInSubFrames['"]?\s*:\s*true|nodeIntegrationInWorker['"]?\s*:\s*true|sandbox['"]?\s*:\s*false)\b`

# The same with quoted keys removed, for the string-literal check.
_unquote_keys(line) := regex.replace(line, `['"](contextIsolation|nodeIntegration|nodeIntegrationInSubFrames|nodeIntegrationInWorker|sandbox)['"](\s*:)`, "$1$2")

findings contains finding if {
	some path, content in input.file_contents
	some ext in _js_ext
	endswith(path, ext)
	regex.match(`require\(\s*['"]electron['"]\s*\)|from\s+['"]electron['"]`, content)
	regex.match(_electron_off, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_electron_off, line)
	not helpers.is_comment_line(line)
	regex.match(_electron_off, _strip(_unquote_keys(line)))
	finding := _finding(path, i, line, "Electron webPreferences turn renderer isolation off: page script (and any XSS in it) reaches Node.js or the preload's privileges. Keep contextIsolation and sandbox on and nodeIntegration off")
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
