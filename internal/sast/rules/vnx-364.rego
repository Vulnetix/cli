# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_364

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-364",
	"name": "Signal Handler Race Condition",
	"description": "A function registered as a signal handler in the same C or C++ file (signal(SIG..., h), std::signal, sigset, or a struct sigaction whose sa_handler/sa_sigaction is h, assigned or in a designated initializer, or a captureless C++ lambda registered in place such as std::signal(SIGTERM, [](int) { ... }); the handler may be defined with its name at column 0, BSD style) writes to a file-scope variable that is not declared volatile sig_atomic_t or atomic (_Atomic, atomic_*, std::atomic): an assignment, increment, compound assignment, a write to a member or element of it, or free() of it. The signal can arrive while the interrupted code is half way through using the same variable, so the handler corrupts it (a pointer freed under the main loop and freed again, a counter update lost, a struct reset mid-read). Not reported: writes to volatile sig_atomic_t or atomic globals, locals and parameters of the handler (also one that shadows a global's name), functions that are not registered as handlers (atexit callbacks, a function only called directly), SIG_IGN/SIG_DFL, and comments. Calls to async-signal-unsafe functions such as printf or malloc in a handler are VNX-479/VNX-828, not this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-364/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [364],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["signal-race", "signal-handler", "cwe-364"],
}

_exts := {".c", ".cc", ".cpp", ".cxx"}

_handler_res := [
	`\b(?:signal|sigset|bsd_signal)\(\s*[A-Za-z_]\w*\s*,\s*&?\s*([A-Za-z_]\w*)\s*\)`,
	`\bsa_(?:handler|sigaction)\s*=\s*&?\s*([A-Za-z_]\w*)\s*[;,}]`,
]

_not_handlers := {"SIG_IGN", "SIG_DFL", "SIG_ERR", "NULL", "nullptr"}

_handlers(content) := {h |
	some re in _handler_res
	some m in regex.find_all_string_submatch_n(re, content, -1)
	h := m[1]
	not h in _not_handlers
}

_decl_re := `^(?:(?:static|extern|volatile|unsigned|signed|struct|long|short|thread_local|__thread)\s+)*([A-Za-z_][\w:]*(?:<[^;()]*>)?)(?:\s+\**\s*|\s*\*+\s*|(?:>|&)\s*)([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:=[^;]*|\{[^;]*\})?;\s*(?://.*|/\*.*)?$`

_not_types := {"return", "typedef", "goto", "using", "namespace", "delete", "throw", "case", "break", "continue"}

# File-scope variables a handler may not touch: declared at column 0, not
# const, not sig_atomic_t and not atomic.
_globals(lines) := {g |
	some l in lines
	regex.match(`^[A-Za-z_]`, l)
	endswith(trim_right(regex.replace(l, `\s*(?://.*|/\*.*)$`, ""), " \t"), ";")
	not contains(l, "(")
	not regex.match(`\bconst(?:expr)?\b|sig_atomic_t|_Atomic|\batomic|\bextern\s+"C"`, l)
	some m in regex.find_all_string_submatch_n(_decl_re, l, 1)
	not m[1] in _not_types
	g := m[2]
}

_def_line(lines, h) := d if {
	re := concat("", [`^(?:[A-Za-z_][^;=]*[\s\*&])?`, h, `\s*\([^;]*$`])
	ds := [k | some k, l in lines; contains(l, h); regex.match(re, l)]
	count(ds) > 0
	d := ds[0]
}

_body_end(lines, d) := e if {
	ends := [k | some k in numbers.range(d + 1, min([count(lines) - 1, d + 200])); startswith(lines[k], "}")]
	count(ends) > 0
	e := ends[0]
}

_writes(line, g) if regex.match(concat("", [`(?:^|[^\w\.>])`, g, `(?:\s*(?:\[[^\]]*\]|\.\w+|->\w+))*\s*(?:=[^=]|\+\+|--|[-+*/%|&^]=|<<=|>>=)`]), line)

_writes(line, g) if regex.match(concat("", [`(?:\+\+|--)\s*`, g, `\b`]), line)

_writes(line, g) if regex.match(concat("", [`\bfree\(\s*`, g, `\s*\)`]), line)

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	_gate(content)
	hs := _handlers(content)
	count(hs) > 0
	lines := split(content, "\n")
	gs := _globals(lines)
	count(gs) > 0
	some h in hs
	d := _def_line(lines, h)
	e := _body_end(lines, d)
	some i in numbers.range(d + 1, e - 1)
	line := lines[i]
	not helpers.is_comment_line(line)
	some g in gs
	contains(line, g)
	_writes(line, g)
	not _shadowed(lines, d, e, g)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Signal handler %s() writes the shared global '%s', which is not volatile sig_atomic_t or atomic: the signal can interrupt code that is using it. Only set a volatile sig_atomic_t flag in the handler and do the work in the main loop", [h, g]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A C++ lambda registered in place: std::signal(SIGTERM, [](int) { ... });
# or sa.sa_handler = [](int) { ... };. Captureless lambdas can only reach
# globals, so a write to a file-scope name in the body is the race.
_lambda_re := `(?:\bsignal\(\s*[A-Za-z_]\w*\s*,|\bsa_(?:handler|sigaction)\s*=)\s*\[\s*\]\s*\([^)]*\)\s*(?:noexcept\s*)?(?:->\s*\w+\s*)?\{(.*)$`

_indent(l) := count(l) - count(trim_left(l, " \t"))

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
	contains(content, "[]")
	_gate(content)
	lines := split(content, "\n")
	some d, dl in lines
	contains(dl, "[]")
	some lm in regex.find_all_string_submatch_n(_lambda_re, dl, 1)
	gs := _globals(lines)
	ends := [k |
		some k in numbers.range(d + 1, min([count(lines) - 1, d + 60]))
		startswith(trim_left(lines[k], " \t"), "}")
		_indent(lines[k]) <= _indent(dl)
	]
	e := _lambda_end(ends, d, lm[1])
	some i in numbers.range(d, e)
	line := _lambda_line(lines, i, d, lm[1])
	not helpers.is_comment_line(line)
	some g in gs
	contains(line, g)
	_writes(line, g)
	not _lambda_local(lines, d, e, g)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Signal handler lambda writes the shared global '%s', which is not volatile sig_atomic_t or atomic: the signal can interrupt code that is using it. Only set a volatile sig_atomic_t flag in the handler and do the work in the main loop", [g]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

# The body closes on the registration line itself.
_lambda_end(ends, d, rest) := d if contains(rest, "}")

_lambda_end(ends, d, rest) := ends[0] if {
	not contains(rest, "}")
	count(ends) > 0
}

_lambda_line(lines, i, d, rest) := rest if i == d

_lambda_line(lines, i, d, rest) := lines[i] if i != d

_lambda_local(lines, d, e, g) if {
	some k in numbers.range(d + 1, e)
	contains(lines[k], g)
	some m in regex.find_all_string_submatch_n(concat("", [`^\s+(?:(?:static|volatile|unsigned|signed|struct|const|long|short|register|auto)\s+)*([A-Za-z_][\w:]*)\s*\**\s*`, g, `\s*(?:[=;,]|\[)`]), lines[k], 1)
	not m[1] in _not_types
	not m[1] in {"else", "do", "sizeof"}
}

# A local or parameter of the handler with the global's name: writes go to
# the handler's own copy.
_shadowed(lines, d, e, g) if {
	some k in numbers.range(d, min([d + 2, e]))
	regex.match(concat("", [`[(,]\s*(?:const\s+)?[A-Za-z_][\w:]*\s*\**\s*`, g, `\s*[,)]`]), lines[k])
}

_shadowed(lines, d, e, g) if {
	some k in numbers.range(d + 1, e - 1)
	contains(lines[k], g)
	some m in regex.find_all_string_submatch_n(concat("", [`^\s+(?:(?:static|volatile|unsigned|signed|struct|const|long|short|register)\s+)*([A-Za-z_][\w:]*)\s*\**\s*`, g, `\s*(?:[=;,]|\[)`]), lines[k], 1)
	not m[1] in _not_types
	not m[1] in {"else", "do", "sizeof"}
}

_gate(content) if contains(content, "signal(")

_gate(content) if {
	not contains(content, "signal(")
	contains(content, "sa_")
}

_gate(content) if {
	not contains(content, "signal(")
	not contains(content, "sa_")
	contains(content, "sigset(")
}
