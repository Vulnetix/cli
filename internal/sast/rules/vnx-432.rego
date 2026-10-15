# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_432

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-432",
	"name": "Dangerous Signal Handler not Disabled During Sensitive Operations",
	"description": "One signal handler that does non-reentrant work is installed for two or more signals without blocking the others while it runs, in C and C++, so a second signal interrupts the handler half way through its own sensitive operation (the CWE-432 example: one handler for SIGHUP and SIGTERM that frees a global, freed twice when the signals arrive together). Reported: signal()/std::signal/sigset/bsd_signal registering the same function (plain or class-qualified, Server::OnSignal) for two or more different signals, and a struct sigaction whose sa_handler/sa_sigaction is that function (assigned, or set by a designated initialiser { .sa_handler = f }) passed to sigaction() for two or more different signals in the thirty lines after the handler is assigned (before the struct gets another handler) while its sa_mask is not filled nearby (no sigfillset or sigaddset on that struct's sa_mask); in both cases only when the handler is defined in the same file and its body calls a function that is not async-signal-safe (free, malloc, calloc, realloc, the printf family, syslog, puts, fputs, fwrite, fflush, fopen, fclose, exit, strtok, localtime, gmtime, ctime, strerror, perror, longjmp, siglongjmp, pthread_mutex_lock, system, popen) or uses new/delete or std::cout/cerr; names inside string literals in the handler do not count. The registration lines are reported. Not reported: a handler installed for one signal, a crash handler shared only between synchronous fault signals (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGTRAP, SIGSYS), a sigaction whose sa_mask blocks other signals, SIG_IGN/SIG_DFL, handlers that only set a flag or call async-signal-safe functions (write, _exit), handlers defined in another file, comments. A handler writing an unprotected global is VNX-364.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-432/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [432],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["dangerous-signal", "signal-handler", "cwe-432"],
}

_exts := {".c", ".cc", ".cpp", ".cxx"}

_not_handlers := {"SIG_IGN", "SIG_DFL", "SIG_ERR", "NULL", "nullptr"}

_signal_re := `\b(?:std::)?(?:signal|sigset|bsd_signal)\s*\(\s*(SIG[A-Z0-9]+)\s*,\s*(?:\(\s*\w+\s*\)\s*)?&?\s*(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)\s*\)`

_sa_handler_re := `\b([A-Za-z_]\w*)\s*(?:\.|->)\s*sa_(?:handler|sigaction)\s*=\s*(?:\(\s*\w+\s*\)\s*)?&?\s*([A-Za-z_]\w*)\s*;`

# struct sigaction sa = { .sa_handler = on_stop, ... }, possibly over a few lines.
_sa_init_re := `^\s*(?:static\s+)?(?:const\s+)?struct\s+sigaction\s+([A-Za-z_]\w*)\s*=\s*\{[^}]*?\.sa_(?:handler|sigaction)\s*=\s*(?:\(\s*\w+\s*\)\s*)?&?\s*([A-Za-z_]\w*)`

# [struct, handler] pairs whose handler is set on line k.
_assignments(lines, k) := {[a[1], a[2]] | some a in regex.find_all_string_submatch_n(_sa_handler_re, lines[k], -1)} | {[a[1], a[2]] |
	regex.match(`struct\s+sigaction\s+\w+\s*=`, lines[k])
	text := concat("\n", [lines[j] | some j in numbers.range(k, min([count(lines) - 1, k + 4]))])
	some a in regex.find_all_string_submatch_n(_sa_init_re, text, 1)
}

_sigaction_re :=`\bsigaction\s*\(\s*(SIG[A-Z0-9]+)\s*,\s*&\s*([A-Za-z_]\w*)\s*,`

# Code with whole-line comments removed, so a commented-out registration
# never counts.
_code(lines) := _strip_strings(helpers.code_text(lines))

_strip_strings(s) := regex.replace(s, `"(?:\\.|[^"\\\n])*"`, `""`)

# Synchronous fault signals are raised by the faulting thread itself; a crash
# handler shared between them is the conventional design, not a re-entry risk.
_fault_signals := {"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT", "SIGTRAP", "SIGSYS"}

_signal_regs(code) := [[m[1], m[2]] |
	some m in regex.find_all_string_submatch_n(_signal_re, code, -1)
	not m[2] in _not_handlers
	not m[1] in _fault_signals
]

_multi_signal_handlers(code) := {h |
	regs := _signal_regs(code)
	some r in regs
	h := r[1]
	count({s | some q in regs; q[1] == h; s := q[0]}) > 1
}

_mask_filled(code, v) if regex.match(concat("", [`\bsig(?:fill|add)set\s*\(\s*&\s*`, v, `\s*(?:\.|->)\s*sa_mask\b`]), code)

# sigaction() calls on struct v in the thirty lines after line k assigned its
# handler, up to the next handler assignment on the same struct.
_sigaction_calls(lines, k, v) := {[i, m[1]] |
	e := min([count(lines) - 1, k + 30])
	reassign := concat("", [`\b`, v, `\s*(?:\.|->)\s*sa_(?:handler|sigaction)\s*=`])
	some i in numbers.range(k + 1, e)
	contains(lines[i], "sigaction")
	not helpers.is_comment_line(lines[i])
	some m in regex.find_all_string_submatch_n(_sigaction_re, _strip_strings(lines[i]), -1)
	m[2] == v
	not m[1] in _fault_signals
	not _reassigned_between(lines, k, i, reassign)
}

_reassigned_between(lines, k, i, re) if {
	i - 1 >= k + 1
	some x in numbers.range(k + 1, i - 1)
	regex.match(re, lines[x])
}

_def_line(lines, h) := d if {
	re := concat("", [`^(?:[A-Za-z_][^;=]*[\s*&:])?`, h, `\s*\([^;]*$`])
	ds := [k | some k, l in lines; contains(l, h); regex.match(re, l)]
	count(ds) > 0
	d := ds[0]
}

_body(lines, h) := b if {
	d := _def_line(lines, h)
	ends := [k | some k in numbers.range(d + 1, min([count(lines) - 1, d + 200])); startswith(lines[k], "}")]
	count(ends) > 0
	b := _strip_strings(helpers.code_text([lines[k] | some k in numbers.range(d + 1, ends[0])]))
}

_unsafe_re := `(?:^|[^\w.>])(free|malloc|calloc|realloc|printf|fprintf|sprintf|snprintf|vprintf|vfprintf|syslog|puts|fputs|fwrite|fflush|fopen|fclose|exit|strtok|localtime|gmtime|ctime|strerror|perror|longjmp|siglongjmp|pthread_mutex_lock|system|popen)\s*\(|\b(delete)\b|\b(new)\s+[A-Za-z_]|(std::(?:cout|cerr|clog))\b`

# The first non-async-signal-safe call in the handler's body.
_unsafe_handler(lines, h) := name if {
	b := _body(lines, h)
	m := regex.find_all_string_submatch_n(_unsafe_re, b, 1)
	count(m) > 0
	name := concat("", [m[0][1], m[0][2], m[0][3], m[0][4]])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`signal\s*\(|sigset\s*\(|sigaction\s*\(`, content)
	lines := split(content, "\n")
	code := _code(lines)
	hs := _multi_signal_handlers(code)
	count(hs) > 0
	some h in hs
	call := _unsafe_handler(lines, h)
	some i, line in lines
	contains(line, h)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_signal_re, _strip_strings(line), -1)
	m[2] == h
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Signal handler %s() is installed for more than one signal with signal(), which does not block the other signals while it runs, and it calls %s(), which is not async-signal-safe: a second signal re-enters it mid-operation. Use sigaction() with sa_mask filled (sigfillset) or only set a volatile sig_atomic_t flag in the handler", [h, call]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	contains(content, "sigaction")
	contains(content, "sa_")
	lines := split(content, "\n")
	some k, assign in lines
	regex.match(`sa_|struct\s+sigaction\s+\w+\s*=`, assign)
	not helpers.is_comment_line(assign)
	some p in _assignments(lines, k)
	not p[1] in _not_handlers
	calls := _sigaction_calls(lines, k, p[0])
	count({c[1] | some c in calls}) > 1
	not _mask_filled(helpers.code_window(lines, k, 15, 30), p[0])
	call := _unsafe_handler(lines, p[1])
	some c in calls
	i := c[0]
	line := lines[i]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Signal handler %s() is installed with sigaction() for more than one signal while %s.sa_mask is left empty, so the other signal interrupts it, and it calls %s(), which is not async-signal-safe. Fill sa_mask (sigfillset(&%s.sa_mask)) or only set a volatile sig_atomic_t flag in the handler", [p[1], p[0], call, p[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
