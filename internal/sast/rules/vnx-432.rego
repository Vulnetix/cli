# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_432

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-432",
	"name": "Dangerous Signal Handler not Disabled During Sensitive Operations",
	"description": "A C/C++ signal handler that does non-reentrant work is installed with sigaction() and SA_NODEFER (or the old SA_NOMASK spelling), which stops the kernel from blocking the signal while its own handler runs, so a second delivery of the same signal re-enters the handler half way through its sensitive operation (a global freed twice, a stdio buffer or lock state corrupted). Reported: the line that puts SA_NODEFER/SA_NOMASK into a struct sigaction's sa_flags (sa.sa_flags = ..., sa.sa_flags |= ..., or a designated initialiser { .sa_flags = SA_NODEFER }) when the same struct's sa_handler/sa_sigaction is a function defined in the same file whose body calls something that is not async-signal-safe (free, malloc, calloc, realloc, the printf family, syslog, puts, fputs, fwrite, fflush, fopen, fclose, exit, strtok, localtime, gmtime, ctime, strerror, perror, longjmp, siglongjmp, pthread_mutex_lock, system, popen, new/delete, std::cout/cerr) and the struct is passed to sigaction() for at least one asynchronous signal within thirty lines. Not reported: SA_NODEFER together with SA_RESETHAND (the second delivery takes the default action, it does not re-enter), handlers installed only for synchronous fault signals (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGTRAP, SIGSYS; crash reporters), handlers that only set a flag or call async-signal-safe functions, handlers defined in another file, SIG_IGN/SIG_DFL, comments and strings. One handler installed for two or more signals without a mask is reported by VNX-831, and a non-async-signal-safe call inside a handler by VNX-828; this rule reports only the flag that disables the handler's own blocking.",
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

_sa_handler_re := `\b([A-Za-z_]\w*)\s*(?:\.|->)\s*sa_(?:handler|sigaction)\s*=\s*(?:\(\s*\w+\s*\)\s*)?&?\s*([A-Za-z_]\w*)\s*;`

# struct sigaction sa = { .sa_handler = on_stop, ... }, possibly over a few lines.
_sa_init_re := `^\s*(?:static\s+)?(?:const\s+)?struct\s+sigaction\s+([A-Za-z_]\w*)\s*=\s*\{[^}]*?\.sa_(?:handler|sigaction)\s*=\s*(?:\(\s*\w+\s*\)\s*)?&?\s*([A-Za-z_]\w*)`

# [struct, handler, designated-initialiser?] triples whose handler is set on line k.
_assignments(lines, k) := {[a[1], a[2], false] | some a in regex.find_all_string_submatch_n(_sa_handler_re, _strip_strings(lines[k]), -1)} | {[a[1], a[2], true] |
	regex.match(`struct\s+sigaction\s+\w+\s*=`, lines[k])
	text := concat("\n", [lines[j] | some j in numbers.range(k, min([count(lines) - 1, k + 4]))])
	some a in regex.find_all_string_submatch_n(_sa_init_re, _strip_strings(text), 1)
}

_sigaction_re := `\bsigaction\s*\(\s*(SIG[A-Z0-9]+)\s*,\s*&\s*([A-Za-z_]\w*)\s*,`

_strip_strings(s) := regex.replace(s, `"(?:\\.|[^"\\\n])*"`, `""`)

# Synchronous fault signals are raised by the faulting thread itself; a crash
# handler (often deliberately SA_NODEFER) is not a re-entry risk this rule owns.
_fault_signals := {"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT", "SIGTRAP", "SIGSYS"}

# sigaction() calls on struct v for an asynchronous signal in the thirty lines
# after line k assigned its handler, up to the next handler assignment on the
# same struct.
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
	some x in helpers.span(k + 1, i - 1)
	regex.match(re, lines[x])
}

_nodefer_re := `\bSA_(?:NODEFER|NOMASK)\b`

# Lines near the handler assignment on line k that put SA_NODEFER into v's
# sa_flags by assignment.
_flag_lines(lines, k, v, false) := {i |
	re := concat("", [`\b`, v, `\s*(?:\.|->)\s*sa_flags\s*\|?=[^;]*`, _nodefer_re])
	some i in numbers.range(max([0, k - 15]), min([count(lines) - 1, k + 30]))
	contains(lines[i], "sa_flags")
	not helpers.is_comment_line(lines[i])
	regex.match(re, _strip_strings(lines[i]))
}

# A designated initialiser carrying .sa_flags = ... SA_NODEFER.
_flag_lines(lines, k, _, true) := {i |
	some i in numbers.range(k, min([count(lines) - 1, k + 4]))
	not helpers.is_comment_line(lines[i])
	regex.match(_nodefer_re, _strip_strings(lines[i]))
	text := concat("\n", [lines[j] | some j in numbers.range(k, i)])
	regex.match(`\.\s*sa_flags\s*=[^}]*$`, regex.replace(_strip_strings(text), `\n`, " "))
}

# SA_RESETHAND anywhere in the struct's flags: the second delivery takes the
# default action instead of re-entering the handler.
_resethand(lines, k, v) if {
	txt := _strip_strings(helpers.code_window(lines, k, 15, 30))
	regex.match(concat("", [`\b`, v, `\s*(?:\.|->)\s*sa_flags\s*\|?=[^;]*\bSA_RESETHAND\b`]), txt)
}

_resethand(lines, k, _) if {
	regex.match(`struct\s+sigaction\s+\w+\s*=`, lines[k])
	text := concat(" ", [lines[j] | some j in numbers.range(k, min([count(lines) - 1, k + 4]))])
	regex.match(`\{[^}]*\.\s*sa_flags\s*=[^},]*\bSA_RESETHAND\b`, _strip_strings(text))
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
	contains(content, "sigaction")
	regex.match(_nodefer_re, content)
	lines := split(content, "\n")
	some k, assign in lines
	regex.match(`sa_|struct\s+sigaction\s+\w+\s*=`, assign)
	not helpers.is_comment_line(assign)
	some p in _assignments(lines, k)
	not p[1] in _not_handlers
	flags := _flag_lines(lines, k, p[0], p[2])
	count(flags) > 0
	not _resethand(lines, k, p[0])
	calls := _sigaction_calls(lines, k, p[0])
	count(calls) > 0
	call := _unsafe_handler(lines, p[1])
	some i in flags
	line := lines[i]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SA_NODEFER on %s.sa_flags stops the kernel blocking the signal while handler %s() runs, and the handler calls %s(), which is not async-signal-safe: a second delivery re-enters it mid-operation. Drop SA_NODEFER (or add SA_RESETHAND), fill sa_mask, or make the handler only set a volatile sig_atomic_t flag", [p[0], p[1], call]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
