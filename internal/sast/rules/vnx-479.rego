# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_479

import rego.v1

metadata := {
	"id": "VNX-479",
	"name": "Signal Handler Use of a Non-reentrant Function",
	"description": "Reports a call to a function that is not async-signal-safe (printf/fprintf/puts and the rest of stdio, malloc/calloc/realloc/free, syslog, exit, strtok, localtime/gmtime/ctime/asctime, perror, longjmp, operator new/delete, std::cout/cerr/clog, mutex locks via pthread_mutex_lock or std::lock_guard/unique_lock/scoped_lock) inside the body of a C/C++ crash handler: a function (defined as `void name(int ...)`, with the return type on the same line or, BSD style, the line above) that the same file installs only for synchronous fault signals (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGTRAP, SIGSYS) with signal(SIG..., handler), or with sa_handler/sa_sigaction = handler and sigaction(SIG..., &sa, ...) within thirty lines. A fault raised inside malloc, stdio or while a lock is held leaves that function's state half updated, and a crash handler that calls it again deadlocks or corrupts the heap instead of writing its report. Not reported: handlers installed for any asynchronous signal (SIGINT, SIGTERM, SIGHUP, SIGALRM, ...) and handlers whose signals cannot be read from the file, whose unsafe calls are reported by VNX-828; the async-signal-safe calls (write, _exit, sig_atomic_t flag stores, signal, kill, raise, abort); handlers registered in another file, SIG_IGN/SIG_DFL, functions not registered as handlers, and comments (whole-line and trailing).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-479/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [479],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["signal-handler", "reentrancy", "cwe-479"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_unsafe := `(?:^|[^\w.>:])(printf|fprintf|vprintf|vfprintf|sprintf|snprintf|puts|fputs|putchar|fputc|fwrite|fflush|fopen|fclose|malloc|calloc|realloc|free|strdup|syslog|exit|strtok|localtime|gmtime|ctime|asctime|perror|longjmp|siglongjmp|pthread_mutex_lock)\s*\(|\bstd::(?:cout|cerr|clog)\b|\bstd::(?:lock_guard|unique_lock|scoped_lock)\b|\bnew\s+[A-Za-z_]|\bdelete\b`

# Code with string literals emptied and trailing /* */ and // comments removed.
_code(line) := regex.replace(regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `/\*.*?(?:\*/|$)`, ""), `//.*$`, "")

# Handler names installed in this file.
_handlers(lines) := {h |
	some l in lines
	not _is_comment(l)
	some m in regex.find_all_string_submatch_n(`\b(?:std::)?signal\s*\(\s*SIG[A-Z0-9]+\s*,\s*&?\s*([A-Za-z_]\w*)\s*\)`, l, -1)
	h := m[1]
	not h in {"SIG_IGN", "SIG_DFL", "SIG_ERR"}
} | {h |
	some l in lines
	not _is_comment(l)
	some m in regex.find_all_string_submatch_n(`\.\s*sa_(?:handler|sigaction)\s*=\s*&?\s*([A-Za-z_]\w*)\s*[;,}]`, l, -1)
	h := m[1]
	not h in {"SIG_IGN", "SIG_DFL", "SIG_ERR"}
}

# The synchronous fault signals, raised by the faulting thread itself.
_fault := {"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT", "SIGTRAP", "SIGSYS", "SIGIOT", "SIGEMT"}

# Signals each handler is installed for: signal(SIGX, h) directly, and
# sigaction(SIGX, &sa, ...) within 30 lines after sa.sa_handler = h. This is
# the same reading VNX-828 makes, so the two rules split handlers exactly:
# VNX-828 owns every handler that is not fault-only, this rule the rest.
_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `//.*$|/\*.*?\*/`, "")

_signals(lines, h) := {s |
	some line in lines
	contains(line, h)
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.>])(?:std::)?(?:signal|sigset|bsd_signal)\s*\(\s*(\w+)\s*,\s*(?:&\s*)?(\w+)\s*\)`, _strip(line), -1)
	m[2] == h
	s := m[1]
} | {s |
	some a, line in lines
	contains(line, h)
	some m in regex.find_all_string_submatch_n(`(\w+)\s*(?:\.|->)\s*sa_(?:handler|sigaction)\s*=\s*(?:\([^)]*\)\s*)?(?:&\s*)?(\w+)`, _strip(line), -1)
	m[2] == h
	some b in numbers.range(a + 1, min([a + 30, count(lines) - 1]))
	contains(lines[b], "sigaction")
	some r in regex.find_all_string_submatch_n(concat("", [`\bsigaction\s*\(\s*(\w+)\s*,\s*&?\s*`, m[1], `\b`]), lines[b], -1)
	s := r[1]
}

# Installed for at least one signal, and only for fault signals.
_fault_only(lines, h) if {
	sigs := _signals(lines, h)
	count(sigs) > 0
	every s in sigs {
		s in _fault
	}
}

# The handler's definition line: `void name(int sig)` (optionally static,
# extern "C", with its brace on the same or the next line) at column 0.
_def_line(lines, h) := j if {
	re := concat("", [`^(?:static\s+|extern\s+"C"\s+|inline\s+)*void\s+`, h, `\s*\(\s*(?:int|const\s+int)\b[^;]*$`])
	bsd := concat("", [`^`, h, `\s*\(\s*(?:int|const\s+int)\b[^;]*$`])
	defs := [k | some k, l in lines; _is_def(lines, k, l, re, bsd)]
	count(defs) > 0
	j := defs[0]
}

_is_def(_, _, l, re, _) if regex.match(re, l)

# BSD style: the return type on its own line above the name.
_is_def(lines, k, l, _, bsd) if {
	k > 0
	regex.match(bsd, l)
	regex.match(`^(?:(?:static|extern\s+"C"|inline)\s+)*void\s*$`, lines[k - 1])
}

# The body ends at the first column-0 closing brace.
_body_end(lines, j) := e if {
	ends := [k | some k in numbers.range(j + 1, min([count(lines) - 1, j + 200])); startswith(lines[k], "}")]
	count(ends) > 0
	e := ends[0]
}

findings contains finding if {
	some path, content in input.file_contents
	some x in _exts
	endswith(path, x)
	regex.match(`\bsignal\s*\(\s*SIG|sa_(?:handler|sigaction)\s*=`, content)
	regex.match(`\bSIG(?:SEGV|BUS|FPE|ILL|ABRT|TRAP|SYS|IOT|EMT)\b`, content)
	lines := split(content, "\n")
	some h in _handlers(lines)
	_fault_only(lines, h)
	j := _def_line(lines, h)
	e := _body_end(lines, j)
	some k in numbers.range(j + 1, e - 1)
	line := lines[k]
	not _is_comment(line)
	m := regex.find_all_string_submatch_n(_unsafe, _code(line), 1)
	count(m) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("crash handler '%s' (installed only for fault signals) calls a function that is not async-signal-safe: if the fault happened inside the same function (malloc, stdio, a held lock) the handler deadlocks or corrupts the heap instead of reporting. Use write/backtrace_symbols_fd and _exit in the handler", [h]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": line,
	}
}
