# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_828

import rego.v1

metadata := {
	"id": "VNX-828",
	"name": "Signal Handler with Functionality that is not Asynchronous-Safe",
	"description": "Reports, in C and C++, each line of a signal handler's body that calls a function outside the POSIX async-signal-safe list. A handler is a function this same file installs with signal()/std::signal/sigset/bsd_signal(SIG..., handler) or assigns to a struct sigaction's sa_handler/sa_sigaction, and whose definition (void name(int ...), also with the return type on the line above, or the three-argument SA_SIGINFO form) is in the file. Reported: direct calls to stdio (printf, fprintf, snprintf, puts, fflush, fopen, fclose), the heap (malloc, calloc, realloc, free, strdup), syslog, exit/atexit, strtok, strerror, localtime/gmtime/ctime/strftime, getenv/setenv, rand, longjmp, pthread mutex and condition calls, dlopen, system/popen, getaddrinfo, std::to_string/make_shared, C++ stream output (std::cout <<), a std::lock_guard/unique_lock/scoped_lock that takes a mutex, new and delete; and, one level deep, a call to a function defined in the same file whose own body makes such a call (cleanup() that calls fclose). Not reported: the async-signal-safe functions (write, read, _exit, abort, kill, raise, sigaction, getpid, close, unlink, memcpy, strlen, siglongjmp), helper functions whose bodies make no unsafe call, functions defined in other files, atomics and wrappers named atomic/signal_safe/FromHandler, upper-case macros, member calls (flag.store(true)), handlers installed only for synchronous fault signals (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGTRAP, SIGSYS; last-resort crash reporters, which VNX-479 reports), functions not installed as handlers, SIG_IGN/SIG_DFL, lambdas, comments and string literals. This rule owns the unsafe-call lines of every handler installed for an asynchronous signal; VNX-479 reports only handlers installed solely for fault signals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-828/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [828],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["signal-handler", "async-signal-safety", "cwe-828", "c", "cpp"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `//.*$|/\*.*?\*/`, "")

_reg_res := [
	`\b(?:signal|sigset|bsd_signal)\s*\(\s*\w+\s*,\s*(?:&\s*)?([A-Za-z_]\w*)\s*\)`,
	`sa_(?:handler|sigaction)\s*=\s*(?:\([^)]*\)\s*)?(?:&\s*)?([A-Za-z_]\w*)`,
]

_not_handlers := {"SIG_IGN", "SIG_DFL", "SIG_ERR", "SIG_HOLD", "NULL", "nullptr", "0"}

_handlers(content) := {h |
	some re in _reg_res
	some m in regex.find_all_string_submatch_n(re, content, -1)
	h := m[1]
	not h in _not_handlers
}

_registers(content) if contains(content, "signal")

_registers(content) if contains(content, "sa_handler")

_registers(content) if contains(content, "sa_sigaction")

_registers(content) if contains(content, "sigset")

# The synchronous fault signals. A handler installed only for these is a
# last-resort crash reporter: the process is already dying and the report is
# best effort, so it is not reported.
_fault := {"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT", "SIGTRAP", "SIGSYS", "SIGIOT", "SIGEMT"}

# Signals each handler is installed for: signal(SIGX, h) directly, and
# sigaction(SIGX, &sa, ...) within 30 lines after sa.sa_handler = h.
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

_fault_only(lines, h) if {
	sigs := _signals(lines, h)
	count(sigs) > 0
	every s in sigs {
		s in _fault
	}
}

# Library functions that are not async-signal-safe (POSIX.1-2017 2.4.3 does
# not list them): stdio, the heap, locale/time conversion, syslog, exit and
# atexit processing, the environment, pthread locking, dynamic loading,
# process spawning through the shell, and C++ standard helpers that allocate.
_unsafe := {
	"printf", "fprintf", "vprintf", "vfprintf", "dprintf", "vdprintf", "sprintf", "vsprintf", "snprintf",
	"vsnprintf", "asprintf", "vasprintf", "puts", "fputs", "putchar", "fputc", "putc", "fwrite", "fread",
	"fflush", "fopen", "fdopen", "freopen", "fclose", "fgets", "fgetc", "getc", "getchar", "scanf", "fscanf",
	"sscanf", "perror", "setvbuf", "setbuf", "tmpfile", "remove", "malloc", "calloc", "realloc",
	"reallocarray", "free", "strdup", "strndup", "aligned_alloc", "posix_memalign", "memalign", "valloc",
	"syslog", "vsyslog", "openlog", "closelog", "exit", "atexit", "quick_exit", "strtok", "strerror",
	"localtime", "gmtime", "ctime", "asctime", "mktime", "strftime", "localtime_r", "gmtime_r", "tzset",
	"setlocale", "getenv", "setenv", "unsetenv", "putenv", "rand", "srand", "random", "longjmp",
	"pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_trylock", "pthread_cond_signal",
	"pthread_cond_broadcast", "pthread_cond_wait", "pthread_join", "pthread_create", "pthread_exit",
	"pthread_cancel", "dlopen", "dlsym", "dlclose", "system", "popen", "pclose", "backtrace_symbols",
	"opendir", "readdir", "closedir", "getpwnam", "getpwuid", "gethostbyname", "getaddrinfo",
	"to_string", "to_wstring", "make_shared", "make_unique", "terminate", "quick_exit",
}

_cpp_unsafe := {
	"operator<< on a standard stream": `\b(?:std::)?(?:cout|cerr|clog|wcout|wcerr)\s*<<`,
	"new": `(?:^|[=(,\s])new\s+[A-Za-z_:]`,
	"a mutex lock (std::lock_guard/unique_lock/scoped_lock)": `\b(?:std::)?(?:lock_guard|unique_lock|scoped_lock)\s*(?:<[^>]*>)?\s*[A-Za-z_]\w*\s*[({]`,
	"delete": `(?:^|[;{\s])delete\s*(?:\[\s*\]\s*)?[A-Za-z_*(]`,
}

_call_re := `(?:^|[^\w.>:])((?:std::)?[A-Za-z_]\w*)\s*\(`

# The handler's own definition line.
_def_re(h) := concat("", [`^\s*(?:extern\s+"C"\s+)?(?:static\s+)?(?:inline\s+)?void\s+(?:\w+::)?`, h, `\s*\(\s*(?:const\s+)?(?:int|signed)\b[^;]*$`])

# The GNU/BSD style, with the return type on the line above:
#   static void
#   on_term (int sig)
_is_handler_def(lines, h, d) if regex.match(_def_re(h), lines[d])

_is_handler_def(lines, h, d) if {
	d > 0
	regex.match(concat("", [`^`, h, `\s*\(\s*(?:const\s+)?(?:int|signed)\b[^;]*$`]), lines[d])
	regex.match(`^(?:extern\s+"C"\s+)?(?:static\s+)?(?:inline\s+)?void\s*$`, lines[d - 1])
}

# A function defined at file scope.
_fn_def_re(f) := concat("", [`^(?:extern\s+"C"\s+)?(?:[A-Za-z_][\w\s\*]*[\s\*])?`, f, `\s*\([^;]*$`])

_body(lines, d) := [k |
	n := count(lines)
	ends := [e | some e in numbers.range(d + 1, min([d + 120, n - 1])); startswith(lines[e], "}")]
	count(ends) > 0
	some k in numbers.range(d + 1, min(ends) - 1)
]

_code_lines(lines, d) := [code |
	some k in _body(lines, d)
	not _is_comment(lines[k])
	code := _strip(lines[k])
]

# Unsafe library calls on one line of code.
_direct(code) := {name |
	some m in regex.find_all_string_submatch_n(_call_re, code, -1)
	name := trim_prefix(m[1], "std::")
	name in _unsafe
} | {name |
	some name, re in _cpp_unsafe
	regex.match(re, code)
}

# A call on this line to a function the same file defines whose own body
# makes an unsafe library call (one level deep).
_indirect(lines, defs, h, code) := {sprintf("%s() (which calls %s)", [f, concat(", ", sort(inner))]) |
	some m in regex.find_all_string_submatch_n(_call_re, code, -1)
	f := m[1]
	not contains(f, "::")
	f != h
	not f in _unsafe
	not regex.match(`^[A-Z_][A-Z0-9_]*$|(?i)atomic|signal_safe|async_safe|fromhandler`, f)
	some pair in defs
	pair[0] == f
	d := pair[1]
	inner := {n | some c in _code_lines(lines, d); some n in _direct(c)}
	count(inner) > 0
}

# Function definitions at file scope: a line starting at column 0 with a
# name and an open parenthesis and no semicolon (prototypes end in one).
_defs(lines) := {[name, d] |
	some d, l in lines
	contains(l, "(")
	not contains(l, ";")
	not startswith(l, " ")
	not startswith(l, "\t")
	regex.match(`^[A-Za-z_]`, l)
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*\(`, l, 1)
	name := m[0][1]
	regex.match(_fn_def_re(name), l)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	_registers(content)
	hs := _handlers(content)
	count(hs) > 0
	lines := split(content, "\n")
	defs := _defs(lines)
	some h in hs
	some pair in defs
	pair[0] == h
	d := pair[1]
	_is_handler_def(lines, h, d)
	not _fault_only(lines, h)
	some k in _body(lines, d)
	line := lines[k]
	not _is_comment(line)
	code := _strip(line)
	names := _direct(code) | _indirect(lines, defs, h, code)
	count(names) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Signal handler %s calls %s, which is not async-signal-safe; the signal can arrive while the program is inside the same function or holds its lock. Set a volatile sig_atomic_t flag and do the work in the main loop, or use only async-signal-safe calls (write, _exit)", [h, concat(", ", sort(names))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": line,
	}
}
