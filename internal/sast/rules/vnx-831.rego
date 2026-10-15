# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_831

import rego.v1

metadata := {
	"id": "VNX-831",
	"name": "Signal Handler Function Associated with Multiple Signals",
	"description": "Reports, in C and C++, the registration lines that install one signal handler for two or more different signals when the handler does non-reentrant work and nothing blocks the other signals while it runs, so a second signal can interrupt the handler half way through its own operation (one handler for SIGHUP and SIGTERM that frees a global frees it twice). Registrations: signal()/std::signal/sigset/bsd_signal(SIGx, handler), and sigaction(SIGx, &sa, ...) within 30 lines after sa.sa_handler/sa_sigaction = handler or a designated initialiser (struct sigaction sa = { .sa_handler = handler }), including a call whose arguments continue on the next line. The handler must be defined in the same file (the return type may sit on the line above) and its body must call a function that is not async-signal-safe (stdio, malloc/free, syslog, exit, strtok, localtime, strerror, pthread locking, std::cout, new/delete), directly or through a function defined in the same file whose body does. Not reported: a handler installed for a single signal, handlers that only set a flag or call async-signal-safe functions (write, _exit), a sigaction whose sa_mask is filled or extended (sigfillset/sigaddset on that struct's sa_mask), a crash handler shared only between synchronous fault signals (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGTRAP, SIGSYS), SIG_IGN/SIG_DFL, handlers defined in another file, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-831/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [831],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["signal-handler", "reentrancy", "cwe-831", "c", "cpp"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `//.*$|/\*.*?\*/`, "")

_fault := {"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT", "SIGTRAP", "SIGSYS", "SIGIOT", "SIGEMT"}

_join(lines, k) := concat(" ", [lines[k], lines[k + 1]]) if {
	k + 1 < count(lines)
	not contains(lines[k], ";")
} else := lines[k]

# [handler, signal, line] for signal(SIGx, h).
_regs(lines) := {[m[2], m[1], k] |
	some k, line in lines
	contains(line, "sig")
	regex.match(`\b(?:signal|sigset|bsd_signal)\s*\(`, line)
	not _is_comment(line)
	some m in regex.find_all_string_submatch_n(`\b(?:signal|sigset|bsd_signal)\s*\(\s*(SIG\w+)\s*,\s*(?:&\s*)?([A-Za-z_]\w*)\s*\)`, _strip(line), -1)
} | {[m[2], s, b] |
	some a, line in lines
	contains(line, "sa_")
	not _is_comment(line)
	some m in regex.find_all_string_submatch_n(`(\w+)\s*(?:\.|->)\s*sa_(?:handler|sigaction)\s*=\s*(?:\([^)]*\)\s*)?(?:&\s*)?([A-Za-z_]\w*)`, _strip(line), -1)
	not _masked(lines, m[1])
	some b in numbers.range(a + 1, min([a + 30, count(lines) - 1]))
	contains(lines[b], "sigaction")
	not _is_comment(lines[b])
	not _rehandled(lines, m[1], a, b)
	some r in regex.find_all_string_submatch_n(concat("", [`\bsigaction\s*\(\s*(SIG\w+)\s*,\s*&?\s*`, m[1], `\b`]), _strip(_join(lines, b)), -1)
	s := r[1]
} | {[m[2], s, b] |
	# A designated initialiser: struct sigaction sa = { .sa_handler = h };
	some a, line in lines
	contains(line, ".sa_")
	not _is_comment(line)
	some m in regex.find_all_string_submatch_n(`\bstruct\s+sigaction\s+(\w+)\s*=\s*\{[^}]*\.\s*sa_(?:handler|sigaction)\s*=\s*(?:\([^)]*\)\s*)?(?:&\s*)?([A-Za-z_]\w*)`, _strip(line), -1)
	not _masked(lines, m[1])
	some b in numbers.range(a + 1, min([a + 30, count(lines) - 1]))
	contains(lines[b], "sigaction")
	not _is_comment(lines[b])
	not _rehandled(lines, m[1], a, b)
	some r in regex.find_all_string_submatch_n(concat("", [`\bsigaction\s*\(\s*(SIG\w+)\s*,\s*&?\s*`, m[1], `\b`]), _strip(_join(lines, b)), -1)
	s := r[1]
}

# The struct's sa_mask blocks other signals while the handler runs.
_masked(lines, sa) if {
	re := concat("", [`\bsig(?:fillset|addset)\s*\(\s*&\s*`, sa, `\s*(?:\.|->)\s*sa_mask`])
	some l in lines
	contains(l, "sa_mask")
	regex.match(re, l)
}

# The struct gets a different handler between its assignment and line b.
_rehandled(lines, sa, a, b) if {
	b > a + 1
	some k in numbers.range(a + 1, b - 1)
	contains(lines[k], "sa_")
	regex.match(concat("", [`\b`, sa, `\s*(?:\.|->)\s*sa_(?:handler|sigaction)\s*=`]), lines[k])
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


_unsafe_names(lines, defs, h) := names if {
	some pair in defs
	pair[0] == h
	d := pair[1]
	_is_handler_def(lines, h, d)
	names := {n |
		some code in _code_lines(lines, d)
		some n in _direct(code) | _indirect(lines, defs, h, code)
	}
	count(names) > 0
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	contains(content, "SIG")
	regex.match(`\b(?:signal|sigset|bsd_signal|sigaction)\s*\(`, content)
	lines := split(content, "\n")
	regs := _regs(lines)
	count(regs) > 1
	handlers := {r[0] | some r in regs}
	some h in handlers
	sigs := {r[1] | some r in regs; r[0] == h}
	count(sigs) > 1
	count(sigs - _fault) > 0
	names := _unsafe_names(lines, _defs(lines), h)
	some r in regs
	r[0] == h
	k := r[2]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Handler %s is installed for %d signals (%s) and calls %s; one signal can interrupt the handler while it is handling another. Install a separate handler per signal, block the other signals with sigaction and a filled sa_mask, or make the handler only set a volatile sig_atomic_t flag", [h, count(sigs), concat(", ", sort(sigs)), concat(", ", sort(names))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": lines[k],
	}
}
