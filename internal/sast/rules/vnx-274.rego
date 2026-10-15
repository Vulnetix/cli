# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_274

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-274",
	"name": "Improper Handling of Insufficient Privileges",
	"description": "A privilege change is checked, but the branch that sees it fail only logs (or does nothing) and then falls through, so the program carries on as if it had the identity or the jail it asked for. Reported in C and C++ for an if on the failure of setuid, setgid, seteuid, setegid, setreuid, setregid, setresuid, setresgid, setgroups, initgroups or chroot (directly, or through a result variable assigned on the line above) and on the failure of ImpersonateNamedPipeClient, ImpersonateLoggedOnUser, ImpersonateSelf, ImpersonateAnonymousToken or SetThreadToken, whose body has no return, exit, abort, std::terminate(), a fatal raise(SIGKILL/SIGABRT), goto, err()/errx(), glibc error() with a nonzero status, break, continue or fatal/die-style call (words inside the log message, such as 'return code', do not count); in Python for os.setuid/os.setgid/os.seteuid/os.setegid/os.setreuid/os.setresuid/os.setgroups/os.initgroups/os.chroot (also called bare after `from os import`) inside a try whose except clause for OSError, PermissionError, Exception or a bare except neither raises, returns nor exits, or inside contextlib.suppress(OSError/PermissionError); in Go for an `if err != nil` after syscall/unix Setuid, Setgid, Setresuid, Setgroups, Chroot and similar whose body neither returns, panics, nor calls os.Exit, syscall.Exit or log.Fatal; and in PHP for an if on the failure of posix_setuid, posix_setgid, posix_seteuid, posix_setegid or posix_initgroups (!posix_setuid(...), !@posix_setuid(...), === false, or Yoda `false === posix_setuid(...)`) whose body neither throws, returns, exits nor dies. Not reported: an unchecked call (VNX-273), a check on success (`== 0`), a raise back to root (seteuid(0)) whose failure leaves the program less privileged, and handlers that stop.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-274/",
	"languages": ["c", "cpp", "python", "go", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [274],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["insufficient-privileges", "privilege-drop", "error-handling", "cwe-274"],
}

_is_c(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
}

_indent(l) := count(l) - count(trim_left(l, " \t"))

_first_or(xs, d) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

# Lines of the block that line i opens: every following line indented deeper,
# up to the first line at i's indent or shallower (a lone Allman `{` right
# after i does not end it). Comment lines are dropped.
_block(lines, i) := txt if {
	ind := _indent(lines[i])
	end := min([count(lines) - 1, i + 30])
	end >= i + 1
	nonblank := [k | some k in numbers.range(i + 1, end); trim_space(lines[k]) != ""]
	stops := [k |
		some n, k in nonblank
		_indent(lines[k]) <= ind
		not _allman_open(lines[k], n)
	]
	stop := _first_or(stops, end + 1)
	txt := concat("\n", [l | some k in numbers.range(i + 1, end); k < stop; l := lines[k]; not helpers.is_comment_line(l)])
}

_block(lines, i) := "" if i + 1 > count(lines) - 1

_allman_open(l, 0) if trim_space(l) == "{"

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# ── C / C++ ──────────────────────────────────────────────────────────────

_posix := `(set(e|re|res)?[ug]id|setgroups|initgroups|chroot)`

_win := `(ImpersonateNamedPipeClient|ImpersonateLoggedOnUser|ImpersonateSelf|ImpersonateAnonymousToken|SetThreadToken)`

_args := `\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_c_call(names) := concat("", [`\b`, names, _args])

# `ops->setuid(` / `obj.setuid(` is somebody else's function.
_c_member_call(line) if regex.match(concat("", [`(\.|->)\s*(`, _posix, `|`, _win, `)\s*\(`]), line)

# A raise back to root is not a drop.
_c_elevation(line) if regex.match(`(^|[^\w.>])set(e|re|res)?[ug]id\s*\(\s*(-1\s*,\s*)?0\s*[,)]`, line)

# The condition is true when a POSIX call (0 on success, -1 on failure) failed.
_posix_fails(cond, subj) if regex.match(concat("", [subj, `\s*(!=\s*0\b|<\s*0\b|==\s*-\s*1\b|<=\s*-\s*1\b)`]), cond)

_posix_fails(cond, subj) if regex.match(concat("", [`(-\s*1\s*==|\b0\s*!=|\b0\s*>)\s*`, subj]), cond)

_posix_fails(cond, subj) if regex.match(concat("", [`(\bif\s*\(|&&|\|\|)\s*`, subj, `\s*(\)|&&|\|\|)`]), cond)

# The condition is true when a Windows BOOL call (nonzero on success) failed.
_win_fails(cond, subj) if regex.match(concat("", [`!\s*`, subj]), cond)

_win_fails(cond, subj) if regex.match(concat("", [subj, `\s*==\s*(FALSE|0)\b`]), cond)

_if_re := `^\s*(\}\s*)?(else\s+)?if\s*\(`

# The condition and anything after it on the same line.
_tail(line) := regex.replace(line, `^\s*(\}\s*)?(else\s+)?if\s*\((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*\)`, "")

# glibc's error()/error_at_line() exit when their status argument is not 0.
_c_stop := `\b(return|goto|break|continue|throw|exit|_exit|_Exit|quick_exit|abort|err|errx|verr|verrx|longjmp|siglongjmp|pthread_exit|ExitProcess|ExitThread|TerminateProcess)\b|\berror(_at_line)?\s*\(\s*(EXIT_\w+|[1-9]\d*)\s*,|(?i)\b\w*(fatal|die|panic|abort|bail|exit)\w*\s*\(`

# A message that says "return code" or "will exit" stops nothing, so string
# contents are blanked before the body is searched.
_c_falls_through(lines, i) if {
	body := _c_code(concat("\n", [_tail(lines[i]), _block(lines, i)]))
	not regex.match(_c_stop, body)
	not regex.match(_c_kill, body)
}

# std::terminate(), and a signal the process sends itself to die.
_c_kill := `\b(std::)?terminate\s*\(\s*\)|\b(std::)?raise\s*\(\s*SIG(KILL|ABRT|TERM|SEGV)\b|\bkill\s*\([^;]*,\s*SIG(KILL|ABRT|TERM)\b`

# The failure is tested on the call itself…
_c_failure_check(lines, i, line) if _posix_fails(line, _c_call(_posix))

_c_failure_check(lines, i, line) if _win_fails(line, _c_call(_win))

# …or on the result variable assigned from it just above.
_c_failure_check(lines, i, line) if {
	i > 0
	some j in numbers.range(max([0, i - 3]), i - 1)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:[A-Za-z_][\w \t\*]*\s)?([A-Za-z_]\w*)\s*=\s*(?:\(\s*\w+\s*\)\s*)?`, _posix, `\s*\(`]), lines[j], 1)
	count(m) > 0
	not _c_elevation(lines[j])
	_posix_fails(line, concat("", [`\b`, m[0][1], `\b`]))
}

_c_failure_check(lines, i, line) if {
	i > 0
	some j in numbers.range(max([0, i - 3]), i - 1)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:[A-Za-z_][\w \t\*]*\s)?([A-Za-z_]\w*)\s*=\s*`, _win, `\s*\(`]), lines[j], 1)
	count(m) > 0
	_win_fails(line, concat("", [`\b`, m[0][1], `\b`]))
}

_c_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	_has_any(content, {"setuid", "setgid", "seteuid", "setegid", "setre", "setgroups", "initgroups", "chroot", "Impersonate", "SetThreadToken"})
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_if_re, line)
	not helpers.is_comment_line(line)
	code := _c_code(line)
	not _c_elevation(code)
	not _c_member_call(code)
	_c_failure_check(lines, i, code)
	_c_falls_through(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The privilege change is checked but its failure is only logged: execution falls through and the program carries on with the identity (or outside the jail) it meant to leave. Stop on failure: return an error, exit or abort",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Python ───────────────────────────────────────────────────────────────

_py_names := `(set(e|re|res)?[ug]id|setgroups|initgroups|chroot)`

_py_call := concat("", [`\bos\.`, _py_names, `\s*\(`])

_py_is_call(line, _) if regex.match(_py_call, line)

# `from os import setgid, setuid` and then a bare `setuid(uid)`.
_py_is_call(line, imported) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, _py_names, `\s*\(`]), line, -1)
	m[1] in imported
}

_py_imported(lines) := {n |
	some l in lines
	contains(l, "import")
	some m in regex.find_all_string_submatch_n(`^\s*from\s+os\s+import\s+\(?([^#\n]*)`, l, 1)
	some part in split(m[1], ",")
	n := trim(trim_space(part), "()")
	regex.match(concat("", [`^`, _py_names, `$`]), n)
}

_py_elevation(line) if regex.match(`(\bos\.|(^|[^\w.]))sete?[ug]id\s*\(\s*0\s*\)`, line)

_py_catches := `^\s*except\s*(:|\(?[^:]*\b(OSError|PermissionError|IOError|EnvironmentError|Exception|BaseException)\b)`

_py_stop := `\b(raise|return|continue|break)\b|\bsys\.exit\s*\(|\bos\._exit\s*\(|\bos\.abort\s*\(|\b(exit|quit)\s*\(|(?i)\b\w*(fatal|die|abort)\w*\s*\(`

# The block opener that directly contains line i.
_py_opener(lines, i) := o if {
	ind := _indent(lines[i])
	i > 0
	cands := [k |
		some k in numbers.range(max([0, i - 40]), i - 1)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
		_indent(lines[k]) < ind
	]
	count(cands) > 0
	o := cands[count(cands) - 1]
}

# An except clause of the try that encloses line i, which catches the error
# and does not stop.
_py_swallowed(lines, i) if {
	t := _py_opener(lines, i)
	regex.match(`^\s*try\s*:`, lines[t])
	tind := _indent(lines[t])
	end := min([count(lines) - 1, i + 40])
	end >= i + 1
	after := [k |
		some k in numbers.range(i + 1, end)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
		_indent(lines[k]) <= tind
	]
	ends := [k | some k in after; not _py_clause(lines[k], tind)]
	stop := _first_or(ends, end + 1)
	some h in after
	h < stop
	regex.match(_py_catches, lines[h])
	body := concat("\n", [regex.replace(lines[h], `^[^:]*:`, ""), _block(lines, h)])
	not regex.match(_py_stop, _c_code(body))
}

_py_clause(l, tind) if {
	_indent(l) == tind
	regex.match(`^\s*(except\b|else\s*:|finally\s*:)`, l)
}

_py_swallowed(lines, i) if {
	o := _py_opener(lines, i)
	regex.match(`^\s*with\s+(contextlib\.)?suppress\s*\([^)]*\b(OSError|PermissionError|IOError|EnvironmentError|Exception|BaseException)\b`, lines[o])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	_has_any(content, {"os.set", "os.initgroups", "os.chroot", "from os import"})
	lines := split(content, "\n")
	imported := _py_imported(lines)
	some i, line in lines
	_has_any(line, {"set", "initgroups", "chroot"})
	_py_is_call(line, imported)
	not helpers.is_comment_line(line)
	not _py_elevation(line)
	_py_swallowed(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "A failed privilege change is caught and swallowed: the except clause neither re-raises nor exits, so the process carries on with the identity (or outside the jail) it meant to leave. Let the error propagate or exit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── PHP ──────────────────────────────────────────────────────────────────

# posix_setuid() & co. return false on failure and raise nothing.
_php_call := `@?\s*\\?posix_(set(e)?[ug]id|initgroups)\s*\(`

_php_fails(cond) if regex.match(concat("", [`!\s*`, _php_call]), cond)

_php_fails(cond) if regex.match(concat("", [_php_call, `(?:[^()]|\([^()]*\))*\)\s*===?\s*false\b`]), cond)

# Yoda order, as Symfony's coding standard writes it: `false === posix_setuid(...)`.
_php_fails(cond) if regex.match(concat("", [`(?i)\bfalse\s*===?\s*`, _php_call]), cond)

_php_elevation(cond) if regex.match(`posix_sete?[ug]id\s*\(\s*0\s*\)`, cond)

_php_stop := `\b(return|throw|exit|die|break|continue)\b|\btrigger_error\s*\([^;]*E_USER_ERROR`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_has_any(content, {"posix_set", "posix_initgroups"})
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"posix_set", "posix_initgroups"})
	regex.match(_if_re, line)
	not helpers.is_comment_line(line)
	code := _c_code(line)
	_php_fails(code)
	not _php_elevation(code)
	not regex.match(_php_stop, _c_code(concat("\n", [_tail(code), _block(lines, i)])))
	finding := {
		"rule_id": metadata.id,
		"message": "The privilege change is checked but its failure is only logged: execution falls through and the program carries on with the identity it meant to leave. Stop on failure: throw, exit or return",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Go ───────────────────────────────────────────────────────────────────

_go_call := `\b(syscall|unix)\.(Set(e|re|res)?[ug]id|Setgroups|Chroot)\s*\(`

_go_elevation(line) if regex.match(`\b(syscall|unix)\.Sete?[ug]id\s*\(\s*0\s*\)`, line)

_go_stop := `\b(return|panic|break|continue|goto)\b|\b(os|syscall|unix)\.Exit\s*\(|\.(Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)\s*\(|\bruntime\.Goexit\s*\(`

# `if err := unix.Setuid(u); err != nil {`
_go_failure_check(lines, i, line) if {
	regex.match(concat("", [`^\s*if\s+\w+\s*:?=\s*`, _go_call, `.*;\s*\w+\s*!=\s*nil\s*\{`]), line)
	not _go_elevation(line)
}

# `err := unix.Setuid(u)` then `if err != nil {`
_go_failure_check(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`^\s*if\s+(\w+)\s*!=\s*nil\s*\{`, line, 1)
	count(m) > 0
	i > 0
	prev := [k | some k in numbers.range(max([0, i - 3]), i - 1); trim_space(lines[k]) != ""; not helpers.is_comment_line(lines[k])]
	count(prev) > 0
	p := lines[prev[count(prev) - 1]]
	regex.match(concat("", [`^\s*`, m[0][1], `\s*:?=\s*`, _go_call]), p)
	not _go_elevation(p)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_has_any(content, {"syscall.Set", "unix.Set", "Chroot"})
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*if\s`, line)
	_go_failure_check(lines, i, line)
	not regex.match(_go_stop, _block(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "The privilege change's error is only logged: execution falls through and the process carries on with the identity (or outside the jail) it meant to leave. Return the error, or exit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
