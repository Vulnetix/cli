# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_273

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-273",
	"name": "Improper Check for Dropped Privileges",
	"description": "A call that drops privileges is made as a bare statement, so its result is thrown away and a failed drop goes unnoticed: the program carries on with the identity it meant to give up. Reported in C and C++ for setuid, setgid, seteuid, setegid, setreuid, setregid, setresuid, setresgid, setgroups and initgroups (also written ::setuid, and behind a (void) or (void)! cast, static_cast<void>() or std::ignore =, which silence warn_unused_result without checking anything, and as the body of a braceless one-line `if (...) setuid(u);` or `else setgid(g);`) and for the Windows impersonation calls ImpersonateNamedPipeClient, ImpersonateLoggedOnUser, ImpersonateSelf, ImpersonateAnonymousToken, RpcImpersonateClient, CoImpersonateClient and SetThreadToken; in Go for syscall/unix Setuid, Setgid, Setreuid, Setresuid, Setgroups and friends called as a statement, assigned to _ or deferred; in Rust for the same libc:: calls whose value is discarded with a semicolon or let _ =, and for the nix crate's unistd::setuid & co. as a bare statement, with .ok(); or let _ =; and in PHP for posix_setuid, posix_setgid, posix_seteuid, posix_setegid and posix_initgroups as a statement (they return false on failure and raise nothing). Not reported: a result that is compared, assigned, returned, asserted or passed on (in Rust also ?, unwrap() and expect(); in PHP also `or die`); Python, Ruby and Node, whose calls raise on failure; a drop followed within a few lines by a getuid()/geteuid()/getgid()/getegid()/errno verification or by a checked attempt to regain root (`if (setuid(0) != -1) abort();`, CERT POS37-C); a raise back to root (seteuid(0), setuid(0)), whose failure leaves the program less privileged; prototypes and definitions (also BSD style, with the return type on the line above), macros, member calls and the names in comments or strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-273/",
	"languages": ["c", "cpp", "go", "rust", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [273],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["dropped-privileges", "setuid", "unchecked-return", "impersonation", "cwe-273"],
}

_lang(path) := "c" if {
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "rust" if endswith(path, ".rs")

_lang(path) := "php" if endswith(path, ".php")

# Substring gates: a whole-file regular expression with alternation is a slow
# scan, a substring test is not.
_needles := {
	"c": {"setuid", "setgid", "seteuid", "setegid", "setre", "setgroups", "initgroups", "Impersonate", "SetThreadToken"},
	"go": {"Setuid", "Setgid", "Seteuid", "Setegid", "Setre", "Setgroups"},
	"rust": {"setuid", "setgid", "seteuid", "setegid", "setre", "setgroups", "initgroups"},
	"php": {"posix_set", "posix_initgroups"},
}

# Rust has two ways in: libc:: calls anywhere, and the nix crate's
# unistd::setuid & co., which are only nix's when the file uses nix.
_rust_file(content) if contains(content, "libc::")

_rust_file(content) if contains(content, "unistd")

_rust_line_ok(line, _) if contains(line, "libc::")

_rust_line_ok(line, content) if {
	not contains(line, "libc::")
	contains(content, "unistd")
}

_file_ok(content, "rust") if _rust_file(content)

_file_ok(_, lang) if lang != "rust"

_line_ok(line, content, "rust") if _rust_line_ok(line, content)

_line_ok(_, _, lang) if lang != "rust"

# The ways a statement throws a value away on purpose without checking it,
# stripped so the call itself is what the statement starts with: a (void)
# or (void)! cast, static_cast<void>(...), std::ignore =, Go's defer (a
# deferred call's result is dropped), Rust's `let _ =`, and C++'s global
# scope `::`; PHP's @ (error suppression) and a leading namespace `\`.
# A braceless `if (cond) setuid(u);` / `} else setgid(g);` on one line is the
# same discarded statement, so the guard is stripped too.
_discard_prefix := `^(\s*)(\(\s*void\s*\)\s*!?\s*|static_cast\s*<\s*void\s*>\s*\(\s*|std::ignore\s*=\s*|defer\s+|let\s+_\s*=\s*|::|@\s*|\\|\}\s*|else\s+|if\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*)+`

_norm(s) := regex.replace(s, _discard_prefix, "$1")

_args := `\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_c_calls := `(set(e|re|res)?[ug]id|setgroups|initgroups|ImpersonateNamedPipeClient|ImpersonateLoggedOnUser|ImpersonateSelf|ImpersonateAnonymousToken|RpcImpersonateClient|CoImpersonateClient|SetThreadToken)`

# The line begins a statement that is nothing but the call.
_stmt_re := {
	"c": concat("", [`^\s*`, _c_calls, `\s*\(`]),
	"go": `^\s*(_\s*=\s*)?(syscall|unix)\.(Set(e|re|res)?[ug]id|Setgroups)\s*\(`,
	"rust": `^\s*(unsafe\s*\{\s*)?(libc::|(nix::)?unistd::)?(set(e|re|res)?[ug]id|setgroups|initgroups)\s*\(`,
	# PHP's posix_* calls return false on failure and raise nothing.
	"php": `^\s*posix_(set(e)?[ug]id|initgroups)\s*\(`,
}

# A raise back to root: if it fails the program is left less privileged.
_elevation(stmt) if regex.match(`^\s*(_\s*=\s*)?(unsafe\s*\{\s*)?((syscall|unix)\.|libc::|(nix::)?unistd::|posix_)?(?i:set(e|re|res)?[ug]id)\s*\(\s*(-1\s*,\s*)?((Uid|Gid)::from_raw\s*\(\s*0\s*\)|ROOT\b|0\s*[,)])`, stmt)

# The statement text from line i up to its terminating semicolon (C, Rust)
# or the end of the line (Go), over at most four lines.
_statement(lines, i, "go") := lines[i]

_statement(lines, i, lang) := s if {
	lang != "go"
	end := min([count(lines) - 1, i + 3])
	ends := [j | some j in numbers.range(i, end); contains(lines[j], ";")]
	count(ends) > 0
	joined := concat(" ", array.slice(lines, i, ends[0] + 1))
	s := split(joined, ";")[0]
}

# The value is consumed by an operator inside the same statement.
_consumed(stmt) if regex.match(`==|!=|<|>|&&|\|\||\?|\}\s*!=|\b(or|and|xor)\b`, replace(stmt, "->", "."))

# Rust: a call without a trailing semicolon is a tail expression whose value
# the enclosing block hands on (`let rc = unsafe { libc::setuid(u) };`).
_rust_discarded(line) if regex.match(`libc::\w+\s*\([^;{}]*\)\s*;`, line)

_rust_discarded(line) if regex.match(`^\s*unsafe\s*\{\s*libc::\w+\s*\([^;{}]*\)\s*;?\s*\}\s*;`, line)

# nix returns a Result: a bare statement, `.ok();` or `let _ =` drops it;
# `?`, unwrap() and expect() do not.
_rust_discarded(line) if regex.match(concat("", [`^\s*((nix::)?unistd::)?(set(e|re|res)?[ug]id|setgroups|initgroups)`, _args, `\s*(\.ok\(\)\s*)?;`]), line)

_discarded(line, "rust") if _rust_discarded(line)

_discarded(_, lang) if lang != "rust"

# A definition or prototype whose return type sits on the line above
# (BSD style: `int\nsetresuid(uid_t r, uid_t e, uid_t s)\n{`): the
# "statement" opens a body, or its parameters are declared with types.
_definition(stmt, lang) if {
	lang in {"c", "php"}
	contains(stmt, "{")
}

_definition(stmt, "c") if regex.match(`^\s*\w+\s*\(\s*(const\s+|unsigned\s+)?(uid_t|gid_t|size_t|int|void|char|long)\b`, stmt)

# The previous code line leaves an expression open, so this line is not the
# start of a statement (`rc =` / `if (` / an argument list).
_continuation(lines, i) if {
	prev := [j | some j in numbers.range(max([0, i - 3]), i - 1); trim_space(lines[j]) != ""; not helpers.is_comment_line(lines[j])]
	count(prev) > 0
	regex.match(`([=(,!?&|<>+\-]|\breturn)\s*$`, trim_space(lines[prev[count(prev) - 1]]))
}

# The drop is verified right after it: the identity is read back, or errno /
# GetLastError() is examined.
_verified_after(lines, i) if {
	end := min([count(lines) - 1, i + 4])
	end >= i + 1
	some j in numbers.range(i + 1, end)
	not helpers.is_comment_line(lines[j])
	regex.match(`(?i)\b(posix_)?(get(e|res)?[ug]id)\s*\(|\berrno\b|\bGetLastError\s*\(|\bset(e|re|res)?[ug]id\s*\(\s*(-1\s*,\s*)?0\s*[,)]`, lines[j])
	regex.match(`\bif\b|\bassert|\bensure|==|!=`, lines[j])
	# `if (getuid() == 0) setuid(uid);` guards the next drop, it reads
	# nothing back.
	not regex.match(`(?i)(\b|_)set(e|re|res)?[ug]id\s*\(\s*([^0\s-]|-1\s*,\s*[^0\s])`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _needles[lang])
	_file_ok(content, lang)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _needles[lang])
	_line_ok(line, content, lang)
	n := _norm(line)
	regex.match(_stmt_re[lang], n)
	not helpers.is_comment_line(line)
	stmt := _norm(_statement(lines, i, lang))
	not _elevation(stmt)
	not _consumed(stmt)
	not _definition(stmt, lang)
	_discarded(n, lang)
	not _continuation(lines, i)
	not _verified_after(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The result of this privilege drop is discarded. If it fails (RLIMIT_NPROC, a missing capability, a failed impersonation) the program keeps running with the privileges it meant to give up. Check the return value and abort on failure, then verify with getuid()/geteuid()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
