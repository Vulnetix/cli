# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_280

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-280",
	"name": "Improper Handling of Insufficient Permissions or Privileges ",
	"description": "The program is refused access to, or control over, a resource and carries on as if it had it. Two concrete shapes are reported. First, a call that restricts a file to its owner (chmod/fchmod/fchmodat to 0600, 0400, 0700 or S_IRUSR|S_IWUSR in C and C++; os.chmod/Path.chmod to 0o600-style modes in Python; os.Chmod/File.Chmod to 0600-style modes in Go) whose failure is ignored: a bare statement with the result discarded, an if on its failure that only logs, an except OSError/PermissionError that passes or logs, contextlib.suppress, or a Go error that is only logged. When the process may not change the mode (the file belongs to someone else) the secret it then writes stays readable. Second, a refused directory or path that is replaced by a broader one: a failed chdir into a home or jail directory that falls back to chdir(\"/\") (C, C++), and an except PermissionError/OSError that falls back to /tmp, tempfile.gettempdir() or os.chdir(\"/\") (Python). Not reported: failures that return, exit, raise or abort; ordinary modes such as 0644 or 0755 whose failure exposes nothing; tempfile.mkdtemp() fallbacks, which are private; test code; and access()-style permission probes, which are a race (TOCTOU), not this weakness.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-280/",
	"languages": ["c", "cpp", "python", "go"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [280],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["insufficient-permissions", "error-handling", "file-permissions", "cwe-280"],
}

_chmod_msg := "Restricting this file to its owner can fail (EPERM when the file belongs to someone else, a read-only filesystem) and the failure is ignored, so whatever is written next stays readable by others. Check the result and stop, or create the file with the restrictive mode from the start (open(..., 0600), os.open(..., 0o600))"

_fallback_msg := "When access to the intended location is refused the program silently switches to a broader one (the filesystem root, a shared /tmp path). Refuse to continue instead, or fall back to a private location created for this run (mkdtemp)"

_is_c(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# ── Shared block helpers ─────────────────────────────────────────────────

_indent(l) := count(l) - count(trim_left(l, " \t"))

_first_or(xs, d) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

_allman_open(l, 0) if trim_space(l) == "{"

# Indices of the lines of the block that line i opens (deeper indentation,
# a lone Allman `{` allowed first), comments excluded.
_block_idx(lines, i) := idx if {
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
	idx := [k | some k in numbers.range(i + 1, end); k < stop; not helpers.is_comment_line(lines[k])]
}

_block_idx(lines, i) := [] if i + 1 > count(lines) - 1

_block(lines, i) := concat("\n", [lines[k] | some k in _block_idx(lines, i)])

# ── Owner-only modes ─────────────────────────────────────────────────────

_owner_only_octal := `(^|[^\w.])0[oO]?[0-7]?[1-7]00\b`

_owner_only(args) if regex.match(_owner_only_octal, args)

_owner_only(args) if {
	regex.match(`\bS_I(RUSR|WUSR|XUSR|RWXU)\b`, args)
	not regex.match(`\bS_I\w*(GRP|OTH)\b|\bS_IRWX[GO]\b`, args)
}

_strip(line) := regex.replace(line, `"(\\.|[^"\\])*"|'(\\.|[^'\\])*'`, `""`)

# ── C / C++: unchecked restrictive chmod ─────────────────────────────────

_c_stmt_re := `^\s*(\(\s*void\s*\)\s*)?(::)?(chmod|fchmod|fchmodat)\s*\(`

_c_statement(lines, i) := s if {
	end := min([count(lines) - 1, i + 3])
	ends := [j | some j in numbers.range(i, end); contains(lines[j], ";")]
	count(ends) > 0
	s := split(concat(" ", array.slice(lines, i, ends[0] + 1)), ";")[0]
}

_consumed(stmt) if regex.match(`==|!=|<|>|&&|\|\||\?`, replace(stmt, "->", "."))

_continuation(lines, i) if {
	prev := [j | some j in numbers.range(max([0, i - 3]), i - 1); trim_space(lines[j]) != ""; not helpers.is_comment_line(lines[j])]
	count(prev) > 0
	regex.match(`([=(,!?&|<>+\-]|\breturn)\s*$`, trim_space(lines[prev[count(prev) - 1]]))
}

_errno_checked(lines, i) if {
	end := min([count(lines) - 1, i + 3])
	end >= i + 1
	some j in numbers.range(i + 1, end)
	regex.match(`\berrno\b`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "chmod")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_c_stmt_re, line)
	stmt := _strip(_c_statement(lines, i))
	_owner_only(stmt)
	not _consumed(stmt)
	not _continuation(lines, i)
	not _errno_checked(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _chmod_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── C / C++: failure branches that fall through or fall back ─────────────

_args := `\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_posix_fails(cond, subj) if regex.match(concat("", [subj, `\s*(!=\s*0\b|<\s*0\b|==\s*-\s*1\b|<=\s*-\s*1\b)`]), cond)

_posix_fails(cond, subj) if regex.match(concat("", [`(-\s*1\s*==|\b0\s*!=|\b0\s*>)\s*`, subj]), cond)

_posix_fails(cond, subj) if regex.match(concat("", [`(\bif\s*\(|&&|\|\|)\s*`, subj, `\s*(\)|&&|\|\|)`]), cond)

_if_re := `^\s*(\}\s*)?(else\s+)?if\s*\(`

_tail(line) := regex.replace(line, `^\s*(\}\s*)?(else\s+)?if\s*\((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*\)`, "")

# glibc's error()/error_at_line() exit when their status argument is not 0.
_c_stop := `\b(return|goto|break|continue|throw|exit|_exit|_Exit|quick_exit|abort|err|errx|verr|verrx|longjmp|siglongjmp|pthread_exit|ExitProcess|ExitThread|TerminateProcess)\b|\berror(_at_line)?\s*\(\s*(EXIT_\w+|[1-9]\d*)\s*,|(?i)\b\w*(fatal|die|panic|abort|bail|exit)\w*\s*\(`

# A restrictive chmod whose failure is tested: directly…
_chmod_fails(lines, i, code) if {
	some m in regex.find_all_string_submatch_n(concat("", [`\b(?:chmod|fchmod|fchmodat)`, _args]), code, -1)
	_owner_only(m[0])
	_posix_fails(code, concat("", [`\b(chmod|fchmod|fchmodat)`, _args]))
}

# …or through the result variable assigned just above.
_chmod_fails(lines, i, code) if {
	i > 0
	some j in numbers.range(max([0, i - 3]), i - 1)
	m := regex.find_all_string_submatch_n(`^\s*(?:[A-Za-z_][\w \t\*]*\s)?([A-Za-z_]\w*)\s*=\s*(?:::)?(?:chmod|fchmod|fchmodat)\s*\(`, lines[j], 1)
	count(m) > 0
	_owner_only(_strip(lines[j]))
	_posix_fails(code, concat("", [`\b`, m[0][1], `\b`]))
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "chmod")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_if_re, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	_chmod_fails(lines, i, code)
	not regex.match(_c_stop, concat("\n", [_tail(code), _block(lines, i)]))
	finding := {
		"rule_id": metadata.id,
		"message": _chmod_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A failed chdir into a directory that is not "/" which then goes to "/".
_chdir_root := `\bchdir\s*\(\s*"/"\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "chdir(\"/\")")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_if_re, line)
	not helpers.is_comment_line(line)
	_posix_fails(line, `\bchdir\s*\(\s*[^")\s](?:[^()]|\([^()]*\))*\)`)
	regex.match(_chdir_root, concat("\n", [_tail(line), _block(lines, i), line]))
	finding := {
		"rule_id": metadata.id,
		"message": _fallback_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Python ───────────────────────────────────────────────────────────────

_py_chmod := `\bos\.(fchmod|lchmod)\s*\(|\.chmod\s*\(`

_py_owner_only(line) if regex.match(`(^|[^\w.])0[oO][0-7]?[1-7]00\b`, line)

_py_owner_only(line) if {
	regex.match(`\bS_I(RUSR|WUSR|XUSR|RWXU)\b`, line)
	not regex.match(`\bS_I\w*(GRP|OTH)\b|\bS_IRWX[GO]\b`, line)
}

_py_catches := `^\s*except\s*(:|\(?[^:]*\b(OSError|PermissionError|IOError|EnvironmentError|Exception|BaseException)\b)`

_py_stop := `\b(raise|return|continue|break)\b|\bsys\.exit\s*\(|\bos\._exit\s*\(|\bos\.abort\s*\(|\b(exit|quit)\s*\(|(?i)\b\w*(fatal|die|abort)\w*\s*\(`

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

_py_clause(l, tind) if {
	_indent(l) == tind
	regex.match(`^\s*(except\b|else\s*:|finally\s*:)`, l)
}

# Handler lines of the try that directly encloses line i.
_py_handlers(lines, i) := hs if {
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
	hs := [h | some h in after; h < stop; regex.match(`^\s*except\b`, lines[h])]
}

_py_swallowed(lines, i) if {
	some h in _py_handlers(lines, i)
	regex.match(_py_catches, lines[h])
	body := concat("\n", [regex.replace(lines[h], `^[^:]*:`, ""), _block(lines, h)])
	not regex.match(_py_stop, body)
}

_py_swallowed(lines, i) if {
	o := _py_opener(lines, i)
	regex.match(`^\s*with\s+(contextlib\.)?suppress\s*\([^)]*\b(OSError|PermissionError|IOError|EnvironmentError|Exception|BaseException)\b`, lines[o])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "chmod")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_py_chmod, line)
	not helpers.is_comment_line(line)
	_py_owner_only(_strip(line))
	_py_swallowed(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _chmod_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A permission error handled by moving to a shared or broader location.
_py_fallback := `["']/tmp(/[^"']*)?["']|\btempfile\.gettempdir\s*\(|\bos\.chdir\s*\(\s*["']/["']\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	_has_any(content, {"/tmp", "gettempdir", "chdir"})
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some h, line in lines
	regex.match(`^\s*except\s*\(?[^:]*\b(PermissionError|OSError|IOError|EnvironmentError)\b`, line)
	some k in array.concat([h], _block_idx(lines, h))
	target := object.get({"t": regex.replace(lines[k], `^\s*except[^:]*:`, "")}, "t", "")
	regex.match(_py_fallback, target)
	finding := {
		"rule_id": metadata.id,
		"message": _fallback_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": lines[k],
	}
}

# ── Go ───────────────────────────────────────────────────────────────────

_go_owner_only := `(^|[^\w.])0[oO]?[0-7]?[1-7]00\b`

_go_stop := `\b(return|panic|break|continue|goto)\b|\bos\.Exit\s*\(|\.(Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)\s*\(|\bruntime\.Goexit\s*\(`

# A bare statement, or one assigned to the blank identifier.
_go_unchecked(lines, i, line) if {
	regex.match(`^\s*(_\s*=\s*)?[\w.]+\.Chmod\s*\(`, line)
	regex.match(_go_owner_only, _strip(line))
}

# `err := os.Chmod(p, 0600)` and then an `if err != nil {` whose body only
# logs.
_go_unchecked(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\s*:?=\s*[\w.]+\.Chmod\s*\(`, line, 1)
	count(m) > 0
	m[0][1] != "_"
	regex.match(_go_owner_only, _strip(line))
	k := helpers.next_code_index(lines, i, 3)
	regex.match(concat("", [`^\s*if\s+`, m[0][1], `\s*!=\s*nil\s*\{`]), lines[k])
	not regex.match(_go_stop, _block(lines, k))
}

# A permission error in particular is let through:
# `err != nil && !os.IsPermission(err)` / `!errors.Is(err, fs.ErrPermission)`.
_go_perm_ignored := `!=\s*nil\s*&&\s*!\s*(os\.IsPermission\s*\(|errors\.Is\s*\([^,]*,\s*(os|fs)\.ErrPermission\b)`

_go_unchecked(lines, i, line) if {
	regex.match(`^\s*if\s+\w+\s*:?=\s*[\w.]+\.Chmod\s*\(`, line)
	regex.match(_go_owner_only, _strip(line))
	regex.match(_go_perm_ignored, line)
}

_go_unchecked(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\s*:?=\s*[\w.]+\.Chmod\s*\(`, line, 1)
	count(m) > 0
	m[0][1] != "_"
	regex.match(_go_owner_only, _strip(line))
	k := helpers.next_code_index(lines, i, 3)
	regex.match(concat("", [`^\s*if\s+`, m[0][1], `\s*`, _go_perm_ignored]), lines[k])
}

# `if err := os.Chmod(p, 0600); err != nil {` whose body only logs.
_go_unchecked(lines, i, line) if {
	regex.match(`^\s*if\s+\w+\s*:?=\s*[\w.]+\.Chmod\s*\(.*;\s*\w+\s*!=\s*nil\s*\{`, line)
	regex.match(_go_owner_only, _strip(line))
	not regex.match(_go_stop, _block(lines, i))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "Chmod")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Chmod")
	not helpers.is_comment_line(line)
	_go_unchecked(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _chmod_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
