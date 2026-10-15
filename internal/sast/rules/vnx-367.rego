# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_367

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-367",
	"name": "Time-of-check Time-of-use (TOCTOU) Race Condition",
	"description": "A file is checked by name and then opened or changed by the same name within ten lines, in C or C++, so another process can swap the file (typically for a symlink) between the check and the use. Reported: access(), eaccess() or euidaccess() on a path followed by any open, open64, fopen, freopen, creat, chmod, chown, lchown, truncate or exec* of that path (the access-then-open setuid race); and stat(), lstat(), stat64() or lstat64() on a path followed by a write or permission change on it: open with O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND, fopen with a w/a/+ mode, creat, chmod, chown, lchown or truncate. The same check and use on one line count. The path may be a variable, a member, a std::string's c_str() or a literal. Flags are read from the call's own statement, including continuation lines. Not reported: open with O_EXCL or O_NOFOLLOW, a read after a stat (a write flag of a later call does not count), a check and a use in different functions (a closing brace at column 0 between them), fstat/fchmod on a descriptor (the safe form), a check and a use on different paths, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-367/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [367],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["toctou", "race-condition", "cwe-367"],
}

_exts := {".c", ".cc", ".cpp", ".cxx"}

_window := 10

_arg := `([A-Za-z_][\w\.]*(?:->[\w\.]+)*(?:\(\))?|"[^"\n]*")`

_check_re := concat("", [`(?:^|[^\w\.>])(?:::)?(access|eaccess|euidaccess|stat|lstat|stat64|lstat64)\(\s*`, _arg, `\s*,`])

_use_re := concat("", [`(?:^|[^\w\.>])(?:::)?(open|open64|fopen|fopen64|freopen|creat|chmod|chown|lchown|truncate|execv|execve|execvp|execl|execlp)\(\s*`, _arg, `\s*[,\)]`])

_access_fns := {"access", "eaccess", "euidaccess"}

# Write or permission change, judged on the call's own text (flags may wrap
# onto the next line).
_writes("creat", _) := true

_writes("chmod", _) := true

_writes("chown", _) := true

_writes("lchown", _) := true

_writes("truncate", _) := true

_writes(fn, text) if {
	fn in {"open", "open64"}
	regex.match(`O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)`, text)
}

_writes(fn, text) if {
	fn in {"fopen", "fopen64", "freopen"}
	regex.match(`fopen(?:64)?\([^,]*,\s*"[rb]*[wa+]|freopen\([^,]*,\s*"[rb]*[wa+]`, text)
}

_safe(text) if regex.match(`O_EXCL|O_NOFOLLOW`, text)

# Blank string literals that are prose (more than a path's worth of words),
# so a message quoting the race is not code. A literal path stays.
_code(line) := regex.replace(line, `"[^"\n]*\s[^"\n]*"`, `""`)

# The checks of a file as [line index, function, path], found from a cheap
# substring test so most lines are never matched against a pattern.
_checks(lines) := {[j, m[1], m[2]] |
	some j, l in lines
	_check_word(l)
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_check_re, _code(l), -1)
}

_check_word(l) if contains(l, "stat(")

_check_word(l) if contains(l, "stat64(")

_check_word(l) if contains(l, "access(")

# A function body closes (a brace at column 0) between the check and the use:
# they are in different functions.
_fn_end_between(lines, j, i) if {
	some k in numbers.range(j + 1, i)
	startswith(lines[k], "}")
}

# The statement that starts on line i: the line itself, or up to two more
# lines while its parentheses are still open (flags wrapped onto the next
# line), so a flag of a later call is never read as this call's.
_open_parens(t) if count(indexof_n(t, "(")) > count(indexof_n(t, ")"))

_stmt(lines, i) := lines[i] if not _open_parens(lines[i])

_stmt(lines, i) := t if {
	_open_parens(lines[i])
	t := concat(" ", array.slice(lines, i, i + 2))
	not _open_parens(t)
}

_stmt(lines, i) := concat(" ", array.slice(lines, i, i + 3)) if {
	_open_parens(lines[i])
	_open_parens(concat(" ", array.slice(lines, i, i + 2)))
}

_qualifies(fn, _, cfn) if {
	cfn in _access_fns
	fn != ""
}

_qualifies(fn, text, cfn) if {
	not cfn in _access_fns
	_writes(fn, text)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	_check_word(content)
	lines := split(content, "\n")
	some c in _checks(lines)
	some i in numbers.range(c[0], min([count(lines) - 1, c[0] + _window]))
	line := lines[i]
	contains(line, "(")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_use_re, _code(line), -1)
	m[2] == c[2]
	fn := m[1]
	not _fn_end_between(lines, c[0], i)
	text := _stmt(lines, i)
	not _safe(text)
	_qualifies(fn, text, c[1])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s(%s) uses a path that was checked by name just above: the file can be replaced (for example with a symlink) between the check and the use. Open once and check the descriptor (fstat), or use O_EXCL/O_NOFOLLOW; never use access() to authorise an open", [fn, c[2]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
