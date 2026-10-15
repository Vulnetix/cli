# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_362

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-362",
	"name": "Check-then-use race on a file path (TOCTOU)",
	"description": "A file path is checked and then used by name a few lines later, so another process can replace the file (typically with a symlink) between the check and the use. Reported in Python: os.path.exists/isfile/lexists(p) or a pathlib p.exists()/p.is_file() followed within eight lines by a write or permission change on the same path (open(p, 'w'/'a'/'r+'), os.open(p, ...O_CREAT/O_WRONLY/O_RDWR...) without O_EXCL, os.chmod/os.chown, p.write_text/p.write_bytes/p.open('w'), shutil.copy/copy2/copyfile/move with p as the destination), and os.access(p, ...) followed by any open of p (the access check is the classic setuid TOCTOU). Reported in Go: os.Stat/os.Lstat(p) followed by os.Create, os.WriteFile/ioutil.WriteFile, os.Chmod/os.Chown/os.Truncate or os.OpenFile with a write or create flag and no O_EXCL on the same path, and syscall/unix.Access(p) followed by any open of p. A use whose call wraps over lines is read as one statement, so a path or a flag on a continuation line counts. Not reported: exclusive creation (mode 'x', O_EXCL, also on a continuation line), a check and a use in different functions (a def or func line between them), an os.OpenFile read whose next statement creates another file, os.makedirs/os.MkdirAll, a plain read after an existence check, a check and a use on different paths, a Go Lstat that tests ModeSymlink (VNX-363 covers that), comments, strings and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-362/",
	"languages": ["go", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [362],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["race-condition", "toctou", "cwe-362"],
}

_window := 8

_arg := `([A-Za-z_][\w\.]*(?:\[[^\]\n]*\])?)`

# ── Python ──────────────────────────────────────────────────────────────

_py_exists_res := [
	concat("", [`\bos\.path\.(?:exists|isfile|lexists)\(\s*`, _arg, `\s*\)`]),
	concat("", [`\b`, _arg, `\.(?:exists|is_file)\(\)`]),
]

_py_access_re := concat("", [`\bos\.access\(\s*`, _arg, `\s*,`])

_py_write_res := [
	concat("", [`\bopen\(\s*`, _arg, `\s*,\s*(?:mode\s*=\s*)?[rbu]?["'][rbt]*[wa+][rwab+t]*["']`]),
	concat("", [`\bos\.(?:chmod|chown|lchown|truncate)\(\s*`, _arg, `\s*,`]),
	concat("", [`\b`, _arg, `\.(?:write_text|write_bytes)\(`]),
	concat("", [`\b`, _arg, `\.open\(\s*(?:mode\s*=\s*)?["'][rbt]*[wa+]`]),
	concat("", [`\bshutil\.(?:copy|copy2|copyfile|move)\(\s*[^,()]+,\s*`, _arg, `\s*[,\)]`]),
]

_py_os_open_re := concat("", [`\bos\.open\(\s*`, _arg, `\s*,`])

_py_any_open_res := [
	concat("", [`(?:^|[^\w\.])open\(\s*`, _arg, `\s*[,\)]`]),
	concat("", [`\bos\.open\(\s*`, _arg, `\s*,`]),
	concat("", [`\bio\.open\(\s*`, _arg, `\s*[,\)]`]),
]

_py_write_uses(line) := {u |
	some re in _py_write_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	u := m[1]
}

_py_uses(line) := _py_write_uses(line) | _py_os_open_uses(line)

_py_os_open_uses(line) := {u |
	some m in regex.find_all_string_submatch_n(_py_os_open_re, line, -1)
	regex.match(`O_(?:CREAT|WRONLY|RDWR|TRUNC|APPEND)`, line)
	not contains(line, "O_EXCL")
	u := m[1]
}

# The statement that starts on line i: the line itself, or up to two more
# lines while its parentheses are still open (a call wrapped over lines).
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

# A function boundary between the check and the use: they are not one flow.
_boundary(lines, j, i, re) if {
	some k in numbers.range(j + 1, i)
	regex.match(re, lines[k])
}

_py_access_uses(line) := {u |
	some re in _py_any_open_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	u := m[1]
}

_py_checked(lines, i, target) if {
	some j in numbers.range(max([0, i - _window]), i)
	l := lines[j]
	contains(l, "os.path.")
	not helpers.is_comment_line(l)
	some re in _py_exists_res
	some m in regex.find_all_string_submatch_n(re, _code(l), -1)
	m[1] == target
	not _boundary(lines, j, i, _py_def_re)
}

_py_checked(lines, i, target) if {
	some j in numbers.range(max([0, i - _window]), i)
	l := lines[j]
	regex.match(`\.(?:exists|is_file)\(\)`, l)
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_py_exists_res[1], _code(l), -1)
	m[1] == target
	not _boundary(lines, j, i, _py_def_re)
}

_py_access_checked(lines, i, target) if {
	some j in numbers.range(max([0, i - _window]), i)
	l := lines[j]
	contains(l, "os.access(")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_py_access_re, _code(l), -1)
	m[1] == target
	not _boundary(lines, j, i, _py_def_re)
}

_py_def_re := `^\s*(?:async\s+)?def\s`

_go_func_re := `^func\s`

# String literals are not code; keep the quotes so a mode argument survives.
_code(line) := regex.replace(line, `"(?:[^"\\\n]|\\.){8,}"|'(?:[^'\\\n]|\\.){8,}'`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`os\.path\.(?:exists|isfile|lexists)\(|\.(?:exists|is_file)\(\)|os\.access\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`open\(|os\.ch|os\.lchown|os\.truncate|\.write_(?:text|bytes)\(|shutil\.(?:copy|move)`, line)
	not helpers.is_comment_line(line)
	code := _code(_stmt(lines, i))
	some target in _py_uses(code)
	_py_checked(lines, i, target)
	finding := _finding(path, i, line, target)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "os.access(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "open(")
	not helpers.is_comment_line(line)
	code := _code(_stmt(lines, i))
	some target in _py_access_uses(code)
	_py_access_checked(lines, i, target)
	finding := _finding(path, i, line, target)
}

# ── Go ──────────────────────────────────────────────────────────────────

_go_stat_re := concat("", [`\bos\.(?:Stat|Lstat)\(\s*`, _arg, `\s*\)`])

_go_access_re := concat("", [`\b(?:syscall|unix)\.Access\(\s*`, _arg, `\s*,`])

_go_write_re := concat("", [`\b(?:os|ioutil)\.(?:Create|WriteFile|Chmod|Chown|Lchown|Truncate)\(\s*`, _arg, `\s*[,\)]`])

_go_openfile_re := concat("", [`\bos\.OpenFile\(\s*`, _arg, `\s*,`])

_go_any_open_re := concat("", [`\bos\.(?:Open|OpenFile|ReadFile|Create|WriteFile)\(\s*`, _arg, `\s*[,\)]`])

_go_uses(lines, i) := _go_write_uses(lines, i) | _go_openfile_uses(lines, i)

_go_write_uses(lines, i) := {u |
	some m in regex.find_all_string_submatch_n(_go_write_re, lines[i], -1)
	u := m[1]
}

_go_openfile_uses(lines, i) := {u |
	some m in regex.find_all_string_submatch_n(_go_openfile_re, lines[i], -1)
	flags := _stmt(lines, i)
	regex.match(`O_(?:CREATE|WRONLY|RDWR|TRUNC|APPEND)`, flags)
	not contains(flags, "O_EXCL")
	u := m[1]
}

_go_checked(lines, i, target) if {
	some j in numbers.range(max([0, i - _window]), i)
	l := lines[j]
	contains(l, "tat(")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_go_stat_re, l, -1)
	m[1] == target
	not _symlink_test(lines, j)
	not _boundary(lines, j, i, _go_func_re)
}

_go_checked(lines, i, target) if {
	some j in numbers.range(max([0, i - _window]), i)
	l := lines[j]
	contains(l, "Access(")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_go_access_re, l, -1)
	m[1] == target
	not _boundary(lines, j, i, _go_func_re)
}

# An Lstat whose result is tested for ModeSymlink is the link-following
# check of VNX-363.
_symlink_test(lines, j) if {
	some k in numbers.range(j, min([count(lines) - 1, j + 5]))
	contains(lines[k], "ModeSymlink")
}

_go_access_use(lines, i, target) if {
	some m in regex.find_all_string_submatch_n(_go_any_open_re, lines[i], -1)
	m[1] == target
	some j in numbers.range(max([0, i - _window]), i)
	contains(lines[j], "Access(")
	not helpers.is_comment_line(lines[j])
	some a in regex.find_all_string_submatch_n(_go_access_re, lines[j], -1)
	a[1] == target
	not _boundary(lines, j, i, _go_func_re)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	regex.match(`os\.L?[Ss]tat\(|\.Access\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:os|ioutil)\.(?:Create|WriteFile|Chmod|Chown|Lchown|Truncate|OpenFile)\(`, line)
	not helpers.is_comment_line(line)
	some target in _go_uses(lines, i)
	_go_checked(lines, i, target)
	finding := _finding(path, i, line, target)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, ".Access(")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`os\.(?:Open|ReadFile)\(`, line)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_go_any_open_re, line, -1)
	target := m[1]
	_go_access_use(lines, i, target)
	finding := _finding(path, i, line, target)
}

_finding(path, i, line, target) := {
	"rule_id": metadata.id,
	"message": sprintf("'%s' is checked and then used by name: the file can be swapped (for example with a symlink) between the check and the use. Open it once (exclusive create with O_EXCL / mode 'x', or O_NOFOLLOW) and act on the open handle", [target]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
