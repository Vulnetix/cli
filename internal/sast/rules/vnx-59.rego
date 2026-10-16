# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_59

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-59",
	"name": "Improper Link Resolution Before File Access ('Link Following')",
	"description": "A file is written or re-permissioned through a path another local user can plant a symbolic link at, so the write lands wherever the link points. Reported: a fixed, predictable name in a shared world-writable directory (/tmp/, /var/tmp/, /dev/shm/, or a join of tempfile.gettempdir()/os.TempDir() with a literal name, inline in the call or in a variable), given as a literal or through a variable filled from one in the 10 lines above, that is opened for writing without exclusive or no-follow semantics (C/C++ fopen with a w/a/+ mode and no x, open() with write/create flags and neither O_EXCL nor O_NOFOLLOW, creat(), std::ofstream; Python open()/io.open() with a w/a/+ mode, os.open() with write flags and no O_EXCL/O_NOFOLLOW, Path.write_text/write_bytes/touch; Go os.Create, os/ioutil.WriteFile, os.OpenFile with write flags and no O_EXCL), or passed to chmod/chown (which follow links); in C/C++, an access() or lstat() check of a path followed within 10 lines by open()/fopen() of the same path (the link can be swapped between the two calls); and in Go, os.Readlink on a request, flag or os.Args value. Not reported: mkstemp/NamedTemporaryFile/CreateTemp/MkdirTemp names, O_EXCL or O_NOFOLLOW opens, Python mode x, reads, writes outside shared temporary directories, test code, comments and strings. In C/C++, a fixed name in a shared temporary directory created by fopen() with a w/a mode (no x) or by open()/creat() with a mode that grants other users access and no O_EXCL is reported by VNX-378, not here; VNX-59 keeps the C/C++ r+ opens, owner-only modes without O_EXCL, chmod/chown, std::ofstream and the check-then-open race.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-59/",
	"languages": ["c", "cpp", "go", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [59],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["symlink", "tocttou", "file", "cwe-59"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "go" if endswith(path, ".go")

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── Fixed names in shared temporary directories ──────────────────────────

# A string literal naming a file in a world-writable directory.
_shared_lit := `f?["'\x60](?:/tmp|/var/tmp|/dev/shm)/[^"'\x60]*["'\x60]`

# A temporary-directory join with a literal file name.
_tempdir_join := `(tempfile\.gettempdir\(\)|os\.TempDir\(\)|["']/tmp["'])\s*,\s*f?["'\x60]`

# A temporary-directory join written inline as the argument.
_inline_join := `(?:filepath\.Join|path\.Join|os\.path\.join)\(\s*(?:tempfile\.gettempdir\(\)|os\.TempDir\(\))\s*,\s*["'\x60][^"'\x60]*["'\x60]\s*\)`

# The argument is the literal, an inline temp-dir join, or a variable.
_arg := concat("", [`(`, _shared_lit, `|`, _inline_join, `|[A-Za-z_]\w*)`])

_write_sink := {
	"c": [
		concat("", [`(?:^|[^\w.>])(?:std::)?fopen\s*\(\s*`, _arg, `\s*,\s*"[^"x]*[wa+][^"x]*"`]),
		concat("", [`(?:^|[^\w.>])open\s*\(\s*`, _arg, `\s*,\s*[^)]*\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)\b`]),
		concat("", [`(?:^|[^\w.>])creat\s*\(\s*`, _arg]),
		concat("", [`(?:^|[^\w.>])(?:chmod|chown)\s*\(\s*`, _arg]),
		concat("", [`\bofstream\s+\w+\s*\(\s*`, _arg]),
	],
	"py": [
		concat("", [`(?:^|[^\w.]|\bio\.|\bcodecs\.)open\s*\(\s*`, _arg, `\s*,\s*(?:mode\s*=\s*)?["'][^"'x]*[wa+][^"'x]*["']`]),
		concat("", [`\bos\.open\s*\(\s*`, _arg, `\s*,\s*[^)]*\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)\b`]),
		concat("", [`\bPath\s*\(\s*`, _arg, `\s*\)\s*\.\s*(?:write_text|write_bytes|touch)\s*\(`]),
		concat("", [`\b(?:os|shutil)\.(?:chmod|chown)\s*\(\s*`, _arg]),
	],
	"go": [
		concat("", [`\bos\.Create\s*\(\s*`, _arg]),
		concat("", [`\b(?:os|ioutil)\.WriteFile\s*\(\s*`, _arg]),
		concat("", [`\bos\.OpenFile\s*\(\s*`, _arg, `\s*,\s*[^)]*\bO_(?:WRONLY|RDWR|CREATE|TRUNC|APPEND)\b`]),
		concat("", [`\bos\.(?:Chmod|Chown)\s*\(\s*`, _arg]),
	],
}

_sink_needles := {
	"c": {"fopen", "open(", "creat(", "chmod(", "chown(", "ofstream"},
	"py": {"open(", "Path(", "chmod(", "chown("},
	"go": {"os.Create(", "WriteFile(", "os.OpenFile(", "os.Chmod(", "os.Chown("},
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# Exclusive creation or refusing links defeats the planted link.
_exclusive(line) if regex.match(`\bO_(EXCL|NOFOLLOW)\b`, line)

_shared_target(_, _, lit) if regex.match(concat("", ["^", _shared_lit, "$"]), lit)

_shared_target(_, _, j) if regex.match(concat("", ["^", _inline_join, "$"]), j)

# A variable filled from a shared-directory name in the 10 lines above.
_shared_target(lines, i, v) if {
	regex.match(`^[A-Za-z_]\w*$`, v)
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	contains(prev, v)
	not helpers.is_comment_line(prev)
	regex.match(concat("|", [_shared_lit, _tempdir_join]), prev)
	not contains(prev, "XXXXXX")
	not regex.match(`(?i)mkstemp|mkdtemp|CreateTemp|MkdirTemp|NamedTemporaryFile`, prev)
	_fills(prev, v)
}

_fills(prev, v) if helpers.assigned_first(prev) == v

_fills(prev, v) if regex.match(concat("", [`\b(s?n?printf|strn?cpy|strn?cat|strlcpy|strlcat)\s*\(\s*`, v, `\b`]), prev)

# C declarations: char *p = "/tmp/..."; char p[] = "/tmp/...";
_fills(prev, v) if regex.match(concat("", [`(^|[\s*])`, v, `\s*(\[[^\]]*\])?\s*=[^=]`]), prev)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	_has_any(content, {"/tmp", "/dev/shm", "gettempdir", "TempDir()"})
	_has_any(content, _sink_needles[lang])
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _sink_needles[lang])
	not helpers.is_comment_line(line)
	not _exclusive(line)
	some re in _write_sink[lang]
	some m in regex.find_all_string_submatch_n(re, line, 1)
	# the call itself is code, not text inside a string
	_has_any(_code(line), _sink_needles[lang])
	arg := _sink_arg(m)
	_shared_target(lines, i, arg)
	not _vnx378_reports(lang, content, lines, i)
	finding := _finding(path, i, line, "A fixed file name in a shared temporary directory is written (or chmod/chown'ed) without exclusive creation or O_NOFOLLOW. Another local user can create a symbolic link at that name first and the write lands on the file it points to. Create the file with mkstemp/NamedTemporaryFile/os.CreateTemp, or open with O_CREAT|O_EXCL (O_NOFOLLOW) in a private directory")
}

# ── C/C++ temporary-file creation belongs to VNX-378 ─────────────────────
#
# A C/C++ fopen() for writing or appending (no x) and an open()/creat() with a
# mode that grants other users access (no O_EXCL), of a fixed name in a shared
# temporary directory, is VNX-378's finding (insecure temporary file creation),
# the C-specific form of the same defect. These mirror VNX-378's conditions, so
# the line is still reported, once. VNX-59 keeps what VNX-378 does not read:
# r+ opens, owner-only modes without O_EXCL, creat/open with no mode, chmod,
# chown and std::ofstream.

_tmp378 := `"/(?:tmp|var/tmp|dev/shm)/[^"]*"`

_vnx378_target(_, _, arg) if regex.match(concat("", [`^`, _tmp378, `$`]), arg)

_vnx378_target(lines, i, arg) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(concat("", [`\b(?:sn?printf|strn?cpy|strlcpy|strcat)\s*\(\s*`, arg, `\s*,[^;]*`, _tmp378]), lines[j])
}

_vnx378_target(lines, i, arg) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(concat("", [`\b`, arg, `\s*(?:\[\s*\])?\s*=\s*`, _tmp378]), lines[j])
}

_vnx378_reports("c", content, lines, i) if {
	regex.match(`(?m)"/(?:tmp|var/tmp|dev/shm)/`, content)
	call := concat(" ", array.slice(lines, i, min([count(lines), i + 2])))
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.>])fopen\s*\(\s*("[^"]*"|[A-Za-z_]\w*)\s*,\s*"([^"]*)"`, call, 1)
	count(m) > 0
	regex.match(`^[wa]`, m[0][2])
	not contains(m[0][2], "x")
	_vnx378_target(lines, i, m[0][1])
}

_vnx378_reports("c", content, lines, i) if {
	regex.match(`(?m)"/(?:tmp|var/tmp|dev/shm)/`, content)
	regex.match(`(?:^|[^\w.>])(?:open|creat)\s*\(`, lines[i])
	call := concat(" ", array.slice(lines, i, min([count(lines), i + 3])))
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.>])(?:open|creat)\s*\(\s*("[^"]*"|[A-Za-z_]\w*)`, call, 1)
	count(m) > 0
	_vnx378_target(lines, i, m[0][1])
	regex.match(`(?:open|creat)\s*\([^;]*?,\s*(?:0[0-7]{0,3}[1-7]\b|S_IRWXO|[^;]*\bS_I[RWX]OTH\b|[^;]*\|\s*S_IRWXO\b)[^,]*\)\s*;?`, call)
	not contains(call, "O_EXCL")
}

# Every other group in the sink patterns is non-capturing: the one capture is
# the path argument.
_sink_arg(m) := m[1]

# ── C: check-then-open on the same path ──────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "c"
	not helpers.is_test_path(path)
	contains(content, "access(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "access(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(^|[^\w.>])(access|lstat)\s*\(\s*([A-Za-z_][\w>.-]*)\s*,`, line, 1)
	count(m) > 0
	v := m[0][3]
	_opened_after(lines, i, v)
	finding := _finding(path, i, line, "The path is checked with access()/lstat() and then opened by name: between the two calls the file can be replaced by a symbolic link, so the open acts on a different file than the one checked. Open first (with O_NOFOLLOW) and check the descriptor with fstat(), or drop privileges instead of using access()")
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "c"
	not helpers.is_test_path(path)
	contains(content, "lstat(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "lstat(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(^|[^\w.>])(lstat)\s*\(\s*([A-Za-z_][\w>.-]*)\s*,`, line, 1)
	count(m) > 0
	v := m[0][3]
	_opened_after(lines, i, v)
	finding := _finding(path, i, line, "The path is checked with lstat() and then opened by name: between the two calls the file can be replaced by a symbolic link, so the open acts on a different file than the one checked. Open first with O_NOFOLLOW and check the descriptor with fstat()")
}

_opened_after(lines, i, v) if {
	re := concat("", [`(^|[^\w.>])f?open\s*\(\s*`, regex.replace(v, `([.>-])`, `\$1`), `\s*,`])
	some j in numbers.range(i, min([count(lines) - 1, i + 10]))
	regex.match(re, lines[j])
	not helpers.is_comment_line(lines[j])
	not _exclusive(lines[j])
}

# ── Go: Readlink of an untrusted path ────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "os.Readlink(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "os.Readlink(")
	not helpers.is_comment_line(line)
	_untrusted_arg(lines, i, line)
	finding := _finding(path, i, line, "os.Readlink is given a path from the request or the command line: the caller learns where any link on the server points, and a program that then follows the target lets them steer it. Resolve with filepath.EvalSymlinks and check the result stays inside the allowed root")
}

# The Readlink argument comes from outside the program: a request value, a
# command-line argument, or a variable assigned from one. Resolving a path the
# program found itself (a directory walk, a known install location) is not a
# traversal primitive.
_untrusted := `(\b(r|req|request)\.(FormValue|PostFormValue|URL\.Query\(\)\.Get|Header\.Get)\(|os\.Args|\bflag\.(String|Arg)|\.Query\(\)\.Get\(|Getenv\()`

_untrusted_arg(_, _, line) if regex.match(_untrusted, line)

_untrusted_arg(lines, i, line) if {
	some v in helpers.tainted_names(lines, i, 20, _untrusted)
	regex.match(concat("", [`\b`, v, `\b`]), line)
}
