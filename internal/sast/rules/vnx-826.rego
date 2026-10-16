# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_826

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-826",
	"name": "Premature Release of Resource During Expected Lifetime",
	"description": "Reports a C or C++ handle that is released while the code below still uses it: fclose/pclose of a FILE* followed by stdio on the same stream (fprintf, fputs, fwrite, fread, fgets, fseek, fflush, ...), close/closesocket of a descriptor followed by read/write/send/recv/lseek/fstat/ioctl/setsockopt/shutdown and the other descriptor calls on it, closedir followed by readdir, sqlite3_close followed by sqlite3_exec/prepare/errmsg on the same connection, and CloseHandle followed by ReadFile/WriteFile/WaitForSingleObject on the same handle. The release line is reported when such a use of the same variable or member (fp, c->fd) follows within 15 lines in the same function, including a call whose argument list continues on the next line. Not reported: a release followed by return, goto, break, continue, exit/abort or throw before the use (error paths), a variable reassigned or reopened in between (fp = fopen(...), fd = -1, fd = accept(...)), a use on another if/else or switch branch, uses in another function (including the next inline method of a class body), method calls (file.close(), s->close()), array elements (close(pipefd[1])), freed memory (use after free() is VNX-C-004 and VNX-416), double release (VNX-1341), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-826/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [826],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["premature-release", "cwe-826", "c", "cpp", "resource-lifetime"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

# Code with string literals emptied and trailing comments removed.
_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$|/\*.*?\*/`, "")

_gate := `(?:^|[^\w.>])(?:std)?(?:::)?(?:fclose|pclose|close|closesocket|closedir|sqlite3_close(?:_v2)?|CloseHandle)\s*\(`

_release_re := `(?:^|[^\w.>:])(?:std::|::)?(fclose|pclose|closesocket|closedir|sqlite3_close_v2|sqlite3_close|CloseHandle|close)\s*\(\s*([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*\)`

# The calls that use each kind of handle.
_uses := {
	"stdio": `fprintf|vfprintf|fputs|fputc|putc|fwrite|fread|fgets|fgetc|getc|ungetc|fscanf|fseek|fseeko|ftell|ftello|rewind|fflush|feof|ferror|clearerr|fileno|setvbuf|setbuf|fgetpos|fsetpos|getline|getdelim`,
	"fd": `read|write|pread|pwrite|readv|writev|send|recv|sendto|recvfrom|sendmsg|recvmsg|lseek|fstat|fsync|fdatasync|ftruncate|fchmod|fchown|ioctl|fcntl|setsockopt|getsockopt|shutdown|getsockname|getpeername|listen|accept|accept4|bind|connect|dup|dup2|flock|SSL_set_fd`,
	"dir": `readdir|readdir_r|rewinddir|telldir|seekdir|dirfd`,
	"sqlite": `sqlite3_exec|sqlite3_prepare|sqlite3_prepare_v2|sqlite3_prepare_v3|sqlite3_errmsg|sqlite3_errcode|sqlite3_changes|sqlite3_last_insert_rowid|sqlite3_busy_timeout`,
	"win": `ReadFile|WriteFile|ReadFileEx|WriteFileEx|WaitForSingleObject|WaitForSingleObjectEx|GetFileSize|GetFileSizeEx|SetFilePointer|SetFilePointerEx|FlushFileBuffers|DeviceIoControl|GetExitCodeProcess|TerminateProcess|ResumeThread`,
}

_kind("fclose") := "stdio"

_kind("pclose") := "stdio"

_kind("close") := "fd"

_kind("closesocket") := "fd"

_kind("closedir") := "dir"

_kind("sqlite3_close") := "sqlite"

_kind("sqlite3_close_v2") := "sqlite"

_kind("CloseHandle") := "win"

_esc(v) := replace(v, ".", `\.`)

# A line that leaves the path or starts another branch.
_breaks_path(code) if regex.match(`(?:^|[^\w])(?:return|goto|break|continue|throw|exit|_exit|abort|longjmp|siglongjmp)\b`, code)

_breaks_path(code) if regex.match(`^\s*(?:\}\s*)?(?:else\b|case\b|default\s*:)|^\s*#\s*(?:if|else|elif|endif)`, code)

# The function ends.
_breaks_path(code) if regex.match(`^\}`, code)

# Another function starts: an inline method in a class body, whose closing
# brace is indented.
_breaks_path(code) if {
	contains(code, "(")
	_fn_header(code)
}

_fn_header_re := `^\s*(?:(?:[\w:<>,*&~]+\s+)+[*&]*\s*[A-Za-z_~][\w:~]*|[A-Za-z_]\w*::~?[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const|noexcept|override|final|\s)*(?:->\s*[\w:<>*&]+\s*)?(?:\{|$)`

_fn_header(code) if {
	regex.match(_fn_header_re, code)
	not regex.match(`^\s*(?:return|if|for|while|switch|else|do|case|delete|new|throw|goto|sizeof|co_\w+)\b`, code)
}

# The variable is given a new value or handed out by address.
_reassigned(code, v) if regex.match(concat("", [`(?:^|[^\w.>])`, _esc(v), `\s*=[^=]`]), code)

_reassigned(code, v) if regex.match(concat("", [`&\s*`, _esc(v), `\b`]), code)

_use_re(kind, v) := concat("", [`(?:^|[^\w.>])(?:std::|::)?(?:`, _uses[kind], `)\s*\((?:[^;]*[(,])?\s*`, _esc(v), `\s*[,)]`])

# The first line after i that uses v, before the path ends or v is reset.
_use_line(lines, i, kind, v) := j if {
	n := count(lines)
	cands := [k |
		some k in numbers.range(i + 1, min([i + 15, n - 1]))
		not _is_comment(lines[k])
		code := _strip(_joined(lines, k, n))
		regex.match(_use_re(kind, v), code)
	]
	count(cands) > 0
	j := min(cands)
	not _interrupted(lines, i, j, v)
}

# A call whose argument list continues on the next line.
_joined(lines, k, n) := concat(" ", [lines[k], lines[k + 1]]) if {
	k + 1 < n
	not contains(lines[k], ";")
	not contains(lines[k], "{")
} else := lines[k]

_interrupted(lines, i, j, v) if {
	some k in helpers.span(i + 1, j - 1)
	k > i
	k < j
	code := _strip(lines[k])
	not _is_comment(lines[k])
	_stops(code, v)
}

_interrupted(lines, i, j, v) if {
	_stops(_after_release(_strip(lines[i]), v), v)
}

# A one-line function body: void shut() { close(rd); }
_interrupted(lines, i, _, v) if {
	code := _strip(lines[i])
	contains(_after_release(code, v), "}")
	before := split(code, "{")[0]
	_fn_header(concat("", [before, "{"]))
}

_stops(code, _) if _breaks_path(code)

_stops(code, v) if _reassigned(code, v)

# The part of the release line after the release call itself.
_after_release(code, v) := tail if {
	parts := split(code, concat("", [v, ")"]))
	count(parts) > 1
	tail := concat(")", array.slice(parts, 1, count(parts)))
} else := ""

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "lose")
	not _is_comment(line)
	code := _strip(line)
	some m in regex.find_all_string_submatch_n(_release_re, code, -1)
	kind := _kind(m[1])
	v := m[2]
	j := _use_line(lines, i, kind, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s(%s) releases the handle, but line %d still uses %s; release it after its last use, or reopen it and assign the new handle first", [m[1], v, j + 1, v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
