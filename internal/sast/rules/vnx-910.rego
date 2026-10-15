# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_910

import rego.v1

metadata := {
	"id": "VNX-910",
	"name": "Use of Expired File Descriptor",
	"description": "A C or C++ file descriptor, socket or FILE stream is used after it was closed in the same function. Reported on the use: after close(fd)/::close(fd)/closesocket(s)/fclose(fp)/pclose(fp) (including a close on a single-line if), a later line within 25 lines (a call split across lines is joined with up to three continuation lines) passes the same handle (fd, conn->fd, sock_, fp) to a descriptor or stream call: read/write/send/recv/fstat/fsync/lseek/ioctl/fcntl/dup/mmap/setsockopt/shutdown/accept..., fprintf/fwrite/fread/fgets/fputs/fflush/fseek/fileno..., or closes it again (double close). By then the number may already name a different file or socket opened by another thread, so the write lands in the wrong file and the second close closes someone else's descriptor. Not reported: the handle reassigned between the close and the use (fd = -1, fd = open(...), fp = NULL) or on the use line before the use (if ((fd = open(p, O_RDONLY)) < 0 || fstat(fd, &st))), a close followed by return/goto/break/continue/exit before the use (an error path that leaves), a use in the else branch of the close, a goto label between them, the close and the use in different functions, other handles (pipefd[0] vs pipefd[1]), comments and strings. Closes in loops reached again on the next iteration, and descriptors closed through a wrapper function, are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-910/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [910],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["use-of-expired-file-descriptor", "cwe-910", "use-after-close", "double-close"],
}

_is_c_family(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".c++"}
	endswith(path, ext)
}

_rng(a, b) := numbers.range(a, b) if a <= b

_rng(a, b) := [] if a > b

_indent(line) := count(line) - count(trim_left(line, " \t"))

# String and character literals and trailing comments removed.
_code(line) := regex.replace(regex.replace(line, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`), `/\*.*?\*/|//.*$`, "")

_comment(l) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$)|#)`, l)

_handle := `[A-Za-z_][\w]*(?:(?:->|\.)[A-Za-z_]\w*|\[[^\]]+\])*`

_close_re := concat("", [`^\s*(?:if\s*\(.*\)\s*)?(?:\(void\)\s*)?(?:::)?(close|fclose|pclose|closesocket)\s*\(\s*(`, _handle, `)\s*\)\s*;`])

_fd_calls := {"read", "write", "pread", "pwrite", "readv", "writev", "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg", "fstat", "fsync", "fdatasync", "ftruncate", "lseek", "ioctl", "fcntl", "dup", "dup2", "dup3", "close", "closesocket", "shutdown", "setsockopt", "getsockopt", "accept", "accept4", "listen", "bind", "connect", "mmap", "flock", "lockf", "fchmod", "fchown", "futimens", "fdopen", "fdopendir", "fstatfs", "posix_fadvise", "sendfile", "splice", "getpeername", "getsockname"}

_stream_calls := {"fprintf", "vfprintf", "fputs", "fputc", "putc", "fwrite", "fread", "fgets", "fgetc", "getc", "fscanf", "fflush", "fseek", "fseeko", "ftell", "ftello", "rewind", "feof", "ferror", "clearerr", "fileno", "fclose", "pclose", "setvbuf", "setbuf", "getline", "getdelim", "ungetc"}

_uses(callee, f) if {
	callee in {"close", "closesocket"}
	_fd_calls[f]
}

_uses(callee, f) if {
	callee in {"fclose", "pclose"}
	_stream_calls[f]
}

_call_re := `([A-Za-z_]\w*)\s*\(([^()]*)\)`

# Innermost calls, then the calls around them: [callee, [arg, ...]].
_calls(c) := array.concat(_calls1(c), _calls1(regex.replace(c, _call_re, " CALL ")))

_calls1(c) := [[m[1], [trim_space(a) | some a in split(m[2], ",")]] |
	some m in regex.find_all_string_submatch_n(_call_re, c, -1)
]

_uses_handle(c, callee, h) if {
	some [f, args] in _calls(c)
	_uses(callee, f)
	some a in args
	a == h
}

_reassigned(c, h) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(`, _handle, `)\s*=[^=]`]), c, -1)
	m[1] == h
}

# Between the close (i) and the use (u): something makes the use unreachable
# from the close, or the handle valid again.
_breaks(lines, i, u, h) if {
	some k in _rng(i + 1, u - 1)
	_stop(lines[k], _indent(lines[i]), h)
}

_stop(l, _, _) if startswith(l, "}")

_stop(l, ci, _) if {
	_indent(l) >= ci
	regex.match(`^\s*(?:return\b|goto\b|break\s*;|continue\s*;|(?:_?exit|abort|longjmp|siglongjmp)\s*\()`, l)
}

_stop(l, ci, _) if {
	_indent(l) < ci
	regex.match(`\belse\b`, l)
}

_stop(l, _, _) if regex.match(`^\s*[A-Za-z_]\w*\s*:\s*$`, l)

_stop(l, _, _) if regex.match(`^\s*case\b|^\s*default\s*:`, l)

_stop(l, _, h) if {
	contains(l, h)
	_reassigned(_code(l), h)
}

# The close itself ends the line's own path: `close(fd); return -1;`.
_stop_on_close_line(line) if regex.match(`;\s*(?:return\b|goto\b|break\s*;|continue\s*;)`, line)

findings contains finding if {
	some path, content in input.file_contents
	_is_c_family(path)
	contains(content, "close")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "close")
	m := regex.find_all_string_submatch_n(_close_re, _code(line), 1)
	count(m) > 0
	callee := m[0][1]
	h := m[0][2]
	not _stop_on_close_line(line)
	uses := [u |
		some u in _rng(i + 1, min([count(lines) - 1, i + 25]))
		contains(lines[u], h)
		not _comment(lines[u])
		c := _use_code(lines, u)
		_uses_handle(c, callee, h)
		not _reopened_first(c, h)
	]
	count(uses) > 0
	u := uses[0]
	not _breaks(lines, i, u, h)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is used after %s(%s): the descriptor number may already belong to another file or socket opened since, so this call reads, writes or closes the wrong one. Set the handle to -1/NULL after closing it and do not use it again", [h, callee, h]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": u + 1,
		"snippet": lines[u],
	}
}

# The use line, joined with up to three continuation lines when the call is
# split across lines (send(sock,\n buf, ...)).
_use_code(lines, u) := c if {
	c := _code(lines[u])
	count(indexof_n(c, "(")) <= count(indexof_n(c, ")"))
}

_use_code(lines, u) := c if {
	c0 := _code(lines[u])
	count(indexof_n(c0, "(")) > count(indexof_n(c0, ")"))
	hi := min([count(lines) - 1, u + 3])
	c := concat(" ", [_code(lines[k]) | some k in _rng(u, hi)])
}

# The line opens the handle again before using it:
# if ((fd = open(path, O_RDONLY)) < 0 || fstat(fd, &st) != 0).
_reopened_first(c, h) if {
	idx := indexof(c, h)
	idx >= 0
	regex.match(`^\s*=[^=]`, substring(c, idx + count(h), -1))
}
