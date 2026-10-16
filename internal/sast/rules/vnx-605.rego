# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_605

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-605",
	"name": "Multiple Binds to the Same Port",
	"description": "Reports a socket option that lets a second socket bind the same port and steal or spoof the service's traffic: setsockopt(..., SO_REUSEPORT, ...) in C/C++ (including ::setsockopt and a call split over several lines), unix/syscall.SetsockoptInt(fd, ..., SO_REUSEPORT, <non-zero>) in Go (also with the arguments on the following lines), sock.setsockopt(..., SO_REUSEPORT, <non-zero>) and reuse_port=True in Python, and setsockopt(..., SO_REUSEADDR, ...) in a Winsock source file (winsock2.h/ws2tcpip.h/windows.h) that never sets SO_EXCLUSIVEADDRUSE, where SO_REUSEADDR lets any process bind over the listener. Not reported: SO_REUSEADDR on POSIX (it only permits reuse of TIME_WAIT addresses), Winsock files that also set SO_EXCLUSIVEADDRUSE, SO_REUSEPORT set to 0/False, getsockopt reads of the option, hasattr(socket, 'SO_REUSEPORT') probes, #ifdef SO_REUSEPORT and other preprocessor lines, the option name inside a string literal or a comment. An option value held in a variable that is zero is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-605/",
	"languages": ["c", "cpp", "go", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [605],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["multiple-binds-same-port", "cwe-605"],
}

_c_ext := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_is_c(path) if {
	some ext in _c_ext
	endswith(path, ext)
}

# The line with string literals and trailing comments removed.
_code(line) := c if {
	s := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)
	c := regex.replace(s, `//.*$|/\*.*?\*/`, "")
}

# The code of lines i-back .. i joined (strings and comments removed).
_window(lines, i, back) := concat(" ", [_code(lines[j]) |
	some j in numbers.range(max([0, i - back]), i)
	not helpers.is_comment_line(lines[j])
])

# The option on line i is an argument of a setsockopt( call that opens on this
# line or one of the two above: no ';' between the call and the option, so a
# finished setsockopt above a getsockopt does not count.
_in_setsockopt(lines, i, opt) if {
	regex.match(concat("", [`\bsetsockopt\s*\([^;]*\b`, opt, `\b`]), _window(lines, i, 2))
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_reuseport_msg := "SO_REUSEPORT lets another socket bind the same port and receive this service's connections; drop it or restrict the port to one owner"

# C / C++: SO_REUSEPORT passed to setsockopt.
findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "SO_REUSEPORT")
	contains(content, "setsockopt")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SO_REUSEPORT")
	not helpers.is_comment_line(line)
	regex.match(`\bSO_REUSEPORT\b`, _code(line))
	_in_setsockopt(lines, i, "SO_REUSEPORT")
	finding := _finding(path, i, line, _reuseport_msg)
}

# C / C++ on Windows: SO_REUSEADDR without SO_EXCLUSIVEADDRUSE.
findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "SO_REUSEADDR")
	regex.match(`(?mi)^\s*#\s*include\s*[<"](winsock2?|ws2tcpip|windows)\.h[>"]`, content)
	not contains(content, "SO_EXCLUSIVEADDRUSE")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SO_REUSEADDR")
	not helpers.is_comment_line(line)
	regex.match(`\bSO_REUSEADDR\b`, _code(line))
	_in_setsockopt(lines, i, "SO_REUSEADDR")
	finding := _finding(path, i, line, "On Windows SO_REUSEADDR lets another process bind over this listener; use SO_EXCLUSIVEADDRUSE instead")
}

# Go: SetsockoptInt(fd, level, SO_REUSEPORT, <non-zero>), including a call
# whose arguments continue on the lines after SetsockoptInt(.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "SO_REUSEPORT")
	contains(content, "Setsockopt")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SO_REUSEPORT")
	not helpers.is_comment_line(line)
	regex.match(`\bSO_REUSEPORT\b`, _code(line))
	end := min([count(lines) - 1, i + 3])
	after := [_code(lines[k]) | some k in numbers.range(i + 1, end); not helpers.is_comment_line(lines[k])]
	call := concat(" ", array.concat([_window(lines, i, 3)], after))
	regex.match(`\bSetsockopt(?:Int|Byte)?\s*\([^;{}]*\bSO_REUSEPORT\s*,\s*[^,)\s]+\s*,?\s*\)`, call)
	not regex.match(`\bSO_REUSEPORT\s*,\s*0\s*,?\s*\)`, call)
	finding := _finding(path, i, line, _reuseport_msg)
}

# Python: sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, <non-zero>) and asyncio /
# socketserver reuse_port=True.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`SO_REUSEPORT|reuse_port`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`SO_REUSEPORT|reuse_port`, line)
	not helpers.is_comment_line(line)
	not _in_triple_quote(lines, i)
	_py_reuseport(_pycode(line))
	finding := _finding(path, i, line, _reuseport_msg)
}

_pycode(line) := c if {
	s := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)
	c := regex.replace(s, `#.*$`, "")
}

# Line i sits inside a triple-quoted string (docstring) opened on an earlier
# line and not yet closed.
_in_triple_quote(lines, i) if {
	i > 0
	opens := [1 |
		some j in numbers.range(0, i - 1)
		some _ in regex.find_n(`"""|'''`, lines[j], -1)
	]
	count(opens) % 2 == 1
}

_py_reuseport(code) if {
	regex.match(`\.setsockopt\s*\([^)]*\bSO_REUSEPORT\s*,\s*[^,)\s]+\s*\)`, code)
	not regex.match(`\bSO_REUSEPORT\s*,\s*(?:0|False)\s*\)`, code)
}

_py_reuseport(code) if regex.match(`\breuse_port\s*=\s*True\b`, code)
