# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_222

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-222",
	"name": "Truncation of Security-relevant Information",
	"description": "A bounded copy or format into a fixed-size buffer may silently cut the result short, the truncation is never checked, and the truncated buffer then decides something that matters: which file is opened, created, removed or executed, which command runs, which host is contacted, which name is compared in an authorisation check, or what the audit log records. A truncated path drops its suffix (\"%s/%s.txt\" becomes a path without the extension), a truncated user name can equal a privileged one, and a truncated log line loses the part an investigator needed. Reported in C and C++: a statement that discards the result of snprintf, vsnprintf, _snprintf, sprintf_s, strncpy, strncpy_s, strcpy_s, strlcpy, strncat, strlcat or g_strlcpy into an array declared in the same function, followed within twelve lines by that buffer passed to open/openat/fopen/freopen/creat, access/stat/lstat/realpath, unlink/remove/rename, chmod/chown/mkdir/rmdir/chdir/chroot/truncate, the exec family, system/popen, dlopen/LoadLibrary, syslog, connect/bind/getaddrinfo/gethostbyname, strcmp/strncmp/strcasecmp/memcmp, crypt, setenv/putenv, SSL_set_tlsext_host_name/X509_check_host, std::ifstream/ofstream/fstream or .open(); and a socket path copied into addr.sun_path of a sockaddr_un that is then passed to bind or connect. Not reported: a copy (not an append) of a string literal, a format that inserts no string, a call whose result is assigned or tested (n = snprintf(...); if (n >= sizeof buf)), a later comparison against sizeof or strlen(buf), a source length tested against the buffer size up to eight lines before the copy (if (strlen(path) >= sizeof(addr.sun_path)) return -1), buffers only displayed (printf, puts, UI calls), comments, strings and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-222/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [222],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["truncation", "buffer", "path", "cwe-222"],
}

_c_file(path) if {
	some e in {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp"}
	endswith(lower(path), e)
}

_needles := {"snprintf", "strncpy", "strlcpy", "strncat", "strlcat", "sprintf_s", "strcpy_s"}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# A statement whose value is discarded: the truncation it may report is lost.
_bounded := `^\s*(\(void\)\s*)?(std::)?(snprintf|vsnprintf|_snprintf|sprintf_s|strncpy|strncpy_s|strcpy_s|strlcpy|strncat|strlcat|g_strlcpy)\s*\(\s*&?\s*([A-Za-z_]\w*)\s*[,)]`

_sinks := `\b(open|openat|fopen|freopen|creat|access|faccessat|stat|lstat|realpath|unlink|unlinkat|remove|rename|chmod|chown|lchown|mkdir|rmdir|chdir|chroot|truncate|execl|execlp|execle|execv|execvp|execve|system|popen|dlopen|LoadLibrary\w*|syslog|connect|bind|getaddrinfo|gethostbyname|inet_pton|strcmp|strncmp|strcasecmp|strncasecmp|memcmp|crypt|setenv|putenv|SSL_set_tlsext_host_name|X509_check_host)\s*\([^;]*`

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	_has_any(content, _needles)
	not helpers.is_test_path(path)
	not regex.match(`(^|/)tests?_[^/]*\.(c|cc|cpp)$`, path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _needles)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_bounded, line, 1)
	count(m) > 0
	buf := m[0][4]
	_can_truncate(lines, i, m[0][3])
	_array_declared(lines, i, buf)
	j := _security_use(lines, i, buf)
	not _checked(lines, i, j, buf)
	not _prechecked(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Bounded write into '%s' can truncate silently, and the truncated value is then used for a security decision (file, command, host, comparison or audit log). Check the return value (n >= sizeof %s) and fail on truncation", [buf, buf]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A copy of a string can always truncate. A format can only when it inserts a
# string (%s) or takes its format from a variable; "%d" into a 256-byte buffer
# cannot.
_can_truncate(lines, i, fn) if {
	not contains(fn, "printf")
	not _literal_source(lines[i], fn)
}

# Copying a string literal into an empty buffer is a fixed size, not
# attacker-controlled input. Appending one (strncat/strlcat) still truncates
# when the buffer is already full.
_literal_source(line, fn) if {
	not endswith(fn, "_s")
	not contains(fn, "cat")
	regex.match(`\(\s*&?\s*[A-Za-z_][\w.>-]*\s*,\s*"`, line)
}

_literal_source(line, fn) if {
	endswith(fn, "_s")
	regex.match(`\(\s*&?\s*[A-Za-z_][\w.>-]*\s*,\s*[^,]+,\s*"`, line)
}

_can_truncate(lines, i, fn) if {
	contains(fn, "printf")
	txt := split(concat(" ", array.slice(lines, i, min([count(lines), i + 3]))), ";")[0]
	regex.match(`%[-+ #0-9.*]*l?s|printf\w*\s*\(\s*&?\s*\w+\s*,\s*[^,]+,\s*[A-Za-z_]\w*\s*[,)]`, txt)
}

_array_declared(lines, i, buf) if {
	some k in numbers.range(max([0, i - 40]), i)
	contains(lines[k], buf)
	regex.match(concat("", [`\b`, buf, `\s*\[[^\]]+\]\s*(;|=|,)`]), lines[k])
}

# The first line within 12 below that hands the buffer to a security-relevant
# call.
_security_use(lines, i, buf) := j if {
	last := min([count(lines) - 1, i + 12])
	uses := [k |
		some k in numbers.range(i + 1, last)
		l := lines[k]
		contains(l, buf)
		not helpers.is_comment_line(l)
		_uses(l, buf)
	]
	count(uses) > 0
	j := uses[0]
}

_uses(l, buf) if regex.match(concat("", [_sinks, `\b`, buf, `\b`]), l)

_uses(l, buf) if regex.match(concat("", [`\b(ifstream|ofstream|fstream)\s+\w+\s*[({]\s*`, buf, `\b|\.open\s*\(\s*`, buf, `\b`]), l)

# A comparison against the buffer size, or a length test on the buffer,
# between the write and the use.
_checked(lines, i, j, buf) if {
	some k in numbers.range(i + 1, j)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`sizeof[^;]*[<>]=?|[<>]=?\s*\(?\s*\w*\s*\)?\s*sizeof|\bstrn?len\s*\(\s*`, buf, `\b[^;]*(>=|==|>)|\btrunc`]), l)
}

# The source length tested against the buffer size up to eight lines before
# the copy: if (strlen(name) >= sizeof(buf)) return -1;
_prechecked(lines, i) if {
	some k in numbers.range(max([0, i - 8]), i - 1)
	k < i
	l := lines[k]
	contains(l, "sizeof")
	not helpers.is_comment_line(l)
	regex.match(`\bstrn?len\s*\([^;]*[<>]=?[^;]*\bsizeof\b|\bsizeof\b[^;]*[<>]=?[^;]*\bstrn?len\s*\(`, l)
}

# strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1); bind(fd, &addr, ...):
# a socket path cut short binds or connects to a different file.
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "sun_path")
	_has_any(content, _needles)
	not helpers.is_test_path(path)
	not regex.match(`(^|/)tests?_[^/]*\.(c|cc|cpp)$`, path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "sun_path")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*(\(void\)\s*)?(std::)?(snprintf|strncpy|strlcpy|strncat|strlcat|g_strlcpy|strcpy_s|strncpy_s)\s*\(\s*&?\s*([A-Za-z_]\w*)\s*(\.|->)\s*sun_path\s*,`, line, 1)
	count(m) > 0
	sa := m[0][4]
	_can_truncate(lines, i, m[0][3])
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 12]))
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\b(bind|connect)\s*\([^;]*\b`, sa, `\b`]), l)
	not _prechecked(lines, i)
	not _sun_checked(lines, i, j)
	finding := {
		"rule_id": metadata.id,
		"message": "A socket path copied into sun_path can truncate silently, so bind/connect uses a different, shorter path. Reject a path that does not fit (strlen(path) >= sizeof(addr.sun_path)) before copying",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_sun_checked(lines, i, j) if {
	some k in numbers.range(i + 1, j)
	regex.match(`sizeof[^;]*[<>]=?|[<>]=?[^;]*sizeof|\bstrn?len\s*\([^;]*(>=|==|>)`, lines[k])
	not regex.match(`\b(bind|connect)\s*\(`, lines[k])
}
