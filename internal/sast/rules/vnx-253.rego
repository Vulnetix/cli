# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_253

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-253",
	"name": "Incorrect Check of Function Return Value",
	"description": "A C or C++ return value is tested against the wrong failure value, so the error path never runs and the failure goes unnoticed. Reported: a pointer-returning call (malloc, calloc, realloc, strdup, strndup, fopen, fdopen, popen, tmpfile, fgets, getenv, opendir, readdir) compared with < 0, <= -1 or == -1, directly or through the variable it was assigned to (they return NULL on failure); an mmap() result compared with NULL or tested with ! (mmap returns MAP_FAILED, not NULL); a file descriptor from open/openat/creat/socket/accept/accept4/dup/dup2/dup3/eventfd/epoll_create tested with !fd or == NULL (they return -1, and 0 is a valid descriptor); a pthread_* result compared with == -1 or < 0 (they return a positive error number); and the result of read/write/recv/recvfrom/recvmsg/send/sendto/sendmsg/pread/pwrite/readlink/getline/getdelim/snprintf stored in an unsigned variable (size_t, unsigned, uintN_t, DWORD), declared on the same line or up to 30 lines above, and then compared with < 0 or == -1, which can never be true. The variable is followed for six code lines after the assignment. Not reported: the correct checks (== NULL, == MAP_FAILED, < 0 on a signed descriptor or ssize_t, != 0 on a pthread result), tests of functions that cannot fail, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-253/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [253],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["return-check", "error-handling", "cwe-253"],
}

_c_file(path) if regex.match(`\.(c|cc|cpp|cxx)$`, path)

# The line with string literals blanked, so text inside quotes cannot match.
_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_ptr_fns := `malloc|calloc|realloc|strdup|strndup|fopen|fdopen|popen|tmpfile|fgets|getenv|opendir|readdir`

_fd_fns := `open|openat|creat|socket|accept|accept4|dup|dup2|dup3|eventfd|epoll_create1?`

_ssize_fns := `read|write|recv|recvfrom|recvmsg|send|sendto|sendmsg|pread|pwrite|readlink|getline|getdelim|snprintf`

_negative := `\s*(?:<\s*0\b|<=\s*-1\b|==\s*-1\b)`

# ── A wrong test written on the call itself ─────────────────────────────

_direct_re := concat("|", [
	concat("", [`\b(?:`, _ptr_fns, `)\s*\([^;]*?\)\s*\)?`, _negative]),
	`\bpthread_\w+\s*\([^;]*?\)\s*\)?\s*(?:==\s*-1\b|<\s*0\b)`,
	`\bmmap(?:64)?\s*\([^;]*?\)\s*\)?\s*==\s*(?:NULL|0)\b`,
])

_direct_msg := "Return value compared with the wrong failure value: pointer functions return NULL, mmap returns MAP_FAILED, pthread functions return a positive error number"

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`(fopen|malloc|calloc|realloc|strdup|strndup|fdopen|popen|tmpfile|fgets|getenv|opendir|readdir|pthread_|mmap)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`<\s*0|-1\b|NULL|==\s*0\b`, line)
	not helpers.is_comment_line(line)
	regex.match(_direct_re, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": _direct_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── A wrong test of the variable the result was assigned to ─────────────

_decl_prefix := `^\s*(?:(?:const|static|struct|unsigned|signed|register)\s+)*(?:[A-Za-z_]\w*\s*\*?\s+\**)?`

_assign_re("ptr") := concat("", [_decl_prefix, `\(?\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(?:std::)?(?:`, _ptr_fns, `)\s*\(`])

_assign_re("mmap") := concat("", [_decl_prefix, `([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?mmap(?:64)?\s*\(`])

_assign_re("fd") := concat("", [_decl_prefix, `([A-Za-z_]\w*)\s*=\s*(?:::)?(?:`, _fd_fns, `)\s*\(`])

_assign_re("pthread") := concat("", [_decl_prefix, `([A-Za-z_]\w*)\s*=\s*pthread_\w+\s*\(`])

_assign_re("unsigned") := concat("", [
	`^\s*(?:const\s+)?(?:size_t|unsigned(?:\s+(?:int|long\s+long|long|short|char))?|uint(?:8|16|32|64)_t|u_int(?:8|16|32|64)?_t|DWORD|UINT|ULONG)\s+`,
	`([A-Za-z_]\w*)\s*=\s*(?:::)?(?:`, _ssize_fns, `)\s*\(`,
])

_bad_check("ptr", v) := concat("", [`\b`, v, _negative])

_bad_check("unsigned", v) := concat("", [`\b`, v, _negative])

_bad_check("mmap", v) := concat("", [`\b`, v, `\s*==\s*(?:NULL|0)\b|\b(?:NULL|0)\s*==\s*`, v, `\b|!\s*`, v, `\b\s*\)`])

_bad_check("fd", v) := concat("", [`\b`, v, `\s*==\s*NULL\b|\bNULL\s*==\s*`, v, `\b|\(\s*!\s*`, v, `\s*\)`])

_bad_check("pthread", v) := concat("", [`\b`, v, `\s*(?:==\s*-1\b|<\s*0\b)`])

_good_check("mmap", _) := `MAP_FAILED`

_good_check("fd", v) := concat("", [`\b`, v, `\s*(?:<\s*0|==\s*-1|<=\s*-1|>=\s*0|!=\s*-1)`])

_msg("ptr") := "A pointer result is compared with a negative value; these functions return NULL on failure, so this check never fires"

_msg("unsigned") := "The result is stored in an unsigned variable, so the < 0 / == -1 failure check can never be true; store it in ssize_t (or int)"

_msg("mmap") := "mmap() returns MAP_FAILED, not NULL, on failure; compare the result with MAP_FAILED"

_msg("fd") := "A file descriptor is tested as if it were a pointer; these calls return -1 on failure and 0 is a valid descriptor, so test fd < 0"

_msg("pthread") := "pthread functions return a positive error number on failure, never -1; test the result with != 0"

_kinds := {"ptr", "mmap", "fd", "pthread", "unsigned"}

_next_codes(lines, i) := [k |
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
	trim_space(lines[k]) != ""
	not helpers.is_comment_line(lines[k])
]

_reassigned(lines, i, j, v) if {
	i + 1 <= j - 1
	some k in numbers.range(i + 1, j - 1)
	regex.match(concat("", [`^\s*`, v, `\s*=[^=]`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`(?m)(?:<\s*0|==\s*-1|<=\s*-1|NULL|!\s*\w+\s*\))`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	regex.match(_any_call, line)
	not helpers.is_comment_line(line)
	some kind in _kinds
	m := regex.find_all_string_submatch_n(_assign_re(kind), line, 1)
	count(m) > 0
	v := m[0][1]
	ks := _next_codes(lines, i)
	some j in array.slice(ks, 0, 6)
	regex.match(_bad_check(kind, v), _code(lines[j]))
	not _reassigned(lines, i, j, v)
	not _has_good(kind, lines, i, ks, v)
	not regex.match(_direct_re, _code(lines[j]))
	finding := {
		"rule_id": metadata.id,
		"message": _msg(kind),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

# `size_t n;` declared a few lines above, then `n = read(...)` and `n < 0`.
_unsigned_type := `(?:size_t|unsigned(?:\s+(?:int|long\s+long|long|short|char))?|uint(?:8|16|32|64)_t|u_int(?:8|16|32|64)?_t|DWORD|UINT|ULONG)`

_bare_ssize_assign := concat("", [`^\s*([A-Za-z_]\w*)\s*=\s*(?:::)?(?:`, _ssize_fns, `)\s*\(`])

_declared_unsigned(lines, i, v) if {
	some k in numbers.range(max([0, i - 30]), i - 1)
	regex.match(concat("", [`^\s*(?:const\s+|static\s+)?`, _unsigned_type, `\s+(?:[\w\s,=]*,\s*)?`, v, `\s*[;,=]`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`(?m)^\s*(?:const\s+|static\s+)?(?:size_t|unsigned|uint\d+_t|u_int\w*|DWORD|UINT|ULONG)\b`, content)
	regex.match(`(?m)(?:<\s*0|==\s*-1|<=\s*-1)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	m := regex.find_all_string_submatch_n(_bare_ssize_assign, line, 1)
	count(m) > 0
	v := m[0][1]
	_declared_unsigned(lines, i, v)
	ks := _next_codes(lines, i)
	some j in array.slice(ks, 0, 6)
	regex.match(_bad_check("unsigned", v), _code(lines[j]))
	not _reassigned(lines, i, j, v)
	finding := {
		"rule_id": metadata.id,
		"message": _msg("unsigned"),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

_has_good(kind, lines, i, ks, v) if {
	some k in array.concat([i], array.slice(ks, 0, 6))
	regex.match(_good_check(kind, v), lines[k])
}

# Every function the assignment kinds above follow, as one cheap line filter.
_any_call := `\b(?:malloc|calloc|realloc|strdup|strndup|fopen|fdopen|popen|tmpfile|fgets|getenv|opendir|readdir|mmap|mmap64|open|openat|creat|socket|accept|accept4|dup|dup2|dup3|eventfd|epoll_create1?|pthread_\w+|read|write|recv|recvfrom|recvmsg|send|sendto|sendmsg|pread|pwrite|readlink|getline|getdelim|snprintf)\s*\(`
