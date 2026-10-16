# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_170

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-170",
	"name": "Improper Null Termination",
	"description": "A C/C++ buffer is filled in a way that can leave it without a terminating NUL and nothing terminates it: strncpy(dst, src, n) with any count other than n - 1 (the full buffer, strlen(src), a variable or a constant), or with n - 1 into a buffer that was not zeroed (memset/bzero/= {0}/calloc/static storage), with no dst[...] = '\\0' (or *p = 0) within the next four lines; memcpy(dst, src, strlen(src)), or memcpy(dst, src, len) with len = strlen(src) a few lines above and unchanged, without a terminator after it; and read/readlink/recv/recvfrom/fread that fills a char array with sizeof(buf) bytes, after which the buffer is used as a string (strlen, strcmp, strstr, atoi/strtol, sscanf, printf %s, std::string, std::string s(buf)) within eight lines without buf[n] = '\\0'. Not reported: a string-literal source (for strncpy and memcpy), a length of strlen(src) + 1, a length that is clamped before the copy or returned/stored beside the bytes (a counted buffer such as an OpenSSL password callback), an n - 1 strncpy whose last byte was terminated just before it, strlcpy/snprintf, a read of sizeof(buf) - 1, a buffer only used as bytes, strncpy wrapper functions, strncat (which always terminates), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-170/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [170],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["null-termination", "memory", "cwe-170"],
}

_exts := {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}

_strncpy_re := `\bstrncpy\s*\(\s*([^,;]+?)\s*,\s*([^,;]+?)\s*,\s*([^;]+?)\)\s*;`

_memcpy_re := `\bmemcpy\s*\(\s*([^,;]+?)\s*,\s*([^,;]+?)\s*,\s*(?:std::)?strlen\s*\(\s*([^();]+?)\s*\)\s*\)\s*;`

_read_re := `\b(?:read|readlink|recv|recvfrom)\s*\(\s*[^,;]+,\s*&?\s*(\w+)\s*,\s*sizeof\s*\(?\s*(\w+)\s*\)?\s*[,)]`

_fread_re := `\bfread\s*\(\s*&?\s*(\w+)\s*,\s*[^,;]+,\s*sizeof\s*\(?\s*(\w+)\s*\)?\s*,`

# The statement starting on line i, joined with up to two continuation lines.
_stmt(lines, i) := s if {
	contains(lines[i], ";")
	s := lines[i]
}

_stmt(lines, i) := s if {
	not contains(lines[i], ";")
	s := concat(" ", array.slice(lines, i, min([count(lines), i + 3])))
}

_base(expr) := b if {
	ids := regex.find_n(`[A-Za-z_]\w*`, expr, -1)
	count(ids) > 0
	b := ids[count(ids) - 1]
}

_root(expr) := r if {
	ids := regex.find_n(`[A-Za-z_]\w*`, regex.replace(expr, `\(\s*(?:const\s+)?(?:unsigned\s+)?char\s*\*\s*\)`, ""), -1)
	count(ids) > 0
	r := ids[0]
}

_in_string(line, word) if {
	idx := indexof(line, word)
	idx >= 0
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	count(regex.find_n(`"`, pre, -1)) % 2 == 1
}

# A terminator for the destination within the next four lines.
_terminated(lines, i, dst) if {
	b := _base(dst)
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	# no comment check: `*p = '\0';` starts with the comment marker `*`
	regex.match(concat("", [`\b`, b, `\b[^;=]*=\s*(?:'\\0'|0|'\\x00'|NUL)\s*;`]), lines[j])
}

# The buffer is zero-filled before the copy, or has static storage.
_zeroed(lines, content, i, dst) if {
	r := _root(dst)
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(concat("", [`\b(?:memset|bzero|explicit_bzero)\s*\(\s*&?\(?\s*`, r, `\b|\b`, r, `\b[^;]*=\s*(?:\{\s*0?\s*\}|""|\(?[\w\s\*]*\)?\s*calloc\s*\()`]), l)
}

# The last byte was terminated before an n - 1 copy, which never writes it.
_zeroed(lines, _, i, dst) if {
	r := _root(dst)
	some j in numbers.range(max([0, i - 6]), i - 1)
	regex.match(concat("", [`\b`, r, `\s*\[[^\]]*-\s*1\s*\]\s*=\s*(?:'\\0'|0)\s*;`]), lines[j])
}

_zeroed(_, content, _, dst) if {
	b := _base(dst)
	regex.match(concat("", [`(?m)^(?:static\s+)?(?:unsigned\s+)?char\s+`, b, `\s*\[`]), content)
}

_wrapper(lines, i) if {
	some j in numbers.range(max([0, i - 6]), i - 1)
	regex.match(`\w+strncpy\w*\s*\(|\bstrncpy\w+\s*\(`, lines[j])
}

_minus_one(n) if regex.match(`-\s*1\s*$`, trim_space(n))

_strncpy_unterminated(lines, content, i, dst, src, n) if {
	not _minus_one(n)
	not regex.match(`strlen\s*\([^()]*\)\s*\+\s*1$`, trim_space(n))
	not _terminated(lines, i, dst)
}

_strncpy_unterminated(lines, content, i, dst, src, n) if {
	_minus_one(n)
	not _zeroed(lines, content, i, dst)
	not _terminated(lines, i, dst)
}

_string_use(l, buf) if {
	regex.match(concat("", [`\b(?:strlen|strcpy|strcat|strdup|strcmp|strncmp|strcasecmp|strstr|strchr|strrchr|atoi|atol|atoll|atof|strtol|strtoul|strtoll|strtoull|strtod|sscanf|puts|fputs|std::string)\s*\(\s*(?:[^(),;]+,\s*)?`, buf, `\b`]), l)
}

_string_use(l, buf) if {
	contains(l, "printf")
	contains(l, "%s")
	regex.match(concat("", [`,\s*`, buf, `\s*[,)]`]), l)
}

# std::string s(buf); std::string s = buf;
_string_use(l, buf) if regex.match(concat("", [`\bstd::string\s+\w+\s*(?:\(\s*|\{\s*|=\s*)`, buf, `\s*[)};]`]), l)

_string_use(l, buf) if regex.match(concat("", [`<<\s*`, buf, `\b\s*(?:<<|;)`]), l)

_char_array(lines, i, buf) if {
	some j in numbers.range(max([0, i - 60]), i - 1)
	regex.match(concat("", [`\bchar\s+(?:[^;]*[,\s\*])?`, buf, `\s*\[`]), lines[j])
}

_used_unterminated(lines, i, buf) if {
	some j in numbers.range(i, min([count(lines) - 1, i + 8]))
	l := lines[j]
	not helpers.is_comment_line(l)
	_string_use(l, buf)
	not _terminated_before(lines, i, j, buf)
}

_terminated_before(lines, i, j, buf) if {
	some k in numbers.range(i, j)
	regex.match(concat("", [`\b`, buf, `\s*\[[^\]]+\]\s*=`]), lines[k])
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

findings contains f if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	contains(content, "strncpy")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "strncpy")
	not helpers.is_comment_line(line)
	not _in_string(line, "strncpy")
	s := _stmt(lines, i)
	some m in regex.find_all_string_submatch_n(_strncpy_re, s, 1)
	not startswith(m[2], "\"")
	not _wrapper(lines, i)
	_strncpy_unterminated(lines, content, i, m[1], m[2], m[3])
	f := _finding(path, i, line, "strncpy leaves the destination without a NUL terminator when the source is as long as the count; terminate it (dst[size-1] = '\\0') or use strlcpy/snprintf")
}

findings contains f if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	contains(content, "memcpy")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "memcpy")
	contains(line, "strlen")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_memcpy_re, line, 1)
	trim_space(m[2]) == trim_space(m[3])
	not startswith(trim_space(m[2]), "\"")
	not _terminated(lines, i, m[1])
	f := _finding(path, i, line, "memcpy of strlen(src) bytes copies the string without its NUL terminator; copy strlen(src) + 1 bytes or terminate the destination")
}

_memcpy_var_re := `\bmemcpy\s*\(\s*([^,;]+?)\s*,\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)\s*;`

# len = strlen(src); (no + 1) a few lines above the copy, not changed since.
_strlen_len(lines, i, n, src) if {
	some j in numbers.range(max([0, i - 5]), i - 1)
	regex.match(concat("", [`\b`, n, `\s*=\s*(?:std::)?strlen\s*\(\s*`, src, `\s*\)\s*;`]), lines[j])
	not _len_adjusted(lines, j, i, n)
}

# The length travels with the bytes (returned, as an OpenSSL password
# callback does, or stored in a length field): a counted buffer, not a string.
_length_carried(lines, i, n) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	regex.match(concat("", [`\breturn\b[^;]*\b`, n, `\b|(?:len|length|size|_len)\w*\s*=\s*`, n, `\s*;`]), lines[k])
}

_len_adjusted(lines, j, i, n) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	regex.match(concat("", [`\b`, n, `\s*(?:[-+]?=[^=]|\+\+|--)`]), lines[k])
}

findings contains f if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	contains(content, "memcpy")
	contains(content, "strlen")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "memcpy")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_memcpy_var_re, line, 1)
	_strlen_len(lines, i, m[3], m[2])
	not _terminated(lines, i, m[1])
	not _length_carried(lines, i, m[3])
	f := _finding(path, i, line, "memcpy of strlen(src) bytes copies the string without its NUL terminator; copy strlen(src) + 1 bytes or terminate the destination")
}

findings contains f if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`\b(?:f?read|readlink|recv|recvfrom)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "sizeof")
	not helpers.is_comment_line(line)
	some re in [_read_re, _fread_re]
	some m in regex.find_all_string_submatch_n(re, line, 1)
	m[1] == m[2]
	_char_array(lines, i, m[1])
	_used_unterminated(lines, i, m[1])
	f := _finding(path, i, line, "The read fills the whole buffer, then the buffer is used as a string with no NUL terminator; read sizeof(buf) - 1 bytes and set buf[n] = '\\0'")
}
