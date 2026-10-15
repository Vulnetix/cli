# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_378

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-378",
	"name": "Creation of Temporary File With Insecure Permissions",
	"description": "A temporary file in C or C++ is created so that other local users can read it, write it or claim it first. Reported: the name-only temporary file functions tmpnam, tmpnam_r, tempnam, mktemp and the Windows _mktemp/_tempnam/_wtmpnam/_wmktemp (also qualified as std:: or ::), which return a name without creating the file, so the later open runs with default permissions on a path another user can pre-create; open() or creat() of a path in /tmp/, /var/tmp/ or /dev/shm/ (a literal, or a variable assigned one in the 10 lines above) with a mode that grants other users any access (an octal mode whose last digit is not 0, S_IRWXO, S_IROTH, S_IWOTH, S_IXOTH); fopen() for writing or appending (w, a, w+, a+; not the exclusive x) of a fixed name in those directories, with the path a literal or a variable assigned one or filled by snprintf/sprintf/strcpy in the 10 lines above (the file gets the umask default permissions and follows a planted symlink); and fchmod()/chmod() that opens up such a mode on a file descriptor or template just returned by mkstemp() in the 10 lines above. Not reported: mkstemp, mkostemp, mkdtemp and tmpfile, owner-only modes (0600, 0640, S_IRUSR|S_IWUSR), opens outside shared temporary directories, read-only opens, function declarations and prototypes (including a C++ member declared with one of these names), lookalike identifiers and members (my_mktemp, obj.mktemp(), p->mktemp(), obj.tmpnam_count), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-378/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [378],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["tempfile-insecure", "cwe-378"],
}

_c_file(path) if regex.match(`\.(?:c|h|cc|cpp|cxx|hpp|hh|hxx)$`, path)

# A name-only temp-file API call. The character before the name is not part
# of an identifier or a member access; `std::` and `::` qualify it.
_name_api_re := `(?:^|[^\w.>$])(?:std\s*)?(?:::\s*)?(_?w?mktemp|_?w?tmpnam(?:_r)?|_?tempnam)\s*\(`

# `char *mktemp(char *t);`, `extern char *tmpnam(char *s);`: a prototype.
_declaration(line) if regex.match(`^\s*(?:extern\s+)?(?:const\s+)?(?:unsigned\s+)?(?:char|int|void|wchar_t|errno_t)\s*\*?\s*\b(?:_?w?mktemp|_?w?tmpnam(?:_r)?|_?tempnam)\s*\([^)]*\)\s*;?\s*$`, line)

# A C++ member or function declared with a lookalike name:
# `std::string mktemp(const std::string &prefix);`.
_declaration(line) if {
	not regex.match(`^\s*(?:return|else|case|goto|throw|delete|co_return)\b`, line)
	regex.match(`^\s*(?:(?:static|extern|inline|virtual|const|unsigned|struct)\s+)*[A-Za-z_][\w:<>]*\s*[*&]*\s+[*&]*(?:_?w?mktemp|_?w?tmpnam(?:_r)?|_?tempnam)\s*\([^)]*\)\s*(?:const\s*)?(?:override\s*)?[;{]?\s*$`, line)
}

_unquote(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_tmp_literal_re := `"/(?:tmp|var/tmp|dev/shm)/[^"]*"`

# A mode granting other users access: octal with a non-zero last digit, or a
# symbolic other-bit.
_open_mode_re := `,\s*(?:0[0-7]{0,3}[1-7]\b|S_IRWXO|[^;]*\bS_I[RWX]OTH\b|[^;]*\|\s*S_IRWXO\b)[^,]*\)\s*;?`

_code_lines(lines, i, n) := concat(" ", array.slice(lines, i, min([count(lines), i + n])))

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`(?m)\b_?w?(?:mktemp|tmpnam|tempnam)`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`(?:mktemp|tmpnam|tempnam)`, raw)
	not helpers.is_comment_line(raw)
	line := _unquote(raw)
	m := regex.find_all_string_submatch_n(_name_api_re, line, 1)
	count(m) > 0
	not _declaration(line)
	not regex.match(`^\s*#\s*define\b`, line)
	finding := _finding(path, i, raw, sprintf("%s() returns a temporary file name without creating the file, so another local user can create it first or the file is opened with default permissions: use mkstemp() or tmpfile()", [m[0][1]]))
}

# open()/creat() of a shared-temp path with a mode other users can use.
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`(?m)"/(?:tmp|var/tmp|dev/shm)/`, content)
	regex.match(`(?m)\b(?:open|creat)\s*\(`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`(?:^|[^\w.>])(?:open|creat)\s*\(`, raw)
	not helpers.is_comment_line(raw)
	call := _code_lines(lines, i, 3)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.>])(?:open|creat)\s*\(\s*("[^"]*"|[A-Za-z_]\w*)`, call, 1)
	count(m) > 0
	_tmp_target(lines, i, m[0][1])
	regex.match(concat("", [`(?:open|creat)\s*\(`, `[^;]*?`, _open_mode_re]), call)
	not contains(call, "O_EXCL")
	finding := _finding(path, i, raw, "Temporary file in a shared directory is created with a mode that grants other users access: create it with mode 0600 (and O_EXCL), or use mkstemp()")
}

_tmp_target(_, _, arg) if regex.match(concat("", [`^`, _tmp_literal_re, `$`]), arg)

# `snprintf(path, sizeof path, "/tmp/%s.lock", name);` or strcpy(path, "/tmp/...").
_tmp_target(lines, i, arg) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(concat("", [`\b(?:sn?printf|strn?cpy|strlcpy|strcat)\s*\(\s*`, arg, `\s*,[^;]*`, _tmp_literal_re]), lines[j])
}

# fopen() of a fixed name in a shared temporary directory for writing: the file
# is created with the umask's default permissions (normally world-readable) and
# a symlink planted at the name is followed.
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`(?m)"/(?:tmp|var/tmp|dev/shm)/`, content)
	contains(content, "fopen")
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "fopen")
	not helpers.is_comment_line(raw)
	call := _code_lines(lines, i, 2)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.>])fopen\s*\(\s*("[^"]*"|[A-Za-z_]\w*)\s*,\s*"([^"]*)"`, call, 1)
	count(m) > 0
	regex.match(`^[wa]`, m[0][2])
	not contains(m[0][2], "x")
	_tmp_target(lines, i, m[0][1])
	finding := _finding(path, i, raw, "Fixed-name file in a shared temporary directory is created by fopen() with default permissions and follows a planted symlink: use mkstemp() and fdopen(), or a private directory")
}

_tmp_target(lines, i, arg) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(concat("", [`\b`, arg, `\s*(?:\[\s*\])?\s*=\s*`, _tmp_literal_re]), lines[j])
}

# fchmod/chmod widening a file just created by mkstemp().
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "mkstemp")
	contains(content, "chmod")
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "chmod")
	not helpers.is_comment_line(raw)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.>])f?chmod\s*\(\s*([A-Za-z_]\w*)\s*,\s*([^;]*)\)\s*;`, raw, 1)
	count(m) > 0
	_wide_mode(m[0][2])
	_from_mkstemp(lines, i, m[0][1])
	finding := _finding(path, i, raw, "Temporary file from mkstemp() is re-permissioned so other users can access it: keep it 0600")
}

_wide_mode(mode) if regex.match(`^\s*0[0-7]{0,3}[1-7]\s*$`, mode)

_wide_mode(mode) if regex.match(`\bS_I(?:RWXO|[RWX]OTH)\b`, mode)

# fd := mkstemp(t) or the template t passed to it, in the 10 lines above.
_from_mkstemp(lines, i, name) if {
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	contains(lines[j], "mkstemp")
	regex.match(concat("", [`\b`, name, `\s*=\s*mko?stemps?\s*\(`]), lines[j])
}

_from_mkstemp(lines, i, name) if {
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	contains(lines[j], "mkstemp")
	regex.match(concat("", [`mko?stemps?\s*\(\s*`, name, `\b`]), lines[j])
}

_finding(path, i, raw, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": raw,
}
