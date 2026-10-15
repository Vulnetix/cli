# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_626

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-626",
	"name": "Request input with an appended file extension used as a file path (null byte truncation)",
	"description": "Reports a file path built from request input followed by a fixed extension, where the extension is what restricts the file type: include/require, fopen, file_get_contents, readfile, file, show_source, highlight_file, parse_ini_file, file_put_contents, copy or unlink in PHP, and new File/FileInputStream/FileReader/FileOutputStream/FileWriter/RandomAccessFile, Paths.get or Path.of in Java, with $_GET/$_POST/$_REQUEST/$_COOKIE, the client-controlled $_SERVER keys (HTTP_*, QUERY_STRING, PATH_INFO, REQUEST_URI, PHP_SELF), request.getParameter/getHeader or a Spring @RequestParam/@PathVariable String parameter (inline, interpolated as \"dir/{$_GET['p']}.php\", through a variable assigned a few lines above, or through a variable whose assignment already appended the suffix) concatenated before a '.ext' literal. A runtime that hands the path to C stops at a NUL byte, so name=../../etc/passwd%00 drops the suffix (PHP before 5.3.4, Java before 7u40, and native extensions on any version); even where NUL is rejected, the suffix is no allow-list. Not reported: $_SERVER['DOCUMENT_ROOT'] and other server-set keys, input passed through basename(), an int cast or intval(), a preg_replace() that strips a negated character class, Integer/Long parse or valueOf and UUID.fromString in Java, str_replace(chr(0), ...), or checked with in_array/preg_match/ctype_*/is_numeric/String.matches/FilenameUtils.getName between the read and the use; paths with no appended extension (path traversal and file inclusion rules cover those; PHP includes also overlap VNX-98); constants; comments and string literals. Python, Ruby, Go and Node.js reject NUL in paths and are not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-626/",
	"languages": ["php", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [626],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["null-byte", "path-traversal", "cwe-626"],
}

_php_ext := {".php", ".phtml", ".inc", ".php5", ".php7"}

# $_SERVER only for the keys the client controls (not DOCUMENT_ROOT, SCRIPT_FILENAME)
_superglobal := `(\$_(GET|POST|REQUEST|COOKIE)\b|\$_SERVER\s*\[\s*['"](HTTP_\w+|QUERY_STRING|PATH_INFO|REQUEST_URI|PHP_SELF)['"]\s*\])`

# one element of request data: $_GET['page'], $_SERVER['HTTP_X']
_sg_elem := `(\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]|\$_SERVER\s*\[\s*['"](HTTP_\w+|QUERY_STRING|PATH_INFO|REQUEST_URI|PHP_SELF)['"]\s*\])`

_php_sink := `(^|[^\w$>:])((include|include_once|require|require_once)\b|(fopen|file_get_contents|readfile|file|show_source|highlight_file|parse_ini_file|file_put_contents|copy|unlink)\s*\()`

_php_guard := `preg_replace\s*\(\s*['"][^'"]*\[\^|basename\s*\(|\(\s*int\s*\)|intval\s*\(|in_array\s*\(|preg_match\s*\(|ctype_\w+\s*\(|is_numeric\s*\(|array_key_exists\s*\(|chr\s*\(\s*0\s*\)|\\0|\\x00`

_java_sink := `new\s+(File|FileInputStream|FileReader|FileOutputStream|FileWriter|RandomAccessFile)\s*\(|\bPaths\.get\s*\(|\bPath\.of\s*\(`

_java_source := `\b(request|req)\.(getParameter|getHeader)\s*\(|@RequestParam|@PathVariable`

_java_guard := `(Integer|Long|Short)\.(parse\w+|valueOf)\s*\(|UUID\.fromString\s*\(|\.matches\s*\(|Pattern\.|FilenameUtils\.getName\s*\(|\.getFileName\s*\(|\\0|\\u0000|indexOf\s*\(\s*'\\0'`

_suffix := `\s*\.\s*['"][^'"$]*\.[A-Za-z0-9]{1,8}['"]`

_strip_strings(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

_message := "A file path is built from request input with a fixed extension appended; a NUL byte (%00) in the input truncates the path at the C level and drops the suffix. Validate the name against an allow-list (or basename() plus a strict pattern) instead of relying on the extension"

_has_ext(path, exts) if {
	some ext in exts
	endswith(path, ext)
}

# ── PHP ────────────────────────────────────────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path, _php_ext)
	regex.match(_superglobal, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_php_sink, _strip_strings(line))
	_php_tainted_suffix(lines, i, line)
	finding := _finding(path, i, line)
}

# include($_GET['page'] . '.php')
_php_tainted_suffix(_, _, line) if {
	# outside single quotes (double quotes interpolate)
	regex.match(_superglobal, regex.replace(line, `'(?:[^'\\]|\\.)*'`, `''`))
	_php_inline_suffix(line)
	not regex.match(_php_guard, line)
}

# $p = $_GET['p']; include "dir/$p.php"; / include $dir . $p . '.php';
_php_tainted_suffix(lines, i, line) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*\$(\w+)\s*=\s*[^;]*`, _superglobal]), prev, 1)
	count(m) > 0
	v := m[0][1]
	not regex.match(_php_guard, prev)
	_php_var_suffix(line, v)
	not _php_guarded(lines, j + 1, i, v)
}

_php_var_suffix(line, v) if regex.match(concat("", [`\$`, v, `\b`, _suffix]), line)

_php_var_suffix(line, v) if regex.match(concat("", [`"[^"]*(\$`, v, `|\{\$`, v, `\})\.[A-Za-z0-9]{1,8}\b[^"]*"`]), line)

_php_guarded(lines, a, i, v) if {
	a <= i
	some k in numbers.range(a, i)
	regex.match(concat("", [`\$`, v, `\b`]), lines[k])
	regex.match(_php_guard, lines[k])
}

# ── Java ───────────────────────────────────────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_java_source, content)
	regex.match(_java_sink, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_java_sink, line)
	_java_tainted_suffix(lines, i, line)
	finding := _finding(path, i, line)
}

_java_tainted_suffix(_, _, line) if {
	regex.match(`\b(request|req)\.(getParameter|getHeader)\s*\([^)]*\)\s*\+\s*"[^"]*\.[A-Za-z0-9]{1,8}"`, line)
	not regex.match(_java_guard, line)
}

_java_tainted_suffix(lines, i, line) if {
	some v in helpers.tainted_names(lines, i, 20, _java_source)
	regex.match(concat("", [`\b`, v, `\s*\+\s*"[^"]*\.[A-Za-z0-9]{1,8}"`]), line)
	not _java_guarded(lines, i, v)
}

_java_guarded(lines, i, v) if {
	some k in numbers.range(max([0, i - 20]), i)
	regex.match(concat("", [`\b`, v, `\b`]), lines[k])
	regex.match(_java_guard, lines[k])
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# $_GET['p'] . '.php'
_php_inline_suffix(line) if regex.match(concat("", [_sg_elem, _suffix]), line)

# "modules/{$_REQUEST['mod']}.inc.php" / "pages/$_GET[page].php"
_php_inline_suffix(line) if {
	regex.match(concat("", [`"[^"]*(\{`, _sg_elem, `\}|\$_(GET|POST|REQUEST|COOKIE)\[\w+\])\.[A-Za-z0-9]{1,8}\b[^"]*"`]), line)
}

# $file = 'reports/' . $_GET['r'] . '.pdf'; ... readfile($file);
_php_tainted_suffix(lines, i, line) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, prev, 1)
	count(m) > 0
	_php_inline_suffix(prev)
	not regex.match(_php_guard, prev)
	v := m[0][1]
	regex.match(concat("", [`\$`, v, `\b`]), _strip_strings(line))
	not regex.match(concat("", [`\$`, v, `\b\s*\.`]), line)
	not _php_guarded(lines, j + 1, i, v)
}

# Spring handler parameters: @RequestParam("name") String name, @PathVariable String id
_java_param_names(lines, i) := {m[4] |
	some k in numbers.range(max([0, i - 20]), i)
	some m in regex.find_all_string_submatch_n(`@(RequestParam|PathVariable)(\([^)]*\))?\s+(final\s+)?String\s+(\w+)`, lines[k], -1)
}

_java_tainted_suffix(lines, i, line) if {
	some v in _java_param_names(lines, i)
	regex.match(concat("", [`\b`, v, `\s*\+\s*"[^"]*\.[A-Za-z0-9]{1,8}"`]), line)
	not _java_guarded(lines, i, v)
}
