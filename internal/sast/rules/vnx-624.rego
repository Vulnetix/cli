# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_624

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-624",
	"name": "Regular expression replacement evaluated as code (preg_replace /e, s///ee)",
	"description": "Reports regular-expression replacements that execute the replacement as code, and patterns a client controls (which can add that modifier). PHP: preg_replace() whose literal pattern carries the /e modifier (any delimiter: /.../e, #...#ie, ~...~sie), including a pattern inside an array(...)/[...] first argument, a pattern on the line after a preg_replace( that breaks the call, and a $pattern = '/.../e' assignment later passed to preg_replace($pattern, ...), mb_ereg_replace()/mb_eregi_replace() with an 'e' option, and preg_replace() whose pattern argument contains a request superglobal (bare, concatenated as '/' . $_POST['find'] . '/' or interpolated as \"/{$_GET['t']}/\") or is a variable assigned from one a few lines above, unless preg_quote() escapes it (on PHP before 7 the caller can append /e; on any version they choose the pattern). Perl: a substitution with the double-eval modifier (s/.../.../ee, after =~ or on $_ at the start of a statement), which evaluates the result of the replacement string as Perl. Not reported: preg_replace_callback(), patterns with ordinary modifiers (i, s, m, u, x), user input passed only as the subject, Perl's single /e (the replacement is code the author wrote), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-624/",
	"languages": ["php", "perl"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [624],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["regex-error", "code-injection", "cwe-624"],
}

_php_ext := {".php", ".phtml", ".inc", ".php5", ".php7"}

_perl_ext := {".pl", ".pm", ".cgi", ".t"}

_has_ext(path, exts) if {
	some ext in exts
	endswith(path, ext)
}

_superglobal := `\$_(GET|POST|REQUEST|COOKIE|SERVER)\b`

_close("(") := ")"

_close("{") := "}"

_close("[") := "]"

_close("<") := ">"

_close(d) := d if not d in {"(", "{", "[", "<"}

_message_php := "The regular-expression replacement is evaluated as PHP code (or the client controls the pattern and can make it so). Use preg_replace_callback() with a fixed pattern"

_message_perl := "s///ee evaluates the result of the replacement as Perl code. Use a lookup (s/\\$(\\w+)/$vars{$1}/g) or a single /e on code you wrote"

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── PHP ────────────────────────────────────────────────────────────────────
_php_call := `preg_replace\s*\(|mb_eregi?_replace\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path, _php_ext)
	regex.match(_php_call, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`preg_replace|mb_eregi?_replace|['"]`, line)
	not helpers.is_comment_line(line)
	not _call_in_string(line)
	_php_exec(lines, i, line)
	finding := _finding(path, i, line, _message_php)
}

# The call name is text inside a string literal: an odd number of quotes of
# one kind precede it on the line.
_call_in_string(line) if {
	parts := regex.split(`preg_replace|mb_eregi?_replace`, line)
	count(parts) > 1
	prefix := parts[0]
	_odd(prefix, "\"")
}

_call_in_string(line) if {
	parts := regex.split(`preg_replace|mb_eregi?_replace`, line)
	count(parts) > 1
	prefix := parts[0]
	_odd(prefix, "'")
}

_odd(s, q) if (count(split(s, q)) - 1) % 2 == 1

_lit_re := `'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"`

_literals(s) := [concat("", [x[1], x[2]]) | some x in regex.find_all_string_submatch_n(_lit_re, s, -1)]

# The string literals that open an argument list: '/x/e' or array('/a/', '/b/e') / ['/a/e'].
_lead_literals(rest) := lits if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:array\s*\(|\[)\s*)?((?:(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s*,?\s*)+)`, rest, 1)
	count(m) > 0
	lits := _literals(m[0][1])
} else := []

# A delimited pattern whose modifiers (after the closing delimiter) include e.
_e_pattern(p) if {
	m := regex.find_all_string_submatch_n(`^([^\w\s\\])[\s\S]*([^A-Za-z])([imsxeuADSUXJn]*)$`, p, 1)
	count(m) > 0
	m[0][2] == _close(m[0][1])
	contains(m[0][3], "e")
}

# Text after `preg_replace(` on this line.
_after_call(line) := rest if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w$>:])preg_replace\s*\((.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

# preg_replace('/.../e', ...) and preg_replace(array('/a/', '/b/e'), ...)
_php_exec(_, _, line) if {
	some p in _lead_literals(_after_call(line))
	_e_pattern(p)
}

# preg_replace(
#     "#...#sie",
_php_exec(lines, i, line) if {
	i > 0
	regex.match(`(?:^|[^\w$>:])preg_replace\s*\(\s*(?:(?:array\s*\(|\[)\s*)?$`, lines[i - 1])
	some p in _lead_literals(line)
	_e_pattern(p)
}

# $pattern = '/.../e'; ... preg_replace($pattern, ...)
_php_exec(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s*;`, line, 1)
	count(m) > 0
	some p in _literals(m[0][2])
	_e_pattern(p)
	v := m[0][1]
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
	regex.match(concat("", [`(?:^|[^\w$>:])preg_replace\s*\(\s*\$`, v, `\b`]), lines[k])
}

_php_exec(_, _, line) if {
	regex.match(`(?:^|[^\w$>:])mb_eregi?_replace\s*\(.*,\s*['"][a-z]*e[a-z]*['"]\s*\)`, line)
}

# The pattern argument contains request data: preg_replace($_GET['p'], ...),
# preg_replace('/' . $_POST['find'] . '/', ...), preg_replace("/{$_GET['t']}/", ...).
# preg_quote() escapes it.
_php_exec(_, _, line) if {
	m := regex.find_all_string_submatch_n(`^\s*((?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|[^,'"])*)`, _after_call(line), 1)
	count(m) > 0
	arg := m[0][1]
	regex.match(_superglobal, arg)
	not contains(arg, "preg_quote")
}

_php_exec(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w$>:])preg_replace\s*\(\s*\$(\w+)\s*,`, line, 1)
	count(m) > 0
	v := m[0][1]
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(concat("", [`^\s*\$`, v, `\s*=[^=]`]), prev)
	regex.match(_superglobal, prev)
	not contains(prev, "preg_quote")
}

# ── Perl ───────────────────────────────────────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path, _perl_ext)
	contains(content, "ee")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`=~|^\s*s\s*[^\w\s]`, line)
	not startswith(trim_space(line), "#")
	m := regex.find_all_string_submatch_n(`(?:=~|^)\s*s\s*[^\w\s].*[^\w\s]([a-z]*)\s*[;)]`, line, 1)
	count(m) > 0
	regex.match(`e[a-z]*e`, m[0][1])
	finding := _finding(path, i, line, _message_perl)
}
