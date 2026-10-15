# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_796

import rego.v1

metadata := {
	"id": "VNX-796",
	"name": "Only Filtering Special Elements Relative to a Marker",
	"description": "Reports sanitising that removes special elements only at the start or end of a value, leaving the same elements anywhere else: Python str.strip/lstrip/rstrip and lodash _.trim/_.trimStart/_.trimEnd whose character set mixes a dot with a path separator ('./', '../\\\\') or holds shell metacharacters (; | & $ backtick: two or more distinct, or one with a command such as exec, subprocess or os.system within six lines), Python removeprefix/removesuffix of a .. sequence, and Python re.sub / JavaScript replace() with an empty replacement whose pattern is anchored with ^ or $ and removes dots with path separators ('^(\\.\\./)+') or shell metacharacters (same test). 'a/../../etc/passwd'.lstrip('./') is unchanged. Plain normalisation (rstrip('/'), lstrip('.'), strip('\"'), strip('<>') on a Message-ID, rstrip(';') on SQL, strip('$') on a price), stripping a file extension (\\.[^/.]+$) and unanchored global replacements are deliberately not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-796/",
	"languages": ["python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [796],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["only-end-special-element", "cwe-796"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in _js_exts
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_is_comment(line) if regex.match(`^\s*(#|//|/\*|\*)`, line)

_lit := `(?:'([^'\n]*)'|"([^"\n]*)")`

_py_strip := concat("", [`\.(?:l|r)?strip\(\s*`, _lit, `\s*\)`])

_lodash_trim := concat("", [`\b_\.trim(?:Start|End)?\(\s*[^,()]+,\s*`, _lit, `\s*\)`])

_py_sub := concat("", [`\bre\.sub\(\s*[rbuRBU]*`, _lit, `\s*,\s*[rbuRBU]*(?:''|"")\s*,`])

_js_re := `\.replace\(\s*/((?:[^/\\\n]|\\.)+)/[a-z]*\s*,\s*(?:''|""|\x60\x60)\s*\)`

# s.removeprefix('../') removes one leading copy; '../../x' keeps the second
_py_prefix := concat("", [`\.remove(?:prefix|suffix)\(\s*`, _lit, `\s*\)`])

_charsets(line, "python") := {concat("", [m[1], m[2]]) |
	some m in regex.find_all_string_submatch_n(_py_strip, line, -1)
}

_prefixes(line, "python") := {concat("", [m[1], m[2]]) |
	some m in regex.find_all_string_submatch_n(_py_prefix, line, -1)
}

_prefixes(_, "js") := set()

_charsets(line, "js") := {concat("", [m[1], m[2]]) |
	some m in regex.find_all_string_submatch_n(_lodash_trim, line, -1)
}

_patterns(line, "python") := {concat("", [m[1], m[2]]) |
	some m in regex.find_all_string_submatch_n(_py_sub, line, -1)
}

_patterns(line, "js") := {m[1] |
	some m in regex.find_all_string_submatch_n(_js_re, line, -1)
}

_bad_charset(cs, _, _) if {
	contains(cs, ".")
	regex.match(`/|\\`, cs)
}

# shell metacharacters: two or more distinct ones is a denylist; a single one
# ('$' from a price, ';' from the end of an SQL statement) only near a command
_shell_chars(s) := {c | some c in [";", "|", "&", "$", "`"]; contains(s, c)}

_bad_charset(cs, _, _) if count(_shell_chars(cs)) >= 2

_bad_charset(cs, lines, i) if {
	count(_shell_chars(cs)) == 1
	_command_context(lines, i)
}

_command_context(lines, i) if {
	some k in numbers.range(max([0, i - 6]), min([count(lines) - 1, i + 6]))
	regex.match(`(?i)(\bcmd|command|\bshell|\bexec|\bsystem\s*\(|subprocess|popen|\bspawn|child_process|check_output)`, lines[k])
}

_anchored(p) if startswith(p, "^")

_anchored(p) if regex.match(`[^\\]\$$`, p)

# dots with a separator: \.\., \.+, \.{2}, or a (non-negated) class holding a
# dot; [^/.]+$ (strip the extension) is not a traversal filter
_bad_pattern(p, _, _) if {
	_anchored(p)
	regex.match(`\\\.\\\.|\\\.[+*]|\\\.\{|\[(?:[^\]^][^\]]*)?\.[^\]]*\]`, p)
	regex.match(`/|\\\\`, p)
}

_bad_pattern(p, lines, i) if {
	_anchored(p)
	regex.match(`^\^\[?\\?[;|&\x60]|[;|&\x60]\]?[+*]?\$$`, p)
	_bad_charset(trim_suffix(trim_prefix(p, "^"), "$"), lines, i)
}

_hit(code, lang, lines, i) if {
	some cs in _charsets(code, lang)
	_bad_charset(cs, lines, i)
}

_hit(code, lang, lines, i) if {
	some p in _patterns(code, lang)
	_bad_pattern(p, lines, i)
}

_hit(code, lang, _, _) if {
	some p in _prefixes(code, lang)
	contains(p, "..")
}

_unquote_calls(line) := regex.replace(regex.replace(line, `"[^"+,()=>]*\w\.(?:l|r)?(?:strip|sub|replace|trim\w*|remove(?:prefix|suffix))\([^"]*"`, `""`), `'[^'+,()=>]*\w\.(?:l|r)?(?:strip|sub|replace|trim\w*|remove(?:prefix|suffix))\([^']*'`, `""`)

_msg := "Special elements are removed only at the start or end of the value; the same sequence in the middle ('a/../../x', 'a;b') survives. Resolve the path and check it stays under the base directory, or validate the whole value against an allow-list"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`\.(l|r)?strip\(|\bre\.sub\(|\.replace\(\s*/\^|\$/[a-z]*\s*,|\b_\.trim|\.remove(prefix|suffix)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`strip\(|sub\(|replace\(|_\.trim|remove(prefix|suffix)\(`, line)
	not _is_comment(line)
	_hit(_unquote_calls(line), lang, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
