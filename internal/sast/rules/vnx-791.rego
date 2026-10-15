# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_791

import rego.v1

metadata := {
	"id": "VNX-791",
	"name": "Incomplete Filtering of Special Elements",
	"description": "Reports hand-written sanitisers in Python and JavaScript/TypeScript that delete a dangerous token in a single pass: str.replace(TOKEN, ''), re.sub(TOKEN, '', s) and PATTERN.sub('', s) on a re.compile(TOKEN) constant in Python, and replaceAll(TOKEN, ''), split(TOKEN).join(''), replace(/TOKEN/g, '') and replace(PATTERN, '') on a /TOKEN/g constant in JavaScript, where TOKEN is a script/iframe/object/embed/svg tag, a generic tag pattern built from word characters (<\\w+..., which cannot match a nested '<'), a javascript:/vbscript: scheme, an event-handler attribute (onerror, on\\w+), a ../ or .. traversal sequence, or shell metacharacters (a class of two or more always; a single ; & | $ or backtick only with a command such as exec, subprocess or cmd within six lines). One pass leaves nested input reassembled ('<scr<script>ipt>', '....//') and a character denylist leaves the others. A replacement repeated in a while/do loop, escaping (replacing with an entity), an ellipsis, <[^>]*> (which absorbs a nested '<'), a lone '$' or '|' away from any command (prices, table cells), anchored patterns (VNX-796) and JavaScript first-occurrence replace() (VNX-792, VNX-793) are deliberately not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-791/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [791],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["incomplete-filtering", "cwe-791"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in _js_exts
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_is_comment(line) if regex.match(`^\s*(#|//|/\*|\*)`, line)

# a string literal; escapes inside it are kept ("\"", "\son\w+=\"")
_lit := `(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)")`

_empty := `(?:''|""|\x60\x60)`

# Python: s.replace(TOKEN, '')
_py_replace := concat("", [`\.replace\(\s*`, _lit, `\s*,\s*`, _empty, `\s*\)`])

# Python: re.sub(TOKEN, '', s ...)
_py_sub := concat("", [`\bre\.sub\(\s*[rbuRBU]*`, _lit, `\s*,\s*[rbuRBU]*`, _empty, `\s*,`])

# JS: replaceAll('TOKEN', '') and the split/join spelling of it
_js_all := concat("", [`\.replaceAll\(\s*`, _lit, `\s*,\s*`, _empty, `\s*\)`])

_js_split := concat("", [`\.split\(\s*`, _lit, `\s*\)\s*\.join\(\s*`, _empty, `\s*\)`])

# JS: replace(/TOKEN/g, '') or replaceAll(/TOKEN/g, '')
_js_re := concat("", [`\.replace(?:All)?\(\s*/((?:[^/\\\n]|\\.)+)/([a-z]*)\s*,\s*`, _empty, `\s*\)`])

# markup, scheme and event-handler tokens: anywhere in the pattern
# A generic tag pattern built from word characters (<\w+...>, <(?:\w+)...)
# cannot match a '<' inside a tag, so '<<b>script>' reassembles after one pass.
_markup_re := `(?i)(<\s*/?\s*(script|iframe|object|embed|svg)|javascript:|vbscript:|(^|\\s|[^A-Za-z])on(error|load|click|mouseover|focus|\\w[+*]|\[a-z\][+*])|^<(\\/\?|/\?)?(\(\?:)?(\\w|\[a-z))`

# traversal tokens: the whole pattern is ../, ..\ or .. (not an ellipsis)
_traversal_re := `(?i)^\(?(\.\.[/\\]*|\\\.\\\.(\\?/|\\\\|\[[^\]]*\])*|\.\.%2f|%2e%2e(%2f)?)\)?[+*]?$`

# shell metacharacters on their own, and character classes of them
_shell_single := `^\s*(;|&|&&|\||\|\||\x60|\$|\$\(|\\\$\\\(|\\\||\\\$)\s*$`

_shell_class := `^\[[;&|$\x60\\ <>(){}!\n]+\][+*]?$`

_bad_token(tok, _, _) if regex.match(_markup_re, tok)

_bad_token(tok, _, _) if regex.match(_traversal_re, tok)

# a class naming two or more distinct shell metacharacters is a denylist
_bad_token(tok, _, _) if {
	regex.match(_shell_class, tok)
	count({c | some c in [";", "&", "|", "$", "`"]; contains(tok, c)}) >= 2
}

# a single character is a shell denylist only near a command; '$', '|' and '&'
# are deleted from prices, table cells and slugs far more often
_bad_token(tok, lines, i) if {
	_shell_token(tok)
	_command_context(lines, i)
}

_shell_token(tok) if regex.match(_shell_single, tok)

_shell_token(tok) if regex.match(_shell_class, tok)

_command_context(lines, i) if {
	some k in numbers.range(max([0, i - 6]), min([count(lines) - 1, i + 6]))
	regex.match(`(?i)(\bcmd|command|\bshell|\bexec|\bsystem\s*\(|subprocess|popen|\bspawn|child_process|check_output)`, lines[k])
}

_tokens(line, "python", compiled) := {concat("", [m[1], m[2]]) |
	some re in [_py_replace, _py_sub]
	some m in regex.find_all_string_submatch_n(re, line, -1)
} | {pair[1] |
	# PATTERN = re.compile(TOKEN) ... PATTERN.sub('', s)
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\.sub\(\s*`, _empty, `\s*,`]), line, -1)
	some pair in compiled
	pair[0] == m[1]
}

_tokens(line, "js", compiled) := {concat("", [m[1], m[2]]) |
	some re in [_js_all, _js_split]
	some m in regex.find_all_string_submatch_n(re, line, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(_js_re, line, -1)
	contains(m[2], "g")
} | {pair[1] |
	# const PATTERN = /TOKEN/g ... s.replace(PATTERN, '')
	some m in regex.find_all_string_submatch_n(concat("", [`\.replace(?:All)?\(\s*([A-Za-z_$][\w$]*)\s*,\s*`, _empty, `\s*\)`]), line, -1)
	some pair in compiled
	pair[0] == m[1]
}

# [name, pattern] for every compiled / regex-literal constant in the file
_compiled(content, "python") := {[m[1], concat("", [m[2], m[3]])] |
	contains(content, "re.compile")
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*([A-Za-z_]\w*)\s*=\s*re\.compile\(\s*[rbuRBU]*`, _lit]), content, -1)
}

_compiled(content, "js") := {[m[1], m[2]] |
	some m in regex.find_all_string_submatch_n(`(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*/((?:[^/\\\n]|\\.)+)/[a-z]*g[a-z]*\s*;?\s*$`, content, -1)
}

_msg := "Single-pass removal of a dangerous token is an incomplete filter: nested input reassembles it ('<scr<script>ipt>', '....//') and a denylist misses the other special characters. Encode for the output context, use an allow-list, or resolve and check the result (e.g. a canonical path under the base directory)"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`\.(replace|replaceAll|sub)\(|\)\s*\.join\(`, content)
	compiled := _compiled(content, lang)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(replace|replaceAll|sub|join)\(`, line)
	not _is_comment(line)
	code := _unquote_calls(line)
	some tok in _tokens(code, lang, compiled)
	not startswith(tok, "^")
	_bad_token(tok, lines, i)
	not _looped(lines, i)
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

# a call spelled inside a string literal ("use name.replace(...) never") is prose
_unquote_calls(line) := regex.replace(regex.replace(line, `"[^"+,()=>]*\w\.(?:replace|replaceAll|sub)\([^"]*"`, `""`), `'[^'+,()=>]*\w\.(?:replace|replaceAll|sub)\([^']*'`, `""`)

_looped(lines, i) if {
	some k in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 2]))
	regex.match(`^\s*(while\b|do\s*\{|\}\s*while\b)`, lines[k])
}
