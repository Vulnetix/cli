# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_793

import rego.v1

metadata := {
	"id": "VNX-793",
	"name": "Only Filtering One Instance of a Special Element",
	"description": "Reports path, command and header sanitising that removes or rewrites only the first occurrence of a special element: in JavaScript/TypeScript, String.replace() with a string literal or a regex literal without the g flag whose pattern is a .., ../, ..\\ or \\.\\.[\\/\\\\] traversal sequence, a shell metacharacter (&& || backtick $( always; a lone ; | $ or a deleted & only with a command such as exec, subprocess or cmd within six lines, since those are stripped from prices, table cells and CSS far more often), CR/LF or a NUL byte; in Python, str.replace(..., 1) and re.sub(..., count=1) with the same tokens. 'a/../../x'.replace('../', '') still contains ../. Global replacements (/g, replaceAll, Python's default replace-all, reported by VNX-791 when they delete the token), anchored patterns (VNX-796) and markup tokens (VNX-792) are deliberately not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-793/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [793],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["only-filtering-one-occurrence", "cwe-793"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in _js_exts
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_is_comment(line) if regex.match(`^\s*(#|//|/\*|\*)`, line)

_lit := `(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"|\x60([^\x60$\n]*)\x60)`

_arg := `\s*(?:'[^'\n]*'|"[^"\n]*"|\x60[^\x60$\n]*\x60)\s*`

# JS: s.replace('TOKEN', '...') -- a string pattern replaces the first match only
_js_str := concat("", [`\.replace\(\s*`, _lit, `\s*,`, _arg, `\)`])

# JS: s.replace(/TOKEN/flags, '...') without g
_js_re := concat("", [`\.replace\(\s*/((?:[^/\\\n]|\\.)+)/([a-z]*)\s*,`, _arg, `\)`])

# Python: s.replace(TOKEN, REPL, 1)
_py_rep := concat("", [`\.replace\(\s*`, _lit, `\s*,`, _arg, `,\s*1\s*\)`])

# Python: re.sub(TOKEN, REPL, s, 1) / re.sub(TOKEN, REPL, s, count=1)
_py_sub := concat("", [`\bre\.sub\(\s*[rbuRBU]*`, _lit, `\s*,\s*[rbuRBU]*`, _arg, `,[^,()]+(?:\([^()]*\))?[^,()]*,\s*(?:count\s*=\s*)?1\s*[,)]`])

# & on its own is a command separator only when it is deleted; '&' -> '&amp;'
# is HTML escaping (VNX-792)
_token_re := `^(\.\.|\.\./|\.\.\\\\|\\\.\\\.(\\?/|\\\\\\\\|\[[^\]]*\])?|&&|\|\||\\?\x60|\\?\$\\?\(|\\r\\n|\\r|\\n\\r|\\0|\\x00|\\u0000|%00|%2e%2e(%2f)?|\.\.%2f)$`

# ; | $ on their own are command separators only near a command: they are
# removed from prices, table cells and CSS far more often
_single_re := `^(;|\\?\||\\?\$)$`

_command_context(lines, i) if {
	some k in numbers.range(max([0, i - 6]), min([count(lines) - 1, i + 6]))
	regex.match(`(?i)(\bcmd|command|\bshell|\bexec|\bsystem\s*\(|subprocess|popen|\bspawn|child_process|check_output)`, lines[k])
}

_tokens(line, "js") := {[concat("", [m[1], m[2], m[3]]), m[0]] |
	some m in regex.find_all_string_submatch_n(_js_str, line, -1)
} | {[m[1], m[0]] |
	some m in regex.find_all_string_submatch_n(_js_re, line, -1)
	not contains(m[2], "g")
}

_tokens(line, "python") := {[concat("", [m[1], m[2], m[3]]), m[0]] |
	some re in [_py_rep, _py_sub]
	some m in regex.find_all_string_submatch_n(re, line, -1)
}

_unquote_calls(line) := regex.replace(regex.replace(line, `"[^"+,()=>]*\w\.(?:replace|sub)\([^"]*"`, `""`), `'[^'+,()=>]*\w\.(?:replace|sub)\([^']*'`, `""`)

_msg := "Only the first occurrence of the special element is filtered, so input that repeats it ('../../', 'a;b;c') keeps the rest. Replace every occurrence until none remain, or better, validate against an allow-list / resolve the path and check it stays under the base directory / pass arguments without a shell"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`\.(replace|sub)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(replace|sub)\(`, line)
	not _is_comment(line)
	code := _unquote_calls(line)
	some t in _tokens(code, lang)
	_bad(t, lines, i)
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

_bad(t, _, _) if regex.match(_token_re, lower(t[0]))

_bad(t, lines, i) if {
	regex.match(_single_re, t[0])
	_command_context(lines, i)
}

# '&' deleted (not escaped to an entity) near a command is a command separator
_bad(t, lines, i) if {
	t[0] == "&"
	regex.match(`,\s*(?:''|""|\x60\x60)\s*(?:,\s*1\s*)?[,)]`, t[1])
	_command_context(lines, i)
}
