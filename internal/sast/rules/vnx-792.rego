# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_792

import rego.v1

metadata := {
	"id": "VNX-792",
	"name": "Incomplete Filtering of One or More Instances of Special Elements",
	"description": "Reports HTML/script sanitising that only handles the first occurrence of a markup special element: in JavaScript/TypeScript, String.replace() with a string literal or a regex literal without the g flag whose pattern is <, >, &, a quote (including an escaped \"), a class of them such as [<>], a script/iframe tag, javascript: or an event-handler attribute, replaced with nothing or with an HTML entity; in Python, str.replace(..., 1) and re.sub(..., count=1) with the same tokens. Every later occurrence passes through unescaped. Global replacements (/g, replaceAll, Python's default replace-all), template substitutions whose replacement is markup, and path/command tokens (VNX-793) are deliberately not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-792/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [792],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incomplete-filtering-one-instance", "cwe-792"],
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

# replacement: empty, or an HTML entity
_repl := `\s*(?:''|""|\x60\x60|'&[#\w]+;?'|"&[#\w]+;?"|\x60&[#\w]+;?\x60)\s*`

# JS: s.replace('TOKEN', REPL) -- a string pattern replaces the first match only
_js_str := concat("", [`\.replace\(\s*`, _lit, `\s*,`, _repl, `\)`])

# JS: s.replace(/TOKEN/flags, REPL) without g
_js_re := concat("", [`\.replace\(\s*/((?:[^/\\\n]|\\.)+)/([a-z]*)\s*,`, _repl, `\)`])

# Python: s.replace(TOKEN, REPL, 1)
_py_rep := concat("", [`\.replace\(\s*`, _lit, `\s*,`, _repl, `,\s*1\s*\)`])

# Python: re.sub(TOKEN, REPL, s, 1) / re.sub(TOKEN, REPL, s, count=1)
_py_sub := concat("", [`\bre\.sub\(\s*[rbuRBU]*`, _lit, `\s*,\s*[rbuRBU]*`, _repl, `,[^,()]+(?:\([^()]*\))?[^,()]*,\s*(?:count\s*=\s*)?1\s*[,)]`])

_token_re := `(?i)^(\\?<|\\?>|&|"|'|\\"|\\'|\\?<\s*/?\s*(script|iframe|object|embed|svg|img)\b.{0,20}|javascript:|vbscript:|on(error|load|click|mouseover|focus)\s*=?|\[[<>&"'\\]+\]\+?)$`

_tokens(line, "js") := {concat("", [m[1], m[2], m[3]]) |
	some m in regex.find_all_string_submatch_n(_js_str, line, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(_js_re, line, -1)
	not contains(m[2], "g")
}

_tokens(line, "python") := {concat("", [m[1], m[2], m[3]]) |
	some re in [_py_rep, _py_sub]
	some m in regex.find_all_string_submatch_n(re, line, -1)
}

_unquote_calls(line) := regex.replace(regex.replace(line, `"[^"+,()=>]*\w\.(?:replace|sub)\([^"]*"`, `""`), `'[^'+,()=>]*\w\.(?:replace|sub)\([^']*'`, `""`)

_msg := "Only the first occurrence of the markup character/tag is filtered; every later one passes through unescaped. Use a global replacement (/g or replaceAll), or better, a context-aware encoder or template auto-escaping"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`\.(replace|sub)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(replace|sub)\(`, line)
	not _is_comment(line)
	code := _unquote_calls(line)
	some tok in _tokens(code, lang)
	regex.match(_token_re, tok)
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
