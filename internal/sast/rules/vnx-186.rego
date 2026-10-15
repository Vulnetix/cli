# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_186

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-186",
	"name": "Overly Restrictive Regular Expression",
	"description": "A denylist filter for markup, script or SQL injection matches its dangerous token case-sensitively, so the variant it was meant to stop gets through (<SCRIPT>, JavaScript:, onError=, UNION SELECT). Reported in Python, JavaScript/TypeScript, Java, PHP and Ruby when the pattern or literal names <script, </script, javascript:, vbscript:, onerror, onload, onmouseover, <iframe, <svg, <img, <object, <embed, union, drop table, sleep( or benchmark( and is used as: a removal (.replace/.replaceAll/.replaceFirst/.gsub/.sub/.delete with an empty replacement, str_replace), a regular expression without a case-insensitive flag (re.sub/search/match/compile without re.I, a JS or Ruby /.../ literal (in a removal, .test(), =~ or match?) or new RegExp without the i flag, Pattern.compile without CASE_INSENSITIVE, String.replaceAll/matches, preg_replace/preg_match without the i modifier), or a membership test of a bare token of at most 16 characters ('<script' in s, s.includes/indexOf/contains/include?, strpos). Not reported: an indexOf/index with a start position or whose result is stored as a position (a parser walking markup), a pattern with (?i), re.I/IGNORECASE, the i flag or modifier, Pattern.CASE_INSENSITIVE, str_ireplace or stripos; a subject lower-cased on the line or a few lines above; a replacement that inserts content (template assembly), regex extraction (.match, .exec, findall), a membership test for a whole payload, test code, minified files and comments. Even a case-insensitive denylist is weaker than output encoding, which this rule does not demand.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-186/",
	"languages": ["java", "node", "python", "php", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [186],
	"capec": ["CAPEC-79"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["regex", "validation", "denylist", "xss", "cwe-186"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "rb" if endswith(path, ".rb")

_tokens := {"<script", "/script", "script>", "javascript:", "vbscript:", "onerror", "onload", "onmouseover", "<iframe", "<svg", "<img", "<object", "<embed", "union", "drop table", "drop\\s+table", "sleep(", "sleep\\(", "benchmark("}

# Cheap whole-file and per-line gate: the text names a token at all.
_needles := {"<script", "script>", "<SCRIPT", "SCRIPT>", "cript:", "CRIPT:", "onerror", "onload", "onmouseover", "<iframe", "<svg", "<img", "<object", "<embed", "union", "UNION", "drop table", "DROP TABLE", "sleep(", "SLEEP(", "benchmark(", "\\/script"}

_gate(s) if {
	some n in _needles
	contains(s, n)
}

_dangerous(pat) if {
	low := lower(pat)
	some t in _tokens
	contains(low, t)
	not contains(pat, "(?i)")
}

_lit := `(?:"((?:\\.|[^"\\\n])*)"|'((?:\\.|[^'\\\n])*)')`

_empty := `(?:""|''|"\s*"|'\s*')`

_text(m) := concat("", [m[0][1], m[0][2]])

# ── Removal with an empty replacement (all five languages) ───────────────

_pattern_hit(line, _) if {
	m := regex.find_all_string_submatch_n(concat("", [`\.(?:replace|replaceAll|replaceFirst|gsub!?|sub!?)\s*\(\s*`, _lit, `\s*,\s*`, _empty, `\s*\)`]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_dangerous(p)
}

_pattern_hit(line, "rb") if {
	m := regex.find_all_string_submatch_n(concat("", [`\.delete!?\s*\(\s*`, _lit, `\s*\)`]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_dangerous(p)
}

_pattern_hit(line, "php") if {
	m := regex.find_all_string_submatch_n(concat("", [`\bstr_replace\s*\(\s*(?:array\s*\(\s*|\[\s*)?`, _lit]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_dangerous(p)
}

# ── Regular expressions without a case-insensitive flag ──────────────────

# JavaScript and Ruby regex literals: /pattern/flags without i.
_pattern_hit(line, lang) if {
	lang in {"js", "rb"}
	some re in _regex_literal_forms
	m := regex.find_all_string_submatch_n(re, line, -1)
	some k
	not contains(m[k][2], "i")
	p := m[k][1]
	_dangerous(p)
}

_re_lit := `/((?:\\.|\[[^\]\n]*\]|[^/\\\n\[])+)/([a-z]*)`

# A regex literal that removes (replace with ''), tests (.test(, =~, match?)
# or is a Ruby case branch; extraction with .match/.exec is parsing.
_regex_literal_forms := [
	concat("", [`\.(?:replace|replaceAll|gsub!?|sub!?)\s*\(\s*`, _re_lit, `\s*,\s*`, _empty]),
	concat("", [`(?:^|[^\w$)\]])\s*!?\s*`, _re_lit, `\s*\.\s*test\s*\(`]),
	concat("", [`(?:=~|!~|\.match\?\s*\()\s*`, _re_lit]),
]

_pattern_hit(line, "js") if {
	m := regex.find_all_string_submatch_n(concat("", [`\bnew\s+RegExp\s*\(\s*`, _lit, `\s*(?:,\s*['"]([a-z]*)['"])?`]), line, -1)
	some k
	not contains(m[k][3], "i")
	p := concat("", [m[k][1], m[k][2]])
	_dangerous(p)
}

_pattern_hit(line, "py") if {
	m := regex.find_all_string_submatch_n(concat("", [`\bre\.(?:sub|subn|search|match|fullmatch|compile)\s*\(\s*[rbuRBU]{0,2}`, _lit]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_dangerous(p)
}

_pattern_hit(line, "java") if {
	m := regex.find_all_string_submatch_n(concat("", [`\bPattern\s*\.\s*compile\s*\(\s*`, _lit]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_dangerous(p)
}

_pattern_hit(line, "java") if {
	m := regex.find_all_string_submatch_n(concat("", [`\.(?:matches|split)\s*\(\s*`, _lit]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_dangerous(p)
}

# PHP: preg_* with the usual delimiters and no i modifier.
_pattern_hit(line, "php") if {
	m := regex.find_all_string_submatch_n(concat("", [`\bpreg_(?:replace|replace_callback|match|match_all|split)\s*\(\s*`, _lit]), line, -1)
	some k
	body := concat("", [m[k][1], m[k][2]])
	d := regex.find_all_string_submatch_n(`^\s*(?:/(.*)/|#(.*)#|~(.*)~|@(.*)@|!(.*)!|\{(.*)\})([a-zA-Z]*)\s*$`, body, 1)
	count(d) > 0
	not contains(d[0][7], "i")
	p := concat("", array.slice(d[0], 1, 7))
	_dangerous(p)
}

# ── Membership tests ─────────────────────────────────────────────────────

_pattern_hit(line, "py") if {
	m := regex.find_all_string_submatch_n(concat("", [_lit, `\s+(?:not\s+)?in\s+[A-Za-z_]`]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_short_token(p)
}

_pattern_hit(line, lang) if {
	lang in {"js", "java", "rb"}
	m := regex.find_all_string_submatch_n(concat("", [`\.(?:includes|indexOf|contains|startsWith|endsWith|include\?|index|start_with\?|end_with\?)\s*\(\s*`, _lit, `\s*\)`]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_short_token(p)
	not _position_lookup(line)
}

# A position kept in a variable (pos = html.indexOf("<script")) is a parser
# walking markup, not a filter; a filter only asks yes or no.
_position_lookup(line) if regex.match(`\b[A-Za-z_$][\w$]*\s*=\s*[\w$.\[\]]+\.(?:indexOf|index)\s*\(`, line)

_pattern_hit(line, "php") if {
	m := regex.find_all_string_submatch_n(concat("", [`\b(?:strpos|strstr|str_contains)\s*\(\s*[^,]+,\s*`, _lit]), line, -1)
	some k
	p := concat("", [m[k][1], m[k][2]])
	_short_token(p)
}

# ── A pattern literal on its own line inside an open compile call ────────

_own_line_re := concat("", [`^\s*[rbuRBU]{0,2}`, _lit, `\s*,?\s*\)?\s*$`])

_multi_line_pattern(lines, i, lang) := p if {
	lang in {"py", "java", "js"}
	i > 0
	m := regex.find_all_string_submatch_n(_own_line_re, lines[i], 1)
	count(m) > 0
	j := max([k | some k in numbers.range(max([0, i - 3]), i - 1); trim_space(lines[k]) != ""])
	regex.match(`(?:\bre\.(?:sub|search|match|fullmatch|findall|compile)|\bPattern\s*\.\s*compile|\bnew\s+RegExp)\s*\(\s*$`, lines[j])
	p := _text(m)
	_dangerous(p)
}

# ── Case-insensitive markers ─────────────────────────────────────────────

_insensitive_re := {
	"py": `\bre\.(?:I|IGNORECASE)\b|\(\?i\)`,
	"java": `CASE_INSENSITIVE|\(\?i\)|toLowerCase\s*\(|toUpperCase\s*\(|equalsIgnoreCase`,
	"js": `\(\?i\)|toLowerCase\s*\(|toUpperCase\s*\(|toLocaleLowerCase\s*\(`,
	"php": `\(\?i\)|strtolower\s*\(|mb_strtolower\s*\(|strtoupper\s*\(`,
	"rb": `\(\?i\)|\.downcase\b|\.upcase\b|/i\b|Regexp::IGNORECASE`,
}

_lower_call_re := `\.lower\s*\(|\.casefold\s*\(|\.upper\s*\(|toLowerCase\s*\(|toUpperCase\s*\(|toLocaleLowerCase\s*\(|strtolower\s*\(|mb_strtolower\s*\(|\.downcase\b|\.upcase\b`

# A flag on the call's own line or its continuation lines.
_insensitive(lines, i, lang) if {
	w := concat("\n", array.slice(lines, i, min([count(lines), i + 3])))
	regex.match(_insensitive_re[lang], w)
}

_insensitive(lines, i, _) if regex.match(_lower_call_re, lines[i])

# A name on the line holds a lower-cased value from a few lines above.
_insensitive(lines, i, _) if {
	some v in helpers.tainted_names(lines, i, 10, _lower_call_re)
	regex.match(concat("", [`\b`, v, `\b`]), lines[i])
}

_hit(lines, i, lang) if _pattern_hit(lines[i], lang)

_hit(lines, i, lang) if _dangerous(_multi_line_pattern(lines, i, lang))

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(content)
	not helpers.is_test_path(path)
	not regex.match(`[.-]min\.js$`, path)
	lines := split(content, "\n")
	some i, line in lines
	_gate(line)
	count(line) < 400
	not helpers.is_comment_line(line)
	_hit(lines, i, lang)
	not _insensitive(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "This denylist matches an injection token case-sensitively, so <SCRIPT>, JavaScript: or UNION SELECT slips past it. Encode output for its context (or use a vetted sanitiser); if a denylist must stay, match case-insensitively",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A membership test is a denylist only for a bare token ('<script',
# 'onerror=', 'union select'); a whole payload is a check for one exact
# string (a challenge or an assertion), not a filter.
_short_token(p) if {
	count(p) <= 16
	_dangerous(p)
}
