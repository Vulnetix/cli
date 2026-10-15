# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_182

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-182",
	"name": "Collapse of Data into Unsafe Value",
	"description": "A single-pass removal of a dangerous token from a string: a traversal sequence (\"../\", \"..\\\\\", \"..\"), a \"<script>\" tag or a \"http://\"/\"https://\"/\"javascript:\" scheme replaced with the empty string by Python str.replace/re.sub, JavaScript replace/replaceAll (string or regex literal), Java replace/replaceAll, C# Replace and static Regex.Replace, Go strings.Replace/ReplaceAll, strings.NewReplacer and regexp.MustCompile(...).ReplaceAllString, or PHP str_replace/str_ireplace (including the array form) and preg_replace; a regex for a whole script element (<script[^>]*>.*?</script>) or a traversal with a separator class (\\.\\.[\\/\\\\]) counts. Removing the token once lets the surrounding characters collapse into it again (\"....//\" becomes \"../\", \"<scr<script>ipt>\" becomes \"<script>\"). Not reported: a removal repeated in a while/do-while loop until the token is gone, a removal whose result is checked for the token again (and rejected) within four lines, a prefix trim (TrimPrefix), a replacement with a non-empty value (escaping), other tokens, the call inside a string literal, comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-182/",
	"languages": ["python", "node", "java", "csharp", "go", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [182],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["collapse", "sanitization", "path-traversal", "xss", "cwe-182"],
}

_exts := {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".cs", ".go", ".php"}

_lit := concat("", [`"[^"\n]*"|'[^'\n]*'|/(?:[^/\n\\]|\\.)+/[a-z]*|`, "`[^`\\n]*`"])

_empty := concat("", [`(?:""|''|`, "``", `)`])

# Each form captures the "search" argument in group 1.
_forms := [
	concat("", [`\.(?:replace|replaceAll|Replace)\s*\(\s*(`, _lit, `)\s*,\s*`, _empty, `\s*[,)]`]),
	concat("", [`\bstrings\.Replace(?:All)?\s*\(\s*[^,]+,\s*(`, _lit, `)\s*,\s*""`]),
	concat("", [`\bstr_i?replace\s*\(\s*(`, _lit, `|array\s*\([^)]*\)|\[[^\]]*\])\s*,\s*`, _empty, `\s*,`]),
	concat("", [`\bre\.sub\s*\(\s*r?(`, _lit, `)\s*,\s*`, _empty, `\s*,`]),
	concat("", [`\bpreg_replace\s*\(\s*(`, _lit, `)\s*,\s*`, _empty, `\s*,`]),
	concat("", [`\bRegex\.Replace\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*@?(`, _lit, `)\s*,\s*(?:""|string\.Empty|String\.Empty)\s*[,)]`]),
	concat("", [`\bstrings\.NewReplacer\s*\(\s*(`, _lit, `)\s*,\s*""`]),
	concat("", [`\bregexp\.MustCompile\s*\(\s*(`, _lit, `)\s*\)\.ReplaceAll(?:Literal)?String\s*\(\s*[^,]+,\s*""\s*\)`]),
]

# Literal text after removing quotes/regex delimiters and escapes.
_bare(l) := b if {
	s := regex.replace(l, `^/|/[a-z]*$`, "")
	t0 := trim(s, "\"'`")
	t := _strip_delims(t0)
	b := lower(replace(regex.replace(t, `\(\?i\)`, ""), "\\", ""))
}

# A PHP preg pattern keeps its /.../flags delimiters inside the quotes.
_strip_delims(t) := regex.replace(t, `^/|/[imsxuU]*$`, "") if regex.match(`^/.+/[imsxuU]*$`, t)

_strip_delims(t) := t if not regex.match(`^/.+/[imsxuU]*$`, t)

_pre := `(?i)(?:replace\w*|re\.sub)\s*\([^\n]{0,120}(?:(?:\\*\.){2}|<\\?/?script|https?:|javascript:)|MustCompile\s*\([^\n]{0,60}(?:<\\?/?script|(?:\\*\.){2})`

_danger := {"..", "../", "<script>", "<script", "</script>", "javascript:"}

_schemes := {"http://", "https://"}

_bares(arg) := {_bare(l) | some l in regex.find_n(concat("", [`"[^"]*"|'[^']*'|/(?:[^/\\]|\\.)+/[a-z]*|`, "`[^`]*`"]), arg, -1)}

_dangerous_arg(arg, _, _) if {
	some b in _bares(arg)
	_danger_bare(b)
}

_danger_bare(b) if _danger[b]

# A regex for a script element (<script[^>]*>.*?</script>) or a traversal
# sequence with a separator class (\.\.[\/\\]).
_danger_bare(b) if startswith(b, "<script")

_danger_bare(b) if startswith(b, "</script")

_danger_bare(b) if regex.match(`^\.\.(?:\[[/]+\]|\(/\|?\)|/)[+*?]?$`, b)

# Stripping a scheme is often display normalisation. It is a filter (and
# collapses: "hthttp://tp://") when it sits in a chain that also strips a
# traversal or script token.
_dangerous_arg(arg, lines, i) if {
	some b in _bares(arg)
	_schemes[b]
	some j in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 3]))
	j != i
	some form in _forms
	some hit in regex.find_all_string_submatch_n(form, lines[j], -1)
	some b2 in _bares(hit[1])
	_danger[b2]
}

# The call is written inside a string literal: an odd number of quotes before it.
_in_string(line, call) if {
	idx := indexof(line, call)
	idx >= 0
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	_odd_quotes(pre)
}

_odd_quotes(pre) if count(regex.find_n(`"`, pre, -1)) % 2 == 1

_odd_quotes(pre) if count(regex.find_n(`'`, pre, -1)) % 2 == 1

_in_loop(lines, i) if {
	some j in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 2]))
	regex.match(`^\s*(?:\}\s*)?while\b|\bwhile\s*\(`, lines[j])
}

_rep_hint(s) if contains(s, "eplace")

_rep_hint(s) if contains(s, "re.sub(")

_rep_hint(s) if contains(s, "MustCompile")

# The stripped value is checked for the token again right after and rejected.
_rejected_after(lines, i) if {
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	regex.match(`["'](?:\.\.|\.\./|<script)["']\s+(?:not\s+)?in\b|(?:includes|contains|Contains|indexOf|IndexOf|strpos|stripos|str_contains)\s*\([^\n]*["'](?:\.\.|\.\./|<script)["']`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not contains(path, ".min.")
	_rep_hint(content)
	regex.match(_pre, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 1000
	_rep_hint(line)
	regex.match(_pre, line)
	not helpers.is_comment_line(line)
	some form in _forms
	m := regex.find_all_string_submatch_n(form, line, -1)
	some hit in m
	_dangerous_arg(hit[1], lines, i)
	not _in_string(line, hit[0])
	not _in_loop(lines, i)
	not _rejected_after(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "A dangerous token is removed in a single pass; the characters around it can collapse back into the token (\"....//\" -> \"../\"). Reject the input, canonicalise the path and check it stays under its base, or encode output instead of stripping",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
