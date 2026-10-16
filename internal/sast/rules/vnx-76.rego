# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_76

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-76",
	"name": "Improper Neutralization of Equivalent Special Elements",
	"description": "A dangerous multi-character sequence is neutralised by deleting it once, so an equivalent input that rebuilds it survives: removing ../ from ....// leaves ../, removing <script> from <scr<script>ipt> leaves <script>, removing && from &;& leaves &&, removing http:// from hthttp://tp:// leaves http://. Reported: a replacement with the empty string of a path-traversal sequence (../, ..\\), an HTML tag opener (<script, </script>, <iframe...), a script scheme (javascript:, vbscript:), a URL scheme (http://, https://, file://), a shell operator (&&, ||, $( ) or a bare SQL/script keyword (UNION, SELECT, script, alert...), via Python str.replace/re.sub, JavaScript/TypeScript replace/replaceAll with a string or regex literal, Java replace/replaceAll/replaceFirst, and PHP str_replace/str_ireplace (string or array) and preg_replace. Not reported: a removal inside a loop that repeats until the sequence is gone (a while within the three lines above), removal of a single character (it cannot be rebuilt), replacements with a non-empty string (encoding such as &lt;), test code, comments and strings. A line that removes a path-traversal sequence (../, ..\\, ..), a script tag or element pattern (<script>, </script>, <script[^>]*>) or javascript:, or strips http:// or https:// beside such a removal, is reported by VNX-182, not here; this rule keeps the other tags, vbscript:, other URL schemes, shell operators and keywords.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-76/",
	"languages": ["java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [76],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["equivalent-elements", "sanitization", "blacklist", "cwe-76"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_needles := {
	"py": {"replace(", "re.sub("},
	"js": {"replace(", "replaceAll("},
	"java": {"replace(", "replaceAll(", "replaceFirst("},
	"php": {"str_replace(", "str_ireplace(", "preg_replace("},
}

# Each pattern's group 1 is the text removed; the replacement is empty.
_removal := {
	"py": [
		`\.replace\s*\(\s*r?"((?:\\.|[^"\\])+)"\s*,\s*(?:""|'')\s*[,)]`,
		`\.replace\s*\(\s*r?'((?:\\.|[^'\\])+)'\s*,\s*(?:""|'')\s*[,)]`,
		`\bre\.sub\s*\(\s*r?"((?:\\.|[^"\\])+)"\s*,\s*(?:""|'')\s*,`,
		`\bre\.sub\s*\(\s*r?'((?:\\.|[^'\\])+)'\s*,\s*(?:""|'')\s*,`,
	],
	"js": [
		`\.replace(?:All)?\s*\(\s*"((?:\\.|[^"\\])+)"\s*,\s*(?:""|''|\x60\x60)\s*\)`,
		`\.replace(?:All)?\s*\(\s*'((?:\\.|[^'\\])+)'\s*,\s*(?:""|''|\x60\x60)\s*\)`,
		`\.replace(?:All)?\s*\(\s*/((?:\\.|[^/\\])+)/[gimsuy]*\s*,\s*(?:""|''|\x60\x60)\s*\)`,
	],
	"java": [`\.(?:replace|replaceAll|replaceFirst)\s*\(\s*"((?:\\.|[^"\\])+)"\s*,\s*""\s*\)`],
	"php": [
		`\bstr_i?replace\s*\(\s*((?:array\s*\([^)]*\)|\[[^\]]*\]|"(?:\\.|[^"\\])+"|'(?:\\.|[^'\\])+'))\s*,\s*(?:""|'')\s*,`,
		`\bpreg_replace\s*\(\s*((?:"(?:\\.|[^"\\])+"|'(?:\\.|[^'\\])+'))\s*,\s*(?:""|'')\s*,`,
	],
}

# Sequences that a single deletion can rebuild and that matter when rebuilt.
_dangerous := `\.\./|\.\.\\|<\s*/?\s*[A-Za-z]|(?i)javascript:|(?i)vbscript:|&&|\|\||\$\(`

# Removing a URL scheme is also how code extracts a host name; it is only a
# neutralisation when it sits beside another removal (an RFI filter).
_scheme := `(?i)(https?|file|ftp|php|data)://`

_keyword := `(?i)^\W*(select|union|insert|update|delete|drop|exec|sleep|benchmark|script|alert|onerror|onload|eval|from|where)\W*$`

_harmful(tok) if regex.match(_dangerous, tok)

# Regex-literal spellings: \.\.\/ is ../
_harmful(tok) if regex.match(_dangerous, regex.replace(tok, `\\([./:<>&|$()])`, "$1"))

# A regex inside a Java/PHP string literal doubles the backslash: "\\.\\./"
_harmful(tok) if {
	contains(tok, `\\`)
	regex.match(_dangerous, regex.replace(regex.replace(tok, `\\\\`, `\`), `\\([./:<>&|$()])`, "$1"))
}

_harmful(tok) if regex.match(_keyword, regex.replace(tok, `\(\?i\)`, ""))

# A loop that repeats the removal until nothing changes.
_in_loop(lines, i) if {
	some k in numbers.range(max([0, i - 3]), i)
	regex.match(`\bwhile\b|\bdo\s*\{|\buntil\b`, lines[k])
	not helpers.is_comment_line(lines[k])
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	_has_any(content, _needles[lang])
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _needles[lang])
	not helpers.is_comment_line(line)
	some re in _removal[lang]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	_counts(lines, i, lang, m[1])
	not _in_string(line, m[0])
	not _in_loop(lines, i)
	not _owned_by_182(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "A dangerous sequence is removed once by replacing it with an empty string. An input that rebuilds it after the deletion (....// becomes ../, <scr<script>ipt> becomes <script>, &;& becomes &&) passes through unchanged in effect. Reject input that contains the sequence, encode for the output context, or for paths take the basename and check the canonical path",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The call sits inside a quoted string (an example in a message), not code:
# the text before it has an odd number of double or single quotes.
_in_string(line, call) if {
	idx := indexof(line, call)
	idx > 0
	before := substring(line, 0, idx)
	some q in {`"`, "'"}
	n := count(regex.find_all_string_submatch_n(regex.replace(q, `(.)`, `\$1`), regex.replace(before, `\\.`, ""), -1))
	n % 2 == 1
}

# ── Lines VNX-182 reports ────────────────────────────────────────────────
# A single-pass removal of a path-traversal sequence (../, ..\, ..), a script
# tag or element pattern (<script>, </script>, <script[^>]*>), javascript:, or
# a URL scheme stripped beside one of them is the collapse VNX-182 reports, in
# these languages and more. The line is that rule's: reporting it here too
# would show one problem twice. This rule keeps the sequences VNX-182 does not
# know: other tags, vbscript:, shell operators and SQL or script keywords.

_owned_set := {"..", "../", "<script>", "<script", "</script>", "javascript:"}

_owned_bare(b) if _owned_set[b]

_owned_bare(b) if startswith(b, "<script")

_owned_bare(b) if startswith(b, "</script")

_owned_bare(b) if regex.match(`^\.\.(?:\[[/]+\]|\(/\|?\)|/)[+*?]?$`, b)

# The literal elements of a removal: a PHP array or quoted string yields its
# quoted parts; any other captured text is one element.
_elts(tok) := es if {
	es := regex.find_n(`"[^"]*"|'[^']*'`, tok, -1)
	count(es) > 0
}

_elts(tok) := [tok] if count(regex.find_n(`"[^"]*"|'[^']*'`, tok, -1)) == 0

# Quotes, PHP regex delimiters, (?i) and escapes removed, lower-cased.
_bare(e) := b if {
	t0 := trim(e, "\"'")
	t := _strip_delims(t0)
	b := lower(replace(regex.replace(t, `\(\?i\)`, ""), "\\", ""))
}

_strip_delims(t) := regex.replace(t, `^/|/[imsxuU]*$`, "") if regex.match(`^/.+/[imsxuU]*$`, t)

_strip_delims(t) := t if not regex.match(`^/.+/[imsxuU]*$`, t)

_owned_tok(tok) if {
	some e in _elts(tok)
	_owned_bare(_bare(e))
}

_scheme_tok(tok) if {
	some e in _elts(tok)
	_bare(e) in {"http://", "https://"}
}

_removals(line, lang) := {[m[0], m[1]] |
	some re in _removal[lang]
	some m in regex.find_all_string_submatch_n(re, line, -1)
}

_owned_by_182(lines, i, lang) if {
	some r in _removals(lines[i], lang)
	_owned_tok(r[1])
	not _in_string(lines[i], r[0])
}

_owned_by_182(lines, i, lang) if {
	some r in _removals(lines[i], lang)
	_scheme_tok(r[1])
	not _in_string(lines[i], r[0])
	some k in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 3]))
	k != i
	some r2 in _removals(lines[k], lang)
	some e in _elts(r2[1])
	_owned_set[_bare(e)]
}

_counts(_, _, _, tok) if _harmful(tok)

_counts(lines, i, lang, tok) if {
	not _harmful(tok)
	regex.match(_scheme, tok)
	some k in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 3]))
	k != i
	some re in _removal[lang]
	some m in regex.find_all_string_submatch_n(re, lines[k], -1)
	_harmful(m[1])
}

_counts(_, _, _, tok) if {
	regex.match(_scheme, tok)
	regex.match(_dangerous, regex.replace(tok, _scheme, ""))
}
