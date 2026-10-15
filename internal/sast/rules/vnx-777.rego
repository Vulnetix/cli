# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_777

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-777",
	"name": "Regular Expression without Anchors",
	"description": "An allow-list regular expression used to validate a value is anchored at only one end (or bounded by a length quantifier and anchored at neither), so the check passes whenever any part of the value conforms and the rest is never examined: `^[a-z0-9]+` accepts `abc; rm -rf /`. Reported: a pattern that is a single positive character class, \\d, \\w or . with a +, * or {n,m} quantifier, tested with a search-semantics API (Python re.search, JavaScript RegExp.test (on a literal or on new RegExp(...)) and String.match/search, Go regexp.MatchString/MatchString/Match, Java Matcher.find(), PHP preg_match with two arguments, Ruby =~, !~ and match/match?) where one anchor is missing or neither is present with a {n,m} length bound; Python re.match and Java lookingAt(), which anchor only the start, with no end anchor when the pattern starts with ^, carries a length bound or the call is negated (if not re.match(...)); and in Ruby, ^ and $ (line anchors, bypassed by a newline) used in place of \\A and \\z in a =~/match test or a validates format: with: option. Patterns are read from the call itself or from a named constant compiled in the same file (re.compile, regexp.MustCompile, Pattern.compile, a JavaScript regex literal). Python and JavaScript match/search and Ruby =~ are reported only in a boolean test (if, not, !, return, &&, ternary), not when the match object is used to extract text (.group()). Not reported: fully anchored patterns, re.fullmatch, String.matches/Pattern.matches, negated classes ([^...], a blocklist that is correct unanchored), unanchored patterns without a length bound (a 'contains a digit' check is legitimate), composite patterns, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-777/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [777],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["regex", "input-validation", "cwe-777"],
}

# ── Languages and whole-file gates ───────────────────────────────────────

_ext_lang := {
	"py": "py",
	"js": "js", "mjs": "js", "cjs": "js", "jsx": "js", "ts": "js", "tsx": "js", "mts": "js", "cts": "js",
	"go": "go",
	"java": "java",
	"php": "php",
	"rb": "rb",
}

_lang(path) := _ext_lang[regex.replace(path, `^.*\.`, "")]

# A literal pattern directly at a call site: gates the file and each line
# before the capturing site regexes run.
_line_gate := {
	"py": `\bre\.(?:match|search)\(\s*[rRbBuU]{0,2}["']|\bre\.compile\([^)]*\)\.(?:match|search)\(`,
	"js": `/[gimsuyd]*\.test\(|\.(?:match|search)\(\s*/|\bRegExp\(\s*["'][^"']*["']\s*(?:,\s*["'][a-z]*["']\s*)?\)\.test\(`,
	"go": "regexp\\.MatchString\\(|regexp\\.(?:MustCompile|Compile)\\([^)]*\\)\\.Match",
	"java": `Pattern\.compile\([^;]*\)\.matcher\(`,
	"php": `preg_match\(\s*["'][/#]`,
	"rb": `[=!]~\s*/|/[imxo]*\s*[=!]~|\.match\??\(\s*/|\bwith:\s*/`,
}

# The end of a single-atom quantified pattern right before its closing
# delimiter: what every reportable literal contains.
_shape_tail := "(?:\\]|\\\\[dw]|\\.)(?:[+*]|\\{\\d+(?:,\\d*)?\\})(?:\\$|\\\\[zZ])?[\"'/`#]"

# Substrings a file needs before any regular expression runs over it.
_file_needles := {
	"py": {"re.match(", "re.search(", ").match(", ").search("},
	"js": {"/.test(", "i.test(", "g.test(", "u.test(", "match(/", "search(/", "RegExp("},
	"go": {"regexp.MatchString(", ").Match"},
	"java": {".matcher("},
	"php": {"preg_match('/", "preg_match(\"/", "preg_match('#", "preg_match(\"#"},
	"rb": {"~ /", "~/", "match(/", "match?(/", "with: /"},
}

_has_needle(line, nds) if {
	some nd in nds
	contains(line, nd)
}


# ── Call sites ───────────────────────────────────────────────────────────
# Each site regex captures the pattern in group 1. kind is "sub" (search
# semantics), "start" (anchored at the start only) or "rbfmt" (Rails format).

_pyq := `[rRbBuU]{0,2}["']((?:[^"'\\]|\\.)*)["']`

_jsre := `/((?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+)/[gimsuyd]*`

_gostr := "[`\"]((?:[^`\"\\\\]|\\\\.)*)[`\"]"

_jstr := `"((?:[^"\\]|\\.)*)"`

_rbre := `/((?:[^/\\\n]|\\.)+)/[imxo]*`

_sites := {
	"py": [
		{"re": concat("", [`\bre\.match\(\s*`, _pyq]), "kind": "start", "bool": true},
		{"re": concat("", [`\bre\.search\(\s*`, _pyq]), "kind": "sub", "bool": true},
		{"re": concat("", [`\bre\.compile\(\s*`, _pyq, `\s*\)\.match\(`]), "kind": "start", "bool": true},
		{"re": concat("", [`\bre\.compile\(\s*`, _pyq, `\s*\)\.search\(`]), "kind": "sub", "bool": true},
	],
	"js": [
		{"re": concat("", [`(?:^|[=(,!&|?:\s])`, _jsre, `\.test\(`]), "kind": "sub", "bool": false},
		{"re": concat("", [`\.(?:match|search)\(\s*`, _jsre, `\s*\)`]), "kind": "sub", "bool": true},
		# new RegExp("...").test(x): a string pattern, so \\d is \d
		{"re": `\bRegExp\(\s*"((?:[^"\\]|\\.)*)"\s*(?:,\s*["'][a-z]*["']\s*)?\)\.test\(`, "kind": "sub", "bool": false, "str": true},
		{"re": `\bRegExp\(\s*'((?:[^'\\]|\\.)*)'\s*(?:,\s*["'][a-z]*["']\s*)?\)\.test\(`, "kind": "sub", "bool": false, "str": true},
	],
	"go": [
		{"re": concat("", [`\bregexp\.MatchString\(\s*`, _gostr]), "kind": "sub", "bool": false},
		{"re": concat("", [`\bregexp\.(?:MustCompile|Compile)\(\s*`, _gostr, `\s*\)\.(?:MatchString|Match|MatchReader)\(`]), "kind": "sub", "bool": false},
	],
	"java": [
		{"re": concat("", [`\bPattern\.compile\(\s*`, _jstr, `\s*\)\.matcher\([^;]*\)\.find\(\)`]), "kind": "sub", "bool": false},
		{"re": concat("", [`\bPattern\.compile\(\s*`, _jstr, `\s*\)\.matcher\([^;]*\)\.lookingAt\(\)`]), "kind": "start", "bool": false},
	],
	"php": [
		{"re": `\bpreg_match\(\s*["']/((?:[^/\\"']|\\.)*)/[a-zA-Z]*["']\s*,\s*[^,;]+?\)\s*(?:[;)=!&|<>]|$)`, "kind": "sub", "bool": false},
		{"re": `\bpreg_match\(\s*["']#((?:[^#\\"']|\\.)*)#[a-zA-Z]*["']\s*,\s*[^,;]+?\)\s*(?:[;)=!&|<>]|$)`, "kind": "sub", "bool": false},
	],
	"rb": [
		{"re": concat("", [`[=!]~\s*`, _rbre]), "kind": "sub", "bool": true},
		{"re": concat("", [`(?:^|[\s(!])`, _rbre, `\s*[=!]~`]), "kind": "sub", "bool": true},
		{"re": concat("", [`\.match\??\(\s*`, _rbre, `\s*\)`]), "kind": "sub", "bool": true},
		{"re": concat("", [`\bwith:\s*`, _rbre]), "kind": "rbfmt", "bool": false},
	],
}

# Named patterns compiled in the file: [name, pattern, usage regexes by kind].
_named_def := {
	"py": concat("", [`(?m)^\s*([A-Za-z_]\w*)\s*=\s*re\.compile\(\s*`, _pyq]),
	"js": concat("", [`(?m)^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*`, _jsre, `\s*;?\s*$`]),
	"go": concat("", [`(?m)^\s*(?:var\s+)?([A-Za-z_]\w*)\s*:?=\s*regexp\.(?:MustCompile|Compile)\(\s*`, _gostr, `\s*\)`]),
	"java": concat("", [`\bPattern\s+([A-Za-z_]\w*)\s*=\s*Pattern\.compile\(\s*`, _jstr, `\s*\)`]),
}

_named_uses(lang, name) := uses if {
	lang == "py"
	uses := [
		{"re": concat("", [`\b`, name, `\.match\(`]), "kind": "start", "bool": true},
		{"re": concat("", [`\b`, name, `\.search\(`]), "kind": "sub", "bool": true},
	]
}

_named_uses(lang, name) := uses if {
	lang == "js"
	uses := [
		{"re": concat("", [`(?:^|[^\w$.])`, replace(name, "$", `\$`), `\.test\(`]), "kind": "sub", "bool": false},
		{"re": concat("", [`\.(?:match|search)\(\s*`, replace(name, "$", `\$`), `\s*\)`]), "kind": "sub", "bool": true},
	]
}

_named_uses(lang, name) := uses if {
	lang == "go"
	uses := [{"re": concat("", [`\b`, name, `\.(?:MatchString|Match|MatchReader)\(`]), "kind": "sub", "bool": false}]
}

_named_uses(lang, name) := uses if {
	lang == "java"
	uses := [
		{"re": concat("", [`\b`, name, `\.matcher\([^;]*\)\.find\(\)`]), "kind": "sub", "bool": false},
		{"re": concat("", [`\b`, name, `\.matcher\([^;]*\)\.lookingAt\(\)`]), "kind": "start", "bool": false},
	]
}

# ── Pattern classification ───────────────────────────────────────────────

_unescape(lang, p) := replace(p, `\\`, `\`) if lang in {"java", "go"}

_unescape(lang, p) := p if not lang in {"java", "go"}

_site_unescape(site, _, p) := replace(p, `\\`, `\`) if object.get(site, "str", false)

_site_unescape(site, lang, p) := _unescape(lang, p) if not object.get(site, "str", false)

_shape := `^(\^|\\A)?(\[(?:[^\]\\^]|\\.)(?:[^\]\\]|\\.)*\]|\\[dw]|\.)(\+|\*|\{\d+(?:,\d*)?\})(\$|\\z|\\Z)?$`

# A whitespace class ([ \t]+, [\s,]) trims or splits; it validates nothing.
_parts(p) := m[0] if {
	m := regex.find_all_string_submatch_n(_shape, p, 1)
	count(m) > 0
	not regex.match(`^\[(?:\\[stnr]|[ ,])+\]$`, m[0][2])
}

_bounded(q) if startswith(q, "{")

# search semantics: one anchor only, or no anchors with a length bound
_weak("sub", lang, p, _) if {
	lang != "rb"
	m := _parts(p)
	_one_sided(m[1], m[4])
}

_weak("sub", lang, p, _) if {
	lang != "rb"
	m := _parts(p)
	m[1] == ""
	m[4] == ""
	_bounded(m[3])
}

# Ruby: ^ and $ are line anchors, so only \A ... \z is a whole-value check.
_weak("sub", "rb", p, _) if {
	m := _parts(p)
	_rb_anchored_any(m[1], m[4])
	not _rb_whole(m[1], m[4])
}

_weak("sub", "rb", p, _) if {
	m := _parts(p)
	m[1] == ""
	m[4] == ""
	_bounded(m[3])
}

# start-anchored APIs: the end anchor is what is missing
_weak("start", _, p, negated) if {
	m := _parts(p)
	m[4] == ""
	_start_intent(m[1], m[3], negated)
}

# Rails format validation with line anchors, whatever the pattern's shape.
_weak("rbfmt", _, p, _) if regex.match(`^\^|[^\\]\$$`, p)

_one_sided(s, e) if {
	s != ""
	e == ""
}

_one_sided(s, e) if {
	s == ""
	e != ""
}

_rb_anchored_any(s, e) if s != ""

_rb_anchored_any(s, e) if e != ""

_rb_whole(`\A`, `\z`)

_rb_whole(`\A`, `\Z`)

_start_intent(s, _, _) if s != ""

_start_intent(_, q, _) if _bounded(q)

_start_intent(_, _, true)

# ── Context ──────────────────────────────────────────────────────────────

# The call sits inside a string literal on its line (an odd number of quotes
# before it).
_in_string(prefix) if {
	some q in {`"`, "'", "`"}
	n := count(indexof_n(prefix, q)) - count(indexof_n(prefix, concat("", [`\`, q])))
	n % 2 == 1
}

_boolean_ctx(prefix, suffix) if regex.match(`^\s*(?:if|elif|elsif|while|unless|until|return|assert)\b|!|\bnot\b|&&|\|\||\band\b|\bor\b|\bbool\(`, prefix)

_boolean_ctx(_, suffix) if regex.match(`^\s*(?:\?|is\s|==|!=|\)\s*(?:\?|&&|\|\||\{|:)|&&|\|\||then\b)`, suffix)

_extracts(suffix) if regex.match(`^(?:[^()]|\([^()]*\))*\)\s*(?:\.\s*(?:group|groups|groupdict|start|end|span|index|pre_match|post_match|captures)\b|\[)`, suffix)

_extracts(suffix) if regex.match(`^\s*(?:\.\s*(?:group|groups|groupdict|start|end|span|index|pre_match|post_match|captures)\b|\[)`, suffix)

_context_ok(site, _, _) if not site.bool

_context_ok(site, prefix, suffix) if {
	site.bool
	_boolean_ctx(prefix, suffix)
	not _extracts(suffix)
}

# ── Findings ─────────────────────────────────────────────────────────────

_hit(lang, line, site, p_override) if {
	some m in regex.find_all_string_submatch_n(site.re, line, -1)
	idx := indexof(line, m[0])
	prefix := substring(line, 0, idx)
	suffix := substring(line, idx + count(m[0]), -1)
	not _in_string(prefix)
	p := _pat(m, p_override)
	_weak(site.kind, lang, _site_unescape(site, lang, p), _negated(prefix))
	_context_ok(site, prefix, suffix)
}

_pat(m, "") := m[1]

_pat(_, o) := o if o != ""

_negated(prefix) := false if not _negated_t(prefix)

_negated(prefix) := true if _negated_t(prefix)

_negated_t(prefix) if regex.match(`(?:!|\bnot\s+|\bunless\s+.*)\s*$`, prefix)

_message := "Validation regex is not anchored at both ends (or uses Ruby line anchors ^/$): a value that only partly conforms passes. Anchor with ^...$ (\\A...\\z in Ruby) or use a full-match API (re.fullmatch, String.matches)"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_needle(content, _file_needles[lang])
	# Only the lines holding a literal at a call site are visited: splitting
	# and walking every line of every file that merely uses preg_match or =~
	# costs more than the whole check.
	some h in regex.find_all_string_submatch_n(concat("", [`(?m)^[^\n]*(?:`, _line_gate[lang], `)[^\n]*$`]), content, -1)
	line := h[0]
	count(line) < 2000 # minified bundles are not validation code
	regex.match(_shape_tail, line)
	not helpers.is_comment_line(line)
	some site in _sites[lang]
	_hit(lang, line, site, "")
	some i in _line_numbers(content, line)
	f := _finding(path, i, line)
}

# Zero-based line indexes at which the whole line `line` occurs.
_line_numbers(content, line) := {i |
	some off in indexof_n(content, line)
	_at_line_start(content, off)
	i := count(indexof_n(substring(content, 0, off), "\n"))
}

_at_line_start(_, 0)

_at_line_start(content, off) if {
	off > 0
	substring(content, off - 1, 1) == "\n"
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_needle(content, _def_needles[lang])
	some d in regex.find_all_string_submatch_n(_named_def[lang], content, -1)
	_parts(_unescape(lang, d[2]))
	name := d[1]
	use_re := concat("", [`(?m)^[^\n]*\b`, replace(name, "$", `\$`), `\b[^\n]*$`])
	some h in regex.find_all_string_submatch_n(use_re, content, -1)
	line := h[0]
	count(line) < 2000
	not helpers.is_comment_line(line)
	some site in _named_uses(lang, name)
	_hit(lang, line, site, d[2])
	some i in _line_numbers(content, line)
	f := _finding(path, i, line)
}

_def_needles := {
	"py": {"re.compile("},
	"js": {"= /"},
	"go": {"regexp.MustCompile(", "regexp.Compile("},
	"java": {"Pattern.compile("},
}
