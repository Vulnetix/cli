# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_625

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-625",
	"name": "Permissive host/URL allow-list regular expression",
	"description": "Reports a regular expression that checks a URL, origin or host name and accepts more than intended, in the three forms that bypass real allow-lists: an unescaped dot inside a host name (^https://shop.example.com/ also accepts shopXexample.com), a host pattern that ends at the domain with no end anchor (^https://([a-z]+\\.)?example\\.com also accepts https://example.com.attacker.net; an optional port (:\\d+)? or slash /? after the domain does not anchor it), and a pattern that is only a domain anchored at the end but not the start, used with search/test/MatchString (example\\.com$ also accepts evilexample.com and a URL that merely ends in the domain). Patterns are read from Python re.match/search/compile, JavaScript regex literals used with .test()/.exec() or assigned, new RegExp('...'), Go regexp.MustCompile/Compile/MatchString and Java Pattern.compile/matches and String.matches. A pattern counts as a host check when it starts with ^, contains ://, or is used with re.match. Not reported: escaped dots with an end anchor ($, \\Z, a following / or (:\\d+)?$), re.fullmatch() and Java's whole-string matches() for the missing-anchor form, re.sub(), JavaScript .replace()/.replaceAll()/.split() with a regex literal and other replace/extract uses, patterns without a host name, test files, comments and plain string literals. Redirect, CORS and SSRF checks built on these patterns are what the bypass defeats; the rule does not follow a pattern stored in a variable into its use.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-625/",
	"languages": ["python", "node", "go", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [625],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["permissive-url", "regex", "cwe-625"],
}

_tld := `(?:com|net|org|io|dev|co|app|gov|edu|cloud|ai|me|us|uk|de|fr|nl|jp|cn|ru|in|au|ca|biz|info|xyz|local|internal)`

_gate := `re\.(match|search|compile)\s*\(|RegExp\s*\(|\.(test|exec)\s*\(|=\s*/\^|regexp\.(MustCompile|Compile|MatchString)\s*\(|Pattern\.(compile|matches)\s*\(|\.matches\s*\(`

_lang("py", path) if endswith(path, ".py")

_lang("js", path) if {
	some ext in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang("go", path) if endswith(path, ".go")

_lang("java", path) if endswith(path, ".java")

# (pattern, implicitly anchored at start, whole-string match)
_patterns("py", line) := {[p, call == "match", false] |
	some m in regex.find_all_string_submatch_n(`\bre\.(match|search|compile)\s*\(\s*[rRbB]{0,2}(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')`, line, -1)
	call := m[1]
	p := concat("", [m[2], m[3]])
}

_patterns("js", line) := {[p, false, false] |
	some m in regex.find_all_string_submatch_n(`(?:(?:^|[=(,:!&|?]\s*|\breturn\s+)/((?:[^/\\\n]|\\.)+)/[dgimsuy]*\s*(?:\.(?:test|exec)\s*\(|[;,)]|$)|new\s+RegExp\s*\(\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|\x60([^\x60$]*)\x60))`, line, -1)
	p := concat("", [m[1], m[2], m[3], m[4]])
}

_patterns("go", line) := {[p, false, false] |
	some m in regex.find_all_string_submatch_n(`\bregexp\.(?:MustCompile|Compile|MatchString)\s*\(\s*(?:\x60([^\x60]*)\x60|"((?:[^"\\]|\\.)*)")`, line, -1)
	p := concat("", [m[1], m[2]])
}

_patterns("java", line) := {[p, false, full] |
	some m in regex.find_all_string_submatch_n(`(Pattern\.compile|Pattern\.matches|\.matches)\s*\(\s*"((?:[^"\\]|\\.)*)"`, line, -1)
	full := m[1] != "Pattern.compile"
	p := m[2]
}

_host_check(p, start_anchored) if start_anchored

_host_check(p, _) if startswith(p, "^")

_host_check(p, _) if contains(p, "://")

_host_check(p, _) if contains(p, `:\/\/`)

# a dot that is not escaped, between two host labels
_unescaped_dot(p) if regex.match(concat("", [`[A-Za-z0-9-]\.`, _tld, `(?:$|[^A-Za-z0-9])`]), p)

# the pattern ends at the escaped domain: nothing anchors the end
_open_end(p) if regex.match(concat("", [`\\\\?\.`, _tld, _open_suffix]), p)

# what may follow the domain without anchoring it: ) ? (:\d+)? /? \/?
_open_suffix := `(?:[)?]|\((?:\?:)?:\\{1,2}d[+*]\)\?|\\{0,2}/\?)*$`

# The whole pattern is a domain that ends anchored but starts unanchored, used
# with search/test: evilexample.com and https://evil.net/?example.com match.
_tld_strict := `(?:com|net|org|io|co|gov|edu|cloud|ai|uk|de|internal)`

_no_start(p, start_anchored) if {
	not start_anchored
	regex.match(concat("", [`^[A-Za-z0-9-]+(?:\\{1,2}\.[A-Za-z0-9-]+)*\\{1,2}\.`, _tld_strict, `(?:\$|\\{1,2}Z)$`]), p)
}

_reason(p, _) := "an unescaped '.' in the host name matches any character" if _unescaped_dot(p)

_reason(p, full) := "the host pattern has no end anchor, so example.com.attacker.net also matches" if {
	not _unescaped_dot(p)
	not full
	_open_end(p)
}

findings contains finding if {
	some path, content in input.file_contents
	some lang in {"py", "js", "go", "java"}
	_lang(lang, path)
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	regex.match(concat("", [`[A-Za-z0-9-]\\{0,2}\.`, _tld, `\b`]), content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 400
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	some pat in _patterns(lang, line)
	p := pat[0]
	not _js_transform(lang, line, p)
	why := _why(p, pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Permissive allow-list regular expression: %s. Escape every '.' and anchor the end ($ or a following '/')", [why]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_why(p, pat) := r if {
	_host_check(p, pat[1])
	r := _reason(p, pat[2])
}

_why(p, pat) := "the host pattern has no start anchor, so evilexample.com (or a URL that merely ends in the domain) also matches" if {
	not _host_check(p, pat[1])
	not pat[2]
	_no_start(p, pat[1])
}

# u.replace(/^https:\/\/www.example.com/, '') rewrites a URL; it checks nothing.
_js_transform("js", line, p) if {
	some fn in {".replace(/", ".replaceAll(/", ".split(/"}
	contains(line, concat("", [fn, p, "/"]))
}
