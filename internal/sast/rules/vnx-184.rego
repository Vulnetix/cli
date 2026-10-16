# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_184

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-184",
	"name": "Incomplete List of Disallowed Inputs",
	"description": "Input validation by deny-list: a collection literal (Python list/tuple/set/dict, JavaScript array, Java List.of/Arrays.asList/Set.of/array, Go slice or map, PHP array) whose entries are attack tokens, either named as a deny-list (blacklist, denylist, blocklist, forbidden, disallowed, banned, blocked, dangerous, unsafe, bad..., ...filter) with at least one such entry, or holding two or more tokens of one family and used by a later contains/includes/replace/str_replace/in/for loop; and such a collection written inline in the check itself (any(c in s for c in [\";\", \"&\"]), [...].some(...), str_replace(array(';', '&&'), '', $x), in_array($c, [...]), for t in [...], Go for _, t := range []string{...}, Java for (String t : new String[]{...})). Families: shell metacharacters (; && | || & ` $( > <), script/HTML (<script, javascript:, onerror, onload, <iframe), traversal (../, ..\\\\, /etc/passwd) and SQL (--, /*, ', union, select, drop..., with at least one punctuation token or union), plus executable extensions (.php, .exe, .jsp, .sh...) for a deny-named list. A deny-list misses an encoding, a case, a separator or a newline the author did not think of. Not reported: escaping tables (entries mapped to non-empty replacements), allow-lists, operator, keyword, separator and token tables of a lexer or formatter (OPERATORS, SQL_KEYWORDS, separators) unless they are searched for inside the input (any(k in q for k in SQL_KEYWORDS), includes, replace), deny-named lists of other values (IP addresses, user names), token lists the file never applies, test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-184/",
	"languages": ["go", "java", "node", "python", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [184],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["denylist", "validation", "cwe-184"],
}

_ext_ok := {"py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "go", "php"}

_deny_name := `(?i)black_?list|deny_?list|block_?list|forbidden|disallow|banned|blocked|dangerous|unsafe|reject|^\$?bad_?|_bad_|filter`

# name = <collection opener>
_assign_re := `^\s*(?:(?:private|public|protected|static|final|const|let|var|readonly|export)\s+)*(?:[\w<>\[\],.?]+\s+)?(\$?[A-Za-z_]\w*)\s*(?::\s*[^=]{1,60})?\s*:?=\s*(.*)$`

_opener_re := `^(?:new\s+[\w.<>]+\s*(?:\[\])?\s*)?(?:[\w.]+\s*(?:<[^>]*>)?\s*)?[\[\{\(]|^array\s*\(|^\[\]\w+\s*\{|^map\[[^\]]+\]\w+\s*\{`

_lit_re := `"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'`

_family := {
	"shell": {";", "&&", "&", "|", "||", "`", "$(", ">", "<", ">>", "\\n"},
	"html": {"<script", "<script>", "</script>", "javascript:", "onerror", "onerror=", "onload", "onload=", "<iframe", "<img", "<svg", "alert(", "document.cookie"},
	"path": {"../", "..\\", "..\\\\", "..", "/etc/passwd", "%2e%2e", "..%2f"},
	"sql": {"--", "/*", "*/", "'", "' or", "or 1=1", "union", "select", "drop", "insert", "delete", "update", "xp_cmdshell", "sleep(", "benchmark(", ";"},
}

_sql_anchor := {"--", "/*", "'", "' or", "or 1=1", "union", "xp_cmdshell"}

_exts := {".php", "php", ".phtml", "phtml", ".phar", ".exe", "exe", ".jsp", "jsp", ".jspx", ".asp", "asp", ".aspx", "aspx", ".sh", "sh", ".bat", "bat", ".cmd", ".ps1", ".dll", ".cgi", ".pl", ".py", ".js", ".html", ".htm", ".svg", ".war", ".jar", ".htaccess"}

_bare(l) := lower(substring(l, 1, count(l) - 2))

# The lines of the collection opened on line i: up to the first line that
# closes a bracket at its end, at most twelve lines.
_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 12])
	closers := [j |
		some j in numbers.range(i, last)
		regex.match(`[\]\)\}]\s*[;,]?\s*$`, lines[j])
	]
	e := min(array.concat([last], closers))
}

_entries(text) := {_bare(l) | some l in regex.find_n(_lit_re, text, -1)}

# Pairs mapped to a non-empty value: an escaping or translation table.
_escaping(text) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(`, _lit_re, `)\s*(?:=>|:)\s*(`, _lit_re, `)`]), text, -1)
	count(m[2]) > 2
}

_family_hits(es, fam) := {e | some e in es; _family[fam][e]}

_strong(es) if {
	some fam in {"shell", "html", "path"}
	count(_family_hits(es, fam)) >= 2
}

_strong(es) if {
	hits := _family_hits(es, "sql")
	count(hits) >= 2
	some a in hits
	_sql_anchor[a]
}

_any_token(es) if {
	some fam, _ in _family
	count(_family_hits(es, fam)) >= 1
}

_any_token(es) if {
	some e in es
	_exts[e]
}

_used(lines, e, v) if {
	re := concat("", [`(?:^|[^\w$])`, replace(v, "$", `\$`), `\b`])
	some j in numbers.range(e + 1, min([count(lines) - 1, e + 40]))
	l := lines[j]
	regex.match(re, l)
	regex.match(`replace|contains|includes|indexOf|strpos|stristr|strstr|\bin\b|\bany\(|\.some\(|forEach|\bfor\b|\brange\b|\bmatch|\.test\(|\.split\(|array_keys|in_array`, l)
}

_in_string(line, word) if {
	idx := indexof(line, word)
	idx >= 0
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	count(regex.find_n(`"`, pre, -1)) % 2 == 1
}

_src[path] := content if {
	some path, content in input.file_contents
	parts := split(path, ".")
	_ext_ok[parts[count(parts) - 1]]
	not helpers.is_test_path(path)
	not contains(path, ".min.")
}

_reported(lines, i, e, v, es) if {
	regex.match(_deny_name, v)
	_any_token(es)
}

_reported(lines, i, e, v, es) if {
	_strong(es)
	not regex.match(_grammar_name, v)
	_used(lines, e, v)
}

# A keyword or operator list searched for inside the input (any(k in q for k
# in SQL_KEYWORDS), .some(...includes), replace) is a filter after all; a
# token compared for equality with an entry (tok in OPERATORS) is a lexer.
_reported(lines, i, e, v, es) if {
	_strong(es)
	regex.match(_grammar_name, v)
	re := concat("", [`(?:^|[^\w$])`, replace(v, "$", `\$`), `\b`])
	some j in numbers.range(e + 1, min([count(lines) - 1, e + 40]))
	regex.match(re, lines[j])
	regex.match(`\bany\s*\(|\.some\s*\(|replace|\.includes\s*\(|\.contains\s*\(|strpos|str_contains`, lines[j])
}

# Python loop over the list whose element is then searched for inside some
# other text: for tok in SQL_TOKENS: if tok in q.lower()
_reported(lines, i, e, v, es) if {
	_strong(es)
	regex.match(_grammar_name, v)
	some j in numbers.range(e + 1, min([count(lines) - 1, e + 40]))
	m := regex.find_all_string_submatch_n(concat("", [`^\s*for\s+(\w+)\s+in\s+`, replace(v, "$", `\$`), `\s*:`]), lines[j], 1)
	count(m) > 0
	t := m[0][1]
	some k in numbers.range(j + 1, min([count(lines) - 1, j + 4]))
	regex.match(concat("", [`\b`, t, `\s+in\s+[A-Za-z_]`]), lines[k])
	not regex.match(concat("", [`\b`, t, `\s+in\s+`, v, `\b`]), lines[k])
}

# A lexer's or formatter's table of operators and keywords is a grammar,
# not a validation list.
_grammar_name := `(?i)operator|^ops?$|_ops?$|token|delim|separator|punct|keyword|lexer|symbol|grammar|reserved`

# An attack-token collection written inline in the check itself:
# any(c in s for c in [";", "&"]), [...].some(...), str_replace(array(...), '', $x).
_inline_use := `\bany\s*\(|\ball\s*\(|\]\s*\.\s*(?:some|every|forEach|find)\s*\(|\bstr_i?replace\s*\(\s*(?:array\s*\(|\[)|\bin_array\s*\([^,]+,\s*(?:array\s*\(|\[)|\bfor\s+\(?\s*\w+\s*\)?\s+in\s+[\[\(]\s*["']|\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+of\s+\[|\brange\s+\[\]string\s*\{|\bfor\s*\(\s*(?:final\s+)?String\s+\w+\s*:\s*(?:new\s+String\s*\[\]\s*\{|List\.of\s*\(|Arrays\.asList\s*\()`

# A quoted token that a strong inline list needs one of.
_qtok(s) if contains(s, `";"`)

_qtok(s) if contains(s, `';'`)

_qtok(s) if contains(s, `"&`)

_qtok(s) if contains(s, `'&`)

_qtok(s) if contains(s, `"|`)

_qtok(s) if contains(s, `'|`)

_qtok(s) if contains(s, `"<script`)

_qtok(s) if contains(s, `'<script`)

_qtok(s) if contains(s, `"javascript:`)

_qtok(s) if contains(s, `'javascript:`)

_qtok(s) if contains(s, `"../`)

_qtok(s) if contains(s, `'../`)

_qtok(s) if contains(s, `"--"`)

_qtok(s) if contains(s, `'--'`)

_inline_hint(s) if contains(s, "any(")

_inline_hint(s) if contains(s, "all(")

_inline_hint(s) if contains(s, "].")

_inline_hint(s) if contains(s, "replace(")

_inline_hint(s) if contains(s, "in_array(")

_inline_hint(s) if contains(s, " in [")

_inline_hint(s) if contains(s, " in (")

_inline_hint(s) if contains(s, " of [")

_inline_hint(s) if contains(s, "range []string")

_inline_hint(s) if contains(s, ": new String[]")

_inline_hint(s) if contains(s, ": List.of(")

_inline_hint(s) if contains(s, ": Arrays.asList(")

findings contains finding if {
	some path, content in _src
	_qtok(content)
	_inline_hint(content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 1000
	_qtok(line)
	_inline_hint(line)
	regex.match(_inline_use, line)
	not helpers.is_comment_line(line)
	not regex.match(`=\s*(?:new\s+[\w.<>\[\]]+\s*)?(?:array\s*\(|[\[\{])`, line)
	not _escaping(line)
	es := _entries(line)
	_strong(es)
	finding := {
		"rule_id": metadata.id,
		"message": "Input is validated against an inline deny-list of attack tokens; deny-lists miss encodings, cases and separators the author did not list. Validate against an allow-list of what is permitted, or use the safe API (parameterised query, argument array, output encoding)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in _src
	regex.match(`["'](?:;|&&|\||<script|javascript:|\.\./|--|\.php|\.exe|\.jsp)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	count(line) < 1000
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_assign_re, line, 1)
	regex.match(_opener_re, m[2])
	v := m[1]
	not _in_string(line, v)
	e := _end(lines, i)
	text := concat("\n", array.slice(lines, i, e + 1))
	not _escaping(text)
	es := _entries(text)
	_reported(lines, i, e, v, es)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' validates input against a deny-list of attack tokens; deny-lists miss encodings, cases and separators the author did not list. Validate against an allow-list of what is permitted, or use the safe API (parameterised query, argument array, output encoding)", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
