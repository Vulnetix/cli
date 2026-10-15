# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_546

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-546",
	"name": "Suspicious Comment",
	"description": "A TODO, FIXME, HACK, XXX or BUG comment admits a security gap in the code beside it: the comment starts with the marker (TODO:, TODO(name):, @todo, FIXME ...) and its text names a security concern (authentication, authorization, permission, privilege, password, credential, secret, CSRF, XSS, injection, sanitising, escaping, validation, encryption, plain text, SSL/TLS, certificates, overflow, bounds checks, unsafe, insecure, vulnerable, hard-coded, rate limiting, access control, traversal, parameterized queries / prepared statements, verifying a signature). Whole-line, block-comment continuation and trailing comments are read, in Python, JavaScript/TypeScript, Java, Go, C and C++. Not reported: ordinary TODOs (refactoring, performance, naming), the vocabulary in a non-security sense (the Escape key, CSS text overflow, Go's unsafe.String/unsafe.Pointer named as an API), security prose without a marker, markers inside string literals or URLs, identifiers that contain the word (TODO_AUTH, todoSecurity), XXXXXX placeholders, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-546/",
	"languages": ["c", "cpp", "go", "java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [546],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["comments", "todo-comment", "cwe-546"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "c" if {
	some ext in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".java", ".go", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

# Where a comment begins: `#` for Python; `//`, `/*` or a leading `*` otherwise.
_comment_re := {
	"py": `^(.*?)#+\s*(.*)$`,
	"c": `^(.*?)(?://+|/\*+|^\s*\*+)\s*(.*)$`,
}

_marker_re := `^@?(TODO|FIXME|HACK|XXX|BUG)\b(\([^)]*\))?\s*[:\-!.,]?\s*`

_security_re := `(?i)\b(secur(e|ity)|insecure\w*|vulnerab\w*|exploit\w*|auth|authn|authz|authenticat\w*|unauthenticat\w*|authori[sz]\w*|unauthori[sz]\w*|permissions?|privileges?|passwords?|passwd|credentials?|secrets?|csrf|xsrf|xss|injections?|injectable|saniti[sz]\w*|unsaniti[sz]\w*|escap(e|es|ed|ing)|unescaped|validat\w*|unvalidated|encrypt\w*|unencrypted|plain\s?text|ssl|tls|certificates?|overflows?|unsafe|hard-?coded|rate[- ]?limit\w*|access control|traversal|bounds?[- ]checks?|bounds?[- ]checking|out[- ]of[- ]bounds|parameteri[sz]ed|prepared statements?|(verify|verifies|verifying|check|checking|validate)\s+(the\s+)?(\w+\s+)?signatures?)\b`

# Words of the security vocabulary used in a non-security sense, removed from
# the comment text before it is judged: the Escape key, CSS text overflow,
# and Go's unsafe package named as an API (unsafe.String, unsafe.Pointer).
_lookalike_re := `(?i)\bescape[- ]key\b|\b(text|css|scroll|layout|content)[- ]overflow\b|\boverflow[- ](hidden|auto|scroll|menu|x|y)\b|\bunsafe\.\w+`

_quotes_balanced(prefix) if {
	strings.count(prefix, `"`) % 2 == 0
	strings.count(prefix, "'") % 2 == 0
	strings.count(prefix, "`") % 2 == 0
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`TODO|FIXME|HACK|XXX|BUG`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(TODO|FIXME|HACK|XXX|BUG)\b`, line)
	m := regex.find_all_string_submatch_n(_comment_re[lang], line, 1)
	count(m) > 0
	_quotes_balanced(m[0][1])
	text := m[0][2]
	regex.match(_marker_re, text)
	rest := regex.replace(regex.replace(text, _marker_re, ""), _lookalike_re, " ")
	regex.match(_security_re, rest)
	finding := {
		"rule_id": metadata.id,
		"message": "A TODO/FIXME/HACK comment records a known security gap that is still in the code. Fix the weakness it describes, or track it in the issue tracker with an owner, rather than leaving the admission in the source",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
