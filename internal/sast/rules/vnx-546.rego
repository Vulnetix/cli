# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_546

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-546",
	"name": "Suspicious Comment",
	"description": "A TODO, FIXME, HACK, XXX or BUG comment admits a security gap in the code beside it: the comment starts with the marker (TODO:, TODO(name):, @todo, FIXME ...) and its text names a security concern (authentication, authorization, permission, privilege, password, credential, secret, CSRF, XSS, injection, sanitising, escaping, validation, encryption, plain text, SSL/TLS, certificates, overflow, bounds checks, unsafe, insecure, vulnerable, hard-coded, rate limiting, access control, traversal, parameterized queries / prepared statements, verifying a signature). Whole-line, block-comment continuation and trailing comments are read, in Python, JavaScript/TypeScript, Java, Go, C and C++. Not reported: ordinary TODOs (refactoring, performance, naming), the vocabulary in a non-security sense (the Escape key, CSS text overflow, Go's unsafe.String/unsafe.Pointer named as an API), security prose without a marker, markers inside string literals or URLs, identifiers that contain the word (TODO_AUTH, todoSecurity), XXXXXX placeholders, and test files. A marker that admits a missing, disabled or broken control (insecure, vulnerable, an injection/XSS/SSRF risk, add/missing/no authorization, CSRF or validation, verify a signature, skip TLS verification, hard-coded password...) in Go, Java, JavaScript/TypeScript or Python is reported by VNX-635, not here; this rule keeps the rest of the security vocabulary in those languages, and C/C++.",
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

# A marker that admits a missing, disabled or broken control in a language
# VNX-635 reads is reported by VNX-635 (the same comment, judged more
# precisely). These are VNX-635's own expressions, kept in step with it.
_exts_635 := {".go", ".java", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".py", ".rb", ".kt"}

_marker_635 := `(?://|#|/\*|^\s*\*)[^"'\x60\n]*?\b(?:TODO|FIXME|XXX|HACK)\b(.*)$`

_auth_635 := `(?:auth|authn|authz|authenticat\w*|authori[sz]\w*)\b`

_admission_635 := concat("", [
	`(?i)\b(?:insecure|vulnerab\w*|security\s+(?:hole|issue|risk|bug|problem|flaw|fix)`,
	`|(?:sql\s+|command\s+|code\s+|shell\s+|ldap\s+|xpath\s+|template\s+|header\s+)?injection\b|xss\b|ssrf\b|open\s+redirect|path\s+traversal`,
	`|(?:add|implement|missing|needs?|enable|re-?enable|no)\s+(?:proper\s+|real\s+|any\s+|an?\s+|the\s+)?(?:`, _auth_635, `|csrf|xsrf|access\s+control|permission\s+checks?|input\s+validation|validation|saniti[sz]\w*|escaping|encryption|rate[\s-]?limit\w*|signature\s+(?:verification|check)|cert(?:ificate)?\s+(?:verification|validation|check\w*)|host(?:name)?\s+verification)`,
	`|verify\s+(?:the\s+)?(?:\w+\s+){0,2}?(?:signature|certificate|cert|hmac|jwt)s?\b`,
	`|(?:not|isn't|is\s+not|never)\s+(?:validated|saniti[sz]ed|escaped|authenticated|authori[sz]ed|encrypted|verified)`,
	`|un(?:validated|saniti[sz]ed|escaped|authenticated|authori[sz]ed|encrypted|verified)\b`,
	`|hard-?coded\s+(?:\w+\s+)?(?:password|secret|key|credential|token)s?`,
	`|(?:disabl\w*|skip\w*|bypass\w*)\s+(?:the\s+)?(?:ssl|tls|cert\w*|csrf|`, _auth_635, `|signature|verification|security)`,
	`|(?:verification|validation|cert(?:ificate)?\s+checks?|csrf(?:\s+protection)?|`, _auth_635, `)\s+(?:is\s+|was\s+)?(?:disabled|skipped|bypassed|turned\s+off)`,
	`|escape\s+(?:the\s+)?output|(?:validate|saniti[sz]e|escape)\s+(?:the\s+|all\s+)?(?:user\s+|untrusted\s+|request\s+)?(?:input|params|parameters)`,
	`|(?:remove|fix)\s+(?:this\s+|the\s+)?(?:security\s+|`, _auth_635, `\s+)?bypass)`,
])

_reported_by_635(path, line) if {
	some ext in _exts_635
	endswith(path, ext)
	m := regex.find_all_string_submatch_n(_marker_635, line, 1)
	count(m) > 0
	regex.match(_admission_635, m[0][1])
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
	not _reported_by_635(path, line)
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
