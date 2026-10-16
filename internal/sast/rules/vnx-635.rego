# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_635

import rego.v1

import data.vulnetix.helpers

# CWE-635 is a view (the weaknesses NVD used from 2008 to 2016), not a
# weakness with a code shape of its own. The rule reports the one concrete,
# defensible signal that maps onto it: a work marker in a comment where the
# author admits a security control is missing, disabled or broken.

metadata := {
	"id": "VNX-635",
	"name": "Unresolved security TODO/FIXME in production code",
	"description": "CWE-635 is a view of weaknesses rather than one weakness, so this rule reports its most concrete code-level signal: a TODO, FIXME, XXX or HACK marker in a comment (//, #, /* or a block-comment line) whose text admits an unresolved security gap, such as calling the code insecure or vulnerable, naming an injection, XSS, SSRF, open-redirect or path-traversal risk, asking to verify a signature, certificate, HMAC or JWT, asking to add or implement authentication, authorization, CSRF protection, access control, permission checks, input validation, sanitising, escaping, encryption, rate limiting or signature/certificate verification, saying input is not validated, sanitised, escaped, authenticated, authorised, encrypted or verified, admitting a hard-coded (API) password/secret/key/token, or disabling or bypassing SSL/TLS, certificate, hostname, CSRF, auth or signature checks (either word order). Not reported: ordinary work markers (refactor, performance, tests, error messages, authors or authorship), comments that describe a control as present, the words inside string literals, test code, and documentation files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-635/",
	"languages": ["go", "java", "kotlin", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [635],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["security-todo", "comments", "cwe-635"],
}

_exts := {".go", ".java", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".py", ".rb", ".kt"}

# A work marker after a comment opener, with no quote between them (so the
# marker is not inside a string literal on a code line).
_marker_re := `^(?:[^"'\x60]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\x60[^\x60]*\x60)*?(?://|#|/\*|^\s*\*)[^"'\x60\n]*?\b(?:TODO|FIXME|XXX|HACK)\b(.*)$`

_auth := `(?:auth|authn|authz|authenticat\w*|authori[sz]\w*)\b`

_admission_re := concat("", [
	`(?i)\b(?:insecure|vulnerab\w*|security\s+(?:hole|issue|risk|bug|problem|flaw|fix)`,
	`|(?:sql\s+|command\s+|code\s+|shell\s+|ldap\s+|xpath\s+|template\s+|header\s+)?injection\b|xss\b|ssrf\b|open\s+redirect|path\s+traversal`,
	`|(?:add|implement|missing|needs?|enable|re-?enable|no)\s+(?:proper\s+|real\s+|any\s+|an?\s+|the\s+)?(?:`, _auth, `|csrf|xsrf|access\s+control|permission\s+checks?|input\s+validation|validation|saniti[sz]\w*|escaping|encryption|rate[\s-]?limit\w*|signature\s+(?:verification|check)|cert(?:ificate)?\s+(?:verification|validation|check\w*)|host(?:name)?\s+verification)`,
	`|verify\s+(?:the\s+)?(?:\w+\s+){0,2}?(?:signature|certificate|cert|hmac|jwt)s?\b`,
	`|(?:not|isn't|is\s+not|never)\s+(?:validated|saniti[sz]ed|escaped|authenticated|authori[sz]ed|encrypted|verified)`,
	`|un(?:validated|saniti[sz]ed|escaped|authenticated|authori[sz]ed|encrypted|verified)\b`,
	`|hard-?coded\s+(?:\w+\s+)?(?:password|secret|key|credential|token)s?`,
	`|(?:disabl\w*|skip\w*|bypass\w*)\s+(?:the\s+)?(?:ssl|tls|cert\w*|csrf|`, _auth, `|signature|verification|security)`,
	`|(?:verification|validation|cert(?:ificate)?\s+checks?|csrf(?:\s+protection)?|`, _auth, `)\s+(?:is\s+|was\s+)?(?:disabled|skipped|bypassed|turned\s+off)`,
	`|escape\s+(?:the\s+)?output|(?:validate|saniti[sz]e|escape)\s+(?:the\s+|all\s+)?(?:user\s+|untrusted\s+|request\s+)?(?:input|params|parameters)`,
	`|(?:remove|fix)\s+(?:this\s+|the\s+)?(?:security\s+|`, _auth, `\s+)?bypass)`,
])

# One pass over the file: a marker with a security word later on its line.
_prefilter_re := `(?:TODO|FIXME|XXX|HACK)[^\n]*(?i:secur|vulnerab|auth|csrf|xsrf|access|permission|validat|saniti|escap|encrypt|rate|signature|cert|hard-?coded|ssl|tls|verif|inject|xss|ssrf|redirect|traversal)`

_has_marker(content) if contains(content, "TODO")

_has_marker(content) if contains(content, "FIXME")

_has_marker(content) if contains(content, "XXX")

_has_marker(content) if contains(content, "HACK")

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	_has_marker(content)
	regex.match(_prefilter_re, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(TODO|FIXME|XXX|HACK)\b`, line)
	m := regex.find_all_string_submatch_n(_marker_re, line, 1)
	count(m) > 0
	regex.match(_admission_re, m[0][1])
	finding := {
		"rule_id": metadata.id,
		"message": "A TODO/FIXME comment admits an unresolved security gap (missing or disabled control). Resolve it before release or track it as a security issue",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
