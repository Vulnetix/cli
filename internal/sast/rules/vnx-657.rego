# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_657

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-657",
	"name": "Violation of Secure Design Principles",
	"description": "CWE-657 is a design-level class with no single code shape, so this rule reports its most concrete static signal: a TODO, FIXME, XXX or HACK comment in Python or JavaScript/TypeScript production code in which the author records that a security control is missing, disabled or bypassed. Reported: the marker followed by security, insecure, vulnerable or exploitable, or by a verb of absence (add, implement, missing, no, not, enable, disable, bypass, skip, remove, without, lacks, turn off) within forty characters of a control, or a control followed within thirty characters by disabled, turned off, bypassed, skipped, missing or not implemented/enforced/checked/verified (SSL verification disabled), or a marker that orders the control (TODO(bob): sanitize, escape, authenticate, encrypt, or validate user input, the request, a token or a filename) (authentication, authorization, auth, access control, permission check, CSRF/XSRF, sanitizing, escaping, input validation, validation (not validated), encryption, TLS/SSL, certificate verification, rate limiting, a hard-coded secret, password, key or credential). Whole-line and trailing comments, and lines inside a block comment, are read. Not reported: ordinary TODOs (performance, refactoring, layout), notes about adding tests or documentation, statements that a control exists, the same words in a string literal, and test files. The comment is the finding; the code it describes may be reported by other rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-657/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [657],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["comments", "violation-of-secure-design", "security-debt", "cwe-657"],
}

_exts := {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".jsx", ".tsx"}

_strip(line) := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`(?:[^`\\\\]|\\\\.)*`", `""`)

_py_comment := `#\s*(?:TODO|FIXME|XXX|HACK)\b(.*)$`

_js_comment := `(?://|/\*|^\s*\*)\s*(?:TODO|FIXME|XXX|HACK)\b(.*)$`

_re(path) := _py_comment if endswith(path, ".py")

_re(path) := _js_comment if not endswith(path, ".py")

# The word itself, not part of a file, package or path name
# (express-security.txt, vendor/security/).
_admission := `(?i)(?:^|[^\w./-])(?:security|insecure|vulnerab\w*|exploitable)(?:[^\w./-]|$)`

_gap := `(?i)\b(?:add|implement|missing|no|not|enable|re-?enable|disabled?|disabling|bypass(?:es|ed)?|skip(?:s|ped)?|remove|without|lacks?|turn(?:ed)?\s+off)\b.{0,40}?\b(?:auth\w*|csrf|xsrf|access\s+control|permission\s+checks?|sanitiz\w*|sanitis\w*|escap\w*|input\s+validation|validation|encrypt\w*|tls|ssl|certificate\s+verification|cert\s+check\w*|rate[\s_-]?limit\w*|hard-?coded\s+(?:secret|password|key|credentials?|token))`

_about_tests := `(?i)\b(?:tests?|specs?|docs?|documentation|unit\s*tests?)\b`

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	regex.match(`TODO|FIXME|XXX|HACK`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`TODO|FIXME|XXX|HACK`, line)
	m := regex.find_all_string_submatch_n(_re(path), _strip(line), 1)
	count(m) > 0
	text := m[0][1]
	_flags(text)
	not regex.match(_about_tests, text)
	finding := {
		"rule_id": metadata.id,
		"message": "Comment records a missing, disabled or bypassed security control. Implement the control or track it as a security defect; do not ship the gap",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_flags(text) if regex.match(_admission, text)

_flags(text) if regex.match(_gap, text)

_flags(text) if regex.match(_gap_after, text)

_flags(text) if regex.match(_imperative, text)

# The control named first, then its absence: "SSL verification disabled",
# "certificate verification is turned off".
_gap_after := `(?i)\b(?:auth(?:entication|orization|z|n)?|csrf|xsrf|access\s+control|permission\s+checks?|sanitiz\w*|sanitis\w*|escaping|input\s+validation|encryption|tls|ssl|(?:certificate|cert|hostname|signature)\s+(?:verification|validation|checks?))\b.{0,30}?\b(?:is\s+|are\s+|was\s+)?(?:disabled|turned\s+off|switched\s+off|bypassed|skipped|missing|not\s+(?:implemented|enforced|checked|verified|enabled|validated))\b`

# The marker is an order to add the control: "TODO(bob): escape user input".
_imperative := `(?i)^\s*(?:\([^)]*\))?\s*[:\-]?\s*(?:sanitiz\w*|sanitis\w*|escape|html-?escape|authenticate|authori[sz]e|encrypt|validate\s+(?:the\s+)?(?:user|input|request|param\w*|payload|signature|token|upload|file\s*name|path|url|redirect))\b`
