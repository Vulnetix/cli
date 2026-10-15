# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_204

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-204",
	"name": "Observable Response Discrepancy",
	"description": "A login path answers an unknown account differently from a wrong password, so the response tells an attacker which usernames or email addresses exist (account enumeration). Reported: a string literal saying the user, username, account, email or login does not exist, is not found, unknown, invalid or not registered, or that no account was found (\"User not found\", \"no such user\", \"Invalid username\", \"#{email} doesn't exist\", \"That email is not registered\") within 20 lines of, and in the same function as, a distinct literal saying the password is wrong, invalid, incorrect or not valid. The user-not-found line is reported, in Python, JavaScript/TypeScript, Go, Java, PHP, Ruby and C#. Not reported: log statements (console, logger, logging, slog), messages about the current, old, new or repeated password of a signed-in user (change-password forms), test code, one combined message (\"Invalid username or password\"), a not-found message with no password message beside it (an admin lookup returning 404), messages in comments, and messages in different functions of the file. Timing differences between the two branches are VNX-205's subject, not this rule's.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-204/",
	"languages": ["go", "java", "node", "python", "php", "ruby", "csharp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [204],
	"capec": ["CAPEC-575"],
	"attack_technique": ["T1589"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["account-enumeration", "authentication", "observable-response", "cwe-204"],
}

_exts := {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".php", ".rb", ".cs"}

_user_missing_re := `(?i)\b(?:user\s*name|user|account|e-?mail(?:\s+address)?|login|member)\b.{0,40}?\b(?:not\s+found|does\s*n[o']?t\s+exists?|not\s+exists?|is\s+(?:invalid|unknown|not\s+registered)|not\s+registered|unknown)\b|\b(?:no\s+such|unknown|invalid|non-?existent|unregistered)\s+(?:user\s*name|user|account|e-?mail(?:\s+address)?|login)\b|\bno\s+(?:user|account|member)s?\s+(?:found|exists?|registered|with\s+(?:that|this)\s+(?:e-?mail|user\s*name|name|login))\b`

_log_call_re := `(?i)\b(?:console\.\w+|s?log(?:ger|rus)?\.\w+|_?logger\.\w+|logging\.\w+|print|println|fmt\.Print\w*|System\.(?:out|err)\.print\w*|error_log|puts|Rails\.logger\.\w+)\s*\(`

_bad_password_re := `(?i)\b(?:wrong|invalid|incorrect|bad)\s+password\b|\bpassword\s+(?:is\s+)?(?:incorrect|wrong|invalid|mismatch|not\s+(?:valid|correct|recogni[sz]ed)|does\s*n[o']?t\s+match|did\s*n[o']?t\s+match)\b`

# One message that covers both cases is the fix, not the flaw.
_combined_re := `(?i)(?:user\s*name|user|e-?mail|login|account)\s*(?:and\s*/\s*or|or|and|/)\s*password|password\s*(?:and\s*/\s*or|or|/)\s*(?:user\s*name|e-?mail)|credentials`

_fn_header_re := `^\s*(?:async\s+)?def\s|^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\b|^func\s|^\s*(?:(?:public|private|protected|internal|static|final|override|async|virtual)\s+)+[\w<>\[\],\s]*\w+\s*\([^;]*$|^\s*router\.\w+\s*\(|^\s*app\.\w+\s*\(`

_has_quote(line) if contains(line, "\"")

_has_quote(line) if contains(line, "'")

_has_quote(line) if contains(line, "`")

_user_missing(line) if {
	_has_quote(line)
	not helpers.is_comment_line(line)
	regex.match(_user_missing_re, line)
	not regex.match(`(?i)password|credential`, line)
	not regex.match(_log_call_re, line)
}

_bad_password(line) if {
	_has_quote(line)
	not helpers.is_comment_line(line)
	not regex.match(_log_call_re, line)
	regex.match(_bad_password_re, line)
	not regex.match(`(?i)\b(?:current|old|new|existing|previous|repeat\w*|confirm\w*)\s+password`, line)
	not regex.match(_combined_re, line)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	not helpers.is_test_path(path)
	endswith(path, ext)
	regex.match(`(?i)password`, content)
	regex.match(_bad_password_re, content)
	lines := split(content, "\n")
	some i, line in lines
	_user_missing(line)
	some j in numbers.range(max([0, i - 20]), min([count(lines) - 1, i + 20]))
	j != i
	_bad_password(lines[j])
	not _function_between(lines, min([i, j]), max([i, j]))
	finding := {
		"rule_id": metadata.id,
		"message": "Login answers an unknown account with a different message from a wrong password, which tells an attacker which accounts exist. Return one generic message (\"Invalid username or password\") for both cases",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_function_between(lines, a, b) if {
	b > a
	some k in numbers.range(a + 1, b)
	regex.match(_fn_header_re, lines[k])
}
