# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_645

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-645",
	"name": "Overly Restrictive Account Lockout Mechanism",
	"description": "An account is locked permanently after a number of failed logins, so anyone who knows a username can lock its owner out for good by guessing wrong passwords (CWE-645). Reported in Python and JavaScript/TypeScript login code (a file that mentions passwords, login, sign-in or authentication): a statement that locks or disables the account (x.is_locked/locked/blocked/disabled = True, x.is_active/active/enabled = False, x.status = 'locked'/'blocked'/'disabled'/'suspended', or an update object { locked: true } / { active: false } / { status: 'locked' }) on the line of, or up to four lines after, a comparison of a failed-attempt counter (fail*, *attempt*, retries, tries) with a threshold, in a file that sets no expiry for the lock (no locked_until/lockUntil/lockout end, unlock_at, cool-off or cool-down, timedelta, LOCK_TIME/lockout duration, Date.now() + ..., Redis expire/setex, expires_at or ttl); and a django-axes AXES_COOLOFF_TIME = None setting, which never releases a lockout. Not reported: a lock with an expiry, an administrator deactivating a user, a one-time code, token, reset link or session invalidated after too many tries (a receiver named otp/token/code/challenge/reset/session...), counters that are not compared with a threshold, test code, comments and string literals. A lock that expires after a very long time is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-645/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [645],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["account-lockout", "denial-of-service", "authentication", "cwe-645"],
}

_code_ext(path) if {
	some ext in {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_lock_re := `(?i)(?:\.(?:is_?locked|locked|account_?locked|is_?blocked|blocked|is_?disabled|disabled|locked_?out|lockout)\s*=\s*(?:true|1)\b|\.(?:is_?active|active|enabled|is_?enabled)\s*=\s*(?:false|0)\b|[{,]\s*(?:is_?locked|locked|blocked|disabled|account_?locked)\s*:\s*true\b|[{,]\s*(?:is_?active|active|enabled)\s*:\s*false\b)`

_counter_re := `(?i)(?:fail|attempt|retr(?:y|ies)|tries)\w*(?:\s*\|\|\s*0\)?)?(?:\s*\+\s*\d+)?\s*(?:>=|>|==)\s*[\w.]+|[\w.]+\s*(?:<=|<)\s*[\w.]*(?:fail|attempt|tries)`

_expiry_re := `(?i)lock(?:ed)?_?(?:until|expir|end\b|out_?end|out_?until)|unlock_?(?:at|time|after)|cool_?off|cool_?down|timedelta\(|lock_?(?:time|duration|period|window)|lockout_?(?:time|duration|period|window)|Date\.now\(\)\s*\+|\.expire\(|setex\(|expires_?at|\bttl\b`

_login_re := `(?i)password|login|sign_?in|authenticat`

# String literals blanked: a quoted example is not code.
_code(line) := regex.replace(line, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\x60[^\x60]*\x60`, `""`)

_counter_near(lines, i) if {
	some j in numbers.range(max([0, i - 4]), i)
	not helpers.is_comment_line(lines[j])
	regex.match(_counter_re, _code(lines[j]))
}

_locks(line) if regex.match(_lock_re, _code(line))

# A status string: user.status = "LOCKED", { status: 'disabled' }.
_locks(line) if {
	regex.match(`(?i)(?:\.(?:status|state|account_?status)\s*=|[{,]\s*(?:status|state|account_?status)\s*:)\s*['"](?:locked|blocked|disabled|suspended)['"]`, line)
	regex.match(`(?i)(?:\.(?:status|state|account_?status)\s*=|[{,]\s*(?:status|state|account_?status)\s*:)\s*""`, _code(line))
}

# Invalidating a one-time code, token or session after too many tries is
# the right thing to do, not an account lockout.
_not_account_re := `(?i)\b\w*(?:otp|token|code|challenge|reset|invit|session|link|mfa|captcha|apikey|api_key)\w*\s*\.\s*(?:is_?|account_?)?(?:locked|blocked|disabled|active|enabled|status|state)\b`

findings contains finding if {
	some path, content in input.file_contents
	_code_ext(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)lock|block|disabl|active|enabled|suspend`, content)
	regex.match(_counter_re, content)
	regex.match(_login_re, content)
	not regex.match(_expiry_re, helpers.code_text(split(content, "\n")))
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	_locks(line)
	not regex.match(_not_account_re, line)
	_counter_near(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The account is locked permanently after failed logins: anyone who knows the username can lock its owner out. Give the lock an expiry (lock_until, a cool-off period) or throttle by source instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "AXES_COOLOFF_TIME")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*AXES_COOLOFF_TIME\s*=\s*None\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "django-axes AXES_COOLOFF_TIME = None never releases a lockout: anyone who knows a username can lock its owner out for good. Set a cool-off period (for example timedelta(minutes=30))",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
