# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_263

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-263",
	"name": "Password Aging with Long Expiration",
	"description": "A maximum password age is configured, but at more than 180 days. Reported: Terraform max_password_age, boto3/AWS SDK for JavaScript MaxPasswordAge and AWS SDK for Java .maxPasswordAge(n) on an IAM account password policy; Linux PASS_MAX_DAYS (also written by sed with a \\t separator), chage -M/--maxdays and passwd -x/--maxdays, and Ansible password_expire_max and iam_password_policy pw_max_age; PowerShell Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (d.hh:mm:ss or New-TimeSpan -Days) and net accounts /maxpwage:n; Entra ID passwordValidityPeriodInDays; and an application setting whose name says it is a password's maximum age, expiry, lifetime, validity or rotation period in days (PASSWORD_EXPIRY_DAYS = 365, passwordMaxAgeDays: 400) or that is a timedelta(days=n) / Duration.ofDays(n). Not reported: an echo, printf or Write-Host line that only prints the setting (one that writes it with > or tee is reported), 180 days or fewer, 0, 99999 or -1 (aging disabled, which is VNX-262), other durations (sessions, tokens, certificates, password-reset links), comparisons (age > 365), and the settings in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-263/",
	"languages": ["python", "node", "java", "terraform", "bash", "docker", "powershell"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [263],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["password-aging-long", "cwe-263"],
}

_limit := 180

_exts := {
	".tf", ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java",
	".sh", ".bash", ".zsh", ".ps1", ".psm1", ".yml", ".yaml", ".bat", ".cmd",
}

_in_scope(path) if {
	some ext in _exts
	endswith(path, ext)
}

_in_scope(path) if {
	base := lower(regex.replace(path, `^.*/`, ""))
	some name in {"dockerfile", "containerfile", "login.defs"}
	contains(base, name)
}

# Shell, Dockerfile, login.defs, YAML and PowerShell lines quote values as a
# matter of course (sed 's/.../PASS_MAX_DAYS 400/'), so they are read as written.
_admin_file(path) if regex.match(`(?i)(\.(sh|bash|zsh|ya?ml|ps1|psm1|bat|cmd)$|dockerfile|containerfile|login\.defs$)`, path)

_needles := {"assword", "ASSWORD", "PASS_MAX_DAYS", "chage", "passwd", "maxpwage", "MaxPasswordAge", "pw_max_age"}

_has_needle(s) if {
	some n in _needles
	contains(s, n)
}

# Settings whose value is a password's maximum age in days (group 1).
_day_res := [
	`\bmax_password_age\s*=\s*(\d+)`,
	`\bMaxPasswordAge['"]?\s*[:=]\s*(\d+)`,
	`\.maxPasswordAge\(\s*(\d+)\s*\)`,
	`\bpasswordValidityPeriodInDays['"]?\s*[:=]\s*(\d+)`,
]

_admin_res := [
	`\bPASS_MAX_DAYS(?:\s|\\t)+(\d+)`,
	`^\s*pw_max_age\s*:\s*['"]?(\d+)['"]?\s*(?:#.*)?$`,
	`\bchage\b.*(?:-M|--maxdays)[\s=]*(\d+)`,
	`\bpasswd\b.*(?:-x|--maxdays)[\s=]*(\d+)`,
	`\bpassword_expire_max\s*[:=]\s*['"]?(\d+)`,
	`-MaxPasswordAge\s+['"]?(\d+)[.:]`,
	`-MaxPasswordAge\s+\(?\s*New-TimeSpan\s+-Days\s+(\d+)`,
	`(?i)\bnet\s+accounts\b.*\/maxpwage:\s*(\d+)`,
]

# An application setting: <name> = <days> or <name> = timedelta(days=<n>).
_named_num_re := `([A-Za-z_][A-Za-z0-9_]*)['"]?\s*[:=]\s*(\d+)\s*(?:[,;)}]|$)`

_named_dur_re := `([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(?:datetime\.)?(?:timedelta\(\s*days\s*=\s*|Duration\.ofDays\(\s*|java\.time\.Duration\.ofDays\(\s*)(\d+)`

_password_age_name(name) if {
	l := lower(name)
	contains(l, "password")
	regex.match(`max_?age|expir|lifetime|validity|rotation|rotate`, l)
}

_days(path, line) := to_number(m[0][1]) if {
	some re in _day_res
	m := regex.find_all_string_submatch_n(re, _text(path, line), 1)
	count(m) > 0
}

_days(path, line) := to_number(m[0][1]) if {
	_admin_file(path)
	some re in _admin_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
}

_days(path, line) := to_number(m[0][2]) if {
	m := regex.find_all_string_submatch_n(_named_num_re, _text(path, line), 1)
	count(m) > 0
	_password_age_name(m[0][1])
	contains(lower(m[0][1]), "day")
}

_days(path, line) := to_number(m[0][2]) if {
	m := regex.find_all_string_submatch_n(_named_dur_re, _text(path, line), 1)
	count(m) > 0
	_password_age_name(m[0][1])
}

# String literals blanked in code files, so a quoted example is not a setting.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_text(path, line) := line if _admin_file(path)

_text(path, line) := _code(line) if not _admin_file(path)

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	_has_needle(content)
	lines := split(content, "\n")
	some i, line in lines
	_has_needle(line)
	not helpers.is_comment_line(line)
	not _message_line(line)
	ds := {d | d := _days(path, line)}
	some d in ds
	d > _limit
	d < 99999
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Maximum password age is %d days (more than %d): a leaked password stays valid for most of that time. Shorten it, or rely on MFA and breached-password screening instead of scheduled expiry", [d, _limit]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A message that only prints the setting (echo "run chage -M ..."), as opposed
# to one that writes it into a file (echo "PASS_MAX_DAYS ..." >> /etc/login.defs).
_message_line(line) if {
	regex.match(`(?i)^\s*(?:echo|printf|Write-(?:Host|Output|Warning|Verbose)|print|log(?:ger)?)\b`, line)
	not regex.match(`>|\btee\b|Set-Content|Add-Content|Out-File`, line)
}
