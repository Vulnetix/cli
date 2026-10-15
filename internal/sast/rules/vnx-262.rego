# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_262

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-262",
	"name": "Not Using Password Aging",
	"description": "Password aging is switched off where it is configured. Reported: an AWS IAM account password policy with no maximum age (a Terraform aws_iam_account_password_policy block without max_password_age, or with max_password_age = 0; a boto3 update_account_password_policy call, an AWS SDK for JavaScript UpdateAccountPasswordPolicyCommand / updateAccountPasswordPolicy({...}) call or an AWS SDK for Java UpdateAccountPasswordPolicyRequest builder that sets no MaxPasswordAge); an Entra ID (Azure AD) user created with passwordPolicies containing DisablePasswordExpiration or a Terraform azuread_user with disable_password_expiration = true; an Active Directory userAccountControl value written with the DONT_EXPIRE_PASSWORD bit (0x10000, e.g. 66048) or OR-ed with a (UF_|ADS_)DONT_EXPIRE_PASSWD constant; PowerShell -PasswordNeverExpires (New-LocalUser, Set-ADUser, Set-LocalUser) and -PasswordPolicies DisablePasswordExpiration (Update-MgUser); Linux PASS_MAX_DAYS 99999 or -1 (also written by sed with a \\t separator), chage -M/--maxdays and passwd -x 99999 or -1, Ansible password_expire_max 99999 or -1 and iam_password_policy pw_max_age: 0, and Windows net accounts /maxpwage:unlimited; and an explicit passwordNeverExpires = true / password_expires = false field. Not reported: an echo, printf or Write-Host line that only prints the setting (one that writes it with > or tee is reported), a policy that sets a maximum age (an over-long one is VNX-263), reading or comparing these settings (a == test, a & mask, a -Filter string), the switch quoted in a message, account expiry (chage -E), a value of false/$false, and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-262/",
	"languages": ["java", "node", "python", "terraform", "bash", "docker", "powershell"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [262],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["password-aging", "cwe-262"],
}

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

_needles := {"max_password_age", "asswordPolicies", "password_expiration", "userAccountControl", "DONT_EXPIRE", "PasswordNeverExpires", "asswordNeverExpires", "assword_never_expires", "PASS_MAX_DAYS", "chage", "passwd", "password_expire", "maxpwage", "pw_max_age", "asswordExpires", "assword_expires"}

_has_needle(s) if {
	some n in _needles
	contains(s, n)
}

# Line-level shapes that switch aging off.
_line_res := [
	`\bmax_password_age\s*=\s*0\b`,
	`(?i)password_?policies['"]?\s*(?::|=)\s*['"][^'"]*DisablePasswordExpiration`,
	`\bdisable_password_expiration\s*=\s*true\b`,
	`\|=?\s*(?:ADS_)?(?:UF_)?DONT_EXPIRE_PASSW`,
	`=\s*(?:ADS_)?(?:UF_)?DONT_EXPIRE_PASSW\w*\s*[|;]`,
	`(?i)(?:^|\s)-PasswordPolicies\s+["']?[^"'\n]*DisablePasswordExpiration`,
	`(?i)password_?never_?expires['"]?\s*[:=]\s*(?:true|1)\b`,
	`(?i)\bpassword_?expires['"]?\s*[:=]\s*(?:false|0)\b`,
]

# Shell, Dockerfile, login.defs, YAML and PowerShell shapes.
_admin_res := [
	`(?:^|\s)-PasswordNeverExpires\b`,
	`\bPASS_MAX_DAYS(?:\s|\\t)+(?:99999|-1)\b`,
	`^\s*pw_max_age\s*:\s*['"]?0['"]?\s*(?:#.*)?$`,
	`\bchage\b.*(?:-M|--maxdays)[\s=]*(?:99999|-1)\b`,
	`\bpasswd\b.*(?:-x|--maxdays)[\s=]*(?:99999|-1)\b`,
	`\bpassword_expire_max\s*[:=]\s*['"]?(?:99999|-1)\b`,
	`(?i)\bnet\s+accounts\b.*\/maxpwage:\s*unlimited\b`,
]

# Explicitly turned back off.
_negated_re := `(?i)-PasswordNeverExpires\s*:?\s*(?:\$false|0)\b`

_uac_re := `(?i)userAccountControl['"]?\s*[:=,]\s*[^0-9&|\n]{0,40}?\b(\d{5,})\b`


# Shell, Dockerfile, login.defs, YAML and PowerShell files: their lines often
# quote the value (sed 's/.../PASS_MAX_DAYS 99999/'), so they match as written.
_admin_file(path) if regex.match(`(?i)(\.(sh|bash|zsh|ya?ml|ps1|psm1|bat|cmd)$|dockerfile|containerfile|login\.defs$)`, path)

_line_hit(_, line) if {
	some re in _line_res
	regex.match(re, line)
}

_line_hit(path, line) if {
	_admin_file(path)
	some re in _admin_res
	regex.match(re, line)
	not regex.match(_negated_re, line)
	not _only_in_string(line)
}

# A PowerShell switch quoted in a message (Write-Host "use -PasswordNeverExpires ...")
# is prose, not a parameter.
_only_in_string(line) if {
	contains(line, "PasswordNeverExpires")
	code := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)
	not regex.match(`(?:^|\s)-PasswordNeverExpires\b`, code)
}

# userAccountControl written with the 0x10000 (DONT_EXPIRE_PASSWORD) bit set.
_line_hit(_, line) if {
	m := regex.find_all_string_submatch_n(_uac_re, line, 1)
	count(m) > 0
	bits.and(to_number(m[0][1]), 65536) != 0
}

# AWS password-policy calls that set no maximum age.
_policy_call_re := `\bupdate_account_password_policy\s*\(|\bUpdateAccountPasswordPolicyCommand\s*\(|\bupdateAccountPasswordPolicy\s*\(\s*\{|\bUpdateAccountPasswordPolicyRequest\s*\.\s*builder\s*\(`

_call_end(lines, i, line) := k if {
	contains(line, "builder")
	ks := [j | some j in numbers.range(i, min([count(lines) - 1, i + 20])); contains(lines[j], "build()")]
	count(ks) > 0
	k := ks[0]
}

_call_end(lines, i, line) := k if {
	not contains(line, "builder")
	ks := [j | some j in numbers.range(i, min([count(lines) - 1, i + 20])); regex.match(`\)\s*\)?\s*;?\s*$`, lines[j])]
	count(ks) > 0
	k := ks[0]
}

_tf_block_end(lines, i) := k if {
	ks := [j | some j in numbers.range(i + 1, min([count(lines) - 1, i + 60])); startswith(lines[j], "}")]
	count(ks) > 0
	k := ks[0]
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Password aging is disabled: passwords never expire. Set a maximum password age (and rotate on suspected compromise), or document the compensating control (MFA, breached-password screening)",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	_has_needle(content)
	lines := split(content, "\n")
	some i, line in lines
	_has_needle(line)
	not helpers.is_comment_line(line)
	not _message_line(line)
	_line_hit(path, line)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".tf")
	contains(content, "aws_iam_account_password_policy")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*resource\s+"aws_iam_account_password_policy"`, line)
	k := _tf_block_end(lines, i)
	not regex.match(`\bmax_password_age\s*=`, helpers.code_window(lines, i, 0, k - i))
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	_has_policy_call(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_policy_call_re, line)
	not helpers.is_comment_line(line)
	k := _call_end(lines, i, line)
	not regex.match(`(?i)max_?password_?age`, helpers.code_window(lines, i, 0, k - i))
	finding := _finding(path, i, line)
}

_has_policy_call(content) if contains(content, "ccountPasswordPolicy")

_has_policy_call(content) if contains(content, "update_account_password_policy")

# A message that only prints the setting (echo "run chage -M ..."), as opposed
# to one that writes it into a file (echo "PASS_MAX_DAYS ..." >> /etc/login.defs).
_message_line(line) if {
	regex.match(`(?i)^\s*(?:echo|printf|Write-(?:Host|Output|Warning|Verbose)|print|log(?:ger)?)\b`, line)
	not regex.match(`>|\btee\b|Set-Content|Add-Content|Out-File`, line)
}
