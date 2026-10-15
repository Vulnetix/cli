# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_308

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-308",
	"name": "Use of Single-factor Authentication",
	"description": "A setting that enforces a second authentication factor is turned off, leaving the password as the only factor. Reported: a setting, property or keyword whose name says MFA/2FA/two-factor/multi-factor/OTP is required or enforced (require_mfa, mfaRequired, enforce2fa, SECURITY_TWO_FACTOR_REQUIRED, otp_enforced) assigned false, 0, \"off\", \"disabled\" or \"optional\" in Python, JavaScript/TypeScript or Java (including a .setMfaRequired(false)/.requireMfa(false) builder call); an upper-case settings constant that enables MFA (MFA_ENABLED, ENABLE_2FA, TWO_FACTOR_AUTH_ENABLED) set to false; and a Terraform aws_cognito_user_pool with mfa_configuration = \"OFF\". Not reported: a per-user flag such as user.mfaEnabled = false or a model column default (the user has not enrolled, which is not a policy), reads and comparisons (if not settings.MFA_REQUIRED), login-flow state rather than policy (a Redux/store field, initialState, a dispatched action, or a response body such as res.json({ mfaRequired: false }) telling the client this login needs no challenge), the setting turned on, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-308/",
	"languages": ["java", "node", "python", "terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [308],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["single-factor", "auth", "cwe-308"],
}

_code_exts := {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".java"}

_factor := `(?:mfa|2fa|two_?factor|twofactor|multi_?factor|multifactor|totp|otp|second_?factor)`

_off := `(?:false|False|FALSE|0|['"](?:false|off|OFF|disabled|none|optional)['"])`

# require_mfa = False, mfaRequired: false, "enforce2fa": false, two_factor_required=False
_required_off := concat("", [
	`(?i:\b[\w]*(?:(?:require|enforce|mandatory|force)[_-]?`, _factor, `|`, _factor, `[_-]?(?:auth[_-]?)?(?:required|enforced|enforcement|mandatory|enforce|require))\w*)`,
	`['"]?\]?\s*(?:=|:|=>)\s*`, _off, `(?:\s*[,;)}\]]|\s*$|\s+#|\s+//)`,
])

# MFA_ENABLED = False, ENABLE_2FA: false (upper-case settings constants only)
_const_off := concat("", [
	`\b(?:[A-Z0-9]+_)*(?:ENABLE_(?:MFA|2FA|TWO_FACTOR|MULTI_FACTOR|OTP)(?:_AUTH)?|(?:MFA|2FA|TWO_FACTOR|MULTI_FACTOR|OTP)(?:_AUTH)?_(?:ENABLED|ENFORCED))\b['"]?\]?\s*(?:=|:)\s*`,
	_off, `(?:\s*[,;)}\]]|\s*$|\s+#|\s+//)`,
])

# .setMfaRequired(false), .requireMfa(false), .enforceTwoFactor(false)
_setter_off := concat("", [`(?i)\.(?:set)?(?:(?:require|enforce)`, _factor, `|`, _factor, `(?:required|enforced))\(\s*(?:false|Boolean\.FALSE)\s*\)`])

_matches(line) if regex.match(_required_off, line)

_matches(line) if regex.match(_const_off, line)

_matches(line) if regex.match(_setter_off, line)

# A comparison or read is not a setting.
_comparison(line) if regex.match(`(==|!=|\bif\b|\bnot\s|!\s*[\w.]*(mfa|factor))`, line)

# The flag as login-flow state rather than policy: a store or reducer field
# (state.mfaRequired = false, initialState, a dispatched action creator) or a
# response body telling the client this login needs no challenge.
_client_state(lines, i, line) if regex.match(`(?i)(\b(state|draft|store)\.\w+\s*=|\bactions?\.\w+\(|dispatch\()`, line)

_client_state(lines, i, line) if {
	some j in numbers.range(max([0, i - 6]), i)
	regex.match(`(initialState|useState|\bres\.(json|send)\(|\breply\.send\(|\bctx\.body\s*=|return\s*\{|return\s+(jsonify|JsonResponse|Response|ResponseEntity)\b|jsonify\(|JsonResponse\()`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	some e in _code_exts
	endswith(path, e)
	not helpers.is_test_path(path)
	regex.match(`(?i)(mfa|2fa|two_?factor|multi_?factor|otp)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)(mfa|2fa|factor|otp)`, line)
	not helpers.is_comment_line(line)
	_matches(line)
	not _comparison(line)
	not _client_state(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Multi-factor authentication requirement switched off: the password becomes the only factor",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Terraform: a Cognito user pool with MFA turned off.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".tf")
	contains(content, "aws_cognito_user_pool")
	contains(content, "mfa_configuration")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*mfa_configuration\s*=\s*"OFF"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Cognito user pool has MFA turned off (mfa_configuration = \"OFF\"): use ON or OPTIONAL with enforcement",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
