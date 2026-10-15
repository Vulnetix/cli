# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1039

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1039",
	"name": "reCAPTCHA v3 verdict accepted without checking the score",
	"description": "reCAPTCHA v3 is an automated recognition mechanism: siteverify answers success: true for every well-formed token, bots included, and the bot/human judgement is only in the score (0.0 to 1.0). Reported in Python and JavaScript/TypeScript: in a project that uses reCAPTCHA v3 (grecaptcha.execute(...), api.js?render=<site key>, react-google-recaptcha-v3 executeRecaptcha/useGoogleReCaptcha/GoogleReCaptchaProvider, a RECAPTCHA_V3 name), a file that handles the reCAPTCHA siteverify response and reads its success field (result[\"success\"], .get(\"success\"), data.success, const { success } = ...) but never mentions the score; and a score compared against 0 (score > 0, score >= 0.0), which accepts every request. Not reported: reCAPTCHA v2 and hCaptcha/Turnstile projects (no score, success is the verdict), handlers that read the score, comments and test files. CWE-1039 in general (machine-learning classifiers that adversarial input can fool) has no static signature; this rule covers the concrete case of a bot-detection score being ignored.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1039/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1039],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["captcha", "recaptcha", "bot-detection", "cwe-1039"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_code(path) if regex.match(`\.(?:py|js|jsx|mjs|cjs|ts|tsx)$`, path)

_v3_re := `grecaptcha(?:\.enterprise)?\.execute\s*\(|recaptcha/(?:api|enterprise)\.js\?(?:[^"'\s]*&)?render=[^e"'\s&]|executeRecaptcha\s*\(|useGoogleReCaptcha\b|GoogleReCaptchaProvider\b|(?i:recaptcha_?v3)`

_v3_project if {
	some _, c in input.file_contents
	_mentions_recaptcha(c)
	regex.match(_v3_re, c)
}

_success_re := `\[\s*["']success["']\s*\]|\.get\(\s*["']success["']|\.success\b(?:\s*[^\s(]|\s*$)|\{[^{}]*\bsuccess\b[^{}]*\}\s*(?::\s*[\w.<>\[\]]+\s*)?=[^=]`

findings contains _finding(path, i, line, "reCAPTCHA v3 response accepted on success alone: success is true for bots too, and the verdict is the score. Reject requests whose score is below a threshold (for example 0.5) and check the expected action") if {
	some path, content in input.file_contents
	_code(path)
	not helpers.is_test_path(path)
	contains(content, "siteverify")
	_mentions_recaptcha(content)
	contains(content, "success")
	not regex.match(`\bscore\b|["']score["']`, content)
	_v3_project
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_success_re, _untyped(path, line))
	not helpers.is_comment_line(line)
	not regex.match(`\bsuccess\s*:\s*(?:true|false|True|False)\b`, line)
}

findings contains _finding(path, i, line, "reCAPTCHA score compared against 0: every score passes, so the bot check accepts every request. Use a real threshold (for example 0.5)") if {
	some path, content in input.file_contents
	_code(path)
	not helpers.is_test_path(path)
	contains(content, "score")
	_mentions_captcha(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:\bscore\b|["']score["']\s*\]|\.get\(\s*["']score["'][^)]*\))\s*(?:>=?)\s*0(?:\.0*)?\b(?:[^.\d]|$)`, line)
	not helpers.is_comment_line(line)
}

_mentions_captcha(content) if contains(content, "aptcha")

_mentions_captcha(content) if contains(content, "APTCHA")

_mentions_recaptcha(c) if contains(c, "ecaptcha")

_mentions_recaptcha(c) if contains(c, "eCaptcha")

_mentions_recaptcha(c) if contains(c, "ECAPTCHA")

# TypeScript inline object types (`: { success: boolean }`) declare a shape,
# they do not read the field.
_untyped(path, line) := regex.replace(line, `:\s*\{[^{}]*\}`, ": T") if regex.match(`\.tsx?$`, path)

_untyped(path, line) := line if not regex.match(`\.tsx?$`, path)
