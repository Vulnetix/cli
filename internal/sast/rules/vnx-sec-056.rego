package vulnetix.rules.vnx_sec_056

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-056",
	"name": "Sentry auth token",
	"description": "Reports a Sentry auth token as a whole token in any file: a user auth token (sntryu_ and 64 hex characters), an organisation auth token (sntrys_ followed by its base64 JSON claims, eyJ..., and the secret part), or a legacy 64-hex auth token assigned to SENTRY_AUTH_TOKEN / sentry_auth_token / [auth] token in .sentryclirc, or passed to sentry-cli --auth-token. These tokens upload releases and source maps and read issues, whose events can carry user data. Not reported: the DSN (a public ingest identifier), the bare prefixes, placeholder bodies (sntrys_YOUR_TOKEN_HERE), environment references, and test, fixture or vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-056/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "sentry", "monitoring", "credentials"],
}

_tokens := [
	{
		"markers": ["sntryu_"],
		"suffix": "",
		"re": `(?:^|[^A-Za-z0-9_])sntryu_([a-f0-9]{64})(?:[^A-Za-z0-9_]|$)`,
		"msg": "Sentry user auth token found; revoke it in Sentry (User Settings > Auth Tokens) and pass the replacement through a CI secret",
	},
	{
		"markers": ["sntrys_"],
		"suffix": "",
		"re": `(?:^|[^A-Za-z0-9_])sntrys_(eyJ[A-Za-z0-9+/=]{40,}(?:_[A-Za-z0-9+/=]{20,})?)`,
		"msg": "Sentry organisation auth token found; revoke it in Sentry (Organization Settings > Auth Tokens) and pass the replacement through a CI secret",
	},
	{
		"markers": ["AUTH_TOKEN", "auth_token", "authToken", "AuthToken", "auth-token"],
		"suffix": "",
		"re": `(?i)sentry[_-]?auth[_-]?token["']?\s*[:=]\s*["']?([a-f0-9]{64})(?:[^A-Za-z0-9]|$)`,
		"msg": "Sentry auth token found; revoke it in Sentry (Auth Tokens) and pass the replacement through a CI secret",
	},
	{
		"markers": ["--auth-token"],
		"suffix": "",
		"re": `\bsentry-cli\b.*--auth-token(?:=|\s+)["']?([a-f0-9]{64})(?:[^A-Za-z0-9]|$)`,
		"msg": "Sentry auth token passed to sentry-cli on the command line; revoke it in Sentry (Auth Tokens) and set SENTRY_AUTH_TOKEN from a CI secret",
	},
	{
		"markers": ["token"],
		"suffix": ".sentryclirc",
		"re": `^\s*token\s*=\s*([a-f0-9]{64})\s*$`,
		"msg": "Sentry auth token found in .sentryclirc; revoke it in Sentry (Auth Tokens) and keep the file out of the repository",
	},
]

_has_marker(s, markers) if {
	some k in markers
	contains(s, k)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	some t in _tokens
	endswith(path, t.suffix)
	_has_marker(content, t.markers)
	lines := split(content, "\n")
	some i, line in lines
	_has_marker(line, t.markers)
	m := regex.find_all_string_submatch_n(t.re, line, 1)
	count(m) > 0
	body := m[0][1]
	not secrets.is_example_token(body)
	secrets.high_entropy(body, 3)
	finding := {
		"rule_id": metadata.id,
		"message": t.msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
