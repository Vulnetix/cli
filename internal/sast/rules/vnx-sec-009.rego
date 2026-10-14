package vulnetix.rules.vnx_sec_009

import rego.v1

import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-009",
	"name": "SendGrid API key",
	"description": "A SendGrid API key is written into a file: the full SG.<22 characters>.<43 characters> token, standing on its own (quoted, after = or :, in a header, URL or comment), in any file type. SendGrid keys send mail as the account's verified domains and read its contacts, so a leaked one is used for phishing and spam. Not reported: placeholder or low-entropy keys (SG.xxxx..., SG.your-key...), strings that are only SG.-prefixed lookalikes of the wrong length or embedded in a longer token, lock files, minified bundles, and test, fixture and vendored paths. VNX-SEC-453 reports the same token when it is assigned to a subuser key name.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-009/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "sendgrid", "email", "credentials"],
}

# The token is delimited on both sides: a longer base64url run that merely
# contains "SG." is some other value.
_token_re := `(?:^|[^A-Za-z0-9_.\-])(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?:[^A-Za-z0-9_\-]|$)`

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "SG.")
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SG.")
	some m in regex.find_all_string_submatch_n(_token_re, line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 4)
	finding := {
		"rule_id": metadata.id,
		"message": "SendGrid API key found; delete it under SendGrid Settings > API Keys, issue a new key and load it from an environment variable or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
