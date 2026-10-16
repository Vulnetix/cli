package vulnetix.rules.vnx_sec_033

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-033",
	"name": "AWS Bedrock API key (long-lived)",
	"description": "Reports an AWS Bedrock long-term API key: the ABSK prefix followed by 109 to 269 base64 characters, standing alone (not embedded in a longer base64 run). Placeholder and example values, test and fixture paths, and short-term bedrock-api-key- tokens (which expire within hours) are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-033/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "aws", "bedrock", "credentials"],
}

# A long-term Bedrock key is "ABSK" + base64("BedrockAPIKey-<id>-at-<account>:<secret>").
# Both ends must be a non-base64 character so a run inside an image or
# certificate blob that happens to contain "ABSK" does not match.
_pattern := `(?:^|[^A-Za-z0-9+/])(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[^A-Za-z0-9+/=]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	contains(content, "ABSK")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ABSK")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
	finding := {
		"rule_id": metadata.id,
		"message": "AWS Bedrock long-term API key found; revoke the key in IAM and use IAM roles or AWS Secrets Manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
