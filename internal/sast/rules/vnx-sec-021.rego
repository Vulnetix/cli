package vulnetix.rules.vnx_sec_021

import rego.v1

import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-021",
	"name": "Twilio API credentials",
	"description": "Reports a Twilio secret written into a file: (1) a 32-character auth token or API key secret assigned to a name that says what it is (TWILIO_AUTH_TOKEN, authToken, auth_token, api_secret, apiKeySecret) in a file that mentions Twilio or holds an Account SID, and (2) a Twilio client built from literals, an Account SID or API key SID (AC/SK followed by 32 hex characters) passed beside a 32-character secret literal on the same line (Client(\"AC...\", \"<token>\"), twilio('AC...', '<token>')). The secret must not be a placeholder and must have the entropy of a real token; the snippet is redacted. Not reported: an Account SID or API key SID on its own (an identifier, not a credential), secrets read from the environment or a secrets manager, auth_token names outside a Twilio context, and test, fixture, vendored and generated paths. Overlaps the generated rule VNX-SEC-937 (Twilio IoT key SID).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-021/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "twilio", "credentials"],
}

_named_re := `(?i)(?:auth_?token|api_?(?:key_?)?secret|twilio_?(?:secret|token))["']?\s*(?:=>|[:=])\s*["'\x60]?([A-Za-z0-9]{32})(?:[^A-Za-z0-9]|$)`

_sid_re := `\b(?:AC|SK)[0-9a-f]{32}\b`

_literal_re := `["'\x60]([A-Za-z0-9]{32})["'\x60]`

_good(tok) if {
	regex.match(`[0-9]`, tok)
	regex.match(`[a-zA-Z]`, tok)
	not secrets.is_example_token(tok)
	secrets.high_entropy(tok, 3.2)
}

_twilio_file(content) if contains(content, "wilio")

_twilio_file(content) if contains(content, "WILIO")

_twilio_file(content) if {
	contains(content, "AC")
	regex.match(_sid_re, content)
}

_secret(line) if {
	some m in regex.find_all_string_submatch_n(_named_re, line, -1)
	_good(m[1])
}

_secret(line) if {
	regex.match(_sid_re, line)
	some m in regex.find_all_string_submatch_n(_literal_re, line, -1)
	tok := m[1]
	_good(tok)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	_twilio_file(content)

	lines := split(content, "\n")
	some i, line in lines
	_secret(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Twilio auth token or API key secret found; rotate it in the Twilio console, then load it from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
