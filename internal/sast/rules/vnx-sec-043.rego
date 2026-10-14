package vulnetix.rules.vnx_sec_043

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-043",
	"name": "Twilio API key",
	"description": "Reports a Twilio API key SID written into a file: SK followed by exactly 32 lowercase hexadecimal characters, standing alone (not inside a longer word or hex string). With its secret it grants access to Twilio SMS, voice and Verify APIs. The snippet is redacted. Not reported: SK inside a longer identifier (DISK..., TASK...), uppercase or over-long hex runs (hashes), placeholders (SKxxxx..., SK000..., EXAMPLE), low-entropy values, and test, fixture and vendored paths. Account SIDs (AC...) are identifiers, not credentials, and are not reported. The generated VNX-SEC-937 reports the same token shape beside Super SIM / IoT names.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-043/",
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

_pattern := `(?:^|[^A-Za-z0-9_])(SK[0-9a-f]{32})(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "SK")
	regex.match(`SK[0-9a-f]{32}`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SK")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	regex.match(`[a-f]`, substring(token, 2, -1))
	regex.match(`[0-9]`, substring(token, 2, -1))
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.0)
	finding := {
		"rule_id": metadata.id,
		"message": "Twilio API key found; revoke the key in the Twilio console and rotate any leaked secrets",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
