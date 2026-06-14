package vulnetix.rules.vnx_sec_043

import rego.v1

metadata := {
	"id": "VNX-SEC-043",
	"name": "Twilio API key",
	"description": "A Twilio API key (SK prefix) was found in source code. Twilio keys grant access to SMS, voice, and authentication APIs and can be abused for SMS pumping fraud or account takeover.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-043/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "twilio", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`SK[0-9a-fA-F]{32}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Twilio API key found; revoke the key in the Twilio console and rotate any leaked secrets",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
