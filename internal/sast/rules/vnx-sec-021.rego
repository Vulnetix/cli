package vulnetix.rules.vnx_sec_021

import rego.v1

metadata := {
	"id": "VNX-SEC-021",
	"name": "Twilio API credentials",
	"description": "Twilio API credentials (Account SID or Auth Token) were found in source code. These grant access to Twilio communication services for SMS, voice, and video.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-021/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
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
	regex.match(`SK[a-f0-9]{32}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Twilio API key found; rotate and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`AC[a-f0-9]{32}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Twilio Account SID found; use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
