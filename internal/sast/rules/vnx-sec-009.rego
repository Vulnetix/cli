package vulnetix.rules.vnx_sec_009

import rego.v1

metadata := {
	"id": "VNX-SEC-009",
	"name": "SendGrid API key",
	"description": "A SendGrid API key was found in source code. SendGrid keys grant access to email sending services and can be abused for phishing or spam.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-009/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["secrets", "sendgrid", "email", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SendGrid API key found; rotate the key and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
