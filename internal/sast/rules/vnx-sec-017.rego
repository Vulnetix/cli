package vulnetix.rules.vnx_sec_017

import rego.v1

metadata := {
	"id": "VNX-SEC-017",
	"name": "Plaintext protocol URL",
	"description": "Using unencrypted protocol URLs (redis://, amqp://, ftp://, telnet://, ldap://) transmits data including credentials in cleartext, enabling network eavesdropping.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-017/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [319],
	"capec": ["CAPEC-157"],
	"attack_technique": ["T1040"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cleartext", "encryption", "network"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")
_skip(path) if endswith(path, ".txt")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)(redis|amqp|ftp|telnet|ldap)://[a-zA-Z0-9]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Plaintext protocol URL detected; use the TLS-encrypted variant (rediss://, amqps://, ftps://, ldaps://)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
