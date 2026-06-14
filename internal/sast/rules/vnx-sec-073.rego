package vulnetix.rules.vnx_sec_073

import rego.v1

metadata := {
	"id": "VNX-SEC-073",
	"name": "URL with embedded credentials",
	"description": "A URL containing a username:password segment (e.g. https://user:pass@host/) was found in source code. Embedded credentials in URLs are logged in plain text by proxies, web servers, and CDNs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-073/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "url", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)(https?|ftp|amqp|amqps)://[a-zA-Z0-9_.-]+:[^@\s"'<>]+@[a-zA-Z0-9_.-]+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "URL with embedded credentials found; rotate the credential and use a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
