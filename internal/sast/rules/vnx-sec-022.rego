package vulnetix.rules.vnx_sec_022

import rego.v1

metadata := {
	"id": "VNX-SEC-022",
	"name": "Sensitive data in log statement",
	"description": "Logging sensitive data (passwords, tokens, secrets, API keys) exposes credentials in log files, monitoring systems, and log aggregators.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-022/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [532],
	"capec": ["CAPEC-215"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["logging", "secrets", "information-disclosure"],
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
	regex.match(`(?i)(console\.log|logger\.(info|debug|warn|error|log)|log\.(info|debug|warn|error)|print|println|System\.out\.print)\(.*\b(password|passwd|secret_key|api_key|apikey|private_key|auth_token|access_token)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive data may be logged; remove secrets from log statements to prevent credential exposure",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
