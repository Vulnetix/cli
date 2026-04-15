package vulnetix.rules.vnx_sec_007

import rego.v1

metadata := {
	"id": "VNX-SEC-007",
	"name": "Slack token or webhook",
	"description": "A Slack bot/user/app token or webhook URL was found in source code. These credentials grant access to Slack workspaces and channels.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-SEC-007",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["secrets", "slack", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{10,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Slack token found; rotate the token and use environment variables or a secrets manager",
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
	regex.match(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Slack webhook URL found; rotate the webhook and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
