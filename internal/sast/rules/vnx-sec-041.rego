package vulnetix.rules.vnx_sec_041

import rego.v1

metadata := {
	"id": "VNX-SEC-041",
	"name": "Atlassian API token",
	"description": "An Atlassian API token (ATATT3 prefix) was found in source code. These tokens grant access to Jira, Confluence, Bitbucket, and other Atlassian Cloud products.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-041/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "atlassian", "jira", "confluence", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`ATATT3[A-Za-z0-9_\-=]{186}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Atlassian API token found; revoke the token in id.atlassian.com/manage-profile/security/api-tokens",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
