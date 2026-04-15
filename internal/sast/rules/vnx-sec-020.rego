package vulnetix.rules.vnx_sec_020

import rego.v1

metadata := {
	"id": "VNX-SEC-020",
	"name": "GitLab access token",
	"description": "A GitLab personal, project, or group access token was found in source code. These tokens grant API access to GitLab resources.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-020/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["secrets", "gitlab", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`glpat-[A-Za-z0-9\-_]{20,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GitLab access token found; rotate the token and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
