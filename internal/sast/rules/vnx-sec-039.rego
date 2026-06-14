package vulnetix.rules.vnx_sec_039

import rego.v1

metadata := {
	"id": "VNX-SEC-039",
	"name": "GitLab personal access token (legacy)",
	"description": "A legacy GitLab personal access token (glpat- prefix) was found in source code. These tokens grant API access to GitLab repositories, container registries, and package registries.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-039/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
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
	regex.match(`glpat-[\w-]{20}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GitLab personal access token found; revoke the token in GitLab user settings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
