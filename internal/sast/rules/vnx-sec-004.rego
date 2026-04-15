package vulnetix.rules.vnx_sec_004

import rego.v1

metadata := {
	"id": "VNX-SEC-004",
	"name": "GitHub or GitLab token",
	"description": "A GitHub personal access token (ghp_/ghs_) or GitLab personal access token (glpat-) was found in source code. These tokens grant API access to repositories and should never be hardcoded.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-SEC-004",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "github", "gitlab", "tokens"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`gh[ps]_[A-Za-z0-9_]{36,255}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GitHub token found; rotate it and use environment variables or a secrets manager",
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
	regex.match(`glpat-[A-Za-z0-9_\-]{20,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GitLab token found; rotate it and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
