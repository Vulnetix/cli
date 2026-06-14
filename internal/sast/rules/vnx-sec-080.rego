package vulnetix.rules.vnx_sec_080

import rego.v1

metadata := {
	"id": "VNX-SEC-080",
	"name": "GitHub OAuth / App / Refresh token",
	"description": "A GitHub OAuth token (gho_), App user-to-server token (ghu_), App server-to-server token (ghs_), or refresh token (ghr_) was found in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-080/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "github", "oauth", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`gho_[0-9a-zA-Z]{36}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GitHub OAuth token found; revoke the OAuth app authorisation in GitHub settings",
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
	regex.match(`(ghu|ghs)_[0-9a-zA-Z]{36}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GitHub App token found; revoke the installation token in GitHub app settings",
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
	regex.match(`ghr_[0-9a-zA-Z]{36}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GitHub refresh token found; revoke the OAuth app authorisation in GitHub settings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
