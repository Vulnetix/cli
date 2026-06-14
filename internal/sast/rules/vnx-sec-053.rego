package vulnetix.rules.vnx_sec_053

import rego.v1

metadata := {
	"id": "VNX-SEC-053",
	"name": "SonarQube / Snyk API token",
	"description": "A SonarQube (squ_, sqp_, sqa_ prefix) or Snyk API token was found in source code. These tokens grant access to code quality dashboards and security scanning infrastructure.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-053/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "sonarqube", "snyk", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(squ_|sqp_|sqa_)[a-z0-9=_\-]{40}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SonarQube API token found; revoke the token in SonarQube user account",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
