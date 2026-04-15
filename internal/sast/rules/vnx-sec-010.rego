package vulnetix.rules.vnx_sec_010

import rego.v1

metadata := {
	"id": "VNX-SEC-010",
	"name": "Package registry token",
	"description": "An npm or PyPI registry token was found in source code. These tokens grant publish access to package registries, enabling supply chain attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-010/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "npm", "pypi", "supply-chain", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`npm_[0-9a-zA-Z]{36}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "npm access token found; rotate the token and use environment variables or a secrets manager",
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
	regex.match(`pypi-AgEIcHlwaS5vcmc[0-9A-Za-z\-_]{50,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "PyPI upload token found; rotate the token and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
