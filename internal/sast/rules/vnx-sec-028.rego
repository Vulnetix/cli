package vulnetix.rules.vnx_sec_028

import rego.v1

metadata := {
	"id": "VNX-SEC-028",
	"name": "npm access token hardcoded",
	"description": "An npm access token (npm_ prefix) appears hardcoded in source code. This token can be used to publish packages, access private registries, and modify organization settings depending on its scope. Revoke the token at npmjs.com/settings and use environment variables or CI secrets instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-028/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secret", "npm", "registry", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`npm_[0-9A-Za-z]{36}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "npm access token detected — revoke at npmjs.com/settings and store in CI secrets or environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
