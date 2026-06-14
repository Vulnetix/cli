package vulnetix.rules.vnx_sec_035

import rego.v1

metadata := {
	"id": "VNX-SEC-035",
	"name": "DigitalOcean personal access token",
	"description": "A DigitalOcean personal access token (dop_v1_ prefix) was found in source code. These tokens grant full API access to the user's DigitalOcean account and are commonly leaked via .env files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-035/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "digitalocean", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`dop_v1_[a-f0-9]{64}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "DigitalOcean personal access token found; revoke the token in the DigitalOcean control panel",
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
	regex.match(`doo_v1_[a-f0-9]{64}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "DigitalOcean OAuth token found; revoke the token in the DigitalOcean control panel",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
