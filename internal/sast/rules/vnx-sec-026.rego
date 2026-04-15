package vulnetix.rules.vnx_sec_026

import rego.v1

metadata := {
	"id": "VNX-SEC-026",
	"name": "DigitalOcean personal access token hardcoded",
	"description": "A DigitalOcean personal access token (dop_v1_ prefix) appears hardcoded in source code. This token provides full API access to the DigitalOcean account including Droplets, databases, and Kubernetes clusters. Revoke the token at cloud.digitalocean.com/account/api/tokens and store in environment variables.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-026/",
	"languages": ["generic"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secret", "digitalocean", "cloud", "credentials"],
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
	regex.match(`dop_v1_[a-f0-9]{64}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "DigitalOcean personal access token detected — revoke at cloud.digitalocean.com/account/api/tokens and use environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
