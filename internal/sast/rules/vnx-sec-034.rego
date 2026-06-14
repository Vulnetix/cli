package vulnetix.rules.vnx_sec_034

import rego.v1

metadata := {
	"id": "VNX-SEC-034",
	"name": "Alibaba Cloud access key",
	"description": "An Alibaba Cloud access key ID was found in source code. Alibaba keys (LTAI prefix) grant full access to the holder's Alibaba Cloud RAM permissions and are commonly scraped by bots.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-034/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "alibaba", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`LTAI[a-z0-9]{20}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Alibaba Cloud access key ID found; rotate the key in RAM and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
