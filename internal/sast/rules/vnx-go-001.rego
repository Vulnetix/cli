package vulnetix.rules.vnx_go_001

import rego.v1

metadata := {
	"id": "VNX-GO-001",
	"name": "Missing go.sum",
	"description": "Missing a version lock with checksums often leads to malware installation via software supply chain attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-001/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:L/AL:L/IC:H/FC:H/RP:H/RL:H/AV:L/AS:L/IN:L/SC:N/CONF:N/T:P/P:H",
	"tags": ["supply-chain", "lockfile", "integrity"],
}

findings contains finding if {
	some dir in input.dirs_by_language["go"]
	go_sum := concat("/", [dir, "go.sum"])
	not input.file_set[go_sum]
	finding := {
		"rule_id": metadata.id,
		"message": "go.sum is missing; add it to lock module checksums",
		"artifact_uri": dir,
		"severity": metadata.severity,
		"level": metadata.level,
	}
}
