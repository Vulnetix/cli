package vulnetix.rules.vnx_node_001

import rego.v1

metadata := {
	"id": "VNX-NODE-001",
	"name": "Missing npm lock file",
	"description": "No package-lock.json, yarn.lock, or pnpm-lock.yaml found alongside package.json. Without a lock file, npm install resolves floating ranges on every run, enabling dependency confusion and supply chain attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-001/",
	"languages": ["node"],
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
	some dir in input.dirs_by_language["node"]
	pkg_lock := concat("/", [dir, "package-lock.json"])
	yarn_lock := concat("/", [dir, "yarn.lock"])
	pnpm_lock := concat("/", [dir, "pnpm-lock.yaml"])
	not input.file_set[pkg_lock]
	not input.file_set[yarn_lock]
	not input.file_set[pnpm_lock]
	package_json := concat("/", [dir, "package.json"])
	finding := {
		"rule_id": metadata.id,
		"message": "No lock file found (package-lock.json, yarn.lock, or pnpm-lock.yaml); add one to pin dependency versions",
		"artifact_uri": package_json,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
	}
}
