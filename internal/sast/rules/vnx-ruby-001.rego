package vulnetix.rules.vnx_ruby_001

import rego.v1

metadata := {
	"id": "VNX-RUBY-001",
	"name": "Missing Gemfile.lock",
	"description": "Gemfile exists without Gemfile.lock. Without a lock file, bundle install resolves floating ranges non-deterministically, enabling supply chain attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-001/",
	"languages": ["ruby"],
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
	some dir in input.dirs_by_language["ruby"]
	lock := concat("/", [dir, "Gemfile.lock"])
	not input.file_set[lock]
	gemfile := concat("/", [dir, "Gemfile"])
	finding := {
		"rule_id": metadata.id,
		"message": "Gemfile.lock is missing; run bundle lock to pin dependency versions",
		"artifact_uri": gemfile,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
	}
}
