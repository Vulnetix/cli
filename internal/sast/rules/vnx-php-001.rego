package vulnetix.rules.vnx_php_001

import rego.v1

metadata := {
	"id": "VNX-PHP-001",
	"name": "Missing composer.lock",
	"description": "composer.json exists without composer.lock. Without a lock file, composer install resolves floating ranges non-deterministically, enabling supply chain attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-001/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:L/AL:L/IC:H/FC:H/RP:H/RL:H/AV:L/AS:L/IN:L/SC:N/CONF:N/T:P/P:H",
	"tags": ["supply-chain", "lockfile", "integrity"],
}

findings contains finding if {
	some dir in input.dirs_by_language["php"]
	lock := concat("/", [dir, "composer.lock"])
	not input.file_set[lock]
	finding := {
		"rule_id": metadata.id,
		"message": "composer.lock is missing; run composer install to generate a lock file",
		"artifact_uri": dir,
		"severity": metadata.severity,
		"level": metadata.level,
	}
}
