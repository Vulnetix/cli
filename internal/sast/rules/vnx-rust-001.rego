package vulnetix.rules.vnx_rust_001

import rego.v1

metadata := {
	"id": "VNX-RUST-001",
	"name": "Missing Cargo.lock",
	"description": "Cargo.toml exists without Cargo.lock. Without a lock file, cargo resolves floating ranges non-deterministically, enabling supply chain attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-001/",
	"languages": ["rust"],
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
	some dir in input.dirs_by_language["rust"]
	not input.file_set[_dir_path(dir, "Cargo.lock")]
	finding := {
		"rule_id": metadata.id,
		"message": "Cargo.lock is missing; run cargo generate-lockfile to pin dependency versions",
		"artifact_uri": _dir_path(dir, "Cargo.toml"),
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
	}
}

# _dir_path joins a detected dir with a filename to match the file_set key
# format (root files are stored bare; dirs_by_language uses "." for the root).
_dir_path(dir, name) := name if dir == "."

_dir_path(dir, name) := concat("/", [dir, name]) if dir != "."
