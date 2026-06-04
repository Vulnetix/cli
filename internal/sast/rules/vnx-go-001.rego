# SPDX-License-Identifier: Apache-2.0
# Go - missing go.sum

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
	"tags": ["supply-chain", "lockfile", "integrity"]
}

findings contains finding if {
	# Only flag dirs where Go was actually detected (a go.mod is present —
	# dirs_by_language["go"] is keyed on go.mod), and go.sum is absent.
	some dir in input.dirs_by_language["go"]
	not input.file_set[_dir_path(dir, "go.sum")]
	finding := {
		"rule_id": metadata.id,
		"message": "go.sum is missing; add it to lock module checksums",
		"artifact_uri": _dir_path(dir, "go.mod"),
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
	}
}

# _dir_path joins a detected dir with a filename, matching the file_set key
# format: root-level files are stored bare ("go.mod"), nested ones with their
# dir prefix ("svc/go.mod"). dirs_by_language uses "." for the scan root.
_dir_path(dir, name) := name if dir == "."

_dir_path(dir, name) := concat("/", [dir, name]) if dir != "."