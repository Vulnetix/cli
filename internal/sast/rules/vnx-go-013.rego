package vulnetix.rules.vnx_go_013

import rego.v1

metadata := {
	"id": "VNX-GO-013",
	"name": "Go zip/tar slip via archive entry name",
	"description": "An archive entry header.Name is joined into a file path via filepath.Join() without validating the result stays within the target directory. An attacker can craft entries with '../' sequences to write files outside the intended directory.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-013/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [22],
	"capec": ["CAPEC-139"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["path-traversal", "zip-slip", "go"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "filepath.Join")
	regex.match(`[Hh]eader\.Name`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Archive entry name joined into file path without validation; check that the resolved path stays within the destination directory using filepath.Rel() or reject entries containing '..'",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
