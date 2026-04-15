package vulnetix.rules.vnx_go_011

import rego.v1

metadata := {
	"id": "VNX-GO-011",
	"name": "Go gob deserialization from HTTP request body",
	"description": "gob.NewDecoder decoding directly from an HTTP request body deserializes arbitrary Go types. Untrusted gob data can cause denial of service via resource exhaustion and may trigger unexpected behaviour in complex types.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-011/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["deserialization", "go", "dos"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "gob.NewDecoder")
	regex.match(`(r\.Body|req\.Body|request\.Body)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "gob.NewDecoder from HTTP request body; validate and size-limit input before decoding — consider using JSON with explicit struct types instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
