package vulnetix.rules.vnx_c_006

import rego.v1

metadata := {
	"id": "VNX-C-006",
	"name": "Use of alloca() for dynamic stack allocation",
	"description": "alloca() allocates memory on the stack based on a runtime size without bounds checking. If the size is attacker-controlled or unexpectedly large, this causes a stack overflow or corrupts adjacent stack frames. Use malloc()/calloc() with proper size validation instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-006/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [676, 1325],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["alloca", "stack-overflow", "c", "dangerous-function", "memory-safety"],
}

_is_c(path) if endswith(path, ".c")

_is_c(path) if endswith(path, ".h")

_is_c(path) if endswith(path, ".cpp")

_is_c(path) if endswith(path, ".cc")

_is_c(path) if endswith(path, ".cxx")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_c(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\balloca\s*\(`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "alloca() stack allocation has no bounds checking; use malloc()/calloc() with validated size to prevent stack overflow when size is runtime-determined",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
