package vulnetix.rules.vnx_c_001

import rego.v1

metadata := {
	"id": "VNX-C-001",
	"name": "Use of unbounded string copy function (strcpy/strcat/gets)",
	"description": "strcpy, stpcpy, strcat, gets, wcscpy, wcscat, or similar unbounded copy functions are used without bounds checking, enabling buffer overflow attacks. Prefer strlcpy/strlcat/fgets with explicit size limits.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-001/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [120, 676, 787],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["buffer-overflow", "c", "dangerous-function", "memory-safety"],
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
	regex.match(`\b(strcpy|stpcpy|strcat|gets|wcscpy|wcpcpy|wcscat|_mbscpy|_mbscat)\s*\(`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unbounded copy function detected; use strlcpy/strlcat/fgets and always pass destination buffer size to prevent stack or heap buffer overflow",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
