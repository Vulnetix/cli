package vulnetix.rules.vnx_rust_004

import rego.v1

metadata := {
	"id": "VNX-RUST-004",
	"name": "Rust command injection via process::Command with format",
	"description": "std::process::Command is constructed using format! macro or string concatenation with potentially user-controlled input. This can enable command injection if the interpolated value is not validated.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-004/",
	"languages": ["rust"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["command-injection", "rust"],
}

_is_rust(path) if endswith(path, ".rs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rust(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "Command::new")
	contains(line, "format!")
	finding := {
		"rule_id": metadata.id,
		"message": "process::Command constructed with format! macro; pass user input as a separate argument via .arg() rather than interpolating into the command string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rust(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "Command::new")
	regex.match(`shell\s*=\s*true|\.arg\s*\(\s*"sh"\s*\)|\.arg\s*\(\s*"-c"\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "process::Command invokes a shell interpreter (sh -c); if arguments include user input this enables command injection — pass arguments directly to Command::new instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
