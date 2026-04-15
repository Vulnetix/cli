package vulnetix.rules.vnx_cs_002

import rego.v1

metadata := {
	"id": "VNX-CS-002",
	"name": "C# command injection via Process.Start with user input",
	"description": "System.Diagnostics.Process.Start is called with arguments that may be user-controlled. Interpolating user input into OS command arguments allows an attacker to inject arbitrary shell commands.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-002/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["command-injection", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

# Detect Process.Start with string concatenation or interpolation
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Process\.Start\s*\(`, line)
	regex.match(`\+\s*\w|\bstring\.Format\b|\$"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Process.Start called with concatenated or interpolated string; validate and sanitise all user-controlled input before passing it as a process argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Detect FileName or Arguments assignment with concatenation
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.(FileName|Arguments)\s*=`, line)
	regex.match(`\+\s*\w|\bstring\.Format\b|\$"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "ProcessStartInfo.FileName or .Arguments assigned with concatenated or interpolated string; validate and sanitise all user-controlled input before passing it as a process argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
