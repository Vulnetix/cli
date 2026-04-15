package vulnetix.rules.vnx_bash_001

import rego.v1

metadata := {
	"id": "VNX-BASH-001",
	"name": "eval with potentially user-controlled input",
	"description": "eval is used with a variable or command substitution rather than a static string. If any portion of the evaluated string originates from user input, environment variables, or external sources, an attacker can execute arbitrary shell commands.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-001/",
	"languages": ["bash", "shell"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["eval", "bash", "command-injection", "shell"],
}

_is_bash(path) if endswith(path, ".sh")

_is_bash(path) if endswith(path, ".bash")

_is_bash(path) if endswith(path, ".bats")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_bash(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# eval followed by a variable, command substitution, or concatenation - not a plain literal
	regex.match(`^\s*eval\s+`, line)
	not regex.match(`^\s*eval\s+"[^$` + "`" + `]+"\s*$`, line)
	not regex.match(`^\s*#`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "eval with a variable or command substitution enables code injection; avoid eval or restrict to a known-safe static string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
