package vulnetix.rules.vnx_node_026

import rego.v1

metadata := {
	"id": "VNX-NODE-026",
	"name": "Child process spawn with shell:true enables command injection",
	"description": "spawn() or spawnSync() is called with {shell:true}. This causes the command to be executed through a shell interpreter (sh/cmd), which processes shell metacharacters in the command and arguments. If any part of the command is user-controlled, an attacker can inject arbitrary shell commands. Set shell:false (the default) and pass command arguments as a separate array.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-026/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["command-injection", "spawn", "shell", "child-process", "node"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`spawn(Sync)?\s*\(`, line)
	contains(line, "shell")
	contains(line, "true")
	not contains(line, "shell: false")
	not contains(line, "shell:false")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "spawn/spawnSync called with shell:true; this enables shell metacharacter injection — set shell:false and pass arguments as a separate array",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`child_process`, line)
	contains(line, "shell:")
	contains(line, "true")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "child_process function called with shell:true; this routes execution through a shell and enables command injection — use shell:false with an explicit argument array",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
