package vulnetix.rules.vnx_bash_002

import rego.v1

metadata := {
	"id": "VNX-BASH-002",
	"name": "curl or wget output piped directly to shell interpreter",
	"description": "Downloading remote content and immediately executing it via a pipe to bash/sh/zsh bypasses integrity verification. A compromised CDN, DNS hijack, or MITM attack can result in arbitrary command execution on the host.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-002/",
	"languages": ["bash", "shell"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [494, 829],
	"capec": ["CAPEC-310"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["curl", "wget", "pipe-to-shell", "bash", "supply-chain"],
}

_is_bash(path) if endswith(path, ".sh")

_is_bash(path) if endswith(path, ".bash")

_is_bash(path) if endswith(path, ".bats")

# curl ... | bash/sh/zsh
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_bash(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bcurl\b.+\|\s*(bash|sh|zsh|ksh|dash)\b`, line)
	not regex.match(`^\s*#`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "curl piped to shell executes remote code without integrity checks; download the script first, verify its checksum/signature, then execute",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# wget ... | bash/sh/zsh or wget -O - | bash
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_bash(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bwget\b.+\|\s*(bash|sh|zsh|ksh|dash)\b`, line)
	not regex.match(`^\s*#`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "wget piped to shell executes remote code without integrity checks; download the script first, verify its checksum/signature, then execute",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
