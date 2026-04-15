package vulnetix.rules.vnx_bash_006

import rego.v1

metadata := {
	"id": "VNX-BASH-006",
	"name": "Global IFS reassignment in shell script",
	"description": "The special IFS (Internal Field Separator) variable is reassigned globally in a shell script. Changing IFS affects how all subsequent variable expansions and command-line argument splitting behave, which can cause security-sensitive operations to parse input differently than expected. If field splitting is required, set IFS locally with 'local IFS=...' or 'IFS=... read ...' to limit the scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-006/",
	"languages": ["bash"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [20],
	"capec": ["CAPEC-15"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:M/AV:L/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["ifs", "bash", "input-validation", "shell"],
}

_is_bash(path) if endswith(path, ".sh")
_is_bash(path) if endswith(path, ".bash")
_is_bash(path) if endswith(path, ".bats")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_bash(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*IFS\s*=`, line)
	not regex.match(`^\s*#`, line)
	not contains(line, "local IFS")
	finding := {
		"rule_id": metadata.id,
		"message": "Global IFS reassignment changes word-splitting behaviour for the rest of the script; use 'local IFS=...' inside a function or 'IFS=... read ...' to limit the scope",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
