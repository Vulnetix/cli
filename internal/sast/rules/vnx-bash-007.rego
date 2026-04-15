package vulnetix.rules.vnx_bash_007

import rego.v1

metadata := {
	"id": "VNX-BASH-007",
	"name": "Unquoted command substitution in shell script",
	"description": "A command substitution $(...) or backtick expression is used without double-quotes. Without quotes, the output is subject to word splitting and glob expansion according to the current IFS value. An attacker who can influence the output can inject extra arguments into the enclosing command. Always quote command substitutions: \"$(...)\".",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-007/",
	"languages": ["bash"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [88],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:M/AV:L/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["word-splitting", "bash", "command-substitution", "shell"],
}

_is_bash(path) if endswith(path, ".sh")
_is_bash(path) if endswith(path, ".bash")
_is_bash(path) if endswith(path, ".bats")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_bash(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not regex.match(`^\s*#`, line)
	# Detect unquoted $(...) that is not preceded by a double-quote, assignment =, or another $
	regex.match(`(^|[^"$=])\$\([^)]+\)([^"]|$)`, line)
	not regex.match(`"\$\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unquoted command substitution $(...) is subject to word splitting and glob expansion; wrap in double quotes: \"$(...)\"",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
