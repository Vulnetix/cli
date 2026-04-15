package vulnetix.rules.vnx_bash_004

import rego.v1

metadata := {
	"id": "VNX-BASH-004",
	"name": "Unquoted variable used in command or test",
	"description": "Shell variables used in command arguments or test expressions without double-quotes are subject to word splitting and glob expansion. An attacker who controls a variable value containing spaces or glob characters can cause argument injection or unexpected command behaviour.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-004/",
	"languages": ["bash", "shell"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [78, 88],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["bash", "word-splitting", "unquoted-variable", "argument-injection"],
}

_is_bash(path) if endswith(path, ".sh")

_is_bash(path) if endswith(path, ".bash")

# Detect command substitution result used unquoted in an assignment that feeds a command,
# or variable in [ ] test without quotes, e.g.: [ $var == "x" ]
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_bash(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Pattern: [ $VAR ... ] or [ ... $VAR ] - variable not double-quoted inside single brackets
	regex.match(`\[\s+\$[a-zA-Z_][a-zA-Z0-9_]*[^"]`, line)
	not regex.match(`\[\[\s+`, line)
	not regex.match(`^\s*#`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unquoted variable inside [ ] test is subject to word splitting; use double-quotes: [ \"$var\" = \"value\" ] or switch to [[ ]] to avoid word-splitting issues",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
