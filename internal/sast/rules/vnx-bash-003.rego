package vulnetix.rules.vnx_bash_003

import rego.v1

metadata := {
	"id": "VNX-BASH-003",
	"name": "Missing set -euo pipefail in Bash script",
	"description": "Bash scripts without 'set -euo pipefail' (or equivalent) silently ignore errors, unbound variables, and pipeline failures. This can cause scripts to continue execution after a failed command, operate on unset variables with empty values, or miss failures in piped commands.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-003/",
	"languages": ["bash", "shell"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [755],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["bash", "error-handling", "set-e", "best-practice"],
}

_is_bash(path) if endswith(path, ".sh")

_is_bash(path) if endswith(path, ".bash")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_bash(path)
	content := input.file_contents[path]
	# Must have a bash/sh shebang to be a real script
	regex.match(`^#!\s*/usr/bin/(env\s+)?(bash|sh)`, content)
	# Must NOT already have set -e, set -u, or set -euo/set -eu somewhere
	not regex.match(`(?m)^\s*set\s+.*-[a-z]*e[a-z]*`, content)
	not regex.match(`(?m)^\s*set\s+-e`, content)
	finding := {
		"rule_id": metadata.id,
		"message": "Script lacks 'set -euo pipefail'; add it immediately after the shebang to exit on errors, catch unbound variables, and detect pipeline failures",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "Missing: set -euo pipefail",
	}
}
