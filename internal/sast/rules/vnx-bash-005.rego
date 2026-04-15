package vulnetix.rules.vnx_bash_005

import rego.v1

metadata := {
	"id": "VNX-BASH-005",
	"name": "Hardcoded secret or password in shell script",
	"description": "A variable with a name indicating a secret, password, token, or key is assigned a non-empty string literal in a shell script. Hardcoded credentials are exposed to anyone with read access to the repository or file system.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-005/",
	"languages": ["bash", "shell"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [798, 259],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["bash", "hardcoded-secret", "credentials", "password"],
}

_is_bash(path) if endswith(path, ".sh")

_is_bash(path) if endswith(path, ".bash")

_is_bash(path) if endswith(path, ".env")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_bash(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_KEY|DB_PASS|DB_PASSWORD)\s*=\s*['"][^'"]{4,}['"]`, line)
	not regex.match(`^\s*#`, line)
	not regex.match(`\$\{`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded secret detected in shell variable assignment; store secrets in environment variables injected at runtime, a secrets manager, or a vault - never in source code",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
