package vulnetix.rules.vnx_py_019

import rego.v1

metadata := {
	"id": "VNX-PY-019",
	"name": "Paramiko implicit host key trust",
	"description": "paramiko SSHClient is configured with AutoAddPolicy or WarningPolicy, which silently accepts any server host key without verification. This enables man-in-the-middle attacks. Use RejectPolicy and pre-populate known_hosts, or implement a custom policy that validates host key fingerprints.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-019/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [322],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["paramiko", "ssh", "mitm", "python"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "AutoAddPolicy")
	finding := {
		"rule_id": metadata.id,
		"message": "paramiko AutoAddPolicy silently trusts any SSH host key; use RejectPolicy and maintain a known_hosts file to prevent man-in-the-middle attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "WarningPolicy")
	finding := {
		"rule_id": metadata.id,
		"message": "paramiko WarningPolicy logs a warning but still accepts unverified SSH host keys; use RejectPolicy and maintain a known_hosts file to prevent man-in-the-middle attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
