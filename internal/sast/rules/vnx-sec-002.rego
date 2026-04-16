package vulnetix.rules.vnx_sec_002

import rego.v1

metadata := {
	"id": "VNX-SEC-002",
	"name": "Private key committed",
	"description": "A private key file (RSA, EC, DSA, or OpenSSH) was found in the repository. Committed private keys can be extracted from git history even after deletion.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-002/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [321],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "private-key", "cryptography"],
}

_key_markers := [
	"BEGIN RSA PRIVATE KEY",
	"BEGIN EC PRIVATE KEY",
	"BEGIN DSA PRIVATE KEY",
	"BEGIN OPENSSH PRIVATE KEY",
	"BEGIN PRIVATE KEY",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some marker in _key_markers
	contains(line, marker)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Private key (%s) found; remove it from the repository and rotate the key", [marker]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
