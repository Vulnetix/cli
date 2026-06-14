package vulnetix.rules.vnx_sec_068

import rego.v1

metadata := {
	"id": "VNX-SEC-068",
	"name": "Ethereum private key",
	"description": "A 64-character hexadecimal Ethereum private key (optionally 0x-prefixed) was found in source code. Ethereum private keys grant full control of the associated account and all funds/assets it holds.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-068/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "ethereum", "crypto", "blockchain", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".json")
_skip(path) if endswith(path, ".md")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`0x[0-9a-fA-F]{64}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Ethereum private key candidate (64-hex) found; treat as compromised and move funds immediately",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
