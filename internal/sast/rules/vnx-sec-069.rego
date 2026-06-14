package vulnetix.rules.vnx_sec_069

import rego.v1

metadata := {
	"id": "VNX-SEC-069",
	"name": "age secret key",
	"description": "An age secret key (AGE-SECRET-KEY-1... prefix) was found in source code. age keys grant the ability to decrypt files encrypted with the corresponding public key.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-069/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "age", "encryption", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "age secret key found; rotate the key and re-encrypt any files encrypted to the matching public key",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
