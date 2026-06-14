package vulnetix.rules.vnx_sec_074

import rego.v1

metadata := {
	"id": "VNX-SEC-074",
	"name": "Kubernetes Secret manifest with credential data",
	"description": "A Kubernetes Secret manifest with non-empty data or stringData fields was found. While not a hard-coded secret in the same sense, committed Secret manifests let anyone with repo read access decrypt the secret.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-074/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "kubernetes", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".md")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".yaml")
	contains(input.file_contents[path], "kind: Secret")
	contains(input.file_contents[path], "data:")
	finding := {
		"rule_id": metadata.id,
		"message": "Kubernetes Secret manifest with data field committed; use Sealed Secrets, External Secrets Operator, or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "kind: Secret with data: field",
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".yaml")
	contains(input.file_contents[path], "kind: Secret")
	contains(input.file_contents[path], "stringData:")
	finding := {
		"rule_id": metadata.id,
		"message": "Kubernetes Secret manifest with stringData field committed; use Sealed Secrets, External Secrets Operator, or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "kind: Secret with stringData: field",
	}
}
