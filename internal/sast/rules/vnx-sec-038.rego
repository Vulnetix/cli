package vulnetix.rules.vnx_sec_038

import rego.v1

metadata := {
	"id": "VNX-SEC-038",
	"name": "HashiCorp Terraform Cloud token",
	"description": "A HashiCorp Terraform Cloud API token was found in source code. Terraform Cloud tokens grant ability to modify infrastructure-as-code state and trigger runs that can alter production infrastructure.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-038/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "terraform", "hashicorp", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".tfvars")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Terraform Cloud API token found; revoke the token in TFC and rotate any leaked secrets",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
