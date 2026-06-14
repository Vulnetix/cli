package vulnetix.rules.vnx_sec_037

import rego.v1

metadata := {
	"id": "VNX-SEC-037",
	"name": "HashiCorp Vault token",
	"description": "A HashiCorp Vault batch token (hvb.) or service token (hvs.) was found in source code. Vault tokens grant access to secrets stored in Vault and must be tightly scoped and short-lived.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-037/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "vault", "hashicorp", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`hvb\.[\w-]{138,300}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "HashiCorp Vault batch token found; revoke the token in Vault and rotate any leaked secrets",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`hvs\.[\w-]{90,120}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "HashiCorp Vault service token found; revoke the token in Vault and rotate any leaked secrets",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`s\.[a-z0-9]{24}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "HashiCorp Vault legacy service token found; revoke the token and migrate to hvs./hvb. format",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
