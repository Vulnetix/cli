package vulnetix.rules.vnx_sec_025

import rego.v1

metadata := {
	"id": "VNX-SEC-025",
	"name": "Azure Storage Account key hardcoded",
	"description": "An Azure Storage Account key (base64-encoded, ~88 characters) appears hardcoded in source code. Azure Storage keys provide full read/write access to all blobs, queues, tables, and files in the account. Rotate keys immediately via the Azure Portal and store in Azure Key Vault or environment variables.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-025/",
	"languages": ["generic"],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secret", "azure", "cloud", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)azure[_\-\.]?(storage)?[_\-\.]?(account)?[_\-\.]?key`, line)
	regex.match(`[A-Za-z0-9+/]{86}==`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Azure Storage Account key detected — rotate immediately via Azure Portal and store in Azure Key Vault instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
