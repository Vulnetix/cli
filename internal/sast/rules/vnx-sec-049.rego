package vulnetix.rules.vnx_sec_049

import rego.v1

metadata := {
	"id": "VNX-SEC-049",
	"name": "Anthropic admin API key",
	"description": "An Anthropic admin API key (sk-ant-admin01- prefix) was found in source code. Admin keys grant organization-wide access including the ability to manage members, billing, and other keys.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-049/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "anthropic", "ai", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Anthropic admin API key found; revoke the key in the Anthropic console",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
