package vulnetix.rules.vnx_sec_027

import rego.v1

metadata := {
	"id": "VNX-SEC-027",
	"name": "Hugging Face API token hardcoded",
	"description": "A Hugging Face API token (hf_ prefix) appears hardcoded in source code. This token provides access to private model repositories, datasets, and inference API endpoints. Revoke the token at huggingface.co/settings/tokens and store in environment variables.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-027/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secret", "huggingface", "ai", "credentials"],
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
	regex.match(`hf_[A-Za-z0-9]{34,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hugging Face API token detected — revoke at huggingface.co/settings/tokens and store in environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
