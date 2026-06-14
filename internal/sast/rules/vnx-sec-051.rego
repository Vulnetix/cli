package vulnetix.rules.vnx_sec_051

import rego.v1

metadata := {
	"id": "VNX-SEC-051",
	"name": "RubyGems API token",
	"description": "A RubyGems API token (rubygems_ prefix) was found in source code. These tokens grant publish access to RubyGems.org and enable supply chain attacks on Ruby libraries.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-051/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "rubygems", "supply-chain", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`rubygems_[a-f0-9]{48}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "RubyGems API token found; revoke the token in the RubyGems.org profile",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
