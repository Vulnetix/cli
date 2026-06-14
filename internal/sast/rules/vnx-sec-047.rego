package vulnetix.rules.vnx_sec_047

import rego.v1

metadata := {
	"id": "VNX-SEC-047",
	"name": "Shopify access token",
	"description": "A Shopify access token (shpat_, shpca_, shppa_, shpss_ prefix) was found in source code. Shopify tokens grant API access to storefronts, customer data, and order information.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-047/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "shopify", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`shp(at|ca|pa|ss)_[a-fA-F0-9]{32}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Shopify access token found; revoke the token in the Shopify admin",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
