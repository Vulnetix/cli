package vulnetix.rules.vnx_sec_077

import rego.v1

metadata := {
	"id": "VNX-SEC-077",
	"name": "Mapbox access token",
	"description": "A Mapbox access token (pk.60-char.22-char format) was found in source code. Mapbox tokens grant access to map tiles, geocoding, and directions APIs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-077/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "mapbox", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`pk\.[a-z0-9]{60}\.[a-z0-9]{22}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Mapbox access token found; revoke the token in the Mapbox account",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
