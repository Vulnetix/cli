package vulnetix.rules.vnx_android_005

import rego.v1

metadata := {
	"id": "VNX-ANDROID-005",
	"name": "Android network security config allows plaintext HTTP traffic",
	"description": "The Android network security configuration allows cleartext (HTTP) traffic for all domains or specific sensitive domains. Plaintext traffic can be intercepted by network attackers, exposing user data and credentials.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-005/",
	"languages": ["android"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [319],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["android", "cleartext", "network-security", "mobile-security"],
}

_is_xml(path) if endswith(path, ".xml")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_xml(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`cleartextTrafficPermitted\s*=\s*"true"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Android network security config permits cleartext HTTP traffic; set cleartextTrafficPermitted=\"false\" and migrate all endpoints to HTTPS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
