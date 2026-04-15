package vulnetix.rules.vnx_ruby_010

import rego.v1

metadata := {
	"id": "VNX-RUBY-010",
	"name": "OpenSSL certificate verification disabled (VERIFY_NONE)",
	"description": "OpenSSL::SSL::VERIFY_NONE disables certificate chain verification for TLS connections, allowing a man-in-the-middle attacker to intercept and modify encrypted traffic without detection. Use OpenSSL::SSL::VERIFY_PEER to enforce certificate validation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-010/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["ssl", "tls", "certificate", "mitm", "ruby"],
}

_is_rb(path) if endswith(path, ".rb")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rb(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "VERIFY_NONE")
	finding := {
		"rule_id": metadata.id,
		"message": "OpenSSL::SSL::VERIFY_NONE disables TLS certificate verification and enables man-in-the-middle attacks; use OpenSSL::SSL::VERIFY_PEER instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
