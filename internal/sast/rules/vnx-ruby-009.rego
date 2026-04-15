package vulnetix.rules.vnx_ruby_009

import rego.v1

metadata := {
	"id": "VNX-RUBY-009",
	"name": "Ruby dynamic method dispatch via send with user-controlled method name",
	"description": "Object#send, public_send, or __send__ is called with a method name derived from user-controlled input (params, request). This allows attackers to call arbitrary methods including dangerous ones like exit!, destroy, or system. Validate the method name against an explicit allowlist before dispatching.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-009/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-153"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["reflection", "send", "code-injection", "ruby"],
}

_is_rb(path) if endswith(path, ".rb")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rb(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.(send|public_send|__send__)\s*\(\s*params`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Dynamic method dispatch with params-derived method name; validate against an explicit allowlist before calling send/public_send to prevent arbitrary method invocation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rb(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.(send|public_send|__send__)\s*\(\s*request`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Dynamic method dispatch with request-derived method name; validate against an explicit allowlist before calling send/public_send to prevent arbitrary method invocation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
