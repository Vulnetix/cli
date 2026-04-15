package vulnetix.rules.vnx_ruby_007

import rego.v1

metadata := {
	"id": "VNX-RUBY-007",
	"name": "YAML.load() insecure deserialization",
	"description": "YAML.load() deserializes arbitrary Ruby objects from the input string, enabling remote code execution when the input is attacker-controlled. Use YAML.safe_load() or Psych.safe_load() which restrict deserialization to simple types, or pass permitted_classes to explicitly allowlist safe types.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-007/",
	"languages": ["ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["deserialization", "yaml", "rce", "ruby"],
}

_is_rb(path) if endswith(path, ".rb")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rb(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`YAML\.load\s*\(`, line)
	not contains(line, "safe_load")
	not contains(line, "safe: true")
	finding := {
		"rule_id": metadata.id,
		"message": "YAML.load() can deserialize arbitrary Ruby objects and lead to remote code execution; replace with YAML.safe_load() or Psych.safe_load() to restrict deserialization to safe types",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
