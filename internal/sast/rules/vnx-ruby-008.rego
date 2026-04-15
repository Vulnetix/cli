package vulnetix.rules.vnx_ruby_008

import rego.v1

metadata := {
	"id": "VNX-RUBY-008",
	"name": "Open3.pipeline with dynamic command",
	"description": "Open3.pipeline, pipeline_r, pipeline_rw, pipeline_w, or pipeline_start is called with a non-literal command argument. If user-controlled data reaches this call, an attacker can inject arbitrary OS commands. Use parameterized argument arrays instead of shell strings, and validate all inputs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-008/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["command-injection", "open3", "ruby"],
}

_is_rb(path) if endswith(path, ".rb")

_pipeline_methods := [
	"Open3.pipeline(",
	"Open3.pipeline_r(",
	"Open3.pipeline_rw(",
	"Open3.pipeline_w(",
	"Open3.pipeline_start(",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rb(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some method in _pipeline_methods
	contains(line, method)
	finding := {
		"rule_id": metadata.id,
		"message": "Open3.pipeline* called with potentially dynamic command; if user input can reach this call, command injection is possible — pass commands as argument arrays and validate all inputs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
