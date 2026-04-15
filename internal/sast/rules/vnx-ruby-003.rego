package vulnetix.rules.vnx_ruby_003

import rego.v1

metadata := {
	"id": "VNX-RUBY-003",
	"name": "Insecure deserialization in Ruby",
	"description": "Marshal.load and YAML.load (without safe class restrictions) deserialize arbitrary Ruby objects. Malicious data can execute arbitrary code during deserialization.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-003/",
	"languages": ["ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["deserialization", "marshal", "yaml", "dangerous-function"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_deser_indicators := {
	"Marshal.load(",
	"Marshal.restore(",
	"YAML.load(",
	"YAML.unsafe_load(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _deser_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Insecure deserialization (%s); use JSON.parse, YAML.safe_load, or Marshal with trusted data only", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
