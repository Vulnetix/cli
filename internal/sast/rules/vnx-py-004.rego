package vulnetix.rules.vnx_py_004

import rego.v1

metadata := {
	"id": "VNX-PY-004",
	"name": "yaml.load() without SafeLoader",
	"description": "yaml.load() without an explicit safe Loader (SafeLoader, CSafeLoader, BaseLoader) can deserialize arbitrary Python objects, enabling remote code execution.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-004/",
	"languages": ["python"],
	"severity": "high",
	"level": "warning",
	"kind": "open",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["deserialization", "yaml", "dangerous-function"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "yaml.load(")
	not contains(line, "Loader=")
	not contains(line, "SafeLoader")
	not contains(line, "CSafeLoader")
	not contains(line, "BaseLoader")
	not contains(line, "safe_load")
	finding := {
		"rule_id": metadata.id,
		"message": "yaml.load() without SafeLoader; use yaml.safe_load() or pass Loader=SafeLoader",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
