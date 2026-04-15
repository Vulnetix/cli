package vulnetix.rules.vnx_go_002

import rego.v1

metadata := {
	"id": "VNX-GO-002",
	"name": "Command injection via exec.Command",
	"description": "exec.Command() with fmt.Sprintf or string concatenation can inject shell commands when the formatted value is user-controlled.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-GO-002",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["command-injection", "dangerous-function"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "exec.Command")
	contains(line, "fmt.Sprintf")
	finding := {
		"rule_id": metadata.id,
		"message": "exec.Command with fmt.Sprintf; pass arguments as separate parameters to avoid shell injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
