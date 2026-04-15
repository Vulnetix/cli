package vulnetix.rules.vnx_py_002

import rego.v1

metadata := {
	"id": "VNX-PY-002",
	"name": "eval()/exec() usage in Python",
	"description": "Use of eval() or exec() executes arbitrary Python code. If any part of the argument is user-controlled, this enables remote code execution.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-002/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-35"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["code-injection", "dangerous-function"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\beval\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "eval() can execute arbitrary code; use ast.literal_eval() for safe evaluation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bexec\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "exec() can execute arbitrary code; avoid dynamic code execution",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
