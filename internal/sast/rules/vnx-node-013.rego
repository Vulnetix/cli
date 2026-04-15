package vulnetix.rules.vnx_node_013

import rego.v1

metadata := {
	"id": "VNX-NODE-013",
	"name": "Node.js command injection via child_process",
	"description": "Passing user input to child_process.exec(), execSync(), or similar functions enables OS command injection, allowing attackers to execute arbitrary system commands.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-013/",
	"languages": ["node"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["command-injection", "child-process", "rce"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_cmd_injection_indicators := {
	"exec(req.",
	"exec(request.",
	"execSync(req.",
	"execSync(request.",
	"child_process.exec(",
	"child_process.execSync(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _cmd_injection_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input in child_process command; use execFile() with an argument array or validate/escape input",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(exec|execSync)\(\x60.*\$\{`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Command built with template literal interpolation; use execFile() with an argument array instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
