package vulnetix.rules.vnx_py_007

import rego.v1

metadata := {
	"id": "VNX-PY-007",
	"name": "subprocess with shell=True",
	"description": "subprocess calls with shell=True pass the command through the system shell, enabling command injection if any part of the command is user-controlled.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PY-007",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["command-injection", "subprocess", "dangerous-function"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`subprocess\.(call|run|Popen|check_call|check_output)\(.*shell\s*=\s*True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "subprocess called with shell=True; use shell=False with a list of arguments instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
