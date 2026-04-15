package vulnetix.rules.vnx_py_020

import rego.v1

metadata := {
	"id": "VNX-PY-020",
	"name": "tarfile.extractall() without path validation (zip slip)",
	"description": "tarfile.extractall() is called without filtering member paths. Archive members with paths containing '..' or absolute paths can escape the extraction directory and overwrite arbitrary files on the system (zip slip / path traversal). Filter members using a safe extraction helper or validate each member path before extraction.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-020/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [22],
	"capec": ["CAPEC-139"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["path-traversal", "zip-slip", "tarfile", "python"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, ".extractall(")
	not contains(line, "filter=")
	not contains(line, "members=")
	finding := {
		"rule_id": metadata.id,
		"message": "tarfile.extractall() without a members filter or path validation is vulnerable to zip-slip path traversal; use the 'filter' parameter (Python 3.12+) or manually validate each member's path before extraction",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
