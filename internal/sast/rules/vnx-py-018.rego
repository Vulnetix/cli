package vulnetix.rules.vnx_py_018

import rego.v1

metadata := {
	"id": "VNX-PY-018",
	"name": "Insecure temporary file creation via tempfile.mktemp()",
	"description": "tempfile.mktemp() returns a filename that does not exist at the time of the call, but the file is not created atomically. A race condition (TOCTOU) between the name check and file creation allows an attacker to create the file first, leading to privilege escalation or data corruption. Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-018/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [377],
	"capec": ["CAPEC-29"],
	"attack_technique": ["T1574"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:M/AV:L/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["tempfile", "race-condition", "toctou", "python"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "tempfile.mktemp(")
	finding := {
		"rule_id": metadata.id,
		"message": "tempfile.mktemp() is unsafe due to a TOCTOU race condition; use tempfile.NamedTemporaryFile() or tempfile.mkstemp() to create temporary files atomically",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
