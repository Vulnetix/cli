package vulnetix.rules.vnx_py_015

import rego.v1

metadata := {
	"id": "VNX-PY-015",
	"name": "Python ReDoS via user-controlled regular expression",
	"description": "User-controlled input from a Flask/Django request is compiled or matched as a regular expression pattern. An attacker can supply a malicious pattern with catastrophic backtracking to cause denial of service.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-015/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1333],
	"capec": ["CAPEC-197"],
	"attack_technique": ["T1499.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["redos", "regex", "dos", "python"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`re\.(compile|match|search|fullmatch)\s*\(\s*request\.(args|form|data|json)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User-controlled input from request passed to re.compile/match/search; this enables ReDoS — use a fixed pattern or the google-re2 library for linear-time matching",
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
	regex.match(`re\.compile\s*\(\s*request\.`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User-controlled input from request passed to re.compile; this enables ReDoS attacks — use a fixed pattern",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
