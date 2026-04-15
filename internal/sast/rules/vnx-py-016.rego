package vulnetix.rules.vnx_py_016

import rego.v1

metadata := {
	"id": "VNX-PY-016",
	"name": "Django mass assignment via request data unpacking",
	"description": "Django model is created or updated by passing request data directly via dictionary unpacking (**request.data, **request.POST). This allows attackers to set any model field, including sensitive ones like is_staff, is_admin, or price.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-016/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [915],
	"capec": ["CAPEC-78"],
	"attack_technique": ["T1565"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["mass-assignment", "django", "python"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.objects\.create\s*\(\s*\*\*request\.(data|POST)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Mass assignment via **request.data in Model.objects.create(); explicitly list the fields you intend to set to prevent over-posting attacks",
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
	regex.match(`fields\s*=\s*["']__all__["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "DRF ModelSerializer with fields='__all__' exposes every model field for writing; explicitly list allowed fields or use read_only_fields for sensitive attributes",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
