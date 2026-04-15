package vulnetix.rules.vnx_py_012

import rego.v1

metadata := {
	"id": "VNX-PY-012",
	"name": "Python server-side template injection",
	"description": "Using render_template_string() or Template() with user-controlled input in Flask/Jinja2 enables server-side template injection, allowing attackers to execute arbitrary Python code on the server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-012/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [1336],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ssti", "template-injection", "flask", "jinja2"],
}

_is_py(path) if endswith(path, ".py")

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_ssti_indicators := {
	"render_template_string(request.",
	"render_template_string(f\"",
	"render_template_string(f'",
	"Template(request.",
	"Template(f\"",
	"Template(f'",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ssti_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input in template string enables server-side template injection; use render_template with a static template file instead",
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
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`render_template_string\(.*\+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User input in template string enables server-side template injection; use render_template with a static template file instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
