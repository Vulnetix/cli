package vulnetix.rules.vnx_py_006

import rego.v1

metadata := {
	"id": "VNX-PY-006",
	"name": "Django DEBUG=True",
	"description": "DEBUG=True in Django settings exposes detailed tracebacks, SQL queries, and configuration to any visitor. Must be False in production.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PY-006",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [489],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["django", "config", "debug"],
}

_is_settings(path) if endswith(path, "settings.py")
_is_settings(path) if endswith(path, "settings/base.py")
_is_settings(path) if endswith(path, "settings/production.py")
_is_settings(path) if endswith(path, "settings/prod.py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_settings(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*DEBUG\s*=\s*True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "DEBUG = True in Django settings; set DEBUG = False for production",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
