package vulnetix.rules.vnx_py_001

import rego.v1

metadata := {
	"id": "VNX-PY-001",
	"name": "Missing Python lock file",
	"description": "A Python project manifest (pyproject.toml or Pipfile) exists without a corresponding lock file. Without pinned versions, dependency resolution is non-deterministic and vulnerable to supply chain attacks.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PY-001",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:L/AL:L/IC:H/FC:H/RP:H/RL:H/AV:L/AS:L/IN:L/SC:N/CONF:N/T:P/P:H",
	"tags": ["supply-chain", "lockfile", "integrity"],
}

# Fire when pyproject.toml exists without any lock file.
findings contains finding if {
	some dir in input.dirs_by_language["python"]
	pyproject := concat("/", [dir, "pyproject.toml"])
	input.file_set[pyproject]
	uv_lock := concat("/", [dir, "uv.lock"])
	poetry_lock := concat("/", [dir, "poetry.lock"])
	pipfile_lock := concat("/", [dir, "Pipfile.lock"])
	not input.file_set[uv_lock]
	not input.file_set[poetry_lock]
	not input.file_set[pipfile_lock]
	finding := {
		"rule_id": metadata.id,
		"message": "pyproject.toml has no lock file (uv.lock, poetry.lock, or Pipfile.lock); add one to pin dependency versions",
		"artifact_uri": dir,
		"severity": metadata.severity,
		"level": metadata.level,
	}
}

# Fire when Pipfile exists without Pipfile.lock.
findings contains finding if {
	some dir in input.dirs_by_language["python"]
	pipfile := concat("/", [dir, "Pipfile"])
	input.file_set[pipfile]
	pipfile_lock := concat("/", [dir, "Pipfile.lock"])
	not input.file_set[pipfile_lock]
	finding := {
		"rule_id": metadata.id,
		"message": "Pipfile has no Pipfile.lock; run pipenv lock to pin dependency versions",
		"artifact_uri": dir,
		"severity": metadata.severity,
		"level": metadata.level,
	}
}
