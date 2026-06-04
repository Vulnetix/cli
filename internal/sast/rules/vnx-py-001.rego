package vulnetix.rules.vnx_py_001

import rego.v1

metadata := {
	"id": "VNX-PY-001",
	"name": "Missing Python lock file",
	"description": "A Python project manifest (pyproject.toml or Pipfile) exists without a corresponding lock file. Without pinned versions, dependency resolution is non-deterministic and vulnerable to supply chain attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-001/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
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
	pyproject := _dir_path(dir, "pyproject.toml")
	input.file_set[pyproject]
	not input.file_set[_dir_path(dir, "uv.lock")]
	not input.file_set[_dir_path(dir, "poetry.lock")]
	not input.file_set[_dir_path(dir, "Pipfile.lock")]
	finding := {
		"rule_id": metadata.id,
		"message": "pyproject.toml has no lock file (uv.lock, poetry.lock, or Pipfile.lock); add one to pin dependency versions",
		"artifact_uri": pyproject,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
	}
}

# Fire when Pipfile exists without Pipfile.lock.
findings contains finding if {
	some dir in input.dirs_by_language["python"]
	pipfile := _dir_path(dir, "Pipfile")
	input.file_set[pipfile]
	not input.file_set[_dir_path(dir, "Pipfile.lock")]
	finding := {
		"rule_id": metadata.id,
		"message": "Pipfile has no Pipfile.lock; run pipenv lock to pin dependency versions",
		"artifact_uri": pipfile,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
	}
}

# _dir_path joins a detected dir with a filename to match the file_set key
# format (root files are stored bare; dirs_by_language uses "." for the root).
_dir_path(dir, name) := name if dir == "."

_dir_path(dir, name) := concat("/", [dir, name]) if dir != "."
