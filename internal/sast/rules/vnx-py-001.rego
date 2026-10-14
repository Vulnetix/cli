package vulnetix.rules.vnx_py_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-001",
	"name": "Missing Python lock file",
	"description": "A Python project that has chosen a locking dependency manager has no lock file, so every install re-resolves its version ranges and can pull a different (or a hijacked) release. Reported: a Pipfile with no Pipfile.lock beside it (the [packages] header, or line 1), and a pyproject.toml managed by Poetry ([tool.poetry]), PDM ([tool.pdm]) or uv ([tool.uv]) that declares at least one dependency other than python, with no uv.lock, poetry.lock, pdm.lock, Pipfile.lock or pylock.toml in its directory (a uv.lock in an enclosing directory counts, which is how a uv workspace member is locked). Not reported: a pyproject.toml with no locking tool configured (a setuptools, flit or hatch library publishes ranges by design and is not expected to commit a lock), a project with no dependencies, requirements.txt files (whether they are pinned is not judged here), and test fixtures.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-001/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["supply-chain", "lockfile", "integrity"],
}

_lock_names := ["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"]

_dir_of(path) := d if {
	parts := split(path, "/")
	count(parts) > 1
	d := concat("/", array.slice(parts, 0, count(parts) - 1))
}

_dir_of(path) := "." if not contains(path, "/")

_base(path) := b if {
	parts := split(path, "/")
	b := parts[count(parts) - 1]
}

_join(".", name) := name

_join(dir, name) := concat("/", [dir, name]) if dir != "."

_locked_here(dir) if {
	some name in _lock_names
	input.file_set[_join(dir, name)]
}

# A lock of the PEP 751 form pylock.<name>.toml.
_locked_here(dir) if {
	some f, _ in input.file_set
	_dir_of(f) == dir
	regex.match(`^pylock\.[^/]+\.toml$`, _base(f))
}

# A uv workspace root locks every member below it.
_locked_above(dir) if {
	dir != "."
	parts := split(dir, "/")
	some n in numbers.range(0, count(parts) - 1)
	anc := _ancestor(parts, n)
	input.file_set[_join(anc, "uv.lock")]
}

_ancestor(_, 0) := "."

_ancestor(parts, n) := concat("/", array.slice(parts, 0, n)) if n > 0

_tool_header := `^\s*\[\[?tool\.(?:poetry|uv|pdm)(?:\.[\w.-]+)?\]\]?\s*(#.*)?$`

# pdm-backend is also a plain build backend; only the sections the PDM
# dependency manager reads say the project resolves with PDM.
_not_pdm_build(line) if not regex.match(`\[tool\.pdm\.(build|version)\b`, line)

# At least one dependency besides the interpreter constraint.
_has_dependencies(content) if regex.match(`(?m)^\s*dependencies\s*=\s*\[\s*(#[^\n]*\s*)*["']`, content)

# A key other than python in a [tool.poetry...dependencies] table.
_has_dependencies(content) if {
	contains(content, "dependencies]")
	keys := regex.find_all_string_submatch_n(`(?m)^\[tool\.poetry(?:\.group\.[\w-]+)?\.dependencies\]\s*\n((?:[ \t]*(?:#[^\n]*|["']?[\w.-]+["']?\s*=[^\n]*)?\n?)*)`, content, -1)
	some m in keys
	some kv in regex.find_all_string_submatch_n(`(?m)^[ \t]*["']?([\w.-]+)["']?\s*=`, m[1], -1)
	kv[1] != "python"
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, "pyproject.toml")
	_base(path) == "pyproject.toml"
	contains(content, "[tool.")
	regex.match(`(?m)^\s*\[\[?tool\.(?:poetry|uv|pdm)[\].]`, content)
	not helpers.is_test_path(path)
	_has_dependencies(content)
	dir := _dir_of(path)
	not _locked_here(dir)
	not _locked_above(dir)
	lines := split(content, "\n")
	idx := [i | some i, l in lines; regex.match(_tool_header, l); _not_pdm_build(l)]
	count(idx) > 0
	i := idx[0]
	finding := {
		"rule_id": metadata.id,
		"message": "pyproject.toml is managed by a locking tool but has no lock file (uv.lock, poetry.lock or pdm.lock); commit one to pin dependency versions",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, "Pipfile")
	_base(path) == "Pipfile"
	not helpers.is_test_path(path)
	dir := _dir_of(path)
	not input.file_set[_join(dir, "Pipfile.lock")]
	lines := split(content, "\n")
	i := _pipfile_line(lines)
	finding := {
		"rule_id": metadata.id,
		"message": "Pipfile has no Pipfile.lock; run pipenv lock and commit it to pin dependency versions",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

_pipfile_line(lines) := idx[0] if {
	idx := [i | some i, l in lines; regex.match(`^\s*\[packages\]`, l)]
	count(idx) > 0
}

_pipfile_line(lines) := 0 if {
	not regex.match(`(?m)^\s*\[packages\]`, concat("\n", lines))
}
