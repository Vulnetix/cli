package vulnetix.rules.vnx_node_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-001",
	"name": "Missing npm lock file",
	"description": "A package.json that declares at least one dependency (dependencies, devDependencies or optionalDependencies) has no lock file (package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock or bun.lockb) in its own directory or in any ancestor directory. Without one, every install re-resolves floating ranges, so a compromised or confused release reaches CI unnoticed. Not reported: a workspace member covered by a lock file at the workspace root, a package.json with no dependencies, and package.json files under test, fixture, mock or example directories. A lock file excluded by .gitignore is treated as absent, because it is not committed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-001/",
	"languages": ["node"],
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

_lockfiles := [
	"package-lock.json",
	"npm-shrinkwrap.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"bun.lock",
	"bun.lockb",
]

findings contains finding if {
	some dir in input.dirs_by_language.node
	manifest := _dir_path(dir, "package.json")
	input.file_set[manifest]
	not helpers.is_test_path(manifest)
	not regex.match(`(^|/)(examples?|samples?|demos?)/`, manifest)
	_declares_dependencies(manifest)
	not _locked(dir)
	finding := {
		"rule_id": metadata.id,
		"message": "package.json declares dependencies but no lock file (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock) is committed here or at a workspace root; commit one and install with npm ci",
		"artifact_uri": manifest,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "package.json",
	}
}

# A manifest whose content was not loaded is judged by its presence alone.
_declares_dependencies(manifest) if not input.file_contents[manifest]

_declares_dependencies(manifest) if {
	content := input.file_contents[manifest]
	regex.match(`"(?:dependencies|devDependencies|optionalDependencies)"\s*:\s*\{\s*"`, content)
}

# A lock file in the directory itself or in any ancestor (workspace root).
_locked(dir) if {
	some anc in _ancestors(dir)
	some lf in _lockfiles
	input.file_set[_dir_path(anc, lf)]
}

_ancestors(dir) := ["."] if dir == "."

_ancestors(dir) := array.concat(["."], [concat("/", array.slice(parts, 0, k)) |
	some k in numbers.range(1, count(parts))
]) if {
	dir != "."
	parts := split(dir, "/")
}

# _dir_path joins a detected dir with a filename to match the file_set key
# format (root files are stored bare; dirs_by_language uses "." for the root).
_dir_path(dir, name) := name if dir == "."

_dir_path(dir, name) := concat("/", [dir, name]) if dir != "."
