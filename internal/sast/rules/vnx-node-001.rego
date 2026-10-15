package vulnetix.rules.vnx_node_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-001",
	"name": "Missing npm lock file",
	"description": "A package.json that declares at least one dependency (dependencies, devDependencies or optionalDependencies) has no lock file (package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock, bun.lockb or deno.lock) in its own directory or in an ancestor directory that is a workspace root (package.json \"workspaces\", pnpm-workspace.yaml or lerna.json), and is not inside a Rush monorepo (rush.json) whose lock file lives under common/config/rush. Without one, every install re-resolves floating ranges, so a compromised or confused release reaches CI unnoticed. Reported: a nested tool or service package under a root lock file that is not a workspace root, because that lock file does not cover it. Not reported: a workspace member covered by a lock file at the workspace root, a package.json with no dependencies, and package.json files under test, fixture, mock or example directories. A lock file excluded by .gitignore is treated as absent, because it is not committed.",
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
	"deno.lock",
]

# A Rush monorepo keeps its one lock file under common/config/rush.
_locked(dir) if {
	some anc in _ancestors(dir)
	input.file_set[_dir_path(anc, "rush.json")]
	some lf in ["pnpm-lock.yaml", "npm-shrinkwrap.json", "yarn.lock"]
	input.file_set[_dir_path(anc, concat("/", ["common/config/rush", lf]))]
}

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

# A lock file in the directory itself.
_locked(dir) if {
	some lf in _lockfiles
	input.file_set[_dir_path(dir, lf)]
}

# A lock file in an ancestor covers this manifest only when that ancestor is a
# workspace root (package.json "workspaces", pnpm-workspace.yaml or lerna.json):
# a root lock file of an unrelated package does not lock a nested tool.
_locked(dir) if {
	some anc in _ancestors(dir)
	anc != dir
	some lf in _lockfiles
	input.file_set[_dir_path(anc, lf)]
	_workspace_root(anc)
}

_workspace_root(anc) if input.file_set[_dir_path(anc, "pnpm-workspace.yaml")]

_workspace_root(anc) if input.file_set[_dir_path(anc, "lerna.json")]

_workspace_root(anc) if contains(input.file_contents[_dir_path(anc, "package.json")], `"workspaces"`)

# No package.json beside the lock file, or one whose content was not loaded:
# nothing says it is not a workspace root, so the lock file is credited.
_workspace_root(anc) if not input.file_contents[_dir_path(anc, "package.json")]

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
