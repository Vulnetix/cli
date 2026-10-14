package vulnetix.rules.vnx_rust_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-001",
	"name": "Missing Cargo.lock",
	"description": "A Cargo.toml that declares at least one dependency ([dependencies], [dev-dependencies], [build-dependencies], [workspace.dependencies], a [target.*.dependencies] table or a [dependencies.<name>] table with an entry) has no Cargo.lock in its own directory or in any ancestor directory. Without a committed lock file every build re-resolves the version requirements against the registry, so a compromised or yanked-and-replaced release reaches the build unnoticed and cargo audit has nothing stable to check. Not reported: a workspace member covered by the Cargo.lock at the workspace root, a manifest whose dependency tables are empty, and manifests under test, fixture, mock or example directories. A Cargo.lock excluded by .gitignore is treated as absent, because it is not committed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-001/",
	"languages": ["rust"],
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

findings contains finding if {
	some dir in input.dirs_by_language.rust
	manifest := _dir_path(dir, "Cargo.toml")
	input.file_set[manifest]
	not helpers.is_test_path(manifest)
	not regex.match(`(^|/)(examples?|samples?|demos?|benches)/`, manifest)
	_declares_dependencies(manifest)
	not _locked(dir)
	finding := {
		"rule_id": metadata.id,
		"message": "Cargo.toml declares dependencies but no Cargo.lock is committed here or at a workspace root; run cargo generate-lockfile, commit it, and build with --locked",
		"artifact_uri": manifest,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "Cargo.toml",
	}
}

# A dependency table header followed (after blank or comment lines) by an entry.
_dep_table_re := `(?m)^\s*\[(?:[^\]\n]*\.)?(?:dev-|build-)?dependencies\]\s*\n(?:\s*(?:#[^\n]*)?\n)*\s*["A-Za-z0-9_-]+\s*=`

# The one-table-per-dependency form: [dependencies.serde].
_dep_named_table_re := `(?m)^\s*\[(?:[^\]\n]*\.)?(?:dev-|build-)?dependencies\.[^\]\n]+\]`

# A manifest whose content was not loaded is judged by its presence alone.
_declares_dependencies(manifest) if not input.file_contents[manifest]

_declares_dependencies(manifest) if regex.match(_dep_table_re, input.file_contents[manifest])

_declares_dependencies(manifest) if regex.match(_dep_named_table_re, input.file_contents[manifest])

# A Cargo.lock in the directory itself or in any ancestor (workspace root).
_locked(dir) if {
	some anc in _ancestors(dir)
	input.file_set[_dir_path(anc, "Cargo.lock")]
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
