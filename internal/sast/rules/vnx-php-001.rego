package vulnetix.rules.vnx_php_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-001",
	"name": "Missing composer.lock",
	"description": "An application's composer.json that requires at least one Composer package (in require or require-dev, other than php itself and ext-*/lib-* platform packages) has no composer.lock committed in the same directory. Without the lock file, every composer install re-resolves the version ranges, so a compromised or broken release reaches the build unnoticed. An application is a manifest with \"type\": \"project\", or one with no \"name\" (it cannot be published as a package). Not reported: libraries and other published package types (Composer's own guidance leaves their lock file optional, and a missing type means library), a manifest that requires only platform packages, manifests under vendor/, test, fixture, example or demo directories, and a project whose composer.lock is present. A lock file excluded by .gitignore is treated as absent, because it is not committed. The rule declares the generic marker beside php because composer.json is JSON, which the engine otherwise hides from PHP rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-001/",
	"languages": ["php", "generic"],
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
	some dir in input.dirs_by_language.php
	manifest := _dir_path(dir, "composer.json")
	content := input.file_contents[manifest]
	not input.file_set[_dir_path(dir, "composer.lock")]
	not helpers.is_test_path(manifest)
	not regex.match(`(^|/)(vendor|examples?|samples?|demos?)/`, manifest)
	_is_application(content)
	_requires_packages(content)
	finding := {
		"rule_id": metadata.id,
		"message": "composer.json requires packages but no composer.lock is committed beside it; run composer update once, commit composer.lock and install with composer install",
		"artifact_uri": manifest,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "composer.json",
	}
}

_is_application(content) if regex.match(`"type"\s*:\s*"project"`, content)

_is_application(content) if not regex.match(`"name"\s*:\s*"[^"]+/[^"]+"`, content)

# A "require"/"require-dev" object naming a vendor/package dependency. Platform
# packages (php, ext-json, lib-curl) have no slash and are not installed.
_requires_packages(content) if {
	some block in regex.find_n(`"require(?:-dev)?"\s*:\s*\{[^}]*\}`, content, -1)
	regex.match(`"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"\s*:`, block)
}

# _dir_path joins a detected dir with a filename to match the file_set key
# format (root files are stored bare; dirs_by_language uses "." for the root).
_dir_path(dir, name) := name if dir == "."

_dir_path(dir, name) := concat("/", [dir, name]) if dir != "."
