package vulnetix.rules.vnx_ruby_006

import rego.v1

metadata := {
	"id": "VNX-RUBY-006",
	"name": "Ruby mass assignment",
	"description": "Passing unfiltered params directly to ActiveRecord create, update, or new enables mass assignment attacks, allowing attackers to modify protected attributes like admin flags or roles.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-006/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-17"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["mass-assignment", "activerecord", "authorization"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_mass_assign_indicators := {
	".create(params)",
	".create(params[",
	".new(params)",
	".new(params[",
	".update(params)",
	".update(params[",
	".update_attributes(params)",
	".update_attributes(params[",
	".assign_attributes(params)",
	".assign_attributes(params[",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _mass_assign_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "Unfiltered params passed to ActiveRecord method; use strong parameters (params.require().permit()) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
