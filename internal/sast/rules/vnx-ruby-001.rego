package vulnetix.rules.vnx_ruby_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-001",
	"name": "Missing Gemfile.lock",
	"description": "A directory holds an application Gemfile but no committed Gemfile.lock beside it (or Bundler's alternative gems.rb without gems.locked), so every bundle install resolves the floating version ranges afresh and a newly published or compromised gem version enters the build unreviewed. Reported once per Gemfile, on its first line. Not reported: a gem library (a *.gemspec beside the Gemfile or a gemspec directive in it), whose consumers resolve its dependencies from their own lock; Gemfiles under test, spec or fixture directories; vendored gems under vendor/ or node_modules/.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-001/",
	"languages": ["ruby"],
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
	some dir in input.dirs_by_language.ruby
	gemfile := _dir_path(dir, "Gemfile")
	input.file_set[gemfile]
	not input.file_set[_dir_path(dir, "Gemfile.lock")]
	not helpers.is_test_path(gemfile)
	not regex.match(`(^|/)(vendor|node_modules)/`, gemfile)
	not _library(dir, gemfile)
	finding := {
		"rule_id": metadata.id,
		"message": "Gemfile has no committed Gemfile.lock; run bundle lock and commit the lock file so every install resolves the same gem versions",
		"artifact_uri": gemfile,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
	}
}

# Bundler's alternative names: gems.rb is locked by gems.locked. A directory
# holding only gems.rb is not in dirs_by_language, so walk the file set.
findings contains finding if {
	some f, _ in input.file_set
	endswith(f, "gems.rb")
	_base(f) == "gems.rb"
	dir := _parent(f)
	not input.file_set[_dir_path(dir, "gems.locked")]
	not input.file_set[_dir_path(dir, "Gemfile.lock")]
	not helpers.is_test_path(f)
	not regex.match(`(^|/)(vendor|node_modules)/`, f)
	not _library(dir, f)
	finding := {
		"rule_id": metadata.id,
		"message": "gems.rb has no committed gems.locked; run bundle lock and commit the lock file so every install resolves the same gem versions",
		"artifact_uri": f,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
	}
}

_base(f) := f if not contains(f, "/")

_base(f) := regex.replace(f, `^.*/`, "") if contains(f, "/")

# A gem library: its own lock does not reach the applications that depend on it.
_library(_, gemfile) if {
	content := input.file_contents[gemfile]
	regex.match(`(?m)^\s*gemspec\b`, content)
}

_library(dir, _) if {
	some f, _ in input.file_set
	endswith(f, ".gemspec")
	_parent(f) == dir
}

_parent(f) := "." if not contains(f, "/")

_parent(f) := regex.replace(f, `/[^/]*$`, "") if contains(f, "/")

# _dir_path joins a detected dir with a filename to match the file_set key
# format (root files are stored bare; dirs_by_language uses "." for the root).
_dir_path(dir, name) := name if dir == "."

_dir_path(dir, name) := concat("/", [dir, name]) if dir != "."
