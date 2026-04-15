package vulnetix.rules.vnx_ruby_005

import rego.v1

metadata := {
	"id": "VNX-RUBY-005",
	"name": "Ruby XSS via html_safe or raw",
	"description": "Using .html_safe or raw() on user-controlled strings in Rails views bypasses HTML escaping, enabling cross-site scripting (XSS) attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-005/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "warning",
	"kind": "open",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xss", "rails", "html-safe"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, ".html_safe")
	finding := {
		"rule_id": metadata.id,
		"message": "html_safe/raw bypasses HTML escaping; sanitize user input before marking as safe",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`<%=\s*raw\s`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "html_safe/raw bypasses HTML escaping; sanitize user input before marking as safe",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
