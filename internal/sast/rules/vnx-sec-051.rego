package vulnetix.rules.vnx_sec_051

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-051",
	"name": "RubyGems API token",
	"description": "Reports a RubyGems.org API key: rubygems_ followed by exactly 48 lower-case hex characters as a whole token, in any file (~/.gem/credentials, GEM_HOST_API_KEY in a workflow, Rakefile or shell script). The key can push and yank gems, so a leak is a supply-chain compromise of every gem the owner publishes. Not reported: the bare prefix, shorter or longer hex runs (an identifier such as rubygems_<64 hex>_label), placeholder bodies, CI secret references (${{ secrets.X }}), and test, fixture or vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-051/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "rubygems", "supply-chain", "credentials"],
}

_pattern := `(?:^|[^A-Za-z0-9_])(rubygems_[a-f0-9]{48})(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "rubygems_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "rubygems_")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(substring(token, 9, -1))
	secrets.high_entropy(substring(token, 9, -1), 3)
	finding := {
		"rule_id": metadata.id,
		"message": "RubyGems API key found; revoke it at rubygems.org/profile/api_keys, check the account's recent pushes, and use trusted publishing or a CI secret instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
