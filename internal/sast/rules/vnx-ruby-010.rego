package vulnetix.rules.vnx_ruby_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-010",
	"name": "OpenSSL certificate verification disabled (VERIFY_NONE)",
	"description": "Reports Ruby code that turns TLS certificate verification off with OpenSSL::SSL::VERIFY_NONE (qualified, or bare after include OpenSSL::SSL): assigned to verify_mode (Net::HTTP, OpenSSL::SSL::SSLContext, HTTPClient ssl_config), passed as a verify_mode:/:verify_mode =>/verify_ssl: option (Net::HTTP.start, set_params, Faraday ssl:, RestClient), chosen by a ternary, or assigned over OpenSSL::SSL::VERIFY_PEER; and verify_mode set to the literal 0. A connection made this way accepts any certificate, so a man-in-the-middle can read and alter the traffic. Not reported: VERIFY_PEER, a comparison against VERIFY_NONE (==, !=, defined?), an option table that maps a \"none\"/:none key to the constant, comments and string literals, and test and spec files. Options that disable verification without the constant (Faraday ssl: { verify: false }, HTTParty verify: false) are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-010/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ssl", "tls", "certificate", "mitm", "ruby"],
}

# Empties string literals so a constant named in a message is not code.
_strip(line) := regex.replace(line, `'[^']*'|"[^"]*"`, `""`)

_const := `(?:(?:::)?OpenSSL::SSL::)?VERIFY_NONE\b`

# A use of the constant that only inspects it.
_inspects(code) if regex.match(concat("", [`(?:==|!=|===)\s*`, _const]), code)

_inspects(code) if regex.match(`\bVERIFY_NONE\s*(?:==|!=|===)`, code)

_inspects(code) if regex.match(concat("", [`defined\?\s*\(?\s*`, _const]), code)

# A lookup table offering "none" as a configurable mode: `"none" => VERIFY_NONE`.
_mode_table(line) if regex.match(concat("", [`(?i)(?:["']none["']\s*=>|:none\s*=>|\bnone:)\s*`, _const]), line)

_disables(line, code) if {
	regex.match(`\bVERIFY_NONE\b`, code)
	not _inspects(code)
	not _mode_table(line)
}

_disables(_, code) if regex.match(`\bverify_mode\s*(?:=|:|=>)\s*0\b`, code)

# Ruby source: .rb, Rake tasks, Rack config, gemspecs, Rakefile and Gemfile.
_ruby_path(path) if regex.match(`(?:\.(?:rb|rake|ru|gemspec)|(?:^|/)(?:Rakefile|Gemfile))$`, path)

findings contains finding if {
	some path, content in input.file_contents
	_ruby_path(path)
	regex.match(`VERIFY_NONE|verify_mode\s*(?:=|:|=>)\s*0\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`VERIFY_NONE|verify_mode`, line)
	not helpers.is_comment_line(line)
	_disables(line, _strip(line))
	finding := {
		"rule_id": metadata.id,
		"message": "TLS certificate verification is disabled (OpenSSL::SSL::VERIFY_NONE), so any certificate is accepted and a man-in-the-middle can intercept the connection; use OpenSSL::SSL::VERIFY_PEER and supply the CA with ca_file/cert_store",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
