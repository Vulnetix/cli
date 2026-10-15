package vulnetix.rules.vnx_sec_028

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-028",
	"name": "npm access token hardcoded",
	"description": "Reports an npm access token: npm_ followed by exactly 36 letters or digits, delimited on both sides, in any file (.npmrc, .yarnrc.yml, workflows, Dockerfiles, scripts), and a legacy UUID token written literally as _authToken or npmAuthToken in .npmrc, .yarnrc or .yarnrc.yml, or as a registry-scoped //host/:_authToken=<uuid> in any file (a Dockerfile or script echoing it into .npmrc). ${NPM_TOKEN}-style references, npm_config_*/npm_package_* environment names and other identifiers, placeholders and low-entropy values, and test and fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-028/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secret", "npm", "registry", "credentials"],
}

_token_re := `(?:^|[^A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?:[^A-Za-z0-9_]|$)`

_legacy_re := `(?i)(?:_authToken|npmAuthToken)["']?\s*[=:\s]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:["'\s]|$)`

_identifier(body) if regex.match(`^(?:[A-Z]?[a-z]+)+$`, body)

_npm_config(path) if endswith(path, ".npmrc")

_npm_config(path) if endswith(path, ".yarnrc.yml")

_npm_config(path) if endswith(path, ".yarnrc")

# A registry-scoped legacy token written into .npmrc from a Dockerfile or
# script: //registry.example/:_authToken=<uuid>.
_scoped_legacy_re := `//[^\s"'=]+:_authToken\s*=\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:["'\s]|$)`

_candidate(path, content) if contains(content, "npm_")

_candidate(path, content) if contains(content, ":_authToken")

_candidate(path, content) if {
	_npm_config(path)
	regex.match(`(?i)(_authToken|npmAuthToken)`, content)
}

_hit(path, line) if {
	contains(line, "npm_")
	m := regex.find_all_string_submatch_n(_token_re, line, -1)
	some hit in m
	token := hit[1]
	body := substring(token, 4, -1)
	not _identifier(body)
	not secrets.is_example_token(token)
	secrets.high_entropy(body, 4.0)
}

_hit(path, line) if {
	_npm_config(path)
	m := regex.find_all_string_submatch_n(_legacy_re, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.0)
}

_hit(path, line) if {
	contains(line, ":_authToken")
	m := regex.find_all_string_submatch_n(_scoped_legacy_re, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.0)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	_candidate(path, content)
	lines := split(content, "\n")
	some i, line in lines
	_hit(path, line)
	finding := {
		"rule_id": metadata.id,
		"message": "npm access token detected; revoke at npmjs.com/settings and store in CI secrets or environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
