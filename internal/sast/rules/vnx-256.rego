# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_256

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-256",
	"name": "Plaintext Storage of a Password",
	"description": "Detects source patterns associated with CWE-256 (Plaintext Storage of a Password). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-256/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [256],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["password-storage", "plaintext", "cwe-256"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")
_skip(path) if endswith(path, ".min.html")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
_is_comment_line(line) if startswith(trim_space(line), "--")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".py", ".js", ".ts", ".java", ".go", ".php", ".rb"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	not helpers.is_test_path(path)
	m := regex.find_all_string_submatch_n(_literal_assign, line, 1)
	count(m) > 0
	value := m[0][1]
	count(value) > 0
	not regex.match(`(%|\$\{|\{\{|<|os\.environ|getenv|process\.env|hash|bcrypt|argon|scrypt|encrypt)`, lower(value))
	not regex.match(`(?i)(hash|bcrypt|argon|scrypt|encrypt)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Password appears stored as plaintext; hash with bcrypt/argon2/scrypt",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A name containing password, assigned a quoted literal. A format string that
# mentions "password = %q", an environment lookup and a YAML template that is
# built from a variable are not a stored password.
_literal_assign := `(?i)\b\w*password\w*["']?\s*(?::=|=|:)\s*["'\x60]([^"'\x60]*)["'\x60]`
