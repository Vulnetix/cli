# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_256

import rego.v1

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
	"cwss": "",
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
	contains(line, "\"")
	some _pat in {"password = ", "PASSWORD =", "password:"}
	contains(line, _pat)
	not contains(line, "hash")
	not contains(line, "bcrypt")
	not contains(line, "argon")
	not contains(line, "scrypt")
	not contains(line, "encrypt")
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
