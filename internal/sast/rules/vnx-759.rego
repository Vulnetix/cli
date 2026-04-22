# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_759

import rego.v1

metadata := {
	"id": "VNX-759",
	"name": "CWE-759",
	"description": "Detects source patterns associated with CWE-759 (CWE-759). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-759/",
	"languages": ["java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [759],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["password-hash", "unsalted", "cwe-759"],
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
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "password")
	some _pat in {"hashlib.sha256(", "hashlib.md5(", "hashlib.sha1("}
	contains(line, _pat)
	not contains(line, "salt")
	finding := {
		"rule_id": metadata.id,
		"message": "Password hashed with unsalted digest — use bcrypt/scrypt/argon2 with per-password salt",
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "MessageDigest.getInstance(")
	some _pat in {"password"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Password hashed using MessageDigest without salt/KDF",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
