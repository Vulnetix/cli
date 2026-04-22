# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_335

import rego.v1

metadata := {
	"id": "VNX-335",
	"name": "Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)",
	"description": "Detects source patterns associated with CWE-335 (Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-335/",
	"languages": ["java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [335],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["prng", "seed", "cwe-335"],
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
	contains(line, "random.seed(")
	not contains(line, "secrets")
	finding := {
		"rule_id": metadata.id,
		"message": "random.seed used in security context — use secrets module for cryptographic randomness",
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
	contains(line, "new Random(")
	some _pat in {"token", "password", "session"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "java.util.Random used for security value — use SecureRandom",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
