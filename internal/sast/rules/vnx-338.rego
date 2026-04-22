# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_338

import rego.v1

metadata := {
	"id": "VNX-338",
	"name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
	"description": "Detects source patterns associated with CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-338/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["prng", "security", "cwe-338"],
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
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "token")
	some _pat in {"math/rand"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "math/rand used for cryptographic token — use crypto/rand",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
