# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_325

import rego.v1

metadata := {
	"id": "VNX-325",
	"name": "Missing Cryptographic Step",
	"description": "Detects source patterns associated with CWE-325 (Missing Cryptographic Step). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-325/",
	"languages": ["java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [325],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["missing-crypto-step", "cwe-325"],
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
	some _ext in {".py", ".java"}
	endswith(path, _ext)
	content := input.file_contents[path]
	not contains(content, "HMAC")
	not contains(content, "GCM")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"AES.new(", "Cipher.getInstance(\"AES\""}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "AES cipher without MAC/HMAC/AEAD — integrity step is missing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
