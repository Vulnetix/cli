# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_347

import rego.v1

metadata := {
	"id": "VNX-347",
	"name": "Improper Verification of Cryptographic Signature",
	"description": "Detects source patterns associated with CWE-347 (Improper Verification of Cryptographic Signature). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-347/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [347],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["signature", "crypto", "cwe-347"],
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
	some _ext in {".py", ".java", ".js", ".ts", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"verify=False", "InsecureSkipVerify", "rejectUnauthorized: false", "VERIFY_NONE"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Signature/cert verification disabled via %s — enables MITM", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
