# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_329

import rego.v1

metadata := {
	"id": "VNX-329",
	"name": "CWE-329",
	"description": "Detects source patterns associated with CWE-329 (CWE-329). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-329/",
	"languages": ["go", "java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [329],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "iv-reuse", "cwe-329"],
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
	some _ext in {".py", ".java", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"IV = b\"", "iv = b\"", "IvParameterSpec(\"", "iv := []byte("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Hard-coded or predictable IV/nonce — use cryptographically random value for each encryption",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
