# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_757

import rego.v1

metadata := {
	"id": "VNX-757",
	"name": "CWE-757",
	"description": "Detects source patterns associated with CWE-757 (CWE-757). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-757/",
	"languages": ["go", "java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [757],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "downgrade", "cwe-757"],
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
	some _pat in {"SSLv2", "SSLv3", "TLSv1", "TLSv1_0", "TLSv1_1", "TLS_RSA_"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Obsolete TLS/cipher %s — enforce TLS 1.2+ with modern ciphersuites", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
