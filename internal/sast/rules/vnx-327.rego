# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_327

import rego.v1

metadata := {
	"id": "VNX-327",
	"name": "CWE-327",
	"description": "Detects source patterns associated with CWE-327 (CWE-327). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-327/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "weak-algorithm", "cwe-327"],
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
	some _ext in {".py", ".java", ".js", ".ts", ".go", ".php", ".rb"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"MD5", "SHA1", "sha1(", "md5(", "MessageDigest.getInstance(\"MD5\")", "MessageDigest.getInstance(\"SHA-1\")"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Broken hash/algorithm %s in use — migrate to SHA-256 or stronger", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
