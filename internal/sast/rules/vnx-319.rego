# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_319

import rego.v1

metadata := {
	"id": "VNX-319",
	"name": "Cleartext Transmission of Sensitive Information",
	"description": "Detects embedded cleartext HTTP/FTP URLs that suggest credentials or data transmitted without encryption.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-319/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [319],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cleartext-transmission", "cwe-319"],
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
	some _pat in {"http://", "ftp://"}
	contains(line, _pat)
	not contains(line, "localhost")
	not contains(line, "127.0.0.1")
	not contains(line, "example.com")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cleartext URL %s — use HTTPS/SFTP", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
