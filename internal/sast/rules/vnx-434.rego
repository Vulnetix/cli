# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_434

import rego.v1

metadata := {
	"id": "VNX-434",
	"name": "Unrestricted file upload",
	"description": "Accepting file uploads without validating the file type, extension, or MIME type allows attackers to upload and execute malicious code (web shells), leading to remote code execution.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-434/",
	"languages": ["python", "java", "php", "ruby", "node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [434],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1505.003"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["file-upload", "rce", "web-shell"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"$_FILES[",
	"move_uploaded_file(",
	"request.FILES",
	"request.files",
	"MultipartFile",
	"getOriginalFilename()",
	"multer()",
	"multer({",
	"req.files",
	"permit(:avatar)",
	"permit(:file)",
	"permit(:attachment)",
	"attach_file",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("File upload pattern '%v' detected — ensure file type, extension, and MIME type are validated before saving", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
