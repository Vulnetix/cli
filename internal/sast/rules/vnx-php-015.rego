package vulnetix.rules.vnx_php_015

import rego.v1

metadata := {
	"id": "VNX-PHP-015",
	"name": "PHP unrestricted file upload via move_uploaded_file",
	"description": "move_uploaded_file() is used without sufficient validation context. File uploads are a common attack vector enabling webshell upload and remote code execution if MIME type, file extension, content inspection, and upload destination are not all validated server-side. Ensure: (1) MIME type validated server-side, (2) file extension whitelisted, (3) file content inspected, (4) upload destination outside web root, (5) filename randomized.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-015/",
	"languages": ["php"],
	"severity": "high",
	"level": "warning",
	"kind": "sast",
	"cwe": [434],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["file-upload", "rce", "php"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`move_uploaded_file\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "File upload detected: verify MIME type is validated server-side, file extension is whitelisted, content is inspected, destination is outside web root, and filename is randomized to prevent webshell upload",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
