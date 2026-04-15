package vulnetix.rules.vnx_java_023

import rego.v1

metadata := {
	"id": "VNX-JAVA-023",
	"name": "Java unrestricted file upload — no content-type or extension validation",
	"description": "A MultipartFile upload handler stores the file using the original filename or does not validate the file's content type. Without allowlist validation of extensions and MIME types an attacker can upload server-side scripts (e.g. .jsp, .php) leading to remote code execution.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-023/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [434],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["file-upload", "cwe-434", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "getOriginalFilename()")
	regex.match(`transferTo|Files\.copy|FileOutputStream|Files\.write`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "File stored using getOriginalFilename() without extension or MIME-type validation; validate against an allowlist before saving to prevent remote code execution",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "getOriginalFilename()")
	not regex.match(`(?i)(allowedExtensions|allowlist|contentType|getContentType|tika|magic|extension\s*\.|endsWith)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "getOriginalFilename() used without apparent content-type or extension check; ensure uploaded file types are validated against an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
