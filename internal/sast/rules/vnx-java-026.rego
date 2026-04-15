package vulnetix.rules.vnx_java_026

import rego.v1

metadata := {
	"id": "VNX-JAVA-026",
	"name": "Java Spring/servlet file serving without access control",
	"description": "A Spring @GetMapping or servlet handler returns a FileSystemResource, InputStreamResource, or raw byte stream from a user-supplied path without verifying that the requesting user is authorised to access that file. This exposes arbitrary files to any authenticated or unauthenticated user.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-026/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [552],
	"capec": ["CAPEC-87"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["access-control", "file-exposure", "spring", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`new\s+FileSystemResource\s*\(`, line)
	regex.match(`getParameter|PathVariable|RequestParam`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "FileSystemResource constructed from user-supplied path without access control check; verify the requesting user is authorised to access the file before returning it",
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
	contains(line, "new InputStreamResource(")
	regex.match(`getParameter|PathVariable|RequestParam`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "InputStreamResource returned for a user-specified resource without authorisation check; restrict file access to authorised users only",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
