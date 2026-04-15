package vulnetix.rules.vnx_java_022

import rego.v1

metadata := {
	"id": "VNX-JAVA-022",
	"name": "Java insecure temporary file creation",
	"description": "File.createTempFile() without explicitly setting restrictive permissions, or constructing a predictable temp file path with new File(\"/tmp/\" + ...), can be exploited via race conditions (TOCTOU) or symlink attacks. Use Files.createTempFile() in a secure temporary directory and set POSIX permissions to owner-read/write only.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-022/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [377],
	"capec": ["CAPEC-29"],
	"attack_technique": ["T1036"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:H/AV:L/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["file", "tempfile", "race-condition", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "File.createTempFile(")
	finding := {
		"rule_id": metadata.id,
		"message": "File.createTempFile() creates a world-readable file by default; use Files.createTempFile() and set restrictive PosixFilePermissions (OWNER_READ | OWNER_WRITE) before writing sensitive data",
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
	regex.match(`new\s+File\s*\(\s*"/tmp/"\s*\+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Predictable temp file path constructed under /tmp/ with string concatenation; use Files.createTempFile() for a securely named file",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
