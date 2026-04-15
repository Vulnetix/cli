package vulnetix.rules.vnx_java_014

import rego.v1

metadata := {
	"id": "VNX-JAVA-014",
	"name": "Java zip/tar slip via ZipEntry getName()",
	"description": "ZipEntry.getName() is passed to new File() or Paths.get() without validating for path traversal sequences. An attacker can craft a zip archive with entries like '../../etc/cron.d/backdoor' to write files outside the intended directory.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-014/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [22],
	"capec": ["CAPEC-139"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["path-traversal", "zip-slip", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(new File|Paths\.get)\s*\(.*getName\s*\(\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "ZipEntry.getName() used in file path without traversal check; validate that the resolved path starts with the target directory to prevent zip slip",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
