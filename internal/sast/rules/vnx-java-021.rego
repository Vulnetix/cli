package vulnetix.rules.vnx_java_021

import rego.v1

metadata := {
	"id": "VNX-JAVA-021",
	"name": "Java sensitive data logged (password, token, secret, key)",
	"description": "A call to a logger method (log.debug, log.info, log.warn, log.error, Logger.log) includes a variable or string that contains a password, token, secret, or key. Logging sensitive data exposes it in log files, monitoring systems, and SIEM tools.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-021/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "secrets",
	"cwe": [532],
	"capec": ["CAPEC-215"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["logging", "secrets", "cwe-532", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(log|logger|LOG|LOGGER)\s*\.\s*(debug|info|warn|error|trace|fatal)\s*\(`, line)
	regex.match(`(?i)(password|passwd|secret|token|apikey|api_key|authkey|auth_key|credential|private_?key)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Logger call includes a password, token, or secret; never log sensitive credentials — redact or omit them before logging",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
