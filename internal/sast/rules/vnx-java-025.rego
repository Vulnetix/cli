package vulnetix.rules.vnx_java_025

import rego.v1

metadata := {
	"id": "VNX-JAVA-025",
	"name": "Java hardcoded password or credential in source code",
	"description": "A password, credential, or database connection string is hardcoded as a string literal assigned to a variable named password, passwd, pwd, credential, or similar. Hardcoded credentials can be extracted from source code or compiled binaries and are difficult to rotate without a code change.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-025/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [259],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["hardcoded-credentials", "secrets", "cwe-259", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)(password|passwd|pwd)\s*=\s*"[^"]{3,}"`, line)
	not contains(line, "getParameter")
	not contains(line, "getenv")
	not contains(line, "@Value")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Password or credential hardcoded as a string literal; use environment variables, a secrets manager, or Spring @Value with externalized configuration",
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
	regex.match(`DriverManager\.getConnection\s*\(.*"jdbc:.*",\s*"[^"]+",\s*"[^"]+"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Database credentials hardcoded in DriverManager.getConnection(); move username and password to environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
