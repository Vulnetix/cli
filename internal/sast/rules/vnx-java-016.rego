package vulnetix.rules.vnx_java_016

import rego.v1

metadata := {
	"id": "VNX-JAVA-016",
	"name": "Java weak PRNG (java.util.Random) used for security-sensitive value",
	"description": "java.util.Random and Math.random() are not cryptographically secure. When used to generate tokens, session IDs, nonces, passwords, or keys they produce predictable values that an attacker can reproduce. Replace with java.security.SecureRandom.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-016/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [330],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "weak-random", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`new\s+(java\.util\.)?Random\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "java.util.Random is not cryptographically secure; replace with java.security.SecureRandom for tokens, session IDs, nonces, passwords, and keys",
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
	contains(line, "Math.random()")
	finding := {
		"rule_id": metadata.id,
		"message": "Math.random() is not cryptographically secure; replace with java.security.SecureRandom for security-sensitive random values",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
