package vulnetix.rules.vnx_java_020

import rego.v1

metadata := {
	"id": "VNX-JAVA-020",
	"name": "Java static IV reuse in block cipher",
	"description": "A static, hardcoded byte array is used as the initialization vector (IV) for a block cipher via IvParameterSpec. Reusing the same IV with the same key leaks information about plaintext and breaks the semantic security of CBC, CTR, and GCM modes.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-020/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [329],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "iv", "cbc", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`new\s+IvParameterSpec\s*\(.*"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "IvParameterSpec constructed from a string literal; generate a fresh random IV with SecureRandom for each encryption operation",
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
	regex.match(`(static|final)\s.*\bIV\b.*=\s*\{`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Static or final IV byte array detected; IVs must be unique per encryption — generate with new SecureRandom().nextBytes(iv)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
