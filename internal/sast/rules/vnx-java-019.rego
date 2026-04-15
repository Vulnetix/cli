package vulnetix.rules.vnx_java_019

import rego.v1

metadata := {
	"id": "VNX-JAVA-019",
	"name": "Java hardcoded cryptographic key literal",
	"description": "A cryptographic key, secret, or IV is hardcoded as a string or byte literal and passed directly to SecretKeySpec, IvParameterSpec, or similar constructors. Hardcoded keys are embedded in source code and any binary, allowing any reader to decrypt protected data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-019/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [321],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "hardcoded-key", "secrets", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`new\s+SecretKeySpec\s*\(.*"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SecretKeySpec constructed from a string literal; load cryptographic keys from a key store or secrets manager, never hardcode them",
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
	regex.match(`(SECRET_KEY|ENCRYPTION_KEY|CRYPTO_KEY|AES_KEY|HMAC_KEY)\s*=\s*"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Cryptographic key assigned from a string literal constant; load keys from environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
