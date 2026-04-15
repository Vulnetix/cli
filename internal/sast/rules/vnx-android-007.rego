package vulnetix.rules.vnx_android_007

import rego.v1

metadata := {
	"id": "VNX-ANDROID-007",
	"name": "Android weak cryptography using AES in ECB mode",
	"description": "AES is initialised with ECB mode (Cipher.getInstance(\"AES/ECB/...\") or just \"AES\"). ECB mode is deterministic and does not provide semantic security: identical plaintext blocks produce identical ciphertext blocks, leaking patterns in the encrypted data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-007/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["android", "weak-crypto", "aes-ecb", "mobile-security"],
}

_is_java(path) if endswith(path, ".java")
_is_java(path) if endswith(path, ".kt")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "Cipher.getInstance")
	regex.match(`Cipher\.getInstance\s*\(\s*"(AES|AES/ECB)[^"]*"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "AES cipher initialised in ECB mode; use AES/GCM/NoPadding or AES/CBC/PKCS5Padding with a random IV to provide semantic security",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
