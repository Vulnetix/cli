package vulnetix.rules.vnx_kotlin_001

import rego.v1

metadata := {
	"id": "VNX-KOTLIN-001",
	"name": "Kotlin ECB cipher mode — deterministic, unauthenticated encryption",
	"description": "A Cipher is obtained with AES/ECB or another mode that includes ECB. ECB mode encrypts each block independently, producing identical ciphertext for identical plaintext blocks. This reveals data patterns and provides no integrity protection.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-001/",
	"languages": ["kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [327],
	"capec": ["CAPEC-463"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "ecb", "kotlin"],
}

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_kotlin(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Cipher\.getInstance\s*\(`, line)
	regex.match(`(?i)ECB`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Cipher.getInstance() uses ECB mode; ECB is deterministic and leaks plaintext patterns — use AES/GCM/NoPadding (authenticated) or AES/CBC/PKCS7Padding with a random IV",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
