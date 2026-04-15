package vulnetix.rules.vnx_kotlin_002

import rego.v1

metadata := {
	"id": "VNX-KOTLIN-002",
	"name": "Kotlin RSA key smaller than 2048 bits",
	"description": "An RSA KeyPairGenerator is initialised with fewer than 2048 bits. Keys smaller than 2048 bits (e.g. 512, 1024) can be factored with today's computing resources, compromising the confidentiality and authenticity of all data protected by the key pair.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-002/",
	"languages": ["kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [326],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "rsa", "key-size", "kotlin"],
}

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_kotlin(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, ".initialize(")
	regex.match(`\.initialize\s*\(\s*(512|768|1024)\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "RSA key initialized with fewer than 2048 bits; use at least 2048 bits (preferably 4096) per NIST SP 800-57 recommendations",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
