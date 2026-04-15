package vulnetix.rules.vnx_java_018

import rego.v1

metadata := {
	"id": "VNX-JAVA-018",
	"name": "Java RSA cipher without OAEP padding",
	"description": "RSA encryption using PKCS#1 v1.5 padding (RSA/ECB/PKCS1Padding or RSA/NONE/NoPadding) is vulnerable to padding oracle attacks (Bleichenbacher PKCS#1 attacks). Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-018/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [780],
	"capec": ["CAPEC-463"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "rsa", "padding", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Cipher\.getInstance\s*\(`, line)
	regex.match(`RSA.*PKCS1Padding|RSA.*NoPadding|RSA/ECB/PKCS1`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "RSA cipher uses PKCS#1 v1.5 or no padding; use RSA/ECB/OAEPWithSHA-256AndMGF1Padding to prevent padding oracle attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
