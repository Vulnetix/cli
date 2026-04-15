package vulnetix.rules.vnx_php_019

import rego.v1

metadata := {
	"id": "VNX-PHP-019",
	"name": "PHP insecure cipher mode (AES-CBC)",
	"description": "openssl_encrypt() or openssl_decrypt() is called with an AES-CBC cipher mode. CBC mode is unauthenticated and prone to padding oracle attacks and bit-flipping. Prefer authenticated encryption modes such as AES-256-GCM or ChaCha20-Poly1305 that provide both confidentiality and integrity.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-019/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["weak-crypto", "cipher", "php"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`openssl_(encrypt|decrypt)\s*\(`, line)
	regex.match(`(?i)aes-(128|192|256)-cbc`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Insecure cipher mode: AES-CBC is unauthenticated and vulnerable to padding oracle attacks — use AES-256-GCM or ChaCha20-Poly1305 instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`["'](?i)aes-(128|192|256)-cbc["']`, line)
	not regex.match(`openssl_(encrypt|decrypt)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Insecure cipher mode: AES-CBC is unauthenticated and vulnerable to padding oracle attacks — use AES-256-GCM or ChaCha20-Poly1305 instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
