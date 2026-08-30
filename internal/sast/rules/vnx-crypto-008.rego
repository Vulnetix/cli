package vulnetix.rules.vnx_crypto_008

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-008",
	"name": "Timing attack via direct comparison of secrets",
	"description": "HMAC, hash, token, digest, or signature values are compared using standard equality operators (==, ===). These are vulnerable to timing attacks where an attacker can infer the correct value by measuring response time differences.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-008/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [208],
	"capec": ["CAPEC-462"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["crypto", "timing-attack", "hmac"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(hmac|hash|digest|signature|token)\s*==\s*`, line)
	not contains(line, "hmac.compare_digest")
	not contains(line, "timingSafeEqual")
	not contains(line, "#")
	finding := {
		"rule_id": metadata.id,
		"message": "Direct == comparison of HMAC/hash/token/digest is vulnerable to timing attacks; use hmac.compare_digest() (Python) or crypto.timingSafeEqual() (Node.js) for constant-time comparison",
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(hmac|hash|digest|signature|token)\s*===\s*`, line)
	not contains(line, "timingSafeEqual")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Direct === comparison of HMAC/hash/token/digest is vulnerable to timing attacks; use crypto.timingSafeEqual() for constant-time comparison in Node.js",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
