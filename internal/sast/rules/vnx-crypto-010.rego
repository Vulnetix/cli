package vulnetix.rules.vnx_crypto_010

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-010",
	"name": "Hardcoded IV, nonce, or salt in cryptographic operation",
	"description": "A static or hardcoded IV (initialization vector), nonce, or salt is used with a symmetric cipher, AEAD scheme, or KDF. Reusing the same IV/nonce with the same key completely breaks confidentiality for stream ciphers (CTR, GCM) and can reduce security for block ciphers. IVs and nonces must be randomly generated per encryption operation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-010/",
	"languages": ["python", "javascript", "typescript", "go", "java", "c", "cpp", "rust"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [329, 330, 760],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "iv", "nonce", "salt", "hardcoded"],
}

_skip(path) if endswith(path, ".lock")

_skip(path) if endswith(path, ".sum")

_skip(path) if endswith(path, ".min.js")

# Hardcoded IV/nonce byte array assignment, e.g. iv = b'\x00\x00...' or iv = [0,0,0...]
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)\b(iv|nonce|initialization_vector|init_vector)\s*[=:]\s*(b["']|bytes|\\x00|new byte|&\[|vec!\[|\[0[ux]?\b)`, line)
	not regex.match(`^\s*(#|//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded IV/nonce detected; generate a fresh random IV/nonce for every encryption operation using a CSPRNG (e.g., os.urandom(), crypto.randomBytes(), rand::random())",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Zero-filled IV pattern: iv = b'\x00' * 16, bytes.fromhex("000000000000"), [0]*16
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)\b(iv|nonce|salt)\b.*(\\x00.*\*\s*\d+|b["']\\x00|"0{8,}"|'0{8,}'|\[0\]\s*\*\s*\d+|bytes\.fromhex\(["']0+["']\))`, line)
	not regex.match(`^\s*(#|//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Zero-filled or all-zero IV/nonce/salt detected; use a cryptographically random value for each operation - a static zero IV provides no security",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
