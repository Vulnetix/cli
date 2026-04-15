package vulnetix.rules.vnx_crypto_006

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-006",
	"name": "Weak RSA key size",
	"description": "RSA key generation with fewer than 2048 bits is cryptographically weak. NIST recommends a minimum of 2048 bits; prefer 4096 bits for long-lived keys.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-CRYPTO-006",
	"languages": ["python", "go", "java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [326],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["weak-crypto", "rsa", "key-size"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(GenerateKey|generate_private_key|initialize|KeyPairGenerator)\s*\(\s*.*(512|768|1024)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "RSA key size below 2048 bits; use at least 2048-bit keys (4096 recommended)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
