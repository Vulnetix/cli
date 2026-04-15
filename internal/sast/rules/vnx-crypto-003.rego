package vulnetix.rules.vnx_crypto_003

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-003",
	"name": "AES in ECB mode",
	"description": "AES in ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking patterns. Use CBC, CTR, or GCM mode instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-003/",
	"languages": ["python", "node", "go", "java", "ruby", "php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["weak-crypto", "ecb", "aes", "block-cipher"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_ecb_indicators := {
	"AES/ECB",
	"AES.MODE_ECB",
	"MODE_ECB",
	"AESMode.ecb",
	"aes-128-ecb",
	"aes-256-ecb",
	"aes-192-ecb",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ecb_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AES ECB mode detected (%s); use GCM, CBC with HMAC, or CTR mode instead", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
