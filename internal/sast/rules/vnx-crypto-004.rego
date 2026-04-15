package vulnetix.rules.vnx_crypto_004

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-004",
	"name": "Broken or obsolete cipher",
	"description": "DES, 3DES, RC4, and Blowfish are cryptographically broken or deprecated. Use AES-256-GCM or ChaCha20-Poly1305 instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-004/",
	"languages": ["python", "node", "go", "java", "ruby", "php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["weak-crypto", "des", "rc4", "blowfish", "cipher"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_weak_cipher_indicators := {
	"DES/CBC",
	"DES/ECB",
	"DESede",
	"3DES",
	"TripleDES",
	"RC4",
	"ARCFOUR",
	"Blowfish",
	"from Crypto.Cipher import DES",
	"from Crypto.Cipher import Blowfish",
	"des.NewCipher",
	"des.NewTripleDESCipher",
	"rc4.NewCipher",
	"createCipheriv('des",
	"createCipheriv(\"des",
	"createCipheriv('rc4",
	"createCipheriv(\"rc4",
	"Cipher.getInstance(\"DES",
	"Cipher.getInstance(\"RC4",
	"KeyGenerator.getInstance(\"DES",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _weak_cipher_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Broken or obsolete cipher detected (%s); use AES-256-GCM or ChaCha20-Poly1305", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
