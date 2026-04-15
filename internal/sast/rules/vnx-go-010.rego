package vulnetix.rules.vnx_go_010

import rego.v1

metadata := {
	"id": "VNX-GO-010",
	"name": "Go weak cipher usage",
	"description": "Using DES, Triple DES, or RC4 ciphers in Go provides inadequate security. DES has a 56-bit key, RC4 has known biases, and Triple DES is deprecated by NIST. Use AES-GCM instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-010/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "weak-cipher", "des", "rc4"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_weak_cipher_indicators := {
	"des.NewCipher(",
	"des.NewTripleDESCipher(",
	"rc4.NewCipher(",
	"\"crypto/des\"",
	"\"crypto/rc4\"",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _weak_cipher_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak cipher usage: %s; use AES-GCM (crypto/aes with cipher.NewGCM) instead", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
